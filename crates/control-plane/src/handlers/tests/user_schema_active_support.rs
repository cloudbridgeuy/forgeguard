//! Shared fixtures for the V4 Active-branch `PUT /user-schema` tests.
//!
//! - `active_org` / `active_org_no_pool` — seed an `InMemoryOrgStore` with one
//!   Active org, with or without a `cognito_user_pool_id` in its config.
//! - `seed_schema` — install an initial schema row so the append-only diff has
//!   a non-empty baseline; returns the row's `ETag`.
//! - `SchemaTestApp` / `schema_test_app` — build the `PUT/GET /user-schema`
//!   router and expose the in-memory `UserPoolClient` so tests can arm Cognito
//!   failures via `arm_update_user_pool_once`.
//! - `FailingStore` — one-shot `put_user_schema` failure injection, used by T4
//!   to drive the "Cognito OK + DDB fail" → `502` branch.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::Request;
use axum::Router;
use forgeguard_authn_core::static_api_key::{ApiKeyEntry, StaticApiKeyResolver};
use forgeguard_authn_core::IdentityChain;
use forgeguard_authn_core::UserSchema;
use forgeguard_authz_core::{PolicyDecision, PolicyEngine, StaticPolicyEngine, ValidatedRbacEntry};
use forgeguard_axum::{forgeguard_layer, ForgeGuard};
use forgeguard_core::{
    FlagConfig, GroupName, Organization, OrganizationId, ProjectId, TenantId, UserId,
};
use forgeguard_http::{
    DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
};
use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::config::OrgConfig;
use crate::error::{Error, Result};
use crate::etag::Etag;
use crate::handlers::test_support::TEST_API_KEY;
use crate::handlers::AppState;
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};
use crate::store::{
    build_org_store, EtagedGroup, EtagedUserSchema, InMemoryOrgStore, InMemorySagaTicketStore,
    OrgRecord, OrgStore, PutMembershipRowParams, SagaTicketStore,
};
use crate::user_pool::{InMemoryUserPoolClient, UserPoolClient};
use crate::vp_client::stub::{happy_stub, StubVpClient};

/// `PUT`/`GET` URI for the org used by every test in this module.
pub(super) const URI: &str = "/api/v1/organizations/org-acme/user-schema";

const ORG_ID: &str = "org-acme";

/// Seed an Active org carrying `cognito_user_pool_id` in its config.
pub(super) fn active_org(pool_id: &str) -> Arc<InMemoryOrgStore> {
    org_store(&format!(r#""cognito_user_pool_id": "{pool_id}","#))
}

/// Seed an Active org whose config omits `cognito_user_pool_id` — drives the
/// `409 pool_not_provisioned` guard.
pub(super) fn active_org_no_pool() -> Arc<InMemoryOrgStore> {
    org_store("")
}

fn org_store(pool_id_line: &str) -> Arc<InMemoryOrgStore> {
    let json = format!(
        r#"{{
            "organizations": {{
                "{ORG_ID}": {{
                    "name": "Acme",
                    "status": "active",
                    "config": {{
                        "version": "2026-04-07",
                        "project_id": "acme-app",
                        "upstream_url": "https://api.example.com",
                        "default_policy": "deny",
                        {pool_id_line}
                        "routes": [],
                        "public_routes": [],
                        "features": {{}}
                    }}
                }}
            }}
        }}"#
    );
    Arc::new(build_org_store(&json).unwrap())
}

/// Install an initial schema row and return its `ETag` string.
pub(super) async fn seed_schema(store: &dyn OrgStore, schema: serde_json::Value) -> String {
    let org_id = OrganizationId::new(ORG_ID).unwrap();
    let parsed: UserSchema = serde_json::from_value(schema).unwrap();
    let stored = store
        .put_user_schema(&org_id, parsed, None)
        .await
        .expect("seed put_user_schema");
    stored.etag().as_str().to_owned()
}

/// Test-app handles. `user_pool` is exposed so tests can arm one-shot Cognito
/// failures before issuing a request.
pub(super) struct SchemaTestApp {
    pub(super) router: Router,
    pub(super) user_pool: Arc<InMemoryUserPoolClient>,
}

/// Build a `PUT/GET /user-schema` router over the supplied store.
pub(super) fn schema_test_app(store: Arc<dyn OrgStore>) -> SchemaTestApp {
    let route_matcher = RouteMatcher::new(&[]).unwrap();
    let public_routes = vec![PublicRoute::new(
        "GET".parse().unwrap(),
        "/health".to_string(),
        PublicAuthMode::Anonymous,
    )];
    let public_route_matcher = PublicRouteMatcher::new(&public_routes).unwrap();
    let config = PipelineConfig::new(PipelineConfigParams {
        route_matcher,
        public_route_matcher,
        flag_config: FlagConfig::default(),
        project_id: ProjectId::new("test").unwrap(),
        default_policy: DefaultPolicy::Passthrough,
        debug_mode: false,
        auth_providers: vec!["api-key".to_string()],
        membership_resolver: None,
    });

    let mut keys = HashMap::new();
    keys.insert(
        TEST_API_KEY.to_owned(),
        ApiKeyEntry::new(
            UserId::new("test-user").unwrap(),
            Some(TenantId::new("test-org").unwrap()),
            vec![GroupName::new("admin").unwrap()],
        ),
    );
    let resolver = StaticApiKeyResolver::new(keys);
    let chain = IdentityChain::new(vec![Arc::new(resolver)]);
    let engine: Arc<dyn PolicyEngine> = Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
    let fg = Arc::new(ForgeGuard::new(config, chain, engine));

    let user_pool = Arc::new(InMemoryUserPoolClient::new());
    let saga_tickets: Arc<dyn SagaTicketStore> = Arc::new(InMemorySagaTicketStore::new());
    let model_events: Arc<dyn crate::model_event_store::ModelEventStore> =
        Arc::new(crate::model_event_store::InMemoryModelEventStore::new());
    let state = AppState {
        store,
        vp: happy_stub(),
        user_pool: Arc::clone(&user_pool) as Arc<dyn UserPoolClient>,
        saga_tickets,
        model_events,
    };
    let router = Router::new()
        .route(
            "/api/v1/organizations/{org_id}/user-schema",
            axum::routing::get(crate::handlers::user_schema::get_user_schema_handler)
                .put(crate::handlers::user_schema::put_user_schema_handler::<StubVpClient>),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));
    SchemaTestApp { router, user_pool }
}

/// Issue a `PUT /user-schema` request, optionally with an `If-Match` header.
pub(super) async fn put_schema(
    router: &Router,
    body: serde_json::Value,
    if_match: Option<&str>,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("PUT")
        .uri(URI)
        .header("x-api-key", TEST_API_KEY)
        .header("content-type", "application/json");
    if let Some(value) = if_match {
        req = req.header("if-match", value);
    }
    router
        .clone()
        .oneshot(
            req.body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Issue a `GET /user-schema` request — used to assert the row is unchanged
/// after a failed `PUT`.
pub(super) async fn get_schema(router: &Router) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(URI)
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Deserialize a response body into JSON.
pub(super) async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// One-shot failure-injection wrapper over an [`InMemoryOrgStore`].
///
/// Arm `fail_next_put_user_schema` before a request to force the *first*
/// `put_user_schema` call to return `Error::Store`; the slot then drains so a
/// follow-up retry persists normally.
pub(super) struct FailingStore {
    inner: Arc<InMemoryOrgStore>,
    fail_put_user_schema_once: AtomicBool,
}

impl FailingStore {
    pub(super) fn new(inner: Arc<InMemoryOrgStore>) -> Self {
        Self {
            inner,
            fail_put_user_schema_once: AtomicBool::new(false),
        }
    }

    pub(super) fn fail_next_put_user_schema(&self) {
        self.fail_put_user_schema_once.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl OrgStore for FailingStore {
    async fn get(&self, org_id: &OrganizationId) -> Result<Option<OrgRecord>> {
        self.inner.get(org_id).await
    }
    async fn create(&self, org: Organization, config: Option<OrgConfig>) -> Result<OrgRecord> {
        self.inner.create(org, config).await
    }
    async fn list(&self, offset: usize, limit: usize) -> Result<Vec<OrgRecord>> {
        self.inner.list(offset, limit).await
    }
    async fn update(
        &self,
        org_id: &OrganizationId,
        org: Organization,
        config: Option<OrgConfig>,
        expected_etag: Option<&Etag>,
    ) -> Result<OrgRecord> {
        self.inner.update(org_id, org, config, expected_etag).await
    }
    async fn delete(&self, org_id: &OrganizationId) -> Result<()> {
        self.inner.delete(org_id).await
    }
    async fn generate_key(&self, org_id: &OrganizationId) -> Result<GenerateKeyResult> {
        self.inner.generate_key(org_id).await
    }
    async fn list_keys(&self, org_id: &OrganizationId) -> Result<Vec<SigningKeyEntry>> {
        self.inner.list_keys(org_id).await
    }
    async fn revoke_key(&self, org_id: &OrganizationId, key_id: &str) -> Result<()> {
        self.inner.revoke_key(org_id, key_id).await
    }
    async fn rotate_signing_key(
        &self,
        org_id: &OrganizationId,
        key_id: &str,
    ) -> Result<GenerateKeyResult> {
        self.inner.rotate_signing_key(org_id, key_id).await
    }
    async fn get_group(&self, org_id: &OrganizationId, name: &str) -> Result<Option<EtagedGroup>> {
        self.inner.get_group(org_id, name).await
    }
    async fn put_group(
        &self,
        org_id: &OrganizationId,
        entry: ValidatedRbacEntry,
        expected_etag: Option<&str>,
    ) -> Result<EtagedGroup> {
        self.inner.put_group(org_id, entry, expected_etag).await
    }
    async fn list_groups(&self, org_id: &OrganizationId) -> Result<Vec<EtagedGroup>> {
        self.inner.list_groups(org_id).await
    }
    async fn delete_group(
        &self,
        org_id: &OrganizationId,
        name: &str,
        expected_etag: &str,
    ) -> Result<()> {
        self.inner.delete_group(org_id, name, expected_etag).await
    }
    async fn list_inheritors(&self, org_id: &OrganizationId, name: &str) -> Result<Vec<String>> {
        self.inner.list_inheritors(org_id, name).await
    }
    async fn count_memberships_for_group(
        &self,
        org_id: &OrganizationId,
        name: &str,
    ) -> Result<BTreeMap<String, u32>> {
        self.inner.count_memberships_for_group(org_id, name).await
    }
    async fn is_declared_group(&self, org_id: &OrganizationId, name: &str) -> Result<bool> {
        self.inner.is_declared_group(org_id, name).await
    }
    async fn get_user_schema(&self, org_id: &OrganizationId) -> Result<Option<EtagedUserSchema>> {
        self.inner.get_user_schema(org_id).await
    }
    async fn put_user_schema(
        &self,
        org_id: &OrganizationId,
        schema: UserSchema,
        expected_etag: Option<&Etag>,
    ) -> Result<EtagedUserSchema> {
        if self.fail_put_user_schema_once.swap(false, Ordering::SeqCst) {
            return Err(Error::Store("forced put_user_schema failure".to_owned()));
        }
        self.inner
            .put_user_schema(org_id, schema, expected_etag)
            .await
    }
    async fn put_membership_row(&self, params: PutMembershipRowParams<'_>) -> Result<()> {
        self.inner.put_membership_row(params).await
    }
}
