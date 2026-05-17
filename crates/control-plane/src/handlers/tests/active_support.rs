//! Test fixtures for the V3 Active-org write path.
//!
//! - `active_org_store` — seeds an `InMemoryOrgStore` with one Active org
//!   carrying a populated `vp_store_id`. Used by every Active-branch test.
//! - `FailingStore` — delegating wrapper over [`Arc<dyn OrgStore>`] with
//!   one-shot failure injection on `delete_group` / `put_group`. Used by the
//!   F3' tests to drive the rollback into `Err(rollback_err)`.
//! - `test_app_for_store` — counterpart to
//!   [`super::super::test_support::test_app_with_stub`]; accepts an arbitrary
//!   `Arc<dyn OrgStore>` so the failure-mode tests can plug in [`FailingStore`].

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use tokio::sync::{Mutex, MutexGuard};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use forgeguard_authn_core::static_api_key::{ApiKeyEntry, StaticApiKeyResolver};
use forgeguard_authn_core::IdentityChain;
use forgeguard_authz_core::{PolicyDecision, PolicyEngine, StaticPolicyEngine, ValidatedRbacEntry};
use forgeguard_axum::{forgeguard_layer, ForgeGuard};
use forgeguard_core::{
    FlagConfig, GroupName, Organization, OrganizationId, ProjectId, TenantId, UserId,
};
use forgeguard_http::{
    DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
};
use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};

use tower::ServiceExt;

use forgeguard_authn_core::UserSchema;

use crate::config::OrgConfig;
use crate::error::{Error, Result};
use crate::etag::Etag;
use crate::handlers::test_support::TEST_API_KEY;
use crate::handlers::AppState;
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};
use crate::store::{
    build_org_store, EtagedGroup, EtagedUserSchema, InMemorySagaTicketStore, OrgRecord, OrgStore,
    PutMembershipRowParams, SagaTicketStore,
};
use crate::user_pool::{InMemoryUserPoolClient, UserPoolClient};
use crate::vp_client::stub::StubVpClient;

/// Process-wide async lock for tests that read/assert against the global
/// `GROUP_ROLLBACK_FAILED_TOTAL` counter. Cargo runs tests in parallel, and
/// the prometheus counter is process-global, so concurrent F3/F3'/F4 tests
/// would race on `counter_after - counter_before` deltas without this guard.
/// Uses `tokio::sync::Mutex` so the guard can be held across `await` points.
pub(super) async fn metric_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

pub(super) fn active_org_store(org_id: &str, vp_store_id: &str) -> Arc<dyn OrgStore> {
    let json = format!(
        r#"{{
            "organizations": {{
                "{org_id}": {{
                    "name": "Active Org",
                    "status": "active",
                    "config": {{
                        "version": "2026-04-07",
                        "project_id": "test-app",
                        "upstream_url": "https://api.example.com",
                        "default_policy": "deny",
                        "vp_store_id": "{vp_store_id}",
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

/// One-shot failure-injection wrapper over any [`OrgStore`].
///
/// Used to drive the F3' rollback-fails branch: arm `fail_next_delete_group`
/// (for CREATE rollback) or `fail_next_put_group` (for UPDATE/DELETE rollback)
/// before the request, and the *first* matching call returns `Error::Store`.
pub(super) struct FailingStore {
    inner: Arc<dyn OrgStore>,
    fail_delete_group_once: AtomicBool,
    fail_put_group_once: AtomicBool,
}

impl FailingStore {
    pub(super) fn new(inner: Arc<dyn OrgStore>) -> Self {
        Self {
            inner,
            fail_delete_group_once: AtomicBool::new(false),
            fail_put_group_once: AtomicBool::new(false),
        }
    }

    pub(super) fn fail_next_delete_group(&self) {
        self.fail_delete_group_once.store(true, Ordering::SeqCst);
    }

    pub(super) fn fail_next_put_group(&self) {
        self.fail_put_group_once.store(true, Ordering::SeqCst);
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
        if self.fail_put_group_once.swap(false, Ordering::SeqCst) {
            return Err(Error::Store("forced put_group failure".to_owned()));
        }
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
        if self.fail_delete_group_once.swap(false, Ordering::SeqCst) {
            return Err(Error::Store("forced delete_group failure".to_owned()));
        }
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
        self.inner
            .put_user_schema(org_id, schema, expected_etag)
            .await
    }
    async fn put_membership_row(&self, params: PutMembershipRowParams<'_>) -> Result<()> {
        self.inner.put_membership_row(params).await
    }
}

/// Test app builder — same wiring as
/// [`super::super::test_support::test_app_with_stub`] but accepts any
/// `Arc<dyn OrgStore>` so failure-mode tests can plug in [`FailingStore`].
///
/// Only the group routes are mounted (the only routes the Active-branch tests
/// need). Health, org, key, metrics, and proxy-config routes are intentionally
/// absent.
pub(super) fn test_app_for_store(store: Arc<dyn OrgStore>, vp: Arc<StubVpClient>) -> Router {
    let route_matcher = RouteMatcher::new(&[]).unwrap();
    let public_routes = vec![
        PublicRoute::new(
            "GET".parse().unwrap(),
            "/health".to_string(),
            PublicAuthMode::Anonymous,
        ),
        PublicRoute::new(
            "GET".parse().unwrap(),
            "/metrics".to_string(),
            PublicAuthMode::Anonymous,
        ),
    ];
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

    let user_pool: Arc<dyn UserPoolClient> = Arc::new(InMemoryUserPoolClient::new());
    let saga_tickets: Arc<dyn SagaTicketStore> = Arc::new(InMemorySagaTicketStore::new());
    let state = AppState {
        store,
        vp,
        user_pool,
        saga_tickets,
    };
    Router::new()
        .route(
            "/api/v1/organizations/{org_id}/groups",
            axum::routing::post(crate::handlers::groups::create_handler::<StubVpClient>)
                .get(crate::handlers::groups::list_handler),
        )
        .route(
            "/api/v1/organizations/{org_id}/groups/{name}",
            axum::routing::get(crate::handlers::groups::get_handler)
                .put(crate::handlers::groups::update_handler::<StubVpClient>)
                .delete(crate::handlers::groups::delete_handler::<StubVpClient>),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer))
}

/// Build a POST /groups body. Pass `inherits: &[]` when the group has no
/// parent groups.
pub(super) fn group_body(name: &str, allow: &[&str], inherits: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": name,
        "allow": allow,
        "inherits": inherits,
    }))
    .unwrap()
}

/// Create a group via POST /groups and return its `ETag`. Panics on failure.
pub(super) async fn create_group(
    app: axum::Router,
    org_id: &str,
    name: &str,
    allow: &[&str],
    inherits: &[&str],
) -> String {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{org_id}/groups"))
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body(name, allow, inherits)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "POST {name} failed");
    resp.headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}
