//! Shared fixtures for `POST /api/v1/organizations/{org_id}/users` tests.
//!
//! Builds an `InMemoryOrgStore` seeded with one Active org carrying a
//! `cognito_user_pool_id` and (optionally) a set of declared groups + a
//! `name`-required schema. The Active branch of the saga driver fails fast
//! without a pool id, so every test in `users_create.rs` consumes this
//! fixture rather than rolling its own JSON.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use axum::Router;
use forgeguard_authn_core::static_api_key::{ApiKeyEntry, StaticApiKeyResolver};
use forgeguard_authn_core::IdentityChain;
use forgeguard_authn_core::UserSchema;
use forgeguard_authz_core::rbac::{validate_rbac_entry, RbacEntry};
use forgeguard_authz_core::{PolicyDecision, PolicyEngine, StaticPolicyEngine, ValidatedRbacEntry};
use forgeguard_axum::{forgeguard_layer, ForgeGuard};
use forgeguard_core::{
    FlagConfig, GroupName, Organization, OrganizationId, ProjectId, TenantId, UserId,
};
use forgeguard_http::{
    DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
};
use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};

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

/// Build an Active-org store with the given pool id, a seeded user schema
/// (required attribute: `name`), and the listed declared groups.
///
/// The store is returned as `Arc<InMemoryOrgStore>` so callers retain the
/// concrete type for the `get_membership_row` test probe; coerce to
/// `Arc<dyn OrgStore>` at the router boundary.
pub(super) async fn active_org_with_schema(
    org_id: &str,
    pool_id: &str,
    declared_groups: &[&str],
) -> Arc<InMemoryOrgStore> {
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
                        "cognito_user_pool_id": "{pool_id}",
                        "routes": [],
                        "public_routes": [],
                        "features": {{}}
                    }}
                }}
            }}
        }}"#
    );
    let store = Arc::new(build_org_store(&json).unwrap());
    let org_id_typed = OrganizationId::new(org_id).unwrap();

    let schema: UserSchema = serde_json::from_value(serde_json::json!({
        "standard": { "name": { "required": true } },
        "custom": {}
    }))
    .unwrap();
    OrgStore::put_user_schema(store.as_ref(), &org_id_typed, schema, None)
        .await
        .unwrap();

    for raw in declared_groups {
        let proposed = RbacEntry {
            name: (*raw).to_owned(),
            description: None,
            inherits: Vec::new(),
            allow: vec!["app:noop:read".to_owned()],
            tenant_scoped: true,
        };
        let entry = validate_rbac_entry(proposed.clone(), &[proposed]).expect("valid rbac entry");
        OrgStore::put_group(store.as_ref(), &org_id_typed, entry, None)
            .await
            .unwrap();
    }
    store
}

/// Test app handles — returned alongside the `Router` so individual tests can
/// arm failures on the in-memory `UserPoolClient`, assert against the saga
/// ticket store, and probe the materialised membership rows on the store.
pub(super) struct UsersTestApp {
    pub(super) router: Router,
    pub(super) store: Arc<InMemoryOrgStore>,
    pub(super) user_pool: Arc<InMemoryUserPoolClient>,
    pub(super) saga_tickets: Arc<InMemorySagaTicketStore>,
}

/// Build the shared `ForgeGuard` middleware used by both test-app builders.
fn build_test_forgeguard() -> Arc<ForgeGuard> {
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
    Arc::new(ForgeGuard::new(config, chain, engine))
}

/// Build a `POST /users` test router with the supplied store.
///
/// The user pool and saga ticket store are freshly constructed and exposed via
/// the returned [`UsersTestApp`] so tests can arm failures and assert state
/// without going through the HTTP surface.
pub(super) fn test_app_for_store(store: Arc<InMemoryOrgStore>) -> UsersTestApp {
    let fg = build_test_forgeguard();
    let user_pool = Arc::new(InMemoryUserPoolClient::new());
    let saga_tickets = Arc::new(InMemorySagaTicketStore::new());
    let vp = happy_stub();
    let model_events: Arc<dyn crate::model_event_store::ModelEventStore> =
        Arc::new(crate::model_event_store::InMemoryModelEventStore::new());
    let state = AppState {
        store: Arc::clone(&store) as Arc<dyn OrgStore>,
        vp,
        user_pool: Arc::clone(&user_pool) as Arc<dyn UserPoolClient>,
        saga_tickets: Arc::clone(&saga_tickets) as Arc<dyn SagaTicketStore>,
        model_events,
    };
    let router = Router::new()
        .route(
            "/api/v1/organizations/{org_id}/users",
            axum::routing::post(crate::handlers::users::create_handler::<StubVpClient>),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));
    UsersTestApp {
        router,
        store,
        user_pool,
        saga_tickets,
    }
}

/// Process-wide async lock for tests that read/assert against the global
/// `SAGA_COMPENSATION_FAILED_TOTAL` counter. Tests that *write* the metric
/// (i.e. cause C2 to fail) also acquire it so the asserting test reads a
/// quiescent delta.
pub(super) async fn metric_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

pub(super) fn payload(email: &str, name: Option<&str>, groups: &[&str]) -> Vec<u8> {
    let attributes = match name {
        Some(n) => serde_json::json!({ "name": n }),
        None => serde_json::json!({}),
    };
    serde_json::to_vec(&serde_json::json!({
        "email": email,
        "attributes": attributes,
        "groups": groups,
    }))
    .unwrap()
}

/// One-shot failure-injection wrapper over an [`InMemoryOrgStore`].
///
/// Arm `fail_next_put_membership_row` before a request to force stage S3 into
/// the compensation branch — the *first* `put_membership_row` call returns
/// `Error::Store("forced put_membership_row failure")` and the slot is then
/// drained, so subsequent S3 attempts (in retry scenarios) succeed normally.
pub(super) struct FailingStore {
    inner: Arc<InMemoryOrgStore>,
    fail_put_membership_row_once: AtomicBool,
}

impl FailingStore {
    pub(super) fn new(inner: Arc<InMemoryOrgStore>) -> Self {
        Self {
            inner,
            fail_put_membership_row_once: AtomicBool::new(false),
        }
    }

    pub(super) fn fail_next_put_membership_row(&self) {
        self.fail_put_membership_row_once
            .store(true, Ordering::SeqCst);
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
        self.inner
            .put_user_schema(org_id, schema, expected_etag)
            .await
    }
    async fn put_membership_row(&self, params: PutMembershipRowParams<'_>) -> Result<()> {
        if self
            .fail_put_membership_row_once
            .swap(false, Ordering::SeqCst)
        {
            return Err(Error::Store("forced put_membership_row failure".to_owned()));
        }
        self.inner.put_membership_row(params).await
    }
}

/// Test app handles for the failing-store path.
///
/// Mirrors [`UsersTestApp`] but with a [`FailingStore`] in front of the
/// in-memory store so the S3-failure response paths (Path 2 / Path 3) can be
/// exercised without inventing duplicate-sub collisions on the inner store.
pub(super) struct FailingUsersTestApp {
    pub(super) router: Router,
    pub(super) failing_store: Arc<FailingStore>,
    pub(super) user_pool: Arc<InMemoryUserPoolClient>,
    pub(super) saga_tickets: Arc<InMemorySagaTicketStore>,
}

/// Build a `POST /users` test router whose `OrgStore` is the [`FailingStore`]
/// wrapper. The wrapper is returned via [`FailingUsersTestApp::failing_store`]
/// so tests can arm one-shot `put_membership_row` failures.
pub(super) fn failing_test_app_for_store(inner: Arc<InMemoryOrgStore>) -> FailingUsersTestApp {
    let failing = Arc::new(FailingStore::new(inner));
    let fg = build_test_forgeguard();
    let user_pool = Arc::new(InMemoryUserPoolClient::new());
    let saga_tickets = Arc::new(InMemorySagaTicketStore::new());
    let vp = happy_stub();
    let model_events: Arc<dyn crate::model_event_store::ModelEventStore> =
        Arc::new(crate::model_event_store::InMemoryModelEventStore::new());
    let state = AppState {
        store: Arc::clone(&failing) as Arc<dyn OrgStore>,
        vp,
        user_pool: Arc::clone(&user_pool) as Arc<dyn UserPoolClient>,
        saga_tickets: Arc::clone(&saga_tickets) as Arc<dyn SagaTicketStore>,
        model_events,
    };
    let router = Router::new()
        .route(
            "/api/v1/organizations/{org_id}/users",
            axum::routing::post(crate::handlers::users::create_handler::<StubVpClient>),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));
    FailingUsersTestApp {
        router,
        failing_store: failing,
        user_pool,
        saga_tickets,
    }
}
