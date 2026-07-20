//! Test fixtures for the V4 Active-org write path (push-then-append).
//!
//! - `active_org_store` — seeds an `InMemoryOrgStore` with one Active org
//!   carrying a populated `vp_store_id`. Used by every Active-branch test.
//! - `FailingModelEventStore` — delegating wrapper over
//!   [`Arc<dyn ModelEventStore>`] with one-shot failure injection on
//!   `put_group`/`delete_group` (the event-sourced *append*, which now runs
//!   AFTER the VP push — #113 V4 Task 4). Used by the F-append tests to drive
//!   the post-push compensation path.
//! - `test_app_for_store` — counterpart to
//!   [`super::super::test_support::test_app_with_stub`]; accepts an arbitrary
//!   `Arc<dyn OrgStore>` plus `Arc<dyn ModelEventStore>` so the failure-mode
//!   tests can plug in [`FailingModelEventStore`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use tokio::sync::{Mutex, MutexGuard};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use forgeguard_authn_core::static_api_key::{ApiKeyEntry, StaticApiKeyResolver};
use forgeguard_authn_core::IdentityChain;
use forgeguard_authz_core::{Actor, PolicyDecision, PolicyEngine, RbacEntry, StaticPolicyEngine};
use forgeguard_axum::{forgeguard_layer, ForgeGuard};
use forgeguard_core::{FlagConfig, GroupName, NativeId, ProjectId, Segment, TenantId, UserId};
use forgeguard_http::{
    DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
};
use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};

use tower::ServiceExt;

use crate::error::{Error, Result};
use crate::handlers::test_support::TEST_API_KEY;
use crate::handlers::AppState;
use crate::model_event_store::{
    EventSigningKey, GroupWriteOutcome, InMemoryModelEventStore, ModelEventStore,
};
use crate::promotion_store::PromotionEntry;
use crate::signing_key::GenerateKeyResult;
use crate::store::{build_org_store, OrgRecord, OrgStore};
use crate::user_pool::{InMemoryUserPoolClient, UserPoolClient};
use crate::vp_client::stub::StubVpClient;
use forgeguard_authz_core::{EventEnvelope, EventKind, FoldedState, Revision};

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

/// One-shot failure-injection wrapper over any [`ModelEventStore`].
///
/// #113 V4 Task 4 inverted the active-org write order to VP-first-then-append,
/// so the seam that can fail *after* a successful VP push is now
/// `ModelEventStore::{put_group, delete_group}` (the event-sourced append),
/// not `OrgStore`'s old etag-gated writes. Used to drive the F-append
/// compensation branch: arm `fail_next_put_group` (CREATE/UPDATE) or
/// `fail_next_delete_group` (DELETE) before the request, and the *first*
/// matching call returns `Error::Store`. All other methods delegate straight
/// through to `inner`.
pub(super) struct FailingModelEventStore {
    inner: Arc<dyn ModelEventStore>,
    fail_put_group_once: AtomicBool,
    fail_delete_group_once: AtomicBool,
}

impl FailingModelEventStore {
    pub(super) fn new(inner: Arc<dyn ModelEventStore>) -> Self {
        Self {
            inner,
            fail_put_group_once: AtomicBool::new(false),
            fail_delete_group_once: AtomicBool::new(false),
        }
    }

    pub(super) fn fail_next_put_group(&self) {
        self.fail_put_group_once.store(true, Ordering::SeqCst);
    }

    pub(super) fn fail_next_delete_group(&self) {
        self.fail_delete_group_once.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl ModelEventStore for FailingModelEventStore {
    async fn get_principal(
        &self,
        org_id: &str,
        native_id: &NativeId,
    ) -> Result<Option<serde_json::Value>> {
        self.inner.get_principal(org_id, native_id).await
    }
    async fn latest_revision(&self, org_id: &str) -> Result<Revision> {
        self.inner.latest_revision(org_id).await
    }
    async fn upsert_changed(
        &self,
        org_id: &str,
        native_id: &NativeId,
        actor: Actor,
        payload: serde_json::Value,
    ) -> Result<Revision> {
        self.inner
            .upsert_changed(org_id, native_id, actor, payload)
            .await
    }
    async fn events_after(
        &self,
        org_id: &str,
        after: Revision,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>> {
        self.inner.events_after(org_id, after, limit).await
    }
    async fn get_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
    ) -> Result<Option<String>> {
        self.inner
            .get_promotion(org_id, resource_type, native_id)
            .await
    }
    async fn put_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Revision> {
        self.inner
            .put_promotion(org_id, resource_type, native_id, actor)
            .await
    }
    async fn tombstone_promotion(
        &self,
        org_id: &str,
        resource_type: &Segment,
        native_id: &NativeId,
        actor: Actor,
    ) -> Result<Option<Revision>> {
        self.inner
            .tombstone_promotion(org_id, resource_type, native_id, actor)
            .await
    }
    async fn list_promotions(
        &self,
        org_id: &str,
        resource_type: &Segment,
        after: Option<&NativeId>,
        limit: usize,
    ) -> Result<Vec<PromotionEntry>> {
        self.inner
            .list_promotions(org_id, resource_type, after, limit)
            .await
    }
    async fn list_signing_keys(&self, org_id: &str) -> Result<Vec<EventSigningKey>> {
        self.inner.list_signing_keys(org_id).await
    }
    async fn generate_org_key(
        &self,
        org_id: &str,
        actor: Actor,
    ) -> Result<(GenerateKeyResult, Revision)> {
        self.inner.generate_org_key(org_id, actor).await
    }
    async fn revoke_org_key(
        &self,
        org_id: &str,
        key_id: &str,
        actor: Actor,
    ) -> Result<Option<Revision>> {
        self.inner.revoke_org_key(org_id, key_id, actor).await
    }
    async fn rotate_org_key(
        &self,
        org_id: &str,
        key_id: &str,
        actor: Actor,
    ) -> Result<(GenerateKeyResult, Revision)> {
        self.inner.rotate_org_key(org_id, key_id, actor).await
    }
    async fn create_org(&self, record: OrgRecord, actor: Actor) -> Result<Revision> {
        self.inner.create_org(record, actor).await
    }
    async fn update_org(
        &self,
        record: OrgRecord,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<Revision> {
        self.inner
            .update_org(record, actor, expected_revision)
            .await
    }
    async fn transition_org(
        &self,
        record: OrgRecord,
        kind: EventKind,
        actor: Actor,
        expected_revision: Revision,
    ) -> Result<Revision> {
        self.inner
            .transition_org(record, kind, actor, expected_revision)
            .await
    }
    async fn put_group(
        &self,
        org_id: &str,
        entry: RbacEntry,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<GroupWriteOutcome> {
        if self.fail_put_group_once.swap(false, Ordering::SeqCst) {
            return Err(Error::Store("forced put_group failure".to_owned()));
        }
        self.inner
            .put_group(org_id, entry, actor, expected_revision)
            .await
    }
    async fn delete_group(
        &self,
        org_id: &str,
        name: &str,
        actor: Actor,
        expected_revision: Option<Revision>,
    ) -> Result<GroupWriteOutcome> {
        if self.fail_delete_group_once.swap(false, Ordering::SeqCst) {
            return Err(Error::Store("forced delete_group failure".to_owned()));
        }
        self.inner
            .delete_group(org_id, name, actor, expected_revision)
            .await
    }
    async fn fold_at(&self, org_id: &str, at: Option<Revision>) -> Result<FoldedState> {
        self.inner.fold_at(org_id, at).await
    }
}

/// Build an `InMemoryModelEventStore` write-through-wired to `store` — the
/// same wiring `test_app_with_stub` uses internally, exposed here so
/// `test_app_for_store` callers that don't need failure injection can share
/// the read-model with the `Arc<dyn OrgStore>` they pass alongside it.
pub(super) fn model_events_for(store: &Arc<dyn OrgStore>) -> Arc<dyn ModelEventStore> {
    Arc::new(InMemoryModelEventStore::new_with_org_store(Arc::clone(
        store,
    )))
}

/// Test app builder — same wiring as
/// [`super::super::test_support::test_app_with_stub`] but accepts an
/// arbitrary `Arc<dyn ModelEventStore>` so failure-mode tests can plug in
/// [`FailingModelEventStore`].
///
/// Only the group routes are mounted (the only routes the Active-branch tests
/// need). Health, org, key, metrics, and proxy-config routes are intentionally
/// absent.
pub(super) fn test_app_for_store(
    store: Arc<dyn OrgStore>,
    vp: Arc<StubVpClient>,
    model_events: Arc<dyn ModelEventStore>,
) -> Router {
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
    let state = AppState {
        store,
        vp,
        user_pool,
        model_events,
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
