pub(crate) mod events;
pub(crate) mod groups;
pub(crate) mod if_revision;
mod keys;
pub(crate) mod lifecycle;
pub(crate) mod min_revision;
pub(crate) mod principals;
pub(crate) mod promotions;
pub(crate) mod signing_keys;
pub(crate) mod user_schema;
pub(crate) mod users;

use std::sync::Arc;

use axum::extract::{FromRef, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authz_core::Actor;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{Fgrn, NativeId, OrgStatus, Organization, OrganizationId, Segment};
use serde::{Deserialize, Serialize};

use crate::config::OrgConfig;
use crate::etag::{self, Etag, IfNoneMatchResult};
use crate::model_event_store::ModelEventStore;
use crate::store::{OrgRecord, OrgStore, SagaTicketStore};
use crate::user_pool::UserPoolClient;
use crate::vp_client::VpClient;

pub(super) const DEFAULT_LIMIT: u16 = 100;
pub(super) const MAX_LIMIT: u16 = 1000;

/// Response header carrying the log revision an append advanced to (or the
/// current revision, on a no-op). Shared across every model-plane write
/// (principals, promotions, orgs) so clients see one consistent name.
pub(crate) const REVISION_HEADER: &str = "x-fg-revision";

/// Derive the `Actor` recorded on an appended event from the resolved
/// identity, falling back to `Actor::System` when there is no identity (dev
/// mode) or either segment fails to parse (identity fields are already
/// validated upstream, so this is not expected to trigger in practice).
pub(super) fn actor_for(org_id: &str, identity: Option<&forgeguard_authn_core::Identity>) -> Actor {
    let Some(identity) = identity else {
        return Actor::System;
    };
    let (Ok(segment), Ok(native_id)) = (
        Segment::try_new(org_id),
        NativeId::try_new(identity.user_id().as_str()),
    ) else {
        return Actor::System;
    };
    Actor::Principal(Fgrn::principal(&segment, &native_id))
}

/// Clamp a requested page size to [`MAX_LIMIT`], logging when the request
/// exceeded it — "no silent caps": a client asking for more than we serve
/// must be able to see that in the logs, not just get a smaller page back.
pub(super) fn clamp_limit(requested: u16) -> usize {
    if requested > MAX_LIMIT {
        tracing::warn!(
            requested_limit = requested,
            clamped_limit = MAX_LIMIT,
            "query limit clamped to maximum"
        );
        usize::from(MAX_LIMIT)
    } else if requested == 0 {
        tracing::warn!("query limit of 0 floored to 1");
        1
    } else {
        usize::from(requested)
    }
}

/// Shared router state for the control-plane Axum app.
///
/// Carries the object-safe [`OrgStore`] handle and the `VpClient` used by
/// the V3 Active write path. Non-group handlers extract
/// `State<Arc<dyn OrgStore>>` via the `FromRef` impl below; group handlers
/// extract the full [`AppState<V>`].
///
/// V3 adds `user_pool` and `saga_tickets` for the inline `POST /users` saga
/// driver. The trait objects let production wire `AwsCognitoUserPoolClient` +
/// `DynamoSagaTicketStore` while tests wire the in-memory equivalents.
///
/// V1-append-spine adds `model_events` — the [`ModelEventStore`] seam the
/// `PUT /principals/{native_id}` handler upserts through, wiring
/// `DynamoModelEventStore` in production and
/// `InMemoryModelEventStore` for `--store=memory` dev mode and handler
/// tests.
pub(crate) struct AppState<V> {
    pub(crate) store: Arc<dyn OrgStore>,
    pub(crate) vp: Arc<V>,
    pub(crate) user_pool: Arc<dyn UserPoolClient>,
    pub(crate) saga_tickets: Arc<dyn SagaTicketStore>,
    pub(crate) model_events: Arc<dyn ModelEventStore>,
}

impl<V> Clone for AppState<V> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            vp: Arc::clone(&self.vp),
            user_pool: Arc::clone(&self.user_pool),
            saga_tickets: Arc::clone(&self.saga_tickets),
            model_events: Arc::clone(&self.model_events),
        }
    }
}

impl<V> FromRef<AppState<V>> for Arc<dyn OrgStore> {
    fn from_ref(input: &AppState<V>) -> Arc<dyn OrgStore> {
        Arc::clone(&input.store)
    }
}

impl<V> FromRef<AppState<V>> for Arc<dyn UserPoolClient> {
    fn from_ref(input: &AppState<V>) -> Arc<dyn UserPoolClient> {
        Arc::clone(&input.user_pool)
    }
}

impl<V> FromRef<AppState<V>> for Arc<dyn SagaTicketStore> {
    fn from_ref(input: &AppState<V>) -> Arc<dyn SagaTicketStore> {
        Arc::clone(&input.saga_tickets)
    }
}

impl<V> FromRef<AppState<V>> for Arc<dyn ModelEventStore> {
    fn from_ref(input: &AppState<V>) -> Arc<dyn ModelEventStore> {
        Arc::clone(&input.model_events)
    }
}

pub(crate) use keys::{
    generate_key_handler, list_keys_handler, revoke_key_handler, rotate_key_handler,
};

/// Response body emitted on every `412 Precondition Failed` from `PUT /organizations/{id}`.
///
/// The `reason` field surfaces the same label that drives the Prometheus counter
/// (`PreconditionReason::as_label()`), keeping the wire shape, metrics, and span
/// fields a single source of truth.
#[derive(Debug, Serialize)]
pub(crate) struct PreconditionFailedBody {
    /// Stable machine-readable error code. Always `"etag mismatch"` for 412 responses.
    error: &'static str,
    /// Machine-readable reason: one of `"stale_etag"`, `"draft_fail_closed"`,
    /// or `"wildcard_on_draft"`.
    reason: &'static str,
    /// The ETag of the current stored representation as a string. Empty string for
    /// Draft orgs that have no config yet (`None` current_etag from the store).
    current_etag: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateOrgRequest {
    org_id: String,
    name: String,
    /// Proxy config. Omit to create a Draft org without one — the
    /// admin can set it later via `PUT /api/v1/organizations/{org_id}`.
    #[serde(default)]
    config: Option<OrgConfig>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListParams {
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

pub(crate) async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

pub(crate) async fn metrics_handler() -> Response {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buf = Vec::new();
    if encoder.encode(&prometheus::gather(), &mut buf).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let content_type: axum::http::HeaderValue = encoder
        .format_type()
        .parse()
        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("text/plain"));
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        buf,
    )
        .into_response()
}

/// `POST /api/v1/organizations` — create a Draft org on the event log.
///
/// Appends `org.created` via [`ModelEventStore::create_org`] and responds
/// `201` with the created organization and the revision the log advanced
/// to. No `ETag` — org mutations are revision-tokened, not etag-conditioned
/// (D5).
pub(crate) async fn create_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    State(state): State<AppState<V>>,
    Json(body): Json<CreateOrgRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&body.org_id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid org_id"})),
        )
            .into_response();
    };
    let raw_org_id = org_id.to_string();

    let now = chrono::Utc::now();
    let org = Organization::new(org_id, body.name, OrgStatus::Draft, now);
    let org_snapshot = org.clone();
    let record = OrgRecord::new(
        org,
        body.config.map(crate::store::ConfiguredConfig::compute),
    );
    let actor = actor_for(&raw_org_id, identity.as_ref());

    match state.model_events.create_org(record, actor).await {
        Ok(revision) => {
            let mut response_headers = HeaderMap::new();
            if let Ok(val) = HeaderValue::from_str(&revision.value().to_string()) {
                response_headers.insert(REVISION_HEADER, val);
            }
            (
                StatusCode::CREATED,
                response_headers,
                Json(serde_json::json!({
                    "organization": org_snapshot,
                    "revision": revision.value(),
                })),
            )
                .into_response()
        }
        Err(crate::error::Error::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "create org failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[tracing::instrument(
    name = "show_org",
    skip_all,
    fields(org_id = %raw_org_id, if_none_match_hit = tracing::field::Empty),
)]
pub(crate) async fn get_handler(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<dyn OrgStore>>,
    headers: HeaderMap,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return not_found();
    };

    let record = match store.get(&org_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "get org failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let if_none_match_parsed = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match);
    let stored_etag = record
        .configured()
        .map(crate::store::ConfiguredConfig::etag);

    let response_headers = etag_header_map(stored_etag);

    match etag::check_if_none_match(if_none_match_parsed, stored_etag) {
        IfNoneMatchResult::Matched | IfNoneMatchResult::WildcardMatched => {
            tracing::Span::current().record("if_none_match_hit", true);
            (
                StatusCode::NOT_MODIFIED,
                response_headers,
                axum::body::Body::empty(),
            )
                .into_response()
        }
        IfNoneMatchResult::NotMatched | IfNoneMatchResult::WildcardOnDraft => {
            (StatusCode::OK, response_headers, Json(record.org().clone())).into_response()
        }
    }
}

pub(crate) async fn list_handler(
    Query(params): Query<ListParams>,
    State(store): State<Arc<dyn OrgStore>>,
) -> Response {
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(20).min(100);

    match store.list(offset, limit).await {
        Ok(records) => {
            let orgs: Vec<&Organization> = records.iter().map(OrgRecord::org).collect();
            Json(orgs).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "list orgs failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[tracing::instrument(
    name = "proxy_config",
    skip_all,
    fields(org_id = %raw_org_id, if_none_match_hit = tracing::field::Empty),
)]
pub(crate) async fn proxy_config_handler(
    ForgeGuardIdentity(_identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<dyn OrgStore>>,
    headers: HeaderMap,
) -> Response {
    // Validate org_id format
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return not_found();
    };

    // Lookup org
    let record = match store.get(&org_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "store lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Org exists but is Draft (no proxy config set yet) — distinct from "not found"
    // per the issue body. 409 Conflict matches RFC 7231 ¶6.5.8: "current resource
    // state forbids the action".
    let Some(configured) = record.configured() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("organization '{org_id}' has no proxy config")
            })),
        )
            .into_response();
    };

    let if_none_match_parsed = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match);

    // Build response headers once — ETag is echoed on both 304 and 200 (RFC 7232 §4.1).
    let response_headers = etag_header_map(Some(configured.etag()));

    match etag::check_if_none_match(if_none_match_parsed, Some(configured.etag())) {
        IfNoneMatchResult::Matched | IfNoneMatchResult::WildcardMatched => {
            tracing::Span::current().record("if_none_match_hit", true);
            (
                StatusCode::NOT_MODIFIED,
                response_headers,
                axum::body::Body::empty(),
            )
                .into_response()
        }
        // WildcardOnDraft is unreachable: the Draft 409 branch fires above.
        // Matched exhaustively to keep the call site total.
        IfNoneMatchResult::NotMatched | IfNoneMatchResult::WildcardOnDraft => (
            StatusCode::OK,
            response_headers,
            Json(configured.config().clone()),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateOrgRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    config: Option<OrgConfig>,
}

/// `PUT /api/v1/organizations/{org_id}` — update an org's name and/or proxy
/// config on the event log.
///
/// Optimistic concurrency is revision-tokened (D5), not etag-conditioned:
/// callers send `X-Fg-If-Revision: <n>` to assert the log is still at
/// revision `n`; a mismatch responds `412` with both the caller's expected
/// and the log's current revision. A missing header writes unconditionally.
/// `If-Match`/`ETag` are no longer consulted by this handler.
///
/// A request that would not change the org's semantic state (ignoring
/// `updated_at`) is a no-op: it responds `200` with the current revision and
/// appends no event.
#[tracing::instrument(name = "update_org", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn update_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
    headers: HeaderMap,
    Json(body): Json<UpdateOrgRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return not_found();
    };

    let raw_if_revision = headers
        .get(crate::handlers::if_revision::IF_REVISION_HEADER)
        .and_then(|v| v.to_str().ok());
    let Ok(if_revision) = crate::handlers::if_revision::parse_if_revision(raw_if_revision) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid X-Fg-If-Revision header"})),
        )
            .into_response();
    };

    let record = match state.store.get(&org_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "update org: get failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let now = chrono::Utc::now();
    let mut candidate_org = record.org().clone();
    if let Some(name) = body.name {
        candidate_org = candidate_org.update_name(name, now);
    }
    let candidate_config = body.config.or_else(|| record.config().cloned());

    let stored_payload = match org_payload_json(record.org(), record.config()) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "update org: serialize stored payload failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let candidate_payload = match org_payload_json(&candidate_org, candidate_config.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "update org: serialize candidate payload failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let decision = forgeguard_authz_core::decide_upsert(
        Some(&forgeguard_authz_core::org_semantic_view(&stored_payload)),
        &forgeguard_authz_core::org_semantic_view(&candidate_payload),
    );

    if matches!(decision, forgeguard_authz_core::UpsertDecision::NoOp) {
        let current_revision = match state.model_events.latest_revision(&raw_org_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(org_id = %raw_org_id, error = %e, "update org: latest_revision failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        return (
            StatusCode::OK,
            revision_header_map(current_revision.value()),
            Json(serde_json::json!({
                "organization": record.org(),
                "revision": current_revision.value(),
            })),
        )
            .into_response();
    }

    let org = candidate_org.with_updated_at(now);
    let updated_record = OrgRecord::new(
        org.clone(),
        candidate_config.map(crate::store::ConfiguredConfig::compute),
    );
    let actor = actor_for(&raw_org_id, identity.as_ref());

    match state
        .model_events
        .update_org(updated_record, actor, if_revision)
        .await
    {
        Ok(revision) => (
            StatusCode::OK,
            revision_header_map(revision.value()),
            Json(serde_json::json!({
                "organization": org,
                "revision": revision.value(),
            })),
        )
            .into_response(),
        Err(crate::error::Error::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(crate::error::Error::RevisionMismatch { current }) => (
            StatusCode::PRECONDITION_FAILED,
            revision_header_map(current),
            Json(serde_json::json!({
                "error": "revision_mismatch",
                "current_revision": current,
                "expected_revision": if_revision.map(forgeguard_authz_core::Revision::value),
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "update org failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Build the `{"organization", "config"}` payload JSON for no-op comparison —
/// mirrors `model_event_store::org_payload`'s shape without depending on the
/// crate-private `OrgRecord`-shaped helper.
fn org_payload_json(
    org: &Organization,
    config: Option<&OrgConfig>,
) -> Result<serde_json::Value, serde_json::Error> {
    let organization = serde_json::to_value(org)?;
    let config = config.map(serde_json::to_value).transpose()?;
    Ok(forgeguard_authz_core::org_event_payload(
        &organization,
        config.as_ref(),
    ))
}

pub(crate) fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "not found"})),
    )
        .into_response()
}

/// Build a [`HeaderMap`] carrying the [`REVISION_HEADER`] for a model-plane
/// write response. Silently omits the header if `revision` can't round-trip
/// through [`HeaderValue`] (never happens for a `u64`, but avoids a panic).
fn revision_header_map(revision: u64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(&revision.to_string()) {
        headers.insert(REVISION_HEADER, val);
    }
    headers
}

/// Build a [`HeaderMap`] containing an `ETag` header when `stored_etag` is
/// `Some`. Returns an empty map for Draft orgs (no stored representation).
fn etag_header_map(stored_etag: Option<&Etag>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(etag) = stored_etag {
        if let Ok(val) = etag.as_str().parse() {
            headers.insert(axum::http::header::ETAG, val);
        }
    }
    headers
}

// ---------------------------------------------------------------------------
// Test support — shared helpers for handler tests across submodules
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(super) mod test_support {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::Router;
    use forgeguard_authn_core::static_api_key::{ApiKeyEntry, StaticApiKeyResolver};
    use forgeguard_authn_core::IdentityChain;
    use forgeguard_authz_core::{PolicyDecision, PolicyEngine, StaticPolicyEngine};
    use forgeguard_axum::{forgeguard_layer, ForgeGuard};
    use forgeguard_core::{FlagConfig, GroupName, OrganizationId, ProjectId, TenantId, UserId};
    use forgeguard_http::{
        DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
    };
    use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};

    use crate::model_event_store::ModelEventStore;
    use crate::store::{
        build_org_store, InMemoryOrgStore, InMemorySagaTicketStore, OrgStore, SagaTicketStore,
    };
    use crate::user_pool::{InMemoryUserPoolClient, UserPoolClient};
    use crate::vp_client::stub::{happy_stub, StubVpClient};

    /// Test-only handler that probes whether a group name is declared for an org.
    ///
    /// Mounted only by `test_app` at `GET /test/declared-group/{org_id}/{name}`.
    /// This route is **never** compiled into production binaries — it is gated
    /// by `#[cfg(test)]` and only wired inside `test_app`.
    pub(crate) async fn declared_group_handler(
        Path((org_id, name)): Path<(String, String)>,
        State(store): State<Arc<dyn OrgStore>>,
    ) -> Response {
        let Ok(o) = OrganizationId::new(&org_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        match store.is_declared_group(&o, &name).await {
            Ok(true) => StatusCode::OK.into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    pub const TEST_API_KEY: &str = "test-key";

    pub fn build_test_store() -> Arc<dyn OrgStore> {
        let json = r#"{
            "organizations": {
                "org-acme": {
                    "name": "Acme Corp",
                    "status": "active",
                    "config": {
                        "version": "2026-04-07",
                        "project_id": "todo-app",
                        "upstream_url": "https://api.acme.com",
                        "default_policy": "deny",
                        "routes": [],
                        "public_routes": [],
                        "features": {}
                    }
                }
            }
        }"#;
        Arc::new(build_org_store(json).unwrap())
    }

    pub fn test_app(store: Arc<dyn OrgStore>) -> Router {
        test_app_with_stub(store, happy_stub())
    }

    pub fn test_app_with_stub(store: Arc<dyn OrgStore>, vp: Arc<StubVpClient>) -> Router {
        test_app_with_principals(store, vp).0
    }

    /// Like [`test_app_with_stub`], but also exposes the in-memory
    /// [`ModelEventStore`] handle so promotion tests can seed state
    /// directly (there is no promotion-create HTTP API in this slice).
    pub fn test_app_with_principals(
        store: Arc<dyn OrgStore>,
        vp: Arc<StubVpClient>,
    ) -> (Router, Arc<dyn ModelEventStore>) {
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
        let engine: Arc<dyn PolicyEngine> =
            Arc::new(StaticPolicyEngine::new(PolicyDecision::Allow));
        let fg = Arc::new(ForgeGuard::new(config, chain, engine));

        let user_pool: Arc<dyn UserPoolClient> = Arc::new(InMemoryUserPoolClient::new());
        let saga_tickets: Arc<dyn SagaTicketStore> = Arc::new(InMemorySagaTicketStore::new());
        let model_events: Arc<dyn ModelEventStore> = Arc::new(
            crate::model_event_store::InMemoryModelEventStore::new_with_org_store(Arc::clone(
                &store,
            )),
        );
        let model_events_handle = Arc::clone(&model_events);
        let state = super::AppState {
            store,
            vp,
            user_pool,
            saga_tickets,
            model_events,
        };
        let router = Router::new()
            .route(
                "/api/v1/organizations",
                axum::routing::post(super::create_handler::<StubVpClient>).get(super::list_handler),
            )
            .route(
                "/api/v1/organizations/{org_id}",
                axum::routing::get(super::get_handler).put(super::update_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/proxy-config",
                axum::routing::get(super::proxy_config_handler),
            )
            .route(
                "/api/v1/organizations/{org_id}/keys",
                axum::routing::post(super::keys::generate_key_handler::<StubVpClient>)
                    .get(super::keys::list_keys_handler),
            )
            .route(
                "/api/v1/organizations/{org_id}/keys/{key_id}",
                axum::routing::delete(super::keys::revoke_key_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/keys/{key_id}/rotate",
                axum::routing::post(super::keys::rotate_key_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/groups",
                axum::routing::post(super::groups::create_handler::<StubVpClient>)
                    .get(super::groups::list_handler),
            )
            .route(
                "/api/v1/organizations/{org_id}/groups/{name}",
                axum::routing::get(super::groups::get_handler)
                    .put(super::groups::update_handler::<StubVpClient>)
                    .delete(super::groups::delete_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/user-schema",
                axum::routing::get(super::user_schema::get_user_schema_handler)
                    .put(super::user_schema::put_user_schema_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/users",
                axum::routing::post(super::users::create_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/principals/{native_id}",
                axum::routing::put(super::principals::upsert_principal::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/events",
                axum::routing::get(super::events::list_events_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/promoted-resources/{resource_type}/{native_id}",
                axum::routing::delete(
                    super::promotions::tombstone_promotion_handler::<StubVpClient>,
                ),
            )
            .route(
                "/api/v1/organizations/{org_id}/promoted-resources",
                axum::routing::get(super::promotions::list_promotions_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/signing-keys",
                axum::routing::get(super::signing_keys::list_signing_keys_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/activate",
                axum::routing::post(super::lifecycle::activate_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/suspend",
                axum::routing::post(super::lifecycle::suspend_handler::<StubVpClient>),
            )
            .route(
                "/api/v1/organizations/{org_id}/restore",
                axum::routing::post(super::lifecycle::restore_handler::<StubVpClient>),
            )
            .route("/metrics", axum::routing::get(super::metrics_handler))
            // Test-only probe route — never compiled into production binaries.
            // Allows tests to check `is_declared_group` via HTTP without
            // exposing the predicate through the real API surface.
            .route(
                "/test/declared-group/{org_id}/{name}",
                axum::routing::get(declared_group_handler),
            )
            .with_state(state)
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer));
        (router, model_events_handle)
    }

    pub async fn create_draft_org(
        app: &axum::Router,
        org_id: &str,
        name: &str,
    ) -> axum::response::Response {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let body = serde_json::to_vec(&serde_json::json!({
            "org_id": org_id,
            "name": name,
        }))
        .unwrap();
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/organizations")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    pub fn create_org_json(org_id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "org_id": org_id,
            "name": name,
            "config": {
                "version": "2026-04-07",
                "project_id": "proj",
                "upstream_url": "https://example.com",
                "default_policy": "deny",
                "routes": [],
                "public_routes": [],
                "features": {}
            }
        })
    }

    pub fn empty_store() -> Arc<dyn OrgStore> {
        Arc::new(InMemoryOrgStore::new(std::collections::BTreeMap::new()))
    }

    /// Concrete `Arc<InMemoryOrgStore>` for tests that need access to
    /// inherent methods (e.g. `seed_membership`) which are intentionally not on
    /// the `OrgStore` trait. Coerces to `Arc<dyn OrgStore>` at any call site
    /// that takes the trait object.
    pub fn empty_in_memory_store() -> Arc<InMemoryOrgStore> {
        Arc::new(InMemoryOrgStore::new(std::collections::BTreeMap::new()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
