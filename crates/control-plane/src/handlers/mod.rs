mod keys;

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{OrgStatus, Organization, OrganizationId};
use serde::{Deserialize, Serialize};

use crate::config::OrgConfig;
use crate::etag::{self, Etag, IfNoneMatchResult, ResolvedIfMatch};
use crate::store::{OrgRecord, OrgStore};

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

pub(crate) async fn create_handler<S: OrgStore>(
    State(store): State<Arc<S>>,
    Json(body): Json<CreateOrgRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&body.org_id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid org_id"})),
        )
            .into_response();
    };

    let now = chrono::Utc::now();
    let org = Organization::new(org_id, body.name, OrgStatus::Draft, now);

    match store.create(org, body.config).await {
        Ok(record) => {
            let mut response_headers = HeaderMap::new();
            if let Some(val) = record
                .configured()
                .and_then(|c| c.etag().as_str().parse().ok())
            {
                response_headers.insert(axum::http::header::ETAG, val);
            }
            (
                StatusCode::CREATED,
                response_headers,
                Json(record.org().clone()),
            )
                .into_response()
        }
        Err(crate::error::Error::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "create org failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[tracing::instrument(
    name = "show_org",
    skip_all,
    fields(org_id = %raw_org_id, if_none_match_hit = tracing::field::Empty),
)]
pub(crate) async fn get_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
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

pub(crate) async fn list_handler<S: OrgStore>(
    Query(params): Query<ListParams>,
    State(store): State<Arc<S>>,
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
pub(crate) async fn proxy_config_handler<S: OrgStore>(
    ForgeGuardIdentity(_identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
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
        // NotMatched: header absent, stale etag, or strong match against a
        // Draft org — return the full config.
        // WildcardOnDraft: unreachable here because the Draft branch above
        // already returned 409; matched exhaustively to keep the call site total.
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

/// `PUT /api/v1/organizations/{org_id}` — update an org's name and/or proxy config.
///
/// Supports optimistic locking via `If-Match`: when the request body includes
/// `config`, the `If-Match` header is checked against the stored etag. A
/// missing header writes unconditionally. Name-only PUTs skip the check.
///
/// Returns `200 OK` with an `ETag` header on success, `412 Precondition Failed`
/// (also with the current `ETag`) on a stale match, and `404 Not Found` when
/// the org does not exist.
#[tracing::instrument(
    name = "update_org",
    skip_all,
    fields(org_id = %raw_org_id, precondition_reason = tracing::field::Empty)
)]
pub(crate) async fn update_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
    headers: HeaderMap,
    Json(body): Json<UpdateOrgRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return not_found();
    };

    let record = match store.get(&org_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "update org: get failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let now = chrono::Utc::now();
    let mut org = record.org().clone();
    if let Some(name) = body.name {
        org = org.update_name(name, now);
    }
    org = org.with_updated_at(now);

    // If the body omits `config`, keep whatever was previously stored
    // (None for Draft orgs, Some(...) for Configured ones).
    let caller_supplied_config = body.config.is_some();
    let config = body.config.or_else(|| record.config().cloned());

    // Derive the optimistic-locking expectation. Name-only PUTs (no `config`
    // in the body) are unconditional; all other cases go through resolve_if_match.
    let if_match_parsed = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match);
    let stored_etag = record
        .configured()
        .map(crate::store::ConfiguredConfig::etag);
    let resolved = if caller_supplied_config {
        etag::resolve_if_match(if_match_parsed, stored_etag)
    } else {
        ResolvedIfMatch::Absent
    };
    // `expected_etag` is `Option<Etag>` — `Some` means a strong check is required,
    // `None` means unconditional write (Absent or WildcardMatched paths).
    let expected_etag: Option<Etag> = match &resolved {
        ResolvedIfMatch::Absent => None,
        ResolvedIfMatch::Strong(e) => Some(e.clone()),
        // Wildcard with existing config — unconditional write; check already passed.
        ResolvedIfMatch::WildcardMatched => None,
        // Wildcard on a Draft org — fail closed: no stored representation exists.
        ResolvedIfMatch::WildcardOnDraft => {
            crate::metrics::record_precondition_failed(
                crate::metrics::PreconditionReason::WildcardOnDraft,
            );
            return (
                StatusCode::PRECONDITION_FAILED,
                Json(PreconditionFailedBody {
                    error: "etag mismatch",
                    reason: crate::metrics::PreconditionReason::WildcardOnDraft.as_label(),
                    // Draft org has no stored etag — emit empty string on the wire.
                    current_etag: String::new(),
                }),
            )
                .into_response();
        }
    };

    match store
        .update(&org_id, org, config, expected_etag.as_ref())
        .await
    {
        Ok(updated) => {
            let mut response_headers = HeaderMap::new();
            if let Some(val) = updated
                .configured()
                .and_then(|c| c.etag().as_str().parse().ok())
            {
                response_headers.insert(axum::http::header::ETAG, val);
            }
            (
                StatusCode::OK,
                response_headers,
                Json(updated.org().clone()),
            )
                .into_response()
        }
        Err(crate::error::Error::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(crate::error::Error::PreconditionFailed { current_etag }) => {
            // `record` is the pre-update snapshot; the store returned 412
            // without mutating it, so its `configured()` etag still reflects
            // the state the decision was made against. This is what
            // `precondition_reason` needs to distinguish `DraftFailClosed`
            // (stored == None) from `StaleEtag` (stored == Some).
            let reason = crate::metrics::precondition_reason(
                &resolved,
                record
                    .configured()
                    .map(crate::store::ConfiguredConfig::etag),
            );
            crate::metrics::record_precondition_failed(reason);
            let mut response_headers = HeaderMap::new();
            // Only emit ETag when `current_etag` is `Some`. `None` signals a
            // Draft org (no config yet) — there is no etag to include.
            let current_etag_str = match current_etag {
                Some(ref etag) => {
                    if let Ok(val) = etag.as_str().parse() {
                        response_headers.insert(axum::http::header::ETAG, val);
                    }
                    etag.as_str().to_string()
                }
                None => String::new(),
            };
            (
                StatusCode::PRECONDITION_FAILED,
                response_headers,
                Json(PreconditionFailedBody {
                    error: "etag mismatch",
                    reason: reason.as_label(),
                    current_etag: current_etag_str,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "update org failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) async fn delete_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return StatusCode::NO_CONTENT.into_response();
    };

    match store.delete(&org_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "delete org failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "not found"})),
    )
        .into_response()
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

    use axum::Router;
    use forgeguard_authn_core::static_api_key::{ApiKeyEntry, StaticApiKeyResolver};
    use forgeguard_authn_core::IdentityChain;
    use forgeguard_authz_core::{PolicyDecision, PolicyEngine, StaticPolicyEngine};
    use forgeguard_axum::{forgeguard_layer, ForgeGuard};
    use forgeguard_core::{FlagConfig, GroupName, ProjectId, TenantId, UserId};
    use forgeguard_http::{
        DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
    };
    use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};

    use crate::store::{build_org_store, InMemoryOrgStore};

    pub const TEST_API_KEY: &str = "test-key";

    pub fn build_test_store() -> Arc<InMemoryOrgStore> {
        let json = r#"{
            "organizations": {
                "org-acme": {
                    "name": "Acme Corp",
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

    pub fn test_app(store: Arc<InMemoryOrgStore>) -> Router {
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

        Router::new()
            .route(
                "/api/v1/organizations",
                axum::routing::post(super::create_handler::<InMemoryOrgStore>)
                    .get(super::list_handler::<InMemoryOrgStore>),
            )
            .route(
                "/api/v1/organizations/{org_id}",
                axum::routing::get(super::get_handler::<InMemoryOrgStore>)
                    .put(super::update_handler::<InMemoryOrgStore>)
                    .delete(super::delete_handler::<InMemoryOrgStore>),
            )
            .route(
                "/api/v1/organizations/{org_id}/proxy-config",
                axum::routing::get(super::proxy_config_handler::<InMemoryOrgStore>),
            )
            .route(
                "/api/v1/organizations/{org_id}/keys",
                axum::routing::post(super::keys::generate_key_handler::<InMemoryOrgStore>)
                    .get(super::keys::list_keys_handler::<InMemoryOrgStore>),
            )
            .route(
                "/api/v1/organizations/{org_id}/keys/{key_id}",
                axum::routing::delete(super::keys::revoke_key_handler::<InMemoryOrgStore>),
            )
            .route(
                "/api/v1/organizations/{org_id}/keys/{key_id}/rotate",
                axum::routing::post(super::keys::rotate_key_handler::<InMemoryOrgStore>),
            )
            .route("/metrics", axum::routing::get(super::metrics_handler))
            .with_state(store)
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer))
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

    pub fn empty_store() -> Arc<InMemoryOrgStore> {
        Arc::new(InMemoryOrgStore::new(std::collections::BTreeMap::new()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
