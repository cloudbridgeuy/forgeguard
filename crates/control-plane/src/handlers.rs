use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{OrgStatus, Organization, OrganizationId};
use serde::Deserialize;

use crate::config::OrgConfig;
use crate::store::{OrgRecord, OrgStore};

#[derive(Debug, Deserialize)]
pub(crate) struct CreateOrgRequest {
    org_id: String,
    name: String,
    config: OrgConfig,
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
        Ok(record) => (StatusCode::CREATED, Json(record.org().clone())).into_response(),
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

pub(crate) async fn get_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return not_found();
    };

    match store.get(&org_id).await {
        Ok(Some(record)) => (StatusCode::OK, Json(record.org().clone())).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "get org failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
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

    // ETag check
    if headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|etag| etag == record.etag())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    // Return config with ETag
    let mut response_headers = HeaderMap::new();
    if let Ok(val) = record.etag().parse() {
        response_headers.insert(axum::http::header::ETAG, val);
    }

    (
        StatusCode::OK,
        response_headers,
        Json(record.config().clone()),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateOrgRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    config: Option<OrgConfig>,
}

pub(crate) async fn update_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
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

    let config = body.config.unwrap_or_else(|| record.config().clone());

    match store.update(&org_id, org, config).await {
        Ok(updated) => (StatusCode::OK, Json(updated.org().clone())).into_response(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use forgeguard_authn_core::IdentityChain;
    use forgeguard_authz_core::{PolicyDecision, PolicyEngine, StaticPolicyEngine};
    use forgeguard_axum::{forgeguard_layer, ForgeGuard};
    use forgeguard_core::{FlagConfig, ProjectId};
    use forgeguard_http::{
        DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
    };
    use forgeguard_proxy_core::PipelineConfig;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::store::{build_org_store, InMemoryOrgStore};

    fn build_test_store() -> Arc<InMemoryOrgStore> {
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

    fn test_app(store: Arc<InMemoryOrgStore>) -> Router {
        let route_matcher = RouteMatcher::new(&[]).unwrap();
        let public_routes = vec![
            PublicRoute::new(
                "GET".parse().unwrap(),
                "/health".to_string(),
                PublicAuthMode::Anonymous,
            ),
            PublicRoute::new(
                "POST".parse().unwrap(),
                "/api/v1/organizations".to_string(),
                PublicAuthMode::Anonymous,
            ),
            PublicRoute::new(
                "GET".parse().unwrap(),
                "/api/v1/organizations".to_string(),
                PublicAuthMode::Anonymous,
            ),
            PublicRoute::new(
                "GET".parse().unwrap(),
                "/api/v1/organizations/{org_id}".to_string(),
                PublicAuthMode::Anonymous,
            ),
            PublicRoute::new(
                "PUT".parse().unwrap(),
                "/api/v1/organizations/{org_id}".to_string(),
                PublicAuthMode::Anonymous,
            ),
            PublicRoute::new(
                "DELETE".parse().unwrap(),
                "/api/v1/organizations/{org_id}".to_string(),
                PublicAuthMode::Anonymous,
            ),
            PublicRoute::new(
                "GET".parse().unwrap(),
                "/api/v1/organizations/{org_id}/proxy-config".to_string(),
                PublicAuthMode::Anonymous,
            ),
        ];
        let public_route_matcher = PublicRouteMatcher::new(&public_routes).unwrap();
        let config = PipelineConfig::new(
            route_matcher,
            public_route_matcher,
            FlagConfig::default(),
            ProjectId::new("test").unwrap(),
            DefaultPolicy::Passthrough,
            false,
            vec![],
        );
        let chain = IdentityChain::new(vec![]);
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
            .with_state(store)
            .layer(axum::middleware::from_fn_with_state(fg, forgeguard_layer))
    }

    #[tokio::test]
    async fn returns_200_for_valid_org() {
        let store = build_test_store();
        let app = test_app(store);

        let request = Request::builder()
            .uri("/api/v1/organizations/org-acme/proxy-config")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Check ETag header exists
        assert!(response.headers().get("etag").is_some());

        // Check body is valid JSON containing project_id
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["project_id"], "todo-app");
    }

    #[tokio::test]
    async fn returns_404_for_unknown_org() {
        let store = build_test_store();
        let app = test_app(store);

        let request = Request::builder()
            .uri("/api/v1/organizations/org-unknown/proxy-config")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_304_on_matching_etag() {
        let store = build_test_store();

        // First request: get the ETag
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .uri("/api/v1/organizations/org-acme/proxy-config")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let etag = response
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Second request: send the ETag back via If-None-Match
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations/org-acme/proxy-config")
            .header("if-none-match", &etag)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn returns_200_on_non_matching_etag() {
        let store = build_test_store();
        let app = test_app(store);

        let request = Request::builder()
            .uri("/api/v1/organizations/org-acme/proxy-config")
            .header("if-none-match", "\"stale\"")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Should still return ETag and full body
        assert!(response.headers().get("etag").is_some());
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["project_id"], "todo-app");
    }

    // ── Create + Get tests ─────────────────────────────────────────

    fn create_org_json(org_id: &str, name: &str) -> serde_json::Value {
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

    fn empty_store() -> Arc<InMemoryOrgStore> {
        Arc::new(InMemoryOrgStore::new(std::collections::BTreeMap::new()))
    }

    #[tokio::test]
    async fn create_and_get_org() {
        let store = empty_store();
        let app = test_app(Arc::clone(&store));

        let body = serde_json::to_string(&create_org_json("org-new", "New Org")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], "New Org");
        assert_eq!(json["status"], "draft");
        assert_eq!(json["org_id"], "org-new");

        // GET the created org
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations/org-new")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], "New Org");
        assert_eq!(json["status"], "draft");
    }

    #[tokio::test]
    async fn create_duplicate_returns_409() {
        let store = empty_store();

        // First create
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-dup", "First")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Duplicate create
        let app = test_app(store);
        let body = serde_json::to_string(&create_org_json("org-dup", "Second")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_invalid_org_id_returns_422() {
        let store = empty_store();
        let app = test_app(store);

        let body = serde_json::to_string(&create_org_json("UPPERCASE", "Bad")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn get_unknown_org_returns_404() {
        let store = empty_store();
        let app = test_app(store);

        let request = Request::builder()
            .uri("/api/v1/organizations/org-nope")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── List tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn list_orgs_empty_then_populated() {
        let store = empty_store();

        // List empty
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .uri("/api/v1/organizations")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert!(json.is_empty());

        // Create an org
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-alpha", "Alpha")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // List populated
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["name"], "Alpha");
    }

    #[tokio::test]
    async fn list_orgs_pagination() {
        let store = empty_store();

        // Create 3 orgs
        for i in 0..3 {
            let app = test_app(Arc::clone(&store));
            let body =
                serde_json::to_string(&create_org_json(&format!("org-{i}"), &format!("Org {i}")))
                    .unwrap();
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/organizations")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        // List with limit=2
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations?limit=2")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json.len(), 2);
    }

    // ── Update tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn update_changes_name() {
        let store = empty_store();

        // Create org
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-upd", "Original")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Update name
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&serde_json::json!({"name": "Renamed"})).unwrap();
        let request = Request::builder()
            .method("PUT")
            .uri("/api/v1/organizations/org-upd")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], "Renamed");

        // GET to verify persistence
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations/org-upd")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], "Renamed");
    }

    #[tokio::test]
    async fn update_replaces_config() {
        let store = empty_store();

        // Create org
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-cfg", "Cfg Org")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Update config
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&serde_json::json!({
            "config": {
                "version": "2026-04-08",
                "project_id": "new-proj",
                "upstream_url": "https://new-upstream.com",
                "default_policy": "passthrough"
            }
        }))
        .unwrap();
        let request = Request::builder()
            .method("PUT")
            .uri("/api/v1/organizations/org-cfg")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // GET proxy-config to verify
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations/org-cfg/proxy-config")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["upstream_url"], "https://new-upstream.com");
        assert_eq!(json["default_policy"], "passthrough");
    }

    #[tokio::test]
    async fn update_unknown_org_returns_404() {
        let store = empty_store();
        let app = test_app(store);

        let body = serde_json::to_string(&serde_json::json!({"name": "Ghost"})).unwrap();
        let request = Request::builder()
            .method("PUT")
            .uri("/api/v1/organizations/org-unknown")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── Delete tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn delete_draft_org() {
        let store = empty_store();

        // Create a draft org
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-del", "To Delete")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Delete it
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/v1/organizations/org-del")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // GET should return 404
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations/org-del")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_active_org() {
        // File-loaded orgs are Active
        let store = build_test_store();

        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/v1/organizations/org-acme")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // GET should return 404
        let app = test_app(store);
        let request = Request::builder()
            .uri("/api/v1/organizations/org-acme")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_already_deleted_returns_404() {
        let store = empty_store();

        // Create then delete
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-gone", "Gone")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/v1/organizations/org-gone")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Second delete is idempotent — still 204
        let app = test_app(store);
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/v1/organizations/org-gone")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_unknown_org_returns_204() {
        let store = empty_store();
        let app = test_app(store);

        let request = Request::builder()
            .method("DELETE")
            .uri("/api/v1/organizations/org-nope")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
