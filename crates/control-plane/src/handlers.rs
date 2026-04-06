use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::OrganizationId;

use crate::store::OrgStore;

pub(crate) async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

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
    let Some(entry) = store.get(&org_id) else {
        return not_found();
    };

    // ETag check
    if headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|etag| etag == entry.etag())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    // Return config with ETag
    let mut response_headers = HeaderMap::new();
    if let Ok(val) = entry.etag().parse() {
        response_headers.insert(axum::http::header::ETAG, val);
    }

    (
        StatusCode::OK,
        response_headers,
        Json(entry.config().clone()),
    )
        .into_response()
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
    use forgeguard_core::{FlagConfig, OrganizationId, ProjectId};
    use forgeguard_http::{
        DefaultPolicy, PublicAuthMode, PublicRoute, PublicRouteMatcher, RouteMatcher,
    };
    use forgeguard_proxy_core::PipelineConfig;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::config::OrgProxyConfig;
    use crate::store::{OrgConfigStore, OrgEntry, OrgStore};

    fn build_test_store() -> Arc<dyn OrgStore> {
        let config: OrgProxyConfig = serde_json::from_value(serde_json::json!({
            "organization_id": "org-acme",
            "cognito_pool_id": "us-east-1_ABC",
            "cognito_jwks_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC/.well-known/jwks.json",
            "policy_store_id": "ps-123",
            "project_id": "todo-app",
            "upstream_url": "https://api.acme.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }))
        .unwrap();

        let org_id = OrganizationId::new("org-acme").unwrap();
        let entry = OrgEntry::new(config).unwrap();
        let store = OrgConfigStore::from_entries(vec![(org_id, entry)]);
        Arc::new(store)
    }

    fn test_app(store: Arc<dyn OrgStore>) -> Router {
        let route_matcher = RouteMatcher::new(&[]).unwrap();
        let public_routes = vec![
            PublicRoute::new(
                "GET".parse().unwrap(),
                "/health".to_string(),
                PublicAuthMode::Anonymous,
            ),
            // Make the proxy-config path public so tests don't need auth
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
                "/api/v1/organizations/{org_id}/proxy-config",
                axum::routing::get(super::proxy_config_handler),
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

        // Check body is valid JSON containing organization_id
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["organization_id"], "org-acme");
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
        assert_eq!(json["organization_id"], "org-acme");
    }
}
