use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_core::OrganizationId;

use crate::auth::{self, BearerToken};
use crate::store::OrgStore;

pub(crate) async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

pub(crate) async fn proxy_config_handler(
    State(store): State<Arc<dyn OrgStore>>,
    Path(raw_org_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth::extract_bearer_token(auth_header) {
        BearerToken::Valid(t) => t,
        BearerToken::Missing | BearerToken::Invalid => {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer"),
            );
            return (
                StatusCode::UNAUTHORIZED,
                headers,
                Json(serde_json::json!({"error": "missing or invalid authorization token"})),
            )
                .into_response();
        }
    };

    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return not_found();
    };

    let Some(entry) = store.get(&org_id) else {
        return not_found();
    };

    if !auth::token_matches_org(token, entry.token()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "token not authorized for this organization"})),
        )
            .into_response();
    }

    if headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|etag| etag == entry.etag())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }

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
    use axum::http::{header, Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use forgeguard_core::OrganizationId;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::config::OrgProxyConfig;
    use crate::store::{OrgConfigStore, OrgEntry, OrgStore};

    const TEST_TOKEN: &str = "fgt_acme-test-token";
    const TEST_ORG: &str = "org-acme";

    fn test_config() -> OrgProxyConfig {
        OrgProxyConfig {
            organization_id: TEST_ORG.to_string(),
            cognito_pool_id: "us-east-1_Test".to_string(),
            cognito_jwks_url: "https://example.com/.well-known/jwks.json".to_string(),
            policy_store_id: "ps-test".to_string(),
            project_id: "test-project".to_string(),
            upstream_url: "https://api.test.com".to_string(),
            default_policy: "deny".to_string(),
            routes: vec![],
            public_routes: vec![],
            features: Default::default(),
        }
    }

    fn test_store() -> Arc<dyn OrgStore> {
        let org_id = OrganizationId::new(TEST_ORG).unwrap();
        let entry = OrgEntry::new(test_config(), TEST_TOKEN.to_string()).unwrap();
        let store = OrgConfigStore::from_entries(vec![(org_id, entry)]);
        Arc::new(store)
    }

    fn test_router() -> Router {
        let store = test_store();
        Router::new()
            .route(
                "/api/v1/organizations/{org_id}/proxy-config",
                get(super::proxy_config_handler),
            )
            .with_state(store)
    }

    async fn body_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn returns_200_with_valid_token() {
        let app = test_router();
        let req = Request::get("/api/v1/organizations/org-acme/proxy-config")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify ETag is present
        assert!(resp.headers().get(header::ETAG).is_some());

        // Verify response body contains org config
        let body = body_string(resp.into_body()).await;
        assert!(body.contains("org-acme"));
        assert!(body.contains("deny"));
    }

    #[tokio::test]
    async fn returns_401_without_token() {
        let app = test_router();
        let req = Request::get("/api/v1/organizations/org-acme/proxy-config")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Verify WWW-Authenticate header
        let www_auth = resp.headers().get(header::WWW_AUTHENTICATE).unwrap();
        assert_eq!(www_auth, "Bearer");
    }

    #[tokio::test]
    async fn returns_401_with_invalid_token() {
        let app = test_router();
        let req = Request::get("/api/v1/organizations/org-acme/proxy-config")
            .header(header::AUTHORIZATION, "Bearer not-a-fgt-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn returns_403_with_wrong_org_token() {
        let app = test_router();
        let req = Request::get("/api/v1/organizations/org-acme/proxy-config")
            .header(header::AUTHORIZATION, "Bearer fgt_wrong-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_404_for_unknown_org() {
        let app = test_router();
        let req = Request::get("/api/v1/organizations/org-unknown/proxy-config")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_304_on_matching_etag() {
        let app = test_router();

        // First request to get the ETag
        let req = Request::get("/api/v1/organizations/org-acme/proxy-config")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let etag = resp
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Second request with If-None-Match
        let req = Request::get("/api/v1/organizations/org-acme/proxy-config")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn returns_200_on_non_matching_etag() {
        let app = test_router();
        let req = Request::get("/api/v1/organizations/org-acme/proxy-config")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .header(header::IF_NONE_MATCH, "\"stale-etag\"")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
