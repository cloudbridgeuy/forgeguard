use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{build_test_store, test_app, TEST_API_KEY};

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let store = build_test_store();
    let app = test_app(store);

    let request = Request::builder()
        .uri("/api/v1/organizations")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_200_for_valid_org() {
    let store = build_test_store();
    let app = test_app(store);

    let request = Request::builder()
        .uri("/api/v1/organizations/org-acme/proxy-config")
        .header("x-api-key", TEST_API_KEY)
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
        .header("x-api-key", TEST_API_KEY)
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
        .header("x-api-key", TEST_API_KEY)
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
        .header("x-api-key", TEST_API_KEY)
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
        .header("x-api-key", TEST_API_KEY)
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
