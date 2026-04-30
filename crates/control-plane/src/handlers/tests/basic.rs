use axum::body::Body;
use axum::http::{Request, StatusCode};
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
