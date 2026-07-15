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

#[test]
fn clamp_limit_caps_above_maximum_and_passes_through_below() {
    use super::super::clamp_limit;

    assert_eq!(clamp_limit(50), 50);
    assert_eq!(clamp_limit(1000), 1000);
    // Above the 1000 ceiling: clamped, not silently truncated to something
    // else and not rejected — this is a unit test on the pure clamp function
    // rather than an end-to-end 1001-event push, since pushing >1000 events
    // through the in-memory log in a handler test would be slow and add no
    // additional coverage over exercising the clamp logic directly.
    assert_eq!(clamp_limit(u16::MAX), 1000);
}
