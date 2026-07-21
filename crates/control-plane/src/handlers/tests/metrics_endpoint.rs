use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{build_test_store, test_app};

#[tokio::test]
async fn metrics_endpoint_returns_200_with_text_plain_content_type() {
    let store = build_test_store();
    let app = test_app(store.clone());

    // Request /metrics without any auth header — must succeed anonymously.
    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let content_type = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .expect("content-type header must be present")
        .to_str()
        .unwrap();
    assert!(
        content_type.starts_with("text/plain"),
        "content-type must start with text/plain, got: {content_type}"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&bytes).unwrap();
    // #117 V2: no VP push, nothing to roll back — the metric must stay gone.
    assert!(
        !body_str.contains("forgeguard_cp_group_rollback_failed_total"),
        "retired rollback metric must not appear in /metrics output"
    );
}
