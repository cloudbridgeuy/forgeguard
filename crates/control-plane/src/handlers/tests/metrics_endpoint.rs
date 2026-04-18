use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{build_test_store, test_app, TEST_API_KEY};

#[tokio::test]
async fn metrics_endpoint_returns_200_with_text_plain_content_type() {
    // Trigger a 412 first so the counter's `LazyLock` initialises and the metric
    // is registered with the default prometheus registry. Without this bootstrap,
    // `/metrics` output could omit the counter name entirely and the body assertion
    // below would flake.
    {
        let store = build_test_store();
        let app = test_app(store.clone());
        let body = serde_json::to_vec(&serde_json::json!({
            "config": {
                "version": "2026-04-07",
                "project_id": "proj",
                "upstream_url": "https://example.com",
                "default_policy": "deny",
                "routes": [],
                "public_routes": [],
                "features": {}
            }
        }))
        .unwrap();
        let _ = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/organizations/org-acme")
                    .header("x-api-key", TEST_API_KEY)
                    .header("if-match", "\"stale-for-endpoint-test\"")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

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
    assert!(
        body_str.contains("forgeguard_control_plane_put_org_412_total"),
        "metrics body must contain the 412 counter metric name"
    );
}
