use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{build_test_store, test_app, TEST_API_KEY};

// -----------------------------------------------------------------
// Conditional GET tests (A1) — If-None-Match / 304 / ETag on
// GET /organizations/{id}/proxy-config
// -----------------------------------------------------------------

/// Fetch the stored ETag for org-acme by performing an unconditional GET.
async fn get_stored_etag(app: axum::Router) -> String {
    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    res.headers()
        .get(axum::http::header::ETAG)
        .expect("initial GET must include ETag")
        .to_str()
        .unwrap()
        .to_string()
}

/// Smoke: GET proxy-config without any `If-None-Match` header.
/// Expects 200 + JSON body + ETag response header.
#[tokio::test]
async fn proxy_config_no_if_none_match_returns_200_with_body_and_etag() {
    let app = test_app(build_test_store());

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_some(),
        "Configured org proxy-config GET must include an ETag header"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["project_id"], "todo-app");
}

/// Wildcard `If-None-Match: *` against a Configured org.
/// Expects 304 + ETag header echoing the stored etag.
#[tokio::test]
async fn proxy_config_wildcard_if_none_match_on_configured_returns_304_with_etag() {
    let app = test_app(build_test_store());
    let stored_etag = get_stored_etag(app.clone()).await;

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", "*")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    let response_etag = res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("304 for wildcard on Configured org must include ETag")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        response_etag, stored_etag,
        "304 ETag must echo the stored etag"
    );

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert!(body_bytes.is_empty(), "304 body must be empty");
}

/// Strong `If-None-Match: <stored etag>` against a Configured org.
/// Expects 304 — strong-match still works after the refactor.
#[tokio::test]
async fn proxy_config_strong_matching_if_none_match_returns_304() {
    let app = test_app(build_test_store());
    let etag = get_stored_etag(app.clone()).await;

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    let response_etag = res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("304 must include ETag header")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(response_etag, etag, "304 ETag must match the original");

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert!(body_bytes.is_empty(), "304 body must be empty");
}

/// Stale `If-None-Match: <stale etag>` against a Configured org.
/// Expects 200 + body + ETag (parity check).
#[tokio::test]
async fn proxy_config_stale_if_none_match_returns_200_with_body_and_etag() {
    let app = test_app(build_test_store());
    let stored_etag = get_stored_etag(app.clone()).await;

    let stale_value = "\"definitely-not-the-etag\"";

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", stale_value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let etag_header = res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("200 on stale If-None-Match must include ETag")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        etag_header, stored_etag,
        "200 ETag must echo the stored value"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["project_id"], "todo-app");
}
