use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{
    build_test_store, create_draft_org, empty_store, test_app, TEST_API_KEY,
};

// -----------------------------------------------------------------
// Conditional GET tests (A-3) — If-None-Match / 304 / ETag on GET /organizations/{id}
// -----------------------------------------------------------------

/// Baseline: GET a Configured org without any `If-None-Match` header.
/// Expects 200 + JSON body + ETag response header.
#[tokio::test]
async fn get_without_if_none_match_returns_200_with_body_and_etag() {
    let app = test_app(build_test_store());

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_some(),
        "Configured org GET must include an ETag header"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["org_id"], "org-acme");
}

/// Conditional GET: send a matching `If-None-Match`. Expects 304 + ETag, empty body.
#[tokio::test]
async fn get_with_matching_if_none_match_returns_304_and_etag_no_body() {
    let app = test_app(build_test_store());

    // First GET: capture the current ETag.
    let first_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_res.status(), StatusCode::OK);
    let etag = first_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("first GET must include ETag")
        .to_str()
        .unwrap()
        .to_string();

    // Second GET: send the captured ETag as If-None-Match.
    let second_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(second_res.status(), StatusCode::NOT_MODIFIED);
    let response_etag = second_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("304 must include ETag header")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(response_etag, etag, "304 ETag must match the original");

    // Body must be empty.
    let body_bytes = second_res.into_body().collect().await.unwrap().to_bytes();
    assert!(body_bytes.is_empty(), "304 body must be empty");
}

/// Stale `If-None-Match`: etag differs from stored. Expects 200 + body + ETag.
#[tokio::test]
async fn get_with_stale_if_none_match_returns_200_with_body() {
    let app = test_app(build_test_store());

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", "\"definitely-not-the-etag\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let stale_value = "\"definitely-not-the-etag\"";

    assert_eq!(res.status(), StatusCode::OK);
    let etag_header = res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("200 on stale If-None-Match must include ETag")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(
        etag_header, stale_value,
        "response ETag must be the stored etag, not the stale request value"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["org_id"], "org-acme");
}

/// Wildcard `If-None-Match: *` on a Configured org. Expects 304 + ETag.
#[tokio::test]
async fn get_wildcard_if_none_match_on_configured_returns_304() {
    let app = test_app(build_test_store());

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", "*")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_some(),
        "304 for wildcard on Configured org must include ETag"
    );

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert!(body_bytes.is_empty(), "304 body must be empty");
}

/// Wildcard `If-None-Match: *` on a Draft org (no stored etag). Expects 200 + body, no ETag.
#[tokio::test]
async fn get_wildcard_if_none_match_on_draft_returns_200_with_body() {
    let app = test_app(empty_store());

    let create_res = create_draft_org(&app, "org-v5-cond-draft", "V5 Conditional Draft").await;
    assert_eq!(create_res.status(), StatusCode::CREATED);

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-v5-cond-draft")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", "*")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_none(),
        "Draft org GET must NOT include an ETag header"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["org_id"], "org-v5-cond-draft");
}

/// Strong `If-None-Match` on a Draft org (no stored etag). Expects 200 + body, no ETag.
#[tokio::test]
async fn get_strong_if_none_match_on_draft_returns_200_with_body() {
    let app = test_app(empty_store());

    let create_res = create_draft_org(
        &app,
        "org-v5-cond-draft-strong",
        "V5 Conditional Draft Strong",
    )
    .await;
    assert_eq!(create_res.status(), StatusCode::CREATED);

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-v5-cond-draft-strong")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", "\"something\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_none(),
        "Draft org GET must NOT include an ETag header"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["org_id"], "org-v5-cond-draft-strong");
}

/// Malformed (whitespace-only) `If-None-Match` degrades gracefully: same as no header.
/// Expects 200 + body + ETag.
#[tokio::test]
async fn get_malformed_if_none_match_returns_200() {
    let app = test_app(build_test_store());

    let res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-none-match", "   ")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_some(),
        "200 on malformed If-None-Match must include ETag (same as no header)"
    );

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["org_id"], "org-acme");
}
