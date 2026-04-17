use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{empty_store, test_app, TEST_API_KEY};

// ── Draft (no config) tests — issue #76 ────────────────────────

/// `POST /api/v1/organizations` accepts a body with no `config` field
/// and creates a Draft org.
#[tokio::test]
async fn create_without_config_returns_201_draft() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));

    let body = serde_json::to_string(&serde_json::json!({
        "org_id": "org-draft",
        "name": "Draft Org"
    }))
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["org_id"], "org-draft");
    assert_eq!(json["name"], "Draft Org");
    assert_eq!(json["status"], "draft");

    // GET round-trips
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-draft")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// `GET /api/v1/organizations/{org_id}/proxy-config` on a Draft org
/// returns 409 Conflict, distinguishing from 404 ("org not found").
#[tokio::test]
async fn proxy_config_on_draft_org_returns_409() {
    let store = empty_store();

    // Create a Draft org (no config)
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&serde_json::json!({
        "org_id": "org-draft-cfg",
        "name": "Draft"
    }))
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Proxy-config returns 409, not 404
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-draft-cfg/proxy-config")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("org-draft-cfg"),
        "error body must name the org: {json}"
    );
}

/// `PUT /api/v1/organizations/{org_id}` with a `config` body sets the
/// config on a Draft org, after which proxy-config returns 200.
#[tokio::test]
async fn put_config_on_draft_org_makes_proxy_config_200() {
    let store = empty_store();

    // Create Draft
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&serde_json::json!({
        "org_id": "org-set-cfg",
        "name": "Will Configure"
    }))
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // PUT a config
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "p1",
            "upstream_url": "https://example.com",
            "default_policy": "deny"
        }
    }))
    .unwrap();
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/organizations/org-set-cfg")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Proxy-config now returns 200 with ETag
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-set-cfg/proxy-config")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("etag").is_some());
}

/// `PUT` with no `config` on a Draft org keeps it Draft (no-op for config).
#[tokio::test]
async fn put_without_config_keeps_draft_state() {
    let store = empty_store();

    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&serde_json::json!({
        "org_id": "org-keep-draft",
        "name": "Keep Draft"
    }))
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // PUT only the name
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&serde_json::json!({"name": "Renamed"})).unwrap();
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/organizations/org-keep-draft")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Proxy-config still 409
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-keep-draft/proxy-config")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// `proxy-config` on a totally unknown org id stays 404 — distinct from 409.
#[tokio::test]
async fn proxy_config_on_unknown_org_returns_404_not_409() {
    let store = empty_store();
    let app = test_app(store);

    let request = Request::builder()
        .uri("/api/v1/organizations/org-ghost/proxy-config")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
