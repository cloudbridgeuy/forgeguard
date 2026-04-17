use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::test_support::{build_test_store, create_org_json, empty_store, test_app, TEST_API_KEY};

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

// ── Create + Get tests ─────────────────────────────────────────

#[tokio::test]
async fn create_and_get_org() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));

    let body = serde_json::to_string(&create_org_json("org-new", "New Org")).unwrap();
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
    assert_eq!(json["name"], "New Org");
    assert_eq!(json["status"], "draft");
    assert_eq!(json["org_id"], "org-new");

    // GET the created org
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-new")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["name"], "New Org");
    assert_eq!(json["status"], "draft");
}

#[tokio::test]
async fn create_duplicate_returns_409() {
    let store = empty_store();

    // First create
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&create_org_json("org-dup", "First")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Duplicate create
    let app = test_app(store);
    let body = serde_json::to_string(&create_org_json("org-dup", "Second")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_invalid_org_id_returns_422() {
    let store = empty_store();
    let app = test_app(store);

    let body = serde_json::to_string(&create_org_json("UPPERCASE", "Bad")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn get_unknown_org_returns_404() {
    let store = empty_store();
    let app = test_app(store);

    let request = Request::builder()
        .uri("/api/v1/organizations/org-nope")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── List tests ─────────────────────────────────────────────────

#[tokio::test]
async fn list_orgs_empty_then_populated() {
    let store = empty_store();

    // List empty
    let app = test_app(Arc::clone(&store));
    let request = Request::builder()
        .uri("/api/v1/organizations")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert!(json.is_empty());

    // Create an org
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&create_org_json("org-alpha", "Alpha")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // List populated
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json.len(), 1);
    assert_eq!(json[0]["name"], "Alpha");
}

#[tokio::test]
async fn list_orgs_pagination() {
    let store = empty_store();

    // Create 3 orgs
    for i in 0..3 {
        let app = test_app(Arc::clone(&store));
        let body =
            serde_json::to_string(&create_org_json(&format!("org-{i}"), &format!("Org {i}")))
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
    }

    // List with limit=2
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations?limit=2")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json.len(), 2);
}

// ── Update tests ───────────────────────────────────────────────

#[tokio::test]
async fn update_changes_name() {
    let store = empty_store();

    // Create org
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&create_org_json("org-upd", "Original")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Update name
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&serde_json::json!({"name": "Renamed"})).unwrap();
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/organizations/org-upd")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["name"], "Renamed");

    // GET to verify persistence
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-upd")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["name"], "Renamed");
}

#[tokio::test]
async fn update_replaces_config() {
    let store = empty_store();

    // Create org
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&create_org_json("org-cfg", "Cfg Org")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Update config
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&serde_json::json!({
        "config": {
            "version": "2026-04-08",
            "project_id": "new-proj",
            "upstream_url": "https://new-upstream.com",
            "default_policy": "passthrough"
        }
    }))
    .unwrap();
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/organizations/org-cfg")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // GET proxy-config to verify
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-cfg/proxy-config")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["upstream_url"], "https://new-upstream.com");
    assert_eq!(json["default_policy"], "passthrough");
}

#[tokio::test]
async fn update_unknown_org_returns_404() {
    let store = empty_store();
    let app = test_app(store);

    let body = serde_json::to_string(&serde_json::json!({"name": "Ghost"})).unwrap();
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/organizations/org-unknown")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Delete tests ───────────────────────────────────────────────

#[tokio::test]
async fn delete_draft_org() {
    let store = empty_store();

    // Create a draft org
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&create_org_json("org-del", "To Delete")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Delete it
    let app = test_app(Arc::clone(&store));
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/organizations/org-del")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // GET should return 404
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-del")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_active_org() {
    // File-loaded orgs are Active
    let store = build_test_store();

    let app = test_app(Arc::clone(&store));
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/organizations/org-acme")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // GET should return 404
    let app = test_app(store);
    let request = Request::builder()
        .uri("/api/v1/organizations/org-acme")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_already_deleted_returns_204() {
    let store = empty_store();

    // Create then delete
    let app = test_app(Arc::clone(&store));
    let body = serde_json::to_string(&create_org_json("org-gone", "Gone")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/organizations/org-gone")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Second delete is idempotent — still 204
    let app = test_app(store);
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/organizations/org-gone")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_unknown_org_returns_204() {
    let store = empty_store();
    let app = test_app(store);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/organizations/org-nope")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

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

// -----------------------------------------------------------------
// Optimistic-locking tests (issue #56, V1)
// -----------------------------------------------------------------

#[tokio::test]
async fn update_with_matching_if_match_returns_200_and_new_etag() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let get_res = app
        .clone()
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
    assert_eq!(get_res.status(), StatusCode::OK);
    let current_etag = get_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("etag header")
        .to_str()
        .unwrap()
        .to_string();

    let new_config = serde_json::json!({
        "version": "2026-04-07",
        "project_id": "todo-app",
        "upstream_url": "https://api.v2.acme.com",
        "default_policy": "deny",
        "routes": [],
        "public_routes": [],
        "features": {}
    });
    let body = serde_json::to_vec(&serde_json::json!({ "config": new_config })).unwrap();
    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &current_etag)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(put_res.status(), StatusCode::OK);
    let new_etag = put_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("etag on 200")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(
        new_etag, current_etag,
        "etag should change on content change"
    );

    // Round-trip: GET the updated proxy-config and confirm the new etag
    // and upstream_url are durably stored.
    let get_after = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_after.status(), axum::http::StatusCode::OK);
    let etag_after = get_after
        .headers()
        .get(axum::http::header::ETAG)
        .expect("etag header after put")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(etag_after, new_etag);

    let bytes = http_body_util::BodyExt::collect(get_after.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["upstream_url"], "https://api.v2.acme.com");
}

#[tokio::test]
async fn update_with_stale_if_match_returns_412_and_current_etag() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let stale_etag = "\"definitely-not-the-etag\"";
    let new_config = serde_json::json!({
        "version": "2026-04-07",
        "project_id": "todo-app",
        "upstream_url": "https://stale.example",
        "default_policy": "deny",
        "routes": [],
        "public_routes": [],
        "features": {}
    });
    let body = serde_json::to_vec(&serde_json::json!({ "config": new_config })).unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", stale_etag)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);

    let current_header = res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("ETag header on 412")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(current_header, stale_etag);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "etag mismatch");
    assert_eq!(json["current_etag"], current_header);
}

#[tokio::test]
async fn update_without_if_match_still_succeeds() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "todo-app",
            "upstream_url": "https://legacy.example",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_some(),
        "200 response should carry ETag when org has a config"
    );
}

#[tokio::test]
async fn update_name_only_with_stale_if_match_is_ignored() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let body = serde_json::to_vec(&serde_json::json!({
        "name": "Acme Corporation (rebranded)"
    }))
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "\"definitely-not-the-etag\"")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}
