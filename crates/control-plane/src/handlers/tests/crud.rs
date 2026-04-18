use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{
    build_test_store, create_org_json, empty_store, test_app, TEST_API_KEY,
};

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

// ── ETag on POST create tests ──────────────────────────────────

/// POST create with a `config` field returns 201 with a quoted ETag header.
#[tokio::test]
async fn post_create_with_config_returns_etag() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));

    let body = serde_json::to_string(&create_org_json("org-etag-post", "ETag Post Org")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let etag = response
        .headers()
        .get(axum::http::header::ETAG)
        .expect("ETag header must be present on configured POST create")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "ETag must be a quoted string, got: {etag}"
    );
}

/// POST create without a `config` field returns 201 with no ETag header.
#[tokio::test]
async fn post_create_without_config_returns_no_etag() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));

    // Draft create — no `config` key.
    let body = serde_json::to_string(&serde_json::json!({
        "org_id": "org-draft-no-etag",
        "name": "Draft No ETag"
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
    assert!(
        response.headers().get(axum::http::header::ETAG).is_none(),
        "Draft POST create must NOT include an ETag header"
    );
}

/// The ETag returned by POST create is a valid `If-Match` value for the
/// subsequent first PUT — callers can skip the pre-flight GET entirely.
#[tokio::test]
async fn post_create_etag_is_valid_if_match_for_subsequent_update() {
    let store = empty_store();

    // 1. POST create with config — capture the ETag.
    let app = test_app(Arc::clone(&store));
    let body =
        serde_json::to_string(&create_org_json("org-etag-roundtrip", "ETag Roundtrip")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let create_res = app.oneshot(request).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);
    let create_etag = create_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("create must return ETag")
        .to_str()
        .unwrap()
        .to_string();

    // 2. PUT immediately with the create ETag — no pre-flight GET needed.
    let app = test_app(Arc::clone(&store));
    let put_body = serde_json::to_string(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://updated.example.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();
    let put_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/organizations/org-etag-roundtrip")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .header("if-match", &create_etag)
        .body(Body::from(put_body))
        .unwrap();
    let put_res = app.oneshot(put_req).await.unwrap();
    assert_eq!(
        put_res.status(),
        StatusCode::OK,
        "PUT must succeed when If-Match uses the create ETag"
    );

    let fresh_etag = put_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("PUT 200 must return a fresh ETag")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(
        fresh_etag, create_etag,
        "PUT ETag must differ from the create ETag"
    );
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
