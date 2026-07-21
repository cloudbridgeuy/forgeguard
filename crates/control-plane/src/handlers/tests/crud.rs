use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use forgeguard_authz_core::Revision;

use super::super::test_support::{
    create_org_json, empty_store, test_app, test_app_with_principals, TEST_API_KEY,
};

// ── Create tests ────────────────────────────────────────────────

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
    assert_eq!(
        response
            .headers()
            .get("x-fg-revision")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    assert!(response.headers().get(axum::http::header::ETAG).is_none());

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["organization"]["name"], "New Org");
    assert_eq!(json["organization"]["status"], "draft");
    assert_eq!(json["organization"]["org_id"], "org-new");
    assert_eq!(json["revision"], 1);

    // The org store's write-through (mirroring prod's shared DynamoDB table)
    // must make the created org immediately visible to a plain GET.
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
    assert_eq!(json["org_id"], "org-new");
    assert_eq!(json["name"], "New Org");
}

#[tokio::test]
async fn create_emits_org_created_on_cursor() {
    // The HTTP events endpoint gates reads on the org being Active, but
    // `create_handler` always creates Draft orgs — so this asserts directly
    // against the `ModelEventStore` handle (the same seam
    // `test_app_with_principals` exposes for promotion tests) rather than
    // round-tripping through the events HTTP route.
    let (app, model_events) = test_app_with_principals(empty_store());

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

    let events = model_events
        .events_after("org-new", Revision::new(0), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].kind(),
        forgeguard_authz_core::EventKind::OrgCreated
    );
    assert_eq!(events[0].payload()["organization"]["name"], "New Org");
}

#[tokio::test]
async fn create_duplicate_returns_409() {
    // Both requests must hit the same app/model_events instance — creation
    // now writes only to the log, and each `test_app` call builds a fresh
    // in-memory model event store.
    let store = empty_store();
    let app = test_app(store);

    // First create
    let body = serde_json::to_string(&create_org_json("org-dup", "First")).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/organizations")
        .header("content-type", "application/json")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Duplicate create
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
    assert_eq!(json["organization"]["name"], "Renamed");

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

// ── Delete route retired (D9) ────────────────────────────────────
//
// Org deletion is not yet supported on the event-sourced log — the raw
// `OrgStore::delete` write path and its `DELETE` route were retired. The
// route now falls through to Axum's default `405 Method Not Allowed` for
// an unregistered method on an existing path.

#[tokio::test]
async fn delete_route_returns_405() {
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

    // DELETE is no longer a registered method on this path.
    let app = test_app(store);
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/organizations/org-del")
        .header("x-api-key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
