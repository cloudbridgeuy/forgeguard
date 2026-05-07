use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_store, test_app, TEST_API_KEY};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn group_body(name: &str, allow: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": name,
        "allow": allow,
    }))
    .unwrap()
}

async fn create_org_and_group(
    store: Arc<dyn crate::store::OrgStore>,
    org_id: &str,
    group_name: &str,
    allow: &[&str],
) -> (axum::Router, String) {
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, org_id, "Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let body = group_body(group_name, allow);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{org_id}/groups"))
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    (app, etag)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_group_returns_201_with_etag() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-create-g", "Create Group Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let body = group_body("admin", &["cp:org:read"]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-create-g/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(resp.headers().get("etag").is_some(), "ETag header missing");

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["name"], "admin");
    assert_eq!(json["allow"], serde_json::json!(["cp:org:read"]));
    assert!(json["etag"].is_string());
}

#[tokio::test]
async fn create_duplicate_group_returns_409() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-dup-g", "Dup Group Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // First create
    let app = test_app(Arc::clone(&store));
    let body = group_body("admin", &["cp:org:read"]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-dup-g/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Second create — same name
    let app = test_app(Arc::clone(&store));
    let body = group_body("admin", &["cp:org:write"]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-dup-g/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "already_exists");
}

#[tokio::test]
async fn list_groups_returns_sorted_by_name() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-list-g", "List Group Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Create groups in non-alphabetical order
    for name in &["owner", "admin", "member"] {
        let app = test_app(Arc::clone(&store));
        let body = group_body(name, &["cp:org:read"]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/organizations/org-list-g/groups")
                    .header("x-api-key", TEST_API_KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-list-g/groups")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let names: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["admin", "member", "owner"],
        "groups must be sorted by name ascending"
    );
}

#[tokio::test]
async fn list_groups_empty_for_new_org_returns_200_empty_array() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-empty-g", "Empty Group Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-empty-g/groups")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json.as_array().unwrap().is_empty(),
        "expected empty array for new org"
    );
}

#[tokio::test]
async fn get_group_returns_200_with_etag() {
    let store = empty_store();
    let (_, create_etag) =
        create_org_and_group(Arc::clone(&store), "org-get-g", "admin", &["cp:org:read"]).await;

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-get-g/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let get_etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(get_etag, create_etag, "GET etag must match POST etag");

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["name"], "admin");
}

#[tokio::test]
async fn get_unknown_group_returns_404() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-get-404-g", "404 Group Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-get-404-g/groups/nonexistent")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_group_with_matching_if_match_returns_200_and_new_etag() {
    let store = empty_store();
    let (_, etag) =
        create_org_and_group(Arc::clone(&store), "org-upd-g", "admin", &["cp:org:read"]).await;

    let update_body = serde_json::to_vec(&serde_json::json!({
        "allow": ["cp:org:read", "cp:org:write"],
    }))
    .unwrap();

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-upd-g/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &etag)
                .body(Body::from(update_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let new_etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_etag, etag, "updated resource must have a new etag");

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["allow"],
        serde_json::json!(["cp:org:read", "cp:org:write"])
    );
}

#[tokio::test]
async fn delete_group_returns_204() {
    let store = empty_store();
    let (_, etag) =
        create_org_and_group(Arc::clone(&store), "org-del-g", "admin", &["cp:org:read"]).await;

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-del-g/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify the group is gone
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-del-g/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
