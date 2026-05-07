use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_store, test_app, TEST_API_KEY};

// ---------------------------------------------------------------------------
// Helper: POST a group body and return the response
// ---------------------------------------------------------------------------

async fn post_group(
    store: Arc<dyn crate::store::OrgStore>,
    org_id: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let app = test_app(Arc::clone(&store));
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{org_id}/groups"))
            .header("x-api-key", TEST_API_KEY)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn setup_org(store: &Arc<dyn crate::store::OrgStore>, org_id: &str) {
    let app = test_app(Arc::clone(store));
    let resp = create_draft_org(&app, org_id, "Validation Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_group_bad_name_regex_returns_422() {
    let store = empty_store();
    setup_org(&store, "org-val-name").await;

    let resp = post_group(
        Arc::clone(&store),
        "org-val-name",
        serde_json::json!({ "name": "Admin", "allow": ["cp:org:read"] }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "validation_failed");
    assert_eq!(json["reason"], "bad_name_regex");
    assert_eq!(json["field"], "name");
    assert!(json["message"].is_string(), "message field must be present");
}

#[tokio::test]
async fn create_group_bad_action_format_returns_422() {
    // "foo:bar" has only two colon-separated segments — rejected as BadActionFormat.
    let store = empty_store();
    setup_org(&store, "org-val-action").await;

    let resp = post_group(
        Arc::clone(&store),
        "org-val-action",
        serde_json::json!({ "name": "admin", "allow": ["foo:bar"] }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "validation_failed");
    assert_eq!(json["reason"], "bad_action_format");
    assert_eq!(json["field"], "allow");
    assert!(json["message"].is_string());
}

#[tokio::test]
async fn create_group_empty_allow_returns_422() {
    let store = empty_store();
    setup_org(&store, "org-val-empty").await;

    let resp = post_group(
        Arc::clone(&store),
        "org-val-empty",
        serde_json::json!({ "name": "admin", "allow": [] }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "validation_failed");
    assert_eq!(json["reason"], "empty_allow");
    assert_eq!(json["field"], "allow");
    assert!(json["message"].is_string());
}

#[tokio::test]
async fn create_group_self_inherit_returns_422_cycle() {
    let store = empty_store();
    setup_org(&store, "org-val-cycle").await;

    // A group that inherits itself — cycle detected.
    let resp = post_group(
        Arc::clone(&store),
        "org-val-cycle",
        serde_json::json!({ "name": "admin", "allow": ["cp:org:read"], "inherits": ["admin"] }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "validation_failed");
    assert_eq!(json["reason"], "inherit_cycle");
    assert_eq!(json["field"], "inherits");
    assert!(json["message"].is_string());
}

#[tokio::test]
async fn create_group_unknown_inherit_returns_422_unknown() {
    let store = empty_store();
    setup_org(&store, "org-val-unknown").await;

    // References a group that does not exist yet.
    let resp = post_group(
        Arc::clone(&store),
        "org-val-unknown",
        serde_json::json!({
            "name": "admin",
            "allow": ["cp:org:read"],
            "inherits": ["nonexistent-group"]
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "validation_failed");
    assert_eq!(json["reason"], "unknown_inherit");
    assert_eq!(json["field"], "inherits");
    assert!(json["message"].is_string());
}

#[tokio::test]
async fn update_group_path_body_name_mismatch_returns_422() {
    let store = empty_store();
    setup_org(&store, "org-val-mismatch").await;

    // Create a group first
    let app = test_app(Arc::clone(&store));
    let create_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-val-mismatch/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(
                        &serde_json::json!({ "name": "admin", "allow": ["cp:org:read"] }),
                    )
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let etag = create_resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // PUT with body name != path name
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-val-mismatch/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &etag)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "owner",   // mismatches the path "admin"
                        "allow": ["cp:org:write"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "validation_failed");
    assert_eq!(json["reason"], "name_mismatch");
    assert_eq!(json["field"], "name");
    assert!(json["message"].is_string());
}
