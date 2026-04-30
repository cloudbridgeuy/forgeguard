use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_store, test_app, TEST_API_KEY};

// ---------------------------------------------------------------------------
// Tests for the test-only `is_declared_group` probe route
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_declared_group_returns_200_for_existing_group() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-pred-exists", "Predicate Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Create a group
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-pred-exists/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "admin",
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Probe the test-only declared-group route
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/test/declared-group/org-pred-exists/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn is_declared_group_returns_404_for_unknown_group() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-pred-nogrp", "Predicate No Group Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/test/declared-group/org-pred-nogrp/nonexistent")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn is_declared_group_returns_404_for_unknown_org() {
    let store = empty_store();
    // No org created at all.
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/test/declared-group/org-does-not-exist/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // An invalid or unknown org_id is treated as not-found in the predicate handler.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
