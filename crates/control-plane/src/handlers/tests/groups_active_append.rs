//! #117 V2: group writes on an Active org are pure event appends.
//!
//! No VP push, no compensation, no D11 — an Active org behaves identically
//! to a Draft org for group mutations. These tests drive the unified path.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use super::active_support::{active_org_store, group_body};
use crate::handlers::test_support::{test_app, TEST_API_KEY};
use crate::store::build_org_store;
use std::sync::Arc;

/// An Active org whose config has NO vp_store_id. Pre-V2 this was D11
/// (503 vp_push_failed); post-V2 it must behave like any other org.
fn active_org_without_vp_store(org_id: &str) -> Arc<dyn crate::store::OrgStore> {
    let json = format!(
        r#"{{
            "organizations": {{
                "{org_id}": {{
                    "name": "Active No-VP Org",
                    "status": "active",
                    "config": {{
                        "version": "2026-04-07",
                        "project_id": "test-app",
                        "upstream_url": "https://api.example.com",
                        "default_policy": "deny",
                        "routes": [],
                        "public_routes": [],
                        "features": {{}}
                    }}
                }}
            }}
        }}"#
    );
    Arc::new(build_org_store(&json).unwrap())
}

#[tokio::test]
async fn active_org_group_create_appends_and_returns_revision() {
    let app = test_app(active_org_store("org-active", "ps-ignored"));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body(
                    "member",
                    &["cp:organization:read"],
                    &[],
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(resp.headers().contains_key("x-fg-revision"));
}

#[tokio::test]
async fn active_org_without_vp_store_group_create_succeeds() {
    // D11 dropped: Active without vp_store_id is no longer an error state.
    let app = test_app(active_org_without_vp_store("org-active"));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body(
                    "member",
                    &["cp:organization:read"],
                    &[],
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn active_org_group_update_and_delete_are_pure_appends() {
    let app = test_app(active_org_store("org-active", "ps-ignored"));

    // create
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body(
                    "member",
                    &["cp:organization:read"],
                    &[],
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // update
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-active/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body(
                    "member",
                    &["cp:organization:read", "cp:key:read"],
                    &[],
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("x-fg-revision"));

    // delete
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-active/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp.headers().contains_key("x-fg-revision"));
}
