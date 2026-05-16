//! Integration tests for `GET` / `PUT /api/v1/organizations/{org_id}/user-schema`.
//!
//! Exercises the handlers end-to-end against `InMemoryOrgStore` via the
//! test-only router built by [`super::super::test_support::test_app`]. Covers
//! the 11 cases enumerated in §10 of the V2 plan.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use forgeguard_core::{OrgStatus, Organization, OrganizationId};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_in_memory_store, test_app, TEST_API_KEY};
use crate::store::OrgStore;

const URI: &str = "/api/v1/organizations/org-us/user-schema";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn name_required_payload() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "standard": { "name": { "required": true } },
        "custom": {}
    }))
    .unwrap()
}

fn alternate_payload() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "standard": { "name": { "required": false } },
        "custom": {}
    }))
    .unwrap()
}

async fn put_user_schema(app: &axum::Router, body: Vec<u8>, if_match: Option<&str>) -> Response {
    let mut req = Request::builder()
        .method("PUT")
        .uri(URI)
        .header("x-api-key", TEST_API_KEY)
        .header("content-type", "application/json");
    if let Some(value) = if_match {
        req = req.header("if-match", value);
    }
    app.clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn get_user_schema(app: &axum::Router) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(URI)
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn seed_org_with_status(
    store: &Arc<crate::store::InMemoryOrgStore>,
    org_id: &str,
    status: OrgStatus,
) {
    let id = OrganizationId::new(org_id).unwrap();
    let org = Organization::new(id, format!("{org_id} org"), status, Utc::now());
    store.create(org, None).await.unwrap();
}

type Response = axum::response::Response;

fn etag_value(resp: &Response) -> String {
    resp.headers()
        .get(axum::http::header::ETAG)
        .expect("response missing ETag header")
        .to_str()
        .unwrap()
        .to_owned()
}

async fn body_json(resp: Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_user_schema_no_row_returns_200_empty() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = get_user_schema(&app).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(axum::http::header::ETAG).is_none(),
        "absent schema row must not emit ETag header"
    );
    let json = body_json(resp).await;
    assert_eq!(json, serde_json::json!({"standard": {}, "custom": {}}));
}

#[tokio::test]
async fn get_user_schema_with_row_returns_200_and_etag() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let put_resp = put_user_schema(&app, name_required_payload(), None).await;
    assert_eq!(put_resp.status(), StatusCode::OK);
    let put_etag = etag_value(&put_resp);

    let get_resp = get_user_schema(&app).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(etag_value(&get_resp), put_etag);
    let json = body_json(get_resp).await;
    assert_eq!(json["standard"]["name"]["required"], true);
}

#[tokio::test]
async fn get_user_schema_deleted_org_returns_404() {
    let store = empty_in_memory_store();
    seed_org_with_status(&store, "org-us", OrgStatus::Deleted).await;
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);

    let resp = get_user_schema(&app).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// PUT — Draft branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_user_schema_draft_no_if_match_creates_row() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = put_user_schema(&app, name_required_payload(), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(axum::http::header::ETAG).is_some(),
        "successful PUT must emit ETag"
    );
    let json = body_json(resp).await;
    assert_eq!(json["standard"]["name"]["required"], true);
}

#[tokio::test]
async fn put_user_schema_draft_matching_if_match_succeeds() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let first = put_user_schema(&app, name_required_payload(), None).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_etag = etag_value(&first);

    let second = put_user_schema(&app, alternate_payload(), Some(&first_etag)).await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_etag = etag_value(&second);
    assert_ne!(first_etag, second_etag, "etag must change with content");
}

#[tokio::test]
async fn put_user_schema_draft_stale_if_match_returns_412() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let first = put_user_schema(&app, name_required_payload(), None).await;
    let first_etag = etag_value(&first);

    let stale = put_user_schema(&app, alternate_payload(), Some("\"definitely-stale\"")).await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(etag_value(&stale), first_etag);
    let json = body_json(stale).await;
    assert_eq!(json["error"], "etag mismatch");
    assert_eq!(json["reason"], "stale_etag");
    assert_eq!(json["current_etag"], first_etag);
}

#[tokio::test]
async fn put_user_schema_draft_if_match_on_absent_row_returns_412() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = put_user_schema(
        &app,
        name_required_payload(),
        Some("\"anything-goes-here\""),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        resp.headers().get(axum::http::header::ETAG).is_none(),
        "no row exists → no current ETag to emit"
    );
    let json = body_json(resp).await;
    assert_eq!(json["current_etag"], "");
}

// ---------------------------------------------------------------------------
// PUT — non-Draft branches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_user_schema_active_org_returns_409() {
    let store = empty_in_memory_store();
    seed_org_with_status(&store, "org-us", OrgStatus::Active).await;
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);

    let resp = put_user_schema(&app, name_required_payload(), None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "not_implemented");
    assert_eq!(json["reason"], "active_schema_put_requires_v4");
}

#[tokio::test]
async fn put_user_schema_non_draft_non_active_returns_409() {
    let store = empty_in_memory_store();
    seed_org_with_status(&store, "org-us", OrgStatus::Suspended).await;
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);

    let resp = put_user_schema(&app, name_required_payload(), None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "org_state_conflict");
    assert_eq!(json["reason"], "suspended");
}

#[tokio::test]
async fn put_user_schema_no_if_match_on_existing_row_returns_409() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let first = put_user_schema(&app, name_required_payload(), None).await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = put_user_schema(&app, alternate_payload(), None).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let json = body_json(second).await;
    assert_eq!(json["error"], "conflict");
    assert_eq!(json["reason"], "schema_already_exists");
}

#[tokio::test]
async fn put_user_schema_deleted_org_returns_404() {
    let store = empty_in_memory_store();
    seed_org_with_status(&store, "org-us", OrgStatus::Deleted).await;
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);

    let resp = put_user_schema(&app, name_required_payload(), None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_user_schema_invalid_payload_returns_422() {
    let store = empty_in_memory_store();
    let app = test_app(Arc::clone(&store) as Arc<dyn OrgStore>);
    let resp = create_draft_org(&app, "org-us", "US Test Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let bad = serde_json::to_vec(&serde_json::json!({
        "standard": { "not-a-real-attr": { "required": true } },
        "custom": {}
    }))
    .unwrap();
    let resp = put_user_schema(&app, bad, None).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid_payload");
    assert_eq!(json["reason"], "unknown_standard_attr");
}
