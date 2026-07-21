//! #113 V4: revision-tokened optimistic concurrency (D5) on group mutations,
//! replacing the retired `If-Match`/etag machinery (formerly `groups_etag.rs`).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_store, test_app_with_principals};
use crate::handlers::test_support::TEST_API_KEY;

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn revision_header(resp: &axum::response::Response) -> u64 {
    resp.headers()
        .get("x-fg-revision")
        .expect("x-fg-revision header")
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// Boots a Draft org with a single declared group (`admin`) and returns the
/// router/model-events handle plus the org's revision right after the seed
/// group is created.
async fn setup_org_with_group(
    org_id: &str,
    group_name: &str,
) -> (
    axum::Router,
    Arc<dyn crate::model_event_store::ModelEventStore>,
) {
    let store = empty_store();
    let (app, model_events) = test_app_with_principals(store);

    let resp = create_draft_org(&app, org_id, "Revision Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{org_id}/groups"))
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": group_name,
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    (app, model_events)
}

// ---------------------------------------------------------------------------
// POST X-Fg-If-Revision tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_group_with_matching_if_revision_returns_201_and_new_revision() {
    let (app, model_events) = setup_org_with_group("org-rev-c-match", "admin").await;
    let current = model_events
        .latest_revision("org-rev-c-match")
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-rev-c-match/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "viewer",
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let new_revision = revision_header(&resp);
    assert_eq!(new_revision, current.value() + 1);
    let json = body_json(resp).await;
    assert_eq!(json["revision"], new_revision);
    assert_eq!(json["group"]["name"], "viewer");
}

#[tokio::test]
async fn create_group_with_stale_if_revision_returns_412_with_current_revision() {
    let (app, model_events) = setup_org_with_group("org-rev-c-stale", "admin").await;
    let current = model_events
        .latest_revision("org-rev-c-stale")
        .await
        .unwrap();

    // Advance the org via an unconditional update so `current` is now stale.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-c-stale/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-rev-c-stale/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "viewer",
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let new_current = model_events
        .latest_revision("org-rev-c-stale")
        .await
        .unwrap();
    assert_eq!(revision_header(&resp), new_current.value());
    let json = body_json(resp).await;
    assert_eq!(json["error"], "revision_mismatch");
    assert_eq!(json["current_revision"], new_current.value());
    assert_eq!(json["expected_revision"], current.value());
}

#[tokio::test]
async fn create_group_without_if_revision_succeeds() {
    let (app, _model_events) = setup_org_with_group("org-rev-c-absent", "admin").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-rev-c-absent/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "viewer",
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(resp.headers().get("x-fg-revision").is_some());
}

#[tokio::test]
async fn create_group_with_garbage_if_revision_returns_400() {
    let (app, _model_events) = setup_org_with_group("org-rev-c-garbage", "admin").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-rev-c-garbage/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", "banana")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "viewer",
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid X-Fg-If-Revision header");
}

// ---------------------------------------------------------------------------
// PUT X-Fg-If-Revision tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_group_with_matching_if_revision_returns_200_and_new_revision() {
    let (app, model_events) = setup_org_with_group("org-rev-u-match", "admin").await;
    let current = model_events
        .latest_revision("org-rev-u-match")
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-u-match/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let new_revision = revision_header(&resp);
    assert_eq!(new_revision, current.value() + 1);
    let json = body_json(resp).await;
    assert_eq!(json["revision"], new_revision);
    assert_eq!(json["group"]["allow"], serde_json::json!(["cp:org:write"]));
}

#[tokio::test]
async fn update_group_with_stale_if_revision_returns_412_with_current_revision() {
    let (app, model_events) = setup_org_with_group("org-rev-u-stale", "admin").await;
    let current = model_events
        .latest_revision("org-rev-u-stale")
        .await
        .unwrap();
    // Force an actual mismatch: bump the org forward once, then use the
    // pre-bump value as the (now stale) expectation.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-u-stale/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-u-stale/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:read"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let new_current = model_events
        .latest_revision("org-rev-u-stale")
        .await
        .unwrap();
    assert_eq!(revision_header(&resp), new_current.value());
    let json = body_json(resp).await;
    assert_eq!(json["error"], "revision_mismatch");
    assert_eq!(json["current_revision"], new_current.value());
    assert_eq!(json["expected_revision"], current.value());
}

#[tokio::test]
async fn update_group_without_if_revision_succeeds() {
    let (app, _model_events) = setup_org_with_group("org-rev-u-absent", "admin").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-u-absent/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-fg-revision").is_some());
}

#[tokio::test]
async fn update_group_with_garbage_if_revision_returns_400() {
    let (app, _model_events) = setup_org_with_group("org-rev-u-garbage", "admin").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-u-garbage/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", "banana")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid X-Fg-If-Revision header");
}

#[tokio::test]
async fn if_match_header_is_ignored_on_group_put() {
    let (app, _model_events) = setup_org_with_group("org-rev-u-ifmatch", "admin").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-u-ifmatch/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "\"stale\"")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "If-Match must be ignored — etag retired from update_handler"
    );
}

#[tokio::test]
async fn identical_group_put_is_noop_same_revision_no_event() {
    let (app, model_events) = setup_org_with_group("org-rev-u-noop", "admin").await;
    let before = model_events
        .latest_revision("org-rev-u-noop")
        .await
        .unwrap();
    let events_before = model_events
        .events_after(
            "org-rev-u-noop",
            forgeguard_authz_core::Revision::new(0),
            100,
        )
        .await
        .unwrap()
        .len();

    // Identical to the seeded group (`allow: ["cp:org:read"]`, no inherits).
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-u-noop/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:read"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(revision_header(&resp), before.value());
    let json = body_json(resp).await;
    assert_eq!(json["revision"], before.value());

    let after = model_events
        .latest_revision("org-rev-u-noop")
        .await
        .unwrap();
    assert_eq!(
        after.value(),
        before.value(),
        "no-op must not advance revision"
    );

    let events_after = model_events
        .events_after(
            "org-rev-u-noop",
            forgeguard_authz_core::Revision::new(0),
            100,
        )
        .await
        .unwrap()
        .len();
    assert_eq!(
        events_after, events_before,
        "no-op must not append an event"
    );
}

// ---------------------------------------------------------------------------
// DELETE X-Fg-If-Revision tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_with_matching_if_revision_returns_204_and_new_revision() {
    let (app, model_events) = setup_org_with_group("org-rev-d-match", "admin").await;
    let current = model_events
        .latest_revision("org-rev-d-match")
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-rev-d-match/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(revision_header(&resp), current.value() + 1);
}

#[tokio::test]
async fn delete_group_with_stale_if_revision_returns_412_with_current_revision() {
    let (app, model_events) = setup_org_with_group("org-rev-d-stale", "admin").await;
    let current = model_events
        .latest_revision("org-rev-d-stale")
        .await
        .unwrap();

    // Advance the org via an unconditional update so `current` is now stale.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-rev-d-stale/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-rev-d-stale/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let new_current = model_events
        .latest_revision("org-rev-d-stale")
        .await
        .unwrap();
    assert_eq!(revision_header(&resp), new_current.value());
    let json = body_json(resp).await;
    assert_eq!(json["error"], "revision_mismatch");
    assert_eq!(json["current_revision"], new_current.value());
    assert_eq!(json["expected_revision"], current.value());
}

#[tokio::test]
async fn delete_group_without_if_revision_succeeds() {
    let (app, _model_events) = setup_org_with_group("org-rev-d-absent", "admin").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-rev-d-absent/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp.headers().get("x-fg-revision").is_some());
}

#[tokio::test]
async fn delete_group_with_garbage_if_revision_returns_400() {
    let (app, _model_events) = setup_org_with_group("org-rev-d-garbage", "admin").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-rev-d-garbage/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", "banana")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_absent_group_204_current_revision_no_event() {
    let store = empty_store();
    let (app, model_events) = test_app_with_principals(store);
    let resp = create_draft_org(&app, "org-rev-d-absent-noop", "Absent Noop Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let before = model_events
        .latest_revision("org-rev-d-absent-noop")
        .await
        .unwrap();
    let events_before = model_events
        .events_after(
            "org-rev-d-absent-noop",
            forgeguard_authz_core::Revision::new(0),
            100,
        )
        .await
        .unwrap()
        .len();

    // "nonexistent" was never declared for this org.
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-rev-d-absent-noop/groups/nonexistent")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(revision_header(&resp), before.value());

    let after = model_events
        .latest_revision("org-rev-d-absent-noop")
        .await
        .unwrap();
    assert_eq!(
        after.value(),
        before.value(),
        "no-op must not advance revision"
    );

    let events_after = model_events
        .events_after(
            "org-rev-d-absent-noop",
            forgeguard_authz_core::Revision::new(0),
            100,
        )
        .await
        .unwrap()
        .len();
    assert_eq!(
        events_after, events_before,
        "no-op must not append an event"
    );
}
