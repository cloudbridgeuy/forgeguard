//! V4 integration tests: POST /groups on an Active org — push-then-append.
//!
//! Covers the happy path plus F-VP (VP push fails, clean abort — nothing
//! written), F-append (VP push succeeds but the append fails, compensate by
//! deleting the just-created parent policy), and F-append-prime (that
//! compensating delete itself fails).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::active_support::{
    active_org_store, group_body, metric_lock, model_events_for, test_app_for_store,
    FailingModelEventStore,
};
use crate::handlers::test_support::{test_app_with_stub, TEST_API_KEY};
use crate::metrics::GROUP_ROLLBACK_FAILED_TOTAL;
use crate::vp_client::stub::{happy_stub, StubCall, StubVpClient};

#[tokio::test]
async fn create_on_active_org_pushes_parent_policy_to_vp() {
    let store = active_org_store("org-active-c", "ps-create-1");
    let stub = happy_stub();
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active-c/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body("admin", &["cp:org:read"], &[])))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(resp.headers().get("etag").is_some());

    // `push_permit` is delete-then-create (VP has no upsert primitive): the
    // delete targets a not-yet-existing policy and is treated as an
    // idempotent no-op, followed by the real create.
    let calls = stub.calls();
    assert_eq!(calls.len(), 2, "expected delete-then-create: {calls:?}");
    assert_eq!(
        calls[0],
        StubCall::DeletePolicyByName {
            store_id: "ps-create-1".to_owned(),
            name: "cp-rbac-admin".to_owned(),
        }
    );
    assert_eq!(
        calls[1],
        StubCall::CreatePolicy {
            store_id: "ps-create-1".to_owned(),
            name: "cp-rbac-admin".to_owned(),
        }
    );
}

/// F-VP: the VP push fails before any append is attempted. The request
/// aborts cleanly with 503 — nothing was ever written, so there is nothing to
/// roll back (this supersedes the V3 F3 rollback test, which wrote DDB first
/// and then rolled it back on a VP failure).
#[tokio::test]
async fn create_vp_fails_aborts_clean_503_nothing_written() {
    let _guard = metric_lock().await;
    let store = active_org_store("org-active-f-vp", "ps-create-f-vp");
    let stub = Arc::new(StubVpClient::new());
    stub.fail_on_create("cp-rbac-admin");

    let counter_before = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();

    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active-f-vp/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body("admin", &["cp:org:read"], &[])))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "vp_push_failed");
    assert_eq!(json["stage"], "parent");
    assert_eq!(json["failed"], "cp-rbac-admin");
    assert!(json["completed"].as_array().unwrap().is_empty());
    assert!(json["remaining"].as_array().unwrap().is_empty());

    // Nothing written: GET must 404.
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let get_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-f-vp/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);

    // A clean pre-append abort never touches the rollback-failed counter.
    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(counter_after, counter_before);
}

/// F-append: the VP push succeeds but the event-sourced append fails
/// afterward. The orchestrator compensates by deleting the just-created
/// parent policy, and the request surfaces a generic 500 (not
/// `inconsistent_state` — the compensation itself succeeded).
#[tokio::test]
async fn create_append_fails_compensates_vp() {
    let store = active_org_store("org-active-f-append", "ps-create-f-append");
    let stub = happy_stub();
    let model_events = Arc::new(FailingModelEventStore::new(model_events_for(&store)));
    model_events.fail_next_put_group();

    let app = test_app_for_store(Arc::clone(&store), Arc::clone(&stub), model_events);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active-f-append/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body("admin", &["cp:org:read"], &[])))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // VP was compensated: delete-then-create (the original push) followed by
    // another delete (the compensation), leaving no policy behind.
    let calls = stub.calls();
    assert_eq!(
        calls.len(),
        3,
        "expected push then compensating delete: {calls:?}"
    );
    assert_eq!(
        calls[2],
        StubCall::DeletePolicyByName {
            store_id: "ps-create-f-append".to_owned(),
            name: "cp-rbac-admin".to_owned(),
        },
        "compensation must delete the policy the push just created",
    );

    // Append failed: GET must 404 — nothing was ever committed to the group
    // read-model.
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let get_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-f-append/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

/// F-append-prime: the append fails AND the VP compensation (deleting the
/// just-created parent policy) also fails. Surfaces 500
/// `inconsistent_state` and bumps
/// `forgeguard_cp_group_rollback_failed_total{stage="parent"}`.
#[tokio::test]
async fn create_compensation_fails_increments_counter_500() {
    let _guard = metric_lock().await;
    let store = active_org_store("org-active-f-append-p", "ps-create-f-append-p");
    let stub = Arc::new(StubVpClient::new());
    let model_events = Arc::new(FailingModelEventStore::new(model_events_for(&store)));
    model_events.fail_next_put_group();
    // Target the *compensating* delete, not `push_permit`'s own leading
    // delete-of-nonexistent-policy: the first delete call is the harmless
    // no-op inside the push, the second is the compensation.
    stub.fail_after_n_deletes(1);

    let counter_before = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();

    let app = test_app_for_store(Arc::clone(&store), Arc::clone(&stub), model_events);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active-f-append-p/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(group_body("admin", &["cp:org:read"], &[])))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "inconsistent_state");
    assert_eq!(json["ddb_committed"], false);
    assert_eq!(json["vp_committed"], true);

    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(
        counter_after,
        counter_before + 1,
        "F-append-prime must increment the parent rollback counter exactly once",
    );
}
