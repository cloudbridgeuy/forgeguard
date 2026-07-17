//! V4 integration tests: DELETE /groups/{name} on an Active org —
//! push-then-append.
//!
//! Covers happy delete, idempotent treatment of VP `NotFound`, F-VP (VP
//! delete fails, clean abort — the group is untouched), and F-append (VP
//! delete succeeds but the append fails, so the prior permit is re-pushed)
//! plus F-append-prime (that re-push itself fails).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::active_support::{
    active_org_store, create_group, metric_lock, model_events_for, test_app_for_store,
    FailingModelEventStore,
};
use crate::handlers::test_support::{test_app_with_stub, TEST_API_KEY};
use crate::metrics::GROUP_ROLLBACK_FAILED_TOTAL;
use crate::vp_client::stub::{happy_stub, StubCall, StubVpClient};

#[tokio::test]
async fn delete_on_active_org_deletes_vp_policy() {
    let store = active_org_store("org-active-d", "ps-del-1");
    let stub = happy_stub();
    let etag = create_group(
        test_app_with_stub(Arc::clone(&store), Arc::clone(&stub)),
        "org-active-d",
        "admin",
        &["cp:org:read"],
        &[],
    )
    .await;

    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-active-d/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Stub log: delete-then-create (during setup CREATE), then a delete
    // (during DELETE).
    let calls = stub.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(
        matches!(calls[0], StubCall::DeletePolicyByName { ref name, .. } if name == "cp-rbac-admin")
    );
    assert!(matches!(calls[1], StubCall::CreatePolicy { ref name, .. } if name == "cp-rbac-admin"));
    assert!(
        matches!(calls[2], StubCall::DeletePolicyByName { ref name, .. } if name == "cp-rbac-admin"),
    );
}

#[tokio::test]
async fn delete_treats_vp_not_found_as_idempotent_success() {
    let store = active_org_store("org-active-d-nf", "ps-del-nf");
    // Setup: create the group with a happy stub so DDB has the row.
    let setup_stub = happy_stub();
    let etag = create_group(
        test_app_with_stub(Arc::clone(&store), Arc::clone(&setup_stub)),
        "org-active-d-nf",
        "admin",
        &["cp:org:read"],
        &[],
    )
    .await;

    // Now use a FRESH stub that has no record of the policy → delete returns NotFound.
    let stub = Arc::new(StubVpClient::new());
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-active-d-nf/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "VP NotFound on delete must be treated as idempotent",
    );
}

/// F-VP: the VP delete fails before any append is attempted. The request
/// aborts cleanly with 503 — the group row is untouched (this supersedes the
/// V3 F3 rollback test, which deleted DDB first and then rolled the deletion
/// back on a VP failure).
#[tokio::test]
async fn delete_vp_fails_aborts_clean_503_group_still_present() {
    let _guard = metric_lock().await;
    let store = active_org_store("org-active-d-f-vp", "ps-del-f-vp");
    let setup_stub = happy_stub();
    let etag = create_group(
        test_app_with_stub(Arc::clone(&store), Arc::clone(&setup_stub)),
        "org-active-d-f-vp",
        "admin",
        &["cp:org:read"],
        &[],
    )
    .await;

    // Same stub keeps the policy — but arm fail_on_delete to surface a non-NotFound error.
    setup_stub.fail_on_delete("cp-rbac-admin");

    let counter_before = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();

    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&setup_stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-active-d-f-vp/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
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

    // Nothing was ever touched: GET must still return 200.
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let get_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-d-f-vp/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        get_resp.status(),
        StatusCode::OK,
        "a clean pre-append abort must never touch the group row",
    );

    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(counter_after, counter_before);
}

/// F-append: the VP delete succeeds but the event-sourced append fails
/// afterward. The orchestrator compensates by re-pushing the prior parent
/// permit, and the request surfaces a generic 500 (not `inconsistent_state`
/// — the compensation itself succeeded).
#[tokio::test]
async fn delete_append_fails_repushes_permit() {
    let store = active_org_store("org-active-d-f-append", "ps-del-f-append");
    let setup_stub = happy_stub();
    let etag = create_group(
        test_app_with_stub(Arc::clone(&store), Arc::clone(&setup_stub)),
        "org-active-d-f-append",
        "admin",
        &["cp:org:read"],
        &[],
    )
    .await;

    let model_events = Arc::new(FailingModelEventStore::new(model_events_for(&store)));
    model_events.fail_next_delete_group();

    let app = test_app_for_store(Arc::clone(&store), Arc::clone(&setup_stub), model_events);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-active-d-f-append/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "internal");

    // Compensation re-pushed the prior permit: the calls tail is
    // delete-then-create (the DELETE handler's own VP delete, then the
    // re-push after the append failed).
    let calls = setup_stub.calls();
    assert!(
        matches!(calls.last(), Some(StubCall::CreatePolicy { ref name, .. }) if name == "cp-rbac-admin"),
        "compensation must re-create the deleted policy: {calls:?}",
    );

    // Compensation restored VP; the row was never removed from DDB either.
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let get_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-d-f-append/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        get_resp.status(),
        StatusCode::OK,
        "the append never landed, so the row must still be present",
    );
}

/// F-append-prime: the append fails AND re-pushing the prior permit also
/// fails. Surfaces 500 `inconsistent_state` and bumps
/// `forgeguard_cp_group_rollback_failed_total{stage="parent"}`.
#[tokio::test]
async fn delete_f_append_prime_rollback_fail_returns_500_and_increments_counter() {
    let _guard = metric_lock().await;
    let store = active_org_store("org-active-d-f-append-p", "ps-del-f-append-p");
    let setup_stub = happy_stub();
    let etag = create_group(
        test_app_with_stub(Arc::clone(&store), Arc::clone(&setup_stub)),
        "org-active-d-f-append-p",
        "admin",
        &["cp:org:read"],
        &[],
    )
    .await;

    let model_events = Arc::new(FailingModelEventStore::new(model_events_for(&store)));
    model_events.fail_next_delete_group();
    // The compensating re-push (`push_permit`) runs delete-then-create; force
    // the delete half of it to fail. Delete call #1 already happened during
    // setup's CREATE (push_permit's own leading delete-of-nonexistent-policy
    // no-op); delete call #2 is the DELETE handler's own explicit delete;
    // delete call #3 is the compensating re-push's delete — that's the one
    // to target.
    setup_stub.fail_after_n_deletes(2);

    let counter_before = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();

    let app = test_app_for_store(Arc::clone(&store), Arc::clone(&setup_stub), model_events);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-active-d-f-append-p/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "inconsistent_state");
    assert_eq!(json["ddb_committed"], false);
    assert_eq!(json["vp_committed"], false);

    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(counter_after, counter_before + 1);
}
