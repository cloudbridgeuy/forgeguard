//! V3 integration tests: DELETE /groups/{name} on an Active org.
//!
//! Covers happy delete, idempotent treatment of VP `NotFound`, F3 (VP delete
//! fails, rollback succeeds), and F3' (rollback put_back fails).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::active_support::{
    active_org_store, create_group, metric_lock, test_app_for_store, FailingStore,
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

    // Stub log: one create (during setup), one delete (during DELETE).
    let calls = stub.calls();
    assert_eq!(calls.len(), 2);
    assert!(matches!(calls[0], StubCall::CreatePolicy { ref name, .. } if name == "cp-rbac-admin"));
    assert!(
        matches!(calls[1], StubCall::DeletePolicyByName { ref name, .. } if name == "cp-rbac-admin"),
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

#[tokio::test]
async fn delete_f3_vp_fails_rollback_succeeds_returns_503() {
    let _guard = metric_lock().await;
    let store = active_org_store("org-active-d-f3", "ps-del-f3");
    let setup_stub = happy_stub();
    let etag = create_group(
        test_app_with_stub(Arc::clone(&store), Arc::clone(&setup_stub)),
        "org-active-d-f3",
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
                .uri("/api/v1/organizations/org-active-d-f3/groups/admin")
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

    // Rollback succeeded: GET should return 200 (the row was put back).
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let get_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-d-f3/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        get_resp.status(),
        StatusCode::OK,
        "rollback must restore the prior DDB row",
    );

    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(counter_after, counter_before);
}

#[tokio::test]
async fn delete_f3_prime_rollback_fail_returns_500_and_increments_counter() {
    let _guard = metric_lock().await;
    let inner = active_org_store("org-active-d-f3p", "ps-del-f3p");
    // Seed via the unwrapped store (rollback failure is for the *post-DDB-delete*
    // put_group; setup CREATE must succeed, so we can't arm yet).
    let setup_stub = happy_stub();
    let etag = create_group(
        test_app_with_stub(Arc::clone(&inner), Arc::clone(&setup_stub)),
        "org-active-d-f3p",
        "admin",
        &["cp:org:read"],
        &[],
    )
    .await;

    let store = Arc::new(FailingStore::new(Arc::clone(&inner)));
    store.fail_next_put_group();
    setup_stub.fail_on_delete("cp-rbac-admin");

    let counter_before = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();

    let app = test_app_for_store(store.clone(), Arc::clone(&setup_stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-active-d-f3p/groups/admin")
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
    assert_eq!(json["ddb_committed"], true);
    assert_eq!(json["vp_committed"], false);

    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(counter_after, counter_before + 1);
}
