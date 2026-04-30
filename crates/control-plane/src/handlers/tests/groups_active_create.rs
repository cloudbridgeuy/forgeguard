//! V3 integration tests: POST /groups on an Active org.
//!
//! Covers the happy path plus F3 (VP push fails after DDB write, rollback
//! succeeds) and F3' (rollback itself fails).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::active_support::{
    active_org_store, group_body, metric_lock, test_app_for_store, FailingStore,
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

    let calls = stub.calls();
    assert_eq!(calls.len(), 1, "expected exactly one VP call: {calls:?}");
    assert_eq!(
        calls[0],
        StubCall::CreatePolicy {
            store_id: "ps-create-1".to_owned(),
            name: "cp-rbac-admin".to_owned(),
        }
    );
}

#[tokio::test]
async fn create_f3_vp_fails_rollback_succeeds_returns_503() {
    let _guard = metric_lock().await;
    let store = active_org_store("org-active-f3", "ps-create-f3");
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
                .uri("/api/v1/organizations/org-active-f3/groups")
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

    // Rollback succeeded: GET should 404.
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let get_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-f3/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);

    // F3 path must NOT bump the rollback-failed counter.
    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(counter_after, counter_before);
}

#[tokio::test]
async fn create_f3_prime_rollback_fail_returns_500_and_increments_counter() {
    let _guard = metric_lock().await;
    let inner = active_org_store("org-active-f3p", "ps-create-f3p");
    let store = Arc::new(FailingStore::new(Arc::clone(&inner)));
    store.fail_next_delete_group();

    let stub = Arc::new(StubVpClient::new());
    stub.fail_on_create("cp-rbac-admin");

    let counter_before = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();

    let app = test_app_for_store(Arc::clone(&store), Arc::clone(&stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active-f3p/groups")
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
    assert_eq!(json["ddb_committed"], true);
    assert_eq!(json["vp_committed"], false);

    let counter_after = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["parent"])
        .get();
    assert_eq!(
        counter_after,
        counter_before + 1,
        "F3' must increment the parent rollback counter exactly once",
    );
}
