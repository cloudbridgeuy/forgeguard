//! V4 integration tests: F-VP-mid mid-fanout failure on UPDATE plus the
//! Active-without-`vp_store_id` boundary case.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::active_support::{active_org_store, create_group, metric_lock};
use crate::handlers::test_support::{empty_store, test_app_with_stub, TEST_API_KEY};
use crate::metrics::GROUP_ROLLBACK_FAILED_TOTAL;
use crate::store::build_org_store;
use crate::vp_client::stub::{happy_stub, StubVpClient};
use crate::vp_client::VpClient;

/// Seed `member` + three inheritors `admin`, `editor`, `owner`. Update
/// `member` with a stub primed to fail after exactly two successful creates.
/// Sequence: parent re-create (1st) → `admin` (2nd) → `editor` would be 3rd
/// but fails → the orchestrator restores the completed prior (`admin`) and
/// returns 503 `{stage="fanout", completed=[admin], failed=editor,
/// remaining=[owner]}`. Because VP is now pushed *before* the append (#113
/// V4), a mid-fanout failure means the append is never attempted at all: the
/// parent DDB row must keep its pre-UPDATE value, not the new one — this
/// supersedes the V3 `update_f4_mid_fanout_returns_503_with_progress` test,
/// which asserted the parent row DID reflect the update (append-before-VP
/// ordering).
#[tokio::test]
async fn update_mid_fanout_failure_restores_completed_priors_503() {
    let _guard = metric_lock().await;
    let store = active_org_store("org-active-f4", "ps-f4");

    let stub = happy_stub();
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    let parent_etag = create_group(app, "org-active-f4", "member", &["cp:x:read"], &[]).await;
    for name in &["admin", "editor", "owner"] {
        let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
        create_group(app, "org-active-f4", name, &["cp:x:read"], &["member"]).await;
    }

    // Fresh stub for the UPDATE; replay seed creates so the stub's policy state
    // matches DDB. Then arm: fail after 2 more successful creates (parent
    // re-create + admin succeed; editor fails). The threshold is absolute on
    // `creates_so_far`, so we add the 4 replayed seeds.
    let stub_upd = Arc::new(StubVpClient::new());
    for name in &[
        "cp-rbac-member",
        "cp-rbac-admin",
        "cp-rbac-editor",
        "cp-rbac-owner",
    ] {
        stub_upd
            .create_policy("ps-f4", name, None, "permit(...)")
            .await
            .unwrap();
    }
    stub_upd.fail_after_n_creates(4 + 2);

    let counter_before_fanout = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["fanout"])
        .get();

    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub_upd));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-active-f4/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &parent_etag)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "allow": ["cp:x:read", "cp:x:write"],
                        "inherits": []
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "vp_push_failed");
    assert_eq!(json["stage"], "fanout");
    assert_eq!(json["completed"], serde_json::json!(["cp-rbac-admin"]));
    assert_eq!(json["failed"], "cp-rbac-editor");
    assert_eq!(json["remaining"], serde_json::json!(["cp-rbac-owner"]));

    // Push-then-append: a mid-fanout VP failure means the append is never
    // attempted, so the parent DDB row must still hold its pre-UPDATE value.
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let get_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-f4/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let bytes = get_resp.into_body().collect().await.unwrap().to_bytes();
    let parent_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        parent_json["allow"],
        serde_json::json!(["cp:x:read"]),
        "a mid-fanout failure aborts before the append; the parent row must be untouched",
    );

    // The completed prior (`admin`) was successfully restored — no
    // compensation failure, so the fanout rollback-failed counter must not
    // move.
    let counter_after_fanout = GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&["fanout"])
        .get();
    assert_eq!(counter_after_fanout, counter_before_fanout);
}

/// Risk #5 boundary: an org with `OrgStatus::Active` but no `vp_store_id`
/// should surface the same error shape as an F3 `vp_push_failed{stage=parent}`.
/// This guards the Active-without-VP-store path (D11: status-quo 503).
#[tokio::test]
async fn create_on_active_org_without_vp_store_id_returns_503() {
    // Seed an Active org with config but no vp_store_id.
    let json = r#"{
        "organizations": {
            "org-active-no-vp": {
                "name": "Misconfigured Active",
                "status": "active",
                "config": {
                    "version": "2026-04-07",
                    "project_id": "test-app",
                    "upstream_url": "https://api.example.com",
                    "default_policy": "deny",
                    "routes": [],
                    "public_routes": [],
                    "features": {}
                }
            }
        }
    }"#;
    let store: Arc<dyn crate::store::OrgStore> = Arc::new(build_org_store(json).unwrap());

    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-active-no-vp/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "admin",
                        "allow": ["cp:org:read"]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "vp_push_failed");
    assert_eq!(json["stage"], "parent");
}

/// Sanity check: a Draft org (no config) still bypasses the VP path entirely.
#[tokio::test]
async fn create_on_draft_org_skips_vp() {
    let store = empty_store();
    let stub = happy_stub();

    // Bootstrap: create a Draft org via POST /organizations.
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "org_id": "org-draft-1",
                        "name": "Draft Org"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-draft-1/groups")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": "admin",
                        "allow": ["cp:org:read"]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    assert!(
        stub.calls().is_empty(),
        "Draft org must not push anything to VP: {:?}",
        stub.calls(),
    );
}
