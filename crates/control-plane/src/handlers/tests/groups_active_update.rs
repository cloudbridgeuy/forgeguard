//! V3 integration tests: PUT /groups/{name} on an Active org.
//!
//! Covers: happy update with two transitive inheritors (deterministic fanout
//! order asserted across two runs).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use super::active_support::{active_org_store, create_group};
use crate::handlers::test_support::{test_app_with_stub, TEST_API_KEY};
use crate::vp_client::stub::{happy_stub, StubCall, StubVpClient};
use crate::vp_client::VpClient;

fn update_body(allow: &[&str], inherits: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "allow": allow,
        "inherits": inherits,
    }))
    .unwrap()
}

/// Seeds `member` plus three inheritors in non-alphabetical insertion order
/// (`zeta`, `alpha`, `mid`), runs the parent UPDATE twice with a happy stub,
/// and asserts the VP fanout is alphabetical (`alpha`, `mid`, `zeta`) across
/// **both** runs — defeats any HashMap-iteration-order accident.
#[tokio::test]
async fn update_active_org_fans_out_to_dependents_in_alphabetical_order() {
    let store = active_org_store("org-active-u", "ps-upd-1");

    // Seed parent + three inheritors (insertion order: zeta, alpha, mid).
    let stub = happy_stub();
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    let parent_etag = create_group(app, "org-active-u", "member", &["cp:x:read"], &[]).await;

    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    create_group(app, "org-active-u", "zeta", &["cp:x:read"], &["member"]).await;
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    create_group(app, "org-active-u", "alpha", &["cp:x:read"], &["member"]).await;
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub));
    create_group(app, "org-active-u", "mid", &["cp:x:read"], &["member"]).await;

    fn fanout_create_names(calls: &[StubCall]) -> Vec<String> {
        calls
            .iter()
            .filter_map(|c| match c {
                StubCall::CreatePolicy { name, .. } => Some(name.clone()),
                _ => None,
            })
            // The four creates from seeding are at the front; we assert ordering
            // on the post-UPDATE tail (parent + three dependents = 4 entries).
            .skip(4)
            .collect()
    }

    // Run 1: PUT member with widened allow.
    let stub_run1 = Arc::new(StubVpClient::new());
    // Replay seed creates so the stub knows about prior policies (UPDATE does
    // delete-then-create on the parent, so it expects the policy to be present).
    for name in &[
        "cp-rbac-member",
        "cp-rbac-zeta",
        "cp-rbac-alpha",
        "cp-rbac-mid",
    ] {
        stub_run1
            .create_policy("ps-upd-1", name, None, "permit(...)")
            .await
            .unwrap();
    }
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub_run1));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-active-u/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &parent_etag)
                .body(Body::from(update_body(&["cp:x:read", "cp:x:write"], &[])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls_run1 = fanout_create_names(&stub_run1.calls());
    assert_eq!(
        calls_run1,
        vec![
            "cp-rbac-member".to_owned(),
            "cp-rbac-alpha".to_owned(),
            "cp-rbac-mid".to_owned(),
            "cp-rbac-zeta".to_owned(),
        ],
        "fanout must be parent first then dependents in alphabetical order (run 1)",
    );

    // Capture the new parent etag for run 2.
    let app = test_app_with_stub(Arc::clone(&store), happy_stub());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/org-active-u/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let parent_etag_2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // Run 2: PUT member again with a different allow.
    let stub_run2 = Arc::new(StubVpClient::new());
    for name in &[
        "cp-rbac-member",
        "cp-rbac-zeta",
        "cp-rbac-alpha",
        "cp-rbac-mid",
    ] {
        stub_run2
            .create_policy("ps-upd-1", name, None, "permit(...)")
            .await
            .unwrap();
    }
    let app = test_app_with_stub(Arc::clone(&store), Arc::clone(&stub_run2));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-active-u/groups/member")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &parent_etag_2)
                .body(Body::from(update_body(&["cp:x:read"], &[])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls_run2 = fanout_create_names(&stub_run2.calls());
    assert_eq!(
        calls_run2, calls_run1,
        "fanout order must be deterministic across runs (run 2)",
    );
}
