// The prometheus default registry is process-global — it's shared across all
// tests in this crate. These tests run in parallel threads by default, so
// counter values are not deterministic. Each test captures the counter value
// for its own `reason` label immediately before the triggering request, then
// asserts the after-value is strictly greater. Do NOT replace this with
// absolute assertions.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use super::super::test_support::{
    build_test_store, create_draft_org, empty_store, test_app, TEST_API_KEY,
};

fn read_412_counter(reason: &str) -> u64 {
    let families = prometheus::gather();
    for family in families {
        if family.get_name() == "forgeguard_control_plane_put_org_412_total" {
            for m in family.get_metric() {
                let labels = m.get_label();
                if labels
                    .iter()
                    .any(|l| l.get_name() == "reason" && l.get_value() == reason)
                {
                    return m.get_counter().get_value() as u64;
                }
            }
        }
    }
    0
}

#[tokio::test]
async fn stale_etag_increments_counter() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let before = read_412_counter("stale_etag");

    let body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "proj-stale",
            "upstream_url": "https://stale.example.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "\"definitely-stale-etag\"")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);

    let after = read_412_counter("stale_etag");
    assert!(after > before, "stale_etag counter must have incremented");
}

#[tokio::test]
async fn draft_fail_closed_increments_counter() {
    let store = empty_store();
    let app = test_app(store.clone());

    let create_res = create_draft_org(
        &app,
        "org-metrics-draft-fail-closed",
        "Metrics Draft Fail Closed",
    )
    .await;
    assert_eq!(create_res.status(), StatusCode::CREATED);

    let before = read_412_counter("draft_fail_closed");

    let body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "proj-draft-fc",
            "upstream_url": "https://draft.example.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-metrics-draft-fail-closed")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "\"any-strong-etag\"")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);

    let after = read_412_counter("draft_fail_closed");
    assert!(
        after > before,
        "draft_fail_closed counter must have incremented"
    );
}

#[tokio::test]
async fn wildcard_on_draft_increments_counter() {
    let store = empty_store();
    let app = test_app(store.clone());

    let create_res =
        create_draft_org(&app, "org-metrics-wildcard-draft", "Metrics Wildcard Draft").await;
    assert_eq!(create_res.status(), StatusCode::CREATED);

    let before = read_412_counter("wildcard_on_draft");

    let body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "proj-wildcard",
            "upstream_url": "https://wildcard.example.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-metrics-wildcard-draft")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "*")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);

    let after = read_412_counter("wildcard_on_draft");
    assert!(
        after > before,
        "wildcard_on_draft counter must have incremented"
    );
}
