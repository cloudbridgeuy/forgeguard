//! Integration tests for `GET /api/v1/organizations/{org_id}/events`.
//!
//! All in-memory — exercises `InMemoryPrincipalEventStore`'s `events_after`
//! seam directly (via `upsert_principal` writes through the same app), so no
//! DynamoDB Local dependency is needed.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::handlers::test_support::{build_test_store, test_app, TEST_API_KEY};

const ORG: &str = "org-acme";

async fn put_principal(
    app: &axum::Router,
    native_id: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/api/v1/organizations/{ORG}/principals/{native_id}"
                ))
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn get_events(app: &axum::Router, query: &str) -> axum::response::Response {
    let uri = if query.is_empty() {
        format!("/api/v1/organizations/{ORG}/events")
    } else {
        format!("/api/v1/organizations/{ORG}/events?{query}")
    };
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn seed_three_events(app: &axum::Router) {
    put_principal(app, "usr_1", serde_json::json!({ "role": "member" })).await;
    put_principal(app, "usr_2", serde_json::json!({ "role": "member" })).await;
    put_principal(app, "usr_3", serde_json::json!({ "role": "member" })).await;
}

#[tokio::test]
async fn replay_from_zero_returns_all_events_ascending() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events(&app, "after=0").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let revision_header: u64 = resp
        .headers()
        .get("x-fg-revision")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(revision_header, 3);

    let json = body_json(resp).await;
    let seqs: Vec<u64> = json["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    assert_eq!(json["next_after"], 3);
    assert_eq!(json["revision"], 3);
}

#[tokio::test]
async fn after_two_skips_first_two_events() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events(&app, "after=2").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let seqs: Vec<u64> = json["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![3]);
    assert_eq!(json["next_after"], 3);
}

#[tokio::test]
async fn empty_page_keeps_next_after_unchanged() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events(&app, "after=3").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["events"].as_array().unwrap().len(), 0);
    assert_eq!(json["next_after"], 3);
    assert_eq!(json["revision"], 3);
}

#[tokio::test]
async fn defaults_are_after_zero_limit_hundred() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events(&app, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["events"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn wait_param_is_rejected_with_400() {
    let app = test_app(build_test_store());

    let resp = get_events(&app, "wait=1").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "wait is not supported yet");
}

#[tokio::test]
async fn missing_org_returns_404() {
    let app = test_app(build_test_store());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-missing/events")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn clamp_limit_caps_above_maximum_and_passes_through_below() {
    use super::clamp_limit;

    assert_eq!(clamp_limit(50), 50);
    assert_eq!(clamp_limit(1000), 1000);
    // Above the 1000 ceiling: clamped, not silently truncated to something
    // else and not rejected — this is a unit test on the pure clamp function
    // rather than an end-to-end 1001-event push, since pushing >1000 events
    // through the in-memory log in a handler test would be slow and add no
    // additional coverage over exercising the clamp logic directly.
    assert_eq!(clamp_limit(u16::MAX), 1000);
}
