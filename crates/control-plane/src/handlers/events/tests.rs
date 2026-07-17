//! Integration tests for `GET /api/v1/organizations/{org_id}/events`.
//!
//! All in-memory — exercises `InMemoryModelEventStore`'s `events_after`
//! seam directly (via `upsert_principal` writes through the same app), so no
//! DynamoDB Local dependency is needed.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use forgeguard_core::{OrgStatus, Organization, OrganizationId};

use crate::handlers::test_support::{
    build_test_store, create_draft_org, empty_in_memory_store, empty_store, test_app,
    test_app_with_principals, TEST_API_KEY,
};
use crate::store::OrgStore;
use crate::vp_client::stub::happy_stub;

async fn seed_org_with_status(
    store: &std::sync::Arc<crate::store::InMemoryOrgStore>,
    org_id: &str,
    status: OrgStatus,
) {
    let id = OrganizationId::new(org_id).unwrap();
    let org = Organization::new(id, format!("{org_id} org"), status, chrono::Utc::now());
    store.write_through_org(org, None).await;
}

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

async fn get_events_with_headers(
    app: &axum::Router,
    query: &str,
    extra_headers: &[(&str, &str)],
) -> axum::response::Response {
    let uri = if query.is_empty() {
        format!("/api/v1/organizations/{ORG}/events")
    } else {
        format!("/api/v1/organizations/{ORG}/events?{query}")
    };
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-api-key", TEST_API_KEY);
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get_events(app: &axum::Router, query: &str) -> axum::response::Response {
    get_events_with_headers(app, query, &[]).await
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
async fn wait_with_non_one_value_returns_400() {
    let app = test_app(build_test_store());

    let resp = get_events(&app, "wait=yes").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "wait must be '1'");
}

#[test]
fn parse_wait_accepts_only_one() {
    use super::{parse_wait, InvalidWait, WaitMode};

    assert_eq!(parse_wait(None), Ok(WaitMode::Immediate));
    assert_eq!(parse_wait(Some("1")), Ok(WaitMode::Watch));
    assert_eq!(parse_wait(Some("")), Err(InvalidWait));
    assert_eq!(parse_wait(Some("true")), Err(InvalidWait));
    assert_eq!(parse_wait(Some("0")), Err(InvalidWait));
}

#[tokio::test]
async fn min_revision_ahead_of_log_returns_412_with_current_revision() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events_with_headers(&app, "", &[("x-fg-min-revision", "5")]).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
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
    assert_eq!(json["error"], "revision_behind");
    assert_eq!(json["current_revision"], 3);
    assert_eq!(json["min_revision"], 5);
}

#[tokio::test]
async fn min_revision_at_current_serves_the_page() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events_with_headers(&app, "after=0", &[("x-fg-min-revision", "3")]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["events"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn unparseable_min_revision_returns_400() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events_with_headers(&app, "", &[("x-fg-min-revision", "banana")]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid X-Fg-Min-Revision header");
}

#[tokio::test(start_paused = true)]
async fn watch_on_empty_page_holds_until_deadline_then_returns_empty() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let started = tokio::time::Instant::now();
    let resp = get_events(&app, "after=3&wait=1").await;
    let held = started.elapsed();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        held >= std::time::Duration::from_secs(1),
        "watch returned after {held:?}, before the 1s deadline"
    );
    let json = body_json(resp).await;
    assert_eq!(json["events"].as_array().unwrap().len(), 0);
    assert_eq!(json["next_after"], 3);
    assert_eq!(json["revision"], 3);
}

#[tokio::test(start_paused = true)]
async fn watch_returns_early_when_an_event_lands_mid_hold() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let writer_app = app.clone();
    let writer = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        put_principal(
            &writer_app,
            "usr_4",
            serde_json::json!({ "role": "member" }),
        )
        .await;
    });

    let started = tokio::time::Instant::now();
    let resp = get_events(&app, "after=3&wait=1").await;
    let held = started.elapsed();
    writer.await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        held < std::time::Duration::from_secs(1),
        "watch did not return early: held {held:?}"
    );
    let json = body_json(resp).await;
    let seqs: Vec<u64> = json["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![4]);
    assert_eq!(json["next_after"], 4);
}

#[tokio::test]
async fn watch_with_available_events_returns_immediately() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let resp = get_events(&app, "after=0&wait=1").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["events"].as_array().unwrap().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn min_revision_behind_beats_wait() {
    let app = test_app(build_test_store());
    seed_three_events(&app).await;

    let started = tokio::time::Instant::now();
    let resp = get_events_with_headers(&app, "wait=1", &[("x-fg-min-revision", "9")]).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        started.elapsed() < std::time::Duration::from_millis(200),
        "412 must not wait for the watch deadline"
    );
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

#[tokio::test]
async fn events_still_404_for_deleted_org() {
    let store = empty_in_memory_store();
    seed_org_with_status(&store, "org-deleted-events", OrgStatus::Deleted).await;
    let app = test_app(store);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-deleted-events/events")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn events_readable_for_draft_org() {
    let app = test_app(build_test_store());
    let response = create_draft_org(&app, "org-draft-events", "Draft Events").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-draft-events/events")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn events_readable_for_suspended_org() {
    let (app, _model_events) = test_app_with_principals(empty_store(), happy_stub());
    let response = create_draft_org(&app, "org-suspended-events", "Suspended Events").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    for verb in ["activate", "suspend"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/organizations/org-suspended-events/{verb}"))
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-suspended-events/events")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn principal_event_payload_carries_subject_identity() {
    let app = test_app(build_test_store());
    put_principal(&app, "usr_1", serde_json::json!({ "role": "member" })).await;

    let resp = get_events(&app, "after=0").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(
        json["events"][0]["payload"],
        serde_json::json!({ "native_id": "usr_1", "principal": { "role": "member" } })
    );
}
