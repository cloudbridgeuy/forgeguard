use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use forgeguard_authz_core::{EventKind, Revision};

use super::super::test_support::{
    create_org_json, empty_store, test_app_with_principals, TEST_API_KEY,
};

async fn create_draft(app: &axum::Router, org_id: &str) {
    let body = serde_json::to_string(&create_org_json(org_id, "Test Org")).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/organizations")
                .header("content-type", "application/json")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn post_verb(app: &axum::Router, org_id: &str, verb: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{org_id}/{verb}"))
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn activate_draft_org_succeeds_and_emits_org_activated() {
    let (app, model_events) = test_app_with_principals(empty_store());
    create_draft(&app, "org-a").await;

    let response = post_verb(&app, "org-a", "activate").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-fg-revision")
            .and_then(|v| v.to_str().ok()),
        Some("2")
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["organization"]["status"], "active");

    let events = model_events
        .events_after("org-a", Revision::new(0), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].kind(), EventKind::OrgActivated);
}

#[tokio::test]
async fn suspend_active_org_emits_narrowing_event() {
    let (app, model_events) = test_app_with_principals(empty_store());
    create_draft(&app, "org-b").await;
    assert_eq!(
        post_verb(&app, "org-b", "activate").await.status(),
        StatusCode::OK
    );

    let response = post_verb(&app, "org-b", "suspend").await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["organization"]["status"], "suspended");

    let events = model_events
        .events_after("org-b", Revision::new(0), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].kind(), EventKind::OrgSuspended);
    assert!(events[2].kind().narrowing());
}

#[tokio::test]
async fn restore_full_cycle_emits_kinds_in_order() {
    let (app, model_events) = test_app_with_principals(empty_store());
    create_draft(&app, "org-c").await;
    assert_eq!(
        post_verb(&app, "org-c", "activate").await.status(),
        StatusCode::OK
    );
    assert_eq!(
        post_verb(&app, "org-c", "suspend").await.status(),
        StatusCode::OK
    );

    let response = post_verb(&app, "org-c", "restore").await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["organization"]["status"], "active");

    let events = model_events
        .events_after("org-c", Revision::new(0), 10)
        .await
        .unwrap();
    let kinds: Vec<EventKind> = events
        .iter()
        .map(forgeguard_authz_core::EventEnvelope::kind)
        .collect();
    assert_eq!(
        kinds,
        vec![
            EventKind::OrgCreated,
            EventKind::OrgActivated,
            EventKind::OrgSuspended,
            EventKind::OrgRestored,
        ]
    );
}

#[tokio::test]
async fn suspend_draft_org_returns_409_invalid_transition() {
    let (app, model_events) = test_app_with_principals(empty_store());
    create_draft(&app, "org-d").await;

    let response = post_verb(&app, "org-d", "suspend").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_transition");

    let events = model_events
        .events_after("org-d", Revision::new(0), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1, "409 must not append an event");
}

#[tokio::test]
async fn restore_draft_org_returns_409_invalid_transition() {
    let (app, model_events) = test_app_with_principals(empty_store());
    create_draft(&app, "org-e").await;

    let response = post_verb(&app, "org-e", "restore").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_transition");

    let events = model_events
        .events_after("org-e", Revision::new(0), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1, "409 must not append an event");
}

#[tokio::test]
async fn activate_active_org_is_a_no_op() {
    let (app, model_events) = test_app_with_principals(empty_store());
    create_draft(&app, "org-f").await;
    assert_eq!(
        post_verb(&app, "org-f", "activate").await.status(),
        StatusCode::OK
    );

    let response = post_verb(&app, "org-f", "activate").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-fg-revision")
            .and_then(|v| v.to_str().ok()),
        Some("2")
    );

    let events = model_events
        .events_after("org-f", Revision::new(0), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2, "no-op activate must not append an event");
}

#[tokio::test]
async fn activate_unknown_org_returns_404() {
    let (app, _model_events) = test_app_with_principals(empty_store());

    let response = post_verb(&app, "org-does-not-exist", "activate").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
