use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{build_test_store, test_app, TEST_API_KEY};
use crate::vp_client::stub::happy_stub;

fn config_body(upstream_url: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "todo-app",
            "upstream_url": upstream_url,
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap()
}

#[tokio::test]
async fn update_with_matching_if_revision_returns_200_and_new_revision() {
    let store = build_test_store();
    let (app, model_events) =
        super::super::test_support::test_app_with_principals(store.clone(), happy_stub());
    let current = model_events.latest_revision("org-acme").await.unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", current.value().to_string())
                .header("content-type", "application/json")
                .body(Body::from(config_body("https://api.v2.acme.com")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let new_revision: u64 = res
        .headers()
        .get("x-fg-revision")
        .expect("revision header")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(new_revision, current.value() + 1);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["revision"], new_revision);
}

#[tokio::test]
async fn update_with_stale_if_revision_returns_412_with_current_revision() {
    let store = build_test_store();
    let (app, model_events) =
        super::super::test_support::test_app_with_principals(store.clone(), happy_stub());
    let current = model_events.latest_revision("org-acme").await.unwrap();
    let stale = current.value() + 41;

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", stale.to_string())
                .header("content-type", "application/json")
                .body(Body::from(config_body("https://stale.example")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
    let current_header: u64 = res
        .headers()
        .get("x-fg-revision")
        .expect("revision header on 412")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(current_header, current.value());

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "revision_mismatch");
    assert_eq!(json["current_revision"], current.value());
    assert_eq!(json["expected_revision"], stale);
}

#[tokio::test]
async fn update_without_if_revision_succeeds() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(config_body("https://legacy.example")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get("x-fg-revision").is_some());
}

#[tokio::test]
async fn update_with_garbage_if_revision_returns_400() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("x-fg-if-revision", "banana")
                .header("content-type", "application/json")
                .body(Body::from(config_body("https://garbage.example")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn identical_update_is_noop_same_revision_no_event() {
    let store = build_test_store();
    let (app, model_events) =
        super::super::test_support::test_app_with_principals(store.clone(), happy_stub());
    let before = model_events.latest_revision("org-acme").await.unwrap();
    let events_before = model_events
        .events_after("org-acme", forgeguard_authz_core::Revision::new(0), 100)
        .await
        .unwrap()
        .len();

    // Identical to the seeded `org-acme` config in `build_test_store`.
    let body = config_body("https://api.acme.com");
    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["revision"], before.value());

    let after = model_events.latest_revision("org-acme").await.unwrap();
    assert_eq!(
        after.value(),
        before.value(),
        "no-op must not advance revision"
    );

    let events_after = model_events
        .events_after("org-acme", forgeguard_authz_core::Revision::new(0), 100)
        .await
        .unwrap()
        .len();
    assert_eq!(
        events_after, events_before,
        "no-op must not append an event"
    );
}

#[tokio::test]
async fn if_match_header_is_ignored() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "\"stale\"")
                .header("content-type", "application/json")
                .body(Body::from(config_body("https://if-match-ignored.example")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "If-Match must be ignored — ETag retired from update_handler"
    );
}
