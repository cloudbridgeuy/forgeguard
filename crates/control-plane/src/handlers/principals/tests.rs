//! Integration tests for `PUT /api/v1/organizations/{org_id}/principals/{native_id}`.
//!
//! All in-memory — exercises `InMemoryPrincipalEventStore`, which wraps a
//! real `InMemoryEventLog` + a real Ed25519 signature, so no DynamoDB Local
//! dependency is needed to cover the decide-upsert + revision-bump flow.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::handlers::test_support::{build_test_store, test_app, TEST_API_KEY};

const ORG: &str = "org-acme";

fn uri(native_id: &str) -> String {
    format!("/api/v1/organizations/{ORG}/principals/{native_id}")
}

async fn put(
    app: &axum::Router,
    native_id: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri(native_id))
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn revision_header(resp: &axum::response::Response) -> u64 {
    resp.headers()
        .get("x-fg-revision")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn create_returns_201_with_revision_1() {
    let app = test_app(build_test_store());
    let resp = put(&app, "usr_1", serde_json::json!({ "role": "admin" })).await;

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(revision_header(&resp), 1);
    let json = body_json(resp).await;
    assert_eq!(json["revision"], 1);
    assert_eq!(json["principal"], serde_json::json!({ "role": "admin" }));
}

#[tokio::test]
async fn identical_repeat_is_noop_returns_200_same_revision() {
    let app = test_app(build_test_store());
    let payload = serde_json::json!({ "role": "admin" });

    let first = put(&app, "usr_2", payload.clone()).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(revision_header(&first), 1);

    let second = put(&app, "usr_2", payload).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(revision_header(&second), 1);
}

#[tokio::test]
async fn changed_body_returns_200_revision_2() {
    let app = test_app(build_test_store());

    let first = put(&app, "usr_3", serde_json::json!({ "role": "admin" })).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(revision_header(&first), 1);

    let second = put(&app, "usr_3", serde_json::json!({ "role": "owner" })).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(revision_header(&second), 2);
    let json = body_json(second).await;
    assert_eq!(json["principal"], serde_json::json!({ "role": "owner" }));
}

#[tokio::test]
async fn bad_native_id_returns_422() {
    let app = test_app(build_test_store());
    let resp = put(&app, "has%2Aid", serde_json::json!({ "role": "admin" })).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
