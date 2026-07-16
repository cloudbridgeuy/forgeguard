//! Integration tests for the promotion tombstone + reconciliation endpoints.
//!
//! All in-memory — seeds promotions directly through the
//! `InMemoryModelEventStore` handle returned by `test_app_with_principals`,
//! since there is no promotion-create HTTP API in this slice.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use forgeguard_authz_core::Actor;
use forgeguard_core::{NativeId, Segment};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::handlers::test_support::{build_test_store, test_app_with_principals, TEST_API_KEY};
use crate::vp_client::stub::happy_stub;

const ORG: &str = "org-acme";

fn doc_type() -> Segment {
    Segment::try_new("document").unwrap()
}

fn nid(s: &str) -> NativeId {
    NativeId::try_new(s).unwrap()
}

async fn tombstone(app: &axum::Router, native_id: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/organizations/{ORG}/promoted-resources/document/{native_id}"
                ))
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn list_with_headers(
    app: &axum::Router,
    query: &str,
    extra_headers: &[(&str, &str)],
) -> axum::response::Response {
    let uri = if query.is_empty() {
        format!("/api/v1/organizations/{ORG}/promoted-resources")
    } else {
        format!("/api/v1/organizations/{ORG}/promoted-resources?{query}")
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

async fn list(app: &axum::Router, query: &str) -> axum::response::Response {
    list_with_headers(app, query, &[]).await
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
async fn tombstone_existing_promotion_returns_200_with_new_revision_and_event() {
    let (app, principals) = test_app_with_principals(build_test_store(), happy_stub());
    principals
        .put_promotion(ORG, &doc_type(), &nid("doc_1"), Actor::System)
        .await
        .unwrap();

    let resp = tombstone(&app, "doc_1").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(revision_header(&resp), 2);
    let json = body_json(resp).await;
    assert_eq!(json["fgrn"], "fgrn:org-acme:resource:document/doc_1");
    assert_eq!(json["revision"], 2);

    let events_resp = get_events(&app, "after=0").await;
    let events_json = body_json(events_resp).await;
    let kinds: Vec<String> = events_json["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, vec!["resource.promoted", "resource.tombstoned"]);
}

#[tokio::test]
async fn repeat_tombstone_returns_204_with_current_revision_and_no_event() {
    let (app, principals) = test_app_with_principals(build_test_store(), happy_stub());
    principals
        .put_promotion(ORG, &doc_type(), &nid("doc_1"), Actor::System)
        .await
        .unwrap();
    tombstone(&app, "doc_1").await;

    let resp = tombstone(&app, "doc_1").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(revision_header(&resp), 2);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(bytes.is_empty());

    let events_resp = get_events(&app, "after=0").await;
    let events_json = body_json(events_resp).await;
    assert_eq!(events_json["events"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn tombstone_unknown_promotion_returns_204() {
    let (app, _principals) = test_app_with_principals(build_test_store(), happy_stub());

    let resp = tombstone(&app, "doc_missing").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(revision_header(&resp), 0);
}

#[tokio::test]
async fn tombstone_invalid_native_id_returns_422() {
    let (app, _principals) = test_app_with_principals(build_test_store(), happy_stub());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/organizations/{ORG}/promoted-resources/document/not%20valid"
                ))
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn list_missing_type_returns_400() {
    let (app, _principals) = test_app_with_principals(build_test_store(), happy_stub());

    let resp = list(&app, "").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "type query parameter is required");
}

#[tokio::test]
async fn list_returns_fgrn_page_sorted_with_next_after() {
    let (app, principals) = test_app_with_principals(build_test_store(), happy_stub());
    for id in ["doc_1", "doc_2", "doc_3"] {
        principals
            .put_promotion(ORG, &doc_type(), &nid(id), Actor::System)
            .await
            .unwrap();
    }

    let resp = list(&app, "type=document&limit=2").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let native_ids: Vec<String> = json["promotions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["native_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(native_ids, vec!["doc_1", "doc_2"]);
    assert_eq!(json["next_after"], "doc_2");
    assert_eq!(json["revision"], 3);

    let resp = list(&app, "type=document&after=doc_2").await;
    let json = body_json(resp).await;
    let native_ids: Vec<String> = json["promotions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["native_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(native_ids, vec!["doc_3"]);
    assert_eq!(json["next_after"], "doc_3");
}

#[tokio::test]
async fn list_empty_type_returns_empty_page_with_null_next_after() {
    let (app, _principals) = test_app_with_principals(build_test_store(), happy_stub());

    let resp = list(&app, "type=document").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["promotions"].as_array().unwrap().len(), 0);
    assert!(json["next_after"].is_null());
}

#[tokio::test]
async fn list_min_revision_behind_returns_412() {
    let (app, principals) = test_app_with_principals(build_test_store(), happy_stub());
    principals
        .put_promotion(ORG, &doc_type(), &nid("doc_1"), Actor::System)
        .await
        .unwrap();

    let resp = list_with_headers(&app, "type=document", &[("x-fg-min-revision", "9")]).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let json = body_json(resp).await;
    assert_eq!(json["current_revision"], 1);
    assert_eq!(json["min_revision"], 9);
}

#[tokio::test]
async fn tombstoned_promotion_disappears_from_list() {
    let (app, principals) = test_app_with_principals(build_test_store(), happy_stub());
    principals
        .put_promotion(ORG, &doc_type(), &nid("doc_1"), Actor::System)
        .await
        .unwrap();
    principals
        .put_promotion(ORG, &doc_type(), &nid("doc_2"), Actor::System)
        .await
        .unwrap();

    tombstone(&app, "doc_1").await;

    let resp = list(&app, "type=document").await;
    let json = body_json(resp).await;
    let native_ids: Vec<String> = json["promotions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["native_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(native_ids, vec!["doc_2"]);
}

#[tokio::test]
async fn missing_org_returns_404() {
    let (app, _principals) = test_app_with_principals(build_test_store(), happy_stub());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-missing/promoted-resources/document/doc_1")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-missing/promoted-resources?type=document")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
