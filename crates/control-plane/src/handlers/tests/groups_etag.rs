use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{create_draft_org, empty_store, test_app, TEST_API_KEY};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup_org_with_group(
    store: Arc<crate::store::InMemoryOrgStore>,
    org_id: &str,
    group_name: &str,
) -> String {
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, org_id, "ETag Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{org_id}/groups"))
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "name": group_name,
                        "allow": ["cp:org:read"],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    resp.headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// PUT If-Match tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_group_without_if_match_returns_412_missing_if_match() {
    let store = empty_store();
    setup_org_with_group(Arc::clone(&store), "org-etag-nomatch-u", "admin").await;

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-etag-nomatch-u/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                // No If-Match header
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let json = body_json(resp).await;
    assert_eq!(json["reason"], "missing_if_match");
}

#[tokio::test]
async fn update_group_with_stale_if_match_returns_412_stale_etag() {
    let store = empty_store();
    let etag = setup_org_with_group(Arc::clone(&store), "org-etag-stale-u", "admin").await;

    // Perform one update to advance the etag
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-etag-stale-u/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &etag)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Try to update again with the old (stale) etag
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-etag-stale-u/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &etag) // stale
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:read"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let json = body_json(resp).await;
    assert_eq!(json["reason"], "stale_etag");
}

#[tokio::test]
async fn update_group_with_wildcard_if_match_on_existing_returns_200() {
    let store = empty_store();
    setup_org_with_group(Arc::clone(&store), "org-etag-wild-u", "admin").await;

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-etag-wild-u/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", "*")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn update_group_with_wildcard_if_match_on_unknown_returns_404() {
    let store = empty_store();
    let app = test_app(Arc::clone(&store));
    let resp = create_draft_org(&app, "org-etag-wild-404-u", "Wild 404 Org").await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // group does not exist
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-etag-wild-404-u/groups/nonexistent")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", "*")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:read"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// DELETE If-Match tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_group_without_if_match_returns_412() {
    let store = empty_store();
    setup_org_with_group(Arc::clone(&store), "org-etag-nomatch-d", "admin").await;

    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-etag-nomatch-d/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                // No If-Match header
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let json = body_json(resp).await;
    assert_eq!(json["reason"], "missing_if_match");
}

#[tokio::test]
async fn delete_group_with_stale_if_match_returns_412() {
    let store = empty_store();
    let etag = setup_org_with_group(Arc::clone(&store), "org-etag-stale-d", "admin").await;

    // Advance the etag via an update
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-etag-stale-d/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .header("if-match", &etag)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "allow": ["cp:org:write"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Attempt delete with the now-stale original etag
    let app = test_app(Arc::clone(&store));
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/organizations/org-etag-stale-d/groups/admin")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &etag) // stale
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    let json = body_json(resp).await;
    assert_eq!(json["reason"], "stale_etag");
}
