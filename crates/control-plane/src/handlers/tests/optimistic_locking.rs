use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::super::test_support::{
    build_test_store, create_draft_org, empty_store, test_app, TEST_API_KEY,
};

// -----------------------------------------------------------------
// Optimistic-locking tests (issue #56, V1)
// -----------------------------------------------------------------

#[tokio::test]
async fn update_with_matching_if_match_returns_200_and_new_etag() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let get_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    let current_etag = get_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("etag header")
        .to_str()
        .unwrap()
        .to_string();

    let new_config = serde_json::json!({
        "version": "2026-04-07",
        "project_id": "todo-app",
        "upstream_url": "https://api.v2.acme.com",
        "default_policy": "deny",
        "routes": [],
        "public_routes": [],
        "features": {}
    });
    let body = serde_json::to_vec(&serde_json::json!({ "config": new_config })).unwrap();
    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", &current_etag)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(put_res.status(), StatusCode::OK);
    let new_etag = put_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("etag on 200")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(
        new_etag, current_etag,
        "etag should change on content change"
    );

    // Round-trip: GET the updated proxy-config and confirm the new etag
    // and upstream_url are durably stored.
    let get_after = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_after.status(), StatusCode::OK);
    let etag_after = get_after
        .headers()
        .get(axum::http::header::ETAG)
        .expect("etag header after put")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(etag_after, new_etag);

    let bytes = get_after.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["upstream_url"], "https://api.v2.acme.com");
}

#[tokio::test]
async fn update_with_stale_if_match_returns_412_and_current_etag() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let stale_etag = "\"definitely-not-the-etag\"";
    let new_config = serde_json::json!({
        "version": "2026-04-07",
        "project_id": "todo-app",
        "upstream_url": "https://stale.example",
        "default_policy": "deny",
        "routes": [],
        "public_routes": [],
        "features": {}
    });
    let body = serde_json::to_vec(&serde_json::json!({ "config": new_config })).unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", stale_etag)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);

    let current_header = res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("ETag header on 412")
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(current_header, stale_etag);

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "etag mismatch");
    assert_eq!(json["current_etag"], current_header);
}

#[tokio::test]
async fn update_without_if_match_still_succeeds() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "todo-app",
            "upstream_url": "https://legacy.example",
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
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(axum::http::header::ETAG).is_some(),
        "200 response should carry ETag when org has a config"
    );
}

#[tokio::test]
async fn update_name_only_with_stale_if_match_is_ignored() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let body = serde_json::to_vec(&serde_json::json!({
        "name": "Acme Corporation (rebranded)"
    }))
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "\"definitely-not-the-etag\"")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn update_name_only_with_wildcard_if_match_is_ignored() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let body = serde_json::to_vec(&serde_json::json!({
        "name": "Acme Corporation (wildcard rebrand)"
    }))
    .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "*")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

// -----------------------------------------------------------------
// Optimistic-locking tests (issue #56, V2) — Draft org code paths
// -----------------------------------------------------------------

/// V2 — Draft org accepts its first PUT without `If-Match` and returns a fresh ETag.
/// Pins D4 (Draft first-PUT) from the shaping doc.
#[tokio::test]
async fn draft_first_put_without_if_match_succeeds_and_returns_etag() {
    let store = empty_store();
    let app = test_app(store.clone());

    // 1. Create a Draft org (no `config` in the POST body).
    let create_res = create_draft_org(&app, "org-v2-draft-happy", "V2 Draft Happy").await;
    assert_eq!(create_res.status(), StatusCode::CREATED);

    // 2. First PUT attaches config; no If-Match. Expect 200 + ETag.
    let put_body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();
    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-v2-draft-happy")
                .header("x-api-key", TEST_API_KEY)
                .header("content-type", "application/json")
                .body(Body::from(put_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_res.status(), StatusCode::OK);
    let put_etag = put_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("PUT must set ETag on Draft first-PUT")
        .to_str()
        .unwrap()
        .to_string();
    assert!(put_etag.starts_with('"') && put_etag.ends_with('"'));

    // 3. GET /proxy-config confirms the stored etag matches.
    let get_res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-v2-draft-happy/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    let get_etag = get_res
        .headers()
        .get(axum::http::header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(get_etag, put_etag, "PUT and GET etags must match");
}

/// V2 — Draft org fails closed against any `If-Match`, even bogus values.
/// Pins D4 (Draft + If-Match → 412) from the shaping doc.
#[tokio::test]
async fn draft_put_with_any_if_match_returns_412() {
    let store = empty_store();
    let app = test_app(store.clone());

    let create_res = create_draft_org(&app, "org-v2-draft-locked", "V2 Draft Locked").await;
    assert_eq!(create_res.status(), StatusCode::CREATED);

    let put_body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();
    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-v2-draft-locked")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "\"any-stale-value\"")
                .header("content-type", "application/json")
                .body(Body::from(put_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_res.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        put_res.headers().get(axum::http::header::ETAG).is_none(),
        "Draft 412 must NOT emit an ETag response header (empty etag cannot be a valid HeaderValue)"
    );

    let body_bytes = put_res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "etag mismatch");
    assert_eq!(body_json["current_etag"], "");

    // The Draft must still have no config — proxy-config returns 409.
    let proxy_res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-v2-draft-locked/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(proxy_res.status(), StatusCode::CONFLICT);
}

// -----------------------------------------------------------------
// Optimistic-locking tests (issue #56, V4) — Wildcard If-Match
// -----------------------------------------------------------------

/// V4 — `If-Match: *` succeeds when the org already has a config.
/// Pins that a wildcard write is unconditional on a Configured org.
#[tokio::test]
async fn put_wildcard_matches_any_configured_etag() {
    let store = build_test_store();
    let app = test_app(store.clone());

    let body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "todo-app",
            "upstream_url": "https://api.wildcard.acme.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();

    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "*")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(put_res.status(), StatusCode::OK);
    let put_etag = put_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("200 response must include an ETag header")
        .to_str()
        .unwrap()
        .to_string();

    let bytes = put_res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["org_id"], "org-acme");

    // Confirm the new upstream_url is stored and the GET ETag matches the PUT ETag.
    let get_res = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    let get_etag = get_res
        .headers()
        .get(axum::http::header::ETAG)
        .expect("proxy-config GET must include ETag")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        put_etag, get_etag,
        "PUT and subsequent GET etags must match"
    );

    let bytes = get_res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["upstream_url"], "https://api.wildcard.acme.com");
}

/// V4 — `If-Match: *` on a Draft org (no stored config) returns 412 with
/// `current_etag == ""` and no ETag response header.
#[tokio::test]
async fn put_wildcard_on_draft_returns_412() {
    let store = empty_store();
    let app = test_app(store.clone());

    // Create a Draft org (no `config` in POST body).
    let create_res = create_draft_org(&app, "org-v3-wildcard-draft", "V3 Wildcard Draft").await;
    assert_eq!(create_res.status(), StatusCode::CREATED);
    assert!(
        create_res.headers().get(axum::http::header::ETAG).is_none(),
        "Draft POST must NOT include ETag"
    );

    // PUT with wildcard If-Match — must fail closed on a Draft.
    let put_body = serde_json::to_vec(&serde_json::json!({
        "config": {
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();
    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-v3-wildcard-draft")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", "*")
                .header("content-type", "application/json")
                .body(Body::from(put_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(put_res.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        put_res.headers().get(axum::http::header::ETAG).is_none(),
        "Draft 412 must NOT emit an ETag response header"
    );

    let body_bytes = put_res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "etag mismatch");
    assert_eq!(body_json["current_etag"], "");
}

/// V2 — Mixed body (name + config) with stale If-Match is rejected wholesale.
/// Pins that A9 ("name-only ignores If-Match") does NOT apply when config is present.
#[tokio::test]
async fn name_plus_config_put_honors_if_match() {
    let store = build_test_store();
    let app = test_app(store.clone());

    // 1. Capture the true current etag.
    let proxy_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(proxy_res.status(), StatusCode::OK);
    let real_etag = proxy_res
        .headers()
        .get(axum::http::header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 2. PUT with BOTH name and config + a stale If-Match.
    let stale = "\"deadbeefdeadbeef\"";
    assert_ne!(stale, real_etag.as_str(), "sanity: stale must differ");
    let put_body = serde_json::to_vec(&serde_json::json!({
        "name": "Acme Mixed (should not stick)",
        "config": {
            "version": "2026-04-07",
            "project_id": "todo-demo",
            "upstream_url": "https://api.mixed.example",
            "default_policy": "deny",
            "routes": [],
            "public_routes": [],
            "features": {}
        }
    }))
    .unwrap();
    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .header("if-match", stale)
                .header("content-type", "application/json")
                .body(Body::from(put_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_res.status(), StatusCode::PRECONDITION_FAILED);
    let body_bytes = put_res.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["error"], "etag mismatch");
    assert_eq!(body_json["current_etag"], real_etag);

    // 3. Neither name nor config was mutated.
    let get_org = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_org.status(), StatusCode::OK);
    let get_bytes = get_org.into_body().collect().await.unwrap().to_bytes();
    let get_json: serde_json::Value = serde_json::from_slice(&get_bytes).unwrap();
    assert_eq!(get_json["name"], "Acme Corp", "name must NOT have changed");

    let get_proxy = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/organizations/org-acme/proxy-config")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let after_etag = get_proxy
        .headers()
        .get(axum::http::header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(after_etag, real_etag, "config etag must be unchanged");
}
