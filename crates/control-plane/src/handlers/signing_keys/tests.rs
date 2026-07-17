//! Integration tests for `GET /organizations/{org_id}/signing-keys`.
//! All in-memory — exercises the handler through the full test router.

use std::sync::Arc;

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
    store: &Arc<crate::store::InMemoryOrgStore>,
    org_id: &str,
    status: OrgStatus,
) {
    let id = OrganizationId::new(org_id).unwrap();
    let org = Organization::new(id, format!("{org_id} org"), status, chrono::Utc::now());
    store.write_through_org(org, None).await;
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

async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

#[tokio::test]
async fn signing_keys_active_org_returns_key_list() {
    let store = build_test_store(); // org-acme is Active
    let app = test_app(store);

    let (status, json) = get_json(&app, "/api/v1/organizations/org-acme/signing-keys").await;

    assert_eq!(status, StatusCode::OK);
    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["key_id"], "in-memory-test-key");
    assert!(keys[0]["public_key"]
        .as_str()
        .unwrap()
        .contains("BEGIN PUBLIC KEY"));
}

#[tokio::test]
async fn signing_keys_unknown_org_returns_404() {
    let app = test_app(build_test_store());
    let (status, _) = get_json(&app, "/api/v1/organizations/org-ghost/signing-keys").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signing_keys_still_404_for_deleted_org() {
    let store = empty_in_memory_store();
    seed_org_with_status(&store, "org-deleted-keys", OrgStatus::Deleted).await;
    let app = test_app(store);

    let (status, _) = get_json(&app, "/api/v1/organizations/org-deleted-keys/signing-keys").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signing_keys_readable_for_draft_org() {
    let store = build_test_store();
    let app = test_app(Arc::clone(&store));
    let response = create_draft_org(&app, "org-draft-keys", "Draft Keys").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let (status, json) = get_json(&app, "/api/v1/organizations/org-draft-keys/signing-keys").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn signing_keys_readable_for_suspended_org() {
    let (app, _model_events) = test_app_with_principals(empty_store(), happy_stub());
    let response = create_draft_org(&app, "org-suspended-keys", "Suspended Keys").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        post_verb(&app, "org-suspended-keys", "activate")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        post_verb(&app, "org-suspended-keys", "suspend")
            .await
            .status(),
        StatusCode::OK
    );

    let (status, json) = get_json(
        &app,
        "/api/v1/organizations/org-suspended-keys/signing-keys",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["keys"].as_array().unwrap().len(), 1);
}

/// End-to-end external verification through the HTTP surface only (D8, the
/// V4 demo): upsert → fetch events → fetch keys → recompute canonical bytes
/// → Ed25519-verify. No store internals touched.
#[tokio::test]
async fn stored_envelope_verifies_with_published_key() {
    use base64::Engine as _;
    use forgeguard_authn_core::signing::{verify_bytes, VerifyingKey};
    use forgeguard_authz_core::{canonical_envelope_bytes, EventEnvelope};

    let store = build_test_store();
    let (app, _principals) = test_app_with_principals(store, happy_stub());

    // Mutate: PUT a principal (appends event seq=1).
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/organizations/org-acme/principals/alice")
                .header("content-type", "application/json")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::from(r#"{"role": "admin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Fetch the envelope and the published key — HTTP only.
    let (status, events_json) =
        get_json(&app, "/api/v1/organizations/org-acme/events?after=0").await;
    assert_eq!(status, StatusCode::OK);
    let (status, keys_json) = get_json(&app, "/api/v1/organizations/org-acme/signing-keys").await;
    assert_eq!(status, StatusCode::OK);

    let envelope: EventEnvelope = serde_json::from_value(events_json["events"][0].clone()).unwrap();
    let key = keys_json["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_id"] == envelope.key_id())
        .expect("published key for the envelope's key_id");

    let vk = VerifyingKey::from_public_key_pem(key["public_key"].as_str().unwrap()).unwrap();
    let sig_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(envelope.signature())
        .unwrap()
        .try_into()
        .unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let bytes = canonical_envelope_bytes(&envelope, "org-acme");

    assert!(verify_bytes(&vk, &bytes, &signature).is_ok());

    // Tamper check: a flipped org id must fail verification.
    let tampered = canonical_envelope_bytes(&envelope, "org-evil");
    assert!(verify_bytes(&vk, &tampered, &signature).is_err());
}
