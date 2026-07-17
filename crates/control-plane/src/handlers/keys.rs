use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::OrganizationId;

use crate::handlers::{actor_for, revision_header_map, AppState};
use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};
use crate::store::OrgStore;
use crate::vp_client::VpClient;

/// `POST /api/v1/organizations/{org_id}/keys` — mint a request-signing key
/// on the event log (`org.key_generated`, #113 V3).
pub(crate) async fn generate_key_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
) -> Response {
    if OrganizationId::new(&raw_org_id).is_err() {
        return super::not_found();
    }

    let actor = actor_for(&raw_org_id, identity.as_ref());

    match state
        .model_events
        .generate_org_key(&raw_org_id, actor)
        .await
    {
        Ok((result, revision)) => key_result_response(&result, revision.value()),
        Err(crate::error::Error::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "generate key failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `DELETE /api/v1/organizations/{org_id}/keys/{key_id}` — revoke a
/// request-signing key on the event log (`org.key_revoked`, narrowing).
///
/// Unknown org -> `404`. Unknown/already-revoked key is the D6 no-op -> `204`
/// with `x-fg-revision` set to the *current* revision (no event appended).
/// Revoked key -> `204` with `x-fg-revision` set to the *new* revision.
pub(crate) async fn revoke_key_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path((raw_org_id, key_id)): Path<(String, String)>,
    State(state): State<AppState<V>>,
) -> Response {
    if OrganizationId::new(&raw_org_id).is_err() {
        return super::not_found();
    }

    let actor = actor_for(&raw_org_id, identity.as_ref());

    match state
        .model_events
        .revoke_org_key(&raw_org_id, &key_id, actor)
        .await
    {
        Ok(Some(revision)) => (
            StatusCode::NO_CONTENT,
            revision_header_map(revision.value()),
        )
            .into_response(),
        Ok(None) => match state.model_events.latest_revision(&raw_org_id).await {
            Ok(revision) => (
                StatusCode::NO_CONTENT,
                revision_header_map(revision.value()),
            )
                .into_response(),
            Err(e) => {
                tracing::error!(org_id = %raw_org_id, key_id = %key_id, error = %e, "revoke key: latest_revision failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        Err(crate::error::Error::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, key_id = %key_id, error = %e, "revoke key failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `POST /api/v1/organizations/{org_id}/keys/{key_id}/rotate` — rotate a
/// request-signing key on the event log (`org.key_rotated`).
pub(crate) async fn rotate_key_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path((raw_org_id, key_id)): Path<(String, String)>,
    State(state): State<AppState<V>>,
) -> Response {
    if OrganizationId::new(&raw_org_id).is_err() {
        return super::not_found();
    }

    let actor = actor_for(&raw_org_id, identity.as_ref());

    match state
        .model_events
        .rotate_org_key(&raw_org_id, &key_id, actor)
        .await
    {
        Ok((result, revision)) => key_result_response(&result, revision.value()),
        Err(crate::error::Error::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(crate::error::Error::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, key_id = %key_id, error = %e, "rotate key failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) async fn list_keys_handler(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<dyn OrgStore>>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return super::not_found();
    };

    // Check that the org exists before listing keys — the store returns
    // an empty vec for nonexistent orgs, but the spec requires 404.
    match store.get(&org_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return super::not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list keys: org lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    match store.list_keys(&org_id).await {
        Ok(keys) => {
            let entries: Vec<serde_json::Value> = keys.iter().map(key_entry_json).collect();
            Json(entries).into_response()
        }
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list keys failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Build the `201 Created` response returned when a new key is issued.
///
/// Used by both `generate_key_handler` and `rotate_key_handler` — the response
/// shape is identical: key_id, private_key, public_key, created_at, revision.
fn key_result_response(result: &GenerateKeyResult, revision: u64) -> Response {
    (
        StatusCode::CREATED,
        revision_header_map(revision),
        Json(serde_json::json!({
            "key_id": result.key_id(),
            "private_key": result.private_key_pem(),
            "public_key": result.public_key_pem(),
            "created_at": result.created_at().to_rfc3339(),
            "revision": revision,
        })),
    )
        .into_response()
}

/// Serialize a `SigningKeyEntry` to its public JSON representation.
///
/// Includes `key_id`, `public_key`, `status`, `created_at`, and optionally
/// `expires_at`. Never includes the private key.
fn key_entry_json(entry: &SigningKeyEntry) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "key_id": entry.key_id(),
        "public_key": entry.public_key_pem(),
        "status": entry.status().to_string(),
        "created_at": entry.created_at().to_rfc3339(),
    });
    if let Some(expires_at) = entry.expires_at() {
        obj["expires_at"] = serde_json::json!(expires_at.to_rfc3339());
    }
    obj
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::super::test_support::{create_org_json, empty_store, test_app, TEST_API_KEY};

    async fn create_org(app: &axum::Router, org_id: &str, name: &str) {
        let body = serde_json::to_string(&create_org_json(org_id, name)).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    async fn generate_key(app: &axum::Router, org_id: &str) -> axum::response::Response {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{org_id}/keys"))
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap()
    }

    async fn revoke_key(
        app: &axum::Router,
        org_id: &str,
        key_id: &str,
    ) -> axum::response::Response {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/organizations/{org_id}/keys/{key_id}"))
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap()
    }

    async fn rotate_key(
        app: &axum::Router,
        org_id: &str,
        key_id: &str,
    ) -> axum::response::Response {
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/organizations/{org_id}/keys/{key_id}/rotate"
            ))
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap()
    }

    async fn list_keys(app: &axum::Router, org_id: &str) -> axum::response::Response {
        let request = Request::builder()
            .uri(format!("/api/v1/organizations/{org_id}/keys"))
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap()
    }

    async fn get_events(app: &axum::Router, org_id: &str) -> serde_json::Value {
        let request = Request::builder()
            .uri(format!("/api/v1/organizations/{org_id}/events"))
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn generate_key_returns_201_with_keypair() {
        let app = test_app(empty_store());
        create_org(&app, "org-keygen", "Key Org").await;

        let response = generate_key(&app, "org-keygen").await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().get("x-fg-revision").is_some());

        let json = body_json(response).await;
        assert!(json["key_id"].is_string());
        assert!(!json["key_id"].as_str().unwrap().is_empty());
        assert!(json["private_key"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY"));
        assert!(json["public_key"].as_str().unwrap().contains("PUBLIC KEY"));
        assert!(json["created_at"].is_string());
        assert!(json["revision"].is_u64());
    }

    #[tokio::test]
    async fn generate_key_unknown_org_returns_404() {
        let app = test_app(empty_store());

        let response = generate_key(&app, "org-ghost").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn generate_then_events_shows_org_key_generated() {
        let app = test_app(empty_store());
        create_org(&app, "org-keygen-ev", "Key Org").await;

        let response = generate_key(&app, "org-keygen-ev").await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let events = get_events(&app, "org-keygen-ev").await;
        let events = events["events"].as_array().unwrap();
        let last = events.last().unwrap();
        assert_eq!(last["kind"], "org.key_generated");
    }

    #[tokio::test]
    async fn revoke_key_returns_204() {
        let app = test_app(empty_store());
        create_org(&app, "org-revoke", "Revoke Org").await;

        let response = generate_key(&app, "org-revoke").await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_json(response).await;
        let key_id = json["key_id"].as_str().unwrap().to_string();

        let response = revoke_key(&app, "org-revoke", &key_id).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().get("x-fg-revision").is_some());
    }

    #[tokio::test]
    async fn revoke_then_last_event_is_narrowing() {
        let app = test_app(empty_store());
        create_org(&app, "org-revoke-ev", "Revoke Org").await;

        let response = generate_key(&app, "org-revoke-ev").await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_json(response).await;
        let key_id = json["key_id"].as_str().unwrap().to_string();

        let response = revoke_key(&app, "org-revoke-ev", &key_id).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let events = get_events(&app, "org-revoke-ev").await;
        let events = events["events"].as_array().unwrap();
        let last = events.last().unwrap();
        assert_eq!(last["kind"], "org.key_revoked");
    }

    #[tokio::test]
    async fn revoke_nonexistent_key_returns_204() {
        let app = test_app(empty_store());
        create_org(&app, "org-revoke-miss", "Revoke Miss").await;

        let response = revoke_key(&app, "org-revoke-miss", "key-does-not-exist").await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().get("x-fg-revision").is_some());
    }

    #[tokio::test]
    async fn revoke_key_unknown_org_returns_404() {
        let app = test_app(empty_store());

        let response = revoke_key(&app, "org-ghost", "key-does-not-exist").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_keys_returns_generated_keys() {
        let app = test_app(empty_store());
        create_org(&app, "org-list-keys", "List Keys Org").await;

        for _ in 0..2 {
            let response = generate_key(&app, "org-list-keys").await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let response = list_keys(&app, "org-list-keys").await;
        assert_eq!(response.status(), StatusCode::OK);

        let json: Vec<serde_json::Value> = {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&bytes).unwrap()
        };
        assert_eq!(json.len(), 2);

        for entry in &json {
            assert!(entry["key_id"].is_string());
            assert!(entry["public_key"].is_string());
            assert!(entry["status"].is_string());
            assert!(entry["created_at"].is_string());
            assert!(entry.get("private_key").is_none());
        }
    }

    #[tokio::test]
    async fn list_keys_empty_org_returns_empty_array() {
        let app = test_app(empty_store());
        create_org(&app, "org-empty-keys", "Empty Keys Org").await;

        let response = list_keys(&app, "org-empty-keys").await;
        assert_eq!(response.status(), StatusCode::OK);

        let json: Vec<serde_json::Value> = {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&bytes).unwrap()
        };
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn list_keys_unknown_org_returns_404() {
        let app = test_app(empty_store());

        let response = list_keys(&app, "org-ghost").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rotate_key_returns_201_with_new_keypair() {
        let app = test_app(empty_store());
        create_org(&app, "org-rotate", "Rotate Org").await;

        let response = generate_key(&app, "org-rotate").await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_json(response).await;
        let original_key_id = json["key_id"].as_str().unwrap().to_string();

        let response = rotate_key(&app, "org-rotate", &original_key_id).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().get("x-fg-revision").is_some());
        let json = body_json(response).await;
        let new_key_id = json["key_id"].as_str().unwrap().to_string();
        assert_ne!(new_key_id, original_key_id);
        assert!(json["private_key"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY"));

        let response = list_keys(&app, "org-rotate").await;
        assert_eq!(response.status(), StatusCode::OK);
        let keys: Vec<serde_json::Value> = {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&bytes).unwrap()
        };
        assert_eq!(keys.len(), 2);

        let old = keys
            .iter()
            .find(|k| k["key_id"] == original_key_id)
            .unwrap();
        assert!(old["status"].as_str().unwrap().starts_with("Rotating("));
        assert!(old["expires_at"].is_string());

        let new = keys.iter().find(|k| k["key_id"] == new_key_id).unwrap();
        assert_eq!(new["status"].as_str().unwrap(), "Active");
    }

    #[tokio::test]
    async fn rotate_key_unknown_key_returns_404() {
        let app = test_app(empty_store());
        create_org(&app, "org-rot-404", "Rot 404").await;

        let response = rotate_key(&app, "org-rot-404", "key-does-not-exist").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rotate_key_revoked_returns_409() {
        let app = test_app(empty_store());
        create_org(&app, "org-rot-revoked", "Rev").await;

        let response = generate_key(&app, "org-rot-revoked").await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_json(response).await;
        let key_id = json["key_id"].as_str().unwrap().to_string();

        let response = revoke_key(&app, "org-rot-revoked", &key_id).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = rotate_key(&app, "org-rot-revoked", &key_id).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn rotate_key_already_rotating_returns_409() {
        let app = test_app(empty_store());
        create_org(&app, "org-rot-twice", "Twice").await;

        let response = generate_key(&app, "org-rot-twice").await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_json(response).await;
        let key_id = json["key_id"].as_str().unwrap().to_string();

        let response = rotate_key(&app, "org-rot-twice", &key_id).await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = rotate_key(&app, "org-rot-twice", &key_id).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
