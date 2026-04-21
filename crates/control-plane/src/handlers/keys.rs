use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_core::OrganizationId;

use crate::signing_key::{GenerateKeyResult, SigningKeyEntry};
use crate::store::OrgStore;

pub(crate) async fn generate_key_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return super::not_found();
    };

    match store.generate_key(&org_id).await {
        Ok(result) => key_result_response(&result),
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

pub(crate) async fn revoke_key_handler<S: OrgStore>(
    Path((raw_org_id, key_id)): Path<(String, String)>,
    State(store): State<Arc<S>>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return super::not_found();
    };

    match store.revoke_key(&org_id, &key_id).await {
        Ok(()) | Err(crate::error::Error::NotFound(_)) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, key_id = %key_id, error = %e, "revoke key failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) async fn rotate_key_handler<S: OrgStore>(
    Path((raw_org_id, key_id)): Path<(String, String)>,
    State(store): State<Arc<S>>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return super::not_found();
    };

    match store.rotate_signing_key(&org_id, &key_id).await {
        Ok(result) => key_result_response(&result),
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

pub(crate) async fn list_keys_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
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

/// Build the 201 Created response returned when a new key is issued.
///
/// Used by both `generate_key_handler` and `rotate_key_handler` — the response
/// shape is identical: key_id, private_key, public_key, created_at.
fn key_result_response(result: &GenerateKeyResult) -> Response {
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "key_id": result.key_id(),
            "private_key": result.private_key_pem(),
            "public_key": result.public_key_pem(),
            "created_at": result.created_at().to_rfc3339(),
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
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::super::test_support::{create_org_json, empty_store, test_app, TEST_API_KEY};

    #[tokio::test]
    async fn generate_key_returns_201_with_keypair() {
        let store = empty_store();

        // Create an org first
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-keygen", "Key Org")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Generate a key
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations/org-keygen/keys")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["key_id"].is_string());
        assert!(!json["key_id"].as_str().unwrap().is_empty());
        assert!(json["private_key"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY"));
        assert!(json["public_key"].as_str().unwrap().contains("PUBLIC KEY"));
        assert!(json["created_at"].is_string());
    }

    #[tokio::test]
    async fn generate_key_unknown_org_returns_404() {
        let store = empty_store();
        let app = test_app(store);

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations/org-ghost/keys")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn revoke_key_returns_204() {
        let store = empty_store();

        // Create an org
        let app = test_app(Arc::clone(&store));
        let body = serde_json::to_string(&create_org_json("org-revoke", "Revoke Org")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Generate a key
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations/org-revoke/keys")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let key_id = json["key_id"].as_str().unwrap();

        // Revoke it
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/organizations/org-revoke/keys/{key_id}"))
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn revoke_nonexistent_key_returns_204() {
        let store = empty_store();

        // Create an org
        let app = test_app(Arc::clone(&store));
        let body =
            serde_json::to_string(&create_org_json("org-revoke-miss", "Revoke Miss")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Revoke a key that doesn't exist
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/v1/organizations/org-revoke-miss/keys/key-does-not-exist")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_keys_returns_generated_keys() {
        let store = empty_store();

        // Create an org
        let app = test_app(Arc::clone(&store));
        let body =
            serde_json::to_string(&create_org_json("org-list-keys", "List Keys Org")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Generate 2 keys
        for _ in 0..2 {
            let app = test_app(Arc::clone(&store));
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/organizations/org-list-keys/keys")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        // List keys
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .uri("/api/v1/organizations/org-list-keys/keys")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json.len(), 2);

        // Verify each entry has public metadata but no private key
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
        let store = empty_store();

        // Create an org
        let app = test_app(Arc::clone(&store));
        let body =
            serde_json::to_string(&create_org_json("org-empty-keys", "Empty Keys Org")).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations")
            .header("content-type", "application/json")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // List keys before generating any
        let app = test_app(Arc::clone(&store));
        let request = Request::builder()
            .uri("/api/v1/organizations/org-empty-keys/keys")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn list_keys_unknown_org_returns_404() {
        let store = empty_store();
        let app = test_app(store);

        let request = Request::builder()
            .uri("/api/v1/organizations/org-ghost/keys")
            .header("x-api-key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
