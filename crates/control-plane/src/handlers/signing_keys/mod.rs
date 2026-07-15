//! `GET /api/v1/organizations/{org_id}/signing-keys` — the org's event-signing
//! public keys, for external envelope verification (V4 / D8 / N10).
//!
//! Authorization is enforced by the `forgeguard_layer` middleware via the
//! `cp-signing-key-read` action mapping in `app.rs` + `forgeguard.toml`.
//!
//! Serves the event-log signing key (`SK=EVENT_SIGNING_KEY`), not the
//! org-plane request-signing `signing_keys` list — that one lives at
//! `GET /organizations/{org_id}/keys` (`handlers/keys.rs`).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_core::OrgStatus;
use serde::Serialize;

use crate::handlers::AppState;
use crate::vp_client::VpClient;

/// A single event-signing public key, as returned to callers.
#[derive(Serialize)]
struct SigningKeyDto {
    key_id: String,
    public_key: String,
}

/// `GET /api/v1/organizations/{org_id}/signing-keys` response body.
#[derive(Serialize)]
struct ListSigningKeysResponse {
    keys: Vec<SigningKeyDto>,
}

/// `GET /api/v1/organizations/{org_id}/signing-keys`
///
/// `200` + `{"keys":[{"key_id","public_key"}]}` (empty list if no model
/// event has ever been appended); `404` unknown/deleted org; `409` non-active.
/// No revision header — keys are not event-log state.
#[tracing::instrument(name = "list_signing_keys", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn list_signing_keys_handler<V: VpClient + 'static>(
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
) -> Response {
    if let Err(resp) = require_active_org(&state, &raw_org_id).await {
        return resp;
    }

    match state.principals.list_signing_keys(&raw_org_id).await {
        Ok(keys) => {
            let keys = keys
                .into_iter()
                .map(|k| SigningKeyDto {
                    key_id: k.key_id,
                    public_key: k.public_key_pem,
                })
                .collect();
            (StatusCode::OK, Json(ListSigningKeysResponse { keys })).into_response()
        }
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list_signing_keys failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Org existence + `Active` gate — same contract as the promotions module's
/// local helper (404 unknown/deleted, 409 otherwise-non-active, 500 on store
/// error).
async fn require_active_org<V: VpClient + 'static>(
    state: &AppState<V>,
    raw_org_id: &str,
) -> Result<(), Response> {
    let Ok(org_id) = forgeguard_core::OrganizationId::new(raw_org_id) else {
        return Err(crate::handlers::not_found());
    };
    match state.store.get(&org_id).await {
        Ok(Some(record)) => match record.org().status() {
            OrgStatus::Active => Ok(()),
            OrgStatus::Deleted => Err(crate::handlers::not_found()),
            status => Err(state_conflict(status)),
        },
        Ok(None) => Err(crate::handlers::not_found()),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list_signing_keys: org lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// 409 for non-`Active`, non-`Deleted` statuses. Local per module convention
/// (mirrors the promotions module's helper of the same name).
fn state_conflict(status: OrgStatus) -> Response {
    #[derive(Serialize)]
    struct Body {
        error: &'static str,
        reason: String,
    }
    (
        StatusCode::CONFLICT,
        Json(Body {
            error: "org_state_conflict",
            reason: status.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
