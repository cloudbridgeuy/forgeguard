//! `PUT /api/v1/organizations/{org_id}/principals/{native_id}` — principal
//! upsert handler (plan breadboard N1 -> N2 -> {N12 | N3 -> N4 -> N13}).
//!
//! Authorization for this route is enforced by the `forgeguard_layer`
//! middleware via the `cp-principal-upsert` action mapping in `app.rs` +
//! `forgeguard.toml` — the same config-driven gate every other `cp-*`
//! handler relies on, so no explicit authz code lives in this module.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authz_core::{decide_upsert, UpsertDecision};
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::NativeId;

use forgeguard_core::OrgStatus;

use crate::handlers::{actor_for, AppState};
use crate::vp_client::VpClient;

const REVISION_HEADER: &str = "x-fg-revision";

/// `PUT /api/v1/organizations/{org_id}/principals/{native_id}`
///
/// Flow:
/// 1. Parse `native_id` (422 on failure).
/// 2. Strong-read the existing principal.
/// 3. `decide_upsert` — `NoOp` responds with the current revision and
///    appends nothing; `Changed` mints + signs + appends a new event and
///    advances the revision.
/// 4. `201` when nothing existed before the write, `200` otherwise.
#[tracing::instrument(
    name = "upsert_principal",
    skip_all,
    fields(org_id = %raw_org_id, native_id = %raw_native_id),
)]
pub(crate) async fn upsert_principal<V: VpClient + 'static>(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path((raw_org_id, raw_native_id)): Path<(String, String)>,
    State(state): State<AppState<V>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let Ok(native_id) = NativeId::try_new(raw_native_id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid native_id"})),
        )
            .into_response();
    };

    let Ok(org_id) = forgeguard_core::OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };
    match state.store.get(&org_id).await {
        Ok(Some(record)) => match record.org().status() {
            OrgStatus::Active => {}
            OrgStatus::Deleted => return crate::handlers::not_found(),
            status => return state_conflict(status),
        },
        Ok(None) => return crate::handlers::not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "upsert_principal: org lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let principals = &state.principals;

    let existing = match principals.get_principal(&raw_org_id, &native_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "upsert_principal: read failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let existed_before = existing.is_some();

    match decide_upsert(existing.as_ref(), &body) {
        UpsertDecision::NoOp => {
            let revision = match principals.latest_revision(&raw_org_id).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(org_id = %raw_org_id, error = %e, "upsert_principal: latest_revision failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            // `existing` is `Some` on every `NoOp` path (decide_upsert only
            // returns `NoOp` when the incoming payload matches a stored one).
            respond(StatusCode::OK, &existing.unwrap_or(body), revision.value())
        }
        UpsertDecision::Changed { payload } => {
            let actor = actor_for(&raw_org_id, identity.as_ref());
            let revision = match principals
                .upsert_changed(&raw_org_id, &native_id, actor, payload.clone())
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(org_id = %raw_org_id, error = %e, "upsert_principal: append failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let status = if existed_before {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            respond(status, &payload, revision.value())
        }
    }
}

fn respond(status: StatusCode, principal: &serde_json::Value, revision: u64) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(&revision.to_string()) {
        headers.insert(REVISION_HEADER, val);
    }
    (
        status,
        headers,
        Json(serde_json::json!({ "principal": principal, "revision": revision })),
    )
        .into_response()
}

/// 409 response for non-`Active`, non-`Deleted` org statuses (Draft,
/// Provisioning, etc.). Mirrors `state_conflict` in the users/user_schema
/// handlers but with a distinct error code so clients can branch on it.
fn state_conflict(status: OrgStatus) -> Response {
    use serde::Serialize;
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
