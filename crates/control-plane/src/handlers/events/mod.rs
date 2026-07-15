//! `GET /api/v1/organizations/{org_id}/events` — replay-mode cursor handler
//! (Task 8): serves the per-org append-only event log to any org member.
//!
//! Authorization for this route is enforced by the `forgeguard_layer`
//! middleware via the `cp-events-read` action mapping in `app.rs` +
//! `forgeguard.toml` — the same config-driven gate every other `cp-*`
//! handler relies on, so no explicit authz code lives in this module.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authz_core::Revision;
use forgeguard_core::OrgStatus;
use serde::Deserialize;

use crate::handlers::min_revision::{
    check_min_revision, parse_min_revision, MinRevisionCheck, MIN_REVISION_HEADER,
};
use crate::handlers::AppState;
use crate::vp_client::VpClient;

const REVISION_HEADER: &str = "x-fg-revision";
const DEFAULT_LIMIT: u16 = 100;
const MAX_LIMIT: u16 = 1000;

/// Query parameters accepted by `GET /organizations/{org_id}/events`.
#[derive(Debug, Deserialize)]
pub(crate) struct EventsQuery {
    #[serde(default)]
    after: Option<u64>,
    #[serde(default)]
    limit: Option<u16>,
    /// Presence-only flag: any value (including empty) rejects the request
    /// with `400` — long-poll replay lands in V2, so silently ignoring the
    /// param here would be dishonest about what this endpoint does today.
    #[serde(default)]
    wait: Option<String>,
}

/// Clamp a requested page size to [`MAX_LIMIT`], logging when the request
/// exceeded it — "no silent caps": a client asking for more than we serve
/// must be able to see that in the logs, not just get a smaller page back.
fn clamp_limit(requested: u16) -> usize {
    if requested > MAX_LIMIT {
        tracing::warn!(
            requested_limit = requested,
            clamped_limit = MAX_LIMIT,
            "events query limit clamped to maximum"
        );
        usize::from(MAX_LIMIT)
    } else if requested == 0 {
        tracing::warn!("events query limit of 0 floored to 1");
        1
    } else {
        usize::from(requested)
    }
}

/// `GET /api/v1/organizations/{org_id}/events`
///
/// Flow:
/// 1. `wait` present -> `400` (checked before any store I/O).
/// 2. Org existence/Active-state check, mirroring the Task 7 handler.
/// 3. Clamp `limit`, read the page + latest revision, respond.
#[tracing::instrument(name = "list_events", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn list_events_handler<V: VpClient + 'static>(
    Path(raw_org_id): Path<String>,
    Query(query): Query<EventsQuery>,
    request_headers: HeaderMap,
    State(state): State<AppState<V>>,
) -> Response {
    if query.wait.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "wait is not supported yet"})),
        )
            .into_response();
    }

    let raw_min = request_headers
        .get(MIN_REVISION_HEADER)
        .map(|v| v.to_str().unwrap_or(""));
    let min_revision = match parse_min_revision(raw_min) {
        Ok(m) => m,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid X-Fg-Min-Revision header"})),
            )
                .into_response();
        }
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
            tracing::error!(org_id = %raw_org_id, error = %e, "list_events: org lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    if let Some(required) = min_revision {
        let current = match state.principals.latest_revision(&raw_org_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(org_id = %raw_org_id, error = %e, "list_events: min-revision read failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        if let MinRevisionCheck::Behind { current, required } =
            check_min_revision(current, required)
        {
            let mut headers = HeaderMap::new();
            if let Ok(val) = HeaderValue::from_str(&current.value().to_string()) {
                headers.insert(REVISION_HEADER, val);
            }
            return (
                StatusCode::PRECONDITION_FAILED,
                headers,
                Json(serde_json::json!({
                    "error": "revision_behind",
                    "current_revision": current.value(),
                    "min_revision": required.value(),
                })),
            )
                .into_response();
        }
    }

    let after = Revision::new(query.after.unwrap_or(0));
    let limit = clamp_limit(query.limit.unwrap_or(DEFAULT_LIMIT));

    let principals = &state.principals;
    let events = match principals.events_after(&raw_org_id, after, limit).await {
        Ok(events) => events,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list_events: events_after failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let revision = match principals.latest_revision(&raw_org_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list_events: latest_revision failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let next_after = events.last().map_or(after.value(), |e| e.seq().value());

    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(&revision.value().to_string()) {
        headers.insert(REVISION_HEADER, val);
    }
    (
        StatusCode::OK,
        headers,
        Json(serde_json::json!({
            "events": events,
            "next_after": next_after,
            "revision": revision.value(),
        })),
    )
        .into_response()
}

/// 409 response for non-`Active`, non-`Deleted` org statuses (Draft,
/// Provisioning, etc.). Mirrors `state_conflict` in the principals/users/
/// user_schema handlers but kept local per that same convention.
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
