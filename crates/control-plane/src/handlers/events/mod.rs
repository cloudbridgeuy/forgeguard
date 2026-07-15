//! `GET /api/v1/organizations/{org_id}/events` — replay-mode cursor handler
//! (Task 8): serves the per-org append-only event log to any org member.
//!
//! Authorization for this route is enforced by the `forgeguard_layer`
//! middleware via the `cp-events-read` action mapping in `app.rs` +
//! `forgeguard.toml` — the same config-driven gate every other `cp-*`
//! handler relies on, so no explicit authz code lives in this module.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authz_core::{EventEnvelope, Revision};
use forgeguard_core::OrgStatus;
use serde::Deserialize;

use crate::handlers::min_revision::{
    check_min_revision, parse_min_revision, MinRevisionCheck, MIN_REVISION_HEADER,
};
use crate::handlers::{clamp_limit, AppState, DEFAULT_LIMIT};
use crate::principal_store::PrincipalEventStore;
use crate::vp_client::VpClient;

const REVISION_HEADER: &str = "x-fg-revision";

/// Query parameters accepted by `GET /organizations/{org_id}/events`.
#[derive(Debug, Deserialize)]
pub(crate) struct EventsQuery {
    #[serde(default)]
    after: Option<u64>,
    #[serde(default)]
    limit: Option<u16>,
    /// `wait=1` selects watch mode (V2 long-poll, D3); any other value is a
    /// `400`. Absent means immediate mode.
    #[serde(default)]
    wait: Option<String>,
}

/// Long-poll mode requested via the `wait` query param.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum WaitMode {
    /// No `wait` param: answer immediately (V1 behavior).
    Immediate,
    /// `wait=1`: hold an empty page up to the watch deadline (D3).
    Watch,
}

/// The `wait` param was present with a value other than `1`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct InvalidWait;

/// Parse the raw `wait` query value. Only `1` selects watch mode — anything
/// else (including an empty `wait=`) is an error, not silently ignored.
pub(super) fn parse_wait(raw: Option<&str>) -> Result<WaitMode, InvalidWait> {
    match raw {
        None => Ok(WaitMode::Immediate),
        Some("1") => Ok(WaitMode::Watch),
        Some(_) => Err(InvalidWait),
    }
}

/// Tick interval for watch mode: one strongly-consistent `SEQ` read per tick
/// per held request (D3 — ~10 RCU/s/consumer, priced in the spike).
const WATCH_TICK: Duration = Duration::from_millis(200);
/// Maximum hold before returning an empty page (D3: "up to ~1s").
const WATCH_DEADLINE: Duration = Duration::from_secs(1);

/// N8: hold an empty page, polling the log's revision every [`WATCH_TICK`]
/// until it advances past `after` or [`WATCH_DEADLINE`] elapses. On advance,
/// re-run the cursor query once and return that page; on deadline, return an
/// empty page. An `after` cursor ahead of the log's head simply holds the
/// full deadline — min-revision (`412`) is the mechanism for "client knows
/// more than the server", not this loop.
async fn watch_for_events(
    principals: &Arc<dyn PrincipalEventStore>,
    org_id: &str,
    after: Revision,
    limit: usize,
) -> crate::error::Result<Vec<EventEnvelope>> {
    let deadline = tokio::time::Instant::now() + WATCH_DEADLINE;
    loop {
        tokio::time::sleep(WATCH_TICK).await;
        let current = principals.latest_revision(org_id).await?;
        if current > after {
            return principals.events_after(org_id, after, limit).await;
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(Vec::new());
        }
    }
}

/// `GET /api/v1/organizations/{org_id}/events`
///
/// Flow:
/// 1. Parse `wait` and `X-Fg-Min-Revision`; malformed values -> `400`.
/// 2. Org existence/Active-state check, mirroring the Task 7 handler.
/// 3. Min-revision guard: behind -> `412` (before any wait).
/// 4. Clamp `limit`, read the page; empty page + `wait=1` -> watch loop.
/// 5. Read latest revision, respond.
#[tracing::instrument(name = "list_events", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn list_events_handler<V: VpClient + 'static>(
    Path(raw_org_id): Path<String>,
    Query(query): Query<EventsQuery>,
    request_headers: HeaderMap,
    State(state): State<AppState<V>>,
) -> Response {
    let Ok(wait) = parse_wait(query.wait.as_deref()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "wait must be '1'"})),
        )
            .into_response();
    };

    let raw_min = request_headers
        .get(MIN_REVISION_HEADER)
        .map(|v| v.to_str().unwrap_or(""));
    let Ok(min_revision) = parse_min_revision(raw_min) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid X-Fg-Min-Revision header"})),
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
    let events = if events.is_empty() && wait == WaitMode::Watch {
        match watch_for_events(principals, &raw_org_id, after, limit).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(org_id = %raw_org_id, error = %e, "list_events: watch failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        events
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
