//! Promotion lifecycle handlers (V3 / A7): tombstone + reconciliation.
//!
//! Authorization is enforced by the `forgeguard_layer` middleware via the
//! `cp-resource-tombstone` / `cp-promotion-list` action mappings in `app.rs`
//! + `forgeguard.toml`, so no explicit authz code lives here.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{NativeId, OrgStatus, Segment};
use serde::Deserialize;

use crate::handlers::min_revision::{
    check_min_revision, parse_min_revision, MinRevisionCheck, MIN_REVISION_HEADER,
};
use crate::handlers::{actor_for, clamp_limit, AppState, DEFAULT_LIMIT, REVISION_HEADER};

/// `DELETE /api/v1/organizations/{org_id}/promoted-resources/{resource_type}/{native_id}`
///
/// Flow (N5): parse path (422) -> org gate (404/409) -> strong-read the
/// promotion; absent -> `204` + current revision, no event; present ->
/// `resource.tombstoned` append + hard-delete in one transaction -> `200` +
/// new revision. A lost concurrent-delete race also lands on `204`.
#[tracing::instrument(
    name = "tombstone_promotion",
    skip_all,
    fields(org_id = %raw_org_id, resource_type = %raw_type, native_id = %raw_native_id),
)]
pub(crate) async fn tombstone_promotion_handler(
    ForgeGuardIdentity(identity): ForgeGuardIdentity,
    Path((raw_org_id, raw_type, raw_native_id)): Path<(String, String, String)>,
    State(state): State<AppState>,
) -> Response {
    let Ok(resource_type) = Segment::try_new(&raw_type) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid resource_type"})),
        )
            .into_response();
    };
    let Ok(native_id) = NativeId::try_new(raw_native_id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid native_id"})),
        )
            .into_response();
    };

    if let Err(resp) = require_active_org(&state, &raw_org_id, "tombstone_promotion").await {
        return resp;
    }

    let model_events = &state.model_events;
    let existing = match model_events
        .get_promotion(&raw_org_id, &resource_type, &native_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "tombstone_promotion: read failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let Some(fgrn) = existing else {
        return current_revision_no_content(&state, &raw_org_id).await;
    };

    let actor = actor_for(&raw_org_id, identity.as_ref());
    match model_events
        .tombstone_promotion(&raw_org_id, &resource_type, &native_id, actor)
        .await
    {
        Ok(Some(revision)) => {
            let mut headers = HeaderMap::new();
            if let Ok(val) = HeaderValue::from_str(&revision.value().to_string()) {
                headers.insert(REVISION_HEADER, val);
            }
            (
                StatusCode::OK,
                headers,
                Json(serde_json::json!({ "fgrn": fgrn, "revision": revision.value() })),
            )
                .into_response()
        }
        // Lost a concurrent-delete race: already gone, nothing appended.
        Ok(None) => current_revision_no_content(&state, &raw_org_id).await,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "tombstone_promotion: append failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Query parameters for `GET /organizations/{org_id}/promoted-resources`.
#[derive(Debug, Deserialize)]
pub(crate) struct PromotionsQuery {
    /// Resource type to reconcile. Required.
    #[serde(default, rename = "type")]
    resource_type: Option<String>,
    /// Exclusive-start `native_id` cursor within the type.
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    limit: Option<u16>,
}

/// `GET /api/v1/organizations/{org_id}/promoted-resources?type={t}&after={id}&limit={n}`
///
/// Flow (N6/N14): parse query (400) + min-revision header (400) -> org gate
/// (404/409) -> min-revision guard (412, D5) -> `begins_with(SK, PROMO#{t}#)`
/// page -> `200` + FGRN page + `X-Fg-Revision`.
#[tracing::instrument(name = "list_promotions", skip_all, fields(org_id = %raw_org_id))]
pub(crate) async fn list_promotions_handler(
    Path(raw_org_id): Path<String>,
    Query(query): Query<PromotionsQuery>,
    request_headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let Some(raw_type) = query.resource_type.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "type query parameter is required"})),
        )
            .into_response();
    };
    let Ok(resource_type) = Segment::try_new(raw_type) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid type"})),
        )
            .into_response();
    };
    let after = match query.after.as_deref() {
        None => None,
        Some(raw) => match NativeId::try_new(raw) {
            Ok(id) => Some(id),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid after cursor"})),
                )
                    .into_response();
            }
        },
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

    if let Err(resp) = require_active_org(&state, &raw_org_id, "list_promotions").await {
        return resp;
    }

    if let Some(required) = min_revision {
        let current = match state.model_events.latest_revision(&raw_org_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(org_id = %raw_org_id, error = %e, "list_promotions: min-revision read failed");
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

    let limit = clamp_limit(query.limit.unwrap_or(DEFAULT_LIMIT));
    let entries = match state
        .model_events
        .list_promotions(&raw_org_id, &resource_type, after.as_ref(), limit)
        .await
    {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list_promotions: query failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let revision = match state.model_events.latest_revision(&raw_org_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list_promotions: latest_revision failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let next_after = entries.last().map(|e| e.native_id.clone());
    let promotions: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| serde_json::json!({ "fgrn": e.fgrn, "native_id": e.native_id }))
        .collect();

    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(&revision.value().to_string()) {
        headers.insert(REVISION_HEADER, val);
    }
    (
        StatusCode::OK,
        headers,
        Json(serde_json::json!({
            "promotions": promotions,
            "next_after": next_after,
            "revision": revision.value(),
        })),
    )
        .into_response()
}

/// Org existence + `Active` gate shared by both handlers. `Err` carries the
/// ready-to-return response (404 / 409 / 500).
async fn require_active_org(
    state: &AppState,
    raw_org_id: &str,
    handler: &'static str,
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
            tracing::error!(org_id = %raw_org_id, error = %e, "{handler}: org lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// `204 No Content` + `X-Fg-Revision: <current>` — the idempotent-no-op arm.
async fn current_revision_no_content(state: &AppState, raw_org_id: &str) -> Response {
    let revision = match state.model_events.latest_revision(raw_org_id).await {
        Ok(r) => r.value(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "promotion no-op: latest_revision failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(&revision.to_string()) {
        headers.insert(REVISION_HEADER, val);
    }
    (StatusCode::NO_CONTENT, headers).into_response()
}

/// 409 for non-`Active`, non-`Deleted` statuses. Local per module convention.
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
