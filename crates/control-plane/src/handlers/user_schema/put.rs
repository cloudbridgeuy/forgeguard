//! `PUT /api/v1/organizations/{org_id}/user-schema`
//!
//! Imperative shell: load the org, state-gate (Draft proceeds, Active → 409
//! until V4, Deleted → 404, others → 409), parse the payload, resolve the
//! `If-Match` header, and call the store. Pure helpers (DTOs, error mapping)
//! live in [`super::pure`].

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{OrgStatus, OrganizationId};
use serde::Serialize;

use super::pure::{self, etag_header, UpdateUserSchemaPayload, UserSchemaResource};
use crate::error::Error;
use crate::etag::{self, Etag, IfMatch, ResolvedIfMatch};
use crate::store::OrgStore;

/// `PUT /api/v1/organizations/{org_id}/user-schema`
///
/// Replace the org's declared user attribute schema. State-gated per R9.1:
/// `Draft` writes proceed; `Active` returns `409` with
/// `reason: active_schema_put_requires_v4` (deferred to V4); other non-terminal
/// statuses return `409` with a lowercase status reason; `Deleted` returns
/// `404`.
///
/// Optimistic locking via `If-Match`:
/// - absent → unconditional write (first create or blind overwrite),
/// - strong ETag → conditional update; mismatch → `412` with current etag,
/// - `If-Match: *` on absent row → `412` (fail closed).
///
/// Returns `200 OK` with the stored schema and an `ETag` header on success.
#[tracing::instrument(
    name = "put_user_schema",
    skip_all,
    fields(org_id = %raw_org_id),
)]
pub(crate) async fn put_user_schema_handler(
    ForgeGuardIdentity(_identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<dyn OrgStore>>,
    headers: HeaderMap,
    Json(body): Json<UpdateUserSchemaPayload>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    let record = match store.get(&org_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return crate::handlers::not_found(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "put user_schema: org lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match record.org().status() {
        OrgStatus::Deleted => return crate::handlers::not_found(),
        OrgStatus::Draft => {}
        OrgStatus::Active => return active_state_conflict(),
        status => return state_conflict(status),
    }

    let schema = match pure::parse_user_schema_payload(body) {
        Ok(s) => s,
        Err(err) => return pure::shape_422_response(&err),
    };

    let parsed_if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match);

    // For the wildcard case we need to fetch the current row to extract the
    // etag, or fail closed per RFC 7232 §3.1 if no row exists yet.
    let current_row_for_wildcard = if matches!(parsed_if_match, Some(IfMatch::Wildcard)) {
        match store.get_user_schema(&org_id).await {
            Ok(row) => row,
            Err(e) => {
                tracing::error!(org_id = %raw_org_id, error = %e, "put user_schema: wildcard resolve failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        None
    };

    let stored_etag = current_row_for_wildcard
        .as_ref()
        .map(crate::store::EtagedUserSchema::etag);
    let expected_etag = match etag::resolve_if_match(parsed_if_match, stored_etag) {
        ResolvedIfMatch::Absent => None,
        ResolvedIfMatch::Strong(e) => Some(e),
        ResolvedIfMatch::WildcardMatched => stored_etag.cloned(),
        ResolvedIfMatch::WildcardOnDraft => return precondition_failed_response(None),
    };

    match store
        .put_user_schema(&org_id, schema, expected_etag.as_ref())
        .await
    {
        Ok(eg) => (
            StatusCode::OK,
            etag_header(eg.etag()),
            Json(UserSchemaResource::new(eg.schema().clone())),
        )
            .into_response(),
        Err(Error::PreconditionFailed { current_etag }) => {
            precondition_failed_response(current_etag.as_ref())
        }
        Err(Error::Conflict(_)) => (
            StatusCode::CONFLICT,
            Json(ConflictBody {
                error: "conflict",
                reason: "schema_already_exists".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "put user_schema failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Wire body for `412 Precondition Failed`.
///
/// `current_etag` is the empty string when no row exists yet (`If-Match` on
/// an absent schema, or `If-Match: *` on a row that has not yet been written).
#[derive(Debug, Serialize)]
struct PreconditionFailedBody {
    error: &'static str,
    reason: &'static str,
    current_etag: String,
}

fn precondition_failed_response(current_etag: Option<&Etag>) -> Response {
    let mut response_headers = HeaderMap::new();
    let current_etag_str = match current_etag {
        Some(etag) => {
            if let Ok(val) = etag.as_str().parse() {
                response_headers.insert(axum::http::header::ETAG, val);
            }
            etag.as_str().to_string()
        }
        None => String::new(),
    };
    (
        StatusCode::PRECONDITION_FAILED,
        response_headers,
        Json(PreconditionFailedBody {
            error: "etag mismatch",
            reason: "stale_etag",
            current_etag: current_etag_str,
        }),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
struct ConflictBody {
    error: &'static str,
    reason: String,
}

fn active_state_conflict() -> Response {
    (
        StatusCode::CONFLICT,
        Json(ConflictBody {
            error: "not_implemented",
            reason: "active_schema_put_requires_v4".to_string(),
        }),
    )
        .into_response()
}

fn state_conflict(status: OrgStatus) -> Response {
    (
        StatusCode::CONFLICT,
        Json(ConflictBody {
            error: "org_state_conflict",
            reason: status.to_string(),
        }),
    )
        .into_response()
}
