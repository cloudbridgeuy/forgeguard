//! `PUT /api/v1/organizations/{org_id}/user-schema`
//!
//! Imperative shell: load the org, state-gate (Draft and Active proceed,
//! Deleted → 404, others → 409), parse the payload, resolve the `If-Match`
//! header, and call the store. The Draft branch writes DDB only. The Active
//! branch (V4) is Cognito-first: it calls `UpdateUserPool`, tolerates a
//! re-added attribute as success (A4.7 self-healing retry), then writes the
//! new DDB row. Pure helpers (DTOs, error mapping) live in [`super::pure`].

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authn_core::user_pool::{PoolId, UpdatePoolParams, UserPoolError};
use forgeguard_authn_core::user_schema::{
    diff_schema, schema_to_cognito_attrs, AppendOnlyViolation, FieldViolation,
};
use forgeguard_axum::ForgeGuardIdentity;
use forgeguard_core::{OrgStatus, OrganizationId};
use serde::Serialize;

use super::pure::{self, etag_header, UpdateUserSchemaPayload, UserSchemaResource};
use crate::error::Error;
use crate::etag::{self, Etag, EtagCheck, IfMatch, ResolvedIfMatch};
use crate::handlers::AppState;
use crate::store::{OrgRecord, OrgStore};
use crate::user_pool::UserPoolClient;
use crate::vp_client::VpClient;

/// `PUT /api/v1/organizations/{org_id}/user-schema`
///
/// Replace the org's declared user attribute schema. State-gated per R9.1:
/// `Draft` writes proceed (DDB only); `Active` writes go through the
/// Cognito-first flow in [`put_user_schema_active`]; other non-terminal
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
pub(crate) async fn put_user_schema_handler<V: VpClient + 'static>(
    ForgeGuardIdentity(_identity): ForgeGuardIdentity,
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
    headers: HeaderMap,
    Json(body): Json<UpdateUserSchemaPayload>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    let store = state.store.as_ref();

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
        OrgStatus::Active => {
            return put_user_schema_active(
                ActiveSchemaPut {
                    store,
                    user_pool: state.user_pool.as_ref(),
                    record: &record,
                    org_id: &org_id,
                    headers: &headers,
                },
                body,
            )
            .await;
        }
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
        Err(Error::Conflict(_)) => schema_already_exists_response(),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "put user_schema failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Borrowed dependencies for [`put_user_schema_active`].
///
/// Bundled into a params struct so the function stays under the
/// argument-count lint while keeping each dependency individually named.
struct ActiveSchemaPut<'a> {
    store: &'a dyn OrgStore,
    user_pool: &'a dyn UserPoolClient,
    record: &'a OrgRecord,
    org_id: &'a OrganizationId,
    headers: &'a HeaderMap,
}

/// Active-mode schema PUT — Cognito-first, then a conditional DDB write.
///
/// The control flow follows V4 plan §4: decode the payload, read the current
/// schema row, resolve `If-Match`, run the append-only `diff_schema` check,
/// resolve the org's Cognito pool, call `UpdateUserPool`, tolerate a re-added
/// attribute as success, and only then persist the new DDB row.
///
/// `AttributeAlreadyExists` from Cognito is treated as success so a retry
/// after a "Cognito OK + DDB fail" partial failure self-heals (A4.7). Any
/// other Cognito error maps to `502` with the DDB row left unchanged.
async fn put_user_schema_active(
    deps: ActiveSchemaPut<'_>,
    body: UpdateUserSchemaPayload,
) -> Response {
    let ActiveSchemaPut {
        store,
        user_pool,
        record,
        org_id,
        headers,
    } = deps;

    let new_schema = match pure::parse_user_schema_payload(body) {
        Ok(s) => s,
        Err(err) => return pure::shape_422_response(&err),
    };

    let current_row = match store.get_user_schema(org_id).await {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(org_id = %org_id, error = %e, "put user_schema active: row read failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let (stored_etag, old_schema) = match &current_row {
        Some(row) => (Some(row.etag()), row.schema().clone()),
        None => (None, Default::default()),
    };

    let parsed_if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match);
    let expected_etag = match etag::resolve_if_match(parsed_if_match, stored_etag) {
        ResolvedIfMatch::Absent => None,
        ResolvedIfMatch::Strong(e) => Some(e),
        ResolvedIfMatch::WildcardMatched => stored_etag.cloned(),
        // `WildcardOnDraft` is named for its first use site but only means
        // "`If-Match: *` against an absent schema row" — equally a 412 here.
        ResolvedIfMatch::WildcardOnDraft => return precondition_failed_response(None),
    };
    // Fail the optimistic-lock check before touching Cognito so a stale
    // `If-Match` never mutates the pool.
    if let EtagCheck::Mismatch { current } = etag::check_etag(stored_etag, expected_etag.as_ref()) {
        return precondition_failed_response(current.as_ref());
    }

    // Active is append-only: only the violation case is actionable here. The
    // success `SchemaDelta` is intentionally unused — `UpdateUserPool` takes
    // the full rebuilt attribute list and Cognito's `AttributeAlreadyExists`
    // tolerance (below) absorbs the attributes that already exist on the pool.
    if let Err(violation) = diff_schema(&old_schema, &new_schema, &OrgStatus::Active) {
        return append_only_violation_response(violation);
    }

    let schema_attrs = schema_to_cognito_attrs(&new_schema);

    let Some(pool_id_raw) = record
        .config()
        .and_then(crate::config::OrgConfig::cognito_user_pool_id)
    else {
        return pool_not_provisioned_response();
    };
    let pool_id = match PoolId::try_new(pool_id_raw) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(org_id = %org_id, error = %e, "put user_schema active: malformed cognito_user_pool_id");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match user_pool
        .update_user_pool(UpdatePoolParams {
            pool_id,
            schema_attrs,
        })
        .await
    {
        Ok(()) => {}
        // A4.7 self-healing seam: a retry that re-submits an already-registered
        // attribute is the expected idempotent path, not a failure.
        Err(UserPoolError::AttributeAlreadyExists { name }) => {
            tracing::debug!(
                org_id = %org_id,
                attribute = %name,
                "put user_schema active: cognito attribute already exists, tolerated"
            );
        }
        Err(e) => {
            tracing::error!(org_id = %org_id, error = %e, "put user_schema active: cognito update failed");
            return bad_gateway("cognito_update_failed");
        }
    }

    match store
        .put_user_schema(org_id, new_schema, expected_etag.as_ref())
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
        Err(Error::Conflict(_)) => schema_already_exists_response(),
        // Cognito is already ahead of DDB. The caller retries the full PUT;
        // the re-issued `UpdateUserPool` lands on the tolerance branch above
        // and the DDB write then succeeds.
        Err(e) => {
            tracing::error!(org_id = %org_id, error = %e, "put user_schema active: ddb write failed");
            bad_gateway("schema_persist_failed")
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

/// `409 Conflict` for an Active org whose activation ticket never recorded a
/// `cognito_user_pool_id`. Distinguishable from the generic state-conflict
/// `409` via the `error` field so callers can react specifically.
fn pool_not_provisioned_response() -> Response {
    (
        StatusCode::CONFLICT,
        Json(ConflictBody {
            error: "pool_not_provisioned",
            reason: "cognito_user_pool_not_provisioned".to_string(),
        }),
    )
        .into_response()
}

/// `409 Conflict` for a no-`If-Match` PUT that races an existing schema row.
fn schema_already_exists_response() -> Response {
    (
        StatusCode::CONFLICT,
        Json(ConflictBody {
            error: "conflict",
            reason: "schema_already_exists".to_string(),
        }),
    )
        .into_response()
}

/// Wire body for `422` append-only violations — echoes the per-field
/// [`FieldViolation`] list produced by `diff_schema`.
#[derive(Debug, Serialize)]
struct AppendOnlyViolationBody {
    error: &'static str,
    violations: Vec<FieldViolation>,
}

fn append_only_violation_response(violation: AppendOnlyViolation) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(AppendOnlyViolationBody {
            error: "append_only_violation",
            violations: violation.violations,
        }),
    )
        .into_response()
}

/// Wire body for `502 Bad Gateway` — an upstream dependency (Cognito or the
/// DDB write) failed. `reason` names which step.
#[derive(Debug, Serialize)]
struct UpstreamErrorBody {
    error: &'static str,
    reason: &'static str,
}

fn bad_gateway(reason: &'static str) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(UpstreamErrorBody {
            error: "upstream_error",
            reason,
        }),
    )
        .into_response()
}
