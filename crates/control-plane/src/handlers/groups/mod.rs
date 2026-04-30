//! Group RBAC handlers for the control-plane API.
//!
//! ## Module structure
//!
//! - `pure` — functional core: DTOs, conversions, etag computation, error ADT,
//!   error shaper. No I/O. Fully unit-tested.
//! - `codec` — pure DynamoDB item encoder/decoder. No I/O.
//! - `mod` (this file) — request DTOs, `pub(crate)` re-exports, and handler
//!   bodies (imperative shell calling into `pure` and the `OrgStore` trait).

pub(crate) mod codec;
pub(crate) mod pure;

pub(crate) use pure::{shape_group_error_response, GroupHandlerError};

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use forgeguard_authz_core::{validate_rbac_entry, RbacEntry};
use forgeguard_core::{OrgStatus, OrganizationId};
use serde::Deserialize;

use crate::etag;
use crate::metrics::PreconditionReason;
use crate::store::{EtagedGroup, OrgStore};

// ---------------------------------------------------------------------------
// Helper: default for serde
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Private imperative-shell helpers (I/O — call store, return Response on err)
// ---------------------------------------------------------------------------

/// Fetch the org record for `org_id`, returning a ready `Response` on any
/// failure (404 for missing, 500 for store errors).
async fn require_org<S: OrgStore>(
    store: &S,
    org_id: &OrganizationId,
    raw_org_id: &str,
    ctx: &str,
) -> Result<crate::store::OrgRecord, Response> {
    match store.get(org_id).await {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err(crate::handlers::not_found()),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "{ctx}");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// List groups and build the mutable `all_after` vec (existing entries with
/// `proposed_name` removed, ready for the caller to push the proposed entry).
async fn all_after_without<S: OrgStore>(
    store: &S,
    org_id: &OrganizationId,
    raw_org_id: &str,
    proposed_name: &str,
    ctx: &str,
) -> Result<Vec<RbacEntry>, Response> {
    match store.list_groups(org_id).await {
        Ok(gs) => {
            let mut entries: Vec<RbacEntry> = gs.into_iter().map(|g| g.entry().clone()).collect();
            entries.retain(|e| e.name != proposed_name);
            Ok(entries)
        }
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "{ctx}");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Build a [`HeaderMap`] containing a single strong `ETag` header.
fn etag_header(etag: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(val) = etag.parse() {
        headers.insert(axum::http::header::ETAG, val);
    }
    headers
}

/// Extract and parse the `If-Match` header. Returns `None` when absent or
/// unparseable (treated identically to "header not sent").
fn parse_if_match_header(headers: &HeaderMap) -> Option<etag::IfMatch> {
    headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match)
}

/// Fetch an existing group or return a shaped 404/500 `Response`.
async fn require_group<S: OrgStore>(
    store: &S,
    org_id: &OrganizationId,
    name: &str,
    raw_org_id: &str,
    ctx: &str,
) -> Result<EtagedGroup, Response> {
    match store.get_group(org_id, name).await {
        Ok(Some(g)) => Ok(g),
        Ok(None) => Err(shape_group_error_response(&GroupHandlerError::NotFound)),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, group = %name, error = %e, "{ctx}");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Request DTOs
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/organizations/{org_id}/groups`.
///
/// Pure data — `Deserialize` derive only, no behaviour.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub inherits: Vec<String>,
    pub allow: Vec<String>,
    #[serde(default = "default_true")]
    pub tenant_scoped: bool,
}

/// Request body for `PUT /api/v1/organizations/{org_id}/groups/{name}`.
///
/// Pure data — `Deserialize` derive only, no behaviour.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateGroupRequest {
    /// Optional. When present, MUST equal the path `name` or the handler
    /// returns `422 NameMismatch`.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub inherits: Vec<String>,
    pub allow: Vec<String>,
    #[serde(default = "default_true")]
    pub tenant_scoped: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/organizations/{org_id}/groups`
///
/// Create a new RBAC group for the organisation. Returns `201 Created` with
/// `GroupResource` and an `ETag` header.
///
/// - V2 (Draft orgs only): Active org returns `501 Not Implemented`.
/// - Duplicate name returns `409 Conflict`.
pub(crate) async fn create_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
    Json(body): Json<CreateGroupRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    let record = match require_org(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        "create group: org lookup failed",
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if record.org().status() == OrgStatus::Active {
        // V2: Active orgs are unsupported. V3 lands the VP push branch.
        return StatusCode::NOT_IMPLEMENTED.into_response();
    }

    // Build `all_after`: existing groups with the proposed name removed (upsert
    // semantics for create means we need the full post-write set to detect cycles).
    let proposed = pure::rbac_from_create(body);
    let mut all_after = match all_after_without(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        &proposed.name,
        "create group: list failed",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    all_after.push(proposed.clone());
    let validated = match validate_rbac_entry(proposed, &all_after) {
        Ok(v) => v,
        Err(reason) => return shape_group_error_response(&GroupHandlerError::Validation(reason)),
    };

    // Conditional write (imperative shell): None expected_etag = create-only
    match store.put_group(&org_id, validated, None).await {
        Ok(eg) => (
            StatusCode::CREATED,
            etag_header(eg.etag()),
            Json(pure::group_resource_from(eg.entry(), eg.etag())),
        )
            .into_response(),
        Err(crate::error::Error::Conflict(_)) => {
            shape_group_error_response(&GroupHandlerError::AlreadyExists)
        }
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "create group failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `GET /api/v1/organizations/{org_id}/groups`
///
/// List all RBAC groups for the organisation.
/// Returns `200 OK` with an array of `GroupResource`.
///
/// ## `If-None-Match: *` semantics
///
/// RFC 7232 §3.2: `If-None-Match: *` matches when any stored representation
/// exists. For a collection this is approximated as "any groups exist": if
/// the list is non-empty the handler returns `304 Not Modified`; if the list
/// is empty (no groups declared yet) `*` does not match and the handler
/// returns `200` with an empty array. This is the conservative choice —
/// callers that cache "empty" get the freshest possible view without a
/// conditional-request trick, while callers that cache a non-empty snapshot
/// benefit from the fast path.
pub(crate) async fn list_handler<S: OrgStore>(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<S>>,
    headers: HeaderMap,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    // Verify org exists
    if let Err(resp) = require_org(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        "list groups: org lookup failed",
    )
    .await
    {
        return resp;
    }

    let groups = match store.list_groups(&org_id).await {
        Ok(gs) => gs,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "list groups failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // If-None-Match: * — 304 when collection is non-empty (see doc comment).
    if !groups.is_empty() {
        let if_none_match = headers
            .get(axum::http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .and_then(etag::parse_if_match);
        if matches!(if_none_match, Some(etag::IfMatch::Wildcard)) {
            return StatusCode::NOT_MODIFIED.into_response();
        }
    }

    let resources: Vec<_> = groups
        .iter()
        .map(|eg| pure::group_resource_from(eg.entry(), eg.etag()))
        .collect();
    Json(resources).into_response()
}

/// `GET /api/v1/organizations/{org_id}/groups/{name}`
///
/// Fetch a single RBAC group by name.
/// Returns `200 OK` with `GroupResource` and an `ETag` header, or `404`.
///
/// ## `If-None-Match` semantics
///
/// Strong ETag comparison: returns `304` when the stored etag equals the
/// caller's `If-None-Match` value. `If-None-Match: *` returns `304` when the
/// group exists (i.e. always on a 200 path).
pub(crate) async fn get_handler<S: OrgStore>(
    Path((raw_org_id, name)): Path<(String, String)>,
    State(store): State<Arc<S>>,
    headers: HeaderMap,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    // Verify org exists
    if let Err(resp) = require_org(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        "get group: org lookup failed",
    )
    .await
    {
        return resp;
    }

    let eg = match require_group(
        store.as_ref(),
        &org_id,
        &name,
        &raw_org_id,
        "get group failed",
    )
    .await
    {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    // If-None-Match check
    let if_none_match = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match);
    match etag::check_if_none_match(if_none_match, Some(eg.etag())) {
        etag::IfNoneMatchResult::Matched | etag::IfNoneMatchResult::WildcardMatched => {
            return (StatusCode::NOT_MODIFIED, etag_header(eg.etag())).into_response();
        }
        etag::IfNoneMatchResult::NotMatched | etag::IfNoneMatchResult::WildcardOnDraft => {}
    }

    (
        StatusCode::OK,
        etag_header(eg.etag()),
        Json(pure::group_resource_from(eg.entry(), eg.etag())),
    )
        .into_response()
}

/// `PUT /api/v1/organizations/{org_id}/groups/{name}`
///
/// Update an existing RBAC group. Requires `If-Match` (412 with
/// `reason: "missing_if_match"` when absent). `If-Match: *` is accepted per
/// RFC 7232 §3.1 — on a non-existent row this is treated as a 404 (fail
/// closed, no row to match against).
///
/// Returns `200 OK` with updated `GroupResource` and an `ETag` header.
pub(crate) async fn update_handler<S: OrgStore>(
    Path((raw_org_id, name)): Path<(String, String)>,
    State(store): State<Arc<S>>,
    headers: HeaderMap,
    Json(body): Json<UpdateGroupRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    // Org lookup + Active gate
    let record = match require_org(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        "update group: org lookup failed",
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if record.org().status() == OrgStatus::Active {
        return StatusCode::NOT_IMPLEMENTED.into_response();
    }

    // If-Match is required for PUT
    let if_match_raw = parse_if_match_header(&headers);
    if if_match_raw.is_none() {
        crate::metrics::record_precondition_failed(PreconditionReason::MissingIfMatch);
        return shape_group_error_response(&GroupHandlerError::PreconditionFailed {
            current_etag: String::new(),
            reason: PreconditionReason::MissingIfMatch,
        });
    }

    // Fetch the existing group to validate the If-Match
    let existing = match require_group(
        store.as_ref(),
        &org_id,
        &name,
        &raw_org_id,
        "update group: get failed",
    )
    .await
    {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    // Resolve If-Match against the stored etag
    let resolved = etag::resolve_if_match(if_match_raw, Some(existing.etag()));
    let expected_etag: Option<String> = match &resolved {
        etag::ResolvedIfMatch::Strong(e) => Some(e.clone()),
        etag::ResolvedIfMatch::WildcardMatched => None, // unconditional write
        // Wildcard on absent row — fail closed (404 already returned above)
        etag::ResolvedIfMatch::WildcardOnDraft => {
            return shape_group_error_response(&GroupHandlerError::NotFound);
        }
        etag::ResolvedIfMatch::Absent => {
            // Already handled above (if_match_raw.is_none() => 412)
            return shape_group_error_response(&GroupHandlerError::PreconditionFailed {
                current_etag: String::new(),
                reason: PreconditionReason::MissingIfMatch,
            });
        }
    };

    // Pure conversion — validates name match between body and path
    let proposed = match pure::rbac_from_update(&name, body) {
        Ok(e) => e,
        Err(reason) => return shape_group_error_response(&GroupHandlerError::Validation(reason)),
    };

    // Build post-write set: replace existing entry for `name` with proposed
    let mut all_after = match all_after_without(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        &proposed.name,
        "update group: list failed",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    all_after.push(proposed.clone());

    let validated = match validate_rbac_entry(proposed, &all_after) {
        Ok(v) => v,
        Err(reason) => return shape_group_error_response(&GroupHandlerError::Validation(reason)),
    };

    match store
        .put_group(&org_id, validated, expected_etag.as_deref())
        .await
    {
        Ok(eg) => (
            StatusCode::OK,
            etag_header(eg.etag()),
            Json(pure::group_resource_from(eg.entry(), eg.etag())),
        )
            .into_response(),
        Err(crate::error::Error::PreconditionFailed { current_etag }) => {
            crate::metrics::record_precondition_failed(PreconditionReason::StaleEtag);
            shape_group_error_response(&GroupHandlerError::PreconditionFailed {
                current_etag,
                reason: PreconditionReason::StaleEtag,
            })
        }
        Err(crate::error::Error::NotFound(_)) => {
            shape_group_error_response(&GroupHandlerError::NotFound)
        }
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, group = %name, error = %e, "update group failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `DELETE /api/v1/organizations/{org_id}/groups/{name}`
///
/// Delete an RBAC group. Requires `If-Match` (412 with
/// `reason: "missing_if_match"` when absent).
///
/// Pre-checks (both evaluated, results combined):
/// - No other groups inherit from this one (`list_inheritors`).
/// - No users are currently members of this group (`count_memberships_for_group`).
///
/// Returns `204 No Content` on success.
///
/// Note: a member could be added or a new inheriting group could be wired
/// between the concurrent pre-check reads and the conditional delete; this is
/// acceptable for V2 (Draft-only orgs, low concurrency), and the etag
/// pre-condition still protects against blind overwrite of the group row itself.
pub(crate) async fn delete_handler<S: OrgStore>(
    Path((raw_org_id, name)): Path<(String, String)>,
    State(store): State<Arc<S>>,
    headers: HeaderMap,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };

    // Org lookup + Active gate (record needed for the V3 todo! branch after delete)
    let record = match require_org(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        "delete group: org lookup failed",
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // If-Match is required for DELETE
    let if_match_raw = parse_if_match_header(&headers);
    if if_match_raw.is_none() {
        crate::metrics::record_precondition_failed(PreconditionReason::MissingIfMatch);
        return shape_group_error_response(&GroupHandlerError::PreconditionFailed {
            current_etag: String::new(),
            reason: PreconditionReason::MissingIfMatch,
        });
    }

    // Fetch the group to validate it exists and get the etag
    let existing = match require_group(
        store.as_ref(),
        &org_id,
        &name,
        &raw_org_id,
        "delete group: get failed",
    )
    .await
    {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    // Resolve If-Match against the stored etag
    let resolved = etag::resolve_if_match(if_match_raw, Some(existing.etag()));
    let expected_etag: String = match &resolved {
        etag::ResolvedIfMatch::Strong(e) => e.clone(),
        etag::ResolvedIfMatch::WildcardMatched => existing.etag().to_string(),
        // Wildcard on absent row — not reachable (we 404'd above), but handle defensively
        etag::ResolvedIfMatch::WildcardOnDraft => {
            return shape_group_error_response(&GroupHandlerError::NotFound);
        }
        etag::ResolvedIfMatch::Absent => {
            // Already handled above (if_match_raw.is_none() => 412)
            return shape_group_error_response(&GroupHandlerError::PreconditionFailed {
                current_etag: String::new(),
                reason: PreconditionReason::MissingIfMatch,
            });
        }
    };

    // Pre-checks: run BOTH and combine results
    let (memberships_result, inheritors_result) = tokio::join!(
        store.count_memberships_for_group(&org_id, &name),
        store.list_inheritors(&org_id, &name),
    );
    let memberships = match memberships_result {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, group = %name, error = %e, "delete group: memberships check failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let inheritors = match inheritors_result {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, group = %name, error = %e, "delete group: inheritors check failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if !memberships.is_empty() || !inheritors.is_empty() {
        return shape_group_error_response(&GroupHandlerError::DeleteConflict {
            blocking_inheritors: inheritors,
            memberships_count: memberships,
        });
    }

    match store.delete_group(&org_id, &name, &expected_etag).await {
        Ok(()) => {
            if record.org().status() == OrgStatus::Active {
                todo!("V3 DeletePolicy + rollback semantics");
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(crate::error::Error::PreconditionFailed { current_etag }) => {
            crate::metrics::record_precondition_failed(PreconditionReason::StaleEtag);
            shape_group_error_response(&GroupHandlerError::PreconditionFailed {
                current_etag,
                reason: PreconditionReason::StaleEtag,
            })
        }
        Err(crate::error::Error::NotFound(_)) => {
            shape_group_error_response(&GroupHandlerError::NotFound)
        }
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, group = %name, error = %e, "delete group failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
