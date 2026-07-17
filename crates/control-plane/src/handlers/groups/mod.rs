//! Group RBAC handlers for the control-plane API.
//!
//! ## Module structure
//!
//! - `pure` — functional core: DTOs, conversions, etag computation, error ADT,
//!   error shaper. No I/O. Fully unit-tested.
//! - `active_pure` — functional core for the V3 Active-org write path:
//!   `OrgWriteContext` parsing, dependent walking, Cedar compilation, and the
//!   wire-body types for the V3 error variants. No I/O.
//! - `codec` — pure DynamoDB item encoder/decoder. No I/O.
//! - `mod` (this file) — request DTOs, `pub(crate)` re-exports, and handler
//!   bodies (imperative shell calling into `pure` and the `OrgStore` trait).

pub(crate) mod active;
pub(crate) mod active_pure;
pub(crate) mod codec;
pub(crate) mod pure;
pub(crate) mod saga;

pub(crate) use pure::{shape_group_error_response, GroupHandlerError};

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use forgeguard_authz_core::{validate_rbac_entry, Actor, RbacEntry};
use forgeguard_core::OrganizationId;
use serde::Deserialize;

use self::active_pure::{compile_for_active, ActiveStateError, OrgWriteContext, VpStage};
use crate::etag::{self, Etag};
use crate::handlers::AppState;
use crate::metrics::PreconditionReason;
use crate::store::{EtagedGroup, OrgStore};
use crate::vp_client::VpClient;

// ---------------------------------------------------------------------------
// NOTE (#113 V4, Task 4 — rough edge for Task 5):
//
// Task 5 owns the real handler rewrite: parsing `X-Fg-If-Revision`, threading
// `actor_for(...)` from the resolved identity, and mapping `GroupWriteOutcome`
// into the `x-fg-revision` response header. Until then, every call site below
// passes `Actor::System` (no identity extractor is wired into these handlers
// yet) and `expected_revision: None` (the existing `If-Match`/etag precondition
// machinery is untouched and still governs these paths), and discards the
// `GroupWriteOutcome` half of `apply_create`/`apply_update`'s return tuple.
// ---------------------------------------------------------------------------

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
async fn require_org(
    store: &dyn OrgStore,
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

/// List groups and project them down to plain `RbacEntry`s. Callers derive
/// both `all_after` (with the proposed entry replacing any same-name row) and,
/// for UPDATE/DELETE, the prior-validation set from this single fetch.
async fn list_existing_entries(
    store: &dyn OrgStore,
    org_id: &OrganizationId,
    raw_org_id: &str,
    ctx: &str,
) -> Result<Vec<RbacEntry>, Response> {
    match store.list_groups(org_id).await {
        Ok(gs) => Ok(gs.into_iter().map(|g| g.entry().clone()).collect()),
        Err(e) => {
            tracing::error!(org_id = %raw_org_id, error = %e, "{ctx}");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Build the post-write entry set: existing rows with `proposed_name` removed,
/// followed by the caller's proposed entry.
fn all_after_with_proposed(existing: &[RbacEntry], proposed: &RbacEntry) -> Vec<RbacEntry> {
    let mut out: Vec<RbacEntry> = existing
        .iter()
        .filter(|e| e.name != proposed.name)
        .cloned()
        .collect();
    out.push(proposed.clone());
    out
}

/// Shape `OrgWriteContext::from_record` parse failures into the wire response.
///
/// Today the only failure mode is `ActiveWithoutVpStore`. Per Risk #5 in the
/// implementation plan, this surfaces as 503 `vp_push_failed` with
/// `stage="parent"` so operators page the same way they would for a real F3.
fn shape_active_state_error(err: &ActiveStateError, raw_org_id: &str, group: &str) -> Response {
    tracing::error!(
        org_id = %raw_org_id,
        group = %group,
        error = ?err,
        "active org has no vp_store_id; saga invariant violated",
    );
    shape_group_error_response(&GroupHandlerError::VpPushFailed {
        stage: VpStage::Parent,
        completed: vec![],
        failed: None,
        remaining: vec![],
    })
}

/// Build a [`HeaderMap`] containing a single strong `ETag` header.
fn etag_header(etag: &Etag) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(val) = etag.as_str().parse() {
        headers.insert(axum::http::header::ETAG, val);
    }
    headers
}

/// Extract and parse the `If-Match` header. Returns `None` when absent or
/// unparsable (treated identically to "header not sent").
fn parse_if_match_header(headers: &HeaderMap) -> Option<etag::IfMatch> {
    headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(etag::parse_if_match)
}

/// Fetch an existing group or return a shaped 404/500 `Response`.
async fn require_group(
    store: &dyn OrgStore,
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
/// Active-org behaviour (V3): the DDB write is paired with a VP `CreatePolicy`
/// for `cp-rbac-{name}`. F3 (VP push fails after DDB commit) triggers a
/// compensating DDB delete and surfaces 503 `vp_push_failed`. F3' (rollback
/// also fails) increments `forgeguard_cp_group_rollback_failed_total{stage="parent"}`
/// and surfaces 500 `inconsistent_state`.
///
/// Duplicate name returns `409 Conflict`.
pub(crate) async fn create_handler<V: VpClient + 'static>(
    Path(raw_org_id): Path<String>,
    State(state): State<AppState<V>>,
    Json(body): Json<CreateGroupRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };
    let store = &state.store;
    let vp = &state.vp;

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
    let proposed = pure::rbac_from_create(body);
    let proposed_name = proposed.name.clone();
    let existing = match list_existing_entries(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        "create group: list failed",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let all_after = all_after_with_proposed(&existing, &proposed);
    let validated = match validate_rbac_entry(proposed, &all_after) {
        Ok(v) => v,
        Err(reason) => return shape_group_error_response(&GroupHandlerError::Validation(reason)),
    };

    let write_ctx = match OrgWriteContext::from_record(&record) {
        Ok(c) => c,
        Err(err) => return shape_active_state_error(&err, &raw_org_id, &proposed_name),
    };

    let result: Result<EtagedGroup, GroupHandlerError> = match write_ctx {
        OrgWriteContext::Draft => store
            .put_group(&org_id, validated, None)
            .await
            .map_err(|e| match e {
                crate::error::Error::Conflict(_) => GroupHandlerError::AlreadyExists,
                other => {
                    tracing::error!(org_id = %raw_org_id, error = %other, "create group failed");
                    GroupHandlerError::Internal
                }
            }),
        OrgWriteContext::Active(vp_ctx) => {
            let compiled = match compile_for_active(validated.entry(), &all_after, &vp_ctx) {
                Ok(c) => c,
                Err(reason) => {
                    return shape_group_error_response(&GroupHandlerError::Validation(reason));
                }
            };
            active::apply_create(active::CreateParams {
                model_events: state.model_events.as_ref(),
                vp: vp.as_ref(),
                vp_ctx: &vp_ctx,
                org_id: &org_id,
                raw_org_id: &raw_org_id,
                validated,
                compiled,
                actor: Actor::System,
                expected_revision: None,
            })
            .await
            .map(|(eg, _outcome)| eg)
        }
    };

    match result {
        Ok(eg) => (
            StatusCode::CREATED,
            etag_header(eg.etag()),
            Json(pure::group_resource_from(eg.entry(), eg.etag().as_str())),
        )
            .into_response(),
        Err(err) => shape_group_error_response(&err),
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
pub(crate) async fn list_handler(
    Path(raw_org_id): Path<String>,
    State(store): State<Arc<dyn OrgStore>>,
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
        .map(|eg| pure::group_resource_from(eg.entry(), eg.etag().as_str()))
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
pub(crate) async fn get_handler(
    Path((raw_org_id, name)): Path<(String, String)>,
    State(store): State<Arc<dyn OrgStore>>,
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
        Json(pure::group_resource_from(eg.entry(), eg.etag().as_str())),
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
/// Active-org behaviour (V3): the DDB put is paired with a VP delete-then-create
/// of the parent permit, then the same delete-then-create fanned out across
/// every transitive dependent in deterministic order. F3 (parent VP push fail
/// after DDB commit) triggers a compensating put_back. F3' (rollback also
/// fails) increments `forgeguard_cp_group_rollback_failed_total{stage="parent"}`.
/// F4 (mid-fanout fail) returns 503 with `{completed, failed, remaining}` and
/// no rollback.
///
/// Returns `200 OK` with updated `GroupResource` and an `ETag` header.
pub(crate) async fn update_handler<V: VpClient + 'static>(
    Path((raw_org_id, name)): Path<(String, String)>,
    State(state): State<AppState<V>>,
    headers: HeaderMap,
    Json(body): Json<UpdateGroupRequest>,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };
    let store = &state.store;
    let vp = &state.vp;

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
    let expected_etag: String = match &resolved {
        etag::ResolvedIfMatch::Strong(e) => e.to_string(),
        // `If-Match: *` on an existing row — pass the stored etag so that
        // `put_group` takes the conditional-update path rather than the
        // create-only path (which rejects `(Some(_), None)` as Conflict).
        etag::ResolvedIfMatch::WildcardMatched => existing.etag().to_string(),
        // Wildcard on absent row — fail closed (404 already returned above)
        etag::ResolvedIfMatch::WildcardOnDraft => {
            return shape_group_error_response(&GroupHandlerError::NotFound);
        }
        // INVARIANT: if_match_raw.is_none() is checked above and returns 412
        // before we reach resolve_if_match, so Absent is unreachable here.
        etag::ResolvedIfMatch::Absent => {
            unreachable!("if_match_raw.is_none() already guarded above");
        }
    };

    // Pure conversion — validates name match between body and path
    let proposed = match pure::rbac_from_update(&name, body) {
        Ok(e) => e,
        Err(reason) => return shape_group_error_response(&GroupHandlerError::Validation(reason)),
    };
    let proposed_name = proposed.name.clone();

    let existing_entries = match list_existing_entries(
        store.as_ref(),
        &org_id,
        &raw_org_id,
        "update group: list failed",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let all_after = all_after_with_proposed(&existing_entries, &proposed);

    let validated = match validate_rbac_entry(proposed, &all_after) {
        Ok(v) => v,
        Err(reason) => return shape_group_error_response(&GroupHandlerError::Validation(reason)),
    };

    let write_ctx = match OrgWriteContext::from_record(&record) {
        Ok(c) => c,
        Err(err) => return shape_active_state_error(&err, &raw_org_id, &proposed_name),
    };

    let result: Result<EtagedGroup, GroupHandlerError> = match write_ctx {
        OrgWriteContext::Draft => store
            .put_group(&org_id, validated, Some(&expected_etag))
            .await
            .map_err(|e| match e {
                crate::error::Error::PreconditionFailed { current_etag } => {
                    crate::metrics::record_precondition_failed(PreconditionReason::StaleEtag);
                    GroupHandlerError::PreconditionFailed {
                        current_etag: current_etag
                            .map(|e| e.to_string())
                            .unwrap_or_default(),
                        reason: PreconditionReason::StaleEtag,
                    }
                }
                crate::error::Error::NotFound(_) => GroupHandlerError::NotFound,
                other => {
                    tracing::error!(org_id = %raw_org_id, group = %proposed_name, error = %other, "update group failed");
                    GroupHandlerError::Internal
                }
            }),
        OrgWriteContext::Active(vp_ctx) => {
            let prior_for_rollback =
                match validate_rbac_entry(existing.entry().clone(), &existing_entries) {
                    Ok(v) => v,
                    Err(reason) => {
                        // A concurrent delete on an inherited group invalidated
                        // an entry that was already stored. This is a store-state
                        // inconsistency, not a client error — surface 500 and log.
                        tracing::error!(
                            org_id = %raw_org_id,
                            group = %proposed_name,
                            error = %reason,
                            "update group: prior entry failed re-validation; store is inconsistent",
                        );
                        return shape_group_error_response(&GroupHandlerError::Internal);
                    }
                };
            let compiled = match compile_for_active(validated.entry(), &all_after, &vp_ctx) {
                Ok(c) => c,
                Err(reason) => {
                    return shape_group_error_response(&GroupHandlerError::Validation(reason));
                }
            };
            active::apply_update(active::UpdateParams {
                model_events: state.model_events.as_ref(),
                vp: vp.as_ref(),
                vp_ctx: &vp_ctx,
                org_id: &org_id,
                raw_org_id: &raw_org_id,
                validated,
                compiled,
                prior_for_rollback,
                prior_all: existing_entries.clone(),
                actor: Actor::System,
                expected_revision: None,
            })
            .await
            .map(|(eg, _outcome)| eg)
        }
    };

    match result {
        Ok(eg) => (
            StatusCode::OK,
            etag_header(eg.etag()),
            Json(pure::group_resource_from(eg.entry(), eg.etag().as_str())),
        )
            .into_response(),
        Err(err) => shape_group_error_response(&err),
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
///
/// Active-org behaviour (V3): the DDB delete is paired with a VP `DeletePolicy`
/// for the parent permit; a VP `NotFound` is treated as idempotent success.
/// On other VP failures the prior DDB row is restored; F3' (rollback fail)
/// increments `forgeguard_cp_group_rollback_failed_total{stage="parent"}`.
pub(crate) async fn delete_handler<V: VpClient + 'static>(
    Path((raw_org_id, name)): Path<(String, String)>,
    State(state): State<AppState<V>>,
    headers: HeaderMap,
) -> Response {
    let Ok(org_id) = OrganizationId::new(&raw_org_id) else {
        return crate::handlers::not_found();
    };
    let store = &state.store;
    let vp = &state.vp;

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
        etag::ResolvedIfMatch::Strong(e) => e.to_string(),
        etag::ResolvedIfMatch::WildcardMatched => existing.etag().to_string(),
        // Wildcard on absent row — not reachable (we 404'd above), but handle defensively
        etag::ResolvedIfMatch::WildcardOnDraft => {
            return shape_group_error_response(&GroupHandlerError::NotFound);
        }
        // INVARIANT: if_match_raw.is_none() is checked above and returns 412
        // before we reach resolve_if_match, so Absent is unreachable here.
        etag::ResolvedIfMatch::Absent => {
            unreachable!("if_match_raw.is_none() already guarded above");
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

    let write_ctx = match OrgWriteContext::from_record(&record) {
        Ok(c) => c,
        Err(err) => return shape_active_state_error(&err, &raw_org_id, &name),
    };

    let result: Result<(), GroupHandlerError> = match write_ctx {
        OrgWriteContext::Draft => store
            .delete_group(&org_id, &name, &expected_etag)
            .await
            .map_err(|e| match e {
                crate::error::Error::PreconditionFailed { current_etag } => {
                    crate::metrics::record_precondition_failed(PreconditionReason::StaleEtag);
                    GroupHandlerError::PreconditionFailed {
                        current_etag: current_etag
                            .map(|e| e.to_string())
                            .unwrap_or_default(),
                        reason: PreconditionReason::StaleEtag,
                    }
                }
                crate::error::Error::NotFound(_) => GroupHandlerError::NotFound,
                other => {
                    tracing::error!(org_id = %raw_org_id, group = %name, error = %other, "delete group failed");
                    GroupHandlerError::Internal
                }
            }),
        OrgWriteContext::Active(vp_ctx) => {
            let existing_entries = match list_existing_entries(
                store.as_ref(),
                &org_id,
                &raw_org_id,
                "delete group: list failed",
            )
            .await
            {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let prior_for_rollback =
                match validate_rbac_entry(existing.entry().clone(), &existing_entries) {
                    Ok(v) => v,
                    Err(reason) => {
                        // A concurrent delete on an inherited group invalidated
                        // an entry that was already stored. This is a store-state
                        // inconsistency, not a client error — surface 500 and log.
                        tracing::error!(
                            org_id = %raw_org_id,
                            group = %name,
                            error = %reason,
                            "delete group: prior entry failed re-validation; store is inconsistent",
                        );
                        return shape_group_error_response(&GroupHandlerError::Internal);
                    }
                };
            active::apply_delete(active::DeleteParams {
                store: store.as_ref(),
                model_events: state.model_events.as_ref(),
                vp: vp.as_ref(),
                vp_ctx: &vp_ctx,
                org_id: &org_id,
                raw_org_id: &raw_org_id,
                name: name.clone(),
                prior_for_rollback,
                actor: Actor::System,
                expected_revision: None,
            })
            .await
            .map(|_outcome| ())
        }
    };

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => shape_group_error_response(&err),
    }
}
