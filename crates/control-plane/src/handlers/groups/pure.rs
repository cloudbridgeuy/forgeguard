//! Pure functional core for group handlers.
//!
//! Every function here is deterministic, has no I/O, and can be unit-tested
//! without any async runtime or cloud SDK. The imperative shell (Group D
//! handlers) calls into these functions and translates their outputs into HTTP
//! responses or storage side effects.
//!
use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use forgeguard_authz_core::{GroupValidationError, RbacEntry};
use serde::Serialize;

use crate::error::{Error, Result};

use super::{CreateGroupRequest, UpdateGroupRequest};

// ---------------------------------------------------------------------------
// Response DTOs (defined here so pure.rs owns the wire shape)
// ---------------------------------------------------------------------------

/// Wire representation of a group resource returned to callers.
///
/// Borrows from the stored `RbacEntry` and a computed etag string so that
/// handlers can avoid per-request allocations.
///
/// # Note for Group C / D
/// `group_resource_from` currently takes `(entry: &RbacEntry, etag: &str)`
/// directly. Once Group C introduces `EtagedGroup`, Group D should adjust
/// its call site to destructure the tuple (or use `EtagedGroup` accessors).
#[derive(Debug, Serialize)]
pub(crate) struct GroupResource<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub inherits: &'a [String],
    pub allow: &'a [String],
    pub tenant_scoped: bool,
    pub etag: &'a str,
}

/// Body for a `412` revision-mismatch response (#113 V4, D5). Mirrors
/// `handlers::mod`'s org `update_handler` `RevisionMismatch` body shape.
#[derive(Debug, Serialize)]
pub(crate) struct RevisionMismatchBody {
    /// Always `"revision_mismatch"`.
    pub error: &'static str,
    pub current_revision: u64,
    pub expected_revision: Option<u64>,
}

/// Body for a `409 Delete Conflict` response.
#[derive(Debug, Serialize)]
pub(crate) struct DeleteConflictBody<'a> {
    /// Always `"delete_conflict"`.
    pub error: &'static str,
    pub blocking_inheritors: &'a [String],
    pub memberships_count: &'a BTreeMap<String, u32>,
}

/// Body for a `422 Validation Failed` response.
#[derive(Debug, Serialize)]
pub(crate) struct GroupValidationErrorBody<'a> {
    /// Always `"validation_failed"`.
    pub error: &'static str,
    /// Snake-case ADT variant label (e.g. `"bad_name_regex"`).
    pub reason: &'static str,
    /// The field that caused the failure.
    pub field: &'static str,
    /// Human-readable message.
    pub message: &'a str,
}

// ---------------------------------------------------------------------------
// Mechanical conversions (no validation, just field mapping)
// ---------------------------------------------------------------------------

/// Convert a `CreateGroupRequest` DTO into an `RbacEntry`.
///
/// This is a **mechanical conversion** — no field-level validation is performed
/// here. The handler (Group D) MUST call `validate_rbac_entry` on the result
/// before writing to the store.
pub(crate) fn rbac_from_create(req: CreateGroupRequest) -> RbacEntry {
    RbacEntry {
        name: req.name,
        description: req.description,
        inherits: req.inherits,
        allow: req.allow,
        tenant_scoped: req.tenant_scoped,
    }
}

/// Convert an `UpdateGroupRequest` DTO + path `name` into an `RbacEntry`.
///
/// Returns `Err(GroupValidationError::NameMismatch)` when the body contains a
/// `name` field that differs from `path_name`. No other validation is done here.
pub(crate) fn rbac_from_update(
    path_name: &str,
    req: UpdateGroupRequest,
) -> std::result::Result<RbacEntry, GroupValidationError> {
    if let Some(body_name) = req.name.as_deref() {
        if body_name != path_name {
            return Err(GroupValidationError::NameMismatch {
                path_name: path_name.to_owned(),
                body_name: body_name.to_owned(),
            });
        }
    }
    Ok(RbacEntry {
        name: path_name.to_owned(),
        description: req.description,
        inherits: req.inherits,
        allow: req.allow,
        tenant_scoped: req.tenant_scoped,
    })
}

/// Build a `GroupResource` response DTO from a stored entry and its precomputed
/// etag.
///
/// # Note for Group C / D
/// This signature uses `(entry: &RbacEntry, etag: &str)` as a temporary stand-in
/// for the `EtagedGroup` tuple that Group C will introduce. Group D should call
/// this function after destructuring the `(RbacEntry, String)` pair stored by
/// Group C's codec.
pub(crate) fn group_resource_from<'a>(entry: &'a RbacEntry, etag: &'a str) -> GroupResource<'a> {
    GroupResource {
        name: &entry.name,
        description: entry.description.as_deref(),
        inherits: &entry.inherits,
        allow: &entry.allow,
        tenant_scoped: entry.tenant_scoped,
        etag,
    }
}

/// Compute a deterministic ETag for an `RbacEntry`.
///
/// Serialises the entry to JSON, then takes the xxHash-64 of the UTF-8 bytes.
/// The result is formatted as `"<16-hex-digit>"` (18 characters total, with
/// surrounding double-quotes per RFC 7232 strong-etag syntax).
///
/// **Order sensitivity:** actions and inherits are serialised as-is; callers
/// that care about canonical ordering must normalise the slices beforehand.
/// The cycle resolver does not reorder, so two entries that differ only in
/// `allow` element order will produce different etags.
pub(crate) fn compute_group_etag(entry: &RbacEntry) -> Result<String> {
    let json =
        serde_json::to_string(entry).map_err(|e| Error::Config(format!("etag serial: {e}")))?;
    let hash = xxhash_rust::xxh64::xxh64(json.as_bytes(), 0);
    Ok(format!("\"{hash:016x}\""))
}

// ---------------------------------------------------------------------------
// Handler error ADT
// ---------------------------------------------------------------------------

/// All failure modes that a group handler can encounter.
///
/// `shape_group_error_response` is the single place where these are turned
/// into HTTP responses, keeping the handlers free of status-code logic.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GroupHandlerError {
    /// Field-level validation failed on the request body.
    #[error("validation error: {0}")]
    Validation(GroupValidationError),
    /// The requested group does not exist.
    #[error("group not found")]
    NotFound,
    /// A `POST` attempted to create a group whose name already exists.
    #[error("group already exists")]
    AlreadyExists,
    /// The caller's `X-Fg-If-Revision` precondition did not match the log's
    /// current revision at append time (#113 V4, D5). Replaces the retired
    /// `If-Match`/etag `PreconditionFailed` variant.
    #[error("revision mismatch (current: {current_revision}, expected: {expected_revision:?})")]
    RevisionMismatch {
        current_revision: u64,
        expected_revision: Option<u64>,
    },
    /// The group cannot be deleted because other groups inherit from it, or
    /// users are still members of it.
    #[error("delete conflict")]
    DeleteConflict {
        blocking_inheritors: Vec<String>,
        memberships_count: BTreeMap<String, u32>,
    },
    /// Generic internal/store error that doesn't fit a more specific bucket.
    /// The actual error is logged via `tracing::error!` at the call site;
    /// this variant carries no payload and shapes as a bare 500.
    #[error("internal error")]
    Internal,
}

/// Map the `reason` field for a `GroupValidationError` to its snake_case label
/// and the field name that caused the failure.
fn validation_label(err: &GroupValidationError) -> (&'static str, &'static str) {
    match err {
        GroupValidationError::BadNameRegex { .. } => ("bad_name_regex", "name"),
        GroupValidationError::BadActionFormat { .. } => ("bad_action_format", "allow"),
        GroupValidationError::BadActionId { .. } => ("bad_action_id", "allow"),
        GroupValidationError::EmptyAllow => ("empty_allow", "allow"),
        GroupValidationError::InheritCycle(_) => ("inherit_cycle", "inherits"),
        GroupValidationError::UnknownInherit(_) => ("unknown_inherit", "inherits"),
        GroupValidationError::DescriptionTooLong => ("description_too_long", "description"),
        GroupValidationError::NameMismatch { .. } => ("name_mismatch", "name"),
    }
}

/// Convert a `GroupHandlerError` into an HTTP `Response`.
///
/// This is the single source of truth for group-handler status codes and body
/// shapes. The mapping is:
///
/// | Variant                | Status | Body shape                         |
/// |------------------------|--------|------------------------------------|
/// | `Validation`           | 422    | `GroupValidationErrorBody`         |
/// | `NotFound`             | 404    | `{"error": "not found"}`           |
/// | `AlreadyExists`        | 409    | `{"error": "already_exists"}`      |
/// | `RevisionMismatch`     | 412    | `RevisionMismatchBody`              |
/// | `DeleteConflict`       | 409    | `DeleteConflictBody`               |
/// | `Internal`             | 500    | `{"error": "internal"}`            |
pub(crate) fn shape_group_error_response(err: &GroupHandlerError) -> Response {
    match err {
        GroupHandlerError::Validation(v_err) => {
            let (reason, field) = validation_label(v_err);
            let message = v_err.to_string();
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(GroupValidationErrorBody {
                    error: "validation_failed",
                    reason,
                    field,
                    message: &message,
                }),
            )
                .into_response()
        }
        GroupHandlerError::NotFound => crate::handlers::not_found(),
        GroupHandlerError::AlreadyExists => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "already_exists"})),
        )
            .into_response(),
        GroupHandlerError::RevisionMismatch {
            current_revision,
            expected_revision,
        } => {
            let mut headers = axum::http::HeaderMap::new();
            if let Ok(val) = current_revision.to_string().parse() {
                headers.insert(crate::handlers::REVISION_HEADER, val);
            }
            (
                StatusCode::PRECONDITION_FAILED,
                headers,
                Json(RevisionMismatchBody {
                    error: "revision_mismatch",
                    current_revision: *current_revision,
                    expected_revision: *expected_revision,
                }),
            )
                .into_response()
        }
        GroupHandlerError::DeleteConflict {
            blocking_inheritors,
            memberships_count,
        } => (
            StatusCode::CONFLICT,
            Json(DeleteConflictBody {
                error: "delete_conflict",
                blocking_inheritors,
                memberships_count,
            }),
        )
            .into_response(),
        GroupHandlerError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal"})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::to_bytes;

    use super::*;
    use crate::handlers::groups::{CreateGroupRequest, UpdateGroupRequest};

    fn make_create_req(name: &str, allow: Vec<&str>, tenant_scoped: bool) -> CreateGroupRequest {
        CreateGroupRequest {
            name: name.to_owned(),
            description: None,
            inherits: vec![],
            allow: allow.into_iter().map(str::to_owned).collect(),
            tenant_scoped,
        }
    }

    fn make_update_req(
        name: Option<&str>,
        allow: Vec<&str>,
        tenant_scoped: bool,
    ) -> UpdateGroupRequest {
        UpdateGroupRequest {
            name: name.map(str::to_owned),
            description: None,
            inherits: vec![],
            allow: allow.into_iter().map(str::to_owned).collect(),
            tenant_scoped,
        }
    }

    // -----------------------------------------------------------------------
    // rbac_from_create
    // -----------------------------------------------------------------------

    #[test]
    fn rbac_from_create_happy_path() {
        let req = make_create_req("admin", vec!["cp:x:read"], true);
        let entry = rbac_from_create(req);
        assert_eq!(entry.name, "admin");
        assert_eq!(entry.allow, ["cp:x:read"]);
        assert!(entry.tenant_scoped);
        assert!(entry.description.is_none());
        assert!(entry.inherits.is_empty());
    }

    #[test]
    fn rbac_from_create_tenant_scoped_defaults_true_when_omitted() {
        // Simulate the serde default: construct via JSON deserialization.
        let json = r#"{"name":"member","allow":["cp:x:read"]}"#;
        let req: CreateGroupRequest = serde_json::from_str(json).unwrap();
        assert!(req.tenant_scoped, "tenant_scoped should default to true");
        let entry = rbac_from_create(req);
        assert!(entry.tenant_scoped);
    }

    // -----------------------------------------------------------------------
    // rbac_from_update
    // -----------------------------------------------------------------------

    #[test]
    fn rbac_from_update_body_name_equals_path_name_succeeds() {
        let req = make_update_req(Some("admin"), vec!["cp:x:read"], true);
        let result = rbac_from_update("admin", req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "admin");
    }

    #[test]
    fn rbac_from_update_body_name_missing_uses_path_name() {
        let req = make_update_req(None, vec!["cp:x:read"], true);
        let result = rbac_from_update("member", req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "member");
    }

    #[test]
    fn rbac_from_update_body_name_differs_returns_name_mismatch() {
        let req = make_update_req(Some("different"), vec!["cp:x:read"], true);
        let err = rbac_from_update("admin", req).unwrap_err();
        assert!(
            matches!(
                err,
                GroupValidationError::NameMismatch {
                    ref path_name,
                    ref body_name,
                } if path_name == "admin" && body_name == "different"
            ),
            "unexpected error: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // compute_group_etag
    // -----------------------------------------------------------------------

    fn make_entry(name: &str, allow: Vec<&str>) -> RbacEntry {
        RbacEntry {
            name: name.to_owned(),
            description: None,
            inherits: vec![],
            allow: allow.into_iter().map(str::to_owned).collect(),
            tenant_scoped: true,
        }
    }

    #[test]
    fn compute_group_etag_returns_18_char_quoted_hex() {
        let entry = make_entry("admin", vec!["cp:x:read"]);
        let etag = compute_group_etag(&entry).unwrap();
        // Exactly 18 characters: '"' + 16 hex digits + '"'
        assert_eq!(etag.len(), 18, "etag={etag:?}");
        assert!(etag.starts_with('"'), "expected leading quote: {etag:?}");
        assert!(etag.ends_with('"'), "expected trailing quote: {etag:?}");
        // Inner 16 chars are all hex.
        let inner = &etag[1..17];
        assert!(
            inner.chars().all(|c| c.is_ascii_hexdigit()),
            "non-hex chars: {inner:?}"
        );
    }

    #[test]
    fn compute_group_etag_same_input_same_output() {
        let entry = make_entry("admin", vec!["cp:x:read"]);
        let a = compute_group_etag(&entry).unwrap();
        let b = compute_group_etag(&entry).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn compute_group_etag_different_allow_order_yields_different_etag() {
        let e1 = make_entry("admin", vec!["cp:x:read", "cp:y:write"]);
        let e2 = make_entry("admin", vec!["cp:y:write", "cp:x:read"]);
        let t1 = compute_group_etag(&e1).unwrap();
        let t2 = compute_group_etag(&e2).unwrap();
        assert_ne!(
            t1, t2,
            "different allow order should produce different etags"
        );
    }

    // -----------------------------------------------------------------------
    // shape_group_error_response — status code mapping
    // -----------------------------------------------------------------------

    async fn body_json(resp: Response) -> serde_json::Value {
        let body = resp.into_body();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn shape_error_validation_yields_422() {
        let err = GroupHandlerError::Validation(GroupValidationError::EmptyAllow);
        let resp = shape_group_error_response(&err);
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "validation_failed");
        assert_eq!(json["reason"], "empty_allow");
        assert_eq!(json["field"], "allow");
    }

    #[tokio::test]
    async fn shape_error_validation_bad_name_regex_field_is_name() {
        let err = GroupHandlerError::Validation(GroupValidationError::BadNameRegex {
            name: "Bad".to_owned(),
        });
        let resp = shape_group_error_response(&err);
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(resp).await;
        assert_eq!(json["field"], "name");
        assert_eq!(json["reason"], "bad_name_regex");
    }

    #[tokio::test]
    async fn shape_error_validation_inherit_cycle_field_is_inherits() {
        let err = GroupHandlerError::Validation(GroupValidationError::InheritCycle(
            "cycle: a -> b".to_owned(),
        ));
        let resp = shape_group_error_response(&err);
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(resp).await;
        assert_eq!(json["field"], "inherits");
        assert_eq!(json["reason"], "inherit_cycle");
    }

    #[tokio::test]
    async fn shape_error_not_found_yields_404() {
        let resp = shape_group_error_response(&GroupHandlerError::NotFound);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "not found");
    }

    #[tokio::test]
    async fn shape_error_already_exists_yields_409() {
        let resp = shape_group_error_response(&GroupHandlerError::AlreadyExists);
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "already_exists");
    }

    #[tokio::test]
    async fn shape_error_revision_mismatch_yields_412() {
        let err = GroupHandlerError::RevisionMismatch {
            current_revision: 7,
            expected_revision: Some(3),
        };
        let resp = shape_group_error_response(&err);
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            resp.headers().get("x-fg-revision").unwrap(),
            "7",
            "x-fg-revision header must carry the current revision"
        );
        let json = body_json(resp).await;
        assert_eq!(json["error"], "revision_mismatch");
        assert_eq!(json["current_revision"], 7);
        assert_eq!(json["expected_revision"], 3);
    }

    #[tokio::test]
    async fn shape_error_revision_mismatch_absent_expected_is_null() {
        let err = GroupHandlerError::RevisionMismatch {
            current_revision: 5,
            expected_revision: None,
        };
        let resp = shape_group_error_response(&err);
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let json = body_json(resp).await;
        assert!(json["expected_revision"].is_null());
    }

    #[tokio::test]
    async fn shape_error_delete_conflict_yields_409() {
        let blocking = vec!["admin".to_owned()];
        let mut counts = BTreeMap::new();
        counts.insert("org-acme".to_owned(), 3u32);
        let err = GroupHandlerError::DeleteConflict {
            blocking_inheritors: blocking,
            memberships_count: counts,
        };
        let resp = shape_group_error_response(&err);
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "delete_conflict");
        assert!(json["blocking_inheritors"].is_array());
        assert!(json["memberships_count"].is_object());
    }

    #[tokio::test]
    async fn shape_error_internal_yields_500() {
        let resp = shape_group_error_response(&GroupHandlerError::Internal);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "internal");
    }

    // -----------------------------------------------------------------------
    // validation field/reason mapping coverage
    // -----------------------------------------------------------------------

    #[test]
    fn validation_label_bad_action_format_maps_to_allow() {
        let (reason, field) = validation_label(&GroupValidationError::BadActionFormat {
            action: "x".to_owned(),
        });
        assert_eq!(reason, "bad_action_format");
        assert_eq!(field, "allow");
    }

    #[test]
    fn validation_label_unknown_inherit_maps_to_inherits() {
        let (reason, field) =
            validation_label(&GroupValidationError::UnknownInherit("x".to_owned()));
        assert_eq!(reason, "unknown_inherit");
        assert_eq!(field, "inherits");
    }

    #[test]
    fn validation_label_description_too_long_maps_to_description() {
        let (reason, field) = validation_label(&GroupValidationError::DescriptionTooLong);
        assert_eq!(reason, "description_too_long");
        assert_eq!(field, "description");
    }

    #[test]
    fn validation_label_name_mismatch_maps_to_name() {
        let (reason, field) = validation_label(&GroupValidationError::NameMismatch {
            path_name: "a".to_owned(),
            body_name: "b".to_owned(),
        });
        assert_eq!(reason, "name_mismatch");
        assert_eq!(field, "name");
    }
}
