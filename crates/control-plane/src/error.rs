use std::collections::BTreeMap;

use crate::etag::Etag;

/// Control plane errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// Configuration error (invalid JSON, missing fields, invalid IDs).
    #[error("config error: {0}")]
    Config(String),
    /// A resource already exists (e.g. duplicate organization ID on create).
    #[error("conflict: {0}")]
    Conflict(String),
    /// The requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// The caller's `If-Match` value did not match the current stored etag.
    ///
    /// `current_etag` is the stored etag (`None` means the org is a
    /// Draft with no config attached yet — any `If-Match` fails closed).
    #[error("precondition failed (current etag: {current_etag:?})")]
    PreconditionFailed { current_etag: Option<Etag> },
    /// An etag value was empty or otherwise malformed.
    #[error("invalid etag: {raw}")]
    InvalidEtag { raw: String },
    /// Storage backend error (DynamoDB SDK, serialization, etc.).
    #[error("store error: {0}")]
    Store(String),
    /// A group write was rejected by field-level validation.
    ///
    /// Constructed by Group D handlers. The allow below is removed when Group D lands.
    #[allow(dead_code)]
    #[error("group validation failed: {reason}")]
    Validation {
        reason: forgeguard_authz_core::GroupValidationError,
    },
    /// A group cannot be deleted because it is still referenced by inheritors
    /// or has active memberships.
    ///
    /// Constructed by Group D handlers. The allow below is removed when Group D lands.
    #[allow(dead_code)]
    #[error(
        "delete conflict: blocking_inheritors={blocking_inheritors:?}, memberships_count={memberships_count:?}"
    )]
    DeleteConflict {
        blocking_inheritors: Vec<String>,
        memberships_count: BTreeMap<String, u32>,
    },
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
