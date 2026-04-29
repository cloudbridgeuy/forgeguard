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
    /// `current_etag` is the stored etag (empty string means the org is a
    /// Draft with no config attached yet — any `If-Match` fails closed).
    #[error("precondition failed (current etag: {current_etag:?})")]
    PreconditionFailed { current_etag: String },
    /// An etag value was empty or otherwise malformed.
    #[error("invalid etag: {raw}")]
    #[allow(dead_code)] // TODO(stream-7): remove once Etag wiring consumes this variant.
    InvalidEtag { raw: String },
    /// Storage backend error (DynamoDB SDK, serialization, etc.).
    #[error("store error: {0}")]
    Store(String),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
