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
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
