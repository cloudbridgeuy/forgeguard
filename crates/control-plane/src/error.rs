/// Control plane errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// Configuration error (invalid JSON, missing fields, invalid IDs).
    #[error("config error: {0}")]
    Config(String),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
