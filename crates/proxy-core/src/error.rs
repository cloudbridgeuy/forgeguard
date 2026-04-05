//! Error types for the proxy-core crate.

/// Errors that can occur when constructing proxy-core types.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid request input construction.
    #[error("invalid request input: {0}")]
    InvalidRequest(String),

    /// Invalid HTTP status code for a reject outcome.
    #[error("invalid reject status: {0} (must be 400..=599)")]
    InvalidRejectStatus(u16),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;
