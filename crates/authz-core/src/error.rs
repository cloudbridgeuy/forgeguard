//! Error types for forgeguard_authz_core.

/// The error type for all authorization operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Policy evaluation failed internally.
    #[error("policy evaluation failed: {0}")]
    EvaluationFailed(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_evaluation_failed() {
        let err = Error::EvaluationFailed("timeout contacting policy store".into());
        assert_eq!(
            err.to_string(),
            "policy evaluation failed: timeout contacting policy store"
        );
    }
}
