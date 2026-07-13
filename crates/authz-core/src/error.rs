//! Error types for forgeguard_authz_core.

/// The error type for all authorization operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Policy evaluation failed internally.
    #[error("policy evaluation failed: {0}")]
    EvaluationFailed(String),

    /// A read requested a revision the store has never produced.
    #[error("unknown revision {requested} (latest is {latest})")]
    UnknownRevision {
        /// The revision that was requested.
        requested: u64,
        /// The store's latest known revision.
        latest: u64,
    },

    /// A slice query referenced a principal or resource the store does not hold.
    #[error("unknown entity: {0}")]
    UnknownEntity(String),

    /// An underlying core-model operation failed.
    #[error(transparent)]
    Core(#[from] forgeguard_core::Error),
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

    #[test]
    fn display_unknown_revision() {
        let err = Error::UnknownRevision {
            requested: 9,
            latest: 3,
        };
        assert_eq!(err.to_string(), "unknown revision 9 (latest is 3)");
    }

    #[test]
    fn display_unknown_entity() {
        let err = Error::UnknownEntity("fgrn:acme:principal:maria".into());
        assert_eq!(err.to_string(), "unknown entity: fgrn:acme:principal:maria");
    }
}
