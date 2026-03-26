//! Error types for forgeguard_authz.

/// The error type for all authorization I/O operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the authorization core domain.
    #[error(transparent)]
    Core(#[from] forgeguard_authz_core::Error),

    /// An error from the AWS Verified Permissions SDK.
    #[error("verified permissions error: {0}")]
    VerifiedPermissions(String),

    /// The configured policy store was not found.
    #[error("policy store not found: {0}")]
    PolicyStoreNotFound(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_verified_permissions_error() {
        let err = Error::VerifiedPermissions("connection timeout".into());
        assert_eq!(
            err.to_string(),
            "verified permissions error: connection timeout"
        );
    }

    #[test]
    fn display_policy_store_not_found() {
        let err = Error::PolicyStoreNotFound("ps-12345".into());
        assert_eq!(err.to_string(), "policy store not found: ps-12345");
    }

    #[test]
    fn display_core_error() {
        let core_err = forgeguard_authz_core::Error::EvaluationFailed("boom".into());
        let err = Error::Core(core_err);
        assert_eq!(err.to_string(), "policy evaluation failed: boom");
    }
}
