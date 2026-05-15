//! Outcomes surfaced by the `UserPoolClient` (V3) — Cognito-flavored errors.
//!
//! These are deliberately a standalone `pub enum` rather than variants on
//! `authn-core::Error`: they describe Cognito-surface results, not authn
//! pipeline failures. The V3 control-plane handler maps them to HTTP status
//! codes (`UsernameExists` → 409, `Transient` → 502, etc.).

/// Categorical Cognito outcomes that the user-pool client surfaces to callers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UserPoolError {
    /// A user with the same username already exists in the target pool.
    #[error("username already exists in pool")]
    UsernameExists,
    /// One of the attributes named in the request is already populated and
    /// cannot be re-added — usually `email` collision under another login.
    #[error("attribute already exists in pool")]
    AttributeAlreadyExists,
    /// Cognito returned a retryable or transient error; `message` preserves
    /// the original AWS surface text for logs without forcing a typed
    /// dependency on the SDK in this pure crate.
    #[error("transient cognito error: {message}")]
    Transient { message: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_username_exists() {
        assert_eq!(
            UserPoolError::UsernameExists.to_string(),
            "username already exists in pool"
        );
    }

    #[test]
    fn display_attribute_already_exists() {
        assert_eq!(
            UserPoolError::AttributeAlreadyExists.to_string(),
            "attribute already exists in pool"
        );
    }

    #[test]
    fn display_transient_includes_message() {
        let err = UserPoolError::Transient {
            message: "throttled".to_owned(),
        };
        assert_eq!(err.to_string(), "transient cognito error: throttled");
    }
}
