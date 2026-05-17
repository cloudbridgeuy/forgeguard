//! Outcomes surfaced by the `UserPoolClient` (V3) — Cognito-flavored errors.
//!
//! These are deliberately a standalone `pub enum` rather than variants on
//! `authn-core::Error`: they describe Cognito-surface results, not authn
//! pipeline failures. The V3 control-plane handler maps them to HTTP status
//! codes (`UsernameExists` → 409, `Transient` → 502, etc.).
//!
//! `Transient` and `Permanent` carry a boxed `dyn std::error::Error` source so
//! the originating SDK error is preserved on the causal chain — `tracing` and
//! `color-eyre` reports surface the underlying cause without re-stringifying.

use std::error::Error as StdError;

/// Categorical Cognito outcomes that the user-pool client surfaces to callers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UserPoolError {
    /// A user with the same username already exists in the target pool.
    #[error("username already exists in pool")]
    UsernameExists,
    /// One of the attributes named in the request is already populated and
    /// cannot be re-added — usually `email` collision under another login.
    /// `name` is the Cognito attribute name (e.g. `email`) so the handler can
    /// surface a typed 409 body without re-parsing the SDK error text.
    #[error("attribute '{name}' already exists in pool")]
    AttributeAlreadyExists { name: String },
    /// Compensation target user was not present in the pool — treated as
    /// idempotent success by C2 callers.
    #[error("user not found in pool")]
    UserNotFound,
    /// Cognito returned a retryable error (rate limit, throttle, 5xx). The
    /// `source` keeps the original SDK error for tracing/`color-eyre`.
    #[error("transient cognito error")]
    Transient {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// Cognito returned a non-retryable error (validation, permission, etc.).
    /// The `source` keeps the original SDK error for tracing/`color-eyre`.
    #[error("permanent cognito error")]
    Permanent {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("inner: {0}")]
    struct InnerErr(&'static str);

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
            UserPoolError::AttributeAlreadyExists {
                name: "email".to_owned()
            }
            .to_string(),
            "attribute 'email' already exists in pool"
        );
    }

    #[test]
    fn display_user_not_found() {
        assert_eq!(
            UserPoolError::UserNotFound.to_string(),
            "user not found in pool"
        );
    }

    #[test]
    fn display_transient_does_not_print_source() {
        let err = UserPoolError::Transient {
            source: Box::new(InnerErr("throttled")),
        };
        assert_eq!(err.to_string(), "transient cognito error");
    }

    #[test]
    fn transient_preserves_source_chain() {
        let err = UserPoolError::Transient {
            source: Box::new(InnerErr("throttled")),
        };
        let source = StdError::source(&err).expect("source must be present");
        assert_eq!(source.to_string(), "inner: throttled");
    }

    #[test]
    fn permanent_preserves_source_chain() {
        let err = UserPoolError::Permanent {
            source: Box::new(InnerErr("invalid parameter")),
        };
        let source = StdError::source(&err).expect("source must be present");
        assert_eq!(source.to_string(), "inner: invalid parameter");
    }
}
