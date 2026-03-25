//! Error types for forgeguard_core.

/// The error type for all forgeguard_core operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A parse/validation error with structured context.
    #[error("invalid {field}: '{value}' — {reason}")]
    Parse {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    /// A configuration error.
    #[error("configuration error: {0}")]
    Config(String),
    /// An unknown feature flag type.
    #[error("unknown feature flag type: {0}")]
    InvalidFlagType(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_display_includes_all_fields() {
        let err = Error::Parse {
            field: "segment",
            value: "BAD".to_string(),
            reason: "must be lowercase",
        };
        let msg = err.to_string();
        assert!(msg.contains("segment"), "should contain field name");
        assert!(msg.contains("BAD"), "should contain value");
        assert!(msg.contains("must be lowercase"), "should contain reason");
    }

    #[test]
    fn config_error_display() {
        let err = Error::Config("missing field".to_string());
        assert_eq!(err.to_string(), "configuration error: missing field");
    }

    #[test]
    fn invalid_flag_type_display() {
        let err = Error::InvalidFlagType("complex".to_string());
        assert_eq!(err.to_string(), "unknown feature flag type: complex");
    }
}
