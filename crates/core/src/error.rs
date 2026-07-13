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
    /// A percentage value outside the valid 0..=100 range.
    #[error("invalid percentage: {value} (expected 0..=100)")]
    InvalidPercentage { value: u8 },
    /// A config version string that is not a valid YYYY-MM-DD date.
    #[error("invalid config version: {raw} (expected YYYY-MM-DD)")]
    InvalidConfigVersion { raw: String },
    /// A saga id string that is empty or otherwise malformed.
    #[error("invalid saga id: {raw}")]
    InvalidSagaId { raw: String },
    /// A structural violation of the organizational spine (Brief v1.4):
    /// the hierarchy edges must form a single-rooted tree.
    #[error("spine violation: {reason}: {fgrn}")]
    Spine { fgrn: String, reason: &'static str },
    /// A violation of the lateral grant graph (Brief v1.4): grant edges
    /// and principal-set membership. Spine/anchoring violations use
    /// [`Error::Spine`] instead.
    #[error("grant violation: {reason}: {fgrn}")]
    Grant { fgrn: String, reason: &'static str },
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

    #[test]
    fn spine_error_display() {
        let err = Error::Spine {
            fgrn: "fgrn:acme:orgunit:ou_x".to_string(),
            reason: "unknown parent",
        };
        assert_eq!(
            err.to_string(),
            "spine violation: unknown parent: fgrn:acme:orgunit:ou_x"
        );
    }

    #[test]
    fn grant_error_display() {
        let err = Error::Grant {
            fgrn: "fgrn:acme:resource:document/doc_123".to_string(),
            reason: "grant must carry at least one action",
        };
        assert_eq!(
            err.to_string(),
            "grant violation: grant must carry at least one action: fgrn:acme:resource:document/doc_123"
        );
    }
}
