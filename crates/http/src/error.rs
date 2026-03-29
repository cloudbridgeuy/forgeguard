//! Error types for forgeguard_http.

use std::fmt;

/// The error type for all forgeguard_http operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A configuration file or parsing error.
    #[error("config error: {0}")]
    Config(String),

    /// Validation produced one or more errors.
    #[error("validation failed: {count} error(s)", count = .0.len())]
    Validation(Vec<ValidationError>),

    /// No route matched the request.
    #[error("no route matched the request")]
    RouteNotFound,

    /// Invalid query parameter in a debug/admin endpoint.
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// An error from the core crate.
    #[error(transparent)]
    Core(#[from] forgeguard_core::Error),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A structured validation error with a path pointing to the offending config location.
#[derive(Debug, Clone)]
pub struct ValidationError {
    kind: ValidationErrorKind,
    message: String,
    path: String,
}

impl ValidationError {
    /// Create a new validation error.
    pub fn new(
        kind: ValidationErrorKind,
        message: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            path: path.into(),
        }
    }

    /// The kind of validation error.
    pub fn kind(&self) -> &ValidationErrorKind {
        &self.kind
    }

    /// A human-readable message describing the error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The config path where the error occurred (e.g., "routes[2].action").
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.kind, self.path, self.message)
    }
}

/// Categories of validation errors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ValidationErrorKind {
    /// Duplicate route (same method + path pattern).
    DuplicateRoute,
    /// A feature_gate references an undefined flag.
    UndefinedFeatureGate,
    /// A policy reference is invalid.
    InvalidPolicyReference,
    /// A group member-group reference is invalid.
    InvalidGroupReference,
    /// Circular group nesting detected.
    CircularGroupNesting,
    /// Invalid CORS configuration.
    InvalidCorsConfig,
}

impl fmt::Display for ValidationErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRoute => write!(f, "duplicate-route"),
            Self::UndefinedFeatureGate => write!(f, "undefined-feature-gate"),
            Self::InvalidPolicyReference => write!(f, "invalid-policy-reference"),
            Self::InvalidGroupReference => write!(f, "invalid-group-reference"),
            Self::CircularGroupNesting => write!(f, "circular-group-nesting"),
            Self::InvalidCorsConfig => write!(f, "invalid-cors-config"),
        }
    }
}

/// A non-fatal validation warning.
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    message: String,
    path: String,
}

impl ValidationWarning {
    /// Create a new validation warning.
    pub fn new(message: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            path: path.into(),
        }
    }

    /// A human-readable message describing the warning.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The config path where the warning occurred.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[warning] {}: {}", self.path, self.message)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_display() {
        let err = ValidationError::new(
            ValidationErrorKind::DuplicateRoute,
            "GET /users/{id} already defined",
            "routes[3]",
        );
        let s = err.to_string();
        assert!(s.contains("duplicate-route"));
        assert!(s.contains("routes[3]"));
        assert!(s.contains("GET /users/{id} already defined"));
    }

    #[test]
    fn validation_error_getters() {
        let err = ValidationError::new(
            ValidationErrorKind::UndefinedFeatureGate,
            "flag 'beta' not defined",
            "routes[0].feature_gate",
        );
        assert_eq!(*err.kind(), ValidationErrorKind::UndefinedFeatureGate);
        assert_eq!(err.message(), "flag 'beta' not defined");
        assert_eq!(err.path(), "routes[0].feature_gate");
    }

    #[test]
    fn validation_warning_display() {
        let warn = ValidationWarning::new("public route overlaps auth route", "public_routes[0]");
        let s = warn.to_string();
        assert!(s.contains("warning"));
        assert!(s.contains("public_routes[0]"));
    }

    #[test]
    fn error_config_display() {
        let err = Error::Config("missing upstream_url".to_string());
        assert!(err.to_string().contains("missing upstream_url"));
    }

    #[test]
    fn error_route_not_found_display() {
        let err = Error::RouteNotFound;
        assert!(err.to_string().contains("no route matched"));
    }

    #[test]
    fn error_validation_display() {
        let err = Error::Validation(vec![
            ValidationError::new(ValidationErrorKind::DuplicateRoute, "dup", "routes[0]"),
            ValidationError::new(ValidationErrorKind::DuplicateRoute, "dup", "routes[1]"),
        ]);
        assert!(err.to_string().contains("2 error(s)"));
    }

    #[test]
    fn error_from_core() {
        let core_err = forgeguard_core::Error::Config("bad".to_string());
        let err: Error = core_err.into();
        assert!(err.to_string().contains("bad"));
    }
}
