//! Error types for forgeguard_authn_core.

/// The error type for all authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No resolver configured for the given credential type.
    #[error("no resolver available for credential type: {credential_type}")]
    NoResolver { credential_type: String },
    /// JWT token has expired.
    #[error("token expired")]
    TokenExpired,
    /// Invalid issuer in the token.
    #[error("invalid issuer: expected '{expected}', got '{actual}'")]
    InvalidIssuer { expected: String, actual: String },
    /// Invalid audience claim.
    #[error("invalid audience")]
    InvalidAudience,
    /// Required claim is missing from the token.
    #[error("missing required claim: {0}")]
    MissingClaim(String),
    /// Token structure or format is malformed.
    #[error("malformed token: {0}")]
    MalformedToken(String),
    /// Credential is invalid or unrecognized.
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// Request timestamp is outside the allowed drift window.
    #[error("timestamp outside allowed drift window: {0}ms")]
    TimestampDrift(u64),
    /// The signing key is invalid or malformed.
    #[error("invalid signing key: {0}")]
    InvalidSigningKey(String),
    /// The verifying key is invalid or malformed.
    #[error("invalid verifying key: {0}")]
    InvalidVerifyingKey(String),
    /// The key ID is empty.
    #[error("invalid key ID: must be non-empty")]
    InvalidKeyId,
    /// The required X-ForgeGuard-Org-Id header is missing from the signed request.
    #[error("missing X-ForgeGuard-Org-Id header in signed request")]
    MissingOrgId,
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_no_resolver() {
        let err = Error::NoResolver {
            credential_type: "api_key".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "no resolver available for credential type: api_key"
        );
    }

    #[test]
    fn display_token_expired() {
        let err = Error::TokenExpired;
        assert_eq!(err.to_string(), "token expired");
    }

    #[test]
    fn display_invalid_issuer() {
        let err = Error::InvalidIssuer {
            expected: "https://auth.example.com".to_owned(),
            actual: "https://evil.example.com".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "invalid issuer: expected 'https://auth.example.com', got 'https://evil.example.com'"
        );
    }

    #[test]
    fn display_invalid_audience() {
        let err = Error::InvalidAudience;
        assert_eq!(err.to_string(), "invalid audience");
    }

    #[test]
    fn display_missing_claim() {
        let err = Error::MissingClaim("sub".to_owned());
        assert_eq!(err.to_string(), "missing required claim: sub");
    }

    #[test]
    fn display_malformed_token() {
        let err = Error::MalformedToken("invalid base64 in header".to_owned());
        assert_eq!(err.to_string(), "malformed token: invalid base64 in header");
    }

    #[test]
    fn display_invalid_credential() {
        let err = Error::InvalidCredential("unrecognized format".to_owned());
        assert_eq!(err.to_string(), "invalid credential: unrecognized format");
    }
}
