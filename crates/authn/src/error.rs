//! Error types for forgeguard_authn.

/// The error type for all authentication I/O operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the pure authn_core layer.
    #[error(transparent)]
    Core(#[from] forgeguard_authn_core::Error),

    /// Failed to fetch JWKS from the issuer endpoint.
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),

    /// The requested key ID was not found in the JWKS.
    #[error("key not found in JWKS: {0}")]
    KeyNotFound(String),

    /// JWT signature verification failed.
    #[error("invalid JWT signature")]
    SignatureInvalid,

    /// Failed to decode or validate the JWT.
    #[error("token decode error: {0}")]
    TokenDecode(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_core_error() {
        let inner = forgeguard_authn_core::Error::TokenExpired;
        let err = Error::Core(inner);
        assert_eq!(err.to_string(), "token expired");
    }

    #[test]
    fn display_jwks_fetch() {
        let err = Error::JwksFetch("connection refused".to_string());
        assert_eq!(err.to_string(), "JWKS fetch failed: connection refused");
    }

    #[test]
    fn display_key_not_found() {
        let err = Error::KeyNotFound("kid-abc123".to_string());
        assert_eq!(err.to_string(), "key not found in JWKS: kid-abc123");
    }

    #[test]
    fn display_signature_invalid() {
        let err = Error::SignatureInvalid;
        assert_eq!(err.to_string(), "invalid JWT signature");
    }

    #[test]
    fn display_token_decode() {
        let err = Error::TokenDecode("invalid base64".to_string());
        assert_eq!(err.to_string(), "token decode error: invalid base64");
    }

    #[test]
    fn from_authn_core_error() {
        let inner = forgeguard_authn_core::Error::MissingClaim("sub".to_string());
        let err: Error = inner.into();
        assert_eq!(err.to_string(), "missing required claim: sub");
    }
}
