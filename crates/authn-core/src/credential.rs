//! Protocol-agnostic credential types.

use serde::{Deserialize, Serialize};

/// A raw, unvalidated credential. Protocol adapters produce these.
/// Identity resolvers consume them. Neither knows about the other's world.
///
/// No mention of `Authorization: Bearer` or `X-API-Key` headers — those are
/// HTTP concepts. This enum describes what the credential _is_, not where
/// it came from.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Credential {
    /// A bearer token (JWT or opaque).
    Bearer(String),
    /// An API key.
    ApiKey(String),
    /// Ed25519 signed request — BYOC proxy authentication.
    SignedRequest {
        /// From `X-ForgeGuard-Key-Id` header.
        key_id: String,
        /// From `X-ForgeGuard-Timestamp` header (Unix millis).
        timestamp: u64,
        /// Raw `X-ForgeGuard-Signature` header value (`v1:{base64}`).
        signature: String,
        /// From `X-ForgeGuard-Trace-Id` header.
        trace_id: String,
        /// All remaining `X-ForgeGuard-*` headers (excluding the 4 above).
        /// Includes `X-ForgeGuard-Org-Id` for org-scoped key lookup.
        identity_headers: Vec<(String, String)>,
    },
}

impl Credential {
    /// Diagnostic label for this credential type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bearer(_) => "bearer",
            Self::ApiKey(_) => "api-key",
            Self::SignedRequest { .. } => "signed-request",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Construct a `SignedRequest` credential for testing.
    fn make_signed_request(identity_headers: Vec<(String, String)>) -> Credential {
        Credential::SignedRequest {
            key_id: "key-001".into(),
            timestamp: 1_700_000_000_000,
            signature: "v1:AAAA".into(),
            trace_id: "trace-abc".into(),
            identity_headers,
        }
    }

    #[test]
    fn type_name_bearer() {
        let cred = Credential::Bearer("tok_abc".into());
        assert_eq!(cred.type_name(), "bearer");
    }

    #[test]
    fn type_name_api_key() {
        let cred = Credential::ApiKey("key_xyz".into());
        assert_eq!(cred.type_name(), "api-key");
    }

    #[test]
    fn serde_round_trip_bearer() {
        let cred = Credential::Bearer("tok_abc".into());
        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, deserialized);
    }

    #[test]
    fn serde_round_trip_api_key() {
        let cred = Credential::ApiKey("key_xyz".into());
        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, deserialized);
    }

    #[test]
    fn type_name_signed_request() {
        let cred = make_signed_request(vec![("X-ForgeGuard-Org-Id".into(), "org-123".into())]);
        assert_eq!(cred.type_name(), "signed-request");
    }

    #[test]
    fn serde_round_trip_signed_request() {
        let cred = make_signed_request(vec![
            ("X-ForgeGuard-Org-Id".into(), "org-123".into()),
            ("X-ForgeGuard-Custom".into(), "value".into()),
        ]);
        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, deserialized);
    }
}
