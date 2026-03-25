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
}

impl Credential {
    /// Diagnostic label for this credential type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bearer(_) => "bearer",
            Self::ApiKey(_) => "api-key",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
}
