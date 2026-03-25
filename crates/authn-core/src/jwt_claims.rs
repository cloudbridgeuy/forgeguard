//! Raw JWT claims structure.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Raw JWT claims as deserialized from the token payload.
/// This is untrusted input — it becomes an Identity only after validation
/// by a resolver (e.g., CognitoJwtResolver in forgeguard_authn).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject — the principal identifier.
    pub sub: String,
    /// Issuer — the token issuer URL.
    pub iss: String,
    /// Audience — intended recipient of the token.
    pub aud: Option<String>,
    /// Expiration time (seconds since epoch).
    pub exp: u64,
    /// Issued-at time (seconds since epoch).
    pub iat: u64,
    /// Token use — "access" or "id".
    pub token_use: String,
    /// OAuth scopes (space-separated in the original token).
    pub scope: Option<String>,
    /// Cognito group membership.
    #[serde(rename = "cognito:groups")]
    pub cognito_groups: Option<Vec<String>>,
    /// Any additional claims not captured above.
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_claims() -> JwtClaims {
        JwtClaims {
            sub: "user-123".to_string(),
            iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc".to_string(),
            aud: Some("app-client-id".to_string()),
            exp: 1_700_000_000,
            iat: 1_699_996_400,
            token_use: "access".to_string(),
            scope: Some("openid profile".to_string()),
            cognito_groups: Some(vec!["admins".to_string(), "users".to_string()]),
            custom_claims: HashMap::new(),
        }
    }

    #[test]
    fn serde_round_trip() {
        let claims = sample_claims();
        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, claims);
    }

    #[test]
    fn deserialize_with_cognito_groups() {
        let json = r#"{
            "sub": "user-456",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xyz",
            "aud": "client-id",
            "exp": 1700000000,
            "iat": 1699996400,
            "token_use": "id",
            "cognito:groups": ["editors", "viewers"],
            "custom:tenant_id": "tenant-abc"
        }"#;

        let claims: JwtClaims = serde_json::from_str(json).unwrap();

        assert_eq!(claims.sub, "user-456");
        assert_eq!(claims.token_use, "id");
        assert_eq!(
            claims.cognito_groups,
            Some(vec!["editors".to_string(), "viewers".to_string()])
        );
        assert_eq!(claims.scope, None);
        assert_eq!(
            claims.custom_claims.get("custom:tenant_id"),
            Some(&serde_json::Value::String("tenant-abc".to_string()))
        );
    }

    #[test]
    fn deserialize_minimal_claims() {
        let json = r#"{
            "sub": "user-789",
            "iss": "https://issuer.example.com",
            "exp": 1700000000,
            "iat": 1699996400,
            "token_use": "access"
        }"#;

        let claims: JwtClaims = serde_json::from_str(json).unwrap();

        assert_eq!(claims.sub, "user-789");
        assert_eq!(claims.aud, None);
        assert_eq!(claims.scope, None);
        assert_eq!(claims.cognito_groups, None);
        assert!(claims.custom_claims.is_empty());
    }

    #[test]
    fn serialize_uses_cognito_colon_groups_key() {
        let claims = sample_claims();
        let value: serde_json::Value = serde_json::to_value(&claims).unwrap();

        assert!(value.get("cognito:groups").is_some());
        assert!(value.get("cognito_groups").is_none());
    }
}
