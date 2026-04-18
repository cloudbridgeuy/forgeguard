//! Pure claim-to-Identity mapping.

use chrono::DateTime;
use forgeguard_authn_core::{Identity, IdentityParams, JwtClaims};
use forgeguard_core::{PrincipalKind, UserId};

use crate::config::JwtResolverConfig;
use crate::error::Result;

/// Map validated JWT claims to a trusted `Identity`.
///
/// This is a pure function — no I/O, no crypto. It extracts the user_id from
/// the configured claim and constructs an identity-only `Identity` value.
/// Tenant and group context are not extracted from the JWT — they are resolved
/// from DynamoDB membership items per request.
pub(crate) fn map_claims(claims: &JwtClaims, config: &JwtResolverConfig) -> Result<Identity> {
    let user_id = extract_user_id(claims, config)?;
    let expiry = Some(
        DateTime::from_timestamp(claims.exp as i64, 0).ok_or_else(|| {
            forgeguard_authn_core::Error::MalformedToken(format!(
                "invalid exp timestamp: {}",
                claims.exp
            ))
        })?,
    );
    let extra = build_extra(claims);

    Ok(Identity::new(IdentityParams {
        user_id,
        tenant_id: None,
        groups: vec![],
        expiry,
        resolver: "cognito_jwt",
        extra,
        principal_kind: PrincipalKind::User,
    }))
}

/// Extract the user ID from the configured claim.
fn extract_user_id(claims: &JwtClaims, config: &JwtResolverConfig) -> Result<UserId> {
    let claim_name = config.user_id_claim();
    let raw = if claim_name == "sub" {
        claims.sub.clone()
    } else {
        claims
            .custom_claims
            .get(claim_name)
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| forgeguard_authn_core::Error::MissingClaim(claim_name.to_string()))?
    };

    UserId::new(raw).map_err(|e| {
        forgeguard_authn_core::Error::MalformedToken(format!("invalid user_id: {e}")).into()
    })
}

/// Build the `extra` field from custom_claims, preserving all non-standard claims.
fn build_extra(claims: &JwtClaims) -> Option<serde_json::Value> {
    if claims.custom_claims.is_empty() {
        return None;
    }
    let value = serde_json::to_value(&claims.custom_claims).ok()?;
    Some(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn base_config() -> JwtResolverConfig {
        let url = url::Url::parse(
            "https://cognito-idp.us-east-1.amazonaws.com/pool/.well-known/jwks.json",
        )
        .unwrap();
        JwtResolverConfig::new(url, "https://cognito-idp.us-east-1.amazonaws.com/pool")
    }

    fn base_claims() -> JwtClaims {
        JwtClaims {
            sub: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            iss: "https://cognito-idp.us-east-1.amazonaws.com/pool".to_string(),
            aud: Some("client-id".to_string()),
            exp: 1_700_000_000,
            iat: 1_699_996_400,
            token_use: "access".to_string(),
            scope: Some("openid".to_string()),
            cognito_groups: Some(vec!["admins".to_string(), "users".to_string()]),
            custom_claims: {
                let mut m = HashMap::new();
                m.insert("custom:org_id".to_string(), json!("acme-corp"));
                m
            },
        }
    }

    // -- Happy path -----------------------------------------------------------

    #[test]
    fn map_claims_happy_path() {
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();

        assert_eq!(
            identity.user_id().as_str(),
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        );
        assert!(identity.tenant_id().is_none());
        assert!(identity.groups().is_empty());
        assert!(identity.expiry().is_some());
        assert_eq!(identity.resolver(), "cognito_jwt");
        assert_eq!(identity.principal_kind(), PrincipalKind::User);
    }

    #[test]
    fn jwt_identity_has_no_org_context() {
        // JWT proves identity (sub) only — tenant and groups are never populated
        // from JWT claims regardless of what the token contains.
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        assert!(identity.tenant_id().is_none());
        assert!(identity.groups().is_empty());
    }

    // -- User ID extraction ---------------------------------------------------

    #[test]
    fn user_id_from_sub_claim() {
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        assert_eq!(
            identity.user_id().as_str(),
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        );
    }

    #[test]
    fn user_id_from_custom_claim() {
        let mut claims = base_claims();
        claims
            .custom_claims
            .insert("email".to_string(), json!("alice"));
        let config = base_config().with_user_id_claim("email");
        let identity = map_claims(&claims, &config).unwrap();
        assert_eq!(identity.user_id().as_str(), "alice");
    }

    #[test]
    fn user_id_custom_claim_missing_is_error() {
        let claims = base_claims();
        let config = base_config().with_user_id_claim("nonexistent");
        let result = map_claims(&claims, &config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing required claim"));
    }

    #[test]
    fn user_id_invalid_segment_is_error() {
        let mut claims = base_claims();
        claims.sub = "INVALID_USER".to_string();
        let config = base_config();
        let result = map_claims(&claims, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid user_id"));
    }

    // -- Expiry ---------------------------------------------------------------

    #[test]
    fn expiry_is_set_from_exp_claim() {
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        let expiry = identity.expiry().unwrap();
        assert_eq!(expiry.timestamp(), 1_700_000_000);
    }

    // -- Extra ----------------------------------------------------------------

    #[test]
    fn extra_contains_custom_claims() {
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        let extra = identity.extra().unwrap();
        assert_eq!(extra["custom:org_id"], json!("acme-corp"));
    }

    #[test]
    fn extra_is_none_when_no_custom_claims() {
        let mut claims = base_claims();
        claims.custom_claims.clear();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        assert!(identity.extra().is_none());
    }

    // -- Resolver name --------------------------------------------------------

    #[test]
    fn resolver_name_is_cognito_jwt() {
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        assert_eq!(identity.resolver(), "cognito_jwt");
    }
}
