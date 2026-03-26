//! Pure claim-to-Identity mapping.

use chrono::DateTime;
use forgeguard_authn_core::{Identity, JwtClaims};
use forgeguard_core::{GroupName, TenantId, UserId};

use crate::config::JwtResolverConfig;
use crate::error::Result;

/// Map validated JWT claims to a trusted `Identity`.
///
/// This is a pure function — no I/O, no crypto. It extracts user_id, tenant_id,
/// and groups from the claims using the configured claim names, and constructs
/// an `Identity` value.
pub(crate) fn map_claims(claims: &JwtClaims, config: &JwtResolverConfig) -> Result<Identity> {
    let user_id = extract_user_id(claims, config)?;
    let tenant_id = extract_tenant_id(claims, config)?;
    let groups = extract_groups(claims, config)?;
    let expiry = Some(
        DateTime::from_timestamp(claims.exp as i64, 0).ok_or_else(|| {
            forgeguard_authn_core::Error::MalformedToken(format!(
                "invalid exp timestamp: {}",
                claims.exp
            ))
        })?,
    );
    let extra = build_extra(claims);

    Ok(Identity::new(
        user_id,
        tenant_id,
        groups,
        expiry,
        "cognito_jwt",
        extra,
    ))
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

/// Extract the tenant ID from the configured claim in custom_claims.
fn extract_tenant_id(claims: &JwtClaims, config: &JwtResolverConfig) -> Result<Option<TenantId>> {
    let claim_name = config.tenant_claim();
    let raw = claims
        .custom_claims
        .get(claim_name)
        .and_then(|v| v.as_str());

    match raw {
        Some(value) => {
            let tid = TenantId::new(value).map_err(|e| {
                forgeguard_authn_core::Error::MalformedToken(format!("invalid tenant_id: {e}"))
            })?;
            Ok(Some(tid))
        }
        None => Ok(None),
    }
}

/// Extract groups from the claims.
///
/// Checks `cognito_groups` first (the standard Cognito field), then falls back
/// to the configured groups claim in `custom_claims`.
fn extract_groups(claims: &JwtClaims, config: &JwtResolverConfig) -> Result<Vec<GroupName>> {
    let claim_name = config.groups_claim();

    // Default claim name is "cognito:groups", which maps to the cognito_groups field.
    let raw_groups = if claim_name == "cognito:groups" {
        claims.cognito_groups.clone().unwrap_or_default()
    } else {
        // Look in custom_claims for the configured key.
        claims
            .custom_claims
            .get(claim_name)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };

    raw_groups
        .iter()
        .map(|g| {
            GroupName::new(g.as_str()).map_err(|e| {
                forgeguard_authn_core::Error::MalformedToken(format!("invalid group name: {e}"))
                    .into()
            })
        })
        .collect()
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
        assert_eq!(identity.tenant_id().unwrap().as_str(), "acme-corp");
        assert_eq!(identity.groups().len(), 2);
        assert_eq!(identity.groups()[0].as_str(), "admins");
        assert_eq!(identity.groups()[1].as_str(), "users");
        assert!(identity.expiry().is_some());
        assert_eq!(identity.resolver(), "cognito_jwt");
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

    // -- Tenant ID extraction -------------------------------------------------

    #[test]
    fn tenant_id_from_custom_claim() {
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        assert_eq!(identity.tenant_id().unwrap().as_str(), "acme-corp");
    }

    #[test]
    fn tenant_id_missing_returns_none() {
        let mut claims = base_claims();
        claims.custom_claims.remove("custom:org_id");
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        assert!(identity.tenant_id().is_none());
    }

    #[test]
    fn tenant_id_invalid_segment_is_error() {
        let mut claims = base_claims();
        claims
            .custom_claims
            .insert("custom:org_id".to_string(), json!("INVALID_TENANT"));
        let config = base_config();
        let result = map_claims(&claims, &config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid tenant_id"));
    }

    #[test]
    fn tenant_id_from_different_claim() {
        let mut claims = base_claims();
        claims
            .custom_claims
            .insert("custom:tenant".to_string(), json!("other-corp"));
        let config = base_config().with_tenant_claim("custom:tenant");
        let identity = map_claims(&claims, &config).unwrap();
        assert_eq!(identity.tenant_id().unwrap().as_str(), "other-corp");
    }

    // -- Groups extraction ----------------------------------------------------

    #[test]
    fn groups_from_cognito_groups() {
        let claims = base_claims();
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        let names: Vec<&str> = identity.groups().iter().map(GroupName::as_str).collect();
        assert_eq!(names, vec!["admins", "users"]);
    }

    #[test]
    fn groups_empty_when_cognito_groups_is_none() {
        let mut claims = base_claims();
        claims.cognito_groups = None;
        let config = base_config();
        let identity = map_claims(&claims, &config).unwrap();
        assert!(identity.groups().is_empty());
    }

    #[test]
    fn groups_from_custom_claim() {
        let mut claims = base_claims();
        claims.cognito_groups = None;
        claims
            .custom_claims
            .insert("custom:roles".to_string(), json!(["editors", "viewers"]));
        let config = base_config().with_groups_claim("custom:roles");
        let identity = map_claims(&claims, &config).unwrap();
        let names: Vec<&str> = identity.groups().iter().map(GroupName::as_str).collect();
        assert_eq!(names, vec!["editors", "viewers"]);
    }

    #[test]
    fn groups_custom_claim_missing_returns_empty() {
        let mut claims = base_claims();
        claims.cognito_groups = None;
        let config = base_config().with_groups_claim("nonexistent");
        let identity = map_claims(&claims, &config).unwrap();
        assert!(identity.groups().is_empty());
    }

    #[test]
    fn groups_invalid_name_is_error() {
        let mut claims = base_claims();
        claims.cognito_groups = Some(vec!["INVALID_GROUP".to_string()]);
        let config = base_config();
        let result = map_claims(&claims, &config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid group name"));
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
