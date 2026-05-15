//! `PoolId` newtype + parameter structs for `UserPoolClient` calls.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::user_schema::{CognitoAttrDef, RawAttrMap};

/// Cognito user-pool identifier. Non-empty; no `#` (reserved by ForgeGuard
/// composite DDB keys).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PoolId(String);

impl PoolId {
    /// Validate and wrap a raw pool ID.
    pub fn try_new(raw: impl Into<String>) -> Result<Self, Error> {
        let s = raw.into();
        if s.is_empty() || s.contains('#') {
            return Err(Error::InvalidPoolId { raw: s });
        }
        Ok(Self(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PoolId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl<'de> Deserialize<'de> for PoolId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

/// Inputs for `UserPoolClient::create_user` (V3).
#[derive(Debug, Clone)]
pub struct CreateUserParams {
    pub pool_id: PoolId,
    pub email: String,
    pub attributes: RawAttrMap,
}

/// Inputs for `UserPoolClient::update_pool` (V3).
#[derive(Debug, Clone)]
pub struct UpdatePoolParams {
    pub pool_id: PoolId,
    pub schema_attrs: Vec<CognitoAttrDef>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pool_id_valid() {
        assert!(PoolId::try_new("us-east-1_abc").is_ok());
    }

    #[test]
    fn pool_id_empty_rejected() {
        assert!(matches!(
            PoolId::try_new(""),
            Err(Error::InvalidPoolId { .. })
        ));
    }

    #[test]
    fn pool_id_with_hash_rejected() {
        assert!(matches!(
            PoolId::try_new("foo#bar"),
            Err(Error::InvalidPoolId { .. })
        ));
    }

    #[test]
    fn pool_id_roundtrip_serde() {
        let id = PoolId::try_new("us-east-1_abc").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"us-east-1_abc\"");
        let parsed: PoolId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn pool_id_deserialize_rejects_empty() {
        let result: Result<PoolId, _> = serde_json::from_str(r#""""#);
        assert!(result.is_err());
    }

    #[test]
    fn pool_id_from_str() {
        let id: PoolId = "us-east-1_abc".parse().unwrap();
        assert_eq!(id.as_str(), "us-east-1_abc");
    }

    #[test]
    fn pool_id_display_matches_as_str() {
        let id = PoolId::try_new("us-east-1_abc").unwrap();
        assert_eq!(id.to_string(), id.as_str());
    }
}
