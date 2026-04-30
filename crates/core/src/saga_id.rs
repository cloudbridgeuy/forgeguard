//! Identifier for a saga execution.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

const PK_PREFIX: &str = "SAGA#";

/// Identifier for a saga execution.
///
/// Wraps the **bare** id (the part after the `SAGA#` partition-key prefix).
/// Construct via [`SagaId::try_new`] (bare input) or [`SagaId::from_pk`]
/// (full DynamoDB partition-key input).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SagaId(String);

impl SagaId {
    /// Construct from a bare id (no prefix). Rejects empty input and ids that contain `#`.
    pub fn try_new(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if raw.is_empty() || raw.contains('#') {
            return Err(Error::InvalidSagaId { raw });
        }
        Ok(Self(raw))
    }

    /// Construct from a DynamoDB partition key of the form `SAGA#<id>`.
    pub fn from_pk(pk: &str) -> Result<Self> {
        let bare = pk
            .strip_prefix(PK_PREFIX)
            .ok_or_else(|| Error::InvalidSagaId {
                raw: pk.to_string(),
            })?;
        Self::try_new(bare)
    }

    /// The bare id (suitable for AWS Step Functions execution name).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SagaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SagaId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::try_new(s)
    }
}

impl<'de> Deserialize<'de> for SagaId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn try_new_accepts_bare_id() {
        let id = SagaId::try_new("abc-123").unwrap();
        assert_eq!(id.as_str(), "abc-123");
    }

    #[test]
    fn try_new_rejects_empty() {
        let err = SagaId::try_new("").unwrap_err();
        assert!(matches!(err, Error::InvalidSagaId { .. }));
    }

    #[test]
    fn try_new_rejects_hash() {
        let err = SagaId::try_new("SAGA#abc").unwrap_err();
        assert!(matches!(err, Error::InvalidSagaId { .. }));
    }

    #[test]
    fn from_pk_strips_prefix() {
        let id = SagaId::from_pk("SAGA#abc-123").unwrap();
        assert_eq!(id.as_str(), "abc-123");
    }

    #[test]
    fn from_pk_rejects_missing_prefix() {
        let err = SagaId::from_pk("abc-123").unwrap_err();
        assert!(matches!(err, Error::InvalidSagaId { .. }));
    }

    #[test]
    fn from_pk_rejects_wrong_prefix() {
        let err = SagaId::from_pk("USER#abc").unwrap_err();
        assert!(matches!(err, Error::InvalidSagaId { .. }));
    }

    #[test]
    fn from_pk_rejects_empty_bare() {
        let err = SagaId::from_pk("SAGA#").unwrap_err();
        assert!(matches!(err, Error::InvalidSagaId { .. }));
    }

    #[test]
    fn from_str_accepts_bare_id() {
        let id: SagaId = "saga-from-parse-id".parse().unwrap();
        assert_eq!(id.as_str(), "saga-from-parse-id");
    }

    #[test]
    fn from_str_rejects_empty() {
        let err = "".parse::<SagaId>().unwrap_err();
        assert!(matches!(err, Error::InvalidSagaId { .. }));
    }
}
