//! Bounded `0..=100` percentage value.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Percentage value bounded to `0..=100`.
///
/// Construct via [`Percentage::try_new`], `TryFrom<u8>`, or `Deserialize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Percentage(u8);

impl Percentage {
    /// Construct, validating `value <= 100`.
    pub fn try_new(value: u8) -> Result<Self> {
        if value > 100 {
            return Err(Error::InvalidPercentage { value });
        }
        Ok(Self(value))
    }

    /// The wrapped value, always in `0..=100`.
    ///
    /// In rollout evaluation the bucket space is `0..=99` (100 buckets), so
    /// a percentage of `100` puts every user in rollout (all buckets satisfy
    /// `bucket < 100`) and a percentage of `0` excludes every user
    /// (`bucket < 0` is never true).
    pub fn value(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for Percentage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

impl TryFrom<u8> for Percentage {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        Self::try_new(value)
    }
}

impl<'de> Deserialize<'de> for Percentage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = u8::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn try_new_accepts_zero() {
        assert_eq!(Percentage::try_new(0).unwrap().value(), 0);
    }

    #[test]
    fn try_new_accepts_hundred() {
        assert_eq!(Percentage::try_new(100).unwrap().value(), 100);
    }

    #[test]
    fn try_new_rejects_above_hundred() {
        let err = Percentage::try_new(101).unwrap_err();
        assert!(matches!(err, Error::InvalidPercentage { value: 101 }));
    }

    #[test]
    fn try_new_rejects_max_u8() {
        let err = Percentage::try_new(255).unwrap_err();
        assert!(matches!(err, Error::InvalidPercentage { value: 255 }));
    }

    #[test]
    fn deserializes_from_valid_u8() {
        let p: Percentage = serde_json::from_str("42").unwrap();
        assert_eq!(p.value(), 42);
    }

    #[test]
    fn deserialize_rejects_above_hundred() {
        let result: std::result::Result<Percentage, _> = serde_json::from_str("200");
        assert!(result.is_err());
    }

    #[test]
    fn display_includes_percent_sign() {
        assert_eq!(Percentage::try_new(50).unwrap().to_string(), "50%");
    }
}
