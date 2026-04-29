//! AWS-style date-versioned schema id.

use crate::error::{Error, Result};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

const FORMAT: &str = "%Y-%m-%d";

/// AWS-style date-versioned schema id (e.g. `"2026-04-29"`).
///
/// Stores both the parsed [`NaiveDate`] and the original string for
/// lossless round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ConfigVersion {
    raw: String,
    #[serde(skip)]
    date: NaiveDate,
}

impl ConfigVersion {
    /// Construct, validating `YYYY-MM-DD`.
    pub fn try_new(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        let date = NaiveDate::parse_from_str(&raw, FORMAT)
            .map_err(|_| Error::InvalidConfigVersion { raw: raw.clone() })?;
        Ok(Self { raw, date })
    }

    /// The original string, in ISO 8601 date format (`YYYY-MM-DD`).
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The parsed date.
    pub fn date(&self) -> NaiveDate {
        self.date
    }
}

impl fmt::Display for ConfigVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for ConfigVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::try_new(s.to_string())
    }
}

impl<'de> Deserialize<'de> for ConfigVersion {
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
    fn try_new_accepts_valid_date() {
        let v = ConfigVersion::try_new("2026-04-29").unwrap();
        assert_eq!(v.as_str(), "2026-04-29");
        assert_eq!(v.date(), NaiveDate::from_ymd_opt(2026, 4, 29).unwrap());
    }

    #[test]
    fn try_new_rejects_bad_month() {
        let err = ConfigVersion::try_new("2026-13-01").unwrap_err();
        assert!(matches!(err, Error::InvalidConfigVersion { .. }));
    }

    #[test]
    fn try_new_rejects_non_date_string() {
        let err = ConfigVersion::try_new("not a date").unwrap_err();
        assert!(matches!(err, Error::InvalidConfigVersion { .. }));
    }

    #[test]
    fn try_new_rejects_wrong_format() {
        let err = ConfigVersion::try_new("04/29/2026").unwrap_err();
        assert!(matches!(err, Error::InvalidConfigVersion { .. }));
    }

    #[test]
    fn deserializes_from_string() {
        let v: ConfigVersion = serde_json::from_str("\"2026-04-29\"").unwrap();
        assert_eq!(v.as_str(), "2026-04-29");
    }

    #[test]
    fn deserialize_rejects_bad_date() {
        let result: std::result::Result<ConfigVersion, _> = serde_json::from_str("\"2026-13-01\"");
        assert!(result.is_err());
    }

    #[test]
    fn from_str_works() {
        let v: ConfigVersion = "2026-04-29".parse().unwrap();
        assert_eq!(v.as_str(), "2026-04-29");
    }

    #[test]
    fn round_trip_through_serde() {
        let v = ConfigVersion::try_new("2026-04-29").unwrap();
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"2026-04-29\"");
        let v2: ConfigVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }
}
