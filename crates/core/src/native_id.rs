//! Application-native identifier newtype.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// An application-native identifier, crossing into ForgeGuard at the FGRN
/// boundary.
///
/// Rules:
/// - Non-empty
/// - Visible ASCII only (`0x21..=0x7E`) — no whitespace, control chars, or
///   high bytes, so any `NativeId` is header-safe like [`crate::Segment`]
/// - Must not contain `:` (the FGRN separator)
/// - Must not contain `*` (reserved for selectors)
///
/// `/`, `_`, and uppercase letters are all allowed — native ids are the
/// app's own ids, not ForgeGuard's to restyle.
///
/// Examples: `"doc_123"`, `"usr_8f3k2"`, `"Invoice/2024-001"`, `"a"`.
/// Invalid: `""`, `"has space"`, `"has:colon"`, `"has*star"`, non-ASCII.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NativeId(String);

impl NativeId {
    /// Create a new `NativeId` after validating the input.
    pub fn try_new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();

        if s.is_empty() {
            return Err(Error::Parse {
                field: "native_id",
                value: s,
                reason: "cannot be empty",
            });
        }
        if !s.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Parse {
                field: "native_id",
                value: s,
                reason: "must be visible ASCII only",
            });
        }
        if s.contains(':') {
            return Err(Error::Parse {
                field: "native_id",
                value: s,
                reason: "must not contain ':'",
            });
        }
        if s.contains('*') {
            return Err(Error::Parse {
                field: "native_id",
                value: s,
                reason: "must not contain '*'",
            });
        }

        Ok(Self(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NativeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NativeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::try_new(s)
    }
}

impl TryFrom<String> for NativeId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::try_new(s)
    }
}

impl From<NativeId> for String {
    fn from(id: NativeId) -> Self {
        id.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_underscored_id() {
        assert!(NativeId::try_new("doc_123").is_ok());
    }

    #[test]
    fn accepts_underscored_alnum_id() {
        assert!(NativeId::try_new("usr_8f3k2").is_ok());
    }

    #[test]
    fn accepts_uppercase_and_slash() {
        assert!(NativeId::try_new("Invoice/2024-001").is_ok());
    }

    #[test]
    fn accepts_single_char() {
        assert!(NativeId::try_new("a").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(NativeId::try_new("").is_err());
    }

    #[test]
    fn rejects_whitespace() {
        assert!(NativeId::try_new("has space").is_err());
    }

    #[test]
    fn rejects_colon() {
        assert!(NativeId::try_new("has:colon").is_err());
    }

    #[test]
    fn rejects_star() {
        assert!(NativeId::try_new("has*star").is_err());
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(NativeId::try_new("héllo").is_err());
    }

    #[test]
    fn rejects_control_chars() {
        assert!(NativeId::try_new("tab\there").is_err());
    }

    #[test]
    fn display_round_trips() {
        let id = NativeId::try_new("doc_123").unwrap();
        assert_eq!(id.to_string(), "doc_123");
    }

    #[test]
    fn from_str_works() {
        let id: NativeId = "doc_123".parse().unwrap();
        assert_eq!(id.as_str(), "doc_123");
    }

    #[test]
    fn serde_round_trip() {
        let id = NativeId::try_new("doc_123").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"doc_123\"");
        let deser: NativeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deser);
    }
}
