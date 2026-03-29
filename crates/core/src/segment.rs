//! Validated identifier segments and typed ID newtypes.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Segment
// ---------------------------------------------------------------------------

/// A validated identifier segment.
///
/// Rules:
/// - Lowercase ASCII letters, digits, and hyphens only (a-z, 0-9, -)
/// - Must start with a lowercase letter or digit
/// - Must not end with a hyphen
/// - No consecutive hyphens (reserved, Punycode-style)
/// - Non-empty, no upper length limit
/// - Guaranteed visible ASCII only — no control chars, no whitespace, no
///   high bytes. This means any Segment value is safe to use directly as
///   an HTTP header value without encoding or escaping.
///
/// This format survives every environment without translation:
/// URIs, Cedar entity IDs, S3 keys, HTTP headers, CloudWatch dimensions,
/// DNS labels (RFC 1123 allows digit-first), structured logs, TOML values, JSON keys.
/// UUIDs are valid Segments: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".
///
/// Examples: "acme-corp", "todo-app", "list", "item-abc123"
/// Invalid: "AcmeCorp", "my_project", "-leading", "trailing-", "no--double", ""
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Segment(String);

impl Segment {
    /// Create a new `Segment` after validating the input.
    pub fn try_new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();

        if s.is_empty() {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "cannot be empty",
            });
        }
        if !s.as_bytes()[0].is_ascii_lowercase() && !s.as_bytes()[0].is_ascii_digit() {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "must start with a lowercase letter or digit",
            });
        }
        if s.ends_with('-') {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "must not end with a hyphen",
            });
        }
        if s.contains("--") {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "consecutive hyphens are not allowed",
            });
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "must contain only lowercase letters, digits, and hyphens",
            });
        }

        Ok(Self(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert this segment to a Cedar-safe identifier by replacing hyphens
    /// with underscores.
    ///
    /// Every valid `Segment` produces a valid [`CedarIdent`](crate::CedarIdent)
    /// because:
    /// - Segments start with `[a-z0-9]`, which is valid for Cedar IDENTs
    /// - Replacing `-` with `_` keeps all characters in `[_a-zA-Z0-9]`
    pub fn to_cedar_ident(&self) -> crate::CedarIdent {
        crate::CedarIdent::from_valid(self.0.replace('-', "_"))
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Segment {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::try_new(s)
    }
}

impl TryFrom<String> for Segment {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::try_new(s)
    }
}

impl From<Segment> for String {
    fn from(seg: Segment) -> Self {
        seg.0
    }
}

// ---------------------------------------------------------------------------
// define_id! macro
// ---------------------------------------------------------------------------

/// Generates a newtype wrapper over `Segment` with validation, Display,
/// FromStr, Serialize, Deserialize, Clone, Eq, Hash, and accessor methods.
macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Eq, PartialEq, Hash)]
        pub struct $name(Segment);

        impl $name {
            /// Create a new typed ID after validating the input as a `Segment`.
            pub fn new(raw: impl Into<String>) -> Result<Self> {
                Segment::try_new(raw).map(Self)
            }

            /// Borrow the inner string.
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            /// Borrow the inner `Segment`.
            pub fn as_segment(&self) -> &Segment {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::new(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Typed IDs
// ---------------------------------------------------------------------------

define_id!(UserId);
define_id!(TenantId);
define_id!(ProjectId);
define_id!(GroupName);
define_id!(PolicyName);

// ---------------------------------------------------------------------------
// FlowId
// ---------------------------------------------------------------------------

/// A unique identifier for a single request/operation flow, backed by UUID v4.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct FlowId(Uuid);

impl FlowId {
    /// Generate a new random `FlowId` (UUID v4).
    ///
    /// Not available on `wasm32-unknown-unknown` — use [`FlowId::from_uuid`] instead.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Borrow the inner UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for FlowId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- Segment validation --------------------------------------------------

    #[test]
    fn segment_valid_lowercase() {
        assert!(Segment::try_new("acme-corp").is_ok());
    }

    #[test]
    fn segment_valid_digit_first() {
        assert!(Segment::try_new("1abc").is_ok());
    }

    #[test]
    fn segment_valid_uuid() {
        assert!(Segment::try_new("a1b2c3d4-e5f6-7890-abcd-ef1234567890").is_ok());
    }

    #[test]
    fn segment_rejects_empty() {
        assert!(Segment::try_new("").is_err());
    }

    #[test]
    fn segment_rejects_uppercase() {
        assert!(Segment::try_new("AcmeCorp").is_err());
    }

    #[test]
    fn segment_rejects_underscores() {
        assert!(Segment::try_new("my_project").is_err());
    }

    #[test]
    fn segment_rejects_leading_hyphen() {
        assert!(Segment::try_new("-leading").is_err());
    }

    #[test]
    fn segment_rejects_trailing_hyphen() {
        assert!(Segment::try_new("trailing-").is_err());
    }

    #[test]
    fn segment_rejects_consecutive_hyphens() {
        assert!(Segment::try_new("no--double").is_err());
    }

    #[test]
    fn segment_rejects_non_visible_ascii() {
        assert!(Segment::try_new("\x00hidden").is_err());
    }

    // -- Display round-trip --------------------------------------------------

    #[test]
    fn segment_display_round_trip() {
        let seg = Segment::try_new("acme-corp").unwrap();
        let display = seg.to_string();
        let parsed: Segment = display.parse().unwrap();
        assert_eq!(seg, parsed);
    }

    // -- Serde round-trip ----------------------------------------------------

    #[test]
    fn segment_serde_round_trip() {
        let seg = Segment::try_new("acme-corp").unwrap();
        let json = serde_json::to_string(&seg).unwrap();
        let deser: Segment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, deser);
    }

    // -- Typed ID validation -------------------------------------------------

    #[test]
    fn user_id_valid() {
        assert!(UserId::new("alice").is_ok());
        assert!(UserId::new("bob-smith").is_ok());
    }

    #[test]
    fn user_id_rejects_invalid() {
        assert!(UserId::new("Alice").is_err());
        assert!(UserId::new("user_abc").is_err());
        assert!(UserId::new("").is_err());
    }

    #[test]
    fn group_name_valid() {
        assert!(GroupName::new("admin").is_ok());
        assert!(GroupName::new("backend-team").is_ok());
    }

    #[test]
    fn group_name_rejects_invalid() {
        assert!(GroupName::new("Admin").is_err());
        assert!(GroupName::new("my_group").is_err());
    }

    #[test]
    fn policy_name_valid() {
        assert!(PolicyName::new("todo-viewer").is_ok());
        assert!(PolicyName::new("todo-admin").is_ok());
    }

    #[test]
    fn policy_name_rejects_invalid() {
        assert!(PolicyName::new("TodoViewer").is_err());
        assert!(PolicyName::new("todo_admin").is_err());
    }

    // -- UserId serde round-trip ---------------------------------------------

    #[test]
    fn user_id_serde_round_trip() {
        let id = UserId::new("alice").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"alice\"");
        let deser: UserId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deser);
    }

    // -- FlowId --------------------------------------------------------------

    #[test]
    fn flow_id_display_is_uuid_format() {
        let flow = FlowId::new();
        let s = flow.to_string();
        // UUID v4 format: 8-4-4-4-12 hex digits
        assert!(
            Uuid::parse_str(&s).is_ok(),
            "FlowId display should be valid UUID: {s}"
        );
    }
}
