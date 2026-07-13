//! Grant action words (Brief v1.4): the verb half of a `Grant` edge.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// A validated grant action word, e.g. `"read"`, `"share-external"`.
///
/// Rules:
/// - Non-empty
/// - At most 64 characters
/// - First character `a..=z`
/// - Remaining characters `a..=z`, `0..=9`, or `-`
///
/// Deliberately its own type, not a [`crate::Segment`] alias: verbs and
/// name segments are different domain concepts whose rulesets may diverge.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Verb(String);

impl Verb {
    /// Create a new `Verb` after validating the input.
    pub fn try_new(s: impl Into<String>) -> Result<Verb> {
        let s = s.into();

        if s.is_empty() {
            return Err(Error::Parse {
                field: "verb",
                value: s,
                reason: "must not be empty",
            });
        }
        if s.len() > 64 {
            return Err(Error::Parse {
                field: "verb",
                value: s,
                reason: "must be at most 64 characters",
            });
        }
        if !s.starts_with(|c: char| c.is_ascii_lowercase()) {
            return Err(Error::Parse {
                field: "verb",
                value: s,
                reason: "must start with a lowercase letter",
            });
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(Error::Parse {
                field: "verb",
                value: s,
                reason: "must contain only lowercase letters, digits, and hyphens",
            });
        }

        Ok(Verb(s))
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Verb {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::try_new(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_verb() {
        assert!(Verb::try_new("read").is_ok());
    }

    #[test]
    fn accepts_hyphenated_verb() {
        assert!(Verb::try_new("share-external").is_ok());
    }

    #[test]
    fn accepts_verb_with_digit() {
        assert!(Verb::try_new("read2").is_ok());
    }

    #[test]
    fn rejects_empty() {
        let err = Verb::try_new("").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_uppercase() {
        let err = Verb::try_new("Read").unwrap_err();
        assert!(err
            .to_string()
            .contains("must start with a lowercase letter"));
    }

    #[test]
    fn rejects_leading_digit() {
        let err = Verb::try_new("2read").unwrap_err();
        assert!(err
            .to_string()
            .contains("must start with a lowercase letter"));
    }

    #[test]
    fn rejects_underscore() {
        let err = Verb::try_new("re_ad").unwrap_err();
        assert!(err
            .to_string()
            .contains("must contain only lowercase letters, digits, and hyphens"));
    }

    #[test]
    fn rejects_colon() {
        let err = Verb::try_new("re:ad").unwrap_err();
        assert!(err
            .to_string()
            .contains("must contain only lowercase letters, digits, and hyphens"));
    }

    #[test]
    fn rejects_space() {
        let err = Verb::try_new("re ad").unwrap_err();
        assert!(err
            .to_string()
            .contains("must contain only lowercase letters, digits, and hyphens"));
    }

    #[test]
    fn rejects_too_long() {
        let s = "a".repeat(65);
        let err = Verb::try_new(s).unwrap_err();
        assert!(err.to_string().contains("must be at most 64 characters"));
    }

    #[test]
    fn from_str_round_trip() {
        let verb: Verb = "read".parse().unwrap();
        assert_eq!(verb.as_str(), "read");
    }
}
