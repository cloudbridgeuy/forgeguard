//! Pure helpers for optimistic-locking etag handling.
//!
//! This module is the functional core for the `If-Match` / `If-None-Match` /
//! ETag flow on `PUT /api/v1/organizations/{org_id}` and the corresponding
//! `GET` reads. Every function here is pure: deterministic, no I/O, no
//! shared-state mutation. The imperative shell (the handler and the store)
//! calls into these functions and translates their outputs into HTTP responses
//! or storage side effects.

/// RFC 7232 entity tag value.
///
/// Stores the raw etag string exactly as supplied by the caller. For values
/// produced by [`crate::store::compute_etag`] the string includes surrounding
/// double-quotes (e.g. `"\"a1b2c3d4e5f60708\"`). The only invariant enforced
/// here is that the value is non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Etag(String);

impl Etag {
    /// Construct an `Etag`, validating that the input is non-empty.
    ///
    /// Accepts any non-empty string. The string is stored verbatim — this
    /// constructor does not strip or add surrounding quotes. Etags produced by
    /// `compute_etag` include double-quotes (per RFC 7232 wire format) and are
    /// stored that way. Returns `Error::InvalidEtag` on empty input.
    pub(crate) fn try_new(raw: impl Into<String>) -> crate::error::Result<Self> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(crate::error::Error::InvalidEtag { raw });
        }
        Ok(Self(raw))
    }

    /// Construct from a string the caller has already proven non-empty.
    ///
    /// Internal-only helper for cases where validation is statically clear
    /// (e.g., constructed from a fixed-length hash format such as the one
    /// produced by `compute_etag`). Prefer [`Self::try_new`] at untrusted
    /// boundaries.
    pub(crate) fn from_validated(raw: String) -> Self {
        debug_assert!(!raw.is_empty(), "from_validated called with empty string");
        Self(raw)
    }

    /// Return the raw etag string (the value passed to [`Self::try_new`]).
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Etag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parsed form of the `If-Match` request header.
///
/// Only two legal forms are recognised:
/// - `*` — matches any currently stored representation (RFC 7232 §3.1).
/// - A strong ETag (anything else after whitespace trimming) — compared
///   byte-exactly against the stored value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IfMatch {
    /// `If-Match: *` — matches any currently stored representation.
    Wildcard,
    /// `If-Match: "<hex>"` — strong comparator against a specific etag.
    Strong(Etag),
}

/// Outcome of comparing an `If-None-Match` header against the stored etag.
///
/// Maps directly to HTTP status: [`Matched`][IfNoneMatchResult::Matched] /
/// [`WildcardMatched`][IfNoneMatchResult::WildcardMatched] → 304;
/// everything else → 200 + body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IfNoneMatchResult {
    /// No header, or header parsed but nothing to compare (e.g. Draft org
    /// with a strong `If-None-Match`). Handler returns 200 + body.
    NotMatched,
    /// Strong etag matched stored etag. Handler returns 304.
    Matched,
    /// `If-None-Match: *` against a Configured org. Handler returns 304.
    WildcardMatched,
    /// `If-None-Match: *` against a Draft org (no representation). Handler
    /// returns 200 + body. Kept as a distinct variant so the handler match is
    /// total and the intent is self-documenting.
    WildcardOnDraft,
}

/// Parse the raw `If-Match` header value into an [`IfMatch`] ADT.
///
/// - Trims surrounding whitespace.
/// - Empty / whitespace-only → `None` (header absent).
/// - Exactly `*` → `Some(IfMatch::Wildcard)`.
/// - Anything else → `Some(IfMatch::Strong(etag))`.
///
/// Stored etags include their surrounding quotes (produced by `compute_etag`),
/// so strong comparison is byte-exact against the trimmed header value with no
/// unquoting needed.
pub(crate) fn parse_if_match(raw: &str) -> Option<IfMatch> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "*" {
        Some(IfMatch::Wildcard)
    } else {
        Etag::try_new(trimmed).ok().map(IfMatch::Strong)
    }
}

/// Compare an `If-None-Match` header against the currently stored etag and
/// produce an explicit outcome.
///
/// | `header`                  | `stored_etag`         | Result              |
/// |---------------------------|-----------------------|---------------------|
/// | `None`                    | any                   | `NotMatched`        |
/// | `Some(Wildcard)`          | `Some(_)`             | `WildcardMatched`   |
/// | `Some(Wildcard)`          | `None`                | `WildcardOnDraft`   |
/// | `Some(Strong(h))`         | `Some(s)` if `h == s` | `Matched`           |
/// | `Some(Strong(h))`         | `Some(s)` if `h != s` | `NotMatched`        |
/// | `Some(Strong(_))`         | `None`                | `NotMatched`        |
pub(crate) fn check_if_none_match(
    header: Option<IfMatch>,
    stored_etag: Option<&Etag>,
) -> IfNoneMatchResult {
    match (header, stored_etag) {
        (None, _) => IfNoneMatchResult::NotMatched,
        (Some(IfMatch::Wildcard), Some(_)) => IfNoneMatchResult::WildcardMatched,
        (Some(IfMatch::Wildcard), None) => IfNoneMatchResult::WildcardOnDraft,
        (Some(IfMatch::Strong(h)), Some(s)) if h == *s => IfNoneMatchResult::Matched,
        (Some(IfMatch::Strong(_)), _) => IfNoneMatchResult::NotMatched,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod etag_value_tests {
    use super::*;

    #[test]
    fn try_new_accepts_strong() {
        let e = Etag::try_new("abc123").unwrap();
        assert_eq!(e.as_str(), "abc123");
    }

    #[test]
    fn try_new_rejects_empty() {
        assert!(Etag::try_new("").is_err());
    }

    #[test]
    fn display_round_trips() {
        let e = Etag::try_new("abc").unwrap();
        assert_eq!(e.to_string(), "abc");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- parse_if_match -----------------------------------------------------

    #[test]
    fn parse_if_match_wildcard() {
        assert_eq!(parse_if_match("*"), Some(IfMatch::Wildcard));
    }

    #[test]
    fn parse_if_match_wildcard_with_whitespace() {
        assert_eq!(parse_if_match("  *  "), Some(IfMatch::Wildcard));
    }

    #[test]
    fn parse_if_match_strong_quoted_value() {
        assert_eq!(
            parse_if_match("\"abc123\""),
            Some(IfMatch::Strong(Etag::try_new("\"abc123\"").unwrap()))
        );
    }

    #[test]
    fn parse_if_match_strong_trims_whitespace() {
        assert_eq!(
            parse_if_match("   \"abc123\"\t"),
            Some(IfMatch::Strong(Etag::try_new("\"abc123\"").unwrap()))
        );
    }

    #[test]
    fn parse_if_match_double_star_is_strong_not_wildcard() {
        assert_eq!(
            parse_if_match("**"),
            Some(IfMatch::Strong(Etag::try_new("**").unwrap()))
        );
    }

    #[test]
    fn parse_if_match_empty_is_none() {
        assert_eq!(parse_if_match(""), None);
    }

    #[test]
    fn parse_if_match_whitespace_only_is_none() {
        assert_eq!(parse_if_match("   "), None);
    }

    // --- check_if_none_match ------------------------------------------------

    #[test]
    fn check_none_header_is_not_matched() {
        let stored = Etag::try_new("\"abc\"").unwrap();
        assert_eq!(
            check_if_none_match(None, Some(&stored)),
            IfNoneMatchResult::NotMatched
        );
        assert_eq!(
            check_if_none_match(None, None),
            IfNoneMatchResult::NotMatched
        );
    }

    #[test]
    fn check_wildcard_on_configured_is_wildcard_matched() {
        let stored = Etag::try_new("\"abc\"").unwrap();
        assert_eq!(
            check_if_none_match(Some(IfMatch::Wildcard), Some(&stored)),
            IfNoneMatchResult::WildcardMatched
        );
    }

    #[test]
    fn check_wildcard_on_draft() {
        assert_eq!(
            check_if_none_match(Some(IfMatch::Wildcard), None),
            IfNoneMatchResult::WildcardOnDraft
        );
    }

    #[test]
    fn check_strong_matching_stored_is_matched() {
        let stored = Etag::try_new("\"abc123\"").unwrap();
        assert_eq!(
            check_if_none_match(
                Some(IfMatch::Strong(Etag::try_new("\"abc123\"").unwrap())),
                Some(&stored)
            ),
            IfNoneMatchResult::Matched
        );
    }

    #[test]
    fn check_strong_differing_from_stored_is_not_matched() {
        let stored = Etag::try_new("\"current\"").unwrap();
        assert_eq!(
            check_if_none_match(
                Some(IfMatch::Strong(Etag::try_new("\"stale\"").unwrap())),
                Some(&stored)
            ),
            IfNoneMatchResult::NotMatched
        );
    }

    #[test]
    fn check_strong_on_draft_is_not_matched() {
        assert_eq!(
            check_if_none_match(
                Some(IfMatch::Strong(Etag::try_new("\"abc\"").unwrap())),
                None
            ),
            IfNoneMatchResult::NotMatched
        );
    }
}
