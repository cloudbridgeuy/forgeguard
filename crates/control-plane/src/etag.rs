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
/// Stores the etag value **without** surrounding quotes. The optional
/// `W/` weak-validator prefix is preserved as part of the value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Etag(String);

impl Etag {
    /// Construct, validating the input is a non-empty etag value.
    ///
    /// Accepts the bare value (e.g. `"abc123"` or `W/"abc123"`).
    /// Does not require surrounding quotes — quotes belong to the wire
    /// format, not the value.
    pub(crate) fn try_new(raw: impl Into<String>) -> crate::error::Result<Self> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(crate::error::Error::InvalidEtag { raw });
        }
        Ok(Self(raw))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` when this is a weak validator (starts with `W/`).
    ///
    /// Weak validators are accepted in the `If-Match` header but are not
    /// used for strong comparison (RFC 7232 §3). Kept for future use.
    #[allow(dead_code)]
    pub(crate) fn is_weak(&self) -> bool {
        self.0.starts_with("W/")
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

/// Outcome of resolving an `IfMatch` header against the stored state.
///
/// Produced by [`resolve_if_match`]; consumed by the handler to decide
/// whether to proceed with the write, skip the locking check, or fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedIfMatch {
    /// No `If-Match` header present — skip the check.
    Absent,
    /// Strong comparison — forward the expected etag to [`check_etag`].
    Strong(Etag),
    /// Wildcard matched an existing representation — check passes, no
    /// etag comparison needed.
    WildcardMatched,
    /// Wildcard on a Draft org (no stored representation) — fail closed.
    WildcardOnDraft,
}

/// Outcome of comparing a caller-supplied `expected_etag` against the
/// currently stored etag.
///
/// The explicit enum (rather than `Result<bool>` or `Option<String>`) forces
/// each branch to be handled at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EtagCheck {
    /// Caller did not supply an expectation — write unconditionally.
    Unchecked,
    /// Stored etag matches the caller's expectation. Proceed with the write.
    Match,
    /// Stored etag does not match (or there is no stored etag and the
    /// caller supplied one). `current` carries whatever is actually stored;
    /// `None` means there is no stored etag (a Draft org has no config yet).
    Mismatch { current: Option<Etag> },
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
/// - Anything else → `Some(IfMatch::Strong(etag))`, or `None` if the
///   trimmed value is empty (which cannot happen after the earlier check,
///   but we guard defensively).
///
/// Stored etags are already stored with their surrounding quotes (see
/// the `compute_etag` helper in `crate::store`), so strong comparison is byte-exact with no
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

/// Resolve an [`IfMatch`] header against the currently stored etag.
///
/// | `header`           | `stored`  | result              |
/// |--------------------|-----------|---------------------|
/// | `None`             | any       | `Absent`            |
/// | `Some(Strong(e))`  | any       | `Strong(e)`         |
/// | `Some(Wildcard)`   | `Some(_)` | `WildcardMatched`   |
/// | `Some(Wildcard)`   | `None`    | `WildcardOnDraft`   |
pub(crate) fn resolve_if_match(header: Option<IfMatch>, stored: Option<&Etag>) -> ResolvedIfMatch {
    match (header, stored) {
        (None, _) => ResolvedIfMatch::Absent,
        (Some(IfMatch::Strong(e)), _) => ResolvedIfMatch::Strong(e),
        (Some(IfMatch::Wildcard), Some(_)) => ResolvedIfMatch::WildcardMatched,
        (Some(IfMatch::Wildcard), None) => ResolvedIfMatch::WildcardOnDraft,
    }
}

/// Compare stored vs expected etag and produce an explicit outcome.
///
/// - `expected == None`                                          → `Unchecked`
/// - `expected == Some(e)` and `stored == Some(s)` and `s == e`  → `Match`
/// - `expected == Some(e)` and `stored == Some(s)` and `s != e`  → `Mismatch { current: Some(s) }`
/// - `expected == Some(e)` and `stored == None`                  → `Mismatch { current: None }`
pub(crate) fn check_etag(stored: Option<&Etag>, expected: Option<&Etag>) -> EtagCheck {
    match (expected, stored) {
        (None, _) => EtagCheck::Unchecked,
        (Some(e), Some(s)) if s == e => EtagCheck::Match,
        (Some(_), Some(s)) => EtagCheck::Mismatch {
            current: Some(s.clone()),
        },
        (Some(_), None) => EtagCheck::Mismatch { current: None },
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
        assert!(!e.is_weak());
    }

    #[test]
    fn try_new_accepts_weak() {
        let e = Etag::try_new("W/abc123").unwrap();
        assert!(e.is_weak());
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

    // --- resolve_if_match ---------------------------------------------------

    #[test]
    fn resolve_absent_when_no_header() {
        let stored = Etag::try_new("\"abc\"").unwrap();
        assert_eq!(
            resolve_if_match(None, Some(&stored)),
            ResolvedIfMatch::Absent
        );
        assert_eq!(resolve_if_match(None, None), ResolvedIfMatch::Absent);
    }

    #[test]
    fn resolve_strong_forwards_etag_regardless_of_stored() {
        let e = Etag::try_new("\"e\"").unwrap();
        let stored = Etag::try_new("\"abc\"").unwrap();
        assert_eq!(
            resolve_if_match(Some(IfMatch::Strong(e.clone())), Some(&stored)),
            ResolvedIfMatch::Strong(e.clone())
        );
        assert_eq!(
            resolve_if_match(Some(IfMatch::Strong(e.clone())), None),
            ResolvedIfMatch::Strong(e)
        );
    }

    #[test]
    fn resolve_wildcard_matched_when_stored_exists() {
        let stored = Etag::try_new("\"abc\"").unwrap();
        assert_eq!(
            resolve_if_match(Some(IfMatch::Wildcard), Some(&stored)),
            ResolvedIfMatch::WildcardMatched
        );
    }

    #[test]
    fn resolve_wildcard_on_draft_when_no_stored() {
        assert_eq!(
            resolve_if_match(Some(IfMatch::Wildcard), None),
            ResolvedIfMatch::WildcardOnDraft
        );
    }

    // --- check_etag --------------------------------------------------------

    #[test]
    fn check_unchecked_when_expected_is_none() {
        let stored = Etag::try_new("\"abc\"").unwrap();
        assert_eq!(check_etag(Some(&stored), None), EtagCheck::Unchecked);
        assert_eq!(check_etag(None, None), EtagCheck::Unchecked);
    }

    #[test]
    fn check_match_when_stored_equals_expected() {
        let stored = Etag::try_new("\"abc\"").unwrap();
        let expected = Etag::try_new("\"abc\"").unwrap();
        assert_eq!(check_etag(Some(&stored), Some(&expected)), EtagCheck::Match);
    }

    #[test]
    fn check_mismatch_when_stored_differs_from_expected() {
        let stored = Etag::try_new("\"current\"").unwrap();
        let expected = Etag::try_new("\"stale\"").unwrap();
        assert_eq!(
            check_etag(Some(&stored), Some(&expected)),
            EtagCheck::Mismatch {
                current: Some(Etag::try_new("\"current\"").unwrap())
            }
        );
    }

    #[test]
    fn check_mismatch_when_no_stored_etag_but_expected_supplied() {
        let expected = Etag::try_new("\"anything\"").unwrap();
        assert_eq!(
            check_etag(None, Some(&expected)),
            EtagCheck::Mismatch { current: None }
        );
    }

    #[test]
    fn check_etag_typed_mismatch() {
        let stored = Etag::try_new("abc").unwrap();
        let expected = Etag::try_new("xyz").unwrap();
        let result = check_etag(Some(&stored), Some(&expected));
        match result {
            EtagCheck::Mismatch { current } => {
                assert_eq!(current.unwrap().as_str(), "abc")
            }
            _ => panic!("expected Mismatch"),
        }
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
