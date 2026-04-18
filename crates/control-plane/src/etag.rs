//! Pure helpers for optimistic-locking etag handling.
//!
//! This module is the functional core for the `If-Match` / ETag flow on
//! `PUT /api/v1/organizations/{org_id}`. Every function here is pure:
//! deterministic, no I/O, no shared-state mutation. The imperative shell
//! (the handler and the store) calls into these functions and translates
//! their outputs into HTTP responses or storage side effects.

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
    Strong(String),
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
    Strong(String),
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
    /// an empty string means there is no stored etag (a draft org has no
    /// config yet).
    Mismatch { current: String },
}

/// Parse the raw `If-Match` header value into an [`IfMatch`] ADT.
///
/// - Trims surrounding whitespace.
/// - Empty / whitespace-only → `None` (header absent).
/// - Exactly `*` → `Some(IfMatch::Wildcard)`.
/// - Anything else → `Some(IfMatch::Strong(trimmed))`.
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
        Some(IfMatch::Strong(trimmed.to_owned()))
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
pub(crate) fn resolve_if_match(header: Option<IfMatch>, stored: Option<&str>) -> ResolvedIfMatch {
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
/// - `expected == Some(e)` and `stored == Some(s)` and `s != e`  → `Mismatch { current: s }`
/// - `expected == Some(e)` and `stored == None`                  → `Mismatch { current: "" }`
pub(crate) fn check_etag(stored: Option<&str>, expected: Option<&str>) -> EtagCheck {
    match (expected, stored) {
        (None, _) => EtagCheck::Unchecked,
        (Some(e), Some(s)) if s == e => EtagCheck::Match,
        (Some(_), Some(s)) => EtagCheck::Mismatch {
            current: s.to_string(),
        },
        (Some(_), None) => EtagCheck::Mismatch {
            current: String::new(),
        },
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
            Some(IfMatch::Strong("\"abc123\"".to_owned()))
        );
    }

    #[test]
    fn parse_if_match_strong_trims_whitespace() {
        assert_eq!(
            parse_if_match("   \"abc123\"\t"),
            Some(IfMatch::Strong("\"abc123\"".to_owned()))
        );
    }

    #[test]
    fn parse_if_match_double_star_is_strong_not_wildcard() {
        assert_eq!(parse_if_match("**"), Some(IfMatch::Strong("**".to_owned())));
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
        assert_eq!(
            resolve_if_match(None, Some("\"abc\"")),
            ResolvedIfMatch::Absent
        );
        assert_eq!(resolve_if_match(None, None), ResolvedIfMatch::Absent);
    }

    #[test]
    fn resolve_strong_forwards_etag_regardless_of_stored() {
        assert_eq!(
            resolve_if_match(Some(IfMatch::Strong("\"e\"".to_owned())), Some("\"abc\"")),
            ResolvedIfMatch::Strong("\"e\"".to_owned())
        );
        assert_eq!(
            resolve_if_match(Some(IfMatch::Strong("\"e\"".to_owned())), None),
            ResolvedIfMatch::Strong("\"e\"".to_owned())
        );
    }

    #[test]
    fn resolve_wildcard_matched_when_stored_exists() {
        assert_eq!(
            resolve_if_match(Some(IfMatch::Wildcard), Some("\"abc\"")),
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
        assert_eq!(check_etag(Some("\"abc\""), None), EtagCheck::Unchecked);
        assert_eq!(check_etag(None, None), EtagCheck::Unchecked);
    }

    #[test]
    fn check_match_when_stored_equals_expected() {
        assert_eq!(
            check_etag(Some("\"abc\""), Some("\"abc\"")),
            EtagCheck::Match
        );
    }

    #[test]
    fn check_mismatch_when_stored_differs_from_expected() {
        assert_eq!(
            check_etag(Some("\"current\""), Some("\"stale\"")),
            EtagCheck::Mismatch {
                current: "\"current\"".to_string()
            }
        );
    }

    #[test]
    fn check_mismatch_when_no_stored_etag_but_expected_supplied() {
        assert_eq!(
            check_etag(None, Some("\"anything\"")),
            EtagCheck::Mismatch {
                current: String::new()
            }
        );
    }
}
