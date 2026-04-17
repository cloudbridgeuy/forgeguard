//! Pure helpers for optimistic-locking etag handling.
//!
//! This module is the functional core for the `If-Match` / ETag flow on
//! `PUT /api/v1/organizations/{org_id}`. Every function here is pure:
//! deterministic, no I/O, no shared-state mutation. The imperative shell
//! (the handler and the store) calls into these functions and translates
//! their outputs into HTTP responses or storage side effects.

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

/// Parse the raw `If-Match` header value.
///
/// Trim whitespace, treat empty as absent, pass the etag through verbatim
/// (including surrounding quotes). Stored etags are already stored with
/// their quotes (see `store::compute_etag`), so comparison is byte-exact
/// with no unquoting. The RFC 7232 `*` wildcard is not supported.
pub(crate) fn parse_if_match(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Decide the `expected_etag` to pass to the store.
///
/// When the incoming PUT body has no `config` field (name-only edit),
/// skip the check — return `None` regardless of the `If-Match` header.
/// When the body has `config`, honour `If-Match`.
pub(crate) fn derive_expected_etag(
    body_has_config: bool,
    if_match: Option<&str>,
) -> Option<String> {
    if body_has_config {
        if_match.map(str::to_string)
    } else {
        None
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
    fn parse_if_match_passes_through_quoted_value() {
        assert_eq!(parse_if_match("\"abc123\""), Some("\"abc123\"".to_string()));
    }

    #[test]
    fn parse_if_match_trims_surrounding_whitespace() {
        assert_eq!(
            parse_if_match("   \"abc123\"\t"),
            Some("\"abc123\"".to_string())
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

    // --- derive_expected_etag ----------------------------------------------

    #[test]
    fn derive_skips_check_when_body_has_no_config() {
        assert_eq!(derive_expected_etag(false, Some("\"abc\"")), None);
        assert_eq!(derive_expected_etag(false, None), None);
    }

    #[test]
    fn derive_honors_if_match_when_body_has_config() {
        assert_eq!(
            derive_expected_etag(true, Some("\"abc\"")),
            Some("\"abc\"".to_string())
        );
    }

    #[test]
    fn derive_returns_none_when_body_has_config_but_no_if_match() {
        assert_eq!(derive_expected_etag(true, None), None);
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
    fn check_mismatch_with_empty_current_when_draft() {
        assert_eq!(
            check_etag(None, Some("\"anything\"")),
            EtagCheck::Mismatch {
                current: String::new()
            }
        );
    }

    // --- composition sanity check ------------------------------------------

    #[test]
    fn round_trip_legacy_caller_path() {
        let parsed = parse_if_match("");
        let expected = derive_expected_etag(true, parsed.as_deref());
        let outcome = check_etag(Some("\"current\""), expected.as_deref());
        assert_eq!(outcome, EtagCheck::Unchecked);
    }

    #[test]
    fn round_trip_matching_caller_path() {
        let parsed = parse_if_match("\"abc\"");
        let expected = derive_expected_etag(true, parsed.as_deref());
        let outcome = check_etag(Some("\"abc\""), expected.as_deref());
        assert_eq!(outcome, EtagCheck::Match);
    }

    #[test]
    fn round_trip_stale_caller_path() {
        let parsed = parse_if_match("\"stale\"");
        let expected = derive_expected_etag(true, parsed.as_deref());
        let outcome = check_etag(Some("\"current\""), expected.as_deref());
        assert_eq!(
            outcome,
            EtagCheck::Mismatch {
                current: "\"current\"".to_string()
            }
        );
    }

    #[test]
    fn round_trip_name_only_ignores_if_match() {
        let parsed = parse_if_match("\"anything\"");
        let expected = derive_expected_etag(false, parsed.as_deref());
        let outcome = check_etag(Some("\"current\""), expected.as_deref());
        assert_eq!(outcome, EtagCheck::Unchecked);
    }
}
