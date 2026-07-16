//! Pure `X-Fg-If-Revision` request-header parser (V1 org CRUD, issue #113):
//! parses the caller's optimistic-concurrency precondition for `update_org`.
//!
//! Mirrors `handlers/min_revision.rs`'s parse semantics exactly, but this
//! header expresses "only apply if the log is still at this revision"
//! rather than "only serve reads at or above this revision" — the handler
//! maps a mismatch to `412` with both revisions, same as `min_revision`'s
//! `Behind` outcome does for reads.

use forgeguard_authz_core::Revision;

/// Request header carrying the caller's expected current revision.
pub(crate) const IF_REVISION_HEADER: &str = "x-fg-if-revision";

/// The header was present but not a `u64`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidIfRevision;

/// Parse the raw header value. `None` (header absent) means "no precondition".
pub(crate) fn parse_if_revision(raw: Option<&str>) -> Result<Option<Revision>, InvalidIfRevision> {
    match raw {
        None => Ok(None),
        Some(value) => value
            .trim()
            .parse::<u64>()
            .map(|n| Some(Revision::new(n)))
            .map_err(|_| InvalidIfRevision),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn absent_header_means_no_precondition() {
        assert_eq!(parse_if_revision(None), Ok(None));
    }

    #[test]
    fn numeric_header_parses_to_revision() {
        assert_eq!(parse_if_revision(Some("42")), Ok(Some(Revision::new(42))));
        assert_eq!(parse_if_revision(Some(" 7 ")), Ok(Some(Revision::new(7))));
    }

    #[test]
    fn garbage_header_is_invalid() {
        assert_eq!(parse_if_revision(Some("banana")), Err(InvalidIfRevision));
        assert_eq!(parse_if_revision(Some("")), Err(InvalidIfRevision));
        assert_eq!(parse_if_revision(Some("-1")), Err(InvalidIfRevision));
        assert_eq!(parse_if_revision(Some("1.5")), Err(InvalidIfRevision));
    }
}
