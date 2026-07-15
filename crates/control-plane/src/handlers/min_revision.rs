//! Pure min-revision guard (V2 / N11): parse the `X-Fg-Min-Revision` request
//! header and decide fresh-vs-behind against the log's current revision.
//!
//! Lives at `handlers/` level rather than inside `events/` because every
//! model-plane read (V3 promotion list included) adopts the same guard. The
//! strong `SEQ` read that produces `current` is the caller's responsibility —
//! this module is I/O-free.

use forgeguard_authz_core::Revision;

/// Request header carrying the caller's required minimum revision (D5).
pub(crate) const MIN_REVISION_HEADER: &str = "x-fg-min-revision";

/// The header was present but not a `u64`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidMinRevision;

/// Outcome of comparing the log's current revision to the caller's minimum.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MinRevisionCheck {
    /// `current >= required` — serve the read.
    Fresh,
    /// `current < required` — respond `412` carrying both values.
    Behind {
        current: Revision,
        required: Revision,
    },
}

/// Parse the raw header value. `None` (header absent) means "no requirement".
pub(crate) fn parse_min_revision(
    raw: Option<&str>,
) -> Result<Option<Revision>, InvalidMinRevision> {
    match raw {
        None => Ok(None),
        Some(value) => value
            .trim()
            .parse::<u64>()
            .map(|n| Some(Revision::new(n)))
            .map_err(|_| InvalidMinRevision),
    }
}

/// Compare the current revision against the caller's requirement.
pub(crate) fn check_min_revision(current: Revision, required: Revision) -> MinRevisionCheck {
    if current >= required {
        MinRevisionCheck::Fresh
    } else {
        MinRevisionCheck::Behind { current, required }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn absent_header_means_no_requirement() {
        assert_eq!(parse_min_revision(None), Ok(None));
    }

    #[test]
    fn numeric_header_parses_to_revision() {
        assert_eq!(parse_min_revision(Some("42")), Ok(Some(Revision::new(42))));
        assert_eq!(parse_min_revision(Some(" 7 ")), Ok(Some(Revision::new(7))));
    }

    #[test]
    fn garbage_header_is_invalid() {
        assert_eq!(parse_min_revision(Some("banana")), Err(InvalidMinRevision));
        assert_eq!(parse_min_revision(Some("")), Err(InvalidMinRevision));
        assert_eq!(parse_min_revision(Some("-1")), Err(InvalidMinRevision));
        assert_eq!(parse_min_revision(Some("1.5")), Err(InvalidMinRevision));
    }

    #[test]
    fn current_at_or_above_required_is_fresh() {
        assert_eq!(
            check_min_revision(Revision::new(5), Revision::new(5)),
            MinRevisionCheck::Fresh
        );
        assert_eq!(
            check_min_revision(Revision::new(6), Revision::new(5)),
            MinRevisionCheck::Fresh
        );
    }

    #[test]
    fn current_below_required_is_behind() {
        assert_eq!(
            check_min_revision(Revision::new(4), Revision::new(5)),
            MinRevisionCheck::Behind {
                current: Revision::new(4),
                required: Revision::new(5),
            }
        );
    }
}
