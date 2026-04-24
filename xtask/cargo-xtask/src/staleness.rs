//! Pure core: decide whether the cached xtask binary is fresh or stale.

use std::time::SystemTime;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum Staleness {
    Fresh,
    Stale,
}

/// Pure decider. Returns `Stale` when the binary is missing, or when any
/// source mtime exceeds the binary mtime. Equal mtimes are treated as fresh —
/// this matches cargo's own fingerprint semantics for ties.
///
/// **Caller contract:** the shell must pass a non-empty `source_mtimes` slice
/// when a source tree is expected. An empty slice with a present binary returns
/// `Fresh`, so a silent walk failure would mask staleness.
pub(crate) fn is_stale(
    binary_mtime: Option<SystemTime>,
    source_mtimes: &[SystemTime],
) -> Staleness {
    let Some(bin) = binary_mtime else {
        return Staleness::Stale;
    };

    if source_mtimes.iter().any(|src| *src > bin) {
        Staleness::Stale
    } else {
        Staleness::Fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn missing_binary_is_stale() {
        assert_eq!(is_stale(None, &[t(100)]), Staleness::Stale);
    }

    #[test]
    fn binary_newer_than_all_sources_is_fresh() {
        assert_eq!(is_stale(Some(t(200)), &[t(100), t(150)]), Staleness::Fresh);
    }

    #[test]
    fn any_source_newer_than_binary_is_stale() {
        assert_eq!(is_stale(Some(t(100)), &[t(50), t(200)]), Staleness::Stale);
    }

    #[test]
    fn empty_source_list_is_fresh_when_binary_exists() {
        assert_eq!(is_stale(Some(t(100)), &[]), Staleness::Fresh);
    }

    #[test]
    fn equal_mtimes_are_treated_as_fresh() {
        assert_eq!(is_stale(Some(t(100)), &[t(100)]), Staleness::Fresh);
    }

    #[test]
    fn single_source_newer_than_binary_is_stale() {
        assert_eq!(is_stale(Some(t(100)), &[t(101)]), Staleness::Stale);
    }
}
