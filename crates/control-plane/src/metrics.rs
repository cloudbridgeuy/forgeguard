//! Control-plane Prometheus metrics.
//!
//! Metric registration (impure: mutates the global `prometheus` default
//! registry via `register_int_counter_vec!`) and the pure helper that
//! classifies a 412 reason from the `ResolvedIfMatch` + stored-etag pair.

use std::sync::LazyLock;

use crate::etag::{Etag, ResolvedIfMatch};

/// Why a `PUT /organizations/{id}` responded 412.
///
/// The label set is closed — we never emit `org_id` as a label (cardinality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreconditionReason {
    /// Caller supplied a strong `If-Match` that did not equal the stored etag.
    StaleEtag,
    /// Draft org received a (strong) `If-Match`; fail closed because no
    /// representation exists to compare against.
    DraftFailClosed,
    /// Caller sent `If-Match: *` on a Draft org (no stored representation).
    WildcardOnDraft,
}

impl PreconditionReason {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::StaleEtag => "stale_etag",
            Self::DraftFailClosed => "draft_fail_closed",
            Self::WildcardOnDraft => "wildcard_on_draft",
        }
    }
}

/// Classify the 412 reason from the resolved `If-Match` decision and the
/// stored etag at decision time. Pure, total over the combinations that
/// yield a 412.
///
/// # Contract
///
/// Call this function **only on the 412 path** (`WildcardOnDraft` short-circuit
/// or a store-returned `Error::PreconditionFailed`). The non-412 arms
/// (`Absent`, `WildcardMatched`) trip a `debug_assert!` in debug builds and
/// fall through to `StaleEtag` in release builds to avoid panicking a live
/// request handler.
pub(crate) fn precondition_reason(
    resolved: &ResolvedIfMatch,
    stored: Option<&Etag>,
) -> PreconditionReason {
    match resolved {
        ResolvedIfMatch::WildcardOnDraft => PreconditionReason::WildcardOnDraft,
        ResolvedIfMatch::Strong(_) if stored.is_none() => PreconditionReason::DraftFailClosed,
        ResolvedIfMatch::Strong(_) => PreconditionReason::StaleEtag,
        // The two happy-path arms do not yield 412; if the caller reaches
        // here for those arms it indicates a logic error in the handler.
        // We classify them as StaleEtag to emit *something* rather than
        // panicking in production, but a debug_assert! flags dev builds.
        ResolvedIfMatch::Absent | ResolvedIfMatch::WildcardMatched => {
            debug_assert!(
                false,
                "precondition_reason called for non-412 ResolvedIfMatch arm"
            );
            PreconditionReason::StaleEtag
        }
    }
}

pub(crate) static PUT_ORG_412_TOTAL: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "forgeguard_control_plane_put_org_412_total",
        "PUT /organizations/{id} responses that returned 412 Precondition Failed, by reason.",
        &["reason"]
    )
    .unwrap_or_else(|e| {
        panic!("failed to register forgeguard_control_plane_put_org_412_total: {e}")
    })
});

/// Increment the 412 counter and record the reason as a span attribute.
/// Intended to be called from the handler on every 412 path.
pub(crate) fn record_precondition_failed(reason: PreconditionReason) {
    PUT_ORG_412_TOTAL
        .with_label_values(&[reason.as_label()])
        .inc();
    tracing::Span::current().record("precondition_reason", reason.as_label());
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::etag::Etag;

    #[test]
    fn reason_wildcard_on_draft() {
        assert_eq!(
            precondition_reason(&ResolvedIfMatch::WildcardOnDraft, None),
            PreconditionReason::WildcardOnDraft
        );
    }

    #[test]
    fn reason_draft_fail_closed_when_strong_on_missing_store() {
        assert_eq!(
            precondition_reason(
                &ResolvedIfMatch::Strong(Etag::try_new("\"abc\"").unwrap()),
                None
            ),
            PreconditionReason::DraftFailClosed
        );
    }

    #[test]
    fn reason_stale_etag_when_strong_on_configured() {
        let current = Etag::try_new("\"current\"").unwrap();
        assert_eq!(
            precondition_reason(
                &ResolvedIfMatch::Strong(Etag::try_new("\"stale\"").unwrap()),
                Some(&current)
            ),
            PreconditionReason::StaleEtag
        );
    }

    #[test]
    fn as_label_values() {
        assert_eq!(PreconditionReason::StaleEtag.as_label(), "stale_etag");
        assert_eq!(
            PreconditionReason::DraftFailClosed.as_label(),
            "draft_fail_closed"
        );
        assert_eq!(
            PreconditionReason::WildcardOnDraft.as_label(),
            "wildcard_on_draft"
        );
    }
}
