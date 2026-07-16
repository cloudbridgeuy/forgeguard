//! Control-plane Prometheus metrics.
//!
//! Metric registration (impure: mutates the global `prometheus` default
//! registry via `register_int_counter_vec!`) — the 412 label set is still
//! consumed by the groups/user-schema `PUT`/`DELETE` etag paths.

use std::sync::LazyLock;

/// Why a group `PUT`/`DELETE` responded 412 (org `PUT` is revision-tokened,
/// not etag-conditioned, since #113 V1 — see `handlers::update_handler`).
///
/// The label set is closed — we never emit `org_id` as a label (cardinality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreconditionReason {
    /// Caller supplied a strong `If-Match` that did not equal the stored etag.
    StaleEtag,
    /// `PUT`/`DELETE` on a group requires `If-Match`, but the header was absent.
    MissingIfMatch,
}

impl PreconditionReason {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::StaleEtag => "stale_etag",
            Self::MissingIfMatch => "missing_if_match",
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

/// Rollback-failure counter labelled by VP stage (`"parent"` | `"fanout"`).
///
/// Bumped when the compensating delete after a VP push failure itself fails,
/// leaving DDB and VP inconsistent. Alert on
/// `rate(forgeguard_cp_group_rollback_failed_total[5m]) > 0` — each increment
/// requires manual reconciliation.
//
// Naming note: `forgeguard_cp_*` is the canonical prefix for new
// control-plane metrics; `PUT_ORG_412_TOTAL` above predates this and keeps
// `forgeguard_control_plane_*` for stability of existing dashboards.
pub(crate) static GROUP_ROLLBACK_FAILED_TOTAL: LazyLock<prometheus::IntCounterVec> = LazyLock::new(
    || {
        prometheus::register_int_counter_vec!(
            "forgeguard_cp_group_rollback_failed_total",
            "Group write rollback failures by VP stage (parent | fanout). Each increment means DDB and VP are inconsistent and require operator intervention.",
            &["stage"]
        )
        .unwrap_or_else(|e| {
            panic!("failed to register forgeguard_cp_group_rollback_failed_total: {e}")
        })
    },
);

/// Increment the rollback-failure counter for the given VP stage.
///
/// `stage_label` must come from `VpStage::as_label()` so the label set stays
/// closed. The argument is `&'static str` rather than `VpStage` to keep
/// `metrics.rs` independent of `handlers/groups/active_pure.rs`.
pub(crate) fn record_group_rollback_failed(stage_label: &'static str) {
    GROUP_ROLLBACK_FAILED_TOTAL
        .with_label_values(&[stage_label])
        .inc();
    tracing::Span::current().record("rollback_stage", stage_label);
}

/// Saga-compensation-failure counter for the `POST /users` inline saga.
///
/// Bumped exactly on the Path-3 outcome — S3 failed transiently and the C2
/// `AdminDeleteUser` compensation that should have undone S2 ALSO failed,
/// leaving Cognito and DDB inconsistent. No labels (cardinality kept low):
/// the alert lives in the SLO rule, not the dashboard.
pub(crate) static SAGA_COMPENSATION_FAILED_TOTAL: LazyLock<prometheus::IntCounter> = LazyLock::new(
    || {
        prometheus::register_int_counter!(
            "forgeguard_cp_saga_compensation_failed_total",
            "POST /users saga compensation failures. Each increment means a Cognito user may exist without a membership row and requires operator intervention."
        )
        .unwrap_or_else(|e| {
            panic!("failed to register forgeguard_cp_saga_compensation_failed_total: {e}")
        })
    },
);

/// Increment the saga-compensation-failure counter.
pub(crate) fn record_saga_compensation_failed() {
    SAGA_COMPENSATION_FAILED_TOTAL.inc();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn as_label_values() {
        assert_eq!(PreconditionReason::StaleEtag.as_label(), "stale_etag");
        assert_eq!(
            PreconditionReason::MissingIfMatch.as_label(),
            "missing_if_match"
        );
    }

    #[test]
    fn record_group_rollback_failed_increments_counter() {
        let before_parent = GROUP_ROLLBACK_FAILED_TOTAL
            .with_label_values(&["parent"])
            .get();
        let before_fanout = GROUP_ROLLBACK_FAILED_TOTAL
            .with_label_values(&["fanout"])
            .get();

        record_group_rollback_failed("parent");
        record_group_rollback_failed("fanout");
        record_group_rollback_failed("fanout");

        assert_eq!(
            GROUP_ROLLBACK_FAILED_TOTAL
                .with_label_values(&["parent"])
                .get(),
            before_parent + 1
        );
        assert_eq!(
            GROUP_ROLLBACK_FAILED_TOTAL
                .with_label_values(&["fanout"])
                .get(),
            before_fanout + 2
        );
    }
}
