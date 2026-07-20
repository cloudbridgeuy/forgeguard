//! Control-plane Prometheus metrics.
//!
//! Metric registration (impure: mutates the global `prometheus` default
//! registry via `register_int_counter_vec!`).

use std::sync::LazyLock;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
