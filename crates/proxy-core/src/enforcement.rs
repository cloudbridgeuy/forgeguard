//! Enforcement mode and per-request policy effect (#111 V3).

/// How Phase 9 treats a policy deny.
///
/// `Enforce` rejects (403). `Observe` never blocks: the pipeline forwards
/// and reports what WOULD have happened via [`PolicyEffect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Deny blocks the request. The default — misconfiguration fails safe.
    #[default]
    Enforce,
    /// Deny is recorded but the request forwards.
    Observe,
}

/// What policy evaluation concluded for a forwarded request.
///
/// There is deliberately no `Denied` variant: an enforced deny never
/// reaches `Forward` (it rejects in Phase 9), so a forwarded request can
/// only be not-evaluated, allowed, or observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyEffect {
    /// Policy never ran: public route, no identity, or no matched route.
    #[default]
    NotEvaluated,
    /// Enforce mode, allow.
    Allowed,
    /// Observe mode, would have allowed.
    WouldAllow,
    /// Observe mode, would have denied (request forwarded anyway).
    WouldDeny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcement_mode_defaults_to_enforce() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Enforce);
    }

    #[test]
    fn policy_effect_defaults_to_not_evaluated() {
        assert_eq!(PolicyEffect::default(), PolicyEffect::NotEvaluated);
    }
}
