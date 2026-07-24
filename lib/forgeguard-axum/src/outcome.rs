//! Enforcement outcomes delivered to the [`crate::DecisionSink`] (#111 V3).
//!
//! Pure data + mapping. The `DecisionRecord` stays canonical (engine
//! concern); mode and effect wrap around it here in the middleware.

use forgeguard_authz_core::DecisionRecord;
use forgeguard_proxy_core::{EnforcementMode, PolicyEffect};

/// What actually happened to a request, enforcement-wise.
///
/// No `NotEvaluated` variant: outcomes are only constructed when policy
/// evaluation ran (impossible states stay impossible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Enforce mode, allowed and forwarded.
    Allowed,
    /// Enforce mode, denied and rejected (403).
    Denied,
    /// Observe mode, would have been allowed; forwarded.
    WouldAllow,
    /// Observe mode, would have been denied; forwarded anyway.
    WouldDeny,
}

/// One request's enforcement result: the canonical record (when the engine
/// produced one), the mode the route ran under, and the effect.
#[derive(Debug, Clone)]
pub struct EnforcementOutcome {
    record: Option<DecisionRecord>,
    mode: EnforcementMode,
    effect: Effect,
}

impl EnforcementOutcome {
    pub(crate) fn new(
        record: Option<DecisionRecord>,
        mode: EnforcementMode,
        effect: Effect,
    ) -> Self {
        Self {
            record,
            mode,
            effect,
        }
    }

    /// The embedded-engine record, when one was produced.
    pub fn record(&self) -> Option<&DecisionRecord> {
        self.record.as_ref()
    }

    /// The mode this route ran under.
    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    /// The enforcement effect.
    pub fn effect(&self) -> Effect {
        self.effect
    }
}

/// Map the pipeline's forward-side effect into a sink-facing one.
/// `NotEvaluated` maps to `None` — nothing to report.
pub(crate) fn effect_from_forward(effect: PolicyEffect) -> Option<Effect> {
    match effect {
        PolicyEffect::NotEvaluated => None,
        PolicyEffect::Allowed => Some(Effect::Allowed),
        PolicyEffect::WouldAllow => Some(Effect::WouldAllow),
        PolicyEffect::WouldDeny => Some(Effect::WouldDeny),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn effect_from_forward_not_evaluated_maps_to_none() {
        assert_eq!(effect_from_forward(PolicyEffect::NotEvaluated), None);
    }

    #[test]
    fn effect_from_forward_allowed_maps_to_allowed() {
        assert_eq!(
            effect_from_forward(PolicyEffect::Allowed),
            Some(Effect::Allowed)
        );
    }

    #[test]
    fn effect_from_forward_would_allow_maps_to_would_allow() {
        assert_eq!(
            effect_from_forward(PolicyEffect::WouldAllow),
            Some(Effect::WouldAllow)
        );
    }

    #[test]
    fn effect_from_forward_would_deny_maps_to_would_deny() {
        assert_eq!(
            effect_from_forward(PolicyEffect::WouldDeny),
            Some(Effect::WouldDeny)
        );
    }

    #[test]
    fn enforcement_outcome_accessors_round_trip_with_no_record() {
        let outcome = EnforcementOutcome::new(None, EnforcementMode::Enforce, Effect::Allowed);

        assert!(outcome.record().is_none());
        assert_eq!(outcome.mode(), EnforcementMode::Enforce);
        assert_eq!(outcome.effect(), Effect::Allowed);
    }
}
