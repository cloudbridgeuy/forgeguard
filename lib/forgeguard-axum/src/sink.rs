//! Where enforcement outcomes go (#111 V3).

use crate::{Effect, EnforcementOutcome};

/// Receives every enforcement outcome — enforce and observe alike.
///
/// The default is [`TracingDecisionSink`]. Durable sinks (DynamoDB, S3,
/// audit trail) are the embedding app's to plug in; the middleware calls
/// `record` synchronously on the request path, so implementations must be
/// cheap or hand off to their own channel/task.
pub trait DecisionSink: Send + Sync {
    /// Record one request's enforcement outcome.
    fn record(&self, outcome: &EnforcementOutcome);
}

/// Default sink: one structured `tracing` event per outcome.
pub struct TracingDecisionSink;

impl DecisionSink for TracingDecisionSink {
    fn record(&self, outcome: &EnforcementOutcome) {
        let effect = match outcome.effect() {
            Effect::Allowed => "allowed",
            Effect::Denied => "denied",
            Effect::WouldAllow => "would_allow",
            Effect::WouldDeny => "would_deny",
        };
        let revision = outcome.record().map(|r| r.revision().value());
        let scope_path = outcome.record().map(|r| r.scope_path().to_string());
        tracing::info!(
            target: "forgeguard::decision",
            effect,
            mode = ?outcome.mode(),
            revision,
            scope_path,
            "forgeguard decision"
        );
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    use super::DecisionSink;
    use crate::{Effect, EnforcementOutcome};

    /// Captures effects in order, for middleware assertions.
    #[derive(Default)]
    pub(crate) struct TestSink(pub(crate) Mutex<Vec<Effect>>);

    impl DecisionSink for TestSink {
        fn record(&self, outcome: &EnforcementOutcome) {
            #[allow(clippy::unwrap_used)]
            self.0.lock().unwrap().push(outcome.effect());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::test_support::TestSink;
    use super::*;
    use forgeguard_proxy_core::EnforcementMode;

    #[test]
    fn sink_captures_effects_in_order() {
        let sink = TestSink::default();

        sink.record(&EnforcementOutcome::new(
            None,
            EnforcementMode::Enforce,
            Effect::Allowed,
        ));
        sink.record(&EnforcementOutcome::new(
            None,
            EnforcementMode::Observe,
            Effect::WouldDeny,
        ));

        let captured = sink.0.lock().unwrap();
        assert_eq!(*captured, vec![Effect::Allowed, Effect::WouldDeny]);
    }
}
