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
    use forgeguard_authz_core::{
        AuthzStore as _, CedarEngine, DecisionQuery, DecisionRecord, MemoryStore, ModelState,
        Snapshot, StoreWrite,
    };
    use forgeguard_core::principal::PrincipalKind as AuthzPrincipalKind;
    use forgeguard_core::{Fgrn, Grant, NativeId, OrgUnit, Principal, Segment, Spine, Verb};
    use forgeguard_proxy_core::EnforcementMode;

    use super::test_support::TestSink;
    use super::*;

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    fn maria() -> Fgrn {
        Fgrn::principal(&org(), &nid("maria"))
    }

    fn doc() -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_1"),
        )
    }

    /// Mirrors `headers::tests::decision_record` — `DecisionRecord::new` is
    /// `pub(crate)` to authz-core, so a real record can only be produced
    /// here by running the engine against a store.
    async fn decision_record() -> DecisionRecord {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let spine = Spine::try_new(vec![OrgUnit::try_new(root.clone(), None).unwrap()]).unwrap();
        let mut model = ModelState::new(spine);
        model.upsert_principal(
            Principal::try_new(maria(), AuthzPrincipalKind::Human, root).unwrap(),
        );
        let store = MemoryStore::new(model);

        store
            .apply(StoreWrite::PutGrant(
                Grant::try_new(doc(), vec![Verb::try_new("read").unwrap()], maria()).unwrap(),
            ))
            .await
            .unwrap();

        let engine = CedarEngine::new(
            Snapshot::from_policy_text(
                r#"permit(principal, action == Action::"unrelated-action", resource);"#,
            )
            .unwrap(),
        );
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc());

        engine.decide(&store, &query).await.unwrap()
    }

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

    /// Smoke test only: no tracing-capture dev-dependency exists anywhere in
    /// the workspace (checked `tracing_test`/`tracing-test`/`with_test_writer`
    /// across every `Cargo.toml` — #111 V3 Task 7), and adding one for a
    /// single assertion isn't worth the cargo-deny/rail surface. This does
    /// NOT assert the emitted event's fields (target, `effect`, `mode`,
    /// `revision`, `scope_path`) — those were reviewed by eye against
    /// `record`'s body. It only asserts `record` doesn't panic, with and
    /// without a `DecisionRecord` present.
    #[tokio::test]
    async fn tracing_decision_sink_record_does_not_panic() {
        TracingDecisionSink.record(&EnforcementOutcome::new(
            None,
            EnforcementMode::Enforce,
            Effect::Allowed,
        ));
        TracingDecisionSink.record(&EnforcementOutcome::new(
            Some(decision_record().await),
            EnforcementMode::Observe,
            Effect::WouldDeny,
        ));
    }
}
