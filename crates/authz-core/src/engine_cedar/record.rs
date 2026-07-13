//! The decision record — the brief's decision-log unit: every decision
//! names the snapshot version and store revision that decided it (R3), so
//! any historical decision can be replayed exactly.

use forgeguard_core::{Fgrn, Verb};

use crate::snapshot::SnapshotVersion;
use crate::store::Revision;

/// A single authorization question.
#[derive(Debug, Clone)]
pub struct DecisionQuery {
    principal: Fgrn,
    action: Verb,
    resource: Fgrn,
    revision: Option<Revision>,
}

impl DecisionQuery {
    /// Ask whether `principal` may perform `action` on `resource` at the
    /// latest revision.
    pub fn new(principal: Fgrn, action: Verb, resource: Fgrn) -> Self {
        Self {
            principal,
            action,
            resource,
            revision: None,
        }
    }

    /// Pin the decision to a specific store revision.
    pub fn at_revision(mut self, revision: Revision) -> Self {
        self.revision = Some(revision);
        self
    }

    /// The acting principal.
    pub fn principal(&self) -> &Fgrn {
        &self.principal
    }

    /// The attempted action.
    pub fn action(&self) -> &Verb {
        &self.action
    }

    /// The target resource.
    pub fn resource(&self) -> &Fgrn {
        &self.resource
    }

    /// Requested revision; `None` means latest.
    pub fn revision(&self) -> Option<Revision> {
        self.revision
    }
}

/// The verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Access permitted.
    Allow,
    /// Access denied (Cedar default-deny, an explicit forbid, or a
    /// delegation-chain link that does not allow).
    Deny,
}

/// A decision plus the exact state that produced it.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    decision: Decision,
    snapshot_version: SnapshotVersion,
    revision: Revision,
}

impl DecisionRecord {
    pub(crate) fn new(
        decision: Decision,
        snapshot_version: SnapshotVersion,
        revision: Revision,
    ) -> Self {
        Self {
            decision,
            snapshot_version,
            revision,
        }
    }

    /// The verdict.
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Convenience: was this an allow?
    pub fn is_allow(&self) -> bool {
        self.decision == Decision::Allow
    }

    /// The snapshot version that decided.
    pub fn snapshot_version(&self) -> &SnapshotVersion {
        &self.snapshot_version
    }

    /// The store revision the entity slice was read at.
    pub fn revision(&self) -> Revision {
        self.revision
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::Fgrn;

    use super::*;

    fn fgrn(s: &str) -> Fgrn {
        s.parse().unwrap()
    }

    #[test]
    fn query_defaults_to_no_revision() {
        let q = DecisionQuery::new(
            fgrn("fgrn:acme:principal:maria"),
            Verb::try_new("invoice-write").unwrap(),
            fgrn("fgrn:acme:resource:invoice/inv_1"),
        );
        assert_eq!(q.revision(), None);
    }

    #[test]
    fn at_revision_pins_query() {
        let q = DecisionQuery::new(
            fgrn("fgrn:acme:principal:maria"),
            Verb::try_new("invoice-write").unwrap(),
            fgrn("fgrn:acme:resource:invoice/inv_1"),
        )
        .at_revision(Revision::new(2));
        assert_eq!(q.revision(), Some(Revision::new(2)));
    }

    #[test]
    fn record_reports_allow() {
        let record = DecisionRecord::new(
            Decision::Allow,
            SnapshotVersion::of("permit();"),
            Revision::new(1),
        );
        assert!(record.is_allow());
        assert_eq!(record.decision(), Decision::Allow);
        assert_eq!(record.revision(), Revision::new(1));
    }

    #[test]
    fn record_reports_deny() {
        let record = DecisionRecord::new(
            Decision::Deny,
            SnapshotVersion::of("forbid();"),
            Revision::new(1),
        );
        assert!(!record.is_allow());
    }
}
