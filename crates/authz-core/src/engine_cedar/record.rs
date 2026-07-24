//! The decision record — the brief's decision-log unit: every decision
//! names the snapshot version and store revision that decided it (R3), so
//! any historical decision can be replayed exactly.

use forgeguard_core::{DelegationChain, Fgrn, Verb};

use crate::snapshot::SnapshotVersion;
use crate::store::Revision;

use super::ScopePath;

/// A single authorization question.
#[derive(Debug, Clone)]
pub struct DecisionQuery {
    principal: Fgrn,
    action: Verb,
    resource: Fgrn,
    revision: Option<Revision>,
    chain: Option<DelegationChain>,
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
            chain: None,
        }
    }

    /// Pin the decision to a specific store revision.
    pub fn at_revision(mut self, revision: Revision) -> Self {
        self.revision = Some(revision);
        self
    }

    /// Attach a delegation chain. The query's principal must be the chain's
    /// actor — a chained decision is "may this actor act, on behalf of every
    /// link down to the subject".
    pub fn with_chain(mut self, chain: DelegationChain) -> crate::Result<Self> {
        if chain.actor() != &self.principal {
            return Err(crate::Error::ChainActorMismatch {
                principal: self.principal.to_string(),
                actor: chain.actor().to_string(),
            });
        }
        self.chain = Some(chain);
        Ok(self)
    }

    /// The delegation chain, when this is a delegated decision.
    pub fn chain(&self) -> Option<&DelegationChain> {
        self.chain.as_ref()
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
    scope_path: ScopePath,
    entitlements: Vec<Verb>,
    granted_ids: Vec<forgeguard_core::NativeId>,
}

/// Constructor arguments for [`DecisionRecord::new`] — six fields tripped
/// the workspace's `too-many-arguments` threshold (5), see
/// `.claude/context/params-struct-rule.md`.
pub(crate) struct RecordParts {
    pub(crate) decision: Decision,
    pub(crate) snapshot_version: SnapshotVersion,
    pub(crate) revision: Revision,
    pub(crate) scope_path: ScopePath,
    pub(crate) entitlements: Vec<Verb>,
    pub(crate) granted_ids: Vec<forgeguard_core::NativeId>,
}

impl DecisionRecord {
    pub(crate) fn new(parts: RecordParts) -> Self {
        Self {
            decision: parts.decision,
            snapshot_version: parts.snapshot_version,
            revision: parts.revision,
            scope_path: parts.scope_path,
            entitlements: parts.entitlements,
            granted_ids: parts.granted_ids,
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

    /// The principal's org-unit ancestry at decision time.
    pub fn scope_path(&self) -> &ScopePath {
        &self.scope_path
    }

    /// Verbs granted to the principal on the queried resource, sorted.
    pub fn entitlements(&self) -> &[Verb] {
        &self.entitlements
    }

    /// Resource IDs directly granted to the principal on the queried
    /// resource — the RLS exception list (`fg.granted_ids`). Usually empty.
    pub fn granted_ids(&self) -> &[forgeguard_core::NativeId] {
        &self.granted_ids
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

    /// A `maria writes invoice/inv_1` query, the shared fixture for the
    /// tests below.
    fn maria_writes_invoice() -> DecisionQuery {
        DecisionQuery::new(
            fgrn("fgrn:acme:principal:maria"),
            Verb::try_new("invoice-write").unwrap(),
            fgrn("fgrn:acme:resource:invoice/inv_1"),
        )
    }

    #[test]
    fn query_defaults_to_no_revision() {
        let q = maria_writes_invoice();
        assert_eq!(q.revision(), None);
    }

    #[test]
    fn at_revision_pins_query() {
        let q = maria_writes_invoice().at_revision(Revision::new(2));
        assert_eq!(q.revision(), Some(Revision::new(2)));
    }

    #[test]
    fn with_chain_accepts_matching_actor() {
        let chain = DelegationChain::try_new(vec![
            fgrn("fgrn:acme:principal:maria"),
            fgrn("fgrn:acme:principal:bob"),
        ])
        .unwrap();
        let q = maria_writes_invoice().with_chain(chain).unwrap();
        assert!(q.chain().is_some());
    }

    #[test]
    fn with_chain_rejects_mismatched_actor() {
        let chain = DelegationChain::try_new(vec![
            fgrn("fgrn:acme:principal:bob"),
            fgrn("fgrn:acme:principal:maria"),
        ])
        .unwrap();
        let err = maria_writes_invoice().with_chain(chain).unwrap_err();
        assert!(matches!(err, crate::Error::ChainActorMismatch { .. }));
    }

    fn root_scope_path() -> ScopePath {
        ScopePath::try_new(vec![fgrn("fgrn:acme:orgunit:root")]).unwrap()
    }

    #[test]
    fn record_reports_allow() {
        let record = DecisionRecord::new(RecordParts {
            decision: Decision::Allow,
            snapshot_version: SnapshotVersion::of("permit();"),
            revision: Revision::new(1),
            scope_path: root_scope_path(),
            entitlements: vec![],
            granted_ids: vec![],
        });
        assert!(record.is_allow());
        assert_eq!(record.decision(), Decision::Allow);
        assert_eq!(record.revision(), Revision::new(1));
    }

    #[test]
    fn record_reports_deny() {
        let record = DecisionRecord::new(RecordParts {
            decision: Decision::Deny,
            snapshot_version: SnapshotVersion::of("forbid();"),
            revision: Revision::new(1),
            scope_path: root_scope_path(),
            entitlements: vec![],
            granted_ids: vec![],
        });
        assert!(!record.is_allow());
    }
}
