//! The store trait per the brief's consistency section (phase-2 scope):
//! snapshot-at-revision reads and revision-returning writes. The change
//! stream is deliberately absent — it arrives with the event log (#110).
//!
//! Async via boxed futures (same style as [`crate::PolicyEngine`]) so I/O
//! implementations (DynamoDB, phase 3) can implement it; the in-memory
//! reference implementation returns ready futures.

use std::future::Future;
use std::pin::Pin;

use forgeguard_core::{Fgrn, Grant, OrgUnit, Principal, PrincipalSet, PromotedResource};

use crate::error::Result;
use crate::store::revision::Revision;
use crate::store::slice::EntitySlice;

/// A decision-scoped read request.
#[derive(Debug, Clone)]
pub struct SliceQuery {
    principal: Fgrn,
    resource: Fgrn,
    revision: Option<Revision>,
}

impl SliceQuery {
    /// Query the latest revision for a `(principal, resource)` decision.
    pub fn new(principal: Fgrn, resource: Fgrn) -> Self {
        Self {
            principal,
            resource,
            revision: None,
        }
    }

    /// Pin the read to a specific revision.
    pub fn at_revision(mut self, revision: Revision) -> Self {
        self.revision = Some(revision);
        self
    }

    /// The querying principal.
    pub fn principal(&self) -> &Fgrn {
        &self.principal
    }

    /// The queried resource.
    pub fn resource(&self) -> &Fgrn {
        &self.resource
    }

    /// Requested revision; `None` means latest.
    pub fn revision(&self) -> Option<Revision> {
        self.revision
    }
}

/// A single model mutation. Every variant returns the new [`Revision`]
/// when applied.
#[derive(Debug, Clone)]
pub enum StoreWrite {
    /// Add an org unit to the spine.
    PutOrgUnit(OrgUnit),
    /// Insert or replace a principal.
    PutPrincipal(Principal),
    /// Insert or replace a principal set.
    PutPrincipalSet(PrincipalSet),
    /// Add a grant edge.
    PutGrant(Grant),
    /// Remove all grants on `resource` held by `to`.
    RemoveGrant {
        /// The granted resource.
        resource: Fgrn,
        /// The grantee.
        to: Fgrn,
    },
    /// Insert or replace a promotion record.
    PutPromotion(PromotedResource),
}

/// Snapshot-at-revision reads and revision-returning writes over the
/// phase-1 core model.
pub trait AuthzStore: Send + Sync {
    /// Read the entity slice for a decision at `query.revision()` (or the
    /// latest revision when `None`). One call, one revision — never mixed.
    fn slice(
        &self,
        query: &SliceQuery,
    ) -> Pin<Box<dyn Future<Output = Result<EntitySlice>> + Send + '_>>;

    /// Apply one mutation; returns the revision it produced.
    fn apply(
        &self,
        write: StoreWrite,
    ) -> Pin<Box<dyn Future<Output = Result<Revision>> + Send + '_>>;

    /// The store's current revision (0 = empty).
    fn latest_revision(&self) -> Pin<Box<dyn Future<Output = Result<Revision>> + Send + '_>>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use forgeguard_core::{NativeId, Segment};

    fn fgrn(kind: &str) -> Fgrn {
        let org = Segment::try_new("acme").unwrap();
        let id = NativeId::try_new("x").unwrap();
        match kind {
            "principal" => Fgrn::principal(&org, &id),
            _ => Fgrn::resource(&org, &Segment::try_new("document").unwrap(), &id),
        }
    }

    #[test]
    fn new_defaults_to_latest_revision() {
        let query = SliceQuery::new(fgrn("principal"), fgrn("resource"));
        assert_eq!(query.revision(), None);
    }

    #[test]
    fn at_revision_pins_the_read() {
        let query =
            SliceQuery::new(fgrn("principal"), fgrn("resource")).at_revision(Revision::new(3));
        assert_eq!(query.revision(), Some(Revision::new(3)));
    }

    #[test]
    fn accessors_return_constructor_inputs() {
        let principal = fgrn("principal");
        let resource = fgrn("resource");
        let query = SliceQuery::new(principal.clone(), resource.clone());
        assert_eq!(query.principal(), &principal);
        assert_eq!(query.resource(), &resource);
    }
}
