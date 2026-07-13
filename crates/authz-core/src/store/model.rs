//! The store's model value: one immutable-per-revision snapshot of the
//! phase-1 core model. `MemoryStore` keeps one `ModelState` per revision;
//! slice selection reads it purely.

use forgeguard_core::{Fgrn, Grant, Principal, PrincipalSet, PromotedResource, Spine};

/// All model state at a single revision.
#[derive(Debug, Clone)]
pub struct ModelState {
    spine: Spine,
    principals: Vec<Principal>,
    sets: Vec<PrincipalSet>,
    grants: Vec<Grant>,
    promotions: Vec<PromotedResource>,
}

impl ModelState {
    /// A model containing only the organization spine.
    pub fn new(spine: Spine) -> Self {
        Self {
            spine,
            principals: Vec::new(),
            sets: Vec::new(),
            grants: Vec::new(),
            promotions: Vec::new(),
        }
    }

    /// The organization spine.
    pub fn spine(&self) -> &Spine {
        &self.spine
    }

    /// Mutable spine access for structural writes.
    pub fn spine_mut(&mut self) -> &mut Spine {
        &mut self.spine
    }

    /// Insert or replace a principal (matched by FGRN).
    pub fn upsert_principal(&mut self, principal: Principal) {
        self.principals.retain(|p| p.fgrn() != principal.fgrn());
        self.principals.push(principal);
    }

    /// Look up a principal by FGRN.
    pub fn principal(&self, fgrn: &Fgrn) -> Option<&Principal> {
        self.principals.iter().find(|p| p.fgrn() == fgrn)
    }

    /// Insert or replace a principal set (matched by FGRN).
    pub fn upsert_principal_set(&mut self, set: PrincipalSet) {
        self.sets.retain(|s| s.fgrn() != set.fgrn());
        self.sets.push(set);
    }

    /// All principal sets.
    pub fn principal_sets(&self) -> &[PrincipalSet] {
        &self.sets
    }

    /// Append a grant edge.
    pub fn add_grant(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// Remove all grants on `resource` held by `to`. Returns whether any
    /// grant was removed.
    pub fn remove_grant(&mut self, resource: &Fgrn, to: &Fgrn) -> bool {
        let before = self.grants.len();
        self.grants
            .retain(|g| !(g.resource() == resource && g.to() == to));
        self.grants.len() != before
    }

    /// All grant edges.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// Insert or replace a promotion record (matched by resource FGRN).
    pub fn upsert_promotion(&mut self, promotion: PromotedResource) {
        self.promotions.retain(|p| p.fgrn() != promotion.fgrn());
        self.promotions.push(promotion);
    }

    /// Look up a promotion record by resource FGRN.
    pub fn promotion(&self, fgrn: &Fgrn) -> Option<&PromotedResource> {
        self.promotions.iter().find(|p| p.fgrn() == fgrn)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use forgeguard_core::principal::PrincipalKind;
    use forgeguard_core::{
        share, AnchoredResource, NativeId, OrgUnit, Segment, ShareRequest, Verb,
    };

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    fn spine() -> Spine {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        Spine::try_new(vec![
            OrgUnit::try_new(root.clone(), None).unwrap(),
            OrgUnit::try_new(finance, Some(root)).unwrap(),
        ])
        .unwrap()
    }

    fn maria() -> Principal {
        let fgrn = Fgrn::principal(&org(), &nid("maria"));
        let anchor = Fgrn::org_unit(&org(), &nid("finance"));
        Principal::try_new(fgrn, PrincipalKind::Human, anchor).unwrap()
    }

    #[test]
    fn upsert_principal_replaces_by_fgrn() {
        let mut m = ModelState::new(spine());
        m.upsert_principal(maria());
        m.upsert_principal(maria());
        assert!(m.principal(maria().fgrn()).is_some());
        // second upsert replaced, not duplicated
        assert_eq!(
            m.principals
                .iter()
                .filter(|p| p.fgrn() == maria().fgrn())
                .count(),
            1
        );
    }

    #[test]
    fn remove_grant_is_targeted() {
        let mut m = ModelState::new(spine());
        let doc = Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_123"),
        );
        let grant = Grant::try_new(
            doc.clone(),
            vec![Verb::try_new("read").unwrap()],
            maria().fgrn().clone(),
        )
        .unwrap();
        m.add_grant(grant);
        assert_eq!(m.grants().len(), 1);
        assert!(m.remove_grant(&doc, maria().fgrn()));
        assert!(m.grants().is_empty());
        assert!(!m.remove_grant(&doc, maria().fgrn()));
    }

    #[test]
    fn upsert_principal_set_replaces_by_fgrn() {
        let mut m = ModelState::new(spine());
        let anchor = Fgrn::org_unit(&org(), &nid("finance"));
        let set_fgrn = Fgrn::principal_set(&org(), &nid("team_1"));
        m.upsert_principal_set(PrincipalSet::try_new(set_fgrn.clone(), anchor.clone()).unwrap());
        m.upsert_principal_set(PrincipalSet::try_new(set_fgrn.clone(), anchor).unwrap());
        assert_eq!(m.principal_sets().len(), 1);
    }

    #[test]
    fn upsert_promotion_replaces_by_fgrn() {
        let mut m = ModelState::new(spine());
        let anchor = Fgrn::org_unit(&org(), &nid("finance"));
        let resource =
            AnchoredResource::try_new(Segment::try_new("document").unwrap(), anchor).unwrap();
        let (promotion, _grant) = share(ShareRequest {
            resource,
            native_id: nid("doc_123"),
            to: maria().fgrn().clone(),
            actions: vec![Verb::try_new("read").unwrap()],
        })
        .unwrap();
        m.upsert_promotion(promotion.clone());
        m.upsert_promotion(promotion.clone());
        assert!(m.promotion(promotion.fgrn()).is_some());
        assert_eq!(
            m.promotions
                .iter()
                .filter(|p| p.fgrn() == promotion.fgrn())
                .count(),
            1
        );
    }
}
