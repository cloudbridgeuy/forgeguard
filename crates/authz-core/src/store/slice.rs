//! Decision-scoped entity slice and its pure selection function.
//!
//! Selection semantics:
//! 1. Principal must exist (`Error::UnknownEntity` otherwise).
//! 2. Principal sets: direct + transitive membership (fixpoint).
//! 3. Org units: ancestry of the principal's anchor, plus ancestry of a
//!    promoted resource's anchor when that anchor is an org unit.
//! 4. Grants: every grant on the queried resource (no grantee pre-filter —
//!    the engine decides applicability).
//! 5. Promotion record if present; absence is not an error.

use forgeguard_core::{Fgrn, FgrnKind, Grant, OrgUnit, Principal, PrincipalSet, PromotedResource};

use crate::error::{Error, Result};
use crate::store::model::ModelState;
use crate::store::revision::Revision;

/// Everything one decision needs, read at one revision.
#[derive(Debug, Clone)]
pub struct EntitySlice {
    principal: Principal,
    principal_sets: Vec<PrincipalSet>,
    org_units: Vec<OrgUnit>,
    grants: Vec<Grant>,
    promotion: Option<PromotedResource>,
    revision: Revision,
}

impl EntitySlice {
    /// The querying principal.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Sets the principal belongs to, directly or transitively.
    pub fn principal_sets(&self) -> &[PrincipalSet] {
        &self.principal_sets
    }

    /// Relevant spine ancestry.
    pub fn org_units(&self) -> &[OrgUnit] {
        &self.org_units
    }

    /// All grants on the queried resource.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// The resource's promotion record, if promoted.
    pub fn promotion(&self) -> Option<&PromotedResource> {
        self.promotion.as_ref()
    }

    /// The revision this slice was read at.
    pub fn revision(&self) -> Revision {
        self.revision
    }
}

/// Select the entity slice for a `(principal, resource)` decision from one
/// model snapshot. Pure — no I/O, no clock, no store handle.
pub fn select_slice(
    model: &ModelState,
    principal: &Fgrn,
    resource: &Fgrn,
    revision: Revision,
) -> Result<EntitySlice> {
    let principal = model
        .principal(principal)
        .ok_or_else(|| Error::UnknownEntity(principal.to_string()))?
        .clone();

    // 2. Transitive set membership (fixpoint, bounded by set count).
    let selected = transitive_principal_sets(model, principal.fgrn());

    // 3. Spine ancestry: principal anchor + promoted-resource anchor.
    let mut anchors: Vec<Fgrn> = vec![principal.anchor().clone()];
    let promotion = model.promotion(resource).cloned();
    if let Some(promo) = &promotion {
        anchors.push(promo.anchor().clone());
    }
    let org_units = spine_ancestry(model, &anchors)?;

    // 4. All grants on the resource.
    let grants: Vec<Grant> = model
        .grants()
        .iter()
        .filter(|g| g.resource() == resource)
        .cloned()
        .collect();

    Ok(EntitySlice {
        principal,
        principal_sets: selected,
        org_units,
        grants,
        promotion,
        revision,
    })
}

/// Sets `member` belongs to, directly or transitively, computed as a
/// fixpoint bounded by the total number of sets in the model.
fn transitive_principal_sets(model: &ModelState, member: &Fgrn) -> Vec<PrincipalSet> {
    let all_sets = model.principal_sets();
    let mut selected: Vec<PrincipalSet> = Vec::new();
    let mut member_fgrns: Vec<Fgrn> = vec![member.clone()];
    for _ in 0..=all_sets.len() {
        let mut grew = false;
        for set in all_sets {
            if selected.iter().any(|s| s.fgrn() == set.fgrn()) {
                continue;
            }
            if member_fgrns.iter().any(|m| set.contains(m)) {
                member_fgrns.push(set.fgrn().clone());
                selected.push(set.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    selected
}

/// Spine ancestry for every org-unit-kind anchor in `anchors`, deduplicated.
/// User-anchored resources contribute no spine ancestry.
fn spine_ancestry(model: &ModelState, anchors: &[Fgrn]) -> Result<Vec<OrgUnit>> {
    let mut org_units: Vec<OrgUnit> = Vec::new();
    for anchor in anchors {
        if anchor.kind() != FgrnKind::OrgUnit {
            continue;
        }
        for node in model.spine().path(anchor)? {
            if org_units.iter().any(|u| u.fgrn() == node) {
                continue;
            }
            let parent = model.spine().parent(node)?.cloned();
            org_units.push(OrgUnit::try_new(node.clone(), parent)?);
        }
    }
    Ok(org_units)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use forgeguard_core::principal::PrincipalKind;
    use forgeguard_core::{share, AnchoredResource, NativeId, Segment, ShareRequest, Spine, Verb};

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    /// root ── finance ── finance_ap
    ///    └─── engineering
    fn model() -> ModelState {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let finance_ap = Fgrn::org_unit(&org(), &nid("finance_ap"));
        let engineering = Fgrn::org_unit(&org(), &nid("engineering"));
        let spine = Spine::try_new(vec![
            OrgUnit::try_new(root.clone(), None).unwrap(),
            OrgUnit::try_new(finance.clone(), Some(root.clone())).unwrap(),
            OrgUnit::try_new(finance_ap, Some(finance.clone())).unwrap(),
            OrgUnit::try_new(engineering, Some(root)).unwrap(),
        ])
        .unwrap();
        let mut m = ModelState::new(spine);
        m.upsert_principal(
            Principal::try_new(
                Fgrn::principal(&org(), &nid("maria")),
                PrincipalKind::Human,
                finance,
            )
            .unwrap(),
        );
        m
    }

    fn doc() -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_123"),
        )
    }

    #[test]
    fn unknown_principal_is_an_error() {
        let m = model();
        let ghost = Fgrn::principal(&org(), &nid("ghost"));
        let err = select_slice(&m, &ghost, &doc(), Revision::new(1)).unwrap_err();
        assert!(matches!(err, Error::UnknownEntity(_)));
    }

    #[test]
    fn ancestry_covers_anchor_to_root() {
        let m = model();
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let slice = select_slice(&m, &maria, &doc(), Revision::new(1)).unwrap();
        // finance + root, not engineering, not finance_ap
        assert_eq!(slice.org_units().len(), 2);
        assert_eq!(slice.revision(), Revision::new(1));
    }

    #[test]
    fn transitive_set_membership_selected() {
        let mut m = model();
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let inner = Fgrn::principal_set(&org(), &nid("inner"));
        let outer_fgrn = Fgrn::principal_set(&org(), &nid("outer"));
        let anchor = Fgrn::org_unit(&org(), &nid("root"));
        let mut inner_set = PrincipalSet::try_new(inner.clone(), anchor.clone()).unwrap();
        inner_set.add_member(maria.clone()).unwrap();
        let mut outer = PrincipalSet::try_new(outer_fgrn, anchor).unwrap();
        outer.add_member(inner).unwrap();
        m.upsert_principal_set(inner_set);
        m.upsert_principal_set(outer);
        let slice = select_slice(&m, &maria, &doc(), Revision::new(1)).unwrap();
        assert_eq!(slice.principal_sets().len(), 2);
    }

    #[test]
    fn grants_not_prefiltered_by_grantee() {
        let mut m = model();
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let other = Fgrn::principal(&org(), &nid("bob"));
        let read = Verb::try_new("read").unwrap();
        m.add_grant(Grant::try_new(doc(), vec![read.clone()], maria.clone()).unwrap());
        m.add_grant(Grant::try_new(doc(), vec![read], other).unwrap());
        let slice = select_slice(&m, &maria, &doc(), Revision::new(1)).unwrap();
        assert_eq!(slice.grants().len(), 2);
    }

    #[test]
    fn unpromoted_resource_has_no_promotion_and_no_error() {
        let m = model();
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let slice = select_slice(&m, &maria, &doc(), Revision::new(1)).unwrap();
        assert!(slice.promotion().is_none());
    }

    /// A resource promoted to an org-unit anchor contributes its own spine
    /// ancestry, deduplicated against the principal's.
    #[test]
    fn promotion_anchor_contributes_spine_ancestry() {
        let mut m = model();
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let engineering = Fgrn::org_unit(&org(), &nid("engineering"));
        let resource =
            AnchoredResource::try_new(Segment::try_new("document").unwrap(), engineering).unwrap();
        let (promotion, _grant) = share(ShareRequest {
            resource,
            native_id: nid("doc_123"),
            to: maria.clone(),
            actions: vec![Verb::try_new("read").unwrap()],
        })
        .unwrap();
        assert_eq!(promotion.fgrn(), &doc());
        m.upsert_promotion(promotion);

        let slice = select_slice(&m, &maria, &doc(), Revision::new(1)).unwrap();
        // finance + root (principal) + engineering (promotion), root deduped
        assert_eq!(slice.org_units().len(), 3);
        assert!(slice.promotion().is_some());
    }
}
