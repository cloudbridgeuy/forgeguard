//! Pure translation from the store's `EntitySlice` to Cedar entities, plus
//! per-decision grant-policy synthesis (grants are live data evaluated
//! against the snapshot — the brief's two-tier split).
//!
//! Entity mapping contract (fixtures in Task 7 depend on it exactly):
//!
//! | Model | Cedar entity type | UID | Parents |
//! | --- | --- | --- | --- |
//! | `Principal` (kind `Human`) | `User` | full FGRN string | its transitive `PrincipalSet`s + its anchor org unit |
//! | `Principal` (kind `Service`/`Agent`) | `Machine` | full FGRN string | same |
//! | `PrincipalSet` | `PSet` | full FGRN string | none |
//! | `OrgUnit` | `OrgUnit` | full FGRN string | its spine parent (if in slice) |
//! | queried resource | `Resource` | full FGRN string | its promotion anchor (org unit or user), when promoted |
//!
//! UID strings are the full FGRN (e.g. `fgrn:acme:principal:maria`) — stable
//! identity, no positional encoding.
//!
//! `principal::PrincipalKind` (`Human`/`Service`/`Agent`, what `Principal::kind()`
//! returns) collapses to Cedar's two entity types: `Human` → `User`,
//! `Service`/`Agent` → `Machine`. No V2 conformance case distinguishes
//! `Service` from `Agent`, so this is a deliberate simplification, not an
//! oversight — see [`cedar_principal_type`].

use std::collections::HashSet;
use std::str::FromStr;

use cedar_policy::{Entities, Entity, EntityId, EntityTypeName, EntityUid};
use forgeguard_core::{principal::PrincipalKind, Fgrn, FgrnKind};

use crate::error::{Error, Result};
use crate::rbac::validate_cedar_ident;
use crate::store::EntitySlice;

/// Collapse the three native principal kinds to Cedar's two entity types:
/// `Human` → `User`, `Service`/`Agent` → `Machine`.
pub(crate) fn cedar_principal_type(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "User",
        PrincipalKind::Service | PrincipalKind::Agent => "Machine",
    }
}

pub(crate) fn uid(entity_type: &str, fgrn: &Fgrn) -> Result<EntityUid> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| Error::EvaluationFailed(format!("bad entity type {entity_type}: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(fgrn.to_string()),
    ))
}

fn entity(uid: EntityUid, parents: HashSet<EntityUid>) -> Entity {
    Entity::new_no_attrs(uid, parents)
}

/// Cedar entity type of a promotion anchor.
fn promotion_anchor_type(kind: FgrnKind) -> &'static str {
    match kind {
        FgrnKind::OrgUnit => "OrgUnit",
        FgrnKind::Principal => "User",
        _ => "Resource",
    }
}

/// Cedar principal clause for a grant target.
///
/// A `Principal`-kind grantee's Cedar entity type depends on its
/// `PrincipalKind` (`Human` → `User`, `Service`/`Agent` → `Machine`, via
/// [`cedar_principal_type`]) — but that kind isn't known from the FGRN
/// alone, and reading it here would violate `decide`'s single-read
/// invariant. When the grantee *is* the slice's own principal (the common
/// case: the querying principal is the grantee), its kind is already in the
/// slice for free — use it. Otherwise fall back to `User`, which is exactly
/// the pre-existing gap this can't structurally close without a second read
/// (tracked alongside `promotion_anchor_type`'s owner-kind limitation).
fn grant_principal_clause(to: &Fgrn, slice: &EntitySlice) -> String {
    match to.kind() {
        FgrnKind::PrincipalSet => format!(r#"principal in PSet::"{to}""#),
        FgrnKind::OrgUnit => format!(r#"principal in OrgUnit::"{to}""#),
        _ => {
            let entity_type = if slice.principal().fgrn() == to {
                cedar_principal_type(slice.principal().kind())
            } else {
                "User"
            };
            format!(r#"principal == {entity_type}::"{to}""#)
        }
    }
}

/// Validated `Action::"<verb>"` clause for a grant action.
fn action_clause(verb: &forgeguard_core::Verb) -> Result<String> {
    let verb = verb.to_string();
    validate_cedar_ident(&verb, "grant action").map_err(Error::InvalidPolicy)?;
    Ok(format!(r#"Action::"{verb}""#))
}

/// Build the Cedar entity set for one decision.
pub(crate) fn slice_to_entities(slice: &EntitySlice, resource: &Fgrn) -> Result<Entities> {
    let mut entities: Vec<Entity> = Vec::new();

    // Org units, parented on their spine parent when it is in the slice.
    for unit in slice.org_units() {
        let mut parents = HashSet::new();
        if let Some(parent) = unit.parent() {
            if slice.org_units().iter().any(|u| u.fgrn() == parent) {
                parents.insert(uid("OrgUnit", parent)?);
            }
        }
        entities.push(entity(uid("OrgUnit", unit.fgrn())?, parents));
    }

    // Principal sets (flat).
    for set in slice.principal_sets() {
        entities.push(entity(uid("PSet", set.fgrn())?, HashSet::new()));
    }

    // The principal: parents = its sets + its anchor org unit.
    let p = slice.principal();
    let mut p_parents = HashSet::new();
    for set in slice.principal_sets() {
        if set.contains(p.fgrn()) {
            p_parents.insert(uid("PSet", set.fgrn())?);
        }
    }
    if p.anchor().kind() == FgrnKind::OrgUnit {
        p_parents.insert(uid("OrgUnit", p.anchor())?);
    }
    entities.push(entity(
        uid(cedar_principal_type(p.kind()), p.fgrn())?,
        p_parents,
    ));

    // The resource: parent = promotion anchor when promoted.
    let mut r_parents = HashSet::new();
    if let Some(promo) = slice.promotion() {
        let anchor = promo.anchor();
        r_parents.insert(uid(promotion_anchor_type(anchor.kind()), anchor)?);
    }
    entities.push(entity(uid("Resource", resource)?, r_parents));

    Entities::from_entities(entities, None)
        .map_err(|e| Error::EvaluationFailed(format!("entity slice invalid: {e}")))
}

/// Synthesize one Cedar permit per grant in the slice (grants are live data,
/// evaluated against the snapshot at decision time).
pub(crate) fn grant_policies(slice: &EntitySlice) -> Result<String> {
    let mut statements = Vec::with_capacity(slice.grants().len());
    for grant in slice.grants() {
        let to = grant.to();
        validate_cedar_ident(&to.to_string(), "grant target").map_err(Error::InvalidPolicy)?;
        let principal_clause = grant_principal_clause(to, slice);

        let resource = grant.resource();
        validate_cedar_ident(&resource.to_string(), "grant resource")
            .map_err(Error::InvalidPolicy)?;

        let actions: Vec<String> = grant
            .actions()
            .map(action_clause)
            .collect::<Result<Vec<_>>>()?;

        statements.push(format!(
            "permit(\n  {principal_clause},\n  action in [{}],\n  resource == Resource::\"{resource}\"\n);",
            actions.join(", ")
        ));
    }
    Ok(statements.join("\n\n"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::str::FromStr as _;

    use cedar_policy::PolicySet;
    use forgeguard_core::principal::PrincipalKind;
    use forgeguard_core::{
        share, AnchoredResource, NativeId, OrgUnit, Principal, Segment, ShareRequest, Spine, Verb,
    };

    use super::*;
    use crate::store::{select_slice, ModelState, Revision};

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    /// root ── finance ── finance_ap
    fn spine() -> Spine {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let finance_ap = Fgrn::org_unit(&org(), &nid("finance_ap"));
        Spine::try_new(vec![
            OrgUnit::try_new(root.clone(), None).unwrap(),
            OrgUnit::try_new(finance.clone(), Some(root)).unwrap(),
            OrgUnit::try_new(finance_ap, Some(finance)).unwrap(),
        ])
        .unwrap()
    }

    fn doc() -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_1"),
        )
    }

    #[test]
    fn principal_entity_has_anchor_and_set_as_parents() {
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let mut m = ModelState::new(spine());
        m.upsert_principal(
            Principal::try_new(maria.clone(), PrincipalKind::Human, finance.clone()).unwrap(),
        );

        let slice = select_slice(&m, &maria, &doc(), Revision::new(1)).unwrap();
        let entities = slice_to_entities(&slice, &doc()).unwrap();

        let maria_euid = uid("User", &maria).unwrap();
        let finance_euid = uid("OrgUnit", &finance).unwrap();
        assert!(entities.is_ancestor_of(&finance_euid, &maria_euid));
    }

    #[test]
    fn org_unit_chain_parents_link_finance_to_root() {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let mut m = ModelState::new(spine());
        m.upsert_principal(
            Principal::try_new(maria.clone(), PrincipalKind::Human, finance.clone()).unwrap(),
        );

        let slice = select_slice(&m, &maria, &doc(), Revision::new(1)).unwrap();
        let entities = slice_to_entities(&slice, &doc()).unwrap();

        let finance_euid = uid("OrgUnit", &finance).unwrap();
        let root_euid = uid("OrgUnit", &root).unwrap();
        assert!(entities.is_ancestor_of(&root_euid, &finance_euid));
    }

    #[test]
    fn promoted_resource_is_parented_on_its_anchor() {
        let finance_ap = Fgrn::org_unit(&org(), &nid("finance_ap"));
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let mut m = ModelState::new(spine());
        m.upsert_principal(
            Principal::try_new(maria.clone(), PrincipalKind::Human, finance).unwrap(),
        );

        let (promotion, grant) = share(ShareRequest {
            resource: AnchoredResource::try_new(
                Segment::try_new("invoice").unwrap(),
                finance_ap.clone(),
            )
            .unwrap(),
            native_id: nid("inv_1"),
            to: maria.clone(),
            actions: vec![Verb::try_new("invoice-write").unwrap()],
        })
        .unwrap();
        m.upsert_promotion(promotion.clone());
        m.add_grant(grant);

        let slice = select_slice(&m, &maria, promotion.fgrn(), Revision::new(1)).unwrap();
        let entities = slice_to_entities(&slice, promotion.fgrn()).unwrap();

        let resource_euid = uid("Resource", promotion.fgrn()).unwrap();
        let finance_ap_euid = uid("OrgUnit", &finance_ap).unwrap();
        assert!(entities.is_ancestor_of(&finance_ap_euid, &resource_euid));
    }

    #[test]
    fn grant_policies_emit_set_and_principal_grantees_and_parse() {
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let mut m = ModelState::new(spine());
        m.upsert_principal(
            Principal::try_new(maria.clone(), PrincipalKind::Human, finance).unwrap(),
        );

        let (promotion, grant) = share(ShareRequest {
            resource: AnchoredResource::try_new(
                Segment::try_new("invoice").unwrap(),
                Fgrn::org_unit(&org(), &nid("finance_ap")),
            )
            .unwrap(),
            native_id: nid("inv_1"),
            to: maria.clone(),
            actions: vec![Verb::try_new("invoice-write").unwrap()],
        })
        .unwrap();
        m.upsert_promotion(promotion.clone());
        m.add_grant(grant);

        let slice = select_slice(&m, &maria, promotion.fgrn(), Revision::new(1)).unwrap();
        let text = grant_policies(&slice).unwrap();

        assert!(text.contains(&format!(r#"principal == User::"{maria}""#)));
        assert!(text.contains(r#"Action::"invoice-write""#));
        PolicySet::from_str(&text).unwrap();
    }

    #[test]
    fn grant_policies_rejects_backslash_in_resource_native_id() {
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let maria = Fgrn::principal(&org(), &nid("maria"));
        let mut m = ModelState::new(spine());
        m.upsert_principal(
            Principal::try_new(maria.clone(), PrincipalKind::Human, finance).unwrap(),
        );

        let (promotion, grant) = share(ShareRequest {
            resource: AnchoredResource::try_new(
                Segment::try_new("invoice").unwrap(),
                Fgrn::org_unit(&org(), &nid("finance_ap")),
            )
            .unwrap(),
            native_id: nid(r#"inv\"#),
            to: maria.clone(),
            actions: vec![Verb::try_new("invoice-write").unwrap()],
        })
        .unwrap();
        m.upsert_promotion(promotion.clone());
        m.add_grant(grant);

        let slice = select_slice(&m, &maria, promotion.fgrn(), Revision::new(1)).unwrap();
        assert!(grant_policies(&slice).is_err());
    }

    #[test]
    fn grant_policies_emits_machine_clause_for_agent_grantee() {
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let bot = Fgrn::principal(&org(), &nid("bot"));
        let mut m = ModelState::new(spine());
        m.upsert_principal(Principal::try_new(bot.clone(), PrincipalKind::Agent, finance).unwrap());

        let (promotion, grant) = share(ShareRequest {
            resource: AnchoredResource::try_new(
                Segment::try_new("invoice").unwrap(),
                Fgrn::org_unit(&org(), &nid("finance_ap")),
            )
            .unwrap(),
            native_id: nid("inv_1"),
            to: bot.clone(),
            actions: vec![Verb::try_new("invoice-write").unwrap()],
        })
        .unwrap();
        m.upsert_promotion(promotion.clone());
        m.add_grant(grant);

        let slice = select_slice(&m, &bot, promotion.fgrn(), Revision::new(1)).unwrap();
        let text = grant_policies(&slice).unwrap();

        assert!(text.contains(&format!(r#"principal == Machine::"{bot}""#)));
        PolicySet::from_str(&text).unwrap();
    }
}
