//! Pure derivation of decision-record enrichment from the entity slice the
//! engine already read — no extra store I/O (functional core).

use std::collections::{BTreeSet, HashMap, HashSet};

use forgeguard_core::{Fgrn, Verb};

use crate::store::EntitySlice;

use super::ScopePath;

/// The principal's org-unit ancestry, root first, from the slice's spine
/// fragment. Walks parent links from the anchor upward; if the slice lacks
/// ancestry (or a link is missing), degrades to the deepest chain found —
/// worst case `[anchor]`, which always satisfies `ScopePath` invariants.
pub(crate) fn scope_path_of(slice: &EntitySlice) -> ScopePath {
    let parents: HashMap<&Fgrn, Option<&Fgrn>> = slice
        .org_units()
        .iter()
        .map(|u| (u.fgrn(), u.parent()))
        .collect();

    let mut chain = vec![slice.principal().anchor().clone()];
    let mut cursor = slice.principal().anchor();
    let mut seen: HashSet<&Fgrn> = HashSet::from([cursor]);
    while let Some(Some(parent)) = parents.get(cursor) {
        if !seen.insert(parent) {
            break; // cycle guard — malformed slice, stop rather than loop
        }
        chain.push((*parent).clone());
        cursor = parent;
    }
    chain.reverse();

    // Anchor is validated OrgUnit-kind at Principal construction and all
    // parents come from OrgUnit records, so `chain` is always non-empty and
    // all-OrgUnit — try_new cannot fail here (same idiom as
    // `ScopePath::leaf`'s own non-empty invariant).
    ScopePath::try_new(chain)
        .unwrap_or_else(|_| unreachable!("principal anchor chain is always a valid ScopePath"))
}

/// Verbs granted to the principal on the queried resource: grants whose
/// grantee is the principal, one of its principal sets, or an org unit in
/// its ancestry. Deduplicated, sorted (BTreeSet) for a stable projection.
pub(crate) fn entitlements_of(slice: &EntitySlice) -> Vec<Verb> {
    let mut grantees: HashSet<&Fgrn> = HashSet::from([slice.principal().fgrn()]);
    grantees.extend(
        slice
            .principal_sets()
            .iter()
            .map(forgeguard_core::PrincipalSet::fgrn),
    );
    grantees.extend(slice.org_units().iter().map(forgeguard_core::OrgUnit::fgrn));

    let verbs: BTreeSet<Verb> = slice
        .grants()
        .iter()
        .filter(|g| grantees.contains(g.to()))
        .flat_map(|g| g.actions().cloned())
        .collect();
    verbs.into_iter().collect()
}

/// Resource IDs directly granted to the principal — the RLS exception list
/// (#111 V4). Only grants naming the principal's OWN fgrn count (grants via
/// principal sets or org units are scope-shaped, not exceptions). The slice
/// holds grants on the queried resource only, so this is 0 or 1 ids today;
/// a cross-resource exception list would need a dedicated store query and
/// waits for a real consumer. Sorted for stable projection.
pub(crate) fn granted_ids_of(slice: &EntitySlice) -> Vec<forgeguard_core::NativeId> {
    let principal = slice.principal().fgrn();
    let mut ids: Vec<forgeguard_core::NativeId> = slice
        .grants()
        .iter()
        .filter(|g| g.to() == principal)
        .filter_map(|g| g.resource().resource_parts())
        .map(|(_, native_id)| native_id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::principal::PrincipalKind;
    use forgeguard_core::{
        Grant, NativeId, OrgUnit, Principal, PrincipalSet, Segment, Spine, Verb,
    };

    use super::*;
    use crate::store::{AuthzStore as _, MemoryStore, ModelState, SliceQuery, StoreWrite};

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
            &nid("doc-1"),
        )
    }

    /// root → eng spine, maria anchored at eng and a member of the
    /// `auditors` principal set, grant read on doc to maria, grant audit on
    /// doc to `auditors` (principal-set grant), grant write to bob (noise).
    /// `Grant::try_new` only accepts principal/principal-set grantees — an
    /// org-unit grantee is not constructible — so entitlement inclusion via
    /// ancestry is exercised at the `scope_path`/Cedar-entity level instead
    /// (see `translate.rs`), not via a direct org-unit grant here.
    async fn slice() -> EntitySlice {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let eng = Fgrn::org_unit(&org(), &nid("eng"));
        let spine = Spine::try_new(vec![
            OrgUnit::try_new(root.clone(), None).unwrap(),
            OrgUnit::try_new(eng.clone(), Some(root.clone())).unwrap(),
        ])
        .unwrap();
        let mut model = ModelState::new(spine);
        model.upsert_principal(
            Principal::try_new(maria(), PrincipalKind::Human, eng.clone()).unwrap(),
        );
        model.upsert_principal(
            Principal::try_new(
                Fgrn::principal(&org(), &nid("bob")),
                PrincipalKind::Human,
                eng.clone(),
            )
            .unwrap(),
        );
        let auditors = Fgrn::principal_set(&org(), &nid("auditors"));
        let mut auditors_set = PrincipalSet::try_new(auditors.clone(), eng).unwrap();
        auditors_set.add_member(maria()).unwrap();
        model.upsert_principal_set(auditors_set);
        let store = MemoryStore::new(model);
        for (verb, to) in [
            ("read", maria()),
            ("audit", auditors),
            ("write", Fgrn::principal(&org(), &nid("bob"))),
        ] {
            store
                .apply(StoreWrite::PutGrant(
                    Grant::try_new(doc(), vec![Verb::try_new(verb).unwrap()], to).unwrap(),
                ))
                .await
                .unwrap();
        }
        store.slice(&SliceQuery::new(maria(), doc())).await.unwrap()
    }

    #[tokio::test]
    async fn scope_path_walks_root_first() {
        assert_eq!(scope_path_of(&slice().await).to_string(), "root/eng");
    }

    #[tokio::test]
    async fn entitlements_include_direct_and_org_unit_grants_only() {
        let verbs: Vec<String> = entitlements_of(&slice().await)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(verbs, vec!["audit", "read"]); // sorted; bob's write excluded
    }

    #[tokio::test]
    async fn granted_ids_contains_only_directly_granted_resource() {
        let ids: Vec<String> = granted_ids_of(&slice().await)
            .iter()
            .map(ToString::to_string)
            .collect();
        // maria's direct grant on doc-1 counts; eng's org-unit grant and
        // bob's grant do not.
        assert_eq!(ids, vec!["doc-1"]);
    }
}
