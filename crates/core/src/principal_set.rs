//! Principal-sets (Brief v1.4): team-ownership DAG nodes that hold a
//! member set and can themselves be grant targets or nested members.

use std::collections::{BTreeSet, HashMap};

use crate::{Error, Fgrn, FgrnKind, Result};

/// A principal-set (Brief v1.4): a DAG node anchored into the
/// organizational spine, holding a set of principal/principal-set
/// members. Whether `anchor` actually exists in a spine is a
/// store-level check, same doctrine as [`crate::Principal`]. Members are
/// widened monotonically; whether a referenced member FGRN exists is
/// also a store-level check — this type only proves shape.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrincipalSet {
    fgrn: Fgrn,
    anchor: Fgrn,
    members: BTreeSet<Fgrn>,
}

impl PrincipalSet {
    /// Validate and construct an empty `PrincipalSet`.
    pub fn try_new(fgrn: Fgrn, anchor: Fgrn) -> Result<PrincipalSet> {
        if fgrn.kind() != FgrnKind::PrincipalSet {
            return Err(Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "principal set fgrn must have kind principal-set",
            });
        }
        if anchor.kind() != FgrnKind::OrgUnit {
            return Err(Error::Spine {
                fgrn: anchor.to_string(),
                reason: "principal set anchor must be an org unit",
            });
        }
        if anchor.organization() != fgrn.organization() {
            return Err(Error::Spine {
                fgrn: anchor.to_string(),
                reason: "anchor must belong to the same organization",
            });
        }

        Ok(PrincipalSet {
            fgrn,
            anchor,
            members: BTreeSet::new(),
        })
    }

    /// Borrow this set's FGRN.
    pub fn fgrn(&self) -> &Fgrn {
        &self.fgrn
    }

    /// Borrow this set's anchor org-unit FGRN.
    pub fn anchor(&self) -> &Fgrn {
        &self.anchor
    }

    /// Iterate this set's members.
    pub fn members(&self) -> impl Iterator<Item = &Fgrn> {
        self.members.iter()
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether this set has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Whether `member` is in this set.
    pub fn contains(&self, member: &Fgrn) -> bool {
        self.members.contains(member)
    }

    /// Add `member` to this set. Idempotent: re-adding an existing member
    /// is `Ok(false)` (widening is monotonic and retry-safe by
    /// construction); `Ok(true)` means newly added.
    pub fn add_member(&mut self, member: Fgrn) -> Result<bool> {
        if member.kind() != FgrnKind::Principal && member.kind() != FgrnKind::PrincipalSet {
            return Err(Error::Grant {
                fgrn: member.to_string(),
                reason: "member must be a principal or principal-set",
            });
        }
        if member == *self.fgrn() {
            return Err(Error::Grant {
                fgrn: member.to_string(),
                reason: "set cannot be a member of itself",
            });
        }
        if member.organization() != self.fgrn.organization() {
            return Err(Error::Grant {
                fgrn: member.to_string(),
                reason: "member must belong to the same organization",
            });
        }

        Ok(self.members.insert(member))
    }

    /// Remove `member` from this set. Idempotent: `true` means the
    /// member was present and is now removed.
    pub fn remove_member(&mut self, member: &Fgrn) -> bool {
        self.members.remove(member)
    }
}

/// Prove membership edges across a collection of sets form no cycle
/// (a ∈ b ∈ a). Pure; call it wherever a batch of sets is loaded — the
/// store layer's parse step. Members that are principals, or that refer
/// to sets not present in `sets`, are ignored (existence is the store's
/// job).
pub fn assert_acyclic(sets: &[PrincipalSet]) -> Result<()> {
    let by_fgrn: HashMap<&Fgrn, &PrincipalSet> = sets.iter().map(|s| (&s.fgrn, s)).collect();

    for set in sets {
        // Path-based DFS: `path` tracks only ancestors on the *current*
        // root-to-leaf chain, so shared descendants reached via distinct
        // parents (a diamond: a -> b -> d, a -> c -> d) are revisited
        // without tripping a false cycle. A cycle is a member re-appearing
        // on that same path.
        let mut path: Vec<&Fgrn> = Vec::new();
        visit(&set.fgrn, &by_fgrn, &mut path)?;
    }

    Ok(())
}

fn visit<'a>(
    fgrn: &'a Fgrn,
    by_fgrn: &HashMap<&'a Fgrn, &'a PrincipalSet>,
    path: &mut Vec<&'a Fgrn>,
) -> Result<()> {
    if path.contains(&fgrn) {
        return Err(Error::Grant {
            fgrn: fgrn.to_string(),
            reason: "principal-set membership cycle detected",
        });
    }
    let Some(current_set) = by_fgrn.get(fgrn) else {
        return Ok(());
    };

    path.push(fgrn);
    for member in current_set.members() {
        if member.kind() == FgrnKind::PrincipalSet && by_fgrn.contains_key(member) {
            visit(member, by_fgrn, path)?;
        }
    }
    path.pop();

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{NativeId, Segment};

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn other_org() -> Segment {
        Segment::try_new("globex").unwrap()
    }

    fn set(id: &str) -> Fgrn {
        Fgrn::principal_set(&org(), &NativeId::try_new(id).unwrap())
    }

    fn principal(id: &str) -> Fgrn {
        Fgrn::principal(&org(), &NativeId::try_new(id).unwrap())
    }

    fn cross_org_principal(id: &str) -> Fgrn {
        Fgrn::principal(&other_org(), &NativeId::try_new(id).unwrap())
    }

    fn org_unit(id: &str) -> Fgrn {
        Fgrn::org_unit(&org(), &NativeId::try_new(id).unwrap())
    }

    fn resource(id: &str) -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    fn anchor() -> Fgrn {
        org_unit("root")
    }

    // -- try_new ----------------------------------------------------------

    #[test]
    fn try_new_happy_path() {
        let ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
        assert_eq!(ps.fgrn(), &set("readers"));
        assert_eq!(ps.anchor(), &anchor());
    }

    #[test]
    fn try_new_rejects_principal_fgrn_as_set_fgrn() {
        let err = PrincipalSet::try_new(principal("p1"), anchor()).unwrap_err();
        assert!(err
            .to_string()
            .contains("principal set fgrn must have kind principal-set"));
    }

    #[test]
    fn try_new_rejects_principal_anchor() {
        let err = PrincipalSet::try_new(set("readers"), principal("p1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("principal set anchor must be an org unit"));
    }

    #[test]
    fn try_new_rejects_resource_anchor() {
        let err = PrincipalSet::try_new(set("readers"), resource("doc_1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("principal set anchor must be an org unit"));
    }

    #[test]
    fn try_new_rejects_cross_org_anchor() {
        let cross_org_anchor = Fgrn::org_unit(&other_org(), &NativeId::try_new("root").unwrap());
        let err = PrincipalSet::try_new(set("readers"), cross_org_anchor).unwrap_err();
        assert!(err
            .to_string()
            .contains("anchor must belong to the same organization"));
    }

    // -- add_member ---------------------------------------------------------

    #[test]
    fn add_member_accepts_principal() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        assert!(ps.add_member(principal("p1")).unwrap());
        assert!(ps.contains(&principal("p1")));
    }

    #[test]
    fn add_member_accepts_nested_set() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        assert!(ps.add_member(set("writers")).unwrap());
    }

    #[test]
    fn add_member_readd_is_idempotent() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        ps.add_member(principal("p1")).unwrap();
        assert!(!ps.add_member(principal("p1")).unwrap());
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn add_member_rejects_org_unit() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        let err = ps.add_member(org_unit("ou_1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("member must be a principal or principal-set"));
    }

    #[test]
    fn add_member_rejects_resource() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        let err = ps.add_member(resource("doc_1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("member must be a principal or principal-set"));
    }

    #[test]
    fn add_member_rejects_self() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        let err = ps.add_member(set("readers")).unwrap_err();
        assert!(err.to_string().contains("set cannot be a member of itself"));
    }

    #[test]
    fn add_member_rejects_cross_org() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        let err = ps.add_member(cross_org_principal("p1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("member must belong to the same organization"));
    }

    // -- remove_member --------------------------------------------------------

    #[test]
    fn remove_member_present_returns_true() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        ps.add_member(principal("p1")).unwrap();
        assert!(ps.remove_member(&principal("p1")));
        assert!(!ps.contains(&principal("p1")));
    }

    #[test]
    fn remove_member_absent_returns_false() {
        let mut ps = PrincipalSet::try_new(set("readers"), anchor()).unwrap();
        assert!(!ps.remove_member(&principal("p1")));
    }

    // -- assert_acyclic ---------------------------------------------------

    #[test]
    fn assert_acyclic_no_cycle() {
        let mut a = PrincipalSet::try_new(set("a"), anchor()).unwrap();
        a.add_member(set("b")).unwrap();
        let b = PrincipalSet::try_new(set("b"), anchor()).unwrap();
        assert!(assert_acyclic(&[a, b]).is_ok());
    }

    #[test]
    fn assert_acyclic_two_set_cycle_detected() {
        let mut a = PrincipalSet::try_new(set("a"), anchor()).unwrap();
        a.add_member(set("b")).unwrap();
        let mut b = PrincipalSet::try_new(set("b"), anchor()).unwrap();
        b.add_member(set("a")).unwrap();
        let err = assert_acyclic(&[a, b]).unwrap_err();
        assert!(err
            .to_string()
            .contains("principal-set membership cycle detected"));
    }

    #[test]
    fn assert_acyclic_three_set_cycle_detected() {
        let mut a = PrincipalSet::try_new(set("a"), anchor()).unwrap();
        a.add_member(set("b")).unwrap();
        let mut b = PrincipalSet::try_new(set("b"), anchor()).unwrap();
        b.add_member(set("c")).unwrap();
        let mut c = PrincipalSet::try_new(set("c"), anchor()).unwrap();
        c.add_member(set("a")).unwrap();
        let err = assert_acyclic(&[a, b, c]).unwrap_err();
        assert!(err
            .to_string()
            .contains("principal-set membership cycle detected"));
    }

    #[test]
    fn assert_acyclic_member_set_not_in_slice_is_ignored() {
        let mut a = PrincipalSet::try_new(set("a"), anchor()).unwrap();
        a.add_member(set("missing")).unwrap();
        assert!(assert_acyclic(&[a]).is_ok());
    }

    #[test]
    fn assert_acyclic_diamond_is_not_a_cycle() {
        let mut a = PrincipalSet::try_new(set("a"), anchor()).unwrap();
        a.add_member(set("b")).unwrap();
        a.add_member(set("c")).unwrap();
        let mut b = PrincipalSet::try_new(set("b"), anchor()).unwrap();
        b.add_member(set("d")).unwrap();
        let mut c = PrincipalSet::try_new(set("c"), anchor()).unwrap();
        c.add_member(set("d")).unwrap();
        let d = PrincipalSet::try_new(set("d"), anchor()).unwrap();
        assert!(assert_acyclic(&[a, b, c, d]).is_ok());
    }

    #[test]
    fn assert_acyclic_principal_members_are_ok() {
        let mut a = PrincipalSet::try_new(set("a"), anchor()).unwrap();
        a.add_member(principal("p1")).unwrap();
        assert!(assert_acyclic(&[a]).is_ok());
    }
}
