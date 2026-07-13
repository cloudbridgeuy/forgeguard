//! Delegation chains (Brief v1.4): a chain of principals acting
//! on-behalf-of each other is itself a first-class principal.

use crate::{Error, Fgrn, FgrnKind, Result};

/// An ordered on-behalf-of chain (Brief v1.4): `links[0]` acts on behalf
/// of `links[1]`, and so on. "view as" is a self-delegation, so repeated
/// links are legal. Always at least two links — a one-link "chain" is
/// just the principal itself.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DelegationChain {
    links: Vec<Fgrn>,
}

impl DelegationChain {
    /// Validate and construct a `DelegationChain`.
    pub fn try_new(links: Vec<Fgrn>) -> Result<DelegationChain> {
        if links.len() < 2 {
            return Err(Error::Grant {
                fgrn: links.first().map(ToString::to_string).unwrap_or_default(),
                reason: "delegation chain must have at least two links",
            });
        }
        for link in &links {
            if link.kind() != FgrnKind::Principal {
                return Err(Error::Grant {
                    fgrn: link.to_string(),
                    reason: "delegation link must be a principal",
                });
            }
        }
        let org = links[0].organization();
        for link in &links[1..] {
            if link.organization() != org {
                return Err(Error::Grant {
                    fgrn: link.to_string(),
                    reason: "delegation links must belong to the same organization",
                });
            }
        }
        Ok(DelegationChain { links })
    }

    /// The acting principal — the head of the chain.
    pub fn actor(&self) -> &Fgrn {
        // invariant: try_new requires at least two links
        &self.links[0]
    }

    /// The ultimate on-behalf-of principal — the tail of the chain.
    pub fn subject(&self) -> &Fgrn {
        // invariant: try_new requires at least two links
        &self.links[self.links.len() - 1]
    }

    /// Iterate the chain in order, actor first.
    pub fn links(&self) -> impl Iterator<Item = &Fgrn> {
        self.links.iter()
    }

    /// Number of links in the chain.
    // a chain is never empty — try_new requires two links
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.links.len()
    }
}

use std::collections::BTreeSet;

use crate::grant::Grant;
use crate::principal_set::PrincipalSet;
use crate::verb::Verb;

/// Inputs for [`effective_verbs`]. Params struct — pub fields are the
/// documented carve-out (see .claude/context/params-struct-rule.md).
pub struct EffectiveScopeQuery<'a> {
    /// The delegation chain whose effective scope is being computed.
    pub chain: &'a DelegationChain,
    /// The resource the chain is acting on.
    pub resource: &'a Fgrn,
    /// Every grant the caller considers relevant (typically all grants
    /// on `resource` in the organization).
    pub grants: &'a [Grant],
    /// Principal-sets used to expand set-targeted grants to members.
    pub sets: &'a [PrincipalSet],
}

/// The effective verbs of a delegation chain on a resource: the
/// intersection of each link's rights (Brief v1.4 — a chain "is itself a
/// first-class principal whose effective scope is the intersection of the
/// chain's members' rights").
pub fn effective_verbs(query: &EffectiveScopeQuery<'_>) -> Result<BTreeSet<Verb>> {
    if query.resource.kind() != FgrnKind::Resource {
        return Err(Error::Grant {
            fgrn: query.resource.to_string(),
            reason: "effective scope resource must have kind resource",
        });
    }

    let mut effective: Option<BTreeSet<Verb>> = None;
    for link in query.chain.links() {
        let held = verbs_held(link, query);
        effective = Some(match effective {
            None => held,
            Some(prev) => prev.intersection(&held).cloned().collect(),
        });
        if effective.as_ref().is_some_and(BTreeSet::is_empty) {
            break; // intersection can only shrink
        }
    }
    // invariant: a chain has at least two links, so the loop ran
    Ok(effective.unwrap_or_default())
}

/// Union of verbs a single principal holds on the resource across grants
/// targeting it directly or via (transitive) principal-set membership.
fn verbs_held(link: &Fgrn, query: &EffectiveScopeQuery<'_>) -> BTreeSet<Verb> {
    query
        .grants
        .iter()
        .filter(|g| g.resource() == query.resource)
        .filter(|g| g.to() == link || set_contains(query.sets, g.to(), link))
        .flat_map(|g| g.actions().cloned())
        .collect()
}

/// Whether the set named `set_fgrn` (transitively) contains `principal`.
/// Cycle-safe via a visited list; sets absent from `sets` contribute
/// nothing (existence is the store's concern).
fn set_contains(sets: &[PrincipalSet], set_fgrn: &Fgrn, principal: &Fgrn) -> bool {
    fn walk<'a>(
        sets: &'a [PrincipalSet],
        set_fgrn: &Fgrn,
        principal: &Fgrn,
        visited: &mut Vec<&'a Fgrn>,
    ) -> bool {
        let Some(set) = sets.iter().find(|s| s.fgrn() == set_fgrn) else {
            return false;
        };
        if visited.contains(&set.fgrn()) {
            return false;
        }
        visited.push(set.fgrn());
        if set.contains(principal) {
            return true;
        }
        set.members()
            .filter(|m| m.kind() == FgrnKind::PrincipalSet)
            .any(|m| walk(sets, m, principal, visited))
    }
    walk(sets, set_fgrn, principal, &mut Vec::new())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Grant, NativeId, PrincipalSet, Segment};

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn principal(id: &str) -> Fgrn {
        Fgrn::principal(&org(), &NativeId::try_new(id).unwrap())
    }

    fn cross_org_principal(id: &str) -> Fgrn {
        Fgrn::principal(
            &Segment::try_new("globex").unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    #[test]
    fn try_new_two_link_chain() {
        let chain =
            DelegationChain::try_new(vec![principal("deploy-bot"), principal("usr_x")]).unwrap();
        assert_eq!(chain.actor(), &principal("deploy-bot"));
        assert_eq!(chain.subject(), &principal("usr_x"));
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn try_new_three_link_chain_preserves_order() {
        let chain = DelegationChain::try_new(vec![
            principal("agent"),
            principal("svc"),
            principal("usr_x"),
        ])
        .unwrap();
        let links: Vec<&Fgrn> = chain.links().collect();
        assert_eq!(
            links,
            vec![&principal("agent"), &principal("svc"), &principal("usr_x")]
        );
        assert_eq!(chain.subject(), &principal("usr_x"));
    }

    #[test]
    fn self_delegation_is_legal() {
        // "view as" is a self-delegation with a narrowed scope (Brief v1.4)
        let chain = DelegationChain::try_new(vec![principal("usr_x"), principal("usr_x")]).unwrap();
        assert_eq!(chain.actor(), chain.subject());
    }

    #[test]
    fn rejects_empty_chain() {
        let err = DelegationChain::try_new(vec![]).unwrap_err();
        assert!(err
            .to_string()
            .contains("delegation chain must have at least two links"));
    }

    #[test]
    fn rejects_single_link_chain() {
        let err = DelegationChain::try_new(vec![principal("usr_x")]).unwrap_err();
        assert!(err
            .to_string()
            .contains("delegation chain must have at least two links"));
    }

    #[test]
    fn rejects_non_principal_link() {
        let set = Fgrn::principal_set(&org(), &NativeId::try_new("readers").unwrap());
        let err = DelegationChain::try_new(vec![principal("usr_x"), set]).unwrap_err();
        assert!(err
            .to_string()
            .contains("delegation link must be a principal"));
    }

    #[test]
    fn rejects_cross_org_link() {
        let err = DelegationChain::try_new(vec![principal("usr_x"), cross_org_principal("usr_y")])
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("delegation links must belong to the same organization"));
    }

    fn doc(id: &str) -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    fn org_unit(id: &str) -> Fgrn {
        Fgrn::org_unit(&org(), &NativeId::try_new(id).unwrap())
    }

    fn set_fgrn(id: &str) -> Fgrn {
        Fgrn::principal_set(&org(), &NativeId::try_new(id).unwrap())
    }

    fn verb(s: &str) -> Verb {
        Verb::try_new(s).unwrap()
    }

    fn grant(resource: &Fgrn, verbs: &[&str], to: &Fgrn) -> Grant {
        Grant::try_new(
            resource.clone(),
            verbs.iter().map(|v| verb(v)).collect(),
            to.clone(),
        )
        .unwrap()
    }

    fn chain(ids: &[&str]) -> DelegationChain {
        DelegationChain::try_new(ids.iter().map(|id| principal(id)).collect()).unwrap()
    }

    fn names(verbs: &BTreeSet<Verb>) -> Vec<&str> {
        verbs.iter().map(Verb::as_str).collect()
    }

    #[test]
    fn effective_is_intersection_of_links() {
        let resource = doc("doc_1");
        let grants = vec![
            grant(&resource, &["read", "write"], &principal("usr_x")),
            grant(&resource, &["read", "delete"], &principal("deploy-bot")),
        ];
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[],
        };
        assert_eq!(names(&effective_verbs(&query).unwrap()), vec!["read"]);
    }

    #[test]
    fn link_with_no_rights_yields_empty_scope() {
        let resource = doc("doc_1");
        let grants = vec![grant(&resource, &["read"], &principal("usr_x"))];
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[],
        };
        assert!(effective_verbs(&query).unwrap().is_empty());
    }

    #[test]
    fn self_delegation_keeps_full_scope() {
        let resource = doc("doc_1");
        let grants = vec![grant(&resource, &["read", "write"], &principal("usr_x"))];
        let c = chain(&["usr_x", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[],
        };
        assert_eq!(
            names(&effective_verbs(&query).unwrap()),
            vec!["read", "write"]
        );
    }

    #[test]
    fn grants_on_other_resources_ignored() {
        let resource = doc("doc_1");
        let grants = vec![
            grant(&resource, &["read"], &principal("usr_x")),
            grant(&doc("doc_2"), &["write"], &principal("usr_x")),
            grant(&doc("doc_2"), &["write"], &principal("deploy-bot")),
            grant(&resource, &["read"], &principal("deploy-bot")),
        ];
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[],
        };
        assert_eq!(names(&effective_verbs(&query).unwrap()), vec!["read"]);
    }

    #[test]
    fn set_membership_expands_grants() {
        let resource = doc("doc_1");
        let mut readers = PrincipalSet::try_new(set_fgrn("readers"), org_unit("root")).unwrap();
        readers.add_member(principal("usr_x")).unwrap();
        let grants = vec![
            grant(&resource, &["read"], &set_fgrn("readers")),
            grant(&resource, &["read", "write"], &principal("deploy-bot")),
        ];
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[readers],
        };
        assert_eq!(names(&effective_verbs(&query).unwrap()), vec!["read"]);
    }

    #[test]
    fn nested_set_membership_expands_transitively() {
        let resource = doc("doc_1");
        let mut inner = PrincipalSet::try_new(set_fgrn("inner"), org_unit("root")).unwrap();
        inner.add_member(principal("usr_x")).unwrap();
        let mut outer = PrincipalSet::try_new(set_fgrn("outer"), org_unit("root")).unwrap();
        outer.add_member(set_fgrn("inner")).unwrap();
        let grants = vec![
            grant(&resource, &["read"], &set_fgrn("outer")),
            grant(&resource, &["read"], &principal("deploy-bot")),
        ];
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[inner, outer],
        };
        assert_eq!(names(&effective_verbs(&query).unwrap()), vec!["read"]);
    }

    #[test]
    fn absent_set_contributes_nothing() {
        let resource = doc("doc_1");
        let grants = vec![
            grant(&resource, &["read"], &set_fgrn("ghosts")),
            grant(&resource, &["read"], &principal("deploy-bot")),
        ];
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[],
        };
        // usr_x's only path was via the absent set — no rights, empty scope
        assert!(effective_verbs(&query).unwrap().is_empty());
    }

    #[test]
    fn cyclic_sets_do_not_hang() {
        // Build a→b→a by constructing raw sets; add_member allows set
        // members, and assert_acyclic is a separate opt-in check.
        let resource = doc("doc_1");
        let mut a = PrincipalSet::try_new(set_fgrn("a"), org_unit("root")).unwrap();
        a.add_member(set_fgrn("b")).unwrap();
        let mut b = PrincipalSet::try_new(set_fgrn("b"), org_unit("root")).unwrap();
        b.add_member(set_fgrn("a")).unwrap();
        b.add_member(principal("usr_x")).unwrap();
        let grants = vec![
            grant(&resource, &["read"], &set_fgrn("a")),
            grant(&resource, &["read"], &principal("deploy-bot")),
        ];
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &resource,
            grants: &grants,
            sets: &[a, b],
        };
        // must terminate; usr_x reachable via a→b
        assert_eq!(names(&effective_verbs(&query).unwrap()), vec!["read"]);
    }

    #[test]
    fn rejects_non_resource_target() {
        let target = org_unit("ou_1");
        let c = chain(&["deploy-bot", "usr_x"]);
        let query = EffectiveScopeQuery {
            chain: &c,
            resource: &target,
            grants: &[],
            sets: &[],
        };
        let err = effective_verbs(&query).unwrap_err();
        assert!(err
            .to_string()
            .contains("effective scope resource must have kind resource"));
    }
}
