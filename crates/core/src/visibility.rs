//! Ambient subtree visibility (Brief v1.4 §"Users in the hierarchy, and the
//! boundary rule"): does a requester scoped at an org unit see a resource by
//! position alone? Explicit grants and administrative boundary-piercing are
//! separate mechanisms — callers OR this result with the grant check.

use crate::error::{Error, Result};
use crate::fgrn::{Fgrn, FgrnKind};
use crate::resource_type::UserBoundary;
use crate::spine::Spine;

/// A resource's anchor with its spine position already resolved by the
/// caller. Principal- and set-anchored resources sit at their owner's/set's
/// own anchor org unit; the boundary choice exists only for the principal
/// case, so it lives inside that variant.
#[derive(Debug, Clone, Copy)]
pub enum ResolvedAnchor<'a> {
    /// The resource anchors directly to an org unit.
    OrgUnit(&'a Fgrn),
    /// The resource anchors to its owning principal, who is anchored at
    /// `anchored_at`; `boundary` comes from the resource type's declaration.
    Principal {
        owner: &'a Fgrn,
        anchored_at: &'a Fgrn,
        boundary: UserBoundary,
    },
    /// The resource anchors to a principal-set anchored at `anchored_at`.
    /// Sets are ordinary nodes: no boundary.
    PrincipalSet { anchored_at: &'a Fgrn },
}

/// Inputs for one visibility decision. Params struct — public fields are the
/// documented carve-out (see .claude/context/params-struct-rule.md).
#[derive(Debug, Clone, Copy)]
pub struct VisibilityQuery<'a> {
    /// The requesting principal.
    pub requester: &'a Fgrn,
    /// The org unit the requester's visibility is rooted at.
    pub scope: &'a Fgrn,
    /// The resource's resolved anchor.
    pub anchor: ResolvedAnchor<'a>,
    /// The spine to resolve positions against.
    pub spine: &'a Spine,
}

/// Pure decision: is the resource ambiently visible to the requester's
/// subtree scope? Opaque user nodes stop traversal unless the requester is
/// the owner.
pub fn subtree_visible(query: &VisibilityQuery<'_>) -> Result<bool> {
    if query.requester.kind() != FgrnKind::Principal {
        return Err(Error::Spine {
            fgrn: query.requester.to_string(),
            reason: "visibility requester must be a principal",
        });
    }
    if query.scope.kind() != FgrnKind::OrgUnit {
        return Err(Error::Spine {
            fgrn: query.scope.to_string(),
            reason: "visibility scope must be an org unit",
        });
    }
    match query.anchor {
        ResolvedAnchor::OrgUnit(anchor) => {
            expect_kind(
                anchor,
                FgrnKind::OrgUnit,
                "resource anchor must be an org unit",
            )?;
            query.spine.is_at_or_below(anchor, query.scope)
        }
        ResolvedAnchor::PrincipalSet { anchored_at } => {
            expect_kind(
                anchored_at,
                FgrnKind::OrgUnit,
                "set anchor must be an org unit",
            )?;
            query.spine.is_at_or_below(anchored_at, query.scope)
        }
        ResolvedAnchor::Principal {
            owner,
            anchored_at,
            boundary,
        } => {
            expect_kind(
                owner,
                FgrnKind::Principal,
                "resource owner must be a principal",
            )?;
            expect_kind(
                anchored_at,
                FgrnKind::OrgUnit,
                "owner anchor must be an org unit",
            )?;
            if !query.spine.is_at_or_below(anchored_at, query.scope)? {
                return Ok(false);
            }
            if query.requester == owner {
                return Ok(true);
            }
            Ok(matches!(boundary, UserBoundary::Transparent))
        }
    }
}

fn expect_kind(fgrn: &Fgrn, kind: FgrnKind, reason: &'static str) -> Result<()> {
    if fgrn.kind() == kind {
        Ok(())
    } else {
        Err(Error::Spine {
            fgrn: fgrn.to_string(),
            reason,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::native_id::NativeId;
    use crate::segment::Segment;
    use crate::spine::OrgUnit;

    fn ou(org: &str, id: &str) -> Fgrn {
        Fgrn::org_unit(
            &Segment::try_new(org).unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    fn principal(org: &str, id: &str) -> Fgrn {
        Fgrn::principal(
            &Segment::try_new(org).unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    fn principal_set(org: &str, id: &str) -> Fgrn {
        Fgrn::principal_set(
            &Segment::try_new(org).unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    // fixture tree:  root ── finance ── accounting
    //                    └── engineering
    fn fixture() -> Spine {
        Spine::try_new(vec![
            OrgUnit::try_new(ou("acme", "root"), None).unwrap(),
            OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "root"))).unwrap(),
            OrgUnit::try_new(ou("acme", "accounting"), Some(ou("acme", "finance"))).unwrap(),
            OrgUnit::try_new(ou("acme", "engineering"), Some(ou("acme", "root"))).unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn org_unit_anchor_in_scope() {
        let spine = fixture();
        let requester = principal("acme", "alice");
        let scope = ou("acme", "finance");
        let anchor = ou("acme", "accounting");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::OrgUnit(&anchor),
            spine: &spine,
        };
        assert!(subtree_visible(&query).unwrap());
    }

    #[test]
    fn org_unit_anchor_out_of_scope() {
        let spine = fixture();
        let requester = principal("acme", "alice");
        let scope = ou("acme", "finance");
        let anchor = ou("acme", "engineering");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::OrgUnit(&anchor),
            spine: &spine,
        };
        assert!(!subtree_visible(&query).unwrap());
    }

    #[test]
    fn opaque_boundary_hides_owner_resources_from_ancestors() {
        let spine = fixture();
        let owner = principal("acme", "alice");
        let requester = principal("acme", "bob");
        let scope = ou("acme", "finance");
        let anchored_at = ou("acme", "accounting");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::Principal {
                owner: &owner,
                anchored_at: &anchored_at,
                boundary: UserBoundary::Opaque,
            },
            spine: &spine,
        };
        assert!(!subtree_visible(&query).unwrap());
    }

    #[test]
    fn owner_sees_through_own_boundary() {
        let spine = fixture();
        let owner = principal("acme", "alice");
        let scope = ou("acme", "finance");
        let anchored_at = ou("acme", "accounting");
        let query = VisibilityQuery {
            requester: &owner,
            scope: &scope,
            anchor: ResolvedAnchor::Principal {
                owner: &owner,
                anchored_at: &anchored_at,
                boundary: UserBoundary::Opaque,
            },
            spine: &spine,
        };
        assert!(subtree_visible(&query).unwrap());
    }

    #[test]
    fn transparent_boundary_lets_ancestor_see() {
        let spine = fixture();
        let owner = principal("acme", "alice");
        let requester = principal("acme", "bob");
        let scope = ou("acme", "finance");
        let anchored_at = ou("acme", "accounting");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::Principal {
                owner: &owner,
                anchored_at: &anchored_at,
                boundary: UserBoundary::Transparent,
            },
            spine: &spine,
        };
        assert!(subtree_visible(&query).unwrap());
    }

    #[test]
    fn boundary_is_irrelevant_when_out_of_scope() {
        let spine = fixture();
        let owner = principal("acme", "alice");
        let scope = ou("acme", "finance");
        let anchored_at = ou("acme", "engineering");
        let query = VisibilityQuery {
            requester: &owner,
            scope: &scope,
            anchor: ResolvedAnchor::Principal {
                owner: &owner,
                anchored_at: &anchored_at,
                boundary: UserBoundary::Transparent,
            },
            spine: &spine,
        };
        assert!(!subtree_visible(&query).unwrap());
    }

    #[test]
    fn set_anchor_in_scope() {
        let spine = fixture();
        let requester = principal("acme", "alice");
        let scope = ou("acme", "root");
        let set = principal_set("acme", "team_1");
        let anchored_at = ou("acme", "accounting");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::PrincipalSet {
                anchored_at: &anchored_at,
            },
            spine: &spine,
        };
        let _ = &set;
        assert!(subtree_visible(&query).unwrap());
    }

    #[test]
    fn requester_must_be_principal() {
        let spine = fixture();
        let requester = ou("acme", "finance");
        let scope = ou("acme", "finance");
        let anchor = ou("acme", "accounting");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::OrgUnit(&anchor),
            spine: &spine,
        };
        let err = subtree_visible(&query).unwrap_err();
        assert!(err
            .to_string()
            .contains("visibility requester must be a principal"));
    }

    #[test]
    fn scope_must_be_org_unit() {
        let spine = fixture();
        let requester = principal("acme", "alice");
        let scope = principal("acme", "bob");
        let anchor = ou("acme", "accounting");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::OrgUnit(&anchor),
            spine: &spine,
        };
        let err = subtree_visible(&query).unwrap_err();
        assert!(err
            .to_string()
            .contains("visibility scope must be an org unit"));
    }

    #[test]
    fn org_unit_resolved_anchor_must_be_org_unit() {
        let spine = fixture();
        let requester = principal("acme", "alice");
        let scope = ou("acme", "finance");
        let anchor = principal("acme", "bob");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::OrgUnit(&anchor),
            spine: &spine,
        };
        let err = subtree_visible(&query).unwrap_err();
        assert!(err
            .to_string()
            .contains("resource anchor must be an org unit"));
    }

    #[test]
    fn unknown_node_propagates_error() {
        let spine = fixture();
        let requester = principal("acme", "alice");
        let scope = ou("acme", "finance");
        let anchor = ou("acme", "unknown_ou");
        let query = VisibilityQuery {
            requester: &requester,
            scope: &scope,
            anchor: ResolvedAnchor::OrgUnit(&anchor),
            spine: &spine,
        };
        assert!(subtree_visible(&query).is_err());
    }
}
