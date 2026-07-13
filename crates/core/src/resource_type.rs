//! Resource-type declarations (Brief v1.4 §"Users in the hierarchy, and the
//! boundary rule"): each application resource type declares where its
//! instances anchor in the spine and — only when principal-anchored —
//! whether subtree traversal sees through the owning user node.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::fgrn::FgrnKind;
use crate::segment::Segment;

/// Whether subtree traversal crosses a user node for a principal-anchored
/// resource type. Opaque is the default: a user's private resources are not
/// ambiently visible to principals scoped above them.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash)]
pub enum UserBoundary {
    /// Traversal stops at the owner. Only the owner (or an explicit grant,
    /// checked elsewhere) sees the resource.
    #[default]
    Opaque,
    /// The subtree above the owner sees through the boundary
    /// (e.g. a salesperson's deals visible to the manager's subtree).
    Transparent,
}

impl UserBoundary {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserBoundary::Opaque => "opaque",
            UserBoundary::Transparent => "transparent",
        }
    }
}

impl fmt::Display for UserBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UserBoundary {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "opaque" => Ok(UserBoundary::Opaque),
            "transparent" => Ok(UserBoundary::Transparent),
            other => Err(Error::Parse {
                field: "user_boundary",
                value: other.to_string(),
                reason: "unknown boundary — expected opaque or transparent",
            }),
        }
    }
}

/// Where instances of a resource type anchor in the spine. The user-boundary
/// choice exists only for principal-anchored types — an org-unit- or
/// set-anchored type has no owner node to be opaque about, and the type
/// system forbids declaring one.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Anchoring {
    /// Instances anchor to an org unit; visibility is plain subtree scope.
    OrgUnit,
    /// Instances anchor to their creating principal.
    Principal { user_boundary: UserBoundary },
    /// Team-owned instances anchor to a principal-set node.
    PrincipalSet,
}

impl Anchoring {
    /// The FGRN kind an anchor of this declaration must have.
    pub fn anchor_kind(&self) -> FgrnKind {
        match self {
            Anchoring::OrgUnit => FgrnKind::OrgUnit,
            Anchoring::Principal { .. } => FgrnKind::Principal,
            Anchoring::PrincipalSet => FgrnKind::PrincipalSet,
        }
    }
}

/// A resource type's declaration: its name plus its anchoring rule.
/// One declaration per type carries the boundary decision.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResourceTypeDecl {
    name: Segment,
    anchoring: Anchoring,
}

impl ResourceTypeDecl {
    /// Both parts are already-parsed values, so construction cannot fail.
    pub fn new(name: Segment, anchoring: Anchoring) -> ResourceTypeDecl {
        ResourceTypeDecl { name, anchoring }
    }

    pub fn name(&self) -> &Segment {
        &self.name
    }

    pub fn anchoring(&self) -> &Anchoring {
        &self.anchoring
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn boundary_defaults_to_opaque() {
        assert_eq!(UserBoundary::default(), UserBoundary::Opaque);
    }

    #[test]
    fn user_boundary_from_str_round_trips() {
        assert_eq!(
            "opaque".parse::<UserBoundary>().unwrap(),
            UserBoundary::Opaque
        );
        assert_eq!(
            "transparent".parse::<UserBoundary>().unwrap(),
            UserBoundary::Transparent
        );
    }

    #[test]
    fn user_boundary_from_str_rejects_unknown() {
        let err = "open".parse::<UserBoundary>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("user_boundary"));
        assert!(msg.contains("unknown boundary"));
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(
            UserBoundary::Opaque.to_string(),
            UserBoundary::Opaque.as_str()
        );
        assert_eq!(
            UserBoundary::Transparent.to_string(),
            UserBoundary::Transparent.as_str()
        );
    }

    #[test]
    fn anchor_kind_maps_variants() {
        assert_eq!(Anchoring::OrgUnit.anchor_kind(), FgrnKind::OrgUnit);
        assert_eq!(
            Anchoring::Principal {
                user_boundary: UserBoundary::Opaque
            }
            .anchor_kind(),
            FgrnKind::Principal
        );
        assert_eq!(
            Anchoring::PrincipalSet.anchor_kind(),
            FgrnKind::PrincipalSet
        );
    }

    #[test]
    fn resource_type_decl_new_and_accessors() {
        let name = Segment::try_new("document").unwrap();
        let anchoring = Anchoring::Principal {
            user_boundary: UserBoundary::Opaque,
        };
        let decl = ResourceTypeDecl::new(name.clone(), anchoring);
        assert_eq!(decl.name(), &name);
        assert_eq!(decl.anchoring(), &anchoring);
    }
}
