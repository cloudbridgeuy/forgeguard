//! Principals (Brief v1.4): the three native kinds that anchor into the
//! organizational spine. NOT the VP-era `action::PrincipalKind` (User /
//! Machine) — see [`PrincipalKind`]'s own doc for the disambiguation rule.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Fgrn, FgrnKind, Result};

// ---------------------------------------------------------------------------
// PrincipalKind
// ---------------------------------------------------------------------------

/// The three native principal kinds (Brief v1.4). NOT re-exported at the
/// crate root: `action::PrincipalKind` (VP-era User/Machine) still owns
/// that name there until Phase 2 deletes it. Path-qualify:
/// `forgeguard_core::principal::PrincipalKind`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum PrincipalKind {
    Human,
    Service,
    Agent,
}

impl PrincipalKind {
    /// Borrow the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Service => "service",
            Self::Agent => "agent",
        }
    }
}

impl fmt::Display for PrincipalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PrincipalKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "human" => Ok(Self::Human),
            "service" => Ok(Self::Service),
            "agent" => Ok(Self::Agent),
            _ => Err(Error::Parse {
                field: "principal_kind",
                value: s.to_string(),
                reason: "unknown kind — expected human, service, or agent",
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Principal
// ---------------------------------------------------------------------------

/// A principal (Brief v1.4): identity anchored into the organizational
/// spine. Whether `anchor` actually exists in a spine is a store-level
/// check — `Spine::contains(principal.anchor())` at the imperative shell.
/// `Principal` itself only proves shape: kind, and that fgrn/anchor share
/// an organization.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Principal {
    fgrn: Fgrn,
    kind: PrincipalKind,
    anchor: Fgrn,
}

impl Principal {
    /// Validate and construct a `Principal`.
    pub fn try_new(fgrn: Fgrn, kind: PrincipalKind, anchor: Fgrn) -> Result<Principal> {
        if fgrn.kind() != FgrnKind::Principal {
            return Err(Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "principal fgrn must have kind principal",
            });
        }
        if anchor.kind() != FgrnKind::OrgUnit {
            return Err(Error::Spine {
                fgrn: anchor.to_string(),
                reason: "principal anchor must be an org unit",
            });
        }
        if anchor.organization() != fgrn.organization() {
            return Err(Error::Spine {
                fgrn: anchor.to_string(),
                reason: "anchor must belong to the same organization",
            });
        }

        Ok(Principal { fgrn, kind, anchor })
    }

    /// Borrow this principal's FGRN.
    pub fn fgrn(&self) -> &Fgrn {
        &self.fgrn
    }

    /// This principal's kind.
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Borrow this principal's anchor org-unit FGRN.
    pub fn anchor(&self) -> &Fgrn {
        &self.anchor
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{NativeId, Segment};

    fn seg(s: &str) -> Segment {
        Segment::try_new(s).unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    fn principal_fgrn(org: &str, id: &str) -> Fgrn {
        Fgrn::principal(&seg(org), &nid(id))
    }

    fn ou(org: &str, id: &str) -> Fgrn {
        Fgrn::org_unit(&seg(org), &nid(id))
    }

    fn resource(org: &str, rtype: &str, id: &str) -> Fgrn {
        Fgrn::resource(&seg(org), &seg(rtype), &nid(id))
    }

    // -- PrincipalKind ---------------------------------------------------

    #[test]
    fn principal_kind_round_trips() {
        for kind in [
            PrincipalKind::Human,
            PrincipalKind::Service,
            PrincipalKind::Agent,
        ] {
            let s = kind.as_str();
            let parsed: PrincipalKind = s.parse().unwrap();
            assert_eq!(parsed, kind);
            assert_eq!(kind.to_string(), s);
        }
    }

    #[test]
    fn principal_kind_unknown_string_errors() {
        assert!("robot".parse::<PrincipalKind>().is_err());
    }

    // -- Principal::try_new -----------------------------------------------

    #[test]
    fn try_new_accepts_each_kind() {
        for kind in [
            PrincipalKind::Human,
            PrincipalKind::Service,
            PrincipalKind::Agent,
        ] {
            let principal =
                Principal::try_new(principal_fgrn("acme", "p1"), kind, ou("acme", "root")).unwrap();
            assert_eq!(principal.kind(), kind);
            assert_eq!(principal.anchor(), &ou("acme", "root"));
        }
    }

    #[test]
    fn try_new_rejects_orgunit_as_principal_fgrn() {
        let err = Principal::try_new(ou("acme", "root"), PrincipalKind::Human, ou("acme", "root"))
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("principal fgrn must have kind principal"));
    }

    #[test]
    fn try_new_rejects_principal_kind_anchor() {
        let err = Principal::try_new(
            principal_fgrn("acme", "p1"),
            PrincipalKind::Human,
            principal_fgrn("acme", "p2"),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("principal anchor must be an org unit"));
    }

    #[test]
    fn try_new_rejects_resource_kind_anchor() {
        let err = Principal::try_new(
            principal_fgrn("acme", "p1"),
            PrincipalKind::Human,
            resource("acme", "document", "doc_1"),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("principal anchor must be an org unit"));
    }

    #[test]
    fn try_new_rejects_cross_org_anchor() {
        let err = Principal::try_new(
            principal_fgrn("acme", "p1"),
            PrincipalKind::Human,
            ou("globex", "root"),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("anchor must belong to the same organization"));
    }
}
