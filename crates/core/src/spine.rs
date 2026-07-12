//! The organizational spine (Brief v1.4): org units whose hierarchy
//! edges form an enforced single-rooted tree. Grant edges (lateral
//! access) are a separate concept and never live here.
//!
//! Re-parenting changes an edge, never an FGRN — identity does not
//! encode position.

use crate::{Error, Fgrn, FgrnKind, Result};

// ---------------------------------------------------------------------------
// OrgUnit
// ---------------------------------------------------------------------------

/// A single node of the spine and its parent edge.
///
/// `parent = None` means this unit claims to be the root; whether the
/// claim holds (exactly one root) is decided by [`Spine::try_new`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OrgUnit {
    fgrn: Fgrn,
    parent: Option<Fgrn>,
}

impl OrgUnit {
    /// Validate and construct an `OrgUnit`. Does not check that the
    /// parent exists elsewhere in a spine — that is `Spine::try_new`'s job.
    pub fn try_new(fgrn: Fgrn, parent: Option<Fgrn>) -> Result<OrgUnit> {
        if fgrn.kind() != FgrnKind::OrgUnit {
            return Err(Error::Spine {
                fgrn: fgrn.to_string(),
                reason: "org unit fgrn must have kind orgunit",
            });
        }

        if let Some(parent) = &parent {
            if parent.kind() != FgrnKind::OrgUnit {
                return Err(Error::Spine {
                    fgrn: parent.to_string(),
                    reason: "parent fgrn must have kind orgunit",
                });
            }
            if parent == &fgrn {
                return Err(Error::Spine {
                    fgrn: fgrn.to_string(),
                    reason: "org unit cannot be its own parent",
                });
            }
            if parent.organization() != fgrn.organization() {
                return Err(Error::Spine {
                    fgrn: parent.to_string(),
                    reason: "parent must belong to the same organization",
                });
            }
        }

        Ok(OrgUnit { fgrn, parent })
    }

    /// Borrow this unit's FGRN.
    pub fn fgrn(&self) -> &Fgrn {
        &self.fgrn
    }

    /// Borrow this unit's parent FGRN, if any.
    pub fn parent(&self) -> Option<&Fgrn> {
        self.parent.as_ref()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{NativeId, Segment};

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

    #[test]
    fn try_new_accepts_root() {
        let unit = OrgUnit::try_new(ou("acme", "root"), None).unwrap();
        assert_eq!(unit.fgrn(), &ou("acme", "root"));
        assert_eq!(unit.parent(), None);
    }

    #[test]
    fn try_new_accepts_child() {
        let unit = OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "root"))).unwrap();
        assert_eq!(unit.parent(), Some(&ou("acme", "root")));
    }

    #[test]
    fn try_new_rejects_non_orgunit_fgrn() {
        let err = OrgUnit::try_new(principal("acme", "usr_1"), None).unwrap_err();
        assert!(err
            .to_string()
            .contains("org unit fgrn must have kind orgunit"));
    }

    #[test]
    fn try_new_rejects_non_orgunit_parent() {
        let err =
            OrgUnit::try_new(ou("acme", "finance"), Some(principal("acme", "usr_1"))).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent fgrn must have kind orgunit"));
    }

    #[test]
    fn try_new_rejects_self_parent() {
        let err = OrgUnit::try_new(ou("acme", "finance"), Some(ou("acme", "finance"))).unwrap_err();
        assert!(err
            .to_string()
            .contains("org unit cannot be its own parent"));
    }

    #[test]
    fn try_new_rejects_cross_org_parent() {
        let err = OrgUnit::try_new(ou("acme", "finance"), Some(ou("globex", "root"))).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent must belong to the same organization"));
    }
}
