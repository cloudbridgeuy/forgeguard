//! The principal's position in the org-unit spine, root-first — the value
//! phase 4 projects into `X-Fg-Scope-Path` and `fg.scope_path`.

use std::fmt;

use forgeguard_core::{Fgrn, FgrnKind};

use crate::error::{Error, Result};

/// Ordered org-unit ancestry, root first, ending at the principal's anchor.
/// Non-empty; every element is an org-unit FGRN from the same organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePath {
    units: Vec<Fgrn>,
}

impl ScopePath {
    /// Validate and construct: non-empty, all org-unit kind, one organization.
    pub fn try_new(units: Vec<Fgrn>) -> Result<Self> {
        let Some(first) = units.first() else {
            return Err(Error::InvalidScopePath("empty path".to_string()));
        };
        let org = first.organization().clone();
        for unit in &units {
            if unit.kind() != FgrnKind::OrgUnit {
                return Err(Error::InvalidScopePath(format!(
                    "{unit} is not an org unit"
                )));
            }
            if unit.organization() != &org {
                return Err(Error::InvalidScopePath(format!(
                    "{unit} is not in organization {org}"
                )));
            }
        }
        Ok(Self { units })
    }

    /// Root-first org units.
    pub fn units(&self) -> impl Iterator<Item = &Fgrn> {
        self.units.iter()
    }

    /// The principal's anchor (deepest unit).
    pub fn leaf(&self) -> &Fgrn {
        self.units
            .last()
            .unwrap_or_else(|| unreachable!("ScopePath::try_new guarantees non-empty"))
    }
}

impl fmt::Display for ScopePath {
    /// `root/eng/platform` — org-unit ids joined by `/`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, unit) in self.units.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            write!(f, "{}", unit.id())?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{NativeId, Segment};

    use super::*;

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn ou(id: &str) -> Fgrn {
        Fgrn::org_unit(&org(), &NativeId::try_new(id).unwrap())
    }

    #[test]
    fn displays_ids_root_first() {
        let path = ScopePath::try_new(vec![ou("root"), ou("eng")]).unwrap();
        assert_eq!(path.to_string(), "root/eng");
        assert_eq!(path.leaf(), &ou("eng"));
    }

    #[test]
    fn rejects_empty() {
        assert!(ScopePath::try_new(vec![]).is_err());
    }

    #[test]
    fn rejects_non_org_unit() {
        let principal = Fgrn::principal(&org(), &NativeId::try_new("maria").unwrap());
        assert!(ScopePath::try_new(vec![principal]).is_err());
    }

    #[test]
    fn rejects_mixed_organizations() {
        let other = Fgrn::org_unit(
            &Segment::try_new("umbrella").unwrap(),
            &NativeId::try_new("root").unwrap(),
        );
        assert!(ScopePath::try_new(vec![ou("root"), other]).is_err());
    }
}
