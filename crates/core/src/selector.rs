//! Selectors (Brief v1.4 §"Naming: FGRNs and selectors"): position queries.
//! `org:acme.finance/**` is not a name but a pattern, resolved through
//! hierarchy edges at evaluation time. Stable FGRNs for the machine, path
//! patterns for the humans.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::fgrn::Fgrn;
use crate::native_id::NativeId;
use crate::segment::Segment;
use crate::spine::Spine;

/// Whether a selector addresses a single node or its whole subtree.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SelectorScope {
    /// The node the path resolves to, alone.
    Node,
    /// The node and every descendant (`/**`).
    Subtree,
}

/// A parsed position query: an organization, a path of org-unit native ids
/// descending from the root (empty path = the root itself), and a scope.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Selector {
    organization: Segment,
    path: Vec<NativeId>,
    scope: SelectorScope,
}

impl Selector {
    /// All parts are already-parsed values, so construction cannot fail.
    pub fn new(organization: Segment, path: Vec<NativeId>, scope: SelectorScope) -> Selector {
        Selector {
            organization,
            path,
            scope,
        }
    }

    /// The organization this selector queries.
    pub fn organization(&self) -> &Segment {
        &self.organization
    }

    /// Path of org-unit native ids from the root's child downward.
    /// Empty means the root itself.
    pub fn path(&self) -> &[NativeId] {
        &self.path
    }

    /// Node or subtree.
    pub fn scope(&self) -> SelectorScope {
        self.scope
    }

    /// Resolve this selector against a spine snapshot to concrete org-unit
    /// FGRNs, sorted for reproducibility. `Node` yields exactly one FGRN;
    /// `Subtree` yields the node and all descendants.
    pub fn resolve(&self, spine: &Spine) -> Result<Vec<Fgrn>> {
        if spine.organization() != &self.organization {
            return Err(Error::Spine {
                fgrn: self.to_string(),
                reason: "selector organization does not match spine",
            });
        }
        let mut current = spine.root().clone();
        for segment in &self.path {
            let mut next: Option<Fgrn> = None;
            for unit in spine.units() {
                if unit.id() == segment && spine.parent(unit)? == Some(&current) {
                    next = Some(unit.clone());
                    break;
                }
            }
            current = next.ok_or_else(|| Error::Spine {
                fgrn: self.to_string(),
                reason: "selector path does not match any org unit",
            })?;
        }
        match self.scope {
            SelectorScope::Node => Ok(vec![current]),
            SelectorScope::Subtree => {
                let mut resolved = Vec::new();
                for unit in spine.units() {
                    if spine.is_at_or_below(unit, &current)? {
                        resolved.push(unit.clone());
                    }
                }
                resolved.sort();
                Ok(resolved)
            }
        }
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "org:{}", self.organization)?;
        for segment in &self.path {
            write!(f, ".{segment}")?;
        }
        if self.scope == SelectorScope::Subtree {
            f.write_str("/**")?;
        }
        Ok(())
    }
}

impl FromStr for Selector {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let Some(body) = s.strip_prefix("org:") else {
            return Err(Error::Parse {
                field: "selector",
                value: s.to_string(),
                reason: "selector must start with org:",
            });
        };
        let (body, scope) = match body.strip_suffix("/**") {
            Some(stripped) => (stripped, SelectorScope::Subtree),
            None => (body, SelectorScope::Node),
        };
        if body.contains('/') {
            return Err(Error::Parse {
                field: "selector",
                value: s.to_string(),
                reason: "selector path may only end with /**",
            });
        }
        let mut parts = body.split('.');
        // split always yields at least one item; empty parses fail in Segment
        let organization = Segment::try_new(parts.next().unwrap_or_default())?;
        let path = parts
            .map(NativeId::try_new)
            .collect::<Result<Vec<NativeId>>>()?;
        Ok(Selector::new(organization, path, scope))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::spine::OrgUnit;

    fn ou(org: &str, id: &str) -> Fgrn {
        Fgrn::org_unit(
            &Segment::try_new(org).unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    /// root ── finance ── accounting
    ///     └── engineering
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
    fn resolves_node_selector() {
        let spine = fixture();
        let selector: Selector = "org:acme.finance".parse().unwrap();
        assert_eq!(
            selector.resolve(&spine).unwrap(),
            vec![ou("acme", "finance")]
        );
    }

    #[test]
    fn resolves_root_node_selector() {
        let spine = fixture();
        let selector: Selector = "org:acme".parse().unwrap();
        assert_eq!(selector.resolve(&spine).unwrap(), vec![ou("acme", "root")]);
    }

    #[test]
    fn resolves_subtree_selector_sorted() {
        let spine = fixture();
        let selector: Selector = "org:acme.finance/**".parse().unwrap();
        let mut expected = vec![ou("acme", "finance"), ou("acme", "accounting")];
        expected.sort();
        assert_eq!(selector.resolve(&spine).unwrap(), expected);
    }

    #[test]
    fn resolves_whole_org_subtree() {
        let spine = fixture();
        let selector: Selector = "org:acme/**".parse().unwrap();
        assert_eq!(selector.resolve(&spine).unwrap().len(), 4);
    }

    #[test]
    fn deep_path_resolves_through_levels() {
        let spine = fixture();
        let selector: Selector = "org:acme.finance.accounting".parse().unwrap();
        assert_eq!(
            selector.resolve(&spine).unwrap(),
            vec![ou("acme", "accounting")]
        );
    }

    #[test]
    fn wrong_org_is_rejected() {
        let spine = fixture();
        let selector: Selector = "org:globex.finance/**".parse().unwrap();
        let err = selector.resolve(&spine).unwrap_err();
        assert!(err
            .to_string()
            .contains("selector organization does not match spine"));
    }

    #[test]
    fn unknown_path_is_rejected() {
        let spine = fixture();
        let selector: Selector = "org:acme.marketing".parse().unwrap();
        let err = selector.resolve(&spine).unwrap_err();
        assert!(err
            .to_string()
            .contains("selector path does not match any org unit"));
    }

    #[test]
    fn path_segments_must_chain_from_root() {
        // "accounting" exists but is not a child of root
        let spine = fixture();
        let selector: Selector = "org:acme.accounting".parse().unwrap();
        assert!(selector.resolve(&spine).is_err());
    }

    #[test]
    fn parses_the_brief_example() {
        let selector: Selector = "org:acme.finance/**".parse().unwrap();
        assert_eq!(selector.organization().to_string(), "acme");
        assert_eq!(selector.path().len(), 1);
        assert_eq!(selector.path()[0].as_str(), "finance");
        assert_eq!(selector.scope(), SelectorScope::Subtree);
    }

    #[test]
    fn parses_bare_org_as_root_node() {
        let selector: Selector = "org:acme".parse().unwrap();
        assert!(selector.path().is_empty());
        assert_eq!(selector.scope(), SelectorScope::Node);
    }

    #[test]
    fn parses_deep_node_path() {
        let selector: Selector = "org:acme.finance.accounting".parse().unwrap();
        let ids: Vec<&str> = selector.path().iter().map(NativeId::as_str).collect();
        assert_eq!(ids, vec!["finance", "accounting"]);
        assert_eq!(selector.scope(), SelectorScope::Node);
    }

    #[test]
    fn display_round_trips() {
        for raw in [
            "org:acme",
            "org:acme/**",
            "org:acme.finance",
            "org:acme.finance/**",
            "org:acme.finance.accounting",
        ] {
            let selector: Selector = raw.parse().unwrap();
            assert_eq!(selector.to_string(), raw);
        }
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = "acme.finance/**".parse::<Selector>().unwrap_err();
        assert!(err.to_string().contains("selector must start with org:"));
    }

    #[test]
    fn rejects_interior_slash() {
        let err = "org:acme/finance".parse::<Selector>().unwrap_err();
        assert!(err
            .to_string()
            .contains("selector path may only end with /**"));
    }

    #[test]
    fn rejects_empty_organization() {
        assert!("org:".parse::<Selector>().is_err());
        assert!("org:/**".parse::<Selector>().is_err());
    }

    #[test]
    fn rejects_empty_path_segment() {
        assert!("org:acme..finance".parse::<Selector>().is_err());
        assert!("org:acme.".parse::<Selector>().is_err());
    }
}
