//! Selectors (Brief v1.4 §"Naming: FGRNs and selectors"): position queries.
//! `org:acme.finance/**` is not a name but a pattern, resolved through
//! hierarchy edges at evaluation time. Stable FGRNs for the machine, path
//! patterns for the humans.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::native_id::NativeId;
use crate::segment::Segment;

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
