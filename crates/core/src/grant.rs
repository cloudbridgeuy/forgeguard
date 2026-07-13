//! Grant edges (Brief v1.4): permit-only lateral edges with verbs.

use std::collections::BTreeSet;

use crate::verb::Verb;
use crate::{Error, Fgrn, FgrnKind, Result};

/// A permit-only lateral edge (Brief v1.4): "a grant is not a link but a
/// link with an action." Immutable once constructed — changing a grant is
/// remove + add at the store layer, so every edge the decision log points
/// at is exactly what was created.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Grant {
    resource: Fgrn,
    actions: BTreeSet<Verb>,
    to: Fgrn,
}

impl Grant {
    /// Validate and construct a `Grant`.
    pub fn try_new(resource: Fgrn, actions: Vec<Verb>, to: Fgrn) -> Result<Grant> {
        if actions.is_empty() {
            return Err(Error::Grant {
                fgrn: resource.to_string(),
                reason: "grant must carry at least one action",
            });
        }
        if resource.kind() != FgrnKind::Resource {
            return Err(Error::Grant {
                fgrn: resource.to_string(),
                reason: "grant resource must have kind resource",
            });
        }
        if to.kind() != FgrnKind::Principal && to.kind() != FgrnKind::PrincipalSet {
            return Err(Error::Grant {
                fgrn: to.to_string(),
                reason: "grantee must be a principal or principal-set",
            });
        }
        if to.organization() != resource.organization() {
            return Err(Error::Grant {
                fgrn: to.to_string(),
                reason: "grantee must belong to the same organization",
            });
        }

        Ok(Grant {
            resource,
            actions: actions.into_iter().collect(),
            to,
        })
    }

    /// Borrow this grant's resource FGRN.
    pub fn resource(&self) -> &Fgrn {
        &self.resource
    }

    /// Iterate this grant's actions, sorted.
    pub fn actions(&self) -> impl Iterator<Item = &Verb> {
        self.actions.iter()
    }

    /// Whether this grant permits `verb`.
    pub fn permits(&self, verb: &Verb) -> bool {
        self.actions.contains(verb)
    }

    /// Borrow this grant's grantee FGRN.
    pub fn to(&self) -> &Fgrn {
        &self.to
    }
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

    fn doc(id: &str) -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &NativeId::try_new(id).unwrap(),
        )
    }

    fn principal(id: &str) -> Fgrn {
        Fgrn::principal(&org(), &NativeId::try_new(id).unwrap())
    }

    fn cross_org_principal(id: &str) -> Fgrn {
        Fgrn::principal(&other_org(), &NativeId::try_new(id).unwrap())
    }

    fn principal_set(id: &str) -> Fgrn {
        Fgrn::principal_set(&org(), &NativeId::try_new(id).unwrap())
    }

    fn org_unit(id: &str) -> Fgrn {
        Fgrn::org_unit(&org(), &NativeId::try_new(id).unwrap())
    }

    fn verb(s: &str) -> Verb {
        Verb::try_new(s).unwrap()
    }

    // -- happy path ---------------------------------------------------------

    #[test]
    fn try_new_grant_to_principal() {
        let grant = Grant::try_new(doc("doc_1"), vec![verb("read")], principal("p1")).unwrap();
        assert_eq!(grant.resource(), &doc("doc_1"));
        assert_eq!(grant.to(), &principal("p1"));
    }

    #[test]
    fn try_new_grant_to_principal_set() {
        let grant =
            Grant::try_new(doc("doc_1"), vec![verb("read")], principal_set("readers")).unwrap();
        assert_eq!(grant.to(), &principal_set("readers"));
    }

    #[test]
    fn try_new_multi_verb() {
        let grant = Grant::try_new(
            doc("doc_1"),
            vec![verb("read"), verb("write")],
            principal("p1"),
        )
        .unwrap();
        let actions: Vec<&str> = grant.actions().map(Verb::as_str).collect();
        assert_eq!(actions, vec!["read", "write"]);
    }

    #[test]
    fn duplicate_verbs_collapse() {
        let grant = Grant::try_new(
            doc("doc_1"),
            vec![verb("read"), verb("read")],
            principal("p1"),
        )
        .unwrap();
        let actions: Vec<&str> = grant.actions().map(Verb::as_str).collect();
        assert_eq!(actions, vec!["read"]);
    }

    #[test]
    fn permits_held_and_other_verb() {
        let grant = Grant::try_new(doc("doc_1"), vec![verb("read")], principal("p1")).unwrap();
        assert!(grant.permits(&verb("read")));
        assert!(!grant.permits(&verb("write")));
    }

    // -- rejections ---------------------------------------------------------

    #[test]
    fn try_new_rejects_empty_actions() {
        let err = Grant::try_new(doc("doc_1"), vec![], principal("p1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("grant must carry at least one action"));
    }

    #[test]
    fn try_new_rejects_org_unit_resource() {
        let err =
            Grant::try_new(org_unit("ou_1"), vec![verb("read")], principal("p1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("grant resource must have kind resource"));
    }

    #[test]
    fn try_new_rejects_principal_resource() {
        let err = Grant::try_new(principal("p1"), vec![verb("read")], principal("p2")).unwrap_err();
        assert!(err
            .to_string()
            .contains("grant resource must have kind resource"));
    }

    #[test]
    fn try_new_rejects_org_unit_grantee() {
        let err = Grant::try_new(doc("doc_1"), vec![verb("read")], org_unit("ou_1")).unwrap_err();
        assert!(err
            .to_string()
            .contains("grantee must be a principal or principal-set"));
    }

    #[test]
    fn try_new_rejects_resource_grantee() {
        let err = Grant::try_new(doc("doc_1"), vec![verb("read")], doc("doc_2")).unwrap_err();
        assert!(err
            .to_string()
            .contains("grantee must be a principal or principal-set"));
    }

    #[test]
    fn try_new_rejects_cross_org_grantee() {
        let err = Grant::try_new(doc("doc_1"), vec![verb("read")], cross_org_principal("p1"))
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("grantee must belong to the same organization"));
    }
}
