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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{NativeId, Segment};

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
}
