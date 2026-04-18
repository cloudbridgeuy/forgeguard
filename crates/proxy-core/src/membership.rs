//! Membership resolution — validate org membership and enrich group context.
//!
//! Defines [`Membership`] (the result of a lookup) and [`MembershipResolver`]
//! (the trait the pipeline calls after identity resolution).  The trait is
//! pure — implementors supply the I/O (DynamoDB `GetItem`, etc.).

use std::future::Future;
use std::pin::Pin;

use forgeguard_core::{GroupName, OrganizationId, UserId};

/// Result of a membership lookup.
///
/// Carries the list of [`GroupName`]s the user belongs to within the
/// organization.  An empty list is valid — the user is a member but has no
/// groups assigned.
#[derive(Debug, Clone)]
pub struct Membership {
    groups: Vec<GroupName>,
}

impl Membership {
    /// Create a new `Membership` with the given groups.
    #[must_use]
    pub fn new(groups: Vec<GroupName>) -> Self {
        Self { groups }
    }

    /// Return the groups the user belongs to within the organization.
    #[must_use]
    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }
}

/// Resolves org membership for a user.
///
/// Implementors perform I/O (DynamoDB `GetItem`).  The pipeline calls this
/// after identity resolution to validate the org header and enrich groups.
pub trait MembershipResolver: Send + Sync {
    /// Look up whether `user_id` is a member of `org_id`.
    ///
    /// Returns `Some(Membership)` if the user belongs to the org,
    /// `None` if not a member.
    fn resolve(
        &self,
        user_id: &UserId,
        org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Option<Membership>> + Send + '_>>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_with_empty_groups_returns_empty_slice() {
        let membership = Membership::new(vec![]);
        assert!(membership.groups().is_empty());
    }

    #[test]
    fn new_with_groups_returns_groups() {
        let group = GroupName::new("admin").unwrap();
        let membership = Membership::new(vec![group.clone()]);
        assert_eq!(membership.groups(), &[group]);
    }
}
