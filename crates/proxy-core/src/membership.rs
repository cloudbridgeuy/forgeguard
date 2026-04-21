//! Membership resolution — validate org membership and enrich group context.
//!
//! Defines [`Membership`] (the result of a lookup), [`ResolveError`] (the
//! opaque error type for I/O failures), and [`MembershipResolver`] (the trait
//! the pipeline calls after identity resolution).  The trait is pure —
//! implementors supply the I/O (DynamoDB `GetItem`, etc.).

use std::future::Future;
use std::pin::Pin;

use forgeguard_core::{GroupName, OrganizationId, UserId};

/// Opaque error returned when membership resolution fails due to an I/O
/// problem (DynamoDB error, data corruption, etc.).
///
/// The pipeline maps this to an HTTP 500 response.  The full error chain is
/// logged by the implementor before constructing this type — the message
/// stored here is a brief, human-readable summary for tracing/debugging.
#[derive(Debug, thiserror::Error)]
#[error("membership resolution failed: {0}")]
pub struct ResolveError(String);

impl ResolveError {
    /// Create a new `ResolveError` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Result of a membership lookup.
///
/// Carries the list of [`GroupName`]s the user belongs to within the
/// organization.  An empty list is valid — the user is a member but has no
/// groups assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// # Return values
    ///
    /// - `Ok(Some(Membership))` — user is a member; pipeline continues with
    ///   enriched identity (tenant + groups set).
    /// - `Ok(None)` — user is not a member of this organization; pipeline
    ///   returns HTTP 403.
    /// - `Err(ResolveError)` — lookup failed (I/O error, data corruption,
    ///   etc.); pipeline returns HTTP 500.  The implementor is responsible for
    ///   logging the full error chain before returning this.
    fn resolve(
        &self,
        user_id: &UserId,
        org_id: &OrganizationId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Membership>, ResolveError>> + Send + '_>>;
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
