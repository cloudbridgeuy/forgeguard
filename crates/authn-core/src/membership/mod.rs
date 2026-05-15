//! Per-org user membership row — the wire-to-domain product of `CreateUser`.
//!
//! `MembershipRow` mirrors the DynamoDB row described in shaping doc A1.3:
//! `PK = USER#{sub}, SK = ORG#{org_id}` with the user's email, groups, and
//! audit metadata. DDB serialization lives in V3 (`dynamo_store::membership`);
//! this crate owns only the pure domain shape.

use chrono::{DateTime, Utc};
use forgeguard_core::{GroupName, OrganizationId, UserId};

/// Inputs for [`MembershipRow::new`].
///
/// Public params struct (per `params-struct-rule.md`): the constructor has
/// more than five arguments and the fields carry no cross-field invariant,
/// so the struct just passes them through.
#[derive(Debug, Clone)]
pub struct MembershipRowParams {
    pub sub: UserId,
    pub org_id: OrganizationId,
    pub groups: Vec<GroupName>,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub created_by: UserId,
}

/// One user's membership in one org.
///
/// All fields are private; the only constructor is [`MembershipRow::new`]
/// which assumes its inputs have already passed wire-to-domain validation in
/// the V2/V3 handler layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRow {
    sub: UserId,
    org_id: OrganizationId,
    groups: Vec<GroupName>,
    email: String,
    created_at: DateTime<Utc>,
    created_by: UserId,
}

impl MembershipRow {
    /// Build a `MembershipRow` from already-validated inputs.
    pub fn new(params: MembershipRowParams) -> Self {
        let MembershipRowParams {
            sub,
            org_id,
            groups,
            email,
            created_at,
            created_by,
        } = params;
        Self {
            sub,
            org_id,
            groups,
            email,
            created_at,
            created_by,
        }
    }

    pub fn sub(&self) -> &UserId {
        &self.sub
    }

    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn created_by(&self) -> &UserId {
        &self.created_by
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn user(id: &str) -> UserId {
        UserId::new(id).unwrap()
    }

    fn org(id: &str) -> OrganizationId {
        OrganizationId::new(id).unwrap()
    }

    fn group(name: &str) -> GroupName {
        GroupName::new(name).unwrap()
    }

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn membership_row_new_stores_all_fields() {
        let now = fixed_time();
        let row = MembershipRow::new(MembershipRowParams {
            sub: user("alice"),
            org_id: org("acme"),
            groups: vec![group("admins"), group("eng")],
            email: "alice@example.com".to_owned(),
            created_at: now,
            created_by: user("bootstrap"),
        });
        assert_eq!(row.sub(), &user("alice"));
        assert_eq!(row.org_id(), &org("acme"));
        assert_eq!(row.groups(), &[group("admins"), group("eng")]);
        assert_eq!(row.email(), "alice@example.com");
        assert_eq!(row.created_at(), now);
        assert_eq!(row.created_by(), &user("bootstrap"));
    }

    #[test]
    fn membership_row_empty_groups_accepted() {
        let row = MembershipRow::new(MembershipRowParams {
            sub: user("alice"),
            org_id: org("acme"),
            groups: vec![],
            email: "alice@example.com".to_owned(),
            created_at: fixed_time(),
            created_by: user("alice"),
        });
        assert!(row.groups().is_empty());
    }
}
