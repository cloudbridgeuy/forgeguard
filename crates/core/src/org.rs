//! Organization lifecycle types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use chrono::{DateTime, Utc};

use crate::{Error, OrganizationId, Result};

/// Organization lifecycle status.
///
/// ```text
/// Draft → PendingProvisioning → Provisioning → Active → Suspended → Deleting → Deleted
///                                     ↓                      ↓
///                                   Failed                 Failed
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgStatus {
    Draft,
    PendingProvisioning,
    Provisioning,
    Active,
    Suspended,
    Deleting,
    Deleted,
    Failed,
}

impl OrgStatus {
    /// Returns `true` if transitioning from `self` to `target` is valid.
    pub fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            // Happy path
            (Self::Draft, Self::PendingProvisioning)
                | (Self::PendingProvisioning, Self::Provisioning)
                | (Self::Provisioning, Self::Active)
                | (Self::Active, Self::Suspended)
                | (Self::Suspended, Self::Active)
                | (Self::Active, Self::Deleting)
                | (Self::Suspended, Self::Deleting)
                | (Self::Deleting, Self::Deleted)
                // Failure paths
                | (Self::Provisioning, Self::Failed)
                | (Self::Deleting, Self::Failed)
                // Recovery
                | (Self::Failed, Self::Draft)
        )
    }
}

impl fmt::Display for OrgStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Draft => "draft",
            Self::PendingProvisioning => "pending_provisioning",
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
        };
        f.write_str(s)
    }
}

impl FromStr for OrgStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "draft" => Ok(Self::Draft),
            "pending_provisioning" => Ok(Self::PendingProvisioning),
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "deleting" => Ok(Self::Deleting),
            "deleted" => Ok(Self::Deleted),
            "failed" => Ok(Self::Failed),
            _ => Err(Error::Parse {
                field: "org_status",
                value: s.to_string(),
                reason: "expected one of: draft, pending_provisioning, provisioning, active, \
                         suspended, deleting, deleted, failed",
            }),
        }
    }
}

/// A ForgeGuard organization — the domain entity.
///
/// Organizations are created in `Draft` status. AWS resource fields
/// (cognito_pool_id, etc.) are `None` until provisioning completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    org_id: OrganizationId,
    name: String,
    status: OrgStatus,
    cognito_pool_id: Option<String>,
    cognito_jwks_url: Option<String>,
    policy_store_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Organization {
    /// Create a new organization in the given status.
    ///
    /// For API-created orgs, use `OrgStatus::Draft`.
    /// For file-loaded orgs, the status comes from the file.
    pub fn new(
        org_id: OrganizationId,
        name: String,
        status: OrgStatus,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            org_id,
            name,
            status,
            cognito_pool_id: None,
            cognito_jwks_url: None,
            policy_store_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn status(&self) -> OrgStatus {
        self.status
    }

    pub fn cognito_pool_id(&self) -> Option<&str> {
        self.cognito_pool_id.as_deref()
    }

    pub fn cognito_jwks_url(&self) -> Option<&str> {
        self.cognito_jwks_url.as_deref()
    }

    pub fn policy_store_id(&self) -> Option<&str> {
        self.policy_store_id.as_deref()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Transition to a new status. Returns `Err` if the transition is invalid.
    pub fn transition_to(mut self, target: OrgStatus, now: DateTime<Utc>) -> Result<Self> {
        if !self.status.can_transition_to(target) {
            return Err(Error::Parse {
                field: "org_status",
                value: format!("{} → {target}", self.status),
                reason: "invalid status transition",
            });
        }
        self.status = target;
        self.updated_at = now;
        Ok(self)
    }

    /// Update the organization name.
    pub fn update_name(mut self, name: String, now: DateTime<Utc>) -> Self {
        self.name = name;
        self.updated_at = now;
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::OrganizationId;
    use chrono::Utc;

    // ── Valid transitions (11 total) ────────────────────────────────

    #[test]
    fn transition_draft_to_pending_provisioning() {
        assert!(OrgStatus::Draft.can_transition_to(OrgStatus::PendingProvisioning));
    }

    #[test]
    fn transition_pending_provisioning_to_provisioning() {
        assert!(OrgStatus::PendingProvisioning.can_transition_to(OrgStatus::Provisioning));
    }

    #[test]
    fn transition_provisioning_to_active() {
        assert!(OrgStatus::Provisioning.can_transition_to(OrgStatus::Active));
    }

    #[test]
    fn transition_active_to_suspended() {
        assert!(OrgStatus::Active.can_transition_to(OrgStatus::Suspended));
    }

    #[test]
    fn transition_suspended_to_active() {
        assert!(OrgStatus::Suspended.can_transition_to(OrgStatus::Active));
    }

    #[test]
    fn transition_active_to_deleting() {
        assert!(OrgStatus::Active.can_transition_to(OrgStatus::Deleting));
    }

    #[test]
    fn transition_suspended_to_deleting() {
        assert!(OrgStatus::Suspended.can_transition_to(OrgStatus::Deleting));
    }

    #[test]
    fn transition_deleting_to_deleted() {
        assert!(OrgStatus::Deleting.can_transition_to(OrgStatus::Deleted));
    }

    #[test]
    fn transition_provisioning_to_failed() {
        assert!(OrgStatus::Provisioning.can_transition_to(OrgStatus::Failed));
    }

    #[test]
    fn transition_deleting_to_failed() {
        assert!(OrgStatus::Deleting.can_transition_to(OrgStatus::Failed));
    }

    #[test]
    fn transition_failed_to_draft() {
        assert!(OrgStatus::Failed.can_transition_to(OrgStatus::Draft));
    }

    // ── Invalid transitions ─────────────────────────────────────────

    #[test]
    fn invalid_draft_to_active() {
        assert!(!OrgStatus::Draft.can_transition_to(OrgStatus::Active));
    }

    #[test]
    fn invalid_deleted_to_draft() {
        assert!(!OrgStatus::Deleted.can_transition_to(OrgStatus::Draft));
    }

    #[test]
    fn invalid_deleted_to_active() {
        assert!(!OrgStatus::Deleted.can_transition_to(OrgStatus::Active));
    }

    #[test]
    fn invalid_deleted_to_deleting() {
        assert!(!OrgStatus::Deleted.can_transition_to(OrgStatus::Deleting));
    }

    #[test]
    fn invalid_active_to_draft() {
        assert!(!OrgStatus::Active.can_transition_to(OrgStatus::Draft));
    }

    #[test]
    fn invalid_self_transition_active() {
        assert!(!OrgStatus::Active.can_transition_to(OrgStatus::Active));
    }

    #[test]
    fn invalid_self_transition_draft() {
        assert!(!OrgStatus::Draft.can_transition_to(OrgStatus::Draft));
    }

    // ── Serde round-trip ────────────────────────────────────────────

    #[test]
    fn serde_round_trip_all_variants() {
        let variants = [
            OrgStatus::Draft,
            OrgStatus::PendingProvisioning,
            OrgStatus::Provisioning,
            OrgStatus::Active,
            OrgStatus::Suspended,
            OrgStatus::Deleting,
            OrgStatus::Deleted,
            OrgStatus::Failed,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: OrgStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, parsed, "round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn serde_uses_snake_case() {
        let json = serde_json::to_string(&OrgStatus::PendingProvisioning).unwrap();
        assert_eq!(json, "\"pending_provisioning\"");
    }

    // ── Display / FromStr round-trip ────────────────────────────────

    #[test]
    fn display_from_str_round_trip_all_variants() {
        let variants = [
            OrgStatus::Draft,
            OrgStatus::PendingProvisioning,
            OrgStatus::Provisioning,
            OrgStatus::Active,
            OrgStatus::Suspended,
            OrgStatus::Deleting,
            OrgStatus::Deleted,
            OrgStatus::Failed,
        ];
        for variant in variants {
            let display = variant.to_string();
            let parsed: OrgStatus = display.parse().unwrap();
            assert_eq!(variant, parsed, "round-trip failed for {variant:?}");
        }
    }

    // ── FromStr invalid input ───────────────────────────────────────

    #[test]
    fn from_str_invalid_input_returns_error() {
        let result = "not_a_status".parse::<OrgStatus>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("org_status"), "error should mention the field");
        assert!(
            msg.contains("not_a_status"),
            "error should contain the invalid value"
        );
    }

    // ── Organization tests ─────────────────────────────────────────

    #[test]
    fn new_org_has_draft_fields() {
        let now = Utc::now();
        let org = Organization::new(
            OrganizationId::new("org-test").unwrap(),
            "Test Org".to_string(),
            OrgStatus::Draft,
            now,
        );
        assert_eq!(org.name(), "Test Org");
        assert_eq!(org.status(), OrgStatus::Draft);
        assert!(org.cognito_pool_id().is_none());
        assert!(org.policy_store_id().is_none());
        assert_eq!(org.created_at(), now);
        assert_eq!(org.updated_at(), now);
    }

    #[test]
    fn transition_valid_org() {
        let now = Utc::now();
        let org = Organization::new(
            OrganizationId::new("org-test").unwrap(),
            "Test".to_string(),
            OrgStatus::Active,
            now,
        );
        let later = now + chrono::Duration::seconds(1);
        let org = org.transition_to(OrgStatus::Deleting, later).unwrap();
        assert_eq!(org.status(), OrgStatus::Deleting);
        assert_eq!(org.updated_at(), later);
        assert_eq!(org.created_at(), now); // created_at unchanged
    }

    #[test]
    fn transition_invalid_org() {
        let now = Utc::now();
        let org = Organization::new(
            OrganizationId::new("org-test").unwrap(),
            "Test".to_string(),
            OrgStatus::Draft,
            now,
        );
        let result = org.transition_to(OrgStatus::Active, now);
        assert!(result.is_err());
    }

    #[test]
    fn update_name_org() {
        let now = Utc::now();
        let org = Organization::new(
            OrganizationId::new("org-test").unwrap(),
            "Old".to_string(),
            OrgStatus::Draft,
            now,
        );
        let later = now + chrono::Duration::seconds(1);
        let org = org.update_name("New".to_string(), later);
        assert_eq!(org.name(), "New");
        assert_eq!(org.updated_at(), later);
    }

    #[test]
    fn org_serde_round_trip() {
        let now = Utc::now();
        let org = Organization::new(
            OrganizationId::new("org-test").unwrap(),
            "Test".to_string(),
            OrgStatus::Draft,
            now,
        );
        let json = serde_json::to_string(&org).unwrap();
        let back: Organization = serde_json::from_str(&json).unwrap();
        assert_eq!(back.org_id().as_str(), "org-test");
        assert_eq!(back.name(), "Test");
        assert_eq!(back.status(), OrgStatus::Draft);
    }
}
