//! Test builder for Identity.

use chrono::{DateTime, Utc};
use forgeguard_core::{GroupName, PrincipalKind, TenantId, UserId};

use crate::identity::{Identity, IdentityParams};

/// Builder for constructing Identity values in tests.
/// Available only with the `test-support` feature.
pub struct IdentityBuilder {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    expiry: Option<DateTime<Utc>>,
    resolver: &'static str,
    extra: Option<serde_json::Value>,
    principal_kind: PrincipalKind,
}

impl IdentityBuilder {
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            tenant_id: None,
            groups: Vec::new(),
            expiry: None,
            resolver: "test",
            extra: None,
            principal_kind: PrincipalKind::User,
        }
    }

    pub fn tenant(mut self, id: TenantId) -> Self {
        self.tenant_id = Some(id);
        self
    }

    pub fn groups(mut self, groups: Vec<GroupName>) -> Self {
        self.groups = groups;
        self
    }

    pub fn resolver(mut self, name: &'static str) -> Self {
        self.resolver = name;
        self
    }

    pub fn expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.expiry = Some(expiry);
        self
    }

    pub fn extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = Some(extra);
        self
    }

    pub fn principal_kind(mut self, kind: PrincipalKind) -> Self {
        self.principal_kind = kind;
        self
    }

    pub fn build(self) -> Identity {
        Identity::new(IdentityParams {
            user_id: self.user_id,
            tenant_id: self.tenant_id,
            groups: self.groups,
            expiry: self.expiry,
            resolver: self.resolver,
            extra: self.extra,
            principal_kind: self.principal_kind,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    #[test]
    fn build_with_all_fields_set() {
        let expiry = Utc::now();
        let extra = json!({"role": "superadmin"});

        let identity = IdentityBuilder::new(UserId::new("alice").unwrap())
            .tenant(TenantId::new("acme-corp").unwrap())
            .groups(vec![
                GroupName::new("admin").unwrap(),
                GroupName::new("backend-team").unwrap(),
            ])
            .resolver("cognito")
            .expiry(expiry)
            .extra(extra.clone())
            .principal_kind(PrincipalKind::Machine)
            .build();

        assert_eq!(identity.user_id().as_str(), "alice");
        assert_eq!(identity.tenant_id().unwrap().as_str(), "acme-corp");
        assert_eq!(identity.groups().len(), 2);
        assert_eq!(identity.groups()[0].as_str(), "admin");
        assert_eq!(identity.groups()[1].as_str(), "backend-team");
        assert_eq!(identity.resolver(), "cognito");
        assert_eq!(identity.expiry().unwrap(), &expiry);
        assert_eq!(identity.extra().unwrap(), &extra);
        assert_eq!(identity.principal_kind(), PrincipalKind::Machine);
    }

    #[test]
    fn build_with_defaults_only() {
        let identity = IdentityBuilder::new(UserId::new("bob").unwrap()).build();

        assert_eq!(identity.user_id().as_str(), "bob");
        assert!(identity.tenant_id().is_none());
        assert!(identity.groups().is_empty());
        assert_eq!(identity.resolver(), "test");
        assert!(identity.expiry().is_none());
        assert!(identity.extra().is_none());
        assert_eq!(identity.principal_kind(), PrincipalKind::User);
    }
}
