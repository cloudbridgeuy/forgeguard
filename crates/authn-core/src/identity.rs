//! Resolved, trusted identity type.

use chrono::{DateTime, Utc};
use serde::Serialize;

use forgeguard_core::{GroupName, PrincipalKind, TenantId, UserId};

/// A resolved, trusted identity. Produced only by IdentityResolver implementations.
/// Protocol adapters and the authz layer consume this without knowing how it was produced.
///
/// This is ForgeGuard's equivalent of `aws_credential_types::Credentials`.
#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    expiry: Option<DateTime<Utc>>,
    /// Which resolver produced this — for logging/metrics, never for branching.
    resolver: &'static str,
    /// Resolver-specific claims preserved for custom policy evaluation.
    extra: Option<serde_json::Value>,
    /// Whether this identity represents a human user or a machine/service.
    principal_kind: PrincipalKind,
}

/// Parameters for constructing an [`Identity`].
pub struct IdentityParams {
    pub user_id: UserId,
    pub tenant_id: Option<TenantId>,
    pub groups: Vec<GroupName>,
    pub expiry: Option<DateTime<Utc>>,
    pub resolver: &'static str,
    pub extra: Option<serde_json::Value>,
    pub principal_kind: PrincipalKind,
}

impl Identity {
    /// Construct a new Identity. Invariants are enforced by the field types
    /// on [`IdentityParams`] (Parse Don't Validate).
    pub fn new(params: IdentityParams) -> Self {
        Self {
            user_id: params.user_id,
            tenant_id: params.tenant_id,
            groups: params.groups,
            expiry: params.expiry,
            resolver: params.resolver,
            extra: params.extra,
            principal_kind: params.principal_kind,
        }
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }

    pub fn expiry(&self) -> Option<&DateTime<Utc>> {
        self.expiry.as_ref()
    }

    pub fn resolver(&self) -> &'static str {
        self.resolver
    }

    pub fn extra(&self) -> Option<&serde_json::Value> {
        self.extra.as_ref()
    }

    pub fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }

    /// Whether this identity has expired relative to `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expiry.is_some_and(|exp| exp < now)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    /// Helper: build a minimal identity for tests.
    fn make_identity(expiry: Option<DateTime<Utc>>, extra: Option<serde_json::Value>) -> Identity {
        Identity::new(IdentityParams {
            user_id: UserId::new("alice").unwrap(),
            tenant_id: Some(TenantId::new("acme-corp").unwrap()),
            groups: vec![
                GroupName::new("admin").unwrap(),
                GroupName::new("backend-team").unwrap(),
            ],
            expiry,
            resolver: "test-resolver",
            extra,
            principal_kind: PrincipalKind::User,
        })
    }

    // -- Getter tests ---------------------------------------------------------

    #[test]
    fn user_id_returns_correct_value() {
        let id = make_identity(None, None);
        assert_eq!(id.user_id().as_str(), "alice");
    }

    #[test]
    fn tenant_id_returns_some_when_set() {
        let id = make_identity(None, None);
        assert_eq!(id.tenant_id().unwrap().as_str(), "acme-corp");
    }

    #[test]
    fn tenant_id_returns_none_when_absent() {
        let id = Identity::new(IdentityParams {
            user_id: UserId::new("bob").unwrap(),
            tenant_id: None,
            groups: vec![],
            expiry: None,
            resolver: "test-resolver",
            extra: None,
            principal_kind: PrincipalKind::User,
        });
        assert!(id.tenant_id().is_none());
    }

    #[test]
    fn groups_returns_correct_values() {
        let id = make_identity(None, None);
        let names: Vec<&str> = id
            .groups()
            .iter()
            .map(forgeguard_core::GroupName::as_str)
            .collect();
        assert_eq!(names, vec!["admin", "backend-team"]);
    }

    #[test]
    fn groups_returns_empty_when_none() {
        let id = Identity::new(IdentityParams {
            user_id: UserId::new("bob").unwrap(),
            tenant_id: None,
            groups: vec![],
            expiry: None,
            resolver: "test-resolver",
            extra: None,
            principal_kind: PrincipalKind::User,
        });
        assert!(id.groups().is_empty());
    }

    #[test]
    fn resolver_returns_correct_value() {
        let id = make_identity(None, None);
        assert_eq!(id.resolver(), "test-resolver");
    }

    #[test]
    fn extra_returns_some_when_set() {
        let claims = json!({"role": "superadmin"});
        let id = make_identity(None, Some(claims.clone()));
        assert_eq!(id.extra().unwrap(), &claims);
    }

    #[test]
    fn extra_returns_none_when_absent() {
        let id = make_identity(None, None);
        assert!(id.extra().is_none());
    }

    #[test]
    fn expiry_returns_some_when_set() {
        let now = Utc::now();
        let id = make_identity(Some(now), None);
        assert_eq!(id.expiry().unwrap(), &now);
    }

    #[test]
    fn expiry_returns_none_when_absent() {
        let id = make_identity(None, None);
        assert!(id.expiry().is_none());
    }

    // -- is_expired tests -----------------------------------------------------

    #[test]
    fn is_expired_returns_true_when_past_expiry() {
        let now = Utc::now();
        let past = now - Duration::hours(1);
        let id = make_identity(Some(past), None);
        assert!(id.is_expired(now));
    }

    #[test]
    fn is_expired_returns_false_when_before_expiry() {
        let now = Utc::now();
        let future = now + Duration::hours(1);
        let id = make_identity(Some(future), None);
        assert!(!id.is_expired(now));
    }

    #[test]
    fn is_expired_returns_false_when_no_expiry() {
        let now = Utc::now();
        let id = make_identity(None, None);
        assert!(!id.is_expired(now));
    }

    #[test]
    fn is_expired_returns_false_at_exact_expiry() {
        // When expiry == now, `exp < now` is false, so not expired.
        let now = Utc::now();
        let id = make_identity(Some(now), None);
        assert!(!id.is_expired(now));
    }

    // -- PrincipalKind tests --------------------------------------------------

    #[test]
    fn identity_principal_kind_accessor() {
        let id = Identity::new(IdentityParams {
            user_id: UserId::new("machine-key").unwrap(),
            tenant_id: None,
            groups: vec![],
            expiry: None,
            resolver: "ed25519",
            extra: None,
            principal_kind: PrincipalKind::Machine,
        });
        assert_eq!(id.principal_kind(), PrincipalKind::Machine);
    }

    #[test]
    fn identity_default_params_is_user() {
        let id = make_identity(None, None);
        assert_eq!(id.principal_kind(), PrincipalKind::User);
    }

    // -- Serialize test -------------------------------------------------------

    #[test]
    fn identity_serializes_to_json() {
        let id = make_identity(None, Some(json!({"custom": true})));
        let json_str = serde_json::to_string(&id).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(val["user_id"], "alice");
        assert_eq!(val["tenant_id"], "acme-corp");
        assert_eq!(val["groups"][0], "admin");
        assert_eq!(val["groups"][1], "backend-team");
        assert_eq!(val["resolver"], "test-resolver");
        assert_eq!(val["extra"]["custom"], true);
        assert!(val["expiry"].is_null());
        assert_eq!(val["principal_kind"], "user");
    }
}
