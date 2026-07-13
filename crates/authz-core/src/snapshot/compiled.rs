//! The immutable compiled snapshot: Cedar `PolicySet` + content-hash version.
//! Nobody edits a snapshot — sources are truth, this is derived (brief).

use std::str::FromStr;

use cedar_policy::PolicySet;

use crate::error::{Error, Result};
use crate::rbac::{compile_rbac_to_cedar, resolve_inherits, RbacEntry, TenantConfig};
use crate::snapshot::version::SnapshotVersion;

/// A versioned, immutable, compiled policy snapshot.
#[derive(Debug, Clone)]
pub struct Snapshot {
    policies: PolicySet,
    policy_text: String,
    version: SnapshotVersion,
}

impl Snapshot {
    /// Compile Cedar policy text into a snapshot. The version is the
    /// content hash of `text`.
    pub fn from_policy_text(text: &str) -> Result<Self> {
        let policies =
            PolicySet::from_str(text).map_err(|e| Error::InvalidPolicy(e.to_string()))?;
        Ok(Self {
            policies,
            policy_text: text.to_string(),
            version: SnapshotVersion::of(text),
        })
    }

    /// Compile a `forgeguard.toml`-style RBAC surface into a snapshot: for
    /// each role, flatten inheritance and emit one permit. Roles are
    /// compiled in input order; the version hashes the joined text, so
    /// entry order is part of snapshot identity (callers should keep
    /// config-file order).
    pub fn from_rbac(
        entries: &[RbacEntry],
        tenant: &TenantConfig,
        namespace: &str,
    ) -> Result<Self> {
        let mut statements = Vec::with_capacity(entries.len());
        for entry in entries {
            let allow = resolve_inherits(entries, &entry.name).map_err(Error::InvalidPolicy)?;
            let flattened = RbacEntry {
                name: entry.name.clone(),
                description: entry.description.clone(),
                inherits: Vec::new(),
                allow,
                tenant_scoped: entry.tenant_scoped,
            };
            let statement = compile_rbac_to_cedar(&flattened, tenant, namespace)
                .map_err(Error::InvalidPolicy)?;
            statements.push(statement);
        }
        Self::from_policy_text(&statements.join("\n\n"))
    }

    /// The compiled policy set.
    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }

    /// The compiled policy source text (what the version hashes).
    pub fn policy_text(&self) -> &str {
        &self.policy_text
    }

    /// The content-hash version.
    pub fn version(&self) -> &SnapshotVersion {
        &self.version
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn invalid_text_is_rejected() {
        let err = Snapshot::from_policy_text("permit(").unwrap_err();
        assert!(matches!(err, Error::InvalidPolicy(_)));
    }

    #[test]
    fn same_text_same_version() {
        let a = Snapshot::from_policy_text("permit(principal, action, resource);").unwrap();
        let b = Snapshot::from_policy_text("permit(principal, action, resource);").unwrap();
        assert_eq!(a.version(), b.version());
    }

    fn member_and_admin() -> Vec<RbacEntry> {
        vec![
            RbacEntry {
                name: "member".into(),
                description: None,
                inherits: vec![],
                allow: vec!["cp-organization-read".into()],
                tenant_scoped: true,
            },
            RbacEntry {
                name: "admin".into(),
                description: None,
                inherits: vec!["member".into()],
                allow: vec!["cp-organization-update".into()],
                tenant_scoped: true,
            },
        ]
    }

    /// The A5-b bridge: the repo's own RBAC shape compiles and parses
    /// under embedded Cedar 4.x (spike-verified in shaping).
    #[test]
    fn rbac_bridge_compiles_inherited_roles() {
        let snap = Snapshot::from_rbac(&member_and_admin(), &TenantConfig::default(), "forgeguard")
            .unwrap();
        assert_eq!(snap.policies().policies().count(), 2);
        // admin inherited member's action
        assert!(snap
            .policy_text()
            .contains(r#"forgeguard::Action::"cp-organization-read""#));
        assert!(snap.policy_text().contains(r#"forgeguard::Group::"admin""#));
    }

    #[test]
    fn rbac_versions_differ_when_roles_change() {
        let base = Snapshot::from_rbac(&member_and_admin(), &TenantConfig::default(), "forgeguard")
            .unwrap();
        let mut changed = member_and_admin();
        changed[0].allow.push("cp-key-read".into());
        let after = Snapshot::from_rbac(&changed, &TenantConfig::default(), "forgeguard").unwrap();
        assert_ne!(base.version(), after.version());
    }
}
