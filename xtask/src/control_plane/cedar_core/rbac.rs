//! Re-export the lifted RBAC compiler from `forgeguard_authz_core`.
//!
//! The pure compiler lives in `forgeguard_authz_core::rbac`. This module
//! exposes the re-exports xtask call sites already use, plus a small
//! adapter that maps the xtask-local `PolicyEntry` into the lifted
//! `RbacEntry` type at the I/O edge.

pub(crate) use forgeguard_authz_core::{compile_rbac_to_cedar, resolve_inherits, RbacEntry};

use super::config::PolicyEntry;

/// Map xtask-local `PolicyEntry` values to lifted `RbacEntry` instances.
///
/// Filters out `PolicyEntry::Cedar` variants — only RBAC entries
/// participate in the inheritance graph.
pub(crate) fn policy_entries_to_rbac(entries: &[PolicyEntry]) -> Vec<RbacEntry> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            PolicyEntry::Rbac {
                name,
                description,
                inherits,
                allow,
                tenant_scoped,
            } => Some(RbacEntry {
                name: name.clone(),
                description: description.clone(),
                inherits: inherits.clone(),
                allow: allow.clone(),
                tenant_scoped: *tenant_scoped,
            }),
            PolicyEntry::Cedar { .. } => None,
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_entries_to_rbac_maps_rbac_only() {
        let entries = vec![
            PolicyEntry::Rbac {
                name: "viewer".to_string(),
                description: Some("Read-only.".to_string()),
                inherits: vec![],
                allow: vec!["read".to_string()],
                tenant_scoped: true,
            },
            PolicyEntry::Cedar {
                name: "raw-cedar".to_string(),
                description: None,
                body: "permit(principal, action, resource);".to_string(),
            },
            PolicyEntry::Rbac {
                name: "admin".to_string(),
                description: None,
                inherits: vec!["viewer".to_string()],
                allow: vec!["write".to_string(), "delete".to_string()],
                tenant_scoped: false,
            },
        ];

        let rbac = policy_entries_to_rbac(&entries);
        assert_eq!(rbac.len(), 2);

        assert_eq!(rbac[0].name, "viewer");
        assert_eq!(rbac[0].description.as_deref(), Some("Read-only."));
        assert!(rbac[0].inherits.is_empty());
        assert_eq!(rbac[0].allow, vec!["read".to_string()]);
        assert!(rbac[0].tenant_scoped);

        assert_eq!(rbac[1].name, "admin");
        assert!(rbac[1].description.is_none());
        assert_eq!(rbac[1].inherits, vec!["viewer".to_string()]);
        assert_eq!(
            rbac[1].allow,
            vec!["write".to_string(), "delete".to_string()]
        );
        assert!(!rbac[1].tenant_scoped);
    }

    #[test]
    fn policy_entries_to_rbac_empty_input() {
        let rbac = policy_entries_to_rbac(&[]);
        assert!(rbac.is_empty());
    }

    #[test]
    fn policy_entries_to_rbac_only_cedar_returns_empty() {
        let entries = vec![PolicyEntry::Cedar {
            name: "raw".to_string(),
            description: None,
            body: "permit(principal, action, resource);".to_string(),
        }];
        let rbac = policy_entries_to_rbac(&entries);
        assert!(rbac.is_empty());
    }
}
