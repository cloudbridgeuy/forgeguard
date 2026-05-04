//! Pure permit compilation: turn `RbacEntry` declarations into `NamedPermit`s
//! ready for `VpClient::create_policy`.
//!
//! Lifted in V4 from `crates/control-plane/src/handlers/groups/active_pure.rs`
//! so the saga handoff stub can build permits without depending on CP-internal
//! types. The V3 Active write path now imports from this module too.

use crate::rbac::{compile_rbac_to_cedar, RbacEntry, TenantConfig};

/// A single Cedar permit destined for VP, with the canonical `cp-rbac-{name}`
/// policy name already applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPermit {
    pub name: String,
    pub statement: String,
}

/// The VP policy name for a group. Format: `cp-rbac-{group_name}`.
///
/// Canonical mapping shared between the V3 Active write path, the V4 saga
/// stub, and `xtask cedar sync` — all three must produce identical names so
/// policies survive across reconciler runs.
pub fn policy_name_for_group(group_name: &str) -> String {
    format!("cp-rbac-{group_name}")
}

/// Compile-time error from `groups_to_permits` — first compile failure wins.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rbac entry '{name}' failed to compile: {reason}")]
pub struct MaterializeCompileError {
    pub name: String,
    pub reason: String,
}

/// Compile every declared group into a `NamedPermit`, sorted alphabetically
/// by group name.
///
/// **Order:** the output is sorted by `entry.name` ascending. Saga callers
/// rely on this for reproducible test assertions and for stable VP write
/// order across retries.
///
/// **Failure semantics:** stops at the first compile failure and returns
/// `Err(MaterializeCompileError { name, reason })`. No partial-success
/// `Vec` is ever returned alongside an error.
pub fn groups_to_permits(
    entries: &[RbacEntry],
    namespace: &str,
    tenant: &TenantConfig,
) -> Result<Vec<NamedPermit>, MaterializeCompileError> {
    let mut sorted: Vec<&RbacEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.name.as_str());

    sorted
        .into_iter()
        .map(|entry| {
            let statement = compile_rbac_to_cedar(entry, tenant, namespace).map_err(|reason| {
                MaterializeCompileError {
                    name: entry.name.clone(),
                    reason,
                }
            })?;
            Ok(NamedPermit {
                name: policy_name_for_group(&entry.name),
                statement,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn entry(name: &str, allow: &[&str]) -> RbacEntry {
        RbacEntry {
            name: name.to_owned(),
            description: None,
            inherits: vec![],
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            tenant_scoped: false,
        }
    }

    // ----- policy_name_for_group -----

    #[test]
    fn policy_name_simple() {
        assert_eq!(policy_name_for_group("admin"), "cp-rbac-admin");
    }

    #[test]
    fn policy_name_preserves_dashes() {
        assert_eq!(
            policy_name_for_group("billing-readonly"),
            "cp-rbac-billing-readonly"
        );
    }

    #[test]
    fn policy_name_empty_input() {
        // Empty group names are rejected upstream by `validate_group_name`,
        // but the formatter itself must not panic — keep the contract trivial.
        assert_eq!(policy_name_for_group(""), "cp-rbac-");
    }

    // ----- groups_to_permits -----

    #[test]
    fn empty_input_returns_empty_vec() {
        let permits = groups_to_permits(&[], "app", &TenantConfig::default()).unwrap();
        assert!(permits.is_empty());
    }

    #[test]
    fn single_entry_returns_one_permit_with_canonical_name() {
        let permits = groups_to_permits(
            &[entry("admin", &["cp:org:read"])],
            "app",
            &TenantConfig::default(),
        )
        .unwrap();
        assert_eq!(permits.len(), 1);
        assert_eq!(permits[0].name, "cp-rbac-admin");
        assert!(permits[0].statement.contains("app::Group::\"admin\""));
    }

    #[test]
    fn output_sorted_alphabetically_independent_of_input_order() {
        // Input deliberately not alphabetical.
        let entries = vec![
            entry("zeta", &["cp:x:read"]),
            entry("alpha", &["cp:x:read"]),
            entry("member", &["cp:x:read"]),
        ];
        let permits = groups_to_permits(&entries, "app", &TenantConfig::default()).unwrap();
        let names: Vec<&str> = permits.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["cp-rbac-alpha", "cp-rbac-member", "cp-rbac-zeta"]);
    }

    #[test]
    fn first_compile_failure_aborts_with_no_partial_results() {
        // Empty `allow` is the simplest compile failure (`compile_rbac_to_cedar`
        // rejects empty allow lists).
        let bad = RbacEntry {
            name: "broken".to_owned(),
            description: None,
            inherits: vec![],
            allow: vec![],
            tenant_scoped: false,
        };
        let entries = vec![entry("admin", &["cp:x:read"]), bad];
        let err = groups_to_permits(&entries, "app", &TenantConfig::default()).unwrap_err();
        assert_eq!(err.name, "broken");
        assert!(err.reason.contains("empty allow list"));
    }

    #[test]
    fn byte_stable_across_runs() {
        let entries = vec![
            entry("admin", &["cp:org:read"]),
            entry("member", &["cp:org:read"]),
        ];
        let a = groups_to_permits(&entries, "app", &TenantConfig::default()).unwrap();
        let b = groups_to_permits(&entries, "app", &TenantConfig::default()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn namespace_threaded_into_statement() {
        let permits = groups_to_permits(
            &[entry("admin", &["cp:x:read"])],
            "customer-app",
            &TenantConfig::default(),
        )
        .unwrap();
        assert!(permits[0]
            .statement
            .contains("customer-app::Group::\"admin\""));
    }
}
