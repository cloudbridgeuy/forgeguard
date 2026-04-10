use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use super::config::{PolicyEntry, TenantConfig};

/// Compile an RBAC policy entry to a Cedar permit statement.
///
/// The role name becomes the group name in Cedar. Each action in `allow`
/// becomes a Cedar action in the `action in [...]` clause. Tenant scoping
/// appends `when { principal.<attr> == resource.<attr> }` when enabled.
pub(crate) fn compile_rbac_to_cedar(
    name: &str,
    allow: &[String],
    tenant_scoped: bool,
    tenant: &TenantConfig,
) -> Result<String, String> {
    if allow.is_empty() {
        return Err(format!(
            "RBAC policy '{name}' has an empty allow list; cannot compile to Cedar"
        ));
    }

    let mut out = String::new();
    let _ = writeln!(out, "permit(");
    let _ = writeln!(out, "  principal in group::\"{name}\",");

    // Action clause: always use `action in [...]` for consistency.
    let actions: Vec<String> = allow.iter().map(|a| format!("Action::\"{a}\"")).collect();
    let _ = writeln!(out, "  action in [{}],", actions.join(", "));

    let _ = write!(out, "  resource");

    // Tenant scoping: append `when` clause if both per-policy and global are enabled.
    if tenant_scoped && tenant.enabled {
        let _ = writeln!(out);
        let _ = write!(
            out,
            ") when {{ principal.{} == resource.{} }};",
            tenant.principal_attribute, tenant.resource_attribute
        );
    } else {
        let _ = writeln!(out);
        let _ = write!(out, ");");
    }

    Ok(out)
}

/// Resolve role inheritance: collect all actions for a role including
/// inherited actions from parent roles.
///
/// Detects cycles and returns an error. Only RBAC policies participate
/// in inheritance (Cedar policies are ignored).
pub(crate) fn resolve_inherits(
    policies: &[PolicyEntry],
    target_name: &str,
) -> Result<Vec<String>, String> {
    // Build a lookup of RBAC policies by name.
    let rbac_map: HashMap<&str, &[String]> = policies
        .iter()
        .filter_map(|entry| match entry {
            PolicyEntry::Rbac { name, allow, .. } => Some((name.as_str(), allow.as_slice())),
            PolicyEntry::Cedar { .. } => None,
        })
        .collect();

    let inherits_map: HashMap<&str, &[String]> = policies
        .iter()
        .filter_map(|entry| match entry {
            PolicyEntry::Rbac { name, inherits, .. } => Some((name.as_str(), inherits.as_slice())),
            PolicyEntry::Cedar { .. } => None,
        })
        .collect();

    // Verify the target exists.
    if !rbac_map.contains_key(target_name) {
        return Err(format!("RBAC role '{target_name}' not found"));
    }

    let mut walker = InheritanceWalker {
        rbac_map: &rbac_map,
        inherits_map: &inherits_map,
        collected: Vec::new(),
        seen_actions: HashSet::new(),
        visiting: HashSet::new(),
        visited: HashSet::new(),
    };
    walker.collect(target_name)?;

    Ok(walker.collected)
}

/// Mutable state for depth-first traversal of the role inheritance graph.
struct InheritanceWalker<'a> {
    rbac_map: &'a HashMap<&'a str, &'a [String]>,
    inherits_map: &'a HashMap<&'a str, &'a [String]>,
    collected: Vec<String>,
    seen_actions: HashSet<String>,
    visiting: HashSet<&'a str>,
    visited: HashSet<&'a str>,
}

impl<'a> InheritanceWalker<'a> {
    /// Recursively collect actions for a role, detecting cycles.
    fn collect(&mut self, role: &'a str) -> Result<(), String> {
        if self.visiting.contains(role) {
            return Err(format!("cycle detected in role inheritance: '{role}'"));
        }
        if self.visited.contains(role) {
            // Already fully processed (handles diamond inheritance).
            return Ok(());
        }

        self.visiting.insert(role);

        // Add this role's own actions.
        let actions = self
            .rbac_map
            .get(role)
            .ok_or_else(|| format!("RBAC role '{role}' not found (referenced via inherits)"))?;
        for action in *actions {
            if self.seen_actions.insert(action.clone()) {
                self.collected.push(action.clone());
            }
        }

        // Recurse into parents.
        if let Some(parents) = self.inherits_map.get(role) {
            // Copy parent names to avoid borrow conflict with &mut self.
            let parents: Vec<&'a str> = parents.iter().map(String::as_str).collect();
            for parent in parents {
                self.collect(parent)?;
            }
        }

        self.visiting.remove(role);
        self.visited.insert(role);

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // compile_rbac_to_cedar tests
    // -----------------------------------------------------------------------

    #[test]
    fn compile_basic_rbac_with_default_tenant_scoping() {
        let tenant = TenantConfig::default();
        let result = compile_rbac_to_cedar(
            "editor",
            &[
                "todo:list:create".to_string(),
                "todo:list:update".to_string(),
            ],
            true,
            &tenant,
        )
        .unwrap();

        let expected = "\
permit(
  principal in group::\"editor\",
  action in [Action::\"todo:list:create\", Action::\"todo:list:update\"],
  resource
) when { principal.tenant_id == resource.tenant_id };";
        assert_eq!(result, expected);
    }

    #[test]
    fn compile_rbac_with_custom_tenant_attributes() {
        let tenant = TenantConfig {
            enabled: true,
            principal_attribute: "org_id".to_string(),
            resource_attribute: "org_id".to_string(),
        };
        let result = compile_rbac_to_cedar(
            "admin",
            &["shopping:list:create".to_string()],
            true,
            &tenant,
        )
        .unwrap();

        assert!(result.contains("principal.org_id == resource.org_id"));
    }

    #[test]
    fn compile_rbac_tenant_scoped_false_no_when_clause() {
        let tenant = TenantConfig::default();
        let result = compile_rbac_to_cedar(
            "global-reader",
            &["todo:list:list".to_string()],
            false,
            &tenant,
        )
        .unwrap();

        let expected = "\
permit(
  principal in group::\"global-reader\",
  action in [Action::\"todo:list:list\"],
  resource
);";
        assert_eq!(result, expected);
        assert!(!result.contains("when"));
    }

    #[test]
    fn compile_rbac_tenant_globally_disabled_no_when_clause() {
        let tenant = TenantConfig {
            enabled: false,
            principal_attribute: "tenant_id".to_string(),
            resource_attribute: "tenant_id".to_string(),
        };
        let result = compile_rbac_to_cedar(
            "viewer",
            &["todo:list:read".to_string()],
            true, // per-policy wants scoping, but global is off
            &tenant,
        )
        .unwrap();

        assert!(!result.contains("when"));
        assert!(result.ends_with(");"));
    }

    #[test]
    fn compile_rbac_single_action_uses_in_syntax() {
        let tenant = TenantConfig::default();
        let result =
            compile_rbac_to_cedar("viewer", &["todo:list:read".to_string()], true, &tenant)
                .unwrap();

        assert!(result.contains("action in [Action::\"todo:list:read\"]"));
    }

    #[test]
    fn compile_rbac_empty_allow_list_returns_error() {
        let tenant = TenantConfig::default();
        let result = compile_rbac_to_cedar("empty-role", &[], true, &tenant);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("empty allow list"), "unexpected error: {err}");
    }

    #[test]
    fn compile_rbac_many_actions() {
        let tenant = TenantConfig::default();
        let actions: Vec<String> = vec![
            "todo:list:create",
            "todo:list:update",
            "todo:list:delete",
            "todo:list:share",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let result = compile_rbac_to_cedar("admin", &actions, true, &tenant).unwrap();

        assert!(result.contains("Action::\"todo:list:create\""));
        assert!(result.contains("Action::\"todo:list:update\""));
        assert!(result.contains("Action::\"todo:list:delete\""));
        assert!(result.contains("Action::\"todo:list:share\""));
    }

    // -----------------------------------------------------------------------
    // resolve_inherits tests
    // -----------------------------------------------------------------------

    fn rbac(name: &str, allow: &[&str], inherits: &[&str]) -> PolicyEntry {
        PolicyEntry::Rbac {
            name: name.to_string(),
            description: None,
            inherits: inherits.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            tenant_scoped: true,
        }
    }

    fn cedar(name: &str) -> PolicyEntry {
        PolicyEntry::Cedar {
            name: name.to_string(),
            description: None,
            body: "forbid(principal, action, resource);".to_string(),
        }
    }

    #[test]
    fn resolve_no_inheritance() {
        let policies = vec![rbac("viewer", &["read"], &[])];
        let actions = resolve_inherits(&policies, "viewer").unwrap();
        assert_eq!(actions, vec!["read"]);
    }

    #[test]
    fn resolve_simple_inheritance() {
        let policies = vec![
            rbac("viewer", &["read"], &[]),
            rbac("editor", &["write"], &["viewer"]),
        ];
        let actions = resolve_inherits(&policies, "editor").unwrap();
        assert_eq!(actions, vec!["write", "read"]);
    }

    #[test]
    fn resolve_transitive_inheritance() {
        let policies = vec![
            rbac("viewer", &["read"], &[]),
            rbac("editor", &["write"], &["viewer"]),
            rbac("admin", &["delete"], &["editor"]),
        ];
        let actions = resolve_inherits(&policies, "admin").unwrap();
        assert_eq!(actions, vec!["delete", "write", "read"]);
    }

    #[test]
    fn resolve_cycle_detection() {
        let policies = vec![rbac("a", &["x"], &["b"]), rbac("b", &["y"], &["a"])];
        let result = resolve_inherits(&policies, "a");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("cycle"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_self_reference() {
        let policies = vec![rbac("a", &["x"], &["a"])];
        let result = resolve_inherits(&policies, "a");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("cycle"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_inherits_from_nonexistent_role() {
        let policies = vec![rbac("a", &["x"], &["nonexistent"])];
        let result = resolve_inherits(&policies, "a");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not found"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_diamond_inheritance_dedup() {
        // A inherits B and C, both inherit D
        let policies = vec![
            rbac("d", &["read"], &[]),
            rbac("b", &["write"], &["d"]),
            rbac("c", &["exec"], &["d"]),
            rbac("a", &["admin"], &["b", "c"]),
        ];
        let actions = resolve_inherits(&policies, "a").unwrap();

        // "read" from D should appear only once
        let read_count = actions.iter().filter(|a| *a == "read").count();
        assert_eq!(read_count, 1, "diamond should deduplicate actions");

        // All actions should be present
        assert!(actions.contains(&"admin".to_string()));
        assert!(actions.contains(&"write".to_string()));
        assert!(actions.contains(&"exec".to_string()));
        assert!(actions.contains(&"read".to_string()));
    }

    #[test]
    fn resolve_target_not_found() {
        let policies = vec![rbac("viewer", &["read"], &[])];
        let result = resolve_inherits(&policies, "nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not found"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_ignores_cedar_policies() {
        let policies = vec![
            rbac("viewer", &["read"], &[]),
            cedar("some-cedar-policy"),
            rbac("editor", &["write"], &["viewer"]),
        ];
        let actions = resolve_inherits(&policies, "editor").unwrap();
        assert_eq!(actions, vec!["write", "read"]);
    }

    #[test]
    fn resolve_multi_parent_inherits() {
        let policies = vec![
            rbac("viewer", &["todo:list:list", "todo:list:read"], &[]),
            rbac(
                "shopper",
                &["shopping:list:list", "shopping:list:read"],
                &[],
            ),
            rbac("admin", &["todo:list:delete"], &["viewer", "shopper"]),
        ];
        let actions = resolve_inherits(&policies, "admin").unwrap();
        assert_eq!(
            actions,
            vec![
                "todo:list:delete",
                "todo:list:list",
                "todo:list:read",
                "shopping:list:list",
                "shopping:list:read",
            ]
        );
    }
}
