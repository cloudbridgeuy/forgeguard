use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// Prefix emitted by [`resolve_inherits`] (and the internal inheritance
/// walker) when a cycle is detected in the role-inheritance graph.
///
/// [`map_resolve_err`](crate::rbac::validation) uses this constant as the
/// single source of truth so error classification cannot silently drift if the
/// wording changes.
pub const CYCLE_PREFIX: &str = "cycle detected";

fn default_true() -> bool {
    true
}

fn default_tenant_id() -> String {
    "tenant_id".to_string()
}

/// A single RBAC role definition that can be compiled to a Cedar permit statement.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RbacEntry {
    /// The role name — becomes the Cedar `Group` name.
    pub name: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Parent roles whose allow lists are merged in via `resolve_inherits`.
    #[serde(default)]
    pub inherits: Vec<String>,
    /// Actions directly granted by this role.
    pub allow: Vec<String>,
    /// Whether to append a `when { principal.<attr> == resource.<attr> }` clause.
    #[serde(default = "default_true")]
    pub tenant_scoped: bool,
}

/// Tenant scoping configuration for RBAC policies.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TenantConfig {
    /// Master switch — when `false`, no tenant scoping is applied regardless of
    /// per-role `tenant_scoped` flags.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Attribute on the principal entity that carries the tenant identifier.
    #[serde(default = "default_tenant_id")]
    pub principal_attribute: String,
    /// Attribute on the resource entity that carries the tenant identifier.
    #[serde(default = "default_tenant_id")]
    pub resource_attribute: String,
}

impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            principal_attribute: default_tenant_id(),
            resource_attribute: default_tenant_id(),
        }
    }
}

/// Validate that a string is safe to interpolate into a Cedar policy.
/// Rejects empty strings, double quotes, backslashes (Cedar string-escape
/// characters — either would let a crafted value break out of its quoted
/// literal), and control characters (including newlines and carriage
/// returns).
pub fn validate_cedar_ident(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value
        .chars()
        .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err(format!("{label} contains invalid characters: {value:?}"));
    }
    Ok(())
}

/// Compile an RBAC policy entry to a Cedar permit statement.
///
/// The role name becomes the group name in Cedar. Each action in `entry.allow`
/// becomes a Cedar action in the `action in [...]` clause. Tenant scoping
/// appends `when { principal.<attr> == resource.<attr> }` when both the
/// per-entry flag and the global `TenantConfig::enabled` are true.
///
/// # Errors
///
/// Returns an error if the role name, any action, or the tenant attribute
/// names contain characters invalid in Cedar identifiers, or if `allow` is
/// empty.
pub fn compile_rbac_to_cedar(
    entry: &RbacEntry,
    tenant: &TenantConfig,
    namespace: &str,
) -> Result<String, String> {
    let name = &entry.name;
    let allow = &entry.allow;
    let tenant_scoped = entry.tenant_scoped;

    validate_cedar_ident(name, "role name")?;

    if allow.is_empty() {
        return Err(format!(
            "RBAC policy '{name}' has an empty allow list; cannot compile to Cedar"
        ));
    }

    for action in allow {
        validate_cedar_ident(action, "action")?;
    }

    if tenant_scoped && tenant.enabled {
        validate_cedar_ident(&tenant.principal_attribute, "tenant principal_attribute")?;
        validate_cedar_ident(&tenant.resource_attribute, "tenant resource_attribute")?;
    }

    let mut out = String::new();
    let _ = writeln!(out, "permit(");
    let _ = writeln!(out, "  principal in {namespace}::Group::\"{name}\",");

    let _ = writeln!(
        out,
        "  action in [{}],",
        allow
            .iter()
            .map(|a| format!("{namespace}::Action::\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );

    if tenant_scoped && tenant.enabled {
        let _ = write!(
            out,
            "  resource\n) when {{ principal.{} == resource.{} }};",
            tenant.principal_attribute, tenant.resource_attribute
        );
    } else {
        let _ = write!(out, "  resource\n);");
    }

    Ok(out)
}

/// Resolve role inheritance: collect all actions for a role including
/// inherited actions from parent roles.
///
/// Performs a depth-first traversal of the inheritance graph, collecting
/// actions in DFS pre-order (self first, then parents). Diamond inheritance
/// is handled correctly — each action appears at most once. Returns an error
/// if a cycle is detected or a referenced role does not exist.
pub fn resolve_inherits(entries: &[RbacEntry], target_name: &str) -> Result<Vec<String>, String> {
    // Build lookups by name (single pass).
    let mut rbac_map: HashMap<&str, &[String]> = HashMap::new();
    let mut inherits_map: HashMap<&str, &[String]> = HashMap::new();
    for entry in entries {
        rbac_map.insert(entry.name.as_str(), entry.allow.as_slice());
        inherits_map.insert(entry.name.as_str(), entry.inherits.as_slice());
    }

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
            return Err(format!("{CYCLE_PREFIX} in role inheritance: '{role}'"));
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

pub mod permits;
pub mod validation;

pub use permits::{groups_to_permits, policy_name_for_group, MaterializeCompileError, NamedPermit};
pub use validation::{
    validate_action_format, validate_action_id, validate_group_name, validate_rbac_entry,
    GroupValidationError, ValidatedRbacEntry,
};

#[cfg(test)]
mod tests;
