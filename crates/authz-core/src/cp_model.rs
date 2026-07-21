//! Build-time compiler for the control plane's own authorization model.
//!
//! Parses the `[schema]`, `[tenant]`, and `[[policies]]` sections of
//! `forgeguard.toml` and emits a single Cedar policy-text string: RBAC
//! entries are inherits-flattened and compiled via [`compile_rbac_to_cedar`];
//! raw `type = "cedar"` bodies pass through verbatim. VP-only sections
//! (`[authz]`, `[schema.entities]`, `[[templates]]`) are ignored.

use serde::Deserialize;

use crate::rbac::{
    compile_rbac_to_cedar, resolve_inherits, validate_action_id, validate_group_name, RbacEntry,
    TenantConfig,
};

#[derive(Debug, Deserialize)]
struct CpModelToml {
    schema: Option<SchemaSection>,
    tenant: Option<TenantConfig>,
    #[serde(default)]
    policies: Vec<PolicySection>,
}

#[derive(Debug, Deserialize)]
struct SchemaSection {
    namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum PolicySectionTagged {
    Rbac(RbacEntry),
    Cedar { body: String },
}

/// `[[policies]]` entry. `type` defaults to `"rbac"` when absent, matching
/// the xtask `cedar_core` parser this module supersedes.
#[derive(Debug)]
struct PolicySection(PolicySectionTagged);

impl<'de> Deserialize<'de> for PolicySection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = toml::Value::deserialize(deserializer)?;
        if let Some(table) = value.as_table_mut() {
            table
                .entry("type")
                .or_insert_with(|| toml::Value::String("rbac".to_owned()));
        }
        PolicySectionTagged::deserialize(value)
            .map(PolicySection)
            .map_err(serde::de::Error::custom)
    }
}

pub fn compile_cp_model(toml_text: &str) -> std::result::Result<String, String> {
    let model: CpModelToml =
        toml::from_str(toml_text).map_err(|e| format!("forgeguard.toml parse error: {e}"))?;
    let namespace = model
        .schema
        .as_ref()
        .map(|s| s.namespace.as_str())
        .ok_or_else(|| "missing [schema] namespace".to_owned())?;
    let tenant = model.tenant.unwrap_or_default();

    let rbac_entries: Vec<RbacEntry> = model
        .policies
        .iter()
        .filter_map(|p| match &p.0 {
            PolicySectionTagged::Rbac(entry) => Some(entry.clone()),
            PolicySectionTagged::Cedar { .. } => None,
        })
        .collect();

    // Semantic validation before compilation: Cedar accepts arbitrary strings
    // as entity IDs, so a typo'd group name or action would otherwise compile
    // clean and silently never match. Same guards the retired `cedar sync`
    // path applied.
    for entry in &rbac_entries {
        validate_group_name(&entry.name).map_err(|e| format!("policy {:?}: {e}", entry.name))?;
        for action in &entry.allow {
            validate_action_id(action).map_err(|e| format!("policy {:?}: {e}", entry.name))?;
        }
    }

    let mut statements = Vec::with_capacity(model.policies.len());
    for policy in &model.policies {
        match &policy.0 {
            PolicySectionTagged::Rbac(entry) => {
                let allow = resolve_inherits(&rbac_entries, &entry.name)?;
                let flattened = RbacEntry {
                    name: entry.name.clone(),
                    description: entry.description.clone(),
                    inherits: Vec::new(),
                    allow,
                    tenant_scoped: entry.tenant_scoped,
                };
                statements.push(compile_rbac_to_cedar(&flattened, &tenant, namespace)?);
            }
            PolicySectionTagged::Cedar { body } => statements.push(body.trim().to_owned()),
        }
    }

    let text = statements.join("\n\n");
    // Fail here, not at runtime: prove the combined text is valid Cedar.
    crate::Snapshot::from_policy_text(&text).map_err(|e| e.to_string())?;
    Ok(text)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Action ids are already hyphenated Cedar action-name form
    // (`cp-organization-read`), matching the real forgeguard.toml — the RBAC
    // compiler (`compile_rbac_to_cedar`) passes `allow` entries through
    // verbatim, it does not transform `cp:x:y` into `cp-x-y`.
    const MODEL: &str = r#"
[authz]
policy_store_id = "ignored"

[schema]
namespace = "forgeguard"
actions = ["cp-organization-read"]

[tenant]
principal_attribute = "org_id"
resource_attribute = "org_id"

[[policies]]
name = "member"
allow = ["cp-organization-read"]

[[policies]]
name = "admin"
inherits = ["member"]
allow = ["cp-group-create"]

[[policies]]
type = "cedar"
name = "machine-proxy-config-read"
body = '''
permit(
  principal is forgeguard::Machine,
  action == forgeguard::Action::"cp-organization-read",
  resource
) when { principal.org_id == resource.org_id };
'''
"#;

    #[test]
    fn compiles_rbac_and_cedar_policies() {
        let text = compile_cp_model(MODEL).unwrap();
        // One permit per RBAC entry, keyed to its Group.
        assert!(text.contains(r#"forgeguard::Group::"member""#));
        assert!(text.contains(r#"forgeguard::Group::"admin""#));
        // admin inherits member's allows (flattened, not `in`-chained).
        let admin_stmt = text
            .split("\n\n")
            .find(|s| s.contains(r#"Group::"admin""#))
            .unwrap();
        assert!(admin_stmt.contains("cp-organization-read"));
        assert!(admin_stmt.contains("cp-group-create"));
        // Raw cedar body passes through verbatim.
        assert!(text.contains("principal is forgeguard::Machine"));
        // Tenant scoping clause present on RBAC permits.
        assert!(text.contains("principal.org_id == resource.org_id"));
        // Whole thing is valid Cedar.
        crate::Snapshot::from_policy_text(&text).unwrap();
    }

    #[test]
    fn missing_schema_namespace_is_an_error() {
        let err = compile_cp_model("[[policies]]\nname = \"member\"\nallow = [\"cp-x-read\"]\n")
            .unwrap_err();
        assert!(err.contains("schema"), "got: {err}");
    }

    #[test]
    fn inherit_cycle_is_an_error() {
        let bad = r#"
[schema]
namespace = "forgeguard"

[[policies]]
name = "a"
inherits = ["b"]
allow = ["cp-x-read"]

[[policies]]
name = "b"
inherits = ["a"]
allow = ["cp-y-read"]
"#;
        let err = compile_cp_model(bad).unwrap_err();
        assert!(err.contains("cycle"), "got: {err}");
    }

    #[test]
    fn invalid_cedar_body_is_an_error() {
        let bad = r#"
[schema]
namespace = "forgeguard"

[[policies]]
type = "cedar"
name = "broken"
body = "permit(principal action resource"
"#;
        assert!(compile_cp_model(bad).is_err());
    }

    #[test]
    fn malformed_action_id_is_an_error() {
        // Cedar accepts arbitrary strings as entity IDs, so without semantic
        // validation this would compile clean and silently never match
        // (QA Scenario 4 regression, 2026-07-21).
        let bad = r#"
[schema]
namespace = "forgeguard"

[[policies]]
name = "broken"
allow = ["not a valid action ident !!"]
"#;
        let err = compile_cp_model(bad).unwrap_err();
        assert!(err.contains("action id"), "got: {err}");
    }

    #[test]
    fn malformed_group_name_is_an_error() {
        let bad = r#"
[schema]
namespace = "forgeguard"

[[policies]]
name = "Not A Valid Name"
allow = ["cp-organization-read"]
"#;
        let err = compile_cp_model(bad).unwrap_err();
        assert!(err.contains("must match"), "got: {err}");
    }

    #[test]
    fn compiles_the_real_forgeguard_toml() {
        let text = compile_cp_model(include_str!("../../../forgeguard.toml")).unwrap();
        assert!(text.contains(r#"forgeguard::Group::"owner""#));
    }
}
