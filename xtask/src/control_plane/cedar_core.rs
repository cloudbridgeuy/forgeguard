use std::fmt;
use std::fmt::Write as _;

use serde::de::{self, MapAccess, Visitor};
use serde::Deserialize;

/// VP policy store identifier.
///
/// Wraps a raw string to prevent accidental misuse in unrelated contexts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyStoreId(String);

impl PolicyStoreId {
    pub(crate) fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyStoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A snapshot of the VP policy store state.
pub(crate) struct StoreState {
    pub(crate) schema: Option<String>,
    pub(crate) templates: Vec<StoreTemplate>,
    pub(crate) policies: Vec<StorePolicy>,
}

/// A Cedar policy template stored in VP.
pub(crate) struct StoreTemplate {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// A Cedar static policy stored in VP.
pub(crate) struct StorePolicy {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// Return the first line of `text`, truncated to at most 80 visible characters.
///
/// Truncation respects UTF-8 character boundaries so it never panics on
/// multi-byte characters.
pub(crate) fn first_line_preview(text: &str) -> String {
    let first_line = text.lines().next().unwrap_or("");
    if first_line.chars().count() <= 80 {
        return first_line.to_string();
    }
    let end = first_line
        .char_indices()
        .nth(77)
        .map_or(first_line.len(), |(i, _)| i);
    format!("{}...", &first_line[..end])
}

/// Write a single entry (template or policy) to the output buffer.
fn write_entry(out: &mut String, label: &str, description: Option<&str>, statement: &str) {
    let _ = writeln!(out, "  - {label}");
    if let Some(desc) = description {
        let _ = writeln!(out, "    {desc}");
    }
    let _ = writeln!(out, "    {}", first_line_preview(statement));
}

/// Format the VP store state for terminal display.
pub(crate) fn format_status(store_id: &PolicyStoreId, state: &StoreState) -> String {
    let mut out = format!("Policy Store: {store_id}\n");

    match &state.schema {
        Some(schema) => {
            let _ = writeln!(out, "Schema: present");
            let _ = writeln!(out, "  {}", first_line_preview(schema));
        }
        None => out.push_str("Schema: none\n"),
    }

    let _ = writeln!(out, "Templates: {}", state.templates.len());
    for t in &state.templates {
        let label = t.name.as_deref().unwrap_or(&t.id);
        write_entry(&mut out, label, t.description.as_deref(), &t.statement);
    }

    let _ = writeln!(out, "Policies: {}", state.policies.len());
    for p in &state.policies {
        let label = p.name.as_deref().unwrap_or(&p.id);
        write_entry(&mut out, label, p.description.as_deref(), &p.statement);
    }

    out
}

// ---------------------------------------------------------------------------
// Cedar sync config types (deserialized from forgeguard.toml)
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_tenant_id() -> String {
    "tenant_id".to_string()
}

/// Top-level Cedar sync config (subset of forgeguard.toml relevant to sync).
#[derive(Debug, Deserialize)]
pub(crate) struct CedarSyncConfig {
    pub(crate) policy_store_id: String,
    pub(crate) schema: Option<SchemaConfig>,
    /// Used by RBAC compilation (V4).
    #[allow(dead_code)]
    pub(crate) tenant: Option<TenantConfig>,
    #[serde(default)]
    pub(crate) policies: Vec<PolicyEntry>,
    #[serde(default)]
    pub(crate) templates: Vec<TemplateEntry>,
}

/// Path to the Cedar schema file.
#[derive(Debug, Deserialize)]
pub(crate) struct SchemaConfig {
    pub(crate) path: String,
}

/// Tenant scoping configuration for RBAC policies.
///
/// Fields are consumed by RBAC compilation (V4).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct TenantConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_tenant_id")]
    pub(crate) principal_attribute: String,
    #[serde(default = "default_tenant_id")]
    pub(crate) resource_attribute: String,
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

/// Policy entry — dispatches on `type` field.
///
/// When `type` is omitted, defaults to `Rbac`. Uses a custom `Deserialize`
/// implementation that inserts `type = "rbac"` when the field is missing, then
/// delegates to the internally-tagged deserializer.
/// Fields in `Rbac` are consumed by RBAC compilation (V4).
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum PolicyEntry {
    Rbac {
        name: String,
        description: Option<String>,
        inherits: Vec<String>,
        allow: Vec<String>,
        tenant_scoped: bool,
    },
    Cedar {
        name: String,
        description: Option<String>,
        body: String,
    },
}

/// Internally-tagged version used by the custom `Deserialize` impl.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum PolicyEntryTagged {
    Rbac {
        name: String,
        description: Option<String>,
        #[serde(default)]
        inherits: Vec<String>,
        allow: Vec<String>,
        #[serde(default = "default_true")]
        tenant_scoped: bool,
    },
    Cedar {
        name: String,
        description: Option<String>,
        body: String,
    },
}

impl From<PolicyEntryTagged> for PolicyEntry {
    fn from(tagged: PolicyEntryTagged) -> Self {
        match tagged {
            PolicyEntryTagged::Rbac {
                name,
                description,
                inherits,
                allow,
                tenant_scoped,
            } => Self::Rbac {
                name,
                description,
                inherits,
                allow,
                tenant_scoped,
            },
            PolicyEntryTagged::Cedar {
                name,
                description,
                body,
            } => Self::Cedar {
                name,
                description,
                body,
            },
        }
    }
}

impl<'de> Deserialize<'de> for PolicyEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        /// Visitor that collects all key-value pairs, injects `type = "rbac"`
        /// when `type` is absent, then deserializes via the tagged enum.
        struct PolicyEntryVisitor;

        impl<'de> Visitor<'de> for PolicyEntryVisitor {
            type Value = PolicyEntry;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a policy entry (map with optional 'type' field)")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries: Vec<(String, toml::Value)> = Vec::new();
                let mut has_type = false;

                while let Some((key, value)) = map.next_entry::<String, toml::Value>()? {
                    if key == "type" {
                        has_type = true;
                    }
                    entries.push((key, value));
                }

                if !has_type {
                    entries.insert(
                        0,
                        ("type".to_string(), toml::Value::String("rbac".to_string())),
                    );
                }

                let table: toml::map::Map<String, toml::Value> = entries.into_iter().collect();
                let value = toml::Value::Table(table);
                let tagged: PolicyEntryTagged =
                    PolicyEntryTagged::deserialize(value).map_err(de::Error::custom)?;

                Ok(PolicyEntry::from(tagged))
            }
        }

        deserializer.deserialize_map(PolicyEntryVisitor)
    }
}

/// Template entry — only Cedar for now.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum TemplateEntry {
    Cedar {
        name: String,
        description: Option<String>,
        body: String,
    },
}

// ---------------------------------------------------------------------------
// Desired state (compiled from config, ready to sync)
// ---------------------------------------------------------------------------

/// Desired state to sync to VP (compiled from config).
#[derive(Debug)]
pub(crate) struct DesiredState {
    pub(crate) schema: Option<String>,
    pub(crate) templates: Vec<DesiredTemplate>,
    pub(crate) policies: Vec<DesiredPolicy>,
}

/// A Cedar policy template to push to VP.
#[derive(Debug)]
pub(crate) struct DesiredTemplate {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// A Cedar static policy to push to VP.
#[derive(Debug)]
pub(crate) struct DesiredPolicy {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// Build desired state from parsed config and schema file content.
///
/// For V2: Cedar policies/templates pass through verbatim.
/// RBAC policies are skipped (added in V4).
pub(crate) fn build_desired_state(
    config: &CedarSyncConfig,
    schema_content: Option<String>,
) -> DesiredState {
    let policies = config
        .policies
        .iter()
        .filter_map(|entry| match entry {
            PolicyEntry::Cedar {
                name,
                description,
                body,
            } => Some(DesiredPolicy {
                name: name.clone(),
                description: description.clone(),
                statement: body.clone(),
            }),
            // RBAC compilation is V4 — skip for now.
            PolicyEntry::Rbac { .. } => None,
        })
        .collect();

    let templates = config
        .templates
        .iter()
        .map(|entry| {
            let TemplateEntry::Cedar {
                name,
                description,
                body,
            } = entry;
            DesiredTemplate {
                name: name.clone(),
                description: description.clone(),
                statement: body.clone(),
            }
        })
        .collect();

    DesiredState {
        schema: schema_content,
        templates,
        policies,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- PolicyStoreId ---

    #[test]
    fn policy_store_id_display() {
        let id = PolicyStoreId::new("ps-abc123");
        assert_eq!(id.to_string(), "ps-abc123");
        assert_eq!(id.as_str(), "ps-abc123");
    }

    // --- format_status: empty store ---

    #[test]
    fn format_status_empty_store() {
        let id = PolicyStoreId::new("ps-empty");
        let state = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let output = format_status(&id, &state);
        assert!(output.contains("Policy Store: ps-empty"));
        assert!(output.contains("Schema: none"));
        assert!(output.contains("Templates: 0"));
        assert!(output.contains("Policies: 0"));
    }

    // --- format_status: store with schema ---

    #[test]
    fn format_status_with_schema() {
        let id = PolicyStoreId::new("ps-schema");
        let state = StoreState {
            schema: Some("{\"Acme\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let output = format_status(&id, &state);
        assert!(output.contains("Schema: present"));
        assert!(output.contains("{\"Acme\":{}}"));
        assert!(output.contains("Templates: 0"));
        assert!(output.contains("Policies: 0"));
    }

    // --- format_status: store with templates and policies ---

    #[test]
    fn format_status_with_templates_and_policies() {
        let id = PolicyStoreId::new("ps-full");
        let state = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("ReadOnly".to_string()),
                description: Some("Read-only access template".to_string()),
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![
                StorePolicy {
                    id: "pol-1".to_string(),
                    name: Some("AdminAccess".to_string()),
                    description: None,
                    statement: "permit(principal, action, resource);".to_string(),
                },
                StorePolicy {
                    id: "pol-2".to_string(),
                    name: None,
                    description: Some("A nameless policy".to_string()),
                    statement: "forbid(principal, action, resource);".to_string(),
                },
            ],
        };
        let output = format_status(&id, &state);
        assert!(output.contains("Policy Store: ps-full"));
        assert!(output.contains("Schema: present"));
        assert!(output.contains("Templates: 1"));
        assert!(output.contains("- ReadOnly"));
        assert!(output.contains("Read-only access template"));
        assert!(output.contains("permit(principal == ?principal"));
        assert!(output.contains("Policies: 2"));
        assert!(output.contains("- AdminAccess"));
        assert!(output.contains("permit(principal, action, resource)"));
        // pol-2 has no name, should fall back to id
        assert!(output.contains("- pol-2"));
        assert!(output.contains("A nameless policy"));
        assert!(output.contains("forbid(principal, action, resource)"));
    }

    // --- CedarSyncConfig deserialization ---

    #[test]
    fn parse_minimal_config() {
        let toml_str = r#"
policy_store_id = "ps-123"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policy_store_id, "ps-123");
        assert!(config.schema.is_none());
        assert!(config.tenant.is_none());
        assert!(config.policies.is_empty());
        assert!(config.templates.is_empty());
    }

    #[test]
    fn parse_config_with_schema() {
        let toml_str = r#"
policy_store_id = "ps-456"

[schema]
path = "schema.cedarschema"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policy_store_id, "ps-456");
        let schema = config.schema.unwrap();
        assert_eq!(schema.path, "schema.cedarschema");
    }

    // --- TenantConfig defaults ---

    #[test]
    fn tenant_config_defaults() {
        let toml_str = r#"
policy_store_id = "ps-t"

[tenant]
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        let tenant = config.tenant.unwrap();
        assert!(tenant.enabled);
        assert_eq!(tenant.principal_attribute, "tenant_id");
        assert_eq!(tenant.resource_attribute, "tenant_id");
    }

    #[test]
    fn tenant_config_custom() {
        let toml_str = r#"
policy_store_id = "ps-t"

[tenant]
enabled = false
principal_attribute = "org_id"
resource_attribute = "org_id"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        let tenant = config.tenant.unwrap();
        assert!(!tenant.enabled);
        assert_eq!(tenant.principal_attribute, "org_id");
        assert_eq!(tenant.resource_attribute, "org_id");
    }

    #[test]
    fn tenant_config_default_impl() {
        let tenant = TenantConfig::default();
        assert!(tenant.enabled);
        assert_eq!(tenant.principal_attribute, "tenant_id");
        assert_eq!(tenant.resource_attribute, "tenant_id");
    }

    // --- PolicyEntry deserialization ---

    #[test]
    fn parse_rbac_policy_explicit_type() {
        let toml_str = r#"
policy_store_id = "ps-r"

[[policies]]
type = "rbac"
name = "admin"
description = "Full access."
inherits = ["viewer"]
allow = ["todo:list:create", "todo:list:delete"]
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policies.len(), 1);
        match &config.policies[0] {
            PolicyEntry::Rbac {
                name,
                description,
                inherits,
                allow,
                tenant_scoped,
            } => {
                assert_eq!(name, "admin");
                assert_eq!(description.as_deref(), Some("Full access."));
                assert_eq!(inherits, &["viewer"]);
                assert_eq!(allow, &["todo:list:create", "todo:list:delete"]);
                assert!(*tenant_scoped);
            }
            _ => panic!("expected Rbac variant"),
        }
    }

    #[test]
    fn parse_rbac_policy_default_type() {
        let toml_str = r#"
policy_store_id = "ps-d"

[[policies]]
name = "viewer"
allow = ["todo:list:read"]
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policies.len(), 1);
        match &config.policies[0] {
            PolicyEntry::Rbac {
                name,
                description,
                inherits,
                allow,
                tenant_scoped,
            } => {
                assert_eq!(name, "viewer");
                assert!(description.is_none());
                assert!(inherits.is_empty());
                assert_eq!(allow, &["todo:list:read"]);
                assert!(*tenant_scoped);
            }
            _ => panic!("expected Rbac variant when type is omitted"),
        }
    }

    #[test]
    fn parse_rbac_policy_tenant_scoped_false() {
        let toml_str = r#"
policy_store_id = "ps-ts"

[[policies]]
name = "global-reader"
allow = ["todo:list:list"]
tenant_scoped = false
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        match &config.policies[0] {
            PolicyEntry::Rbac { tenant_scoped, .. } => {
                assert!(!*tenant_scoped);
            }
            _ => panic!("expected Rbac variant"),
        }
    }

    #[test]
    fn parse_cedar_policy() {
        let toml_str = r#"
policy_store_id = "ps-c"

[[policies]]
type = "cedar"
name = "deny-all"
description = "Deny everything."
body = "forbid(principal, action, resource);"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policies.len(), 1);
        match &config.policies[0] {
            PolicyEntry::Cedar {
                name,
                description,
                body,
            } => {
                assert_eq!(name, "deny-all");
                assert_eq!(description.as_deref(), Some("Deny everything."));
                assert_eq!(body, "forbid(principal, action, resource);");
            }
            _ => panic!("expected Cedar variant"),
        }
    }

    #[test]
    fn parse_mixed_policies() {
        let toml_str = r#"
policy_store_id = "ps-mix"

[[policies]]
name = "admin"
allow = ["todo:list:create"]

[[policies]]
type = "cedar"
name = "custom"
body = "permit(principal, action, resource);"

[[policies]]
type = "rbac"
name = "viewer"
allow = ["todo:list:read"]
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policies.len(), 3);
        assert!(matches!(&config.policies[0], PolicyEntry::Rbac { name, .. } if name == "admin"));
        assert!(matches!(&config.policies[1], PolicyEntry::Cedar { name, .. } if name == "custom"));
        assert!(matches!(&config.policies[2], PolicyEntry::Rbac { name, .. } if name == "viewer"));
    }

    // --- TemplateEntry deserialization ---

    #[test]
    fn parse_cedar_template() {
        let toml_str = r#"
policy_store_id = "ps-tmpl"

[[templates]]
type = "cedar"
name = "project-access"
description = "Grant access to a specific project."
body = "permit(principal == ?principal, action, resource == ?resource);"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.templates.len(), 1);
        match &config.templates[0] {
            TemplateEntry::Cedar {
                name,
                description,
                body,
            } => {
                assert_eq!(name, "project-access");
                assert_eq!(
                    description.as_deref(),
                    Some("Grant access to a specific project.")
                );
                assert_eq!(
                    body,
                    "permit(principal == ?principal, action, resource == ?resource);"
                );
            }
        }
    }

    // --- build_desired_state ---

    #[test]
    fn build_desired_state_empty() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-e".to_string(),
            schema: None,
            tenant: None,
            policies: vec![],
            templates: vec![],
        };
        let state = build_desired_state(&config, None);
        assert!(state.schema.is_none());
        assert!(state.policies.is_empty());
        assert!(state.templates.is_empty());
    }

    #[test]
    fn build_desired_state_with_schema() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-s".to_string(),
            schema: Some(SchemaConfig {
                path: "schema.cedarschema".to_string(),
            }),
            tenant: None,
            policies: vec![],
            templates: vec![],
        };
        let state = build_desired_state(&config, Some("{\"Ns\":{}}".to_string()));
        assert_eq!(state.schema.as_deref(), Some("{\"Ns\":{}}"));
    }

    #[test]
    fn build_desired_state_skips_rbac_includes_cedar() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-m".to_string(),
            schema: None,
            tenant: None,
            policies: vec![
                PolicyEntry::Rbac {
                    name: "admin".to_string(),
                    description: None,
                    inherits: vec![],
                    allow: vec!["todo:list:create".to_string()],
                    tenant_scoped: true,
                },
                PolicyEntry::Cedar {
                    name: "custom".to_string(),
                    description: Some("Custom policy.".to_string()),
                    body: "forbid(principal, action, resource);".to_string(),
                },
            ],
            templates: vec![],
        };
        let state = build_desired_state(&config, None);
        assert_eq!(state.policies.len(), 1);
        assert_eq!(state.policies[0].name, "custom");
        assert_eq!(
            state.policies[0].description.as_deref(),
            Some("Custom policy.")
        );
        assert_eq!(
            state.policies[0].statement,
            "forbid(principal, action, resource);"
        );
    }

    #[test]
    fn build_desired_state_includes_templates() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-t".to_string(),
            schema: None,
            tenant: None,
            policies: vec![],
            templates: vec![TemplateEntry::Cedar {
                name: "project-access".to_string(),
                description: Some("Access template.".to_string()),
                body: "permit(principal == ?principal, action, resource == ?resource);".to_string(),
            }],
        };
        let state = build_desired_state(&config, None);
        assert_eq!(state.templates.len(), 1);
        assert_eq!(state.templates[0].name, "project-access");
        assert_eq!(
            state.templates[0].description.as_deref(),
            Some("Access template.")
        );
        assert_eq!(
            state.templates[0].statement,
            "permit(principal == ?principal, action, resource == ?resource);"
        );
    }
}
