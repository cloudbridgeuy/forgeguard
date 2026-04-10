use std::collections::HashMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::Deserialize;

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
    pub(crate) tenant: Option<TenantConfig>,
    #[serde(default)]
    pub(crate) policies: Vec<PolicyEntry>,
    #[serde(default)]
    pub(crate) templates: Vec<TemplateEntry>,
}

/// Inline Cedar schema configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct SchemaConfig {
    pub(crate) namespace: String,
    #[serde(default)]
    pub(crate) actions: Vec<String>,
    #[serde(default)]
    pub(crate) entities: HashMap<String, EntityConfig>,
}

/// Entity type configuration within the schema.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct EntityConfig {
    #[serde(default)]
    pub(crate) member_of: Vec<String>,
    #[serde(default)]
    pub(crate) attributes: HashMap<String, AttributeType>,
}

/// Cedar attribute types supported in inline schema definitions.
#[derive(Debug, Clone, Deserialize)]
pub(crate) enum AttributeType {
    #[serde(rename = "String")]
    String,
    #[serde(rename = "Long")]
    Long,
    #[serde(rename = "Boolean")]
    Boolean,
}

impl AttributeType {
    pub(crate) fn as_cedar_type(&self) -> &'static str {
        match self {
            Self::String => "String",
            Self::Long => "Long",
            Self::Boolean => "Boolean",
        }
    }
}

/// Tenant scoping configuration for RBAC policies.
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug)]
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
    fn parse_config_with_schema_namespace_only() {
        let toml_str = r#"
policy_store_id = "ps-456"

[schema]
namespace = "MyApp"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.policy_store_id, "ps-456");
        let schema = config.schema.unwrap();
        assert_eq!(schema.namespace, "MyApp");
        assert!(schema.actions.is_empty());
        assert!(schema.entities.is_empty());
    }

    #[test]
    fn parse_config_with_schema_entities_and_attributes() {
        let toml_str = r#"
policy_store_id = "ps-ent"

[schema]
namespace = "ForgeGuard"
actions = ["proxy-config:read"]

[schema.entities.Organization]

[schema.entities.Machine.attributes]
org_id = "String"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        let schema = config.schema.unwrap();
        assert_eq!(schema.namespace, "ForgeGuard");
        assert_eq!(schema.actions, vec!["proxy-config:read"]);

        // Organization entity: exists with defaults
        let org = &schema.entities["Organization"];
        assert!(org.member_of.is_empty());
        assert!(org.attributes.is_empty());

        // Machine entity: has an attribute
        let machine = &schema.entities["Machine"];
        assert!(machine.member_of.is_empty());
        assert_eq!(machine.attributes.len(), 1);
        assert!(matches!(
            machine.attributes["org_id"],
            AttributeType::String
        ));
    }

    #[test]
    fn parse_schema_with_explicit_actions() {
        let toml_str = r#"
policy_store_id = "ps-act"

[schema]
namespace = "App"
actions = ["read", "write", "delete"]
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        let schema = config.schema.unwrap();
        assert_eq!(schema.actions, vec!["read", "write", "delete"]);
    }

    #[test]
    fn entity_config_defaults() {
        let entity = EntityConfig::default();
        assert!(entity.member_of.is_empty());
        assert!(entity.attributes.is_empty());
    }

    #[test]
    fn attribute_type_deserialization() {
        let toml_str = r#"
policy_store_id = "ps-attr"

[schema]
namespace = "Test"

[schema.entities.Widget.attributes]
name = "String"
count = "Long"
active = "Boolean"
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        let schema = config.schema.unwrap();
        let attrs = &schema.entities["Widget"].attributes;

        assert!(matches!(attrs["name"], AttributeType::String));
        assert!(matches!(attrs["count"], AttributeType::Long));
        assert!(matches!(attrs["active"], AttributeType::Boolean));

        // Verify as_cedar_type returns correct strings
        assert_eq!(attrs["name"].as_cedar_type(), "String");
        assert_eq!(attrs["count"].as_cedar_type(), "Long");
        assert_eq!(attrs["active"].as_cedar_type(), "Boolean");
    }

    #[test]
    fn parse_schema_with_member_of() {
        let toml_str = r#"
policy_store_id = "ps-mem"

[schema]
namespace = "App"

[schema.entities.User]
member_of = ["Group"]

[schema.entities.Group]
"#;
        let config: CedarSyncConfig = toml::from_str(toml_str).unwrap();
        let schema = config.schema.unwrap();
        assert_eq!(schema.entities["User"].member_of, vec!["Group"]);
        assert!(schema.entities["Group"].member_of.is_empty());
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
}
