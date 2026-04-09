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

// ---------------------------------------------------------------------------
// Sync plan (pure diff engine)
// ---------------------------------------------------------------------------

/// A planned sync action.
pub(crate) enum SyncAction {
    PutSchema(String),
    CreateTemplate(DesiredTemplate),
    DeleteTemplate {
        id: String,
        /// Used by V5 dry-run formatting.
        #[allow(dead_code)]
        name: Option<String>,
    },
    CreatePolicy(DesiredPolicy),
    DeletePolicy {
        id: String,
        /// Used by V5 dry-run formatting.
        #[allow(dead_code)]
        name: Option<String>,
    },
}

impl SyncAction {
    /// Sort key for deterministic execution order.
    ///
    /// Schema first (0), then creates (templates 1, policies 2), then
    /// deletes (policies 3, templates 4). This ensures the schema exists
    /// before templates/policies reference it, and deletes happen after
    /// creates so we never leave the store in a broken intermediate state.
    fn sort_key(&self) -> u8 {
        match self {
            Self::PutSchema(_) => 0,
            Self::CreateTemplate(_) => 1,
            Self::CreatePolicy(_) => 2,
            Self::DeletePolicy { .. } => 3,
            Self::DeleteTemplate { .. } => 4,
        }
    }
}

/// The complete sync plan.
pub(crate) struct SyncPlan {
    pub(crate) actions: Vec<SyncAction>,
}

impl SyncPlan {
    pub(crate) fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Compute a sync plan by diffing desired state against current VP state.
///
/// This is a pure function with no I/O. The plan describes what changes are
/// needed to bring the VP store into alignment with the desired state.
pub(crate) fn compute_sync_plan(desired: &DesiredState, current: &StoreState) -> SyncPlan {
    let mut actions = Vec::new();

    // --- Schema ---
    if let Some(desired_schema) = &desired.schema {
        let needs_put = match &current.schema {
            Some(current_schema) => desired_schema.trim() != current_schema.trim(),
            None => true,
        };
        if needs_put {
            actions.push(SyncAction::PutSchema(desired_schema.clone()));
        }
    }

    // --- Templates ---
    let template_diffs = diff_by_name(
        &desired.templates,
        &current.templates,
        |d| (&d.name, &d.statement),
        |s| (s.name.as_deref(), &s.id, &s.statement),
    );
    for diff in template_diffs {
        match diff {
            DiffAction::Create(idx) => {
                actions.push(SyncAction::CreateTemplate(clone_desired_template(
                    &desired.templates[idx],
                )));
            }
            DiffAction::Delete { id, name } => {
                actions.push(SyncAction::DeleteTemplate { id, name });
            }
        }
    }

    // --- Policies ---
    let policy_diffs = diff_by_name(
        &desired.policies,
        &current.policies,
        |d| (&d.name, &d.statement),
        |s| (s.name.as_deref(), &s.id, &s.statement),
    );
    for diff in policy_diffs {
        match diff {
            DiffAction::Create(idx) => {
                actions.push(SyncAction::CreatePolicy(clone_desired_policy(
                    &desired.policies[idx],
                )));
            }
            DiffAction::Delete { id, name } => {
                actions.push(SyncAction::DeletePolicy { id, name });
            }
        }
    }

    // Sort by execution order.
    actions.sort_by_key(|a| a.sort_key());

    SyncPlan { actions }
}

/// Internal diff result — either create a desired item (by index) or delete
/// a current item (by id).
enum DiffAction {
    Create(usize),
    Delete { id: String, name: Option<String> },
}

/// Generic diff-by-name for templates and policies.
///
/// Returns a list of `DiffAction`s. The caller maps them to `SyncAction`s.
fn diff_by_name<D, C>(
    desired_items: &[D],
    current_items: &[C],
    desired_fields: impl Fn(&D) -> (&str, &str),
    current_fields: impl Fn(&C) -> (Option<&str>, &str, &str),
) -> Vec<DiffAction> {
    use std::collections::{HashMap, HashSet};

    let mut results = Vec::new();

    // Index current items by name (skip unnamed ones).
    let mut current_by_name: HashMap<&str, Vec<(usize, &C)>> = HashMap::new();
    let mut unnamed_current: Vec<&C> = Vec::new();

    for (i, item) in current_items.iter().enumerate() {
        let (name, _, _) = current_fields(item);
        if let Some(n) = name {
            current_by_name.entry(n).or_default().push((i, item));
        } else {
            unnamed_current.push(item);
        }
    }

    // Track which current names we've matched.
    let mut matched_names: HashSet<&str> = HashSet::new();

    for (desired_idx, desired_item) in desired_items.iter().enumerate() {
        let (d_name, d_statement) = desired_fields(desired_item);

        if let Some(current_matches) = current_by_name.get(d_name) {
            matched_names.insert(d_name);

            // Check if any current item with this name has the same statement.
            let has_exact_match = current_matches.iter().any(|(_, c)| {
                let (_, _, c_statement) = current_fields(c);
                d_statement.trim() == c_statement.trim()
            });

            if has_exact_match {
                // Idempotent: no action needed.
                continue;
            }

            // Content differs: delete all current items with this name, then create.
            for (_, c) in current_matches {
                let (c_name, c_id, _) = current_fields(c);
                results.push(DiffAction::Delete {
                    id: c_id.to_string(),
                    name: c_name.map(String::from),
                });
            }
            results.push(DiffAction::Create(desired_idx));
        } else {
            // Not in current: create.
            results.push(DiffAction::Create(desired_idx));
        }
    }

    // Delete current named items not in desired.
    for (name, items) in &current_by_name {
        if !matched_names.contains(name) {
            for (_, c) in items {
                let (c_name, c_id, _) = current_fields(c);
                results.push(DiffAction::Delete {
                    id: c_id.to_string(),
                    name: c_name.map(String::from),
                });
            }
        }
    }

    // Delete unnamed current items (we can't match them to anything desired).
    for c in &unnamed_current {
        let (c_name, c_id, _) = current_fields(c);
        results.push(DiffAction::Delete {
            id: c_id.to_string(),
            name: c_name.map(String::from),
        });
    }

    results
}

fn clone_desired_template(t: &DesiredTemplate) -> DesiredTemplate {
    DesiredTemplate {
        name: t.name.clone(),
        description: t.description.clone(),
        statement: t.statement.clone(),
    }
}

fn clone_desired_policy(p: &DesiredPolicy) -> DesiredPolicy {
    DesiredPolicy {
        name: p.name.clone(),
        description: p.description.clone(),
        statement: p.statement.clone(),
    }
}

// ---------------------------------------------------------------------------
// Sync result + summary (pure formatting)
// ---------------------------------------------------------------------------

/// Outcome counters from applying a sync plan.
pub(crate) struct SyncResult {
    pub(crate) schema_updated: bool,
    pub(crate) created_templates: u32,
    pub(crate) deleted_templates: u32,
    pub(crate) created_policies: u32,
    pub(crate) deleted_policies: u32,
}

/// Format a human-readable summary of sync results.
pub(crate) fn format_summary(result: &SyncResult) -> String {
    let all_zero = !result.schema_updated
        && result.created_templates == 0
        && result.deleted_templates == 0
        && result.created_policies == 0
        && result.deleted_policies == 0;

    if all_zero {
        return "No changes.".to_string();
    }

    let mut out = String::new();

    let schema_status = if result.schema_updated {
        "updated"
    } else {
        "unchanged"
    };
    let _ = writeln!(out, "Schema: {schema_status}");
    let _ = writeln!(
        out,
        "Templates: {} created, {} deleted",
        result.created_templates, result.deleted_templates
    );
    let _ = write!(
        out,
        "Policies: {} created, {} deleted",
        result.created_policies, result.deleted_policies
    );

    out
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

    // =========================================================================
    // compute_sync_plan tests
    // =========================================================================

    /// Helper: count actions by variant.
    fn count_actions(plan: &SyncPlan) -> (usize, usize, usize, usize, usize) {
        let mut put_schema = 0;
        let mut create_tmpl = 0;
        let mut delete_tmpl = 0;
        let mut create_pol = 0;
        let mut delete_pol = 0;
        for action in &plan.actions {
            match action {
                SyncAction::PutSchema(_) => put_schema += 1,
                SyncAction::CreateTemplate(_) => create_tmpl += 1,
                SyncAction::DeleteTemplate { .. } => delete_tmpl += 1,
                SyncAction::CreatePolicy(_) => create_pol += 1,
                SyncAction::DeletePolicy { .. } => delete_pol += 1,
            }
        }
        (put_schema, create_tmpl, delete_tmpl, create_pol, delete_pol)
    }

    // --- Empty desired + empty current ---

    #[test]
    fn sync_plan_empty_both() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    // --- Schema tests ---

    #[test]
    fn sync_plan_new_schema() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (put_schema, ..) = count_actions(&plan);
        assert_eq!(put_schema, 1);
    }

    #[test]
    fn sync_plan_same_schema() {
        let schema = "{\"Ns\":{}}".to_string();
        let desired = DesiredState {
            schema: Some(schema.clone()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some(schema),
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_same_schema_with_whitespace() {
        let desired = DesiredState {
            schema: Some("  {\"Ns\":{}}  ".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_schema() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{\"Entity\":{}}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (put_schema, ..) = count_actions(&plan);
        assert_eq!(put_schema, 1);
    }

    #[test]
    fn sync_plan_no_desired_schema_with_existing() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        // No desired schema means we don't touch the current one.
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    // --- Template tests ---

    #[test]
    fn sync_plan_new_template() {
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "read-access".to_string(),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 1);
        assert_eq!(delete_tmpl, 0);
    }

    #[test]
    fn sync_plan_same_template_idempotent() {
        let stmt = "permit(principal == ?principal, action, resource);".to_string();
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "read-access".to_string(),
                description: None,
                statement: stmt.clone(),
            }],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("read-access".to_string()),
                description: None,
                statement: stmt,
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_template_content() {
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "read-access".to_string(),
                description: None,
                statement: "permit(principal == ?principal, action, resource in ?resource);"
                    .to_string(),
            }],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("read-access".to_string()),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 1);
        assert_eq!(delete_tmpl, 1);
    }

    #[test]
    fn sync_plan_removed_template() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("read-access".to_string()),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 0);
        assert_eq!(delete_tmpl, 1);
    }

    #[test]
    fn sync_plan_unnamed_current_template_deleted() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-orphan".to_string(),
                name: None,
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 0);
        assert_eq!(delete_tmpl, 1);
    }

    // --- Policy tests ---

    #[test]
    fn sync_plan_new_policy() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![DesiredPolicy {
                name: "deny-all".to_string(),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 1);
        assert_eq!(delete_pol, 0);
    }

    #[test]
    fn sync_plan_same_policy_idempotent() {
        let stmt = "forbid(principal, action, resource);".to_string();
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![DesiredPolicy {
                name: "deny-all".to_string(),
                description: None,
                statement: stmt.clone(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("deny-all".to_string()),
                description: None,
                statement: stmt,
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_policy_content() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![DesiredPolicy {
                name: "deny-all".to_string(),
                description: None,
                statement: "forbid(principal, action, resource) when { true };".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("deny-all".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 1);
        assert_eq!(delete_pol, 1);
    }

    #[test]
    fn sync_plan_removed_policy() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("deny-all".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 0);
        assert_eq!(delete_pol, 1);
    }

    #[test]
    fn sync_plan_unnamed_current_policy_deleted() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-orphan".to_string(),
                name: None,
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 0);
        assert_eq!(delete_pol, 1);
    }

    // --- Ordering tests ---

    #[test]
    fn sync_plan_ordering_schema_before_creates_before_deletes() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![DesiredTemplate {
                name: "new-tmpl".to_string(),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![DesiredPolicy {
                name: "new-pol".to_string(),
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-old".to_string(),
                name: Some("old-tmpl".to_string()),
                description: None,
                statement: "forbid(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![StorePolicy {
                id: "pol-old".to_string(),
                name: Some("old-pol".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);

        // Collect sort keys to verify ordering.
        let keys: Vec<u8> = plan.actions.iter().map(|a| a.sort_key()).collect();
        // Must be non-decreasing.
        for window in keys.windows(2) {
            assert!(window[0] <= window[1], "actions not sorted: {keys:?}");
        }

        // Verify we have the expected actions.
        let (put_schema, create_tmpl, delete_tmpl, create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(put_schema, 1);
        assert_eq!(create_tmpl, 1);
        assert_eq!(delete_tmpl, 1);
        assert_eq!(create_pol, 1);
        assert_eq!(delete_pol, 1);
    }

    // --- Mixed scenario ---

    #[test]
    fn sync_plan_mixed_creates_deletes_noop() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![
                // Same as current: no-op
                DesiredTemplate {
                    name: "unchanged-tmpl".to_string(),
                    description: None,
                    statement: "permit(principal == ?principal, action, resource);".to_string(),
                },
                // New: create
                DesiredTemplate {
                    name: "new-tmpl".to_string(),
                    description: Some("Brand new.".to_string()),
                    statement: "permit(principal == ?principal, action, resource in ?resource);"
                        .to_string(),
                },
            ],
            policies: vec![
                // Changed: delete + create
                DesiredPolicy {
                    name: "updated-pol".to_string(),
                    description: None,
                    statement: "permit(principal, action, resource) when { true };".to_string(),
                },
            ],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()), // Same schema: no-op
            templates: vec![
                StoreTemplate {
                    id: "tmpl-1".to_string(),
                    name: Some("unchanged-tmpl".to_string()),
                    description: None,
                    statement: "permit(principal == ?principal, action, resource);".to_string(),
                },
                // Not in desired: delete
                StoreTemplate {
                    id: "tmpl-removed".to_string(),
                    name: Some("removed-tmpl".to_string()),
                    description: None,
                    statement: "forbid(principal == ?principal, action, resource);".to_string(),
                },
            ],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("updated-pol".to_string()),
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
        };

        let plan = compute_sync_plan(&desired, &current);

        let (put_schema, create_tmpl, delete_tmpl, create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(put_schema, 0, "schema unchanged");
        assert_eq!(create_tmpl, 1, "new-tmpl created");
        assert_eq!(delete_tmpl, 1, "removed-tmpl deleted");
        assert_eq!(create_pol, 1, "updated-pol re-created");
        assert_eq!(delete_pol, 1, "updated-pol old version deleted");

        // Verify ordering.
        let keys: Vec<u8> = plan.actions.iter().map(|a| a.sort_key()).collect();
        for window in keys.windows(2) {
            assert!(window[0] <= window[1], "actions not sorted: {keys:?}");
        }
    }

    #[test]
    fn sync_plan_whitespace_trimmed_for_comparison() {
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "tmpl".to_string(),
                description: None,
                statement: "  permit(principal == ?principal, action, resource);  ".to_string(),
            }],
            policies: vec![DesiredPolicy {
                name: "pol".to_string(),
                description: None,
                statement: "  forbid(principal, action, resource);  ".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("tmpl".to_string()),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("pol".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty(), "trimmed statements should match");
    }

    // =========================================================================
    // format_summary tests
    // =========================================================================

    #[test]
    fn format_summary_no_changes() {
        let result = SyncResult {
            schema_updated: false,
            created_templates: 0,
            deleted_templates: 0,
            created_policies: 0,
            deleted_policies: 0,
        };
        assert_eq!(format_summary(&result), "No changes.");
    }

    #[test]
    fn format_summary_schema_only() {
        let result = SyncResult {
            schema_updated: true,
            created_templates: 0,
            deleted_templates: 0,
            created_policies: 0,
            deleted_policies: 0,
        };
        let output = format_summary(&result);
        assert!(output.contains("Schema: updated"));
        assert!(output.contains("Templates: 0 created, 0 deleted"));
        assert!(output.contains("Policies: 0 created, 0 deleted"));
    }

    #[test]
    fn format_summary_mixed() {
        let result = SyncResult {
            schema_updated: false,
            created_templates: 2,
            deleted_templates: 1,
            created_policies: 3,
            deleted_policies: 0,
        };
        let output = format_summary(&result);
        assert!(output.contains("Schema: unchanged"));
        assert!(output.contains("Templates: 2 created, 1 deleted"));
        assert!(output.contains("Policies: 3 created, 0 deleted"));
    }

    #[test]
    fn format_summary_all_changes() {
        let result = SyncResult {
            schema_updated: true,
            created_templates: 1,
            deleted_templates: 2,
            created_policies: 3,
            deleted_policies: 4,
        };
        let output = format_summary(&result);
        assert!(output.contains("Schema: updated"));
        assert!(output.contains("Templates: 1 created, 2 deleted"));
        assert!(output.contains("Policies: 3 created, 4 deleted"));
    }
}
