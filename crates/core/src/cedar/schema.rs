//! Cedar JSON schema generation.
//!
//! Pure functions that produce Cedar JSON schemas from policy definitions,
//! qualified actions, and optional entity schema configuration.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use super::compile::{exact_segment, exact_str, is_all_exact};
use crate::permission::Policy;
use crate::{ProjectId, QualifiedAction};

// ---------------------------------------------------------------------------
// EntitySchemaConfig
// ---------------------------------------------------------------------------

/// Configuration for a Cedar entity type's schema properties.
///
/// Defines `memberOf` relationships and typed attributes for an entity type.
/// Used by [`generate_cedar_schema`] to produce richer Cedar JSON schemas.
///
/// This is a pure data type — no I/O. The I/O layer (`forgeguard_http`)
/// constructs these from its own config and passes them down.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntitySchemaConfig {
    /// Entity types this entity can be a member of.
    /// E.g., a `user` entity with `member_of: ["group"]`.
    member_of: Vec<String>,
    /// Typed attributes for this entity type.
    /// Keys are attribute names, values are Cedar type strings
    /// (e.g., `"String"`, `"Long"`, `"Boolean"`).
    attributes: HashMap<String, CedarAttributeType>,
}

impl EntitySchemaConfig {
    /// Create a new `EntitySchemaConfig`.
    pub fn new(member_of: Vec<String>, attributes: HashMap<String, CedarAttributeType>) -> Self {
        Self {
            member_of,
            attributes,
        }
    }

    /// Borrow the `member_of` relationships.
    pub fn member_of(&self) -> &[String] {
        &self.member_of
    }

    /// Borrow the attributes map.
    pub fn attributes(&self) -> &HashMap<String, CedarAttributeType> {
        &self.attributes
    }
}

/// Cedar attribute types supported in schema generation.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum CedarAttributeType {
    /// A Cedar `String` attribute.
    String,
    /// A Cedar `Long` (integer) attribute.
    Long,
    /// A Cedar `Boolean` attribute.
    Boolean,
}

impl CedarAttributeType {
    /// Return the Cedar JSON schema type string.
    fn as_cedar_type(&self) -> &'static str {
        match self {
            Self::String => "String",
            Self::Long => "Long",
            Self::Boolean => "Boolean",
        }
    }
}

impl TryFrom<&str> for CedarAttributeType {
    type Error = crate::Error;

    fn try_from(s: &str) -> crate::Result<Self> {
        match s {
            "String" => Ok(Self::String),
            "Long" => Ok(Self::Long),
            "Boolean" => Ok(Self::Boolean),
            _ => Err(crate::Error::Parse {
                field: "attribute type",
                value: s.to_string(),
                reason: "must be one of: String, Long, Boolean",
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// generate_cedar_schema
// ---------------------------------------------------------------------------

/// Generate a Cedar JSON schema from policies, qualified actions, and
/// optional entity schema configuration.
///
/// Derives entity types from the actions present in policies (and any
/// explicitly provided [`QualifiedAction`]s), adds `user` and `group` IAM
/// entities with `memberOf` relationships, and builds action `appliesTo`
/// blocks.
///
/// When `entity_config` is provided, the generated schema includes:
/// - `memberOfTypes` relationships for configured entity types
/// - typed `attributes` for configured entity types
///
/// # Arguments
///
/// * `policies` — policy definitions whose action patterns contribute entity
///   types and actions to the schema.
/// * `actions` — additional qualified actions to include (e.g., from route
///   definitions). Merged with actions derived from policies.
/// * `project` — the project ID used to derive the Cedar namespace.
/// * `entity_config` — optional per-entity-type configuration for
///   relationships and attributes.
pub fn generate_cedar_schema(
    policies: &[Policy],
    actions: &[QualifiedAction],
    project: &ProjectId,
    entity_config: Option<&HashMap<String, EntitySchemaConfig>>,
) -> String {
    let cedar_ns = crate::CedarNamespace::from_project(project);

    // Collect unique entity types and actions from all policy statements
    let mut entity_types: BTreeSet<String> = BTreeSet::new();
    let mut action_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    // From policies
    for policy in policies {
        for stmt in policy.statements() {
            for ap in stmt.actions() {
                if is_all_exact(ap) {
                    let ns_seg = exact_segment(ap.namespace());
                    let entity_seg = exact_segment(ap.entity());
                    let act = exact_str(ap.action());
                    let entity = exact_str(ap.entity());

                    let ns_ident = ns_seg.to_cedar_ident();
                    let entity_ident = entity_seg.to_cedar_ident();

                    let entity_type = format!("{}__{}", ns_ident.as_str(), entity_ident.as_str());
                    entity_types.insert(entity_type.clone());

                    let ns = exact_str(ap.namespace());
                    let action_id = format!("{ns}-{entity}-{act}");
                    action_map.entry(action_id).or_default().insert(entity_type);
                }
            }
        }
    }

    // From explicit QualifiedActions
    for qa in actions {
        let ns_ident = qa.namespace().as_segment().to_cedar_ident();
        let entity_ident = qa.entity().as_segment().to_cedar_ident();

        let entity_type = format!("{}__{}", ns_ident.as_str(), entity_ident.as_str());
        entity_types.insert(entity_type.clone());

        let action_id = qa.vp_action_id();
        action_map.entry(action_id).or_default().insert(entity_type);
    }

    // Build entity types object
    let mut entity_types_map = serde_json::Map::new();

    // User always has memberOf Group
    entity_types_map.insert(
        "User".to_string(),
        build_entity_type_value("User", Some(&["Group".to_string()]), entity_config),
    );

    // Group always present
    entity_types_map.insert(
        "Group".to_string(),
        build_entity_type_value("Group", None, entity_config),
    );

    // Derived entity types
    for et in &entity_types {
        entity_types_map.insert(et.clone(), build_entity_type_value(et, None, entity_config));
    }

    // Build actions object
    let mut actions_map = serde_json::Map::new();
    for (action_id, resource_types) in &action_map {
        let resource_list: Vec<&str> = resource_types.iter().map(String::as_str).collect();
        actions_map.insert(
            action_id.clone(),
            serde_json::json!({
                "appliesTo": {
                    "principalTypes": ["User", "Group"],
                    "resourceTypes": resource_list,
                }
            }),
        );
    }

    // Assemble the full schema
    let schema = serde_json::json!({
        cedar_ns.as_str(): {
            "entityTypes": serde_json::Value::Object(entity_types_map),
            "actions": serde_json::Value::Object(actions_map),
        }
    });

    serde_json::to_string_pretty(&schema).unwrap_or_default()
}

/// Build the JSON value for a single entity type entry, applying
/// `memberOfTypes` and `attributes` from the config when present.
fn build_entity_type_value(
    entity_name: &str,
    default_member_of: Option<&[String]>,
    entity_config: Option<&HashMap<String, EntitySchemaConfig>>,
) -> serde_json::Value {
    let config = entity_config.and_then(|c| c.get(entity_name));

    // Determine memberOfTypes: config overrides default, but default is
    // merged in (config extends defaults).
    let mut member_of_set: BTreeSet<&str> = BTreeSet::new();
    if let Some(defaults) = default_member_of {
        for m in defaults {
            member_of_set.insert(m.as_str());
        }
    }
    if let Some(cfg) = config {
        for m in &cfg.member_of {
            member_of_set.insert(m.as_str());
        }
    }

    let mut obj = serde_json::Map::new();

    if !member_of_set.is_empty() {
        let member_of_vec: Vec<&str> = member_of_set.into_iter().collect();
        obj.insert(
            "memberOfTypes".to_string(),
            serde_json::json!(member_of_vec),
        );
    }

    // Attributes
    if let Some(cfg) = config {
        if !cfg.attributes.is_empty() {
            let mut shape_attrs = serde_json::Map::new();
            let mut sorted_attrs: Vec<(&String, &CedarAttributeType)> =
                cfg.attributes.iter().collect();
            sorted_attrs.sort_by_key(|(k, _)| k.as_str());

            for (attr_name, attr_type) in sorted_attrs {
                shape_attrs.insert(
                    attr_name.clone(),
                    serde_json::json!({ "type": attr_type.as_cedar_type() }),
                );
            }
            obj.insert(
                "shape".to_string(),
                serde_json::json!({
                    "type": "Record",
                    "attributes": serde_json::Value::Object(shape_attrs),
                }),
            );
        }
    }

    serde_json::Value::Object(obj)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn project() -> ProjectId {
        ProjectId::new("acme-app").unwrap()
    }

    fn make_policy(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    // -- generate_cedar_schema: one exact policy --------------------------------

    #[test]
    fn schema_from_one_exact_policy() {
        let policy = make_policy(
            r#"{
            "name": "todo-viewer",
            "statements": [{"effect": "allow", "actions": ["todo:list:read"]}]
        }"#,
        );
        let schema = generate_cedar_schema(&[policy], &[], &project(), None);
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();

        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();
        assert!(entity_types.contains_key("User"));
        assert!(entity_types.contains_key("Group"));
        assert!(entity_types.contains_key("todo__list"));

        let actions = ns_obj.get("actions").unwrap().as_object().unwrap();
        assert!(actions.contains_key("todo-list-read"));
        let read_list = actions.get("todo-list-read").unwrap();
        let applies_to = read_list.get("appliesTo").unwrap();
        assert_eq!(
            applies_to.get("principalTypes").unwrap(),
            &serde_json::json!(["User", "Group"])
        );
        assert_eq!(
            applies_to.get("resourceTypes").unwrap(),
            &serde_json::json!(["todo__list"])
        );
    }

    // -- generate_cedar_schema: wildcard-only actions are skipped --------------

    #[test]
    fn schema_wildcard_only_actions_skipped() {
        let policy = make_policy(
            r#"{
            "name": "todo-all",
            "statements": [{"effect": "allow", "actions": ["todo:*:*"]}]
        }"#,
        );
        let schema = generate_cedar_schema(&[policy], &[], &project(), None);
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();

        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();
        // Only user and group should be present — no entity types from wildcards
        assert_eq!(entity_types.len(), 2);
        assert!(entity_types.contains_key("User"));
        assert!(entity_types.contains_key("Group"));

        let actions = ns_obj.get("actions").unwrap().as_object().unwrap();
        assert!(actions.is_empty());
    }

    // -- generate_cedar_schema: output is valid JSON --------------------------

    #[test]
    fn schema_output_is_valid_json() {
        let policies = vec![
            make_policy(
                r#"{
                "name": "todo-viewer",
                "statements": [{"effect": "allow", "actions": ["todo:list:read"]}]
            }"#,
            ),
            make_policy(
                r#"{
                "name": "todo-editor",
                "statements": [{"effect": "allow", "actions": ["todo:item:write", "todo:item:delete"]}]
            }"#,
            ),
        ];
        let schema = generate_cedar_schema(&policies, &[], &project(), None);
        let parsed = serde_json::from_str::<serde_json::Value>(&schema);
        assert!(parsed.is_ok(), "schema output must be valid JSON: {schema}");
    }

    // -- generate_cedar_schema: empty inputs produce user/group only ----------

    #[test]
    fn schema_empty_inputs_produce_user_group_only() {
        let schema = generate_cedar_schema(&[], &[], &project(), None);
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();

        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();
        assert_eq!(entity_types.len(), 2);
        assert!(entity_types.contains_key("User"));
        assert!(entity_types.contains_key("Group"));

        // User always has memberOfTypes: ["Group"]
        let user_obj = entity_types.get("User").unwrap();
        assert_eq!(
            user_obj.get("memberOfTypes").unwrap(),
            &serde_json::json!(["Group"])
        );

        let actions = ns_obj.get("actions").unwrap().as_object().unwrap();
        assert!(actions.is_empty());
    }

    // -- generate_cedar_schema: from QualifiedActions -------------------------

    #[test]
    fn schema_from_qualified_actions() {
        let qa1 = QualifiedAction::parse("todo:list:read").unwrap();
        let qa2 = QualifiedAction::parse("todo:item:write").unwrap();

        let schema = generate_cedar_schema(&[], &[qa1, qa2], &project(), None);
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();

        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();
        assert!(entity_types.contains_key("todo__list"));
        assert!(entity_types.contains_key("todo__item"));
        assert!(entity_types.contains_key("User"));
        assert!(entity_types.contains_key("Group"));

        let actions = ns_obj.get("actions").unwrap().as_object().unwrap();
        assert!(actions.contains_key("todo-list-read"));
        assert!(actions.contains_key("todo-item-write"));
    }

    // -- generate_cedar_schema: policies + actions merge ----------------------

    #[test]
    fn schema_policies_and_actions_merge() {
        let policy = make_policy(
            r#"{
            "name": "todo-viewer",
            "statements": [{"effect": "allow", "actions": ["todo:list:read"]}]
        }"#,
        );
        let qa = QualifiedAction::parse("todo:item:write").unwrap();

        let schema = generate_cedar_schema(&[policy], &[qa], &project(), None);
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();

        let actions = ns_obj.get("actions").unwrap().as_object().unwrap();
        assert!(actions.contains_key("todo-list-read"), "from policy");
        assert!(
            actions.contains_key("todo-item-write"),
            "from QualifiedAction"
        );
    }

    // -- generate_cedar_schema: entity relationships (member_of) --------------

    #[test]
    fn schema_with_entity_member_of() {
        let qa = QualifiedAction::parse("todo:item:read").unwrap();

        let mut config = HashMap::new();
        config.insert(
            "todo__item".to_string(),
            EntitySchemaConfig::new(vec!["todo__list".to_string()], HashMap::new()),
        );

        let schema = generate_cedar_schema(&[], &[qa], &project(), Some(&config));
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();
        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();

        let item = entity_types.get("todo__item").unwrap();
        assert_eq!(
            item.get("memberOfTypes").unwrap(),
            &serde_json::json!(["todo__list"])
        );
    }

    // -- generate_cedar_schema: entity attributes -----------------------------

    #[test]
    fn schema_with_entity_attributes() {
        let qa = QualifiedAction::parse("todo:item:read").unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), CedarAttributeType::String);
        attrs.insert("priority".to_string(), CedarAttributeType::Long);
        attrs.insert("completed".to_string(), CedarAttributeType::Boolean);

        let mut config = HashMap::new();
        config.insert(
            "todo__item".to_string(),
            EntitySchemaConfig::new(vec![], attrs),
        );

        let schema = generate_cedar_schema(&[], &[qa], &project(), Some(&config));
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();
        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();

        let item = entity_types.get("todo__item").unwrap();
        let shape = item.get("shape").unwrap();
        assert_eq!(shape.get("type").unwrap(), "Record");

        let shape_attrs = shape.get("attributes").unwrap().as_object().unwrap();
        assert_eq!(
            shape_attrs.get("title").unwrap(),
            &serde_json::json!({"type": "String"})
        );
        assert_eq!(
            shape_attrs.get("priority").unwrap(),
            &serde_json::json!({"type": "Long"})
        );
        assert_eq!(
            shape_attrs.get("completed").unwrap(),
            &serde_json::json!({"type": "Boolean"})
        );
    }

    // -- generate_cedar_schema: user config extends defaults ------------------

    #[test]
    fn schema_user_config_extends_default_member_of() {
        let mut config = HashMap::new();
        config.insert(
            "User".to_string(),
            EntitySchemaConfig::new(vec!["team".to_string()], HashMap::new()),
        );

        let schema = generate_cedar_schema(&[], &[], &project(), Some(&config));
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();
        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();

        let user = entity_types.get("User").unwrap();
        let member_of = user.get("memberOfTypes").unwrap().as_array().unwrap();
        // Should contain both the default "Group" and the configured "team"
        let member_of_strs: Vec<&str> = member_of.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(member_of_strs.contains(&"Group"), "default Group preserved");
        assert!(member_of_strs.contains(&"team"), "config team added");
    }

    // -- generate_cedar_schema: combined member_of + attributes ---------------

    #[test]
    fn schema_with_member_of_and_attributes() {
        let qa = QualifiedAction::parse("todo:item:read").unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("status".to_string(), CedarAttributeType::String);

        let mut config = HashMap::new();
        config.insert(
            "todo__item".to_string(),
            EntitySchemaConfig::new(vec!["todo__list".to_string()], attrs),
        );

        let schema = generate_cedar_schema(&[], &[qa], &project(), Some(&config));
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();

        let ns = crate::CedarNamespace::from_project(&project());
        let ns_obj = parsed.get(ns.as_str()).unwrap().as_object().unwrap();
        let entity_types = ns_obj.get("entityTypes").unwrap().as_object().unwrap();

        let item = entity_types.get("todo__item").unwrap();
        // Has memberOfTypes
        assert_eq!(
            item.get("memberOfTypes").unwrap(),
            &serde_json::json!(["todo__list"])
        );
        // Has shape with attributes
        let shape = item.get("shape").unwrap();
        let shape_attrs = shape.get("attributes").unwrap().as_object().unwrap();
        assert!(shape_attrs.contains_key("status"));
    }

    // -- EntitySchemaConfig accessors -----------------------------------------

    #[test]
    fn entity_schema_config_accessors() {
        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), CedarAttributeType::String);

        let config = EntitySchemaConfig::new(vec!["parent".to_string()], attrs.clone());
        assert_eq!(config.member_of(), &["parent".to_string()]);
        assert_eq!(config.attributes().len(), 1);
        assert_eq!(
            config.attributes().get("name").unwrap(),
            &CedarAttributeType::String
        );
    }

    // -- CedarAttributeType as_cedar_type -------------------------------------

    #[test]
    fn cedar_attribute_type_strings() {
        assert_eq!(CedarAttributeType::String.as_cedar_type(), "String");
        assert_eq!(CedarAttributeType::Long.as_cedar_type(), "Long");
        assert_eq!(CedarAttributeType::Boolean.as_cedar_type(), "Boolean");
    }
}
