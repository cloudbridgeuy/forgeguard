use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::config::SchemaConfig;

/// Generate Cedar JSON schema from inline config and collected RBAC actions.
///
/// Always includes `User` (memberOfTypes: `["Group"]`) and `Group`.
/// Entity types come from `config.entities`.
/// Actions = union of `config.actions` (explicit) + `rbac_actions` (auto-collected),
/// deduplicated and sorted.
/// Each action gets an `appliesTo` block listing all entity types as both
/// `principalTypes` and `resourceTypes` so VP can validate policies/templates.
///
/// Output is under `config.namespace` as the top-level JSON key.
pub(crate) fn generate_schema_json(config: &SchemaConfig, rbac_actions: &[String]) -> String {
    // --- Entity types (BTreeMap for deterministic output) ---
    let mut entity_types: BTreeMap<&str, serde_json::Value> = BTreeMap::new();

    // Always include User with memberOfTypes: ["Group"]
    entity_types.insert("User", json!({ "memberOfTypes": ["Group"] }));

    // Always include Group
    entity_types.insert("Group", json!({}));

    // Add entities from config, merging with hardcoded User/Group if needed.
    for (name, entity_config) in &config.entities {
        // Build the memberOfTypes list: for User, merge config member_of with
        // the hardcoded ["Group"]; for others, use config as-is.
        let member_of: BTreeSet<&str> = if name == "User" {
            let mut set: BTreeSet<&str> = BTreeSet::new();
            set.insert("Group");
            for m in &entity_config.member_of {
                set.insert(m.as_str());
            }
            set
        } else {
            entity_config.member_of.iter().map(|m| m.as_str()).collect()
        };

        let mut entry = serde_json::Map::new();

        if !member_of.is_empty() {
            let sorted: Vec<&str> = member_of.into_iter().collect();
            entry.insert("memberOfTypes".to_string(), json!(sorted));
        }

        if !entity_config.attributes.is_empty() {
            let mut attrs = BTreeMap::new();
            for (attr_name, attr_type) in &entity_config.attributes {
                attrs.insert(
                    attr_name.as_str(),
                    json!({ "type": attr_type.as_cedar_type() }),
                );
            }
            entry.insert(
                "shape".to_string(),
                json!({
                    "type": "Record",
                    "attributes": attrs,
                }),
            );
        }

        entity_types.insert(name.as_str(), serde_json::Value::Object(entry));
    }

    // --- Actions (BTreeSet for dedup + sort, BTreeMap for output) ---
    let mut all_actions: BTreeSet<&str> = BTreeSet::new();
    for action in &config.actions {
        all_actions.insert(action.as_str());
    }
    for action in rbac_actions {
        all_actions.insert(action.as_str());
    }

    // Collect all entity type names for the appliesTo block.
    let entity_type_names: Vec<&str> = entity_types.keys().copied().collect();

    let actions: BTreeMap<&str, serde_json::Value> = all_actions
        .iter()
        .map(|a| {
            (
                *a,
                json!({
                    "appliesTo": {
                        "principalTypes": &entity_type_names,
                        "resourceTypes": &entity_type_names,
                    }
                }),
            )
        })
        .collect();

    // --- Assemble top-level structure ---
    let schema = json!({
        &config.namespace: {
            "entityTypes": entity_types,
            "actions": actions,
        }
    });

    serde_json::to_string_pretty(&schema).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::control_plane::cedar_core::config::{AttributeType, EntityConfig};

    fn minimal_config(namespace: &str) -> SchemaConfig {
        SchemaConfig {
            namespace: namespace.to_string(),
            actions: vec![],
            entities: HashMap::new(),
        }
    }

    #[test]
    fn empty_config_produces_user_and_group_only() {
        let config = minimal_config("TestNs");
        let json_str = generate_schema_json(&config, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let ns = &parsed["TestNs"];
        let entity_types = &ns["entityTypes"];

        // User always present with memberOfTypes: ["Group"]
        assert_eq!(entity_types["User"]["memberOfTypes"], json!(["Group"]));

        // Group always present
        assert_eq!(entity_types["Group"], json!({}));

        // No actions
        assert_eq!(ns["actions"], json!({}));
    }

    #[test]
    fn config_with_entities_member_of_and_attributes() {
        let mut entities = HashMap::new();
        entities.insert("Organization".to_string(), EntityConfig::default());
        entities.insert(
            "Machine".to_string(),
            EntityConfig {
                member_of: vec![],
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert("org_id".to_string(), AttributeType::String);
                    attrs
                },
            },
        );

        let config = SchemaConfig {
            namespace: "ForgeGuard".to_string(),
            actions: vec![],
            entities,
        };

        let json_str = generate_schema_json(&config, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let entity_types = &parsed["ForgeGuard"]["entityTypes"];

        // Organization: empty object
        assert_eq!(entity_types["Organization"], json!({}));

        // Machine: has shape with attributes
        assert_eq!(entity_types["Machine"]["shape"]["type"], json!("Record"));
        assert_eq!(
            entity_types["Machine"]["shape"]["attributes"]["org_id"]["type"],
            json!("String")
        );

        // User and Group still present
        assert_eq!(entity_types["User"]["memberOfTypes"], json!(["Group"]));
        assert_eq!(entity_types["Group"], json!({}));
    }

    #[test]
    fn actions_merged_from_rbac_and_explicit() {
        let config = SchemaConfig {
            namespace: "App".to_string(),
            actions: vec!["proxy-config:read".to_string(), "admin:manage".to_string()],
            entities: HashMap::new(),
        };

        let rbac_actions = vec![
            "todo:list:read".to_string(),
            "todo:list:create".to_string(),
            "proxy-config:read".to_string(), // duplicate with explicit
        ];

        let json_str = generate_schema_json(&config, &rbac_actions);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let actions = parsed["App"]["actions"].as_object().unwrap();

        // All unique actions present (4 unique from 5 total)
        assert_eq!(actions.len(), 4);
        assert!(actions.contains_key("admin:manage"));
        assert!(actions.contains_key("proxy-config:read"));
        assert!(actions.contains_key("todo:list:create"));
        assert!(actions.contains_key("todo:list:read"));

        // Each action has appliesTo with principalTypes and resourceTypes
        for (_, v) in actions {
            assert!(v.get("appliesTo").is_some());
            assert!(v["appliesTo"]["principalTypes"].is_array());
            assert!(v["appliesTo"]["resourceTypes"].is_array());
        }
    }

    #[test]
    fn attribute_type_cedar_strings() {
        assert_eq!(AttributeType::String.as_cedar_type(), "String");
        assert_eq!(AttributeType::Long.as_cedar_type(), "Long");
        assert_eq!(AttributeType::Boolean.as_cedar_type(), "Boolean");
    }

    #[test]
    fn full_integration_example() {
        let mut entities = HashMap::new();
        entities.insert("Organization".to_string(), EntityConfig::default());
        entities.insert(
            "Machine".to_string(),
            EntityConfig {
                member_of: vec![],
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert("org_id".to_string(), AttributeType::String);
                    attrs
                },
            },
        );

        let config = SchemaConfig {
            namespace: "ForgeGuard".to_string(),
            actions: vec!["proxy-config:read".to_string()],
            entities,
        };

        let rbac_actions = vec![
            "org:create".to_string(),
            "proxy-config:read".to_string(), // dup
        ];

        let json_str = generate_schema_json(&config, &rbac_actions);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Namespace key
        assert!(parsed.get("ForgeGuard").is_some());

        let ns = &parsed["ForgeGuard"];

        // Entity types: User, Group, Organization, Machine (4 total)
        let entity_types = ns["entityTypes"].as_object().unwrap();
        assert_eq!(entity_types.len(), 4);

        // Actions: org:create, proxy-config:read (2 unique)
        let actions = ns["actions"].as_object().unwrap();
        assert_eq!(actions.len(), 2);
        assert!(actions.contains_key("org:create"));
        assert!(actions.contains_key("proxy-config:read"));
    }

    #[test]
    fn deterministic_output() {
        let mut entities = HashMap::new();
        entities.insert("Zebra".to_string(), EntityConfig::default());
        entities.insert("Apple".to_string(), EntityConfig::default());

        let config = SchemaConfig {
            namespace: "Det".to_string(),
            actions: vec!["z-action".to_string(), "a-action".to_string()],
            entities,
        };

        let rbac_actions = vec!["m-action".to_string()];

        let first = generate_schema_json(&config, &rbac_actions);
        let second = generate_schema_json(&config, &rbac_actions);
        assert_eq!(first, second);
    }

    #[test]
    fn entity_with_member_of() {
        let mut entities = HashMap::new();
        entities.insert(
            "Team".to_string(),
            EntityConfig {
                member_of: vec!["Organization".to_string()],
                attributes: HashMap::new(),
            },
        );

        let config = SchemaConfig {
            namespace: "App".to_string(),
            actions: vec![],
            entities,
        };

        let json_str = generate_schema_json(&config, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(
            parsed["App"]["entityTypes"]["Team"]["memberOfTypes"],
            json!(["Organization"])
        );
    }

    #[test]
    fn entity_with_multiple_attribute_types() {
        let mut entities = HashMap::new();
        entities.insert(
            "Widget".to_string(),
            EntityConfig {
                member_of: vec![],
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert("name".to_string(), AttributeType::String);
                    attrs.insert("count".to_string(), AttributeType::Long);
                    attrs.insert("active".to_string(), AttributeType::Boolean);
                    attrs
                },
            },
        );

        let config = SchemaConfig {
            namespace: "Factory".to_string(),
            actions: vec![],
            entities,
        };

        let json_str = generate_schema_json(&config, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let attrs = &parsed["Factory"]["entityTypes"]["Widget"]["shape"]["attributes"];
        assert_eq!(attrs["name"]["type"], json!("String"));
        assert_eq!(attrs["count"]["type"], json!("Long"));
        assert_eq!(attrs["active"]["type"], json!("Boolean"));
    }

    #[test]
    fn config_user_without_member_of_preserves_hardcoded_group() {
        let mut entities = HashMap::new();
        entities.insert(
            "User".to_string(),
            EntityConfig {
                member_of: vec![],
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert("email".to_string(), AttributeType::String);
                    attrs
                },
            },
        );

        let config = SchemaConfig {
            namespace: "Merge".to_string(),
            actions: vec![],
            entities,
        };

        let json_str = generate_schema_json(&config, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let user = &parsed["Merge"]["entityTypes"]["User"];

        // Hardcoded memberOfTypes: ["Group"] must be preserved even though
        // the config-defined User has an empty member_of list.
        assert_eq!(user["memberOfTypes"], json!(["Group"]));

        // Config-defined attributes are still present.
        assert_eq!(
            user["shape"]["attributes"]["email"]["type"],
            json!("String")
        );
    }

    #[test]
    fn config_user_with_extra_member_of_merges_with_group() {
        let mut entities = HashMap::new();
        entities.insert(
            "User".to_string(),
            EntityConfig {
                member_of: vec!["Team".to_string()],
                attributes: HashMap::new(),
            },
        );

        let config = SchemaConfig {
            namespace: "MergePlus".to_string(),
            actions: vec![],
            entities,
        };

        let json_str = generate_schema_json(&config, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let user = &parsed["MergePlus"]["entityTypes"]["User"];

        // Must contain both "Group" (hardcoded) and "Team" (from config), sorted.
        assert_eq!(user["memberOfTypes"], json!(["Group", "Team"]));
    }
}
