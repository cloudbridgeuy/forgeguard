use std::collections::HashSet;

use color_eyre::eyre::{self, Result};

use super::config::{CedarSyncConfig, PolicyEntry, TemplateEntry};

/// Desired state to sync to VP (compiled from config).
#[derive(Debug)]
pub(crate) struct DesiredState {
    pub(crate) schema: Option<String>,
    pub(crate) templates: Vec<DesiredTemplate>,
    pub(crate) policies: Vec<DesiredPolicy>,
}

/// A Cedar policy template to push to VP.
#[derive(Debug, Clone)]
pub(crate) struct DesiredTemplate {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// A Cedar static policy to push to VP.
#[derive(Debug, Clone)]
pub(crate) struct DesiredPolicy {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// Build desired state from parsed config and schema file content.
///
/// For V2: Cedar policies/templates pass through verbatim.
/// RBAC policies are skipped (added in V4).
///
/// Returns an error if two policies share the same name or two templates
/// share the same name.
pub(crate) fn build_desired_state(
    config: &CedarSyncConfig,
    schema_content: Option<String>,
) -> Result<DesiredState> {
    let policies: Vec<DesiredPolicy> = config
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

    let templates: Vec<DesiredTemplate> = config
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

    // Validate uniqueness of policy names.
    let mut seen = HashSet::new();
    for p in &policies {
        if !seen.insert(&p.name) {
            eyre::bail!("duplicate policy name: '{}'", p.name);
        }
    }

    // Validate uniqueness of template names.
    seen.clear();
    for t in &templates {
        if !seen.insert(&t.name) {
            eyre::bail!("duplicate template name: '{}'", t.name);
        }
    }

    Ok(DesiredState {
        schema: schema_content,
        templates,
        policies,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::control_plane::cedar_core::config::{SchemaConfig, TemplateEntry};

    #[test]
    fn build_desired_state_empty() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-e".to_string(),
            schema: None,
            tenant: None,
            policies: vec![],
            templates: vec![],
        };
        let state = build_desired_state(&config, None).unwrap();
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
        let state = build_desired_state(&config, Some("{\"Ns\":{}}".to_string())).unwrap();
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
        let state = build_desired_state(&config, None).unwrap();
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
        let state = build_desired_state(&config, None).unwrap();
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

    #[test]
    fn build_desired_state_rejects_duplicate_policy_names() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-dup".to_string(),
            schema: None,
            tenant: None,
            policies: vec![
                PolicyEntry::Cedar {
                    name: "same-name".to_string(),
                    description: None,
                    body: "permit(principal, action, resource);".to_string(),
                },
                PolicyEntry::Cedar {
                    name: "same-name".to_string(),
                    description: None,
                    body: "forbid(principal, action, resource);".to_string(),
                },
            ],
            templates: vec![],
        };
        let err = build_desired_state(&config, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate policy name: 'same-name'"),
            "unexpected error: {msg}"
        );
    }
}
