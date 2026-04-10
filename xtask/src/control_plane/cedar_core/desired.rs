use std::collections::HashSet;

use color_eyre::eyre::{self, Result};

use super::config::{CedarSyncConfig, PolicyEntry, TemplateEntry};
use super::rbac::{compile_rbac_to_cedar, resolve_inherits};

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
/// Cedar policies pass through verbatim. RBAC policies are compiled to
/// Cedar via `compile_rbac_to_cedar` with inheritance resolution.
///
/// Returns an error if two policies share the same name or two templates
/// share the same name.
pub(crate) fn build_desired_state(
    config: &CedarSyncConfig,
    schema_content: Option<String>,
) -> Result<DesiredState> {
    let tenant = config.tenant.clone().unwrap_or_default();

    let mut policies: Vec<DesiredPolicy> = Vec::new();
    for entry in &config.policies {
        match entry {
            PolicyEntry::Cedar {
                name,
                description,
                body,
            } => {
                policies.push(DesiredPolicy {
                    name: name.clone(),
                    description: description.clone(),
                    statement: body.clone(),
                });
            }
            PolicyEntry::Rbac {
                name,
                description,
                tenant_scoped,
                ..
            } => {
                let resolved_actions =
                    resolve_inherits(&config.policies, name).map_err(|e| eyre::eyre!("{e}"))?;
                let statement =
                    compile_rbac_to_cedar(name, &resolved_actions, *tenant_scoped, &tenant)
                        .map_err(|e| eyre::eyre!("{e}"))?;
                policies.push(DesiredPolicy {
                    name: name.clone(),
                    description: description.clone(),
                    statement,
                });
            }
        }
    }

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
    use crate::control_plane::cedar_core::config::{SchemaConfig, TenantConfig};

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
    fn build_desired_state_compiles_rbac_and_includes_cedar() {
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
        assert_eq!(state.policies.len(), 2);

        // RBAC policy is compiled to Cedar.
        assert_eq!(state.policies[0].name, "admin");
        assert!(state.policies[0].statement.contains("group::\"admin\""));
        assert!(state.policies[0]
            .statement
            .contains("Action::\"todo:list:create\""));
        // Default tenant scoping is applied.
        assert!(state.policies[0]
            .statement
            .contains("principal.tenant_id == resource.tenant_id"));

        // Cedar policy passes through verbatim.
        assert_eq!(state.policies[1].name, "custom");
        assert_eq!(
            state.policies[1].description.as_deref(),
            Some("Custom policy.")
        );
        assert_eq!(
            state.policies[1].statement,
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

    #[test]
    fn build_desired_state_rbac_with_inheritance() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-inh".to_string(),
            schema: None,
            tenant: None,
            policies: vec![
                PolicyEntry::Rbac {
                    name: "viewer".to_string(),
                    description: Some("Read-only.".to_string()),
                    inherits: vec![],
                    allow: vec!["todo:list:read".to_string()],
                    tenant_scoped: true,
                },
                PolicyEntry::Rbac {
                    name: "editor".to_string(),
                    description: None,
                    inherits: vec!["viewer".to_string()],
                    allow: vec!["todo:list:write".to_string()],
                    tenant_scoped: true,
                },
            ],
            templates: vec![],
        };
        let state = build_desired_state(&config, None).unwrap();
        assert_eq!(state.policies.len(), 2);

        // viewer: only own action
        assert!(state.policies[0]
            .statement
            .contains("Action::\"todo:list:read\""));
        assert!(!state.policies[0]
            .statement
            .contains("Action::\"todo:list:write\""));

        // editor: own + inherited
        assert!(state.policies[1]
            .statement
            .contains("Action::\"todo:list:write\""));
        assert!(state.policies[1]
            .statement
            .contains("Action::\"todo:list:read\""));
    }

    #[test]
    fn build_desired_state_rbac_with_custom_tenant() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-ct".to_string(),
            schema: None,
            tenant: Some(TenantConfig {
                enabled: true,
                principal_attribute: "org_id".to_string(),
                resource_attribute: "org_id".to_string(),
            }),
            policies: vec![PolicyEntry::Rbac {
                name: "viewer".to_string(),
                description: None,
                inherits: vec![],
                allow: vec!["read".to_string()],
                tenant_scoped: true,
            }],
            templates: vec![],
        };
        let state = build_desired_state(&config, None).unwrap();
        assert!(state.policies[0]
            .statement
            .contains("principal.org_id == resource.org_id"));
    }

    #[test]
    fn build_desired_state_rbac_tenant_disabled() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-td".to_string(),
            schema: None,
            tenant: Some(TenantConfig {
                enabled: false,
                principal_attribute: "tenant_id".to_string(),
                resource_attribute: "tenant_id".to_string(),
            }),
            policies: vec![PolicyEntry::Rbac {
                name: "viewer".to_string(),
                description: None,
                inherits: vec![],
                allow: vec!["read".to_string()],
                tenant_scoped: true,
            }],
            templates: vec![],
        };
        let state = build_desired_state(&config, None).unwrap();
        assert!(!state.policies[0].statement.contains("when"));
    }

    #[test]
    fn build_desired_state_rejects_duplicate_template_names() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-dup-tmpl".to_string(),
            schema: None,
            tenant: None,
            policies: vec![],
            templates: vec![
                TemplateEntry::Cedar {
                    name: "same-tmpl".to_string(),
                    description: None,
                    body: "permit(principal == ?principal, action, resource == ?resource);"
                        .to_string(),
                },
                TemplateEntry::Cedar {
                    name: "same-tmpl".to_string(),
                    description: None,
                    body: "forbid(principal == ?principal, action, resource == ?resource);"
                        .to_string(),
                },
            ],
        };
        let err = build_desired_state(&config, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate template name: 'same-tmpl'"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn build_desired_state_rbac_empty_allow_errors() {
        let config = CedarSyncConfig {
            policy_store_id: "ps-err".to_string(),
            schema: None,
            tenant: None,
            policies: vec![PolicyEntry::Rbac {
                name: "empty".to_string(),
                description: None,
                inherits: vec![],
                allow: vec![],
                tenant_scoped: true,
            }],
            templates: vec![],
        };
        let err = build_desired_state(&config, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty allow list"), "unexpected error: {msg}");
    }
}
