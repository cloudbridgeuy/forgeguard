//! Pure types for the `seed` command configuration.
//!
//! Parsed from `xtask/seed.toml` — defines organizations to seed into
//! DynamoDB along with their RBAC group declarations. Also contains
//! `DynamoTarget`, a pure ADT that parses the CLI flag selecting between
//! prod and local DynamoDB.
//!
//! User provisioning lives in issue #100 and is not the seed's
//! responsibility — every seeded org lands as `OrgStatus::Draft`.

use serde::Deserialize;

/// Top-level seed configuration.
#[derive(Deserialize, Debug)]
pub(crate) struct SeedConfig {
    #[serde(rename = "organization")]
    organizations: Vec<SeedOrg>,
}

impl SeedConfig {
    pub(crate) fn organizations(&self) -> &[SeedOrg] {
        &self.organizations
    }
}

/// An organization to seed into DynamoDB along with its RBAC groups.
#[derive(Deserialize, Debug)]
pub(crate) struct SeedOrg {
    org_id: String,
    name: String,
    // Consumed by `seed::pure` (Task 3 of the V5 plan) and the group-write
    // shell (Task 5). The transitional shim in `seed.rs` does not yet read it.
    #[allow(dead_code)]
    #[serde(default, rename = "group")]
    groups: Vec<SeedGroup>,
}

impl SeedOrg {
    pub(crate) fn org_id(&self) -> &str {
        &self.org_id
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[allow(dead_code)]
    pub(crate) fn groups(&self) -> &[SeedGroup] {
        &self.groups
    }
}

/// A single RBAC role declaration for a seeded organization.
///
/// Mirrors `forgeguard_authz_core::RbacEntry` 1:1; a `From<&SeedGroup>`-style
/// adapter lives in `seed::pure` and is the only way to produce an `RbacEntry`
/// from this type.
#[allow(dead_code)] // consumed by `seed::pure` (Task 3 of V5 plan)
#[derive(Deserialize, Debug, Clone)]
pub(crate) struct SeedGroup {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    inherits: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default = "default_tenant_scoped")]
    tenant_scoped: bool,
}

fn default_tenant_scoped() -> bool {
    true
}

#[allow(dead_code)] // consumed by `seed::pure` (Task 3 of V5 plan)
impl SeedGroup {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub(crate) fn inherits(&self) -> &[String] {
        &self.inherits
    }

    pub(crate) fn allow(&self) -> &[String] {
        &self.allow
    }

    pub(crate) fn tenant_scoped(&self) -> bool {
        self.tenant_scoped
    }
}

/// Where the seed command should write DynamoDB records.
///
/// `Prod` reads the table name from 1Password (`op://<vault>/dynamodb/table-name`)
/// and hits real AWS. `Local` targets a `dynamodb-local` instance — typically
/// the one started by `cargo xtask control-plane dev` — with an explicit table
/// name.
#[derive(Debug, Clone)]
pub(crate) enum DynamoTarget {
    Prod,
    Local { endpoint: String, table: String },
}

impl DynamoTarget {
    /// Parse CLI flags into a `DynamoTarget`. Both flags must be provided
    /// together or not at all; the boundary is enforced here so downstream
    /// code never sees an inconsistent pair.
    pub(crate) fn from_cli_args(
        endpoint: Option<String>,
        table: Option<String>,
    ) -> Result<Self, String> {
        match (endpoint, table) {
            (None, None) => Ok(Self::Prod),
            (Some(endpoint), Some(table)) => Ok(Self::Local { endpoint, table }),
            (Some(_), None) => {
                Err("--dynamodb-endpoint requires --dynamodb-table".to_string())
            }
            (None, Some(_)) => {
                Err("--dynamodb-table requires --dynamodb-endpoint (prod reads the table name from 1Password)".to_string())
            }
        }
    }
}

#[cfg(test)]
mod dynamo_target_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn prod_when_neither_flag_set() {
        let t = DynamoTarget::from_cli_args(None, None).unwrap();
        assert!(matches!(t, DynamoTarget::Prod), "expected Prod, got {t:?}");
    }

    #[test]
    fn local_when_both_flags_set() {
        let t = DynamoTarget::from_cli_args(
            Some("http://127.0.0.1:8000".into()),
            Some("forgeguard-orgs-dev".into()),
        )
        .unwrap();
        match t {
            DynamoTarget::Local { endpoint, table } => {
                assert_eq!(endpoint, "http://127.0.0.1:8000");
                assert_eq!(table, "forgeguard-orgs-dev");
            }
            DynamoTarget::Prod => panic!("expected Local"),
        }
    }

    #[test]
    fn error_when_endpoint_without_table() {
        let err =
            DynamoTarget::from_cli_args(Some("http://127.0.0.1:8000".into()), None).unwrap_err();
        assert!(err.contains("--dynamodb-table"), "got: {err}");
    }

    #[test]
    fn error_when_table_without_endpoint() {
        let err =
            DynamoTarget::from_cli_args(None, Some("forgeguard-orgs-dev".into())).unwrap_err();
        assert!(err.contains("--dynamodb-endpoint"), "got: {err}");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_seed_config_with_groups() {
        let toml_str = r#"
[[organization]]
org_id = "org-acme"
name = "Acme Corp"

[[organization.group]]
name = "member"
description = "Read-only org access"
allow = ["cp-organization-read"]

[[organization.group]]
name = "admin"
description = "Org management"
inherits = ["member"]
allow = ["cp-organization-update"]

[[organization.group]]
name = "owner"
inherits = ["admin"]
allow = ["cp-organization-delete"]

[[organization]]
org_id = "org-globex"
name = "Globex Corporation"
"#;

        let config: SeedConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.organizations().len(), 2);
        let acme = &config.organizations()[0];
        assert_eq!(acme.org_id(), "org-acme");
        assert_eq!(acme.name(), "Acme Corp");
        assert_eq!(acme.groups().len(), 3);

        let member = &acme.groups()[0];
        assert_eq!(member.name(), "member");
        assert_eq!(member.description(), Some("Read-only org access"));
        assert!(member.inherits().is_empty());
        assert_eq!(member.allow(), &["cp-organization-read"]);
        assert!(member.tenant_scoped(), "tenant_scoped defaults to true");

        let admin = &acme.groups()[1];
        assert_eq!(admin.inherits(), &["member"]);
        assert_eq!(admin.allow(), &["cp-organization-update"]);

        let owner = &acme.groups()[2];
        assert_eq!(owner.inherits(), &["admin"]);
        assert_eq!(owner.description(), None);

        let globex = &config.organizations()[1];
        assert_eq!(globex.org_id(), "org-globex");
        assert!(
            globex.groups().is_empty(),
            "missing [[organization.group]] yields empty Vec via #[serde(default)]"
        );
    }

    #[test]
    fn parse_seed_config_tenant_scoped_explicit_false() {
        let toml_str = r#"
[[organization]]
org_id = "org-acme"
name = "Acme"

[[organization.group]]
name = "global"
allow = ["x:y:z"]
tenant_scoped = false
"#;
        let config: SeedConfig = toml::from_str(toml_str).unwrap();
        let group = &config.organizations()[0].groups()[0];
        assert!(!group.tenant_scoped());
    }
}
