//! Pure types for the `seed` command configuration.
//!
//! Parsed from `xtask/seed.toml` — defines organizations to seed into
//! DynamoDB along with their RBAC group declarations. Also contains
//! `DynamoTarget`, a pure ADT that parses the CLI flag selecting between
//! prod and local DynamoDB.
//!
//! Each org also declares a `user_schema` and a set of `user` entries
//! (issue #100 V6); the seed provisions those users in Cognito and writes
//! their membership rows. Every seeded org still lands as `OrgStatus::Draft`.

use std::collections::BTreeMap;

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

/// An organization to seed into DynamoDB along with its RBAC groups,
/// user schema, and seeded users.
#[derive(Deserialize, Debug)]
pub(crate) struct SeedOrg {
    org_id: String,
    name: String,
    cognito_user_pool_id: String,
    #[serde(default)]
    user_schema: SeedUserSchema,
    #[serde(default, rename = "user")]
    users: Vec<SeedUser>,
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

    /// Per-org Cognito user pool id (e.g. `us-east-2_AcmeXXXXX`). A public
    /// identifier — stored in `seed.toml`, not 1Password (V6 §2).
    pub(crate) fn cognito_user_pool_id(&self) -> &str {
        &self.cognito_user_pool_id
    }

    pub(crate) fn user_schema(&self) -> &SeedUserSchema {
        &self.user_schema
    }

    pub(crate) fn users(&self) -> &[SeedUser] {
        &self.users
    }

    pub(crate) fn groups(&self) -> &[SeedGroup] {
        &self.groups
    }
}

/// Per-org user-attribute schema declaration.
///
/// Mirrors `forgeguard_authn_core::user_schema::UserSchema` (standard +
/// custom attribute maps). The `seed::pure::seed_user_schema_to_domain`
/// adapter is the only way to turn this into the domain `UserSchema`.
#[derive(Deserialize, Debug, Default)]
pub(crate) struct SeedUserSchema {
    #[serde(default)]
    standard: BTreeMap<String, SeedAttrSpec>,
    #[serde(default)]
    custom: BTreeMap<String, SeedAttrSpec>,
}

impl SeedUserSchema {
    pub(crate) fn standard(&self) -> &BTreeMap<String, SeedAttrSpec> {
        &self.standard
    }

    pub(crate) fn custom(&self) -> &BTreeMap<String, SeedAttrSpec> {
        &self.custom
    }
}

/// A single attribute spec inside a [`SeedUserSchema`].
#[derive(Deserialize, Debug)]
pub(crate) struct SeedAttrSpec {
    #[serde(default)]
    required: bool,
}

impl SeedAttrSpec {
    pub(crate) fn required(&self) -> bool {
        self.required
    }
}

/// A single user to provision: created in the org's Cognito pool, then
/// written as a membership row keyed by the Cognito-issued sub.
#[derive(Deserialize, Debug)]
pub(crate) struct SeedUser {
    email: String,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
}

impl SeedUser {
    pub(crate) fn email(&self) -> &str {
        &self.email
    }

    pub(crate) fn groups(&self) -> &[String] {
        &self.groups
    }

    /// Declared attributes, validated against the org schema before any AWS
    /// call. `email` / `email_verified` are never declared here — they are
    /// forgeguard invariants injected unconditionally during provisioning.
    pub(crate) fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }
}

/// A single RBAC role declaration for a seeded organization.
///
/// Mirrors `forgeguard_authz_core::RbacEntry` 1:1; a `From<&SeedGroup>`-style
/// adapter lives in `seed::pure` and is the only way to produce an `RbacEntry`
/// from this type.
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
cognito_user_pool_id = "us-east-2_acme"

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
allow = ["cp-member-promote-owner"]

[[organization]]
org_id = "org-globex"
name = "Globex Corporation"
cognito_user_pool_id = "us-east-2_globex"
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
cognito_user_pool_id = "us-east-2_acme"

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

#[cfg(test)]
mod seed_toml_v6_shape_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A V6-shaped config mirroring the real `seed.toml`: two orgs, each with
    /// a `name`-required schema and two users carrying a `name` attribute.
    fn v6_config() -> SeedConfig {
        let toml_str = r#"
[[organization]]
org_id               = "org-acme"
name                 = "Acme Corp"
cognito_user_pool_id = "us-east-2_acme"

[organization.user_schema.standard]
name = { required = true }

[[organization.user]]
email      = "admin@acme.test"
groups     = ["admin"]
attributes = { name = "Acme Admin" }

[[organization.user]]
email      = "member@acme.test"
groups     = ["member"]
attributes = { name = "Acme Member" }

[[organization]]
org_id               = "org-globex"
name                 = "Globex Corporation"
cognito_user_pool_id = "us-east-2_globex"

[organization.user_schema.standard]
name = { required = true }

[[organization.user]]
email      = "admin@globex.test"
groups     = ["admin"]
attributes = { name = "Globex Admin" }

[[organization.user]]
email      = "member@globex.test"
groups     = ["member"]
attributes = { name = "Globex Member" }
"#;
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn each_org_has_two_users() {
        let config = v6_config();
        assert_eq!(config.organizations().len(), 2);
        for org in config.organizations() {
            assert_eq!(org.users().len(), 2, "{} should have 2 users", org.org_id());
        }
    }

    #[test]
    fn each_org_declares_required_name_standard_attr() {
        for org in v6_config().organizations() {
            let name_spec = org
                .user_schema()
                .standard()
                .get("name")
                .unwrap_or_else(|| panic!("{} missing `name` standard attr", org.org_id()));
            assert!(
                name_spec.required(),
                "{} `name` must be required",
                org.org_id()
            );
            assert!(
                org.user_schema().custom().is_empty(),
                "{} declares no custom attrs in V6",
                org.org_id()
            );
        }
    }

    #[test]
    fn every_user_has_non_empty_name_attribute() {
        for org in v6_config().organizations() {
            for user in org.users() {
                let name = user
                    .attributes()
                    .get("name")
                    .unwrap_or_else(|| panic!("{} missing `name` attr", user.email()));
                assert!(!name.is_empty(), "{} `name` attr is empty", user.email());
            }
        }
    }

    #[test]
    fn cognito_user_pool_id_is_parsed() {
        let config = v6_config();
        assert_eq!(
            config.organizations()[0].cognito_user_pool_id(),
            "us-east-2_acme"
        );
    }
}
