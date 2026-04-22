//! Pure types for the `seed` command configuration.
//!
//! Parsed from `xtask/seed.toml` — defines organizations to seed into
//! DynamoDB and Cognito users to create for testing. Also contains
//! `DynamoTarget`, a pure ADT that parses the CLI flag selecting between
//! prod and local DynamoDB.

use serde::Deserialize;

/// Top-level seed configuration.
#[derive(Deserialize)]
pub(crate) struct SeedConfig {
    #[serde(rename = "organization")]
    organizations: Vec<SeedOrg>,
    #[serde(rename = "user")]
    users: Vec<SeedUser>,
}

impl SeedConfig {
    pub(crate) fn organizations(&self) -> &[SeedOrg] {
        &self.organizations
    }

    pub(crate) fn users(&self) -> &[SeedUser] {
        &self.users
    }
}

/// An organization to seed into DynamoDB.
#[derive(Deserialize)]
pub(crate) struct SeedOrg {
    org_id: String,
    name: String,
}

impl SeedOrg {
    pub(crate) fn org_id(&self) -> &str {
        &self.org_id
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// A Cognito user to create for testing.
///
/// Each user may belong to multiple organizations via [`SeedMembership`].
/// `default_org` is a UI/fixture hint (the user's preferred startup org) and
/// is not persisted to Cognito or DynamoDB. `memberships` lists all
/// organizations the user belongs to, each with one or more group roles.
#[derive(Deserialize)]
pub(crate) struct SeedUser {
    username: String,
    email: String,
    // Validated by serde to guard against typos in seed.toml, but never
    // written to Cognito or DynamoDB — it is a UI startup hint only.
    #[allow(dead_code)]
    default_org: String,
    memberships: Vec<SeedMembership>,
}

impl SeedUser {
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn email(&self) -> &str {
        &self.email
    }

    #[cfg(test)]
    pub(crate) fn default_org(&self) -> &str {
        &self.default_org
    }

    pub(crate) fn memberships(&self) -> &[SeedMembership] {
        &self.memberships
    }
}

/// A single organization membership for a user, with one or more group roles.
///
/// Written to DynamoDB as `PK=USER#{sub}`, `SK=ORG#{org_id}` so the proxy
/// can resolve group roles from the `X-ForgeGuard-Org-Id` header at request
/// time rather than embedding them in the JWT.
#[derive(Deserialize)]
pub(crate) struct SeedMembership {
    org_id: String,
    groups: Vec<String>,
}

impl SeedMembership {
    pub(crate) fn org_id(&self) -> &str {
        &self.org_id
    }

    pub(crate) fn groups(&self) -> &[String] {
        &self.groups
    }
}

/// Where the seed command should write DynamoDB records.
///
/// `Prod` reads the table name from 1Password (`op://<vault>/dynamodb/table-name`)
/// and hits real AWS. `Local` targets a `dynamodb-local` instance — typically
/// the one started by `cargo xtask control-plane dev` — with an explicit table
/// name. Cognito is untouched by this split; users are always provisioned in
/// real Cognito regardless of which path is chosen.
// Task 2 will wire this into SeedArgs + seed.rs; suppress dead_code until then.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum DynamoTarget {
    Prod,
    Local { endpoint: String, table: String },
}

impl DynamoTarget {
    /// Parse CLI flags into a `DynamoTarget`. Both flags must be provided
    /// together or not at all; the boundary is enforced here so downstream
    /// code never sees an inconsistent pair.
    // Task 2 will call this from SeedArgs; suppress dead_code until then.
    #[allow(dead_code)]
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
    fn parse_seed_config() {
        let toml_str = r#"
[[organization]]
org_id = "org-acme"
name = "Acme Corp"

[[organization]]
org_id = "org-globex"
name = "Globex Corporation"

[[user]]
username = "acme-admin"
email = "admin@acme.forgeguard.dev"
default_org = "org-acme"

[[user.memberships]]
org_id = "org-acme"
groups = ["admin"]

[[user.memberships]]
org_id = "org-globex"
groups = ["member"]

[[user]]
username = "acme-member"
email = "member@acme.forgeguard.dev"
default_org = "org-acme"

[[user.memberships]]
org_id = "org-acme"
groups = ["member"]
"#;

        let config: SeedConfig = toml::from_str(toml_str).unwrap();

        // Organizations
        assert_eq!(config.organizations().len(), 2);
        assert_eq!(config.organizations()[0].org_id(), "org-acme");
        assert_eq!(config.organizations()[1].name(), "Globex Corporation");

        // Users
        assert_eq!(config.users().len(), 2);

        // acme-admin: multi-org membership
        let admin = &config.users()[0];
        assert_eq!(admin.username(), "acme-admin");
        assert_eq!(admin.email(), "admin@acme.forgeguard.dev");
        assert_eq!(admin.default_org(), "org-acme");
        assert_eq!(admin.memberships().len(), 2);
        assert_eq!(admin.memberships()[0].org_id(), "org-acme");
        assert_eq!(admin.memberships()[0].groups(), &["admin"]);
        assert_eq!(admin.memberships()[1].org_id(), "org-globex");
        assert_eq!(admin.memberships()[1].groups(), &["member"]);

        // acme-member: single-org membership
        let member = &config.users()[1];
        assert_eq!(member.username(), "acme-member");
        assert_eq!(member.default_org(), "org-acme");
        assert_eq!(member.memberships().len(), 1);
        assert_eq!(member.memberships()[0].org_id(), "org-acme");
        assert_eq!(member.memberships()[0].groups(), &["member"]);
    }
}
