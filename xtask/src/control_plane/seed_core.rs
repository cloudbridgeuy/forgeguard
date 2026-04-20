//! Pure types for the `seed` command configuration.
//!
//! Parsed from `xtask/seed.toml` — defines organizations to seed into
//! DynamoDB and Cognito users to create for testing.

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
