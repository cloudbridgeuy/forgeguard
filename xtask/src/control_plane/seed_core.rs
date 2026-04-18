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
#[derive(Deserialize)]
pub(crate) struct SeedUser {
    username: String,
    email: String,
    group: String,
    org_id: String,
}

impl SeedUser {
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn email(&self) -> &str {
        &self.email
    }

    pub(crate) fn group(&self) -> &str {
        &self.group
    }

    pub(crate) fn org_id(&self) -> &str {
        &self.org_id
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
group = "admin"
org_id = "org-acme"

[[user]]
username = "acme-member"
email = "member@acme.forgeguard.dev"
group = "member"
org_id = "org-acme"
"#;

        let config: SeedConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.organizations().len(), 2);
        assert_eq!(config.organizations()[0].org_id(), "org-acme");
        assert_eq!(config.organizations()[1].name(), "Globex Corporation");
        assert_eq!(config.users().len(), 2);
        assert_eq!(config.users()[0].username(), "acme-admin");
        assert_eq!(config.users()[0].group(), "admin");
        assert_eq!(config.users()[1].org_id(), "org-acme");
    }
}
