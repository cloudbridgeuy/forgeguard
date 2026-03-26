use clap::Args;
use color_eyre::eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Functional Core -- pure types and logic, no I/O
// ---------------------------------------------------------------------------

/// Top-level configuration parsed from `infra/dev/users.toml`.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct UserConfig {
    groups: Vec<String>,
    users: Vec<TestUser>,
}

impl UserConfig {
    pub(crate) fn groups(&self) -> &[String] {
        &self.groups
    }

    pub(crate) fn users(&self) -> &[TestUser] {
        &self.users
    }
}

/// A single test user entry.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TestUser {
    username: String,
    tenant: String,
    groups: Vec<String>,
}

impl TestUser {
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn tenant(&self) -> &str {
        &self.tenant
    }

    pub(crate) fn groups(&self) -> &[String] {
        &self.groups
    }
}

/// CLI arguments for the `dev users` subcommand.
#[derive(Args)]
pub struct UsersArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Deserialize a TOML string into a `UserConfig`.
pub(crate) fn parse_users_toml(content: &str) -> Result<UserConfig> {
    toml::from_str(content).wrap_err("failed to parse users.toml")
}

/// Format users as an aligned table with `User`, `Tenant`, and `Groups` columns.
///
/// Column widths are calculated dynamically from the data.
fn format_users_table(config: &UserConfig) -> String {
    let header_user = "User";
    let header_tenant = "Tenant";
    let header_groups = "Groups";

    let user_width = config
        .users
        .iter()
        .map(|u| u.username.len())
        .max()
        .unwrap_or(0)
        .max(header_user.len());

    let tenant_width = config
        .users
        .iter()
        .map(|u| u.tenant.len())
        .max()
        .unwrap_or(0)
        .max(header_tenant.len());

    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<user_width$}  {:<tenant_width$}  {}\n",
        header_user, header_tenant, header_groups,
    ));

    // Separator
    out.push_str(&format!(
        "{:<user_width$}  {:<tenant_width$}  {}\n",
        "-".repeat(user_width),
        "-".repeat(tenant_width),
        "-".repeat(header_groups.len()),
    ));

    // Rows
    for user in &config.users {
        let groups_str = user.groups.join(", ");
        out.push_str(&format!(
            "{:<user_width$}  {:<tenant_width$}  {}\n",
            user.username, user.tenant, groups_str,
        ));
    }

    out
}

/// Serialize the user config as pretty JSON.
fn format_users_json(config: &UserConfig) -> Result<String> {
    let json =
        serde_json::to_string_pretty(config).wrap_err("failed to serialize users as JSON")?;
    Ok(json)
}

/// Join the top-level group names with commas for CDK context.
pub(crate) fn build_groups_context(config: &UserConfig) -> String {
    config.groups().join(",")
}

// ---------------------------------------------------------------------------
// Imperative Shell -- I/O, side effects, orchestration
// ---------------------------------------------------------------------------

/// Run the `dev users` subcommand: read users.toml and display the result.
pub fn run(args: &UsersArgs) -> Result<()> {
    let content = std::fs::read_to_string("infra/dev/users.toml")
        .wrap_err("failed to read infra/dev/users.toml (copy users.example.toml to get started)")?;

    let config = parse_users_toml(&content)?;

    if args.json {
        let json = format_users_json(&config)?;
        println!("{json}");
    } else {
        let table = format_users_table(&config);
        print!("{table}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOML: &str = r#"
groups = ["admin", "member", "viewer"]

[[users]]
username = "alice"
tenant = "acme-corp"
groups = ["admin"]

[[users]]
username = "bob"
tenant = "initech"
groups = ["member", "viewer"]
"#;

    // --- parse_users_toml ---

    #[test]
    fn parse_valid_toml() {
        let config = parse_users_toml(VALID_TOML).unwrap();
        assert_eq!(config.groups, vec!["admin", "member", "viewer"]);
        assert_eq!(config.users.len(), 2);
        assert_eq!(config.users[0].username, "alice");
        assert_eq!(config.users[0].tenant, "acme-corp");
        assert_eq!(config.users[0].groups, vec!["admin"]);
        assert_eq!(config.users[1].username, "bob");
        assert_eq!(config.users[1].tenant, "initech");
        assert_eq!(config.users[1].groups, vec!["member", "viewer"]);
    }

    #[test]
    fn parse_invalid_toml_returns_error() {
        let result = parse_users_toml("this is not [valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_required_fields_returns_error() {
        // Missing `groups` top-level key
        let incomplete = r#"
[[users]]
username = "alice"
tenant = "acme-corp"
"#;
        let result = parse_users_toml(incomplete);
        assert!(result.is_err());
    }

    #[test]
    fn parse_missing_user_field_returns_error() {
        // User missing `tenant`
        let incomplete = r#"
groups = ["admin"]

[[users]]
username = "alice"
groups = ["admin"]
"#;
        let result = parse_users_toml(incomplete);
        assert!(result.is_err());
    }

    // --- format_users_table ---

    #[test]
    fn table_formatting_matches_expected_output() {
        let config = parse_users_toml(VALID_TOML).unwrap();
        let table = format_users_table(&config);

        let lines: Vec<&str> = table.lines().collect();
        // Header + separator + 2 data rows
        assert_eq!(lines.len(), 4);

        // Header contains column names
        assert!(lines[0].contains("User"));
        assert!(lines[0].contains("Tenant"));
        assert!(lines[0].contains("Groups"));

        // Separator line contains dashes
        assert!(lines[1].contains("----"));

        // Data rows
        assert!(lines[2].contains("alice"));
        assert!(lines[2].contains("acme-corp"));
        assert!(lines[2].contains("admin"));

        assert!(lines[3].contains("bob"));
        assert!(lines[3].contains("initech"));
        assert!(lines[3].contains("member, viewer"));
    }

    #[test]
    fn table_columns_are_aligned() {
        let config = parse_users_toml(VALID_TOML).unwrap();
        let table = format_users_table(&config);

        let lines: Vec<&str> = table.lines().collect();
        // All lines should have the same position for the second column start.
        // The "Tenant" column starts after user_width + 2 spaces.
        // "alice" (5 chars) < "User" header is not wider, but let's check
        // max username length is 5 ("alice"), header is 4 ("User"), so width = 5.
        // Second column starts at position 7 (5 + 2 spaces).
        let tenant_positions: Vec<usize> = lines
            .iter()
            .map(|line| {
                // Find position of second non-space column
                let trimmed = line.trim_start();
                let first_word_end = trimmed.find(' ').unwrap();
                let rest = &line[first_word_end..];
                first_word_end + rest.len() - rest.trim_start().len()
            })
            .collect();

        // All tenant columns should start at the same position
        assert!(
            tenant_positions.windows(2).all(|w| w[0] == w[1]),
            "Tenant columns are not aligned: {:?}",
            tenant_positions
        );
    }

    // --- format_users_json ---

    #[test]
    fn json_output_is_valid_and_contains_all_users() {
        let config = parse_users_toml(VALID_TOML).unwrap();
        let json_str = format_users_json(&config).unwrap();

        // Valid JSON
        let value: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Contains groups
        let groups = value["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 3);

        // Contains all users
        let users = value["users"].as_array().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"].as_str().unwrap(), "alice");
        assert_eq!(users[1]["username"].as_str().unwrap(), "bob");
    }

    // --- build_groups_context ---

    #[test]
    fn groups_context_is_comma_separated() {
        let config = parse_users_toml(VALID_TOML).unwrap();
        let context = build_groups_context(&config);
        assert_eq!(context, "admin,member,viewer");
    }

    #[test]
    fn groups_context_single_group() {
        let toml = r#"
groups = ["admin"]

[[users]]
username = "alice"
tenant = "acme-corp"
groups = ["admin"]
"#;
        let config = parse_users_toml(toml).unwrap();
        let context = build_groups_context(&config);
        assert_eq!(context, "admin");
    }

    #[test]
    fn groups_context_empty_groups() {
        let toml = r#"
groups = []

[[users]]
username = "alice"
tenant = "acme-corp"
groups = []
"#;
        let config = parse_users_toml(toml).unwrap();
        let context = build_groups_context(&config);
        assert_eq!(context, "");
    }
}
