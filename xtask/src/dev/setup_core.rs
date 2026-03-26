use color_eyre::eyre::{Context, Result};
use toml_edit::DocumentMut;

// ---------------------------------------------------------------------------
// Functional Core -- pure types and logic, no I/O
// ---------------------------------------------------------------------------

/// All resolved values needed to execute the setup.
pub(crate) struct SetupParams {
    pub(crate) stack_prefix: String,
    pub(crate) region: String,
    pub(crate) groups_context: String,
    pub(crate) password: String,
    pub(crate) force: bool,
}

/// Boolean results of each preflight check.
pub(crate) struct PreflightChecks {
    pub(crate) bun_exists: bool,
    pub(crate) bunx_exists: bool,
    pub(crate) env_file_exists: bool,
    pub(crate) users_file_exists: bool,
}

/// Merge new key-value pairs into existing `.env` content.
///
/// Updates existing keys in place; appends new keys at the end.
/// Preserves comments and blank lines.
pub(crate) fn merge_env_vars(existing: &str, new_vars: &[(&str, &str)]) -> String {
    let mut lines: Vec<String> = existing.lines().map(String::from).collect();
    let mut appended = Vec::new();

    for &(key, value) in new_vars {
        let prefix_eq = format!("{key}=");
        let prefix_commented = format!("# {key}=");

        let found = lines.iter_mut().any(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with(&prefix_eq) || trimmed.starts_with(&prefix_commented) {
                *line = format!("{key}={value}");
                true
            } else {
                false
            }
        });

        if !found {
            appended.push(format!("{key}={value}"));
        }
    }

    lines.extend(appended);

    let mut result = lines.join("\n");
    // Preserve trailing newline if original had one.
    if existing.ends_with('\n') {
        result.push('\n');
    }
    result
}

/// Merge `[authn.jwt]` section into existing TOML content.
///
/// Sets `jwks_url` and `issuer` under `[authn.jwt]`, preserving all other
/// content.
pub(crate) fn merge_authn_jwt_toml(existing: &str, jwks_url: &str, issuer: &str) -> Result<String> {
    let mut doc: DocumentMut = existing
        .parse()
        .context("failed to parse existing TOML content")?;

    // Ensure [authn] table exists.
    if !doc.contains_table("authn") {
        doc["authn"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let authn = doc["authn"]
        .as_table_mut()
        .ok_or_else(|| color_eyre::eyre::eyre!("`authn` is not a table"))?;

    // Ensure [authn.jwt] sub-table exists.
    if !authn.contains_key("jwt") {
        authn["jwt"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let jwt = authn["jwt"]
        .as_table_mut()
        .ok_or_else(|| color_eyre::eyre::eyre!("`authn.jwt` is not a table"))?;

    jwt["jwks_url"] = toml_edit::value(jwks_url);
    jwt["issuer"] = toml_edit::value(issuer);

    Ok(doc.to_string())
}

/// Build a JWKS URL for a Cognito user pool.
pub(crate) fn derive_jwks_url(region: &str, pool_id: &str) -> String {
    format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json")
}

/// Build an issuer URL for a Cognito user pool.
pub(crate) fn derive_issuer(region: &str, pool_id: &str) -> String {
    format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}")
}

/// Validate preflight checks and return human-readable error messages.
///
/// An empty return value means all checks passed.
pub(crate) fn validate_preflight(checks: &PreflightChecks) -> Vec<String> {
    let mut errors = Vec::new();

    if !checks.bun_exists {
        errors.push("`bun` not found in PATH -- install from https://bun.sh".to_string());
    }
    if !checks.bunx_exists {
        errors.push("`bunx` not found in PATH -- expected alongside bun".to_string());
    }
    if !checks.env_file_exists {
        errors.push("infra/dev/.env not found -- copy .env.example and fill in values".to_string());
    }
    if !checks.users_file_exists {
        errors.push(
            "infra/dev/users.toml not found -- copy users.example.toml and customise".to_string(),
        );
    }

    errors
}

/// Format a human-readable description of what the setup would do.
pub(crate) fn format_dry_run(params: &SetupParams) -> String {
    let mut out = String::from("Dry run -- the following actions would be performed:\n\n");

    out.push_str(&format!("  Stack prefix : {}\n", params.stack_prefix));
    out.push_str(&format!("  Region       : {}\n", params.region));
    out.push_str(&format!("  Groups       : {}\n", params.groups_context));
    out.push_str(&format!(
        "  Force delete : {}\n",
        if params.force { "yes" } else { "no" }
    ));
    out.push_str("  Password     : ***\n");

    out.push_str("\nSteps:\n");
    out.push_str("  1. Install node_modules if missing (bun install)\n");
    out.push_str("  2. Deploy CDK stack via `bun run cdk deploy`\n");
    out.push_str("  3. Read CloudFormation stack outputs\n");
    if params.force {
        out.push_str("  4. Delete existing test users (--force)\n");
        out.push_str("  5. Create test users, set passwords, assign groups\n");
        out.push_str("  6. Update infra/dev/.env with Cognito outputs\n");
        out.push_str("  7. Update forgeguard.dev.toml with authn.jwt settings\n");
    } else {
        out.push_str("  4. Create test users (skip existing), set passwords, assign groups\n");
        out.push_str("  5. Update infra/dev/.env with Cognito outputs\n");
        out.push_str("  6. Update forgeguard.dev.toml with authn.jwt settings\n");
    }

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- merge_env_vars ---

    #[test]
    fn merge_env_vars_updates_existing_and_appends_new() {
        let existing = "\
AWS_REGION=us-east-1
# A comment line
STACK_PREFIX=dev
";
        let result = merge_env_vars(
            existing,
            &[("AWS_REGION", "us-west-2"), ("NEW_VAR", "hello")],
        );
        assert!(result.contains("AWS_REGION=us-west-2"));
        assert!(result.contains("# A comment line"));
        assert!(result.contains("STACK_PREFIX=dev"));
        assert!(result.contains("NEW_VAR=hello"));
        // Original region should be replaced, not duplicated.
        assert_eq!(result.matches("AWS_REGION").count(), 1);
    }

    #[test]
    fn merge_env_vars_handles_empty_input() {
        let result = merge_env_vars("", &[("KEY", "value")]);
        assert!(result.contains("KEY=value"));
    }

    #[test]
    fn merge_env_vars_uncomments_commented_key() {
        let existing = "# COGNITO_USER_POOL_ID=\n";
        let result = merge_env_vars(existing, &[("COGNITO_USER_POOL_ID", "pool-123")]);
        assert!(result.contains("COGNITO_USER_POOL_ID=pool-123"));
        assert!(!result.contains("# COGNITO_USER_POOL_ID"));
    }

    #[test]
    fn merge_env_vars_preserves_comments_and_blanks() {
        let existing = "\
# Header comment
AWS_REGION=us-east-1

# Another comment
STACK_PREFIX=dev
";
        let result = merge_env_vars(existing, &[("STACK_PREFIX", "prod")]);
        assert!(result.contains("# Header comment"));
        assert!(result.contains("# Another comment"));
        assert!(result.contains("STACK_PREFIX=prod"));
    }

    // --- merge_authn_jwt_toml ---

    #[test]
    fn merge_authn_jwt_toml_creates_section_in_empty_file() {
        let result =
            merge_authn_jwt_toml("", "https://example.com/jwks", "https://example.com").unwrap();
        assert!(result.contains("[authn.jwt]") || result.contains("[authn]"));
        assert!(result.contains("jwks_url"));
        assert!(result.contains("https://example.com/jwks"));
        assert!(result.contains("issuer"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn merge_authn_jwt_toml_updates_existing_and_preserves_other_sections() {
        let existing = r#"
[logging]
level = "debug"

[authn.jwt]
jwks_url = "https://old.example.com/jwks"
issuer = "https://old.example.com"
"#;
        let result = merge_authn_jwt_toml(
            existing,
            "https://new.example.com/jwks",
            "https://new.example.com",
        )
        .unwrap();

        // Preserved other section.
        assert!(result.contains("[logging]"));
        assert!(result.contains("level = \"debug\""));
        // Updated jwt values.
        assert!(result.contains("https://new.example.com/jwks"));
        assert!(result.contains("https://new.example.com\""));
        // Old values gone.
        assert!(!result.contains("https://old.example.com"));
    }

    // --- derive_jwks_url / derive_issuer ---

    #[test]
    fn derive_jwks_url_correct_format() {
        let url = derive_jwks_url("us-east-1", "us-east-1_ABcDeFgHi");
        assert_eq!(
            url,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABcDeFgHi/.well-known/jwks.json"
        );
    }

    #[test]
    fn derive_issuer_correct_format() {
        let url = derive_issuer("us-east-1", "us-east-1_ABcDeFgHi");
        assert_eq!(
            url,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABcDeFgHi"
        );
    }

    // --- validate_preflight ---

    #[test]
    fn validate_preflight_returns_errors_for_missing_tools() {
        let checks = PreflightChecks {
            bun_exists: false,
            bunx_exists: false,
            env_file_exists: false,
            users_file_exists: false,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 4);
        assert!(errors[0].contains("bun"));
        assert!(errors[1].contains("bunx"));
        assert!(errors[2].contains(".env"));
        assert!(errors[3].contains("users.toml"));
    }

    #[test]
    fn validate_preflight_returns_empty_for_all_clear() {
        let checks = PreflightChecks {
            bun_exists: true,
            bunx_exists: true,
            env_file_exists: true,
            users_file_exists: true,
        };
        let errors = validate_preflight(&checks);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_preflight_partial_failures() {
        let checks = PreflightChecks {
            bun_exists: true,
            bunx_exists: true,
            env_file_exists: false,
            users_file_exists: true,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains(".env"));
    }

    // --- format_dry_run ---

    #[test]
    fn format_dry_run_contains_all_parameters() {
        let params = SetupParams {
            stack_prefix: "forgeguard-dev".to_string(),
            region: "us-east-2".to_string(),
            groups_context: "admin,member,viewer".to_string(),
            password: "TestPass123!".to_string(),
            force: true,
        };
        let output = format_dry_run(&params);

        assert!(output.contains("forgeguard-dev"));
        assert!(output.contains("us-east-2"));
        assert!(output.contains("admin,member,viewer"));
        assert!(output.contains("***"));
        assert!(!output.contains("TestPass123!"));
        assert!(output.contains("yes")); // force = true
        assert!(output.contains("Dry run"));
        assert!(output.contains("CDK"));
        assert!(output.contains("Delete existing"));
    }

    #[test]
    fn format_dry_run_without_force() {
        let params = SetupParams {
            stack_prefix: "fg-test".to_string(),
            region: "eu-west-1".to_string(),
            groups_context: "admin".to_string(),
            password: "Pass!".to_string(),
            force: false,
        };
        let output = format_dry_run(&params);

        assert!(output.contains("no")); // force = false
        assert!(output.contains("skip existing"));
        assert!(!output.contains("Delete existing"));
    }
}
