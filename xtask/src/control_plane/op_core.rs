use std::fmt;

/// Valid deployment environments.
///
/// Parsed at the CLI boundary via clap's `ValueEnum`. Invalid values are
/// rejected before any command logic runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ForgeguardEnv {
    Dev,
    Prod,
}

impl fmt::Display for ForgeguardEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dev => write!(f, "dev"),
            Self::Prod => write!(f, "prod"),
        }
    }
}

/// Preflight check results.
pub(crate) struct PreflightChecks {
    pub(crate) bun_exists: bool,
    pub(crate) op_exists: bool,
    pub(crate) cargo_lambda_exists: bool,
    pub(crate) zig_exists: bool,
}

/// Validate preflight checks. Returns error messages for failures.
pub(crate) fn validate_preflight(checks: &PreflightChecks) -> Vec<String> {
    let mut errors = Vec::new();
    if !checks.bun_exists {
        errors.push("bun is not installed".to_string());
    }
    if !checks.op_exists {
        errors.push("op (1Password CLI) is not installed".to_string());
    }
    if !checks.cargo_lambda_exists {
        errors.push(
            "cargo-lambda is not installed (install: cargo install cargo-lambda)".to_string(),
        );
    }
    if !checks.zig_exists {
        errors.push(
            "zig is not installed (install: brew install zig) — required by cargo-lambda for cross-compilation".to_string(),
        );
    }
    errors
}

/// Check if the user confirmed destroy by typing "destroy".
pub(crate) fn confirm_destroy(input: &str) -> bool {
    input.trim() == "destroy"
}

/// Build the CloudFormation stack name for a given environment.
pub(crate) fn build_stack_name(env: ForgeguardEnv) -> String {
    format!("forgeguard-{env}-dynamodb")
}

/// Build the Lambda CloudFormation stack name for a given environment.
pub(crate) fn build_lambda_stack_name(env: ForgeguardEnv) -> String {
    format!("forgeguard-{env}-lambda")
}

/// Build the Verified Permissions CloudFormation stack name for a given environment.
pub(crate) fn build_vp_stack_name(env: ForgeguardEnv) -> String {
    format!("forgeguard-{env}-vp")
}

/// Build the 1Password vault name for a given environment.
pub(crate) fn build_vault_name(env: ForgeguardEnv) -> String {
    format!("forgeguard-{env}")
}

/// Format CloudFormation stack outputs for terminal display.
pub(crate) fn format_status_output(
    stack_name: &str,
    status: &str,
    outputs: &[(&str, &str)],
) -> String {
    let mut result = format!("Stack: {stack_name}\nStatus: {status}\n");
    if !outputs.is_empty() {
        result.push_str("Outputs:\n");
        for (key, value) in outputs {
            result.push_str(&format!("  {key}: {value}\n"));
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- validate_preflight ---

    #[test]
    fn validate_preflight_all_exist() {
        let checks = PreflightChecks {
            bun_exists: true,
            op_exists: true,
            cargo_lambda_exists: true,
            zig_exists: true,
        };
        assert!(validate_preflight(&checks).is_empty());
    }

    #[test]
    fn validate_preflight_missing_bun() {
        let checks = PreflightChecks {
            bun_exists: false,
            op_exists: true,
            cargo_lambda_exists: true,
            zig_exists: true,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("bun"));
    }

    #[test]
    fn validate_preflight_missing_op() {
        let checks = PreflightChecks {
            bun_exists: true,
            op_exists: false,
            cargo_lambda_exists: true,
            zig_exists: true,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("op"));
    }

    #[test]
    fn validate_preflight_missing_cargo_lambda() {
        let checks = PreflightChecks {
            bun_exists: true,
            op_exists: true,
            cargo_lambda_exists: false,
            zig_exists: true,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("cargo-lambda"));
    }

    #[test]
    fn validate_preflight_missing_zig() {
        let checks = PreflightChecks {
            bun_exists: true,
            op_exists: true,
            cargo_lambda_exists: true,
            zig_exists: false,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("zig"));
    }

    #[test]
    fn validate_preflight_both_missing() {
        let checks = PreflightChecks {
            bun_exists: false,
            op_exists: false,
            cargo_lambda_exists: true,
            zig_exists: true,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn validate_preflight_all_missing() {
        let checks = PreflightChecks {
            bun_exists: false,
            op_exists: false,
            cargo_lambda_exists: false,
            zig_exists: false,
        };
        let errors = validate_preflight(&checks);
        assert_eq!(errors.len(), 4);
    }

    // --- confirm_destroy ---

    #[test]
    fn confirm_destroy_exact_match() {
        assert!(confirm_destroy("destroy"));
    }

    #[test]
    fn confirm_destroy_with_trailing_newline() {
        assert!(confirm_destroy("destroy\n"));
    }

    #[test]
    fn confirm_destroy_uppercase_rejected() {
        assert!(!confirm_destroy("DESTROY"));
    }

    #[test]
    fn confirm_destroy_empty() {
        assert!(!confirm_destroy(""));
    }

    #[test]
    fn confirm_destroy_wrong_word() {
        assert!(!confirm_destroy("yes"));
    }

    // --- ForgeguardEnv ---

    #[test]
    fn forgeguard_env_display_dev() {
        assert_eq!(ForgeguardEnv::Dev.to_string(), "dev");
    }

    #[test]
    fn forgeguard_env_display_prod() {
        assert_eq!(ForgeguardEnv::Prod.to_string(), "prod");
    }

    // --- build_stack_name ---

    #[test]
    fn build_stack_name_prod() {
        assert_eq!(
            build_stack_name(ForgeguardEnv::Prod),
            "forgeguard-prod-dynamodb"
        );
    }

    #[test]
    fn build_stack_name_dev() {
        assert_eq!(
            build_stack_name(ForgeguardEnv::Dev),
            "forgeguard-dev-dynamodb"
        );
    }

    // --- build_lambda_stack_name ---

    #[test]
    fn build_lambda_stack_name_prod() {
        assert_eq!(
            build_lambda_stack_name(ForgeguardEnv::Prod),
            "forgeguard-prod-lambda"
        );
    }

    #[test]
    fn build_lambda_stack_name_dev() {
        assert_eq!(
            build_lambda_stack_name(ForgeguardEnv::Dev),
            "forgeguard-dev-lambda"
        );
    }

    // --- build_vp_stack_name ---

    #[test]
    fn build_vp_stack_name_prod() {
        assert_eq!(
            build_vp_stack_name(ForgeguardEnv::Prod),
            "forgeguard-prod-vp"
        );
    }

    #[test]
    fn build_vp_stack_name_dev() {
        assert_eq!(build_vp_stack_name(ForgeguardEnv::Dev), "forgeguard-dev-vp");
    }

    // --- build_vault_name ---

    #[test]
    fn build_vault_name_prod() {
        assert_eq!(build_vault_name(ForgeguardEnv::Prod), "forgeguard-prod");
    }

    #[test]
    fn build_vault_name_dev() {
        assert_eq!(build_vault_name(ForgeguardEnv::Dev), "forgeguard-dev");
    }

    // --- format_status_output ---

    #[test]
    fn format_status_output_contains_all_parts() {
        let output = format_status_output(
            "forgeguard-prod-dynamodb",
            "CREATE_COMPLETE",
            &[
                ("TableName", "forgeguard-prod-orgs"),
                ("TableArn", "arn:aws:dynamodb:us-east-1:123:table/orgs"),
            ],
        );
        assert!(output.contains("forgeguard-prod-dynamodb"));
        assert!(output.contains("CREATE_COMPLETE"));
        assert!(output.contains("TableName"));
        assert!(output.contains("forgeguard-prod-orgs"));
        assert!(output.contains("TableArn"));
        assert!(output.contains("arn:aws:dynamodb:us-east-1:123:table/orgs"));
    }

    #[test]
    fn format_status_output_empty_outputs() {
        let output = format_status_output("my-stack", "PENDING", &[]);
        assert!(output.contains("my-stack"));
        assert!(output.contains("PENDING"));
        assert!(!output.contains("Outputs:"));
    }
}
