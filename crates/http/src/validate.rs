//! Config validation — collect-all strategy.
//!
//! Returns all errors and warnings at once so the user can fix everything in one pass.

use std::collections::HashSet;

use forgeguard_core::{FlagConfig, GroupDefinition, Policy};

use crate::config::ProxyConfig;
use crate::error::{ValidationError, ValidationErrorKind, ValidationWarning};

/// Validate a proxy config. Returns all errors and warnings (collect-all, not fail-fast).
pub fn validate(
    config: &ProxyConfig,
    policies: &[Policy],
    groups: &[GroupDefinition],
    features: &FlagConfig,
) -> (Vec<ValidationError>, Vec<ValidationWarning>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    check_duplicate_routes(config, &mut errors);
    check_feature_gates(config, features, &mut errors);
    check_policy_references(groups, policies, &mut errors);
    check_group_references(groups, &mut errors);
    check_public_route_overlap(config, &mut warnings);

    (errors, warnings)
}

/// Check for duplicate routes (same method + path pattern).
fn check_duplicate_routes(config: &ProxyConfig, errors: &mut Vec<ValidationError>) {
    let mut seen = HashSet::new();
    for (i, route) in config.routes().iter().enumerate() {
        let key = format!("{} {}", route.method(), route.path_pattern());
        if !seen.insert(key.clone()) {
            errors.push(ValidationError::new(
                ValidationErrorKind::DuplicateRoute,
                format!("{key} is already defined"),
                format!("routes[{i}]"),
            ));
        }
    }
}

/// Check that feature_gate references point to defined flags.
fn check_feature_gates(
    config: &ProxyConfig,
    features: &FlagConfig,
    errors: &mut Vec<ValidationError>,
) {
    for (i, route) in config.routes().iter().enumerate() {
        if let Some(gate) = route.feature_gate() {
            if !features.flags.contains_key(gate) {
                errors.push(ValidationError::new(
                    ValidationErrorKind::UndefinedFeatureGate,
                    format!("flag '{}' is not defined in features", gate),
                    format!("routes[{i}].feature_gate"),
                ));
            }
        }
    }
}

/// Check that all policy references in groups exist.
fn check_policy_references(
    groups: &[GroupDefinition],
    policies: &[Policy],
    errors: &mut Vec<ValidationError>,
) {
    let policy_names: HashSet<&str> = policies.iter().map(|p| p.name().as_str()).collect();
    for (i, group) in groups.iter().enumerate() {
        for (j, policy_ref) in group.policies().iter().enumerate() {
            if !policy_names.contains(policy_ref.as_str()) {
                errors.push(ValidationError::new(
                    ValidationErrorKind::InvalidPolicyReference,
                    format!(
                        "policy '{}' referenced by group '{}' does not exist",
                        policy_ref.as_str(),
                        group.name().as_str()
                    ),
                    format!("groups[{i}].policies[{j}]"),
                ));
            }
        }
    }
}

/// Check that all member_group references in groups exist.
fn check_group_references(groups: &[GroupDefinition], errors: &mut Vec<ValidationError>) {
    let group_names: HashSet<&str> = groups.iter().map(|g| g.name().as_str()).collect();
    for (i, group) in groups.iter().enumerate() {
        for (j, member) in group.member_groups().iter().enumerate() {
            if !group_names.contains(member.as_str()) {
                errors.push(ValidationError::new(
                    ValidationErrorKind::InvalidGroupReference,
                    format!(
                        "member group '{}' referenced by group '{}' does not exist",
                        member.as_str(),
                        group.name().as_str()
                    ),
                    format!("groups[{i}].member_groups[{j}]"),
                ));
            }
        }
    }
}

/// Warn when a public route overlaps with an auth route.
fn check_public_route_overlap(config: &ProxyConfig, warnings: &mut Vec<ValidationWarning>) {
    let auth_routes: HashSet<String> = config
        .routes()
        .iter()
        .map(|r| format!("{} {}", r.method(), r.path_pattern()))
        .collect();

    for (i, pr) in config.public_routes().iter().enumerate() {
        let key = format!("{} {}", pr.method(), pr.path_pattern());
        if auth_routes.contains(&key) {
            warnings.push(ValidationWarning::new(
                format!(
                    "public route {key} also has an auth route — public route takes precedence"
                ),
                format!("public_routes[{i}]"),
            ));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use forgeguard_core::{FlagConfig, FlagDefinition, FlagName, FlagType, FlagValue};

    use crate::config::parse_config;

    use super::*;

    fn empty_features() -> FlagConfig {
        FlagConfig::default()
    }

    fn features_with(name: &str) -> FlagConfig {
        let mut flags = HashMap::new();
        flags.insert(
            FlagName::parse(name).unwrap(),
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );
        FlagConfig { flags }
    }

    fn parse_groups(json: &str) -> Vec<GroupDefinition> {
        serde_json::from_str(json).unwrap()
    }

    fn parse_policies(json: &str) -> Vec<Policy> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn no_errors_on_valid_config() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/users"
action = "todo:list:user"
"#,
        )
        .unwrap();
        let (errors, warnings) = validate(&config, &[], &[], &empty_features());
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn duplicate_route_detected() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/users"
action = "todo:list:user"

[[routes]]
method = "GET"
path = "/users"
action = "todo:read:user"
"#,
        )
        .unwrap();
        // Duplicate routes are detected at validation time (not parse time).
        // parse_config only builds a Vec<RouteMapping>; the RouteMatcher (which
        // rejects dupes via matchit) is built later by the proxy layer.
        let (errors, _) = validate(&config, &[], &[], &empty_features());
        assert_eq!(errors.len(), 1);
        assert_eq!(*errors[0].kind(), ValidationErrorKind::DuplicateRoute);
    }

    #[test]
    fn undefined_feature_gate_detected() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/beta"
action = "todo:read:beta"
feature_gate = "nonexistent"
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config, &[], &[], &empty_features());
        assert_eq!(errors.len(), 1);
        assert_eq!(*errors[0].kind(), ValidationErrorKind::UndefinedFeatureGate);
    }

    #[test]
    fn defined_feature_gate_passes() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/beta"
action = "todo:read:beta"
feature_gate = "beta-feature"
"#,
        )
        .unwrap();
        let features = features_with("beta-feature");
        let (errors, _) = validate(&config, &[], &[], &features);
        assert!(errors.is_empty());
    }

    #[test]
    fn invalid_policy_reference_detected() {
        let groups = parse_groups(
            r#"[{"name": "admin", "policies": ["nonexistent-policy"], "member_groups": []}]"#,
        );
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config, &[], &groups, &empty_features());
        assert_eq!(errors.len(), 1);
        assert_eq!(
            *errors[0].kind(),
            ValidationErrorKind::InvalidPolicyReference
        );
    }

    #[test]
    fn valid_policy_reference_passes() {
        let policies = parse_policies(
            r#"[{"name": "todo-viewer", "statements": [{"effect": "allow", "actions": ["todo:read:list"]}]}]"#,
        );
        let groups = parse_groups(
            r#"[{"name": "admin", "policies": ["todo-viewer"], "member_groups": []}]"#,
        );
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config, &policies, &groups, &empty_features());
        assert!(errors.is_empty());
    }

    #[test]
    fn invalid_group_reference_detected() {
        let groups = parse_groups(
            r#"[{"name": "admin", "policies": [], "member_groups": ["nonexistent"]}]"#,
        );
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config, &[], &groups, &empty_features());
        assert_eq!(errors.len(), 1);
        assert_eq!(
            *errors[0].kind(),
            ValidationErrorKind::InvalidGroupReference
        );
    }

    #[test]
    fn public_route_overlap_warning() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/docs"
action = "todo:read:doc"

[[public_routes]]
method = "GET"
path = "/docs"
auth_mode = "anonymous"
"#,
        )
        .unwrap();
        let (errors, warnings) = validate(&config, &[], &[], &empty_features());
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message().contains("public route"));
    }

    #[test]
    fn multiple_errors_collected() {
        let groups = parse_groups(
            r#"[
                {"name": "admin", "policies": ["missing-policy"], "member_groups": ["missing-group"]}
            ]"#,
        );
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/beta"
action = "todo:read:beta"
feature_gate = "nonexistent"
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config, &[], &groups, &empty_features());
        // Should have: undefined feature gate + invalid policy ref + invalid group ref
        assert_eq!(errors.len(), 3);
    }
}
