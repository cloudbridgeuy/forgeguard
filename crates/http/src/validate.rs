//! Config validation — collect-all strategy.
//!
//! Returns all errors and warnings at once so the user can fix everything in one pass.

use std::collections::{HashMap, HashSet};

use forgeguard_core::GroupName;

use crate::config::ProxyConfig;
use crate::error::{ValidationError, ValidationErrorKind, ValidationWarning};

/// Validate a proxy config. Returns all errors and warnings (collect-all, not fail-fast).
pub fn validate(config: &ProxyConfig) -> (Vec<ValidationError>, Vec<ValidationWarning>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    check_duplicate_routes(config, &mut errors);
    check_feature_gates(config, &mut errors);
    check_policy_group_references(config, &mut errors);
    check_group_references(config, &mut errors);
    check_circular_group_nesting(config, &mut errors);
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
fn check_feature_gates(config: &ProxyConfig, errors: &mut Vec<ValidationError>) {
    for (i, route) in config.routes().iter().enumerate() {
        if let Some(gate) = route.feature_gate() {
            if !config.features().flags.contains_key(gate) {
                errors.push(ValidationError::new(
                    ValidationErrorKind::UndefinedFeatureGate,
                    format!("flag '{}' is not defined in features", gate),
                    format!("routes[{i}].feature_gate"),
                ));
            }
        }
    }
}

/// Check that all group references in policies exist.
fn check_policy_group_references(config: &ProxyConfig, errors: &mut Vec<ValidationError>) {
    let group_names: HashSet<&str> = config.groups().iter().map(|g| g.name().as_str()).collect();
    for (i, policy) in config.policies().iter().enumerate() {
        for (j, group_ref) in policy.groups().iter().enumerate() {
            if !group_names.contains(group_ref.as_str()) {
                errors.push(ValidationError::new(
                    ValidationErrorKind::InvalidPolicyReference,
                    format!(
                        "policy '{}' references undefined group '{}'",
                        policy.name().as_str(),
                        group_ref.as_str()
                    ),
                    format!("policies[{i}].groups[{j}]"),
                ));
            }
        }
    }
}

/// Check that all member_group references in groups exist.
fn check_group_references(config: &ProxyConfig, errors: &mut Vec<ValidationError>) {
    let group_names: HashSet<&str> = config.groups().iter().map(|g| g.name().as_str()).collect();
    for (i, group) in config.groups().iter().enumerate() {
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

/// Detect circular group nesting via DFS.
fn check_circular_group_nesting(config: &ProxyConfig, errors: &mut Vec<ValidationError>) {
    let groups = config.groups();
    if groups.is_empty() {
        return;
    }

    let adjacency: HashMap<&str, Vec<&str>> = groups
        .iter()
        .map(|g| {
            (
                g.name().as_str(),
                g.member_groups().iter().map(GroupName::as_str).collect(),
            )
        })
        .collect();

    let mut visited: HashSet<&str> = HashSet::new();
    let mut in_stack: HashSet<&str> = HashSet::new();

    for group in groups {
        let name = group.name().as_str();
        if !visited.contains(name) {
            dfs_cycle_check(name, &adjacency, &mut visited, &mut in_stack, errors);
        }
    }
}

/// DFS helper for cycle detection. On finding a back-edge, pushes a `ValidationError`.
fn dfs_cycle_check<'a>(
    node: &'a str,
    adjacency: &HashMap<&'a str, Vec<&'a str>>,
    visited: &mut HashSet<&'a str>,
    in_stack: &mut HashSet<&'a str>,
    errors: &mut Vec<ValidationError>,
) {
    visited.insert(node);
    in_stack.insert(node);

    if let Some(neighbors) = adjacency.get(node) {
        for &neighbor in neighbors {
            if in_stack.contains(neighbor) {
                errors.push(ValidationError::new(
                    ValidationErrorKind::CircularGroupNesting,
                    format!(
                        "circular group nesting detected: '{}' -> '{}'",
                        node, neighbor
                    ),
                    format!("groups[{}].member_groups", node),
                ));
            } else if !visited.contains(neighbor) {
                dfs_cycle_check(neighbor, adjacency, visited, in_stack, errors);
            }
        }
    }

    in_stack.remove(node);
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
    use crate::config::parse_config;

    use super::*;

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
        let (errors, warnings) = validate(&config);
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
action = "todo:user:read"
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
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
action = "todo:beta:read"
feature_gate = "nonexistent"
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
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
action = "todo:beta:read"
feature_gate = "beta-feature"

[features.flags.beta-feature]
type = "boolean"
default = false
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        assert!(errors.is_empty());
    }

    #[test]
    fn invalid_group_reference_in_policy() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[policies]]
name = "todo-viewer"
groups = ["nonexistent-group"]
[[policies.statements]]
effect = "allow"
actions = ["todo:list:read"]
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            *errors[0].kind(),
            ValidationErrorKind::InvalidPolicyReference
        );
    }

    #[test]
    fn valid_group_reference_in_policy_passes() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[policies]]
name = "todo-viewer"
groups = ["admin"]
[[policies.statements]]
effect = "allow"
actions = ["todo:list:read"]

[[groups]]
name = "admin"
member_groups = []
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        assert!(errors.is_empty());
    }

    #[test]
    fn invalid_group_reference_detected() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[groups]]
name = "admin"
member_groups = ["nonexistent"]
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            *errors[0].kind(),
            ValidationErrorKind::InvalidGroupReference
        );
    }

    #[test]
    fn circular_group_nesting_detected() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[groups]]
name = "group-a"
member_groups = ["group-b"]

[[groups]]
name = "group-b"
member_groups = ["group-a"]
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        let cycle_errors: Vec<_> = errors
            .iter()
            .filter(|e| *e.kind() == ValidationErrorKind::CircularGroupNesting)
            .collect();
        assert!(!cycle_errors.is_empty());
        assert!(cycle_errors[0].message().contains("circular"));
    }

    #[test]
    fn self_referencing_group_detected() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[groups]]
name = "loop"
member_groups = ["loop"]
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        let cycle_errors: Vec<_> = errors
            .iter()
            .filter(|e| *e.kind() == ValidationErrorKind::CircularGroupNesting)
            .collect();
        assert!(!cycle_errors.is_empty());
    }

    #[test]
    fn no_cycle_in_valid_group_hierarchy() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[groups]]
name = "super-admin"
member_groups = ["admin"]

[[groups]]
name = "admin"
member_groups = ["users"]

[[groups]]
name = "users"
member_groups = []
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        let cycle_errors: Vec<_> = errors
            .iter()
            .filter(|e| *e.kind() == ValidationErrorKind::CircularGroupNesting)
            .collect();
        assert!(cycle_errors.is_empty());
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
action = "todo:doc:read"

[[public_routes]]
method = "GET"
path = "/docs"
auth_mode = "anonymous"
"#,
        )
        .unwrap();
        let (errors, warnings) = validate(&config);
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message().contains("public route"));
    }

    #[test]
    fn multiple_errors_collected() {
        let config = parse_config(
            r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/beta"
action = "todo:beta:read"
feature_gate = "nonexistent"

[[policies]]
name = "bad-policy"
groups = ["missing-group"]
[[policies.statements]]
effect = "allow"
actions = ["todo:beta:read"]

[[groups]]
name = "admin"
member_groups = ["missing-member"]
"#,
        )
        .unwrap();
        let (errors, _) = validate(&config);
        // Should have: undefined feature gate + invalid group ref in policy + invalid member group ref
        assert_eq!(errors.len(), 3);
    }
}
