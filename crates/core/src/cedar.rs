//! Cedar policy compilation.
//!
//! Pure functions that compile ForgeGuard policy and group definitions into
//! Cedar `permit` / `forbid` statements.

use std::collections::{HashMap, HashSet};

use crate::permission::{
    ActionPattern, Effect, GroupDefinition, PatternSegment, Policy, PolicyStatement,
    ResourceConstraint,
};
use crate::{Error, Fgrn, GroupName, ProjectId, Result, TenantId};

// ---------------------------------------------------------------------------
// compile_policy_to_cedar
// ---------------------------------------------------------------------------

/// Compile a single [`Policy`] into Cedar statements, scoped to a group.
///
/// For each [`PolicyStatement`] in the policy:
/// - `Effect::Allow` produces a Cedar `permit`
/// - `Effect::Deny` produces a Cedar `forbid` (with optional `unless` clause
///   for excepted groups)
pub fn compile_policy_to_cedar(
    policy: &Policy,
    attached_to_group: &GroupName,
    project: &ProjectId,
    tenant: &TenantId,
) -> Vec<String> {
    let group_fgrn = Fgrn::group(project, tenant, attached_to_group);
    let mut out = Vec::new();

    for stmt in policy.statements() {
        let keyword = match stmt.effect() {
            Effect::Allow => "permit",
            Effect::Deny => "forbid",
        };

        let principal_clause = format!("principal in iam::group::\"{}\"", group_fgrn);
        let action_clause = build_action_clause(stmt.actions());
        let resource_clause = build_resource_clause(stmt.resources());

        let unless_clause = build_unless_clause(stmt, project, tenant);

        let cedar = format!(
            "{keyword}(\n  {principal_clause},\n  {action_clause},\n  {resource_clause}\n){unless_clause};",
        );
        out.push(cedar);
    }

    out
}

// ---------------------------------------------------------------------------
// compile_all_to_cedar
// ---------------------------------------------------------------------------

/// Compile all policies and groups into Cedar statements.
///
/// Validates:
/// - Every policy referenced by a group is defined.
/// - No circular group nesting.
pub fn compile_all_to_cedar(
    policies: &[Policy],
    groups: &[GroupDefinition],
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<Vec<String>> {
    let policy_map: HashMap<&str, &Policy> =
        policies.iter().map(|p| (p.name().as_str(), p)).collect();

    let group_names: HashSet<&str> = groups.iter().map(|g| g.name().as_str()).collect();

    // Validate policy references
    for group in groups {
        for policy_name in group.policies() {
            if !policy_map.contains_key(policy_name.as_str()) {
                return Err(Error::Config(format!(
                    "group '{}' references undefined policy '{}'",
                    group.name(),
                    policy_name
                )));
            }
        }
    }

    // Validate no circular group nesting via DFS
    detect_circular_nesting(groups, &group_names)?;

    // Compile
    let mut out = Vec::new();
    for group in groups {
        for policy_name in group.policies() {
            if let Some(policy) = policy_map.get(policy_name.as_str()) {
                out.extend(compile_policy_to_cedar(
                    policy,
                    group.name(),
                    project,
                    tenant,
                ));
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the action clause for a Cedar statement.
fn build_action_clause(actions: &[ActionPattern]) -> String {
    let mut cedar_actions: Vec<String> = Vec::new();
    let mut has_wildcard = false;

    for ap in actions {
        if is_all_exact(ap) {
            let ns = exact_str(ap.namespace());
            let entity = exact_str(ap.entity());
            let act = exact_str(ap.action());
            cedar_actions.push(format!("{ns}::action::\"{act}-{entity}\""));
        } else {
            has_wildcard = true;
        }
    }

    if has_wildcard || cedar_actions.is_empty() {
        "action".to_string()
    } else if cedar_actions.len() == 1 {
        format!("action in [{}]", cedar_actions[0])
    } else {
        format!("action in [{}]", cedar_actions.join(", "))
    }
}

/// Build the resource clause for a Cedar statement.
fn build_resource_clause(constraint: &ResourceConstraint) -> String {
    match constraint {
        ResourceConstraint::All => "resource".to_string(),
        ResourceConstraint::Specific(refs) => {
            if refs.len() == 1 {
                format!(
                    "resource == {}::{}::\"{}\"",
                    refs[0].namespace(),
                    refs[0].entity(),
                    refs[0].id()
                )
            } else {
                let items: Vec<String> = refs
                    .iter()
                    .map(|r| format!("{}::{}::\"{}\"", r.namespace(), r.entity(), r.id()))
                    .collect();
                format!("resource in [{}]", items.join(", "))
            }
        }
    }
}

/// Build the `unless` clause for deny statements with excepted groups.
fn build_unless_clause(stmt: &PolicyStatement, project: &ProjectId, tenant: &TenantId) -> String {
    let except = stmt.except();
    if except.is_empty() || stmt.effect() == Effect::Allow {
        return String::new();
    }

    let conditions: Vec<String> = except
        .iter()
        .map(|g| {
            let fgrn = Fgrn::group(project, tenant, g);
            format!("principal in iam::group::\"{}\"", fgrn)
        })
        .collect();

    if conditions.len() == 1 {
        format!(" unless {{\n  {}\n}}", conditions[0])
    } else {
        format!(" unless {{\n  {}\n}}", conditions.join(" || "))
    }
}

/// Check whether all three segments of an action pattern are exact.
fn is_all_exact(ap: &ActionPattern) -> bool {
    matches!(
        (ap.namespace(), ap.action(), ap.entity()),
        (
            PatternSegment::Exact(_),
            PatternSegment::Exact(_),
            PatternSegment::Exact(_)
        )
    )
}

/// Extract the string from an `Exact` pattern segment.
/// Panics if called on a `Wildcard` — callers must check `is_all_exact` first.
fn exact_str(seg: &PatternSegment) -> &str {
    match seg {
        PatternSegment::Exact(s) => s.as_str(),
        PatternSegment::Wildcard => unreachable!("exact_str called on wildcard"),
    }
}

/// Detect circular group nesting via DFS.
fn detect_circular_nesting(groups: &[GroupDefinition], _group_names: &HashSet<&str>) -> Result<()> {
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
            dfs_cycle_check(name, &adjacency, &mut visited, &mut in_stack)?;
        }
    }

    Ok(())
}

fn dfs_cycle_check<'a>(
    node: &'a str,
    adjacency: &HashMap<&'a str, Vec<&'a str>>,
    visited: &mut HashSet<&'a str>,
    in_stack: &mut HashSet<&'a str>,
) -> Result<()> {
    visited.insert(node);
    in_stack.insert(node);

    if let Some(neighbors) = adjacency.get(node) {
        for &neighbor in neighbors {
            if in_stack.contains(neighbor) {
                return Err(Error::Config(format!(
                    "circular group nesting detected: '{}' -> '{}'",
                    node, neighbor
                )));
            }
            if !visited.contains(neighbor) {
                dfs_cycle_check(neighbor, adjacency, visited, in_stack)?;
            }
        }
    }

    in_stack.remove(node);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn project() -> ProjectId {
        ProjectId::new("acme-app").unwrap()
    }

    fn tenant() -> TenantId {
        TenantId::new("acme-corp").unwrap()
    }

    fn make_policy(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    fn make_group(json: &str) -> GroupDefinition {
        serde_json::from_str(json).unwrap()
    }

    // -- Allow policy generates permit ----------------------------------------

    #[test]
    fn allow_policy_generates_permit() {
        let policy = make_policy(
            r#"{
            "name": "todo-viewer",
            "statements": [{
                "effect": "allow",
                "actions": ["todo:read:list"]
            }]
        }"#,
        );
        let group = GroupName::new("viewers").unwrap();
        let stmts = compile_policy_to_cedar(&policy, &group, &project(), &tenant());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].starts_with("permit("));
        assert!(stmts[0]
            .contains("principal in iam::group::\"fgrn:acme-app:acme-corp:iam:group:viewers\""));
        assert!(stmts[0].contains("action in [todo::action::\"read-list\"]"));
        assert!(stmts[0].contains("resource"));
        assert!(stmts[0].ends_with(';'));
    }

    // -- Deny policy with except generates forbid + unless --------------------

    #[test]
    fn deny_with_except_generates_forbid_unless() {
        let policy = make_policy(
            r#"{
            "name": "deny-delete",
            "statements": [{
                "effect": "deny",
                "actions": ["todo:delete:item"],
                "except": ["admin"]
            }]
        }"#,
        );
        let group = GroupName::new("users").unwrap();
        let stmts = compile_policy_to_cedar(&policy, &group, &project(), &tenant());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].starts_with("forbid("));
        assert!(stmts[0].contains("unless {"));
        assert!(stmts[0]
            .contains("principal in iam::group::\"fgrn:acme-app:acme-corp:iam:group:admin\""));
    }

    // -- Deny with multiple except groups uses || -----------------------------

    #[test]
    fn deny_with_multiple_except_uses_or() {
        let policy = make_policy(
            r#"{
            "name": "deny-delete",
            "statements": [{
                "effect": "deny",
                "actions": ["todo:delete:item"],
                "except": ["admin", "ops"]
            }]
        }"#,
        );
        let group = GroupName::new("users").unwrap();
        let stmts = compile_policy_to_cedar(&policy, &group, &project(), &tenant());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains(" || "));
        assert!(stmts[0].contains("iam:group:admin\""));
        assert!(stmts[0].contains("iam:group:ops\""));
    }

    // -- Wildcard action produces unconstrained action ------------------------

    #[test]
    fn wildcard_action_unconstrained() {
        let policy = make_policy(
            r#"{
            "name": "todo-all",
            "statements": [{
                "effect": "allow",
                "actions": ["todo:*:*"]
            }]
        }"#,
        );
        let group = GroupName::new("admins").unwrap();
        let stmts = compile_policy_to_cedar(&policy, &group, &project(), &tenant());

        assert_eq!(stmts.len(), 1);
        // Should have unconstrained `action`, not `action in [...]`
        assert!(stmts[0].contains("\n  action,\n"));
    }

    // -- Specific resource constraint -----------------------------------------

    #[test]
    fn specific_resource_constraint() {
        let policy = make_policy(
            r#"{
            "name": "secret-viewer",
            "statements": [{
                "effect": "allow",
                "actions": ["todo:read:list"],
                "resources": ["todo::list::top-secret"]
            }]
        }"#,
        );
        let group = GroupName::new("secret-team").unwrap();
        let stmts = compile_policy_to_cedar(&policy, &group, &project(), &tenant());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("resource == todo::list::\"top-secret\""));
    }

    // -- ResourceConstraint::All produces unconstrained resource ---------------

    #[test]
    fn resource_all_unconstrained() {
        let policy = make_policy(
            r#"{
            "name": "viewer",
            "statements": [{
                "effect": "allow",
                "actions": ["todo:read:list"]
            }]
        }"#,
        );
        let group = GroupName::new("viewers").unwrap();
        let stmts = compile_policy_to_cedar(&policy, &group, &project(), &tenant());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("\n  resource\n)"));
    }

    // -- compile_all_to_cedar rejects undefined policy reference ---------------

    #[test]
    fn compile_all_rejects_undefined_policy() {
        let policies = vec![make_policy(
            r#"{
            "name": "todo-viewer",
            "statements": [{"effect": "allow", "actions": ["todo:read:list"]}]
        }"#,
        )];
        let groups = vec![make_group(
            r#"{
            "name": "viewers",
            "policies": ["todo-viewer", "nonexistent"]
        }"#,
        )];

        let result = compile_all_to_cedar(&policies, &groups, &project(), &tenant());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent"),
            "error should mention the undefined policy: {err}"
        );
    }

    // -- compile_all_to_cedar detects circular group nesting ------------------

    #[test]
    fn compile_all_detects_circular_nesting() {
        let policies = vec![make_policy(
            r#"{
            "name": "p1",
            "statements": [{"effect": "allow", "actions": ["todo:read:list"]}]
        }"#,
        )];
        let groups = vec![
            make_group(
                r#"{
                "name": "group-a",
                "policies": ["p1"],
                "member_groups": ["group-b"]
            }"#,
            ),
            make_group(
                r#"{
                "name": "group-b",
                "policies": ["p1"],
                "member_groups": ["group-a"]
            }"#,
            ),
        ];

        let result = compile_all_to_cedar(&policies, &groups, &project(), &tenant());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("circular"),
            "error should mention circular nesting: {err}"
        );
    }

    // -- compile_all_to_cedar success case ------------------------------------

    #[test]
    fn compile_all_success() {
        let policies = vec![
            make_policy(
                r#"{
                "name": "todo-viewer",
                "statements": [{"effect": "allow", "actions": ["todo:read:list"]}]
            }"#,
            ),
            make_policy(
                r#"{
                "name": "todo-editor",
                "statements": [{"effect": "allow", "actions": ["todo:write:item"]}]
            }"#,
            ),
        ];
        let groups = vec![
            make_group(
                r#"{
                "name": "viewers",
                "policies": ["todo-viewer"]
            }"#,
            ),
            make_group(
                r#"{
                "name": "editors",
                "policies": ["todo-viewer", "todo-editor"]
            }"#,
            ),
        ];

        let result = compile_all_to_cedar(&policies, &groups, &project(), &tenant());
        assert!(result.is_ok());
        let stmts = result.unwrap();
        // viewers: 1 statement, editors: 2 statements = 3 total
        assert_eq!(stmts.len(), 3);
    }

    // -- Multiple specific resources ------------------------------------------

    #[test]
    fn multiple_specific_resources() {
        let policy = make_policy(
            r#"{
            "name": "multi-resource",
            "statements": [{
                "effect": "allow",
                "actions": ["todo:read:list"],
                "resources": ["todo::list::top-secret", "todo::list::confidential"]
            }]
        }"#,
        );
        let group = GroupName::new("readers").unwrap();
        let stmts = compile_policy_to_cedar(&policy, &group, &project(), &tenant());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("resource in ["));
        assert!(stmts[0].contains("todo::list::\"top-secret\""));
        assert!(stmts[0].contains("todo::list::\"confidential\""));
    }
}
