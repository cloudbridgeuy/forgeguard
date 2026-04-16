//! Cedar policy compilation.
//!
//! Pure functions that compile ForgeGuard policy and group definitions into
//! Cedar `permit` / `forbid` statements.

use std::collections::{HashMap, HashSet};

use crate::permission::{
    ActionPattern, Effect, GroupDefinition, PatternSegment, Policy, PolicyStatement,
    ResourceConstraint,
};
use crate::{CedarEntityType, CedarNamespace, Error, GroupName, ProjectId, Result};

// ---------------------------------------------------------------------------
// compile_policy_to_cedar
// ---------------------------------------------------------------------------

/// Compile a single [`Policy`] into Cedar statements.
///
/// When `scope` is `Some(group)`, the principal clause is scoped to that group
/// (`principal in {ns}::group::"{group}"`). When `scope` is `None`, the
/// principal clause is unconstrained (`principal`), producing a global policy.
///
/// For each [`PolicyStatement`] in the policy:
/// - `Effect::Allow` produces a Cedar `permit`
/// - `Effect::Deny` produces a Cedar `forbid` (with optional `unless` clause
///   for excepted groups)
pub fn compile_policy_to_cedar(
    policy: &Policy,
    scope: Option<&GroupName>,
    project: &ProjectId,
) -> Vec<String> {
    let vp_ns = CedarNamespace::from_project(project);
    let mut out = Vec::new();

    for stmt in policy.statements() {
        let keyword = match stmt.effect() {
            Effect::Allow => "permit",
            Effect::Deny => "forbid",
        };

        let principal_clause = match scope {
            Some(group) => format!(
                "principal in {}::group::\"{}\"",
                vp_ns.as_str(),
                group.as_str()
            ),
            None => "principal".to_string(),
        };
        let action_clause = build_action_clause(stmt.actions(), &vp_ns);
        let resource_clause = build_resource_clause(stmt.resources(), &vp_ns);

        let unless_clause = build_unless_clause(stmt, &vp_ns);

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
/// - Every group referenced by a policy exists.
/// - No circular group nesting.
pub fn compile_all_to_cedar(
    policies: &[Policy],
    groups: &[GroupDefinition],
    project: &ProjectId,
) -> Result<Vec<String>> {
    let group_names: HashSet<&str> = groups.iter().map(|g| g.name().as_str()).collect();

    // Validate group references from policies
    for policy in policies {
        for group_name in policy.groups() {
            if !group_names.contains(group_name.as_str()) {
                return Err(Error::Config(format!(
                    "policy '{}' references undefined group '{}'",
                    policy.name(),
                    group_name
                )));
            }
        }
    }

    // Validate no circular group nesting via DFS
    detect_circular_nesting(groups)?;

    // Compile: iterate policies, emit Cedar for each group the policy belongs to.
    // Policies with no groups are global (scope = None).
    let mut out = Vec::new();
    for policy in policies {
        if policy.groups().is_empty() {
            out.extend(compile_policy_to_cedar(policy, None, project));
        } else {
            for group_name in policy.groups() {
                out.extend(compile_policy_to_cedar(policy, Some(group_name), project));
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the action clause for a Cedar statement.
fn build_action_clause(actions: &[ActionPattern], vp_ns: &CedarNamespace) -> String {
    let mut cedar_actions: Vec<String> = Vec::new();
    let mut has_wildcard = false;

    for ap in actions {
        if is_all_exact(ap) {
            let ns = exact_str(ap.namespace());
            let entity = exact_str(ap.entity());
            let act = exact_str(ap.action());
            cedar_actions.push(format!(
                "{}::Action::\"{ns}-{entity}-{act}\"",
                vp_ns.as_str()
            ));
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
fn build_resource_clause(constraint: &ResourceConstraint, vp_ns: &CedarNamespace) -> String {
    match constraint {
        ResourceConstraint::All => "resource".to_string(),
        ResourceConstraint::Specific(refs) => {
            let format_ref = |r: &crate::permission::CedarEntityRef| {
                let entity_type = CedarEntityType::new_from_segments(r.namespace(), r.entity());
                format!("{}::{}::\"{}\"", vp_ns.as_str(), entity_type, r.id())
            };
            if refs.len() == 1 {
                format!("resource == {}", format_ref(&refs[0]))
            } else {
                let items: Vec<String> = refs.iter().map(format_ref).collect();
                format!("resource in [{}]", items.join(", "))
            }
        }
    }
}

/// Build the `unless` clause for deny statements with excepted groups.
fn build_unless_clause(stmt: &PolicyStatement, vp_ns: &CedarNamespace) -> String {
    let except = stmt.except();
    if except.is_empty() || stmt.effect() == Effect::Allow {
        return String::new();
    }

    let conditions: Vec<String> = except
        .iter()
        .map(|g| format!("principal in {}::group::\"{}\"", vp_ns.as_str(), g.as_str()))
        .collect();

    if conditions.len() == 1 {
        format!(" unless {{\n  {}\n}}", conditions[0])
    } else {
        format!(" unless {{\n  {}\n}}", conditions.join(" || "))
    }
}

/// Check whether all three segments of an action pattern are exact.
pub(super) fn is_all_exact(ap: &ActionPattern) -> bool {
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
pub(super) fn exact_str(seg: &PatternSegment) -> &str {
    match seg {
        PatternSegment::Exact(s) => s.as_str(),
        PatternSegment::Wildcard => unreachable!("exact_str called on wildcard"),
    }
}

/// Extract the inner [`crate::Segment`] reference from an `Exact` pattern segment.
/// Panics if called on a `Wildcard` — callers must check `is_all_exact` first.
pub(super) fn exact_segment(seg: &PatternSegment) -> &crate::Segment {
    match seg {
        PatternSegment::Exact(s) => s,
        PatternSegment::Wildcard => unreachable!("exact_segment called on wildcard"),
    }
}

/// Detect circular group nesting via DFS.
fn detect_circular_nesting(groups: &[GroupDefinition]) -> Result<()> {
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
    use crate::permission::GroupDefinition;

    fn project() -> ProjectId {
        ProjectId::new("acme-app").unwrap()
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
                "actions": ["todo:list:read"]
            }]
        }"#,
        );
        let group = GroupName::new("viewers").unwrap();
        let stmts = compile_policy_to_cedar(&policy, Some(&group), &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].starts_with("permit("));
        assert!(stmts[0].contains("principal in acme_app::group::\"viewers\""));
        assert!(stmts[0].contains("action in [acme_app::Action::\"todo-list-read\"]"));
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
                "actions": ["todo:item:delete"],
                "except": ["admin"]
            }]
        }"#,
        );
        let group = GroupName::new("users").unwrap();
        let stmts = compile_policy_to_cedar(&policy, Some(&group), &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].starts_with("forbid("));
        assert!(stmts[0].contains("unless {"));
        assert!(stmts[0].contains("principal in acme_app::group::\"admin\""));
    }

    // -- Deny with multiple except groups uses || -----------------------------

    #[test]
    fn deny_with_multiple_except_uses_or() {
        let policy = make_policy(
            r#"{
            "name": "deny-delete",
            "statements": [{
                "effect": "deny",
                "actions": ["todo:item:delete"],
                "except": ["admin", "ops"]
            }]
        }"#,
        );
        let group = GroupName::new("users").unwrap();
        let stmts = compile_policy_to_cedar(&policy, Some(&group), &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains(" || "));
        assert!(stmts[0].contains("group::\"admin\""));
        assert!(stmts[0].contains("group::\"ops\""));
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
        let stmts = compile_policy_to_cedar(&policy, Some(&group), &project());

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
                "actions": ["todo:list:read"],
                "resources": ["todo::list::top-secret"]
            }]
        }"#,
        );
        let group = GroupName::new("secret-team").unwrap();
        let stmts = compile_policy_to_cedar(&policy, Some(&group), &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("resource == acme_app::todo__list::\"top-secret\""));
    }

    // -- ResourceConstraint::All produces unconstrained resource ---------------

    #[test]
    fn resource_all_unconstrained() {
        let policy = make_policy(
            r#"{
            "name": "viewer",
            "statements": [{
                "effect": "allow",
                "actions": ["todo:list:read"]
            }]
        }"#,
        );
        let group = GroupName::new("viewers").unwrap();
        let stmts = compile_policy_to_cedar(&policy, Some(&group), &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("\n  resource\n)"));
    }

    // -- compile_all_to_cedar rejects undefined group reference ----------------

    #[test]
    fn compile_all_rejects_undefined_group() {
        let policies = vec![make_policy(
            r#"{
            "name": "todo-viewer",
            "groups": ["viewers", "nonexistent"],
            "statements": [{"effect": "allow", "actions": ["todo:list:read"]}]
        }"#,
        )];
        let groups = vec![make_group(
            r#"{
            "name": "viewers"
        }"#,
        )];

        let result = compile_all_to_cedar(&policies, &groups, &project());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent"),
            "error should mention the undefined group: {err}"
        );
    }

    // -- compile_all_to_cedar detects circular group nesting ------------------

    #[test]
    fn compile_all_detects_circular_nesting() {
        let policies = vec![make_policy(
            r#"{
            "name": "p1",
            "groups": ["group-a"],
            "statements": [{"effect": "allow", "actions": ["todo:list:read"]}]
        }"#,
        )];
        let groups = vec![
            make_group(
                r#"{
                "name": "group-a",
                "member_groups": ["group-b"]
            }"#,
            ),
            make_group(
                r#"{
                "name": "group-b",
                "member_groups": ["group-a"]
            }"#,
            ),
        ];

        let result = compile_all_to_cedar(&policies, &groups, &project());
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
                "groups": ["viewers", "editors"],
                "statements": [{"effect": "allow", "actions": ["todo:list:read"]}]
            }"#,
            ),
            make_policy(
                r#"{
                "name": "todo-editor",
                "groups": ["editors"],
                "statements": [{"effect": "allow", "actions": ["todo:item:write"]}]
            }"#,
            ),
        ];
        let groups = vec![
            make_group(
                r#"{
                "name": "viewers"
            }"#,
            ),
            make_group(
                r#"{
                "name": "editors"
            }"#,
            ),
        ];

        let result = compile_all_to_cedar(&policies, &groups, &project());
        assert!(result.is_ok());
        let stmts = result.unwrap();
        // todo-viewer in [viewers, editors] = 2, todo-editor in [editors] = 1 => 3 total
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
                "actions": ["todo:list:read"],
                "resources": ["todo::list::top-secret", "todo::list::confidential"]
            }]
        }"#,
        );
        let group = GroupName::new("readers").unwrap();
        let stmts = compile_policy_to_cedar(&policy, Some(&group), &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("resource in ["));
        assert!(stmts[0].contains("acme_app::todo__list::\"top-secret\""));
        assert!(stmts[0].contains("acme_app::todo__list::\"confidential\""));
    }

    // -- compile_all_to_cedar with mixed global and group-scoped policies ------

    #[test]
    fn compile_all_mixed_global_and_group_scoped() {
        let policies = vec![
            make_policy(
                r#"{
                "name": "viewer-read",
                "groups": ["viewers"],
                "statements": [{"effect": "allow", "actions": ["todo:list:read"]}]
            }"#,
            ),
            make_policy(
                r#"{
                "name": "global-deny-delete",
                "statements": [{
                    "effect": "deny",
                    "actions": ["todo:item:delete"],
                    "except": ["admin"]
                }]
            }"#,
            ),
        ];
        let groups = vec![
            make_group(r#"{ "name": "viewers" }"#),
            make_group(r#"{ "name": "admin" }"#),
        ];

        let result = compile_all_to_cedar(&policies, &groups, &project());
        assert!(result.is_ok());
        let stmts = result.unwrap();
        // viewer-read in [viewers] = 1, global-deny-delete (no groups) = 1 => 2 total
        assert_eq!(stmts.len(), 2);

        // First statement: group-scoped permit
        assert!(stmts[0].starts_with("permit("));
        assert!(stmts[0].contains("group::\"viewers\""));

        // Second statement: global forbid with unless
        assert!(stmts[1].starts_with("forbid("));
        assert!(
            stmts[1].contains("\n  principal,\n"),
            "global policy should have unconstrained principal"
        );
        assert!(stmts[1].contains("unless {"));
    }

    // -- Global policy (no scope) emits unconstrained principal ---------------

    #[test]
    fn global_policy_emits_unconstrained_principal() {
        let policy = make_policy(
            r#"{
            "name": "global-read",
            "statements": [{
                "effect": "allow",
                "actions": ["todo:list:read"]
            }]
        }"#,
        );
        let stmts = compile_policy_to_cedar(&policy, None, &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].starts_with("permit("));
        assert!(
            stmts[0].contains("\n  principal,\n"),
            "expected unconstrained principal, got: {}",
            stmts[0]
        );
        // Must NOT contain a group scope
        assert!(!stmts[0].contains("group::"));
    }

    // -- Global forbid with except emits forbid + unless ----------------------

    #[test]
    fn global_forbid_with_except_emits_unless() {
        let policy = make_policy(
            r#"{
            "name": "global-deny-delete",
            "statements": [{
                "effect": "deny",
                "actions": ["todo:item:delete"],
                "except": ["admin"]
            }]
        }"#,
        );
        let stmts = compile_policy_to_cedar(&policy, None, &project());

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].starts_with("forbid("));
        assert!(
            stmts[0].contains("\n  principal,\n"),
            "expected unconstrained principal, got: {}",
            stmts[0]
        );
        assert!(stmts[0].contains("unless {"));
        assert!(stmts[0].contains("principal in acme_app::group::\"admin\""));
    }
}
