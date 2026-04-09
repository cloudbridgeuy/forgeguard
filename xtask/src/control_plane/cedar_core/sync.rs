use std::fmt::Write as _;

use super::desired::{DesiredPolicy, DesiredTemplate};
use super::store::StoreState;

/// A planned sync action.
pub(crate) enum SyncAction {
    PutSchema(String),
    CreateTemplate(DesiredTemplate),
    DeleteTemplate {
        id: String,
        /// Used by V5 dry-run formatting.
        #[allow(dead_code)]
        name: Option<String>,
    },
    CreatePolicy(DesiredPolicy),
    DeletePolicy {
        id: String,
        /// Used by V5 dry-run formatting.
        #[allow(dead_code)]
        name: Option<String>,
    },
}

/// The complete sync plan.
pub(crate) struct SyncPlan {
    pub(crate) actions: Vec<SyncAction>,
}

impl SyncPlan {
    pub(crate) fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Compute a sync plan by diffing desired state against current VP state.
///
/// This is a pure function with no I/O. The plan describes what changes are
/// needed to bring the VP store into alignment with the desired state.
///
/// **Ordering guarantees:**
/// 1. `PutSchema` runs first (the schema must exist before templates/policies
///    reference it).
/// 2. For **updates** (same name, different content): the old item is deleted
///    before the new one is created. This is required because VP enforces name
///    uniqueness -- creating a new item with the same name as an existing one
///    would fail.
/// 3. Standalone creates (new items) come next.
/// 4. Standalone deletes (removed items) come last so we never leave the store
///    in a broken intermediate state.
///
/// **Note:** Only `name` and `statement` are compared. Description changes
/// alone do not trigger a sync action.
pub(crate) fn compute_sync_plan(
    desired: &super::desired::DesiredState,
    current: &StoreState,
) -> SyncPlan {
    let mut schema_actions: Vec<SyncAction> = Vec::new();
    let mut update_actions: Vec<SyncAction> = Vec::new();
    let mut create_actions: Vec<SyncAction> = Vec::new();
    let mut delete_actions: Vec<SyncAction> = Vec::new();

    // --- Schema ---
    if let Some(desired_schema) = &desired.schema {
        let needs_put = match &current.schema {
            Some(current_schema) => desired_schema.trim() != current_schema.trim(),
            None => true,
        };
        if needs_put {
            schema_actions.push(SyncAction::PutSchema(desired_schema.clone()));
        }
    }

    // --- Templates ---
    let template_diffs = diff_by_name(
        &desired.templates,
        &current.templates,
        |d| (&d.name, &d.statement),
        |s| (s.name.as_deref(), &s.id, &s.statement),
    );
    for diff in template_diffs {
        match diff {
            DiffAction::Create { index, is_update } => {
                let target = if is_update {
                    &mut update_actions
                } else {
                    &mut create_actions
                };
                target.push(SyncAction::CreateTemplate(desired.templates[index].clone()));
            }
            DiffAction::Delete {
                id,
                name,
                is_update,
            } => {
                let target = if is_update {
                    &mut update_actions
                } else {
                    &mut delete_actions
                };
                target.push(SyncAction::DeleteTemplate { id, name });
            }
        }
    }

    // --- Policies ---
    let policy_diffs = diff_by_name(
        &desired.policies,
        &current.policies,
        |d| (&d.name, &d.statement),
        |s| (s.name.as_deref(), &s.id, &s.statement),
    );
    for diff in policy_diffs {
        match diff {
            DiffAction::Create { index, is_update } => {
                let target = if is_update {
                    &mut update_actions
                } else {
                    &mut create_actions
                };
                target.push(SyncAction::CreatePolicy(desired.policies[index].clone()));
            }
            DiffAction::Delete {
                id,
                name,
                is_update,
            } => {
                let target = if is_update {
                    &mut update_actions
                } else {
                    &mut delete_actions
                };
                target.push(SyncAction::DeletePolicy { id, name });
            }
        }
    }

    // Assemble: schema -> updates (delete-then-create pairs) -> creates -> deletes
    let mut actions = Vec::new();
    actions.append(&mut schema_actions);
    actions.append(&mut update_actions);
    actions.append(&mut create_actions);
    actions.append(&mut delete_actions);

    SyncPlan { actions }
}

/// Internal diff result — either create a desired item (by index) or delete
/// a current item (by id). The `is_update` flag indicates whether this action
/// is part of a delete+create pair for an item whose content changed.
enum DiffAction {
    Create {
        index: usize,
        is_update: bool,
    },
    Delete {
        id: String,
        name: Option<String>,
        is_update: bool,
    },
}

/// Generic diff-by-name for templates and policies.
///
/// Returns a list of `DiffAction`s. For updates (same name, different content),
/// the delete actions are emitted before the create action to preserve the
/// correct execution order (delete old item, then create new one).
fn diff_by_name<D, C>(
    desired_items: &[D],
    current_items: &[C],
    desired_fields: impl Fn(&D) -> (&str, &str),
    current_fields: impl Fn(&C) -> (Option<&str>, &str, &str),
) -> Vec<DiffAction> {
    use std::collections::{HashMap, HashSet};

    let mut results = Vec::new();

    // Index current items by name (skip unnamed ones).
    let mut current_by_name: HashMap<&str, Vec<(usize, &C)>> = HashMap::new();
    let mut unnamed_current: Vec<&C> = Vec::new();

    for (i, item) in current_items.iter().enumerate() {
        let (name, _, _) = current_fields(item);
        if let Some(n) = name {
            current_by_name.entry(n).or_default().push((i, item));
        } else {
            unnamed_current.push(item);
        }
    }

    // Track which current names we've matched.
    let mut matched_names: HashSet<&str> = HashSet::new();

    for (desired_idx, desired_item) in desired_items.iter().enumerate() {
        let (d_name, d_statement) = desired_fields(desired_item);

        if let Some(current_matches) = current_by_name.get(d_name) {
            matched_names.insert(d_name);

            // Check if any current item with this name has the same statement.
            let has_exact_match = current_matches.iter().any(|(_, c)| {
                let (_, _, c_statement) = current_fields(c);
                d_statement.trim() == c_statement.trim()
            });

            if has_exact_match {
                // Idempotent: no action needed.
                continue;
            }

            // Content differs: delete all current items with this name, then create.
            // Emit deletes before create so the pair stays in order.
            for (_, c) in current_matches {
                let (c_name, c_id, _) = current_fields(c);
                results.push(DiffAction::Delete {
                    id: c_id.to_string(),
                    name: c_name.map(String::from),
                    is_update: true,
                });
            }
            results.push(DiffAction::Create {
                index: desired_idx,
                is_update: true,
            });
        } else {
            // Not in current: create.
            results.push(DiffAction::Create {
                index: desired_idx,
                is_update: false,
            });
        }
    }

    // Delete current named items not in desired.
    for (name, items) in &current_by_name {
        if !matched_names.contains(name) {
            for (_, c) in items {
                let (c_name, c_id, _) = current_fields(c);
                results.push(DiffAction::Delete {
                    id: c_id.to_string(),
                    name: c_name.map(String::from),
                    is_update: false,
                });
            }
        }
    }

    // Delete unnamed current items (we can't match them to anything desired).
    for c in &unnamed_current {
        let (c_name, c_id, _) = current_fields(c);
        results.push(DiffAction::Delete {
            id: c_id.to_string(),
            name: c_name.map(String::from),
            is_update: false,
        });
    }

    results
}

// ---------------------------------------------------------------------------
// Sync result + summary (pure formatting)
// ---------------------------------------------------------------------------

/// Outcome counters from applying a sync plan.
pub(crate) struct SyncResult {
    pub(crate) schema_updated: bool,
    pub(crate) created_templates: u32,
    pub(crate) deleted_templates: u32,
    pub(crate) created_policies: u32,
    pub(crate) deleted_policies: u32,
}

/// Format a human-readable summary of sync results.
pub(crate) fn format_summary(result: &SyncResult) -> String {
    let all_zero = !result.schema_updated
        && result.created_templates == 0
        && result.deleted_templates == 0
        && result.created_policies == 0
        && result.deleted_policies == 0;

    if all_zero {
        return "No changes.".to_string();
    }

    let mut out = String::new();

    let schema_status = if result.schema_updated {
        "updated"
    } else {
        "unchanged"
    };
    let _ = writeln!(out, "Schema: {schema_status}");
    let _ = writeln!(
        out,
        "Templates: {} created, {} deleted",
        result.created_templates, result.deleted_templates
    );
    let _ = write!(
        out,
        "Policies: {} created, {} deleted",
        result.created_policies, result.deleted_policies
    );

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::control_plane::cedar_core::desired::{DesiredPolicy, DesiredState, DesiredTemplate};
    use crate::control_plane::cedar_core::store::{StorePolicy, StoreState, StoreTemplate};

    /// Helper: count actions by variant.
    fn count_actions(plan: &SyncPlan) -> (usize, usize, usize, usize, usize) {
        let mut put_schema = 0;
        let mut create_tmpl = 0;
        let mut delete_tmpl = 0;
        let mut create_pol = 0;
        let mut delete_pol = 0;
        for action in &plan.actions {
            match action {
                SyncAction::PutSchema(_) => put_schema += 1,
                SyncAction::CreateTemplate(_) => create_tmpl += 1,
                SyncAction::DeleteTemplate { .. } => delete_tmpl += 1,
                SyncAction::CreatePolicy(_) => create_pol += 1,
                SyncAction::DeletePolicy { .. } => delete_pol += 1,
            }
        }
        (put_schema, create_tmpl, delete_tmpl, create_pol, delete_pol)
    }

    // --- Empty desired + empty current ---

    #[test]
    fn sync_plan_empty_both() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    // --- Schema tests ---

    #[test]
    fn sync_plan_new_schema() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (put_schema, ..) = count_actions(&plan);
        assert_eq!(put_schema, 1);
    }

    #[test]
    fn sync_plan_same_schema() {
        let schema = "{\"Ns\":{}}".to_string();
        let desired = DesiredState {
            schema: Some(schema.clone()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some(schema),
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_same_schema_with_whitespace() {
        let desired = DesiredState {
            schema: Some("  {\"Ns\":{}}  ".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_schema() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{\"Entity\":{}}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (put_schema, ..) = count_actions(&plan);
        assert_eq!(put_schema, 1);
    }

    #[test]
    fn sync_plan_no_desired_schema_with_existing() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        // No desired schema means we don't touch the current one.
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    // --- Template tests ---

    #[test]
    fn sync_plan_new_template() {
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "read-access".to_string(),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 1);
        assert_eq!(delete_tmpl, 0);
    }

    #[test]
    fn sync_plan_same_template_idempotent() {
        let stmt = "permit(principal == ?principal, action, resource);".to_string();
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "read-access".to_string(),
                description: None,
                statement: stmt.clone(),
            }],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("read-access".to_string()),
                description: None,
                statement: stmt,
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_template_content() {
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "read-access".to_string(),
                description: None,
                statement: "permit(principal == ?principal, action, resource in ?resource);"
                    .to_string(),
            }],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("read-access".to_string()),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 1);
        assert_eq!(delete_tmpl, 1);
    }

    #[test]
    fn sync_plan_removed_template() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("read-access".to_string()),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 0);
        assert_eq!(delete_tmpl, 1);
    }

    #[test]
    fn sync_plan_unnamed_current_template_deleted() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-orphan".to_string(),
                name: None,
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (_, create_tmpl, delete_tmpl, ..) = count_actions(&plan);
        assert_eq!(create_tmpl, 0);
        assert_eq!(delete_tmpl, 1);
    }

    // --- Policy tests ---

    #[test]
    fn sync_plan_new_policy() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![DesiredPolicy {
                name: "deny-all".to_string(),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 1);
        assert_eq!(delete_pol, 0);
    }

    #[test]
    fn sync_plan_same_policy_idempotent() {
        let stmt = "forbid(principal, action, resource);".to_string();
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![DesiredPolicy {
                name: "deny-all".to_string(),
                description: None,
                statement: stmt.clone(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("deny-all".to_string()),
                description: None,
                statement: stmt,
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_policy_content() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![DesiredPolicy {
                name: "deny-all".to_string(),
                description: None,
                statement: "forbid(principal, action, resource) when { true };".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("deny-all".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 1);
        assert_eq!(delete_pol, 1);
    }

    #[test]
    fn sync_plan_removed_policy() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("deny-all".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 0);
        assert_eq!(delete_pol, 1);
    }

    #[test]
    fn sync_plan_unnamed_current_policy_deleted() {
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-orphan".to_string(),
                name: None,
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        let (.., create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(create_pol, 0);
        assert_eq!(delete_pol, 1);
    }

    // --- Ordering tests ---

    #[test]
    fn sync_plan_ordering_schema_first_deletes_last() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![DesiredTemplate {
                name: "new-tmpl".to_string(),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![DesiredPolicy {
                name: "new-pol".to_string(),
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-old".to_string(),
                name: Some("old-tmpl".to_string()),
                description: None,
                statement: "forbid(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![StorePolicy {
                id: "pol-old".to_string(),
                name: Some("old-pol".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);

        // Verify we have the expected actions.
        let (put_schema, create_tmpl, delete_tmpl, create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(put_schema, 1);
        assert_eq!(create_tmpl, 1);
        assert_eq!(delete_tmpl, 1);
        assert_eq!(create_pol, 1);
        assert_eq!(delete_pol, 1);

        // Schema must be first action.
        assert!(matches!(plan.actions[0], SyncAction::PutSchema(_)));

        // Standalone deletes must be last.
        let last_two = &plan.actions[plan.actions.len() - 2..];
        let all_deletes = last_two.iter().all(|a| {
            matches!(
                a,
                SyncAction::DeleteTemplate { .. } | SyncAction::DeletePolicy { .. }
            )
        });
        assert!(all_deletes, "standalone deletes should be at the end");
    }

    #[test]
    fn sync_plan_update_deletes_before_creates() {
        // When a policy is updated (same name, different content), the delete
        // must execute before the create to avoid VP name-uniqueness violations.
        let desired = DesiredState {
            schema: None,
            templates: vec![],
            policies: vec![DesiredPolicy {
                name: "my-policy".to_string(),
                description: None,
                statement: "permit(principal, action, resource) when { true };".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("my-policy".to_string()),
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert_eq!(plan.actions.len(), 2);

        // First action must be the delete, second must be the create.
        assert!(
            matches!(&plan.actions[0], SyncAction::DeletePolicy { id, .. } if id == "pol-1"),
            "first action should be DeletePolicy"
        );
        assert!(
            matches!(&plan.actions[1], SyncAction::CreatePolicy(p) if p.name == "my-policy"),
            "second action should be CreatePolicy"
        );
    }

    #[test]
    fn sync_plan_update_template_deletes_before_creates() {
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "my-tmpl".to_string(),
                description: None,
                statement: "permit(principal == ?principal, action, resource in ?resource);"
                    .to_string(),
            }],
            policies: vec![],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("my-tmpl".to_string()),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert_eq!(plan.actions.len(), 2);

        assert!(
            matches!(&plan.actions[0], SyncAction::DeleteTemplate { id, .. } if id == "tmpl-1"),
            "first action should be DeleteTemplate"
        );
        assert!(
            matches!(&plan.actions[1], SyncAction::CreateTemplate(t) if t.name == "my-tmpl"),
            "second action should be CreateTemplate"
        );
    }

    // --- Mixed scenario ---

    #[test]
    fn sync_plan_mixed_creates_deletes_noop() {
        let desired = DesiredState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![
                // Same as current: no-op
                DesiredTemplate {
                    name: "unchanged-tmpl".to_string(),
                    description: None,
                    statement: "permit(principal == ?principal, action, resource);".to_string(),
                },
                // New: create
                DesiredTemplate {
                    name: "new-tmpl".to_string(),
                    description: Some("Brand new.".to_string()),
                    statement: "permit(principal == ?principal, action, resource in ?resource);"
                        .to_string(),
                },
            ],
            policies: vec![
                // Changed: delete + create
                DesiredPolicy {
                    name: "updated-pol".to_string(),
                    description: None,
                    statement: "permit(principal, action, resource) when { true };".to_string(),
                },
            ],
        };
        let current = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()), // Same schema: no-op
            templates: vec![
                StoreTemplate {
                    id: "tmpl-1".to_string(),
                    name: Some("unchanged-tmpl".to_string()),
                    description: None,
                    statement: "permit(principal == ?principal, action, resource);".to_string(),
                },
                // Not in desired: delete
                StoreTemplate {
                    id: "tmpl-removed".to_string(),
                    name: Some("removed-tmpl".to_string()),
                    description: None,
                    statement: "forbid(principal == ?principal, action, resource);".to_string(),
                },
            ],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("updated-pol".to_string()),
                description: None,
                statement: "permit(principal, action, resource);".to_string(),
            }],
        };

        let plan = compute_sync_plan(&desired, &current);

        let (put_schema, create_tmpl, delete_tmpl, create_pol, delete_pol) = count_actions(&plan);
        assert_eq!(put_schema, 0, "schema unchanged");
        assert_eq!(create_tmpl, 1, "new-tmpl created");
        assert_eq!(delete_tmpl, 1, "removed-tmpl deleted");
        assert_eq!(create_pol, 1, "updated-pol re-created");
        assert_eq!(delete_pol, 1, "updated-pol old version deleted");

        // The update pair (delete pol-1, create updated-pol) must be ordered
        // correctly: delete before create.
        let delete_pol_idx = plan
            .actions
            .iter()
            .position(|a| matches!(a, SyncAction::DeletePolicy { id, .. } if id == "pol-1"))
            .unwrap();
        let create_pol_idx = plan
            .actions
            .iter()
            .position(|a| matches!(a, SyncAction::CreatePolicy(p) if p.name == "updated-pol"))
            .unwrap();
        assert!(
            delete_pol_idx < create_pol_idx,
            "update delete must come before update create"
        );
    }

    #[test]
    fn sync_plan_whitespace_trimmed_for_comparison() {
        let desired = DesiredState {
            schema: None,
            templates: vec![DesiredTemplate {
                name: "tmpl".to_string(),
                description: None,
                statement: "  permit(principal == ?principal, action, resource);  ".to_string(),
            }],
            policies: vec![DesiredPolicy {
                name: "pol".to_string(),
                description: None,
                statement: "  forbid(principal, action, resource);  ".to_string(),
            }],
        };
        let current = StoreState {
            schema: None,
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("tmpl".to_string()),
                description: None,
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![StorePolicy {
                id: "pol-1".to_string(),
                name: Some("pol".to_string()),
                description: None,
                statement: "forbid(principal, action, resource);".to_string(),
            }],
        };
        let plan = compute_sync_plan(&desired, &current);
        assert!(plan.is_empty(), "trimmed statements should match");
    }

    // =========================================================================
    // format_summary tests
    // =========================================================================

    #[test]
    fn format_summary_no_changes() {
        let result = SyncResult {
            schema_updated: false,
            created_templates: 0,
            deleted_templates: 0,
            created_policies: 0,
            deleted_policies: 0,
        };
        assert_eq!(format_summary(&result), "No changes.");
    }

    #[test]
    fn format_summary_schema_only() {
        let result = SyncResult {
            schema_updated: true,
            created_templates: 0,
            deleted_templates: 0,
            created_policies: 0,
            deleted_policies: 0,
        };
        let output = format_summary(&result);
        assert!(output.contains("Schema: updated"));
        assert!(output.contains("Templates: 0 created, 0 deleted"));
        assert!(output.contains("Policies: 0 created, 0 deleted"));
    }

    #[test]
    fn format_summary_mixed() {
        let result = SyncResult {
            schema_updated: false,
            created_templates: 2,
            deleted_templates: 1,
            created_policies: 3,
            deleted_policies: 0,
        };
        let output = format_summary(&result);
        assert!(output.contains("Schema: unchanged"));
        assert!(output.contains("Templates: 2 created, 1 deleted"));
        assert!(output.contains("Policies: 3 created, 0 deleted"));
    }

    #[test]
    fn format_summary_all_changes() {
        let result = SyncResult {
            schema_updated: true,
            created_templates: 1,
            deleted_templates: 2,
            created_policies: 3,
            deleted_policies: 4,
        };
        let output = format_summary(&result);
        assert!(output.contains("Schema: updated"));
        assert!(output.contains("Templates: 1 created, 2 deleted"));
        assert!(output.contains("Policies: 3 created, 4 deleted"));
    }
}
