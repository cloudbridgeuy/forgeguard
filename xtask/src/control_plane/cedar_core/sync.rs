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
    let mut phases = PhasedActions::default();

    // --- Schema ---
    if let Some(desired_schema) = &desired.schema {
        let needs_put = match &current.schema {
            Some(current_schema) => desired_schema.trim() != current_schema.trim(),
            None => true,
        };
        if needs_put {
            phases
                .schema
                .push(SyncAction::PutSchema(desired_schema.clone()));
        }
    }

    // --- Templates ---
    let template_diffs = diff_by_name(
        &desired.templates,
        &current.templates,
        |d| (&d.name, &d.statement),
        |s| (s.name.as_deref(), &s.id, &s.statement),
    );
    phases.route_diffs(
        &template_diffs,
        |idx| SyncAction::CreateTemplate(desired.templates[idx].clone()),
        |id, name| SyncAction::DeleteTemplate { id, name },
    );

    // --- Policies ---
    let policy_diffs = diff_by_name(
        &desired.policies,
        &current.policies,
        |d| (&d.name, &d.statement),
        |s| (s.name.as_deref(), &s.id, &s.statement),
    );
    phases.route_diffs(
        &policy_diffs,
        |idx| SyncAction::CreatePolicy(desired.policies[idx].clone()),
        |id, name| SyncAction::DeletePolicy { id, name },
    );

    SyncPlan {
        actions: phases.into_ordered(),
    }
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

/// Groups sync actions into execution phases:
/// schema -> updates (delete-then-create pairs) -> creates -> deletes.
#[derive(Default)]
struct PhasedActions {
    schema: Vec<SyncAction>,
    updates: Vec<SyncAction>,
    creates: Vec<SyncAction>,
    deletes: Vec<SyncAction>,
}

impl PhasedActions {
    /// Route diff actions into the correct phase bucket.
    fn route_diffs(
        &mut self,
        diffs: &[DiffAction],
        make_create: impl Fn(usize) -> SyncAction,
        make_delete: impl Fn(String, Option<String>) -> SyncAction,
    ) {
        for diff in diffs {
            match diff {
                DiffAction::Create { index, is_update } => {
                    let target = if *is_update {
                        &mut self.updates
                    } else {
                        &mut self.creates
                    };
                    target.push(make_create(*index));
                }
                DiffAction::Delete {
                    id,
                    name,
                    is_update,
                } => {
                    let target = if *is_update {
                        &mut self.updates
                    } else {
                        &mut self.deletes
                    };
                    target.push(make_delete(id.clone(), name.clone()));
                }
            }
        }
    }

    /// Assemble all phases into the final ordered action list.
    fn into_ordered(self) -> Vec<SyncAction> {
        let mut actions = self.schema;
        actions.extend(self.updates);
        actions.extend(self.creates);
        actions.extend(self.deletes);
        actions
    }
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

    // -- Test helpers ---------------------------------------------------------

    fn desired(
        schema: Option<&str>,
        templates: Vec<DesiredTemplate>,
        policies: Vec<DesiredPolicy>,
    ) -> DesiredState {
        DesiredState {
            schema: schema.map(String::from),
            templates,
            policies,
        }
    }

    fn current(
        schema: Option<&str>,
        templates: Vec<StoreTemplate>,
        policies: Vec<StorePolicy>,
    ) -> StoreState {
        StoreState {
            schema: schema.map(String::from),
            templates,
            policies,
        }
    }

    fn d_tmpl(name: &str, stmt: &str) -> DesiredTemplate {
        DesiredTemplate {
            name: name.to_string(),
            description: None,
            statement: stmt.to_string(),
        }
    }

    fn d_pol(name: &str, stmt: &str) -> DesiredPolicy {
        DesiredPolicy {
            name: name.to_string(),
            description: None,
            statement: stmt.to_string(),
        }
    }

    fn s_tmpl(id: &str, name: Option<&str>, stmt: &str) -> StoreTemplate {
        StoreTemplate {
            id: id.to_string(),
            name: name.map(String::from),
            description: None,
            statement: stmt.to_string(),
        }
    }

    fn s_pol(id: &str, name: Option<&str>, stmt: &str) -> StorePolicy {
        StorePolicy {
            id: id.to_string(),
            name: name.map(String::from),
            description: None,
            statement: stmt.to_string(),
        }
    }

    /// Count actions by variant: (put_schema, create_tmpl, delete_tmpl, create_pol, delete_pol).
    fn count_actions(plan: &SyncPlan) -> (usize, usize, usize, usize, usize) {
        let mut counts = (0, 0, 0, 0, 0);
        for action in &plan.actions {
            match action {
                SyncAction::PutSchema(_) => counts.0 += 1,
                SyncAction::CreateTemplate(_) => counts.1 += 1,
                SyncAction::DeleteTemplate { .. } => counts.2 += 1,
                SyncAction::CreatePolicy(_) => counts.3 += 1,
                SyncAction::DeletePolicy { .. } => counts.4 += 1,
            }
        }
        counts
    }

    // -- Schema tests ---------------------------------------------------------

    #[test]
    fn sync_plan_empty_both() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![]),
            &current(None, vec![], vec![]),
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_new_schema() {
        let plan = compute_sync_plan(
            &desired(Some("{\"Ns\":{}}"), vec![], vec![]),
            &current(None, vec![], vec![]),
        );
        assert_eq!(count_actions(&plan).0, 1);
    }

    #[test]
    fn sync_plan_same_schema() {
        let plan = compute_sync_plan(
            &desired(Some("{\"Ns\":{}}"), vec![], vec![]),
            &current(Some("{\"Ns\":{}}"), vec![], vec![]),
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_same_schema_with_whitespace() {
        let plan = compute_sync_plan(
            &desired(Some("  {\"Ns\":{}}  "), vec![], vec![]),
            &current(Some("{\"Ns\":{}}"), vec![], vec![]),
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_schema() {
        let plan = compute_sync_plan(
            &desired(Some("{\"Ns\":{\"Entity\":{}}}"), vec![], vec![]),
            &current(Some("{\"Ns\":{}}"), vec![], vec![]),
        );
        assert_eq!(count_actions(&plan).0, 1);
    }

    #[test]
    fn sync_plan_no_desired_schema_with_existing() {
        // No desired schema means we don't touch the current one.
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![]),
            &current(Some("{\"Ns\":{}}"), vec![], vec![]),
        );
        assert!(plan.is_empty());
    }

    // -- Template tests -------------------------------------------------------

    const TMPL_STMT: &str = "permit(principal == ?principal, action, resource);";
    const TMPL_STMT_V2: &str = "permit(principal == ?principal, action, resource in ?resource);";

    #[test]
    fn sync_plan_new_template() {
        let plan = compute_sync_plan(
            &desired(None, vec![d_tmpl("read-access", TMPL_STMT)], vec![]),
            &current(None, vec![], vec![]),
        );
        let (_, ct, dt, ..) = count_actions(&plan);
        assert_eq!((ct, dt), (1, 0));
    }

    #[test]
    fn sync_plan_same_template_idempotent() {
        let plan = compute_sync_plan(
            &desired(None, vec![d_tmpl("read-access", TMPL_STMT)], vec![]),
            &current(
                None,
                vec![s_tmpl("tmpl-1", Some("read-access"), TMPL_STMT)],
                vec![],
            ),
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_template_content() {
        let plan = compute_sync_plan(
            &desired(None, vec![d_tmpl("read-access", TMPL_STMT_V2)], vec![]),
            &current(
                None,
                vec![s_tmpl("tmpl-1", Some("read-access"), TMPL_STMT)],
                vec![],
            ),
        );
        let (_, ct, dt, ..) = count_actions(&plan);
        assert_eq!((ct, dt), (1, 1));
    }

    #[test]
    fn sync_plan_removed_template() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![]),
            &current(
                None,
                vec![s_tmpl("tmpl-1", Some("read-access"), TMPL_STMT)],
                vec![],
            ),
        );
        let (_, ct, dt, ..) = count_actions(&plan);
        assert_eq!((ct, dt), (0, 1));
    }

    #[test]
    fn sync_plan_unnamed_current_template_deleted() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![]),
            &current(
                None,
                vec![s_tmpl(
                    "tmpl-orphan",
                    None,
                    "permit(principal, action, resource);",
                )],
                vec![],
            ),
        );
        let (_, ct, dt, ..) = count_actions(&plan);
        assert_eq!((ct, dt), (0, 1));
    }

    // -- Policy tests ---------------------------------------------------------

    const POL_FORBID: &str = "forbid(principal, action, resource);";
    const POL_FORBID_WHEN: &str = "forbid(principal, action, resource) when { true };";
    const POL_PERMIT: &str = "permit(principal, action, resource);";
    const POL_PERMIT_WHEN: &str = "permit(principal, action, resource) when { true };";

    #[test]
    fn sync_plan_new_policy() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![d_pol("deny-all", POL_FORBID)]),
            &current(None, vec![], vec![]),
        );
        let (.., cp, dp) = count_actions(&plan);
        assert_eq!((cp, dp), (1, 0));
    }

    #[test]
    fn sync_plan_same_policy_idempotent() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![d_pol("deny-all", POL_FORBID)]),
            &current(
                None,
                vec![],
                vec![s_pol("pol-1", Some("deny-all"), POL_FORBID)],
            ),
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn sync_plan_changed_policy_content() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![d_pol("deny-all", POL_FORBID_WHEN)]),
            &current(
                None,
                vec![],
                vec![s_pol("pol-1", Some("deny-all"), POL_FORBID)],
            ),
        );
        let (.., cp, dp) = count_actions(&plan);
        assert_eq!((cp, dp), (1, 1));
    }

    #[test]
    fn sync_plan_removed_policy() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![]),
            &current(
                None,
                vec![],
                vec![s_pol("pol-1", Some("deny-all"), POL_FORBID)],
            ),
        );
        let (.., cp, dp) = count_actions(&plan);
        assert_eq!((cp, dp), (0, 1));
    }

    #[test]
    fn sync_plan_unnamed_current_policy_deleted() {
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![]),
            &current(None, vec![], vec![s_pol("pol-orphan", None, POL_PERMIT)]),
        );
        let (.., cp, dp) = count_actions(&plan);
        assert_eq!((cp, dp), (0, 1));
    }

    // -- Ordering tests -------------------------------------------------------

    #[test]
    fn sync_plan_ordering_schema_first_deletes_last() {
        let plan = compute_sync_plan(
            &desired(
                Some("{\"Ns\":{}}"),
                vec![d_tmpl("new-tmpl", TMPL_STMT)],
                vec![d_pol("new-pol", POL_PERMIT)],
            ),
            &current(
                None,
                vec![s_tmpl(
                    "tmpl-old",
                    Some("old-tmpl"),
                    "forbid(principal == ?principal, action, resource);",
                )],
                vec![s_pol("pol-old", Some("old-pol"), POL_FORBID)],
            ),
        );

        let (ps, ct, dt, cp, dp) = count_actions(&plan);
        assert_eq!((ps, ct, dt, cp, dp), (1, 1, 1, 1, 1));

        // Schema must be first action.
        assert!(matches!(plan.actions[0], SyncAction::PutSchema(_)));

        // Standalone deletes must be last.
        let last_two = &plan.actions[plan.actions.len() - 2..];
        assert!(
            last_two.iter().all(|a| matches!(
                a,
                SyncAction::DeleteTemplate { .. } | SyncAction::DeletePolicy { .. }
            )),
            "standalone deletes should be at the end"
        );
    }

    #[test]
    fn sync_plan_update_deletes_before_creates() {
        // When a policy is updated (same name, different content), the delete
        // must execute before the create to avoid VP name-uniqueness violations.
        let plan = compute_sync_plan(
            &desired(None, vec![], vec![d_pol("my-policy", POL_PERMIT_WHEN)]),
            &current(
                None,
                vec![],
                vec![s_pol("pol-1", Some("my-policy"), POL_PERMIT)],
            ),
        );
        assert_eq!(plan.actions.len(), 2);
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
        let plan = compute_sync_plan(
            &desired(None, vec![d_tmpl("my-tmpl", TMPL_STMT_V2)], vec![]),
            &current(
                None,
                vec![s_tmpl("tmpl-1", Some("my-tmpl"), TMPL_STMT)],
                vec![],
            ),
        );
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

    // -- Mixed scenario -------------------------------------------------------

    #[test]
    fn sync_plan_mixed_creates_deletes_noop() {
        let plan = compute_sync_plan(
            &desired(
                Some("{\"Ns\":{}}"),
                vec![
                    d_tmpl("unchanged-tmpl", TMPL_STMT), // same as current: no-op
                    DesiredTemplate {
                        // new: create (with description)
                        name: "new-tmpl".to_string(),
                        description: Some("Brand new.".to_string()),
                        statement: TMPL_STMT_V2.to_string(),
                    },
                ],
                vec![d_pol("updated-pol", POL_PERMIT_WHEN)], // changed: delete + create
            ),
            &current(
                Some("{\"Ns\":{}}"), // same schema: no-op
                vec![
                    s_tmpl("tmpl-1", Some("unchanged-tmpl"), TMPL_STMT),
                    s_tmpl(
                        "tmpl-removed",
                        Some("removed-tmpl"),
                        "forbid(principal == ?principal, action, resource);",
                    ),
                ],
                vec![s_pol("pol-1", Some("updated-pol"), POL_PERMIT)],
            ),
        );

        let (ps, ct, dt, cp, dp) = count_actions(&plan);
        assert_eq!(ps, 0, "schema unchanged");
        assert_eq!(ct, 1, "new-tmpl created");
        assert_eq!(dt, 1, "removed-tmpl deleted");
        assert_eq!(cp, 1, "updated-pol re-created");
        assert_eq!(dp, 1, "updated-pol old version deleted");

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
        let plan = compute_sync_plan(
            &desired(
                None,
                vec![d_tmpl(
                    "tmpl",
                    "  permit(principal == ?principal, action, resource);  ",
                )],
                vec![d_pol("pol", "  forbid(principal, action, resource);  ")],
            ),
            &current(
                None,
                vec![s_tmpl("tmpl-1", Some("tmpl"), TMPL_STMT)],
                vec![s_pol("pol-1", Some("pol"), POL_FORBID)],
            ),
        );
        assert!(plan.is_empty(), "trimmed statements should match");
    }

    // -- format_summary tests -------------------------------------------------

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
        let output = format_summary(&SyncResult {
            schema_updated: true,
            created_templates: 0,
            deleted_templates: 0,
            created_policies: 0,
            deleted_policies: 0,
        });
        assert!(output.contains("Schema: updated"));
        assert!(output.contains("Templates: 0 created, 0 deleted"));
        assert!(output.contains("Policies: 0 created, 0 deleted"));
    }

    #[test]
    fn format_summary_mixed() {
        let output = format_summary(&SyncResult {
            schema_updated: false,
            created_templates: 2,
            deleted_templates: 1,
            created_policies: 3,
            deleted_policies: 0,
        });
        assert!(output.contains("Schema: unchanged"));
        assert!(output.contains("Templates: 2 created, 1 deleted"));
        assert!(output.contains("Policies: 3 created, 0 deleted"));
    }

    #[test]
    fn format_summary_all_changes() {
        let output = format_summary(&SyncResult {
            schema_updated: true,
            created_templates: 1,
            deleted_templates: 2,
            created_policies: 3,
            deleted_policies: 4,
        });
        assert!(output.contains("Schema: updated"));
        assert!(output.contains("Templates: 1 created, 2 deleted"));
        assert!(output.contains("Policies: 3 created, 4 deleted"));
    }
}
