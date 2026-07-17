//! Imperative shell for the V4 Active-org write path.
//!
//! Three orchestrators — [`apply_create`], [`apply_update`], [`apply_delete`] —
//! pair a sequence of Verified Permissions pushes with a single event-sourced
//! append (`ModelEventStore::{put_group, delete_group}`). Each function owns
//! its compensation strategy and returns a [`GroupHandlerError`] ready for
//! `shape_group_error_response`.
//!
//! ## Ordering (D6 push-then-append)
//!
//! VP is pushed FIRST, then the append. This inverts the V3 ordering
//! (`groups-v3.md`'s F3/F3'/F4), which wrote DDB first and rolled it back on
//! a VP failure. The rationale: a VP failure now aborts the request cleanly
//! before anything is written — there is nothing to roll back. Only a VP
//! push that *succeeds* followed by an append that fails needs compensation,
//! and that compensation runs against VP (delete/recreate policies), not DDB.
//!
//! ## Failure-mode legend
//!
//! - **F-VP** (was F3): a VP push fails before any append is attempted.
//!   Nothing was written anywhere — the orchestrator returns
//!   `GroupHandlerError::VpPushFailed` (503) with no compensation to run.
//! - **F-VP-mid** (was F4, UPDATE fan-out only): a dependent push fails
//!   mid-fanout, after the parent and zero or more dependents already
//!   succeeded. The orchestrator recompiles the *prior* (pre-update)
//!   statements for the parent and every completed dependent and re-pushes
//!   them, then surfaces 503 `VpPushFailed` with `{completed, failed,
//!   remaining}`. Compensation failure bumps
//!   `forgeguard_cp_group_rollback_failed_total{stage="fanout"}` and surfaces
//!   500 `InconsistentState`.
//! - **F-append** (new): every VP push succeeded, but the
//!   `ModelEventStore::{put_group, delete_group}` append failed (stale
//!   `expected_revision` or an infrastructure error). The orchestrator
//!   compensates by restoring VP to its pre-call state (CREATE: delete the
//!   just-created parent policy; UPDATE: restore every prior statement
//!   pushed, parent + dependents; DELETE: re-push the deleted parent permit).
//!   Compensation failure bumps
//!   `forgeguard_cp_group_rollback_failed_total{stage="parent"}` (or
//!   `"fanout"` for UPDATE) and surfaces 500 `InconsistentState`.

use forgeguard_authz_core::{
    policy_name_for_group, Actor, NamedPermit, RbacEntry, Revision, ValidatedRbacEntry,
};
use forgeguard_core::OrganizationId;

use super::active_pure::{compile_for_active, compile_one, CompiledPermits, VpContext, VpStage};
use super::pure::GroupHandlerError;
use crate::metrics::record_group_rollback_failed;
use crate::model_event_store::{GroupWriteOutcome, ModelEventStore};
use crate::store::{EtagedGroup, OrgStore};
use crate::vp_client::{self, VpClient};

/// Inputs to [`apply_create`].
pub(crate) struct CreateParams<'a, V> {
    pub(crate) model_events: &'a dyn ModelEventStore,
    pub(crate) vp: &'a V,
    pub(crate) vp_ctx: &'a VpContext,
    pub(crate) org_id: &'a OrganizationId,
    pub(crate) raw_org_id: &'a str,
    pub(crate) validated: ValidatedRbacEntry,
    pub(crate) compiled: CompiledPermits,
    pub(crate) actor: Actor,
    pub(crate) expected_revision: Option<Revision>,
}

/// Inputs to [`apply_update`].
pub(crate) struct UpdateParams<'a, V> {
    pub(crate) model_events: &'a dyn ModelEventStore,
    pub(crate) vp: &'a V,
    pub(crate) vp_ctx: &'a VpContext,
    pub(crate) org_id: &'a OrganizationId,
    pub(crate) raw_org_id: &'a str,
    pub(crate) validated: ValidatedRbacEntry,
    pub(crate) compiled: CompiledPermits,
    /// The pre-write entry, validated against the pre-write set. Recompiled
    /// (alongside `prior_all`) into the prior parent statement for
    /// compensation.
    pub(crate) prior_for_rollback: ValidatedRbacEntry,
    /// The full pre-write entry set (before the proposed entry replaced its
    /// same-name row). Feeds `compile_for_active` so a mid-fanout or
    /// post-append compensation can recompile each completed dependent's
    /// *prior* statement.
    pub(crate) prior_all: Vec<RbacEntry>,
    pub(crate) actor: Actor,
    pub(crate) expected_revision: Option<Revision>,
}

/// Inputs to [`apply_delete`].
pub(crate) struct DeleteParams<'a, V> {
    /// Read-only existence check before touching VP — the D6 no-op contract
    /// (deleting an absent group) has no side effects, so an absent row must
    /// short-circuit before any VP call. Group reads stay on `OrgStore`
    /// (Task 3/6 only retire the group *write* methods).
    pub(crate) store: &'a dyn OrgStore,
    pub(crate) model_events: &'a dyn ModelEventStore,
    pub(crate) vp: &'a V,
    pub(crate) vp_ctx: &'a VpContext,
    pub(crate) org_id: &'a OrganizationId,
    pub(crate) raw_org_id: &'a str,
    pub(crate) name: String,
    /// The pre-delete entry, used to recompile the parent's permit for
    /// re-push if the append fails after the VP delete already succeeded.
    pub(crate) prior_for_rollback: ValidatedRbacEntry,
    pub(crate) actor: Actor,
    pub(crate) expected_revision: Option<Revision>,
}

/// Active-org create: VP `push_permit` for the parent → event-sourced append.
///
/// F-VP: the push fails → nothing written anywhere, no compensation needed.
/// F-append: the push succeeds but the append fails → compensate by deleting
/// the just-created parent policy. F-append-prime fires when that delete
/// itself fails.
pub(crate) async fn apply_create<V: VpClient>(
    p: CreateParams<'_, V>,
) -> Result<(EtagedGroup, GroupWriteOutcome), GroupHandlerError> {
    debug_assert!(
        p.compiled.dependents.is_empty(),
        "apply_create should never see dependents — a brand-new group cannot be inherited from yet",
    );
    let entry_name = p.validated.entry().name.clone();
    let parent_name = p.compiled.parent.name.clone();

    if let Err(vp_err) = push_permit(p.vp, &p.vp_ctx.store_id, &p.compiled.parent).await {
        tracing::warn!(
            org_id = %p.raw_org_id,
            group = %entry_name,
            policy = %parent_name,
            error = %vp_err,
            "active create: vp parent push failed; aborting before any write",
        );
        return Err(GroupHandlerError::VpPushFailed {
            stage: VpStage::Parent,
            completed: vec![],
            failed: Some(parent_name),
            remaining: vec![],
        });
    }

    let entry = p.validated.into_inner();
    let etaged = etaged_or_internal(entry.clone(), p.raw_org_id, &entry_name, "active create")?;

    match p
        .model_events
        .put_group(p.org_id.as_str(), entry, p.actor, p.expected_revision)
        .await
    {
        Ok(outcome) => Ok((etaged, outcome)),
        Err(append_err) => {
            tracing::warn!(
                org_id = %p.raw_org_id,
                group = %entry_name,
                error = %append_err,
                "active create: append failed after vp push; compensating (delete parent policy)",
            );
            let compensate = async {
                match p
                    .vp
                    .delete_policy_by_name(&p.vp_ctx.store_id, &parent_name)
                    .await
                {
                    Ok(()) | Err(vp_client::Error::NotFound(_)) => Ok(()),
                    Err(e) => Err(e),
                }
            };
            Err(resolve_append_compensation(AppendCompensation {
                compensate,
                append_err: &append_err,
                stage: VpStage::Parent,
                vp_committed: true,
                raw_org_id: p.raw_org_id,
                group_name: &entry_name,
                op: "active create",
            })
            .await)
        }
    }
}

/// Active-org update: VP delete-then-create for the parent, then the same
/// pair fanned out across every transitive dependent in deterministic
/// alphabetical order → event-sourced append.
///
/// F-VP: the parent push fails → nothing written, no compensation needed.
/// F-VP-mid: a dependent push fails mid-fanout → restore the prior
/// statements for the parent and every already-completed dependent, then
/// surface 503 with `{completed, failed, remaining}`. F-append: every push
/// succeeds but the append fails → restore ALL prior statements (parent +
/// every dependent).
pub(crate) async fn apply_update<V: VpClient>(
    p: UpdateParams<'_, V>,
) -> Result<(EtagedGroup, GroupWriteOutcome), GroupHandlerError> {
    let entry_name = p.validated.entry().name.clone();
    let parent_name = p.compiled.parent.name.clone();

    // Recompile the prior (pre-update) state for compensation. The prior
    // parent entry's own dependents list may differ from the post-update one
    // in exotic cases (concurrent edits), but each dependent's own compiled
    // statement only depends on its own entry — unaffected by the parent's
    // content change — so this recompilation is the correct "restore" target
    // regardless.
    let prior_compiled =
        match compile_for_active(p.prior_for_rollback.entry(), &p.prior_all, p.vp_ctx) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    org_id = %p.raw_org_id,
                    group = %entry_name,
                    error = %e,
                    "active update: prior entry failed recompilation; store is inconsistent",
                );
                return Err(GroupHandlerError::Internal);
            }
        };

    if let Err(vp_err) = push_permit(p.vp, &p.vp_ctx.store_id, &p.compiled.parent).await {
        tracing::warn!(
            org_id = %p.raw_org_id,
            group = %entry_name,
            policy = %parent_name,
            error = %vp_err,
            "active update: vp parent push failed; aborting before any write",
        );
        return Err(GroupHandlerError::VpPushFailed {
            stage: VpStage::Parent,
            completed: vec![],
            failed: Some(parent_name),
            remaining: p
                .compiled
                .dependents
                .iter()
                .map(|d| d.name.clone())
                .collect(),
        });
    }

    let mut completed: Vec<NamedPermit> = Vec::with_capacity(p.compiled.dependents.len());
    for (i, dep) in p.compiled.dependents.iter().enumerate() {
        match push_permit(p.vp, &p.vp_ctx.store_id, dep).await {
            Ok(()) => completed.push(dep.clone()),
            Err(vp_err) => {
                tracing::warn!(
                    org_id = %p.raw_org_id,
                    group = %entry_name,
                    policy = %dep.name,
                    error = %vp_err,
                    fanout_index = i + 1,
                    fanout_total = p.compiled.dependents.len(),
                    "active update: vp fanout push failed; restoring completed priors",
                );
                let remaining: Vec<String> = p.compiled.dependents[i + 1..]
                    .iter()
                    .map(|d| d.name.clone())
                    .collect();
                let completed_names: Vec<String> =
                    completed.iter().map(|c| c.name.clone()).collect();

                let restore_targets = restore_targets_for(&prior_compiled, &completed_names);
                return match restore_priors(p.vp, &p.vp_ctx.store_id, &restore_targets).await {
                    Ok(()) => Err(GroupHandlerError::VpPushFailed {
                        stage: VpStage::Fanout,
                        completed: completed_names,
                        failed: Some(dep.name.clone()),
                        remaining,
                    }),
                    Err(restore_err) => {
                        tracing::error!(
                            org_id = %p.raw_org_id,
                            group = %entry_name,
                            error = %restore_err,
                            "active update: fanout compensation failed; vp and ddb now inconsistent",
                        );
                        record_group_rollback_failed(VpStage::Fanout.as_label());
                        Err(GroupHandlerError::InconsistentState {
                            ddb_committed: false,
                            vp_committed: true,
                        })
                    }
                };
            }
        }
    }

    let entry = p.validated.into_inner();
    let etaged = etaged_or_internal(entry.clone(), p.raw_org_id, &entry_name, "active update")?;

    match p
        .model_events
        .put_group(p.org_id.as_str(), entry, p.actor, p.expected_revision)
        .await
    {
        Ok(outcome) => Ok((etaged, outcome)),
        Err(append_err) => {
            tracing::warn!(
                org_id = %p.raw_org_id,
                group = %entry_name,
                error = %append_err,
                "active update: append failed after all vp pushes; restoring all priors",
            );
            let all_names: Vec<String> = p
                .compiled
                .dependents
                .iter()
                .map(|d| d.name.clone())
                .collect();
            let restore_targets = restore_targets_for(&prior_compiled, &all_names);
            Err(resolve_append_compensation(AppendCompensation {
                compensate: restore_priors(p.vp, &p.vp_ctx.store_id, &restore_targets),
                append_err: &append_err,
                stage: VpStage::Fanout,
                vp_committed: true,
                raw_org_id: p.raw_org_id,
                group_name: &entry_name,
                op: "active update",
            })
            .await)
        }
    }
}

/// Active-org delete: existence check (skip VP entirely on a D6 no-op) → VP
/// `DeletePolicy` for the parent → event-sourced append.
///
/// Per shaping doc A8.3, DELETE does not fan out to dependents. A VP
/// `NotFound` is treated as idempotent success. F-append: the VP delete
/// succeeds but the append fails → re-push the prior parent permit.
pub(crate) async fn apply_delete<V: VpClient>(
    p: DeleteParams<'_, V>,
) -> Result<GroupWriteOutcome, GroupHandlerError> {
    // D6 no-op contract: an absent group must not touch VP at all.
    match p.store.get_group(p.org_id, &p.name).await {
        Ok(None) => {
            return p
                .model_events
                .delete_group(p.org_id.as_str(), &p.name, p.actor, p.expected_revision)
                .await
                .map_err(|e| {
                    tracing::error!(
                        org_id = %p.raw_org_id,
                        group = %p.name,
                        error = %e,
                        "active delete: no-op append failed",
                    );
                    GroupHandlerError::Internal
                });
        }
        Ok(Some(_)) => {}
        Err(e) => {
            tracing::error!(
                org_id = %p.raw_org_id,
                group = %p.name,
                error = %e,
                "active delete: existence check failed",
            );
            return Err(GroupHandlerError::Internal);
        }
    }

    let policy_name = policy_name_for_group(&p.name);
    match p
        .vp
        .delete_policy_by_name(&p.vp_ctx.store_id, &policy_name)
        .await
    {
        Ok(()) => {}
        Err(vp_client::Error::NotFound(_)) => {
            tracing::info!(
                org_id = %p.raw_org_id,
                group = %p.name,
                policy = %policy_name,
                "active delete: vp policy already absent (idempotent)",
            );
        }
        Err(vp_err) => {
            tracing::warn!(
                org_id = %p.raw_org_id,
                group = %p.name,
                policy = %policy_name,
                error = %vp_err,
                "active delete: vp delete failed; aborting before any write",
            );
            return Err(GroupHandlerError::VpPushFailed {
                stage: VpStage::Parent,
                completed: vec![],
                failed: Some(policy_name),
                remaining: vec![],
            });
        }
    }

    match p
        .model_events
        .delete_group(p.org_id.as_str(), &p.name, p.actor, p.expected_revision)
        .await
    {
        Ok(outcome) => Ok(outcome),
        Err(append_err) => {
            tracing::warn!(
                org_id = %p.raw_org_id,
                group = %p.name,
                error = %append_err,
                "active delete: append failed after vp delete; re-pushing prior permit",
            );
            let prior_permit = match compile_one(p.prior_for_rollback.entry(), p.vp_ctx) {
                Ok(permit) => permit,
                Err(e) => {
                    tracing::error!(
                        org_id = %p.raw_org_id,
                        group = %p.name,
                        error = %e,
                        "active delete: prior entry failed recompilation; store is inconsistent",
                    );
                    record_group_rollback_failed(VpStage::Parent.as_label());
                    return Err(GroupHandlerError::InconsistentState {
                        ddb_committed: false,
                        vp_committed: false,
                    });
                }
            };
            Err(resolve_append_compensation(AppendCompensation {
                compensate: push_permit(p.vp, &p.vp_ctx.store_id, &prior_permit),
                append_err: &append_err,
                stage: VpStage::Parent,
                vp_committed: false,
                raw_org_id: p.raw_org_id,
                group_name: &p.name,
                op: "active delete",
            })
            .await)
        }
    }
}

/// Compute a group's etag, mapping a failure to `GroupHandlerError::Internal`
/// with a log line identifying which orchestrator (`op`) surfaced it.
///
/// Shared by [`apply_create`] and [`apply_update`] — both need the etag of
/// the post-write entry before the append, and both treat a compute failure
/// identically.
fn etaged_or_internal(
    entry: RbacEntry,
    raw_org_id: &str,
    entry_name: &str,
    op: &str,
) -> Result<EtagedGroup, GroupHandlerError> {
    EtagedGroup::compute(entry).map_err(|e| {
        tracing::error!(org_id = %raw_org_id, group = %entry_name, error = %e, "{op}: etag compute failed");
        GroupHandlerError::Internal
    })
}

/// Inputs to [`resolve_append_compensation`].
struct AppendCompensation<'a, Fut, E> {
    /// The compensating VP action to run (delete the just-created parent,
    /// restore prior statements, or re-push the deleted parent permit).
    compensate: Fut,
    append_err: &'a E,
    stage: VpStage,
    /// Whether VP already reflects the write that DDB failed to record —
    /// `true` for create/update (the new statements were pushed before the
    /// append), `false` for delete (the parent statement was already gone).
    vp_committed: bool,
    raw_org_id: &'a str,
    group_name: &'a str,
    op: &'a str,
}

/// Runs the F-append compensation and classifies the result.
///
/// Every orchestrator hits this after the append fails post-VP-push: run
/// `compensate`, and on success the request still fails (the write never
/// landed) but VP is back to its pre-call state, so it's a plain `Internal`
/// (500) with no metric. On failure VP and DDB have now diverged — bump
/// `forgeguard_cp_group_rollback_failed_total{stage}` and surface
/// `InconsistentState` for manual reconciliation.
async fn resolve_append_compensation<Fut, E>(
    input: AppendCompensation<'_, Fut, E>,
) -> GroupHandlerError
where
    Fut: std::future::Future<Output = Result<(), vp_client::Error>>,
    E: std::fmt::Display,
{
    let AppendCompensation {
        compensate,
        append_err,
        stage,
        vp_committed,
        raw_org_id,
        group_name,
        op,
    } = input;

    match compensate.await {
        Ok(()) => {
            tracing::error!(
                org_id = %raw_org_id,
                group = %group_name,
                error = %append_err,
                "{op}: append failed; vp compensated cleanly",
            );
            GroupHandlerError::Internal
        }
        Err(rollback_err) => {
            tracing::error!(
                org_id = %raw_org_id,
                group = %group_name,
                error = %rollback_err,
                "{op}: vp compensation failed; vp and ddb now inconsistent",
            );
            record_group_rollback_failed(stage.as_label());
            GroupHandlerError::InconsistentState {
                ddb_committed: false,
                vp_committed,
            }
        }
    }
}

/// Select the prior parent permit plus the prior permits for every named
/// dependent in `names`, in `[parent, ...dependents]` order, ready for
/// [`restore_priors`].
fn restore_targets_for<'a>(
    prior_compiled: &'a CompiledPermits,
    names: &[String],
) -> Vec<&'a NamedPermit> {
    let mut targets = vec![&prior_compiled.parent];
    for name in names {
        if let Some(prior_dep) = prior_compiled.dependents.iter().find(|d| &d.name == name) {
            targets.push(prior_dep);
        }
    }
    targets
}

/// Re-push every permit in `targets`, stopping at the first failure.
///
/// Used to restore VP to its pre-call state after a mid-fanout or
/// post-append failure. Each target is pushed via [`push_permit`]
/// (delete-then-create, idempotent), so a partially-restored set from an
/// earlier attempt is safe to retry.
async fn restore_priors<V: VpClient>(
    vp: &V,
    store_id: &str,
    targets: &[&NamedPermit],
) -> Result<(), vp_client::Error> {
    for permit in targets {
        push_permit(vp, store_id, permit).await?;
    }
    Ok(())
}

/// Push a single named permit into VP via delete-then-create.
///
/// VP has no upsert primitive, so we delete the named policy first (treating
/// `NotFound` as idempotent success) and then create the new one. Any other
/// error from delete is surfaced because the subsequent create would conflict
/// with the still-present old policy.
///
/// Reused by the V4 saga stub (`super::saga`) so the per-permit push semantics
/// stay identical between the per-request write path and the Draft → Active
/// materialization path.
pub(super) async fn push_permit<V: VpClient>(
    vp: &V,
    store_id: &str,
    permit: &NamedPermit,
) -> Result<(), vp_client::Error> {
    match vp.delete_policy_by_name(store_id, &permit.name).await {
        Ok(()) | Err(vp_client::Error::NotFound(_)) => {}
        Err(e) => return Err(e),
    }
    vp.create_policy(store_id, &permit.name, None, &permit.statement)
        .await
        .map(|_| ())
}
