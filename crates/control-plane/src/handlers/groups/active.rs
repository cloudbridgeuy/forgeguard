//! Imperative shell for the V3 Active-org write path.
//!
//! Three orchestrators — [`apply_create`], [`apply_update`], [`apply_delete`] —
//! pair a single DDB mutation with a sequence of Verified Permissions pushes.
//! Each function owns its rollback strategy and returns a [`GroupHandlerError`]
//! ready for `shape_group_error_response`.
//!
//! ## Failure-mode legend
//!
//! - **F3** — VP push fails after a successful DDB write. The orchestrator
//!   attempts a compensating DDB mutation; on success the caller surfaces 503
//!   `vp_push_failed`. The DDB record matches the pre-call state; VP may have
//!   diverged (e.g. parent policy deleted but not recreated) — the reconciler
//!   ticket (V4) handles that.
//! - **F3'** — Compensating DDB mutation also fails. The orchestrator bumps
//!   `forgeguard_cp_group_rollback_failed_total{stage="parent"}` and surfaces
//!   500 `inconsistent_state`.
//! - **F4** — Mid-fanout failure during UPDATE. No rollback; the caller
//!   surfaces 503 with `{completed, failed, remaining}`.

use forgeguard_authz_core::{policy_name_for_group, NamedPermit, ValidatedRbacEntry};
use forgeguard_core::OrganizationId;

use super::active_pure::{CompiledPermits, VpContext, VpStage};
use super::pure::GroupHandlerError;
use crate::error::Error;
use crate::metrics::{
    record_group_rollback_failed, record_precondition_failed, PreconditionReason,
};
use crate::store::{EtagedGroup, OrgStore};
use crate::vp_client::{self, VpClient};

/// Inputs to [`apply_create`].
pub(crate) struct CreateParams<'a, S, V> {
    pub(crate) store: &'a S,
    pub(crate) vp: &'a V,
    pub(crate) vp_ctx: &'a VpContext,
    pub(crate) org_id: &'a OrganizationId,
    pub(crate) raw_org_id: &'a str,
    pub(crate) validated: ValidatedRbacEntry,
    pub(crate) compiled: CompiledPermits,
}

/// Inputs to [`apply_update`].
pub(crate) struct UpdateParams<'a, S, V> {
    pub(crate) store: &'a S,
    pub(crate) vp: &'a V,
    pub(crate) vp_ctx: &'a VpContext,
    pub(crate) org_id: &'a OrganizationId,
    pub(crate) raw_org_id: &'a str,
    pub(crate) validated: ValidatedRbacEntry,
    pub(crate) compiled: CompiledPermits,
    /// The pre-write entry, validated against the pre-write set so it can be
    /// re-inserted on rollback.
    pub(crate) prior_for_rollback: ValidatedRbacEntry,
    pub(crate) expected_etag: String,
}

/// Inputs to [`apply_delete`].
pub(crate) struct DeleteParams<'a, S, V> {
    pub(crate) store: &'a S,
    pub(crate) vp: &'a V,
    pub(crate) vp_ctx: &'a VpContext,
    pub(crate) org_id: &'a OrganizationId,
    pub(crate) raw_org_id: &'a str,
    pub(crate) name: String,
    pub(crate) expected_etag: String,
    pub(crate) prior_for_rollback: ValidatedRbacEntry,
}

/// Inputs to [`rollback_create`].
struct RollbackCreateParams<'a, S> {
    store: &'a S,
    org_id: &'a OrganizationId,
    raw_org_id: &'a str,
    entry_name: &'a str,
    written_etag: &'a str,
    parent_name: &'a str,
}

/// Inputs to [`rollback_update`].
struct RollbackUpdateParams<'a, S> {
    store: &'a S,
    org_id: &'a OrganizationId,
    raw_org_id: &'a str,
    entry_name: &'a str,
    prior: ValidatedRbacEntry,
    written_etag: &'a str,
    parent_name: &'a str,
}

/// Inputs to [`rollback_delete`].
struct RollbackDeleteParams<'a, S> {
    store: &'a S,
    org_id: &'a OrganizationId,
    raw_org_id: &'a str,
    entry_name: &'a str,
    prior: ValidatedRbacEntry,
    policy_name: &'a str,
}

/// Active-org create: DDB put → VP `CreatePolicy` for the parent.
///
/// On VP failure, attempts to undo the DDB write via `delete_group`. F3'
/// fires when the rollback itself fails.
pub(crate) async fn apply_create<S: OrgStore, V: VpClient>(
    p: CreateParams<'_, S, V>,
) -> Result<EtagedGroup, GroupHandlerError> {
    debug_assert!(
        p.compiled.dependents.is_empty(),
        "apply_create should never see dependents — a brand-new group cannot be inherited from yet",
    );
    let entry_name = p.validated.entry().name.clone();
    let parent_name = p.compiled.parent.name.clone();

    let eg = p
        .store
        .put_group(p.org_id, p.validated, None)
        .await
        .map_err(|e| match e {
            Error::Conflict(_) => GroupHandlerError::AlreadyExists,
            other => {
                tracing::error!(
                    org_id = %p.raw_org_id,
                    group = %entry_name,
                    error = %other,
                    "active create: ddb put failed",
                );
                GroupHandlerError::Internal
            }
        })?;

    if let Err(vp_err) =
        p.vp.create_policy(
            &p.vp_ctx.store_id,
            &parent_name,
            None,
            &p.compiled.parent.statement,
        )
        .await
    {
        tracing::warn!(
            org_id = %p.raw_org_id,
            group = %entry_name,
            policy = %parent_name,
            error = %vp_err,
            "active create: vp parent push failed; rolling back ddb",
        );
        return rollback_create(RollbackCreateParams {
            store: p.store,
            org_id: p.org_id,
            raw_org_id: p.raw_org_id,
            entry_name: &entry_name,
            written_etag: eg.etag(),
            parent_name: &parent_name,
        })
        .await;
    }

    Ok(eg)
}

async fn rollback_create<S: OrgStore>(
    p: RollbackCreateParams<'_, S>,
) -> Result<EtagedGroup, GroupHandlerError> {
    match p
        .store
        .delete_group(p.org_id, p.entry_name, p.written_etag)
        .await
    {
        Ok(()) => Err(GroupHandlerError::VpPushFailed {
            stage: VpStage::Parent,
            completed: vec![],
            failed: Some(p.parent_name.to_owned()),
            remaining: vec![],
        }),
        Err(rollback_err) => {
            tracing::error!(
                org_id = %p.raw_org_id,
                group = %p.entry_name,
                error = %rollback_err,
                "active create: ddb rollback failed; ddb and vp now inconsistent",
            );
            record_group_rollback_failed(VpStage::Parent.as_label());
            Err(GroupHandlerError::InconsistentState {
                ddb_committed: true,
                vp_committed: false,
            })
        }
    }
}

/// Active-org update: DDB put → VP `DeletePolicy` then `CreatePolicy` for the
/// parent → fanout the same delete-then-create pair across each transitive
/// dependent in deterministic alphabetical order.
///
/// Failure handling:
/// - Parent VP failure: rollback the DDB put by re-inserting the prior entry.
///   F3' fires if the put_back itself fails.
/// - Fanout failure: no rollback. F4 surfaces with `(completed, failed,
///   remaining)` so the caller can drive a manual replay.
pub(crate) async fn apply_update<S: OrgStore, V: VpClient>(
    p: UpdateParams<'_, S, V>,
) -> Result<EtagedGroup, GroupHandlerError> {
    let entry_name = p.validated.entry().name.clone();
    let parent_name = p.compiled.parent.name.clone();

    let eg = p
        .store
        .put_group(p.org_id, p.validated, Some(&p.expected_etag))
        .await
        .map_err(|e| match e {
            Error::PreconditionFailed { current_etag } => {
                record_precondition_failed(PreconditionReason::StaleEtag);
                GroupHandlerError::PreconditionFailed {
                    current_etag,
                    reason: PreconditionReason::StaleEtag,
                }
            }
            Error::NotFound(_) => GroupHandlerError::NotFound,
            other => {
                tracing::error!(
                    org_id = %p.raw_org_id,
                    group = %entry_name,
                    error = %other,
                    "active update: ddb put failed",
                );
                GroupHandlerError::Internal
            }
        })?;

    if let Err(vp_err) = push_permit(p.vp, &p.vp_ctx.store_id, &p.compiled.parent).await {
        tracing::warn!(
            org_id = %p.raw_org_id,
            group = %entry_name,
            policy = %parent_name,
            error = %vp_err,
            "active update: vp parent push failed; rolling back ddb",
        );
        return rollback_update(RollbackUpdateParams {
            store: p.store,
            org_id: p.org_id,
            raw_org_id: p.raw_org_id,
            entry_name: &entry_name,
            prior: p.prior_for_rollback,
            written_etag: eg.etag(),
            parent_name: &parent_name,
        })
        .await;
    }

    let mut completed: Vec<String> = Vec::with_capacity(p.compiled.dependents.len());
    for (i, dep) in p.compiled.dependents.iter().enumerate() {
        match push_permit(p.vp, &p.vp_ctx.store_id, dep).await {
            Ok(()) => completed.push(dep.name.clone()),
            Err(vp_err) => {
                tracing::warn!(
                    org_id = %p.raw_org_id,
                    group = %entry_name,
                    policy = %dep.name,
                    error = %vp_err,
                    fanout_index = i + 1,
                    fanout_total = p.compiled.dependents.len(),
                    "active update: vp fanout push failed",
                );
                let remaining: Vec<String> = p.compiled.dependents[i + 1..]
                    .iter()
                    .map(|d| d.name.clone())
                    .collect();
                return Err(GroupHandlerError::VpPushFailed {
                    stage: VpStage::Fanout,
                    completed,
                    failed: Some(dep.name.clone()),
                    remaining,
                });
            }
        }
    }

    Ok(eg)
}

async fn rollback_update<S: OrgStore>(
    p: RollbackUpdateParams<'_, S>,
) -> Result<EtagedGroup, GroupHandlerError> {
    match p
        .store
        .put_group(p.org_id, p.prior, Some(p.written_etag))
        .await
    {
        Ok(_) => Err(GroupHandlerError::VpPushFailed {
            stage: VpStage::Parent,
            completed: vec![],
            failed: Some(p.parent_name.to_owned()),
            remaining: vec![],
        }),
        Err(rollback_err) => {
            tracing::error!(
                org_id = %p.raw_org_id,
                group = %p.entry_name,
                error = %rollback_err,
                "active update: ddb rollback failed; ddb and vp now inconsistent",
            );
            record_group_rollback_failed(VpStage::Parent.as_label());
            Err(GroupHandlerError::InconsistentState {
                ddb_committed: true,
                vp_committed: false,
            })
        }
    }
}

/// Active-org delete: DDB delete → VP `DeletePolicy`.
///
/// Per shaping doc A8.3, DELETE does not fan out to dependents. On VP failure
/// the orchestrator restores the prior DDB row; F3' fires if that put_back
/// fails. A VP `NotFound` is treated as idempotent success.
pub(crate) async fn apply_delete<S: OrgStore, V: VpClient>(
    p: DeleteParams<'_, S, V>,
) -> Result<(), GroupHandlerError> {
    p.store
        .delete_group(p.org_id, &p.name, &p.expected_etag)
        .await
        .map_err(|e| match e {
            Error::PreconditionFailed { current_etag } => {
                record_precondition_failed(PreconditionReason::StaleEtag);
                GroupHandlerError::PreconditionFailed {
                    current_etag,
                    reason: PreconditionReason::StaleEtag,
                }
            }
            Error::NotFound(_) => GroupHandlerError::NotFound,
            other => {
                tracing::error!(
                    org_id = %p.raw_org_id,
                    group = %p.name,
                    error = %other,
                    "active delete: ddb delete failed",
                );
                GroupHandlerError::Internal
            }
        })?;

    let policy_name = policy_name_for_group(&p.name);
    match p
        .vp
        .delete_policy_by_name(&p.vp_ctx.store_id, &policy_name)
        .await
    {
        Ok(()) => Ok(()),
        Err(vp_client::Error::NotFound(_)) => {
            tracing::info!(
                org_id = %p.raw_org_id,
                group = %p.name,
                policy = %policy_name,
                "active delete: vp policy already absent (idempotent)",
            );
            Ok(())
        }
        Err(vp_err) => {
            tracing::warn!(
                org_id = %p.raw_org_id,
                group = %p.name,
                policy = %policy_name,
                error = %vp_err,
                "active delete: vp delete failed; rolling back ddb",
            );
            rollback_delete(RollbackDeleteParams {
                store: p.store,
                org_id: p.org_id,
                raw_org_id: p.raw_org_id,
                entry_name: &p.name,
                prior: p.prior_for_rollback,
                policy_name: &policy_name,
            })
            .await
        }
    }
}

async fn rollback_delete<S: OrgStore>(
    p: RollbackDeleteParams<'_, S>,
) -> Result<(), GroupHandlerError> {
    match p.store.put_group(p.org_id, p.prior, None).await {
        Ok(_) => Err(GroupHandlerError::VpPushFailed {
            stage: VpStage::Parent,
            completed: vec![],
            failed: Some(p.policy_name.to_owned()),
            remaining: vec![],
        }),
        Err(rollback_err) => {
            tracing::error!(
                org_id = %p.raw_org_id,
                group = %p.entry_name,
                error = %rollback_err,
                "active delete: ddb rollback failed; ddb and vp now inconsistent",
            );
            record_group_rollback_failed(VpStage::Parent.as_label());
            Err(GroupHandlerError::InconsistentState {
                ddb_committed: true,
                vp_committed: false,
            })
        }
    }
}

/// Push a single named permit into VP via delete-then-create.
///
/// VP has no upsert primitive, so we delete the named policy first (treating
/// `NotFound` as idempotent success) and then create the new one. Any other
/// error from delete is surfaced because the subsequent create would conflict
/// with the still-present old policy.
///
/// Reused by the V4 saga stub (`super::saga`) so the per-permit push semantics
/// stay identical between the per-request write path (V3) and the
/// Draft → Active materialization path (V4).
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
