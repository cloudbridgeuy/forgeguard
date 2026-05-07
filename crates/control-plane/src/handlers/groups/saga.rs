//! Saga handoff stub for Draft → Active materialization (V4).
//!
//! `materialize_groups_to_vp` walks every declared group for an org, compiles
//! each via the shared `forgeguard_authz_core::groups_to_permits` pipeline,
//! and pushes each permit into the org's Verified Permissions store using the
//! V3 `push_permit` delete-then-create primitive.
//!
//! ## Failure mode
//!
//! V4 stops at the first push failure and returns
//! `MaterializeError::PushFailed { name, source }`. **No DDB rollback, no
//! Prometheus counter, no resume state** — the saga ticket (separate, future)
//! is responsible for retry semantics and partial-failure recovery.
//!
//! ## Order
//!
//! Permits are pushed alphabetically by group name (sorting happens inside the
//! pure `groups_to_permits`). This is for test reproducibility — Cedar permits
//! are independent so order has no semantic effect.
//!
//! ## Why this stub exists in V4 even though no Active org exists yet
//!
//! Issue #102 R2.3 requires the function to be wired so the saga ticket can
//! call into it without re-shaping the boundary. Unit tests against a fake
//! VP store (`StubVpClient`) prove the orchestration works; integration
//! against a real VP store happens once the saga lands.

use forgeguard_authz_core::{groups_to_permits, MaterializeCompileError, TenantConfig};
use forgeguard_core::OrganizationId;

use super::active::push_permit;
use crate::store::OrgStore;
use crate::vp_client::{self, VpClient};

/// Inputs to [`materialize_groups_to_vp`].
///
/// Bundled into a struct to avoid the `clippy::too_many_arguments` lint
/// (CLAUDE.md params-struct-rule). Callers construct one explicitly per call;
/// it is not `Clone` or `Default` because every field is required.
#[allow(dead_code)] // V4: caller (saga ticket) does not exist yet; covered by tests.
pub(crate) struct MaterializeParams<'a, V> {
    pub(crate) store: &'a dyn OrgStore,
    pub(crate) vp: &'a V,
    pub(crate) org_id: &'a OrganizationId,
    pub(crate) raw_org_id: &'a str,
    pub(crate) vp_store_id: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) tenant: &'a TenantConfig,
}

/// Failure modes for the V4 saga stub.
///
/// Each variant pinpoints which stage failed so the future saga ticket can
/// classify retries (compile failures are operator-visible bugs; push
/// failures are typically transient). The shared `Failed` suffix mirrors the
/// stage labels used by metrics and logs.
#[allow(dead_code)] // V4: variants surface in tests only until the saga ticket lands.
#[allow(clippy::enum_variant_names)] // shared `Failed` suffix is intentional.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MaterializeError {
    /// `OrgStore::list_groups` failed before any compile work happened.
    #[error("materialize: list_groups failed: {0}")]
    ListGroupsFailed(crate::error::Error),

    /// `forgeguard_authz_core::groups_to_permits` rejected one of the entries.
    /// The offending group's name is in `compile.name`.
    #[error("materialize: compile failed for group '{}': {}", .compile.name, .compile.reason)]
    CompileFailed { compile: MaterializeCompileError },

    /// VP push failed mid-walk. `name` is the policy name (`cp-rbac-{group}`).
    /// Permits before this one in alphabetical order are already in VP; the
    /// saga ticket decides whether to retry the whole batch or resume from
    /// `name`.
    #[error("materialize: vp push failed for policy '{name}': {source}")]
    PushFailed {
        name: String,
        #[source]
        source: vp_client::Error,
    },
}

/// Push every declared group for an org into the org's VP policy store.
///
/// Caller-supplied `vp_store_id`, `namespace`, and `tenant` come from the
/// org's `OrgConfig` (the saga ticket reads `OrgConfig` first; this function
/// stays oblivious to where they came from).
///
/// Returns `Ok(())` on success or the first error encountered. Permits up to
/// the failure point may have been pushed to VP — the saga ticket is the
/// recovery owner.
#[allow(dead_code)] // V4: caller (saga ticket) does not exist yet; covered by tests.
pub(crate) async fn materialize_groups_to_vp<V>(
    p: MaterializeParams<'_, V>,
) -> Result<(), MaterializeError>
where
    V: VpClient,
{
    let etaged = p
        .store
        .list_groups(p.org_id)
        .await
        .map_err(MaterializeError::ListGroupsFailed)?;

    let entries: Vec<_> = etaged.iter().map(|eg| eg.entry().clone()).collect();

    let permits = groups_to_permits(&entries, p.namespace, p.tenant)
        .map_err(|compile| MaterializeError::CompileFailed { compile })?;

    for permit in &permits {
        push_permit(p.vp, p.vp_store_id, permit)
            .await
            .map_err(|source| MaterializeError::PushFailed {
                name: permit.name.clone(),
                source,
            })?;
        tracing::info!(
            org_id = %p.raw_org_id,
            policy = %permit.name,
            "saga: pushed permit",
        );
    }

    tracing::info!(
        org_id = %p.raw_org_id,
        count = permits.len(),
        "saga: materialize_groups_to_vp completed",
    );
    Ok(())
}
