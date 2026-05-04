//! Pure helpers for the V3 Active-org write path.
//!
//! Lifted out of `pure.rs` to keep that file under the 1000-line cap. Every
//! function here is deterministic and free of I/O — the imperative shell in
//! `active.rs` drives them, and `pure.rs::shape_group_error_response` consumes
//! the wire-body types defined at the bottom of this module.

use std::collections::{BTreeSet, VecDeque};

use forgeguard_authz_core::{
    compile_rbac_to_cedar, policy_name_for_group, GroupValidationError, NamedPermit, RbacEntry,
    TenantConfig,
};
use forgeguard_core::OrgStatus;
use serde::Serialize;

use crate::store::OrgRecord;

// ---------------------------------------------------------------------------
// Active-org write context — Parse-Don't-Validate at the handler boundary
// ---------------------------------------------------------------------------

/// Everything the Active write path needs to push policies into Verified
/// Permissions: the policy-store id and the Cedar compile inputs.
///
/// Constructed only by `OrgWriteContext::from_record`, which guarantees the
/// `vp_store_id` is present (i.e. the org is fully provisioned).
#[derive(Debug, Clone)]
pub(crate) struct VpContext {
    pub(crate) store_id: String,
    pub(crate) namespace: String,
    pub(crate) tenant: TenantConfig,
}

/// The two write states a group handler can encounter for an org.
///
/// Parsing happens once at the handler boundary; the orchestrator never
/// re-checks `Option<vp_store_id>`.
#[derive(Debug, Clone)]
pub(crate) enum OrgWriteContext {
    /// Org is in Draft status. Group writes only touch DDB.
    Draft,
    /// Org is in Active status with a populated `vp_store_id`.
    Active(VpContext),
}

/// Why an org failed to parse into an `OrgWriteContext`.
///
/// Currently only `ActiveWithoutVpStore`, which happens when an org's status
/// is `Active` but its config is missing `vp_store_id`. The saga that flips
/// status to Active is supposed to populate `vp_store_id` first; this variant
/// catches the case where that invariant was violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActiveStateError {
    ActiveWithoutVpStore,
}

impl OrgWriteContext {
    /// Parse an `OrgRecord` into the write context the handler should use.
    ///
    /// - `OrgStatus::Active` + `OrgConfig.vp_store_id == Some(_)` → `Active`.
    /// - `OrgStatus::Active` + missing `vp_store_id` → `ActiveStateError`. This
    ///   shapes as 503 `vp_push_failed { stage: parent }` per the V3 boundary
    ///   decision (Risk #5 in the implementation plan).
    /// - Anything else → `Draft`. (V3 only distinguishes Active vs not; future
    ///   slices will refine the intermediate states.)
    pub(crate) fn from_record(record: &OrgRecord) -> std::result::Result<Self, ActiveStateError> {
        if record.org().status() != OrgStatus::Active {
            return Ok(Self::Draft);
        }
        let cfg = record
            .config()
            .ok_or(ActiveStateError::ActiveWithoutVpStore)?;
        let store_id = cfg
            .vp_store_id()
            .ok_or(ActiveStateError::ActiveWithoutVpStore)?
            .to_owned();
        Ok(Self::Active(VpContext {
            store_id,
            namespace: cfg.namespace().to_owned(),
            tenant: cfg.tenant().clone(),
        }))
    }
}

/// The result of compiling an `RbacEntry` plus its transitive dependents into
/// VP-ready permits.
///
/// `dependents` is sorted globally alphabetically so the fanout walk is
/// deterministic across runs (key for F4 reproducibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledPermits {
    pub(crate) parent: NamedPermit,
    pub(crate) dependents: Vec<NamedPermit>,
}

/// Which step of the Active write path was running when a VP call failed.
///
/// Used as the `stage` label on `forgeguard_cp_group_rollback_failed_total`
/// and as the `stage` field in the 503/500 error body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpStage {
    /// The parent CREATE/DELETE that mirrors the DDB write.
    Parent,
    /// The dependent re-emit that runs after a successful parent UPDATE.
    Fanout,
}

impl VpStage {
    /// Stable snake_case label for metrics and JSON bodies.
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::Fanout => "fanout",
        }
    }
}

// ---------------------------------------------------------------------------
// Dependency walking + Cedar compilation for the Active write path
// ---------------------------------------------------------------------------

/// Transitive inheritors of `parent_name` from `all_after`, sorted by group
/// name.
///
/// Walks the inverse-`inherits` relation: a group `g` is included if its
/// `inherits` chain (directly or transitively) contains `parent_name`. The
/// result is sorted alphabetically so the fanout walk is reproducible across
/// runs (HashMap iteration order would otherwise leak in).
///
/// `parent_name` itself is never included.
///
/// # Precondition: no cycles
///
/// The caller guarantees that `all_after` contains no inheritance cycles.
/// This invariant is enforced by `validate_rbac_entry` at write time, which
/// rejects any entry whose `inherits` chain forms a cycle before it reaches
/// the store. If the invariant is violated (e.g. by a self-loop), the BFS
/// still terminates because each entry name is added to `visited` at most
/// once — so a self-referencing entry cannot be enqueued a second time.
pub(crate) fn compute_dependents_in_order<'a>(
    parent_name: &str,
    all_after: &'a [RbacEntry],
) -> Vec<&'a RbacEntry> {
    let mut frontier: VecDeque<&str> = VecDeque::new();
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    frontier.push_back(parent_name);

    while let Some(current) = frontier.pop_front() {
        for entry in all_after {
            // Never add the root parent to visited — the final filter on
            // visited membership is what excludes it from the output.
            if entry.name == parent_name {
                continue;
            }
            if visited.contains(entry.name.as_str()) {
                continue;
            }
            if entry.inherits.iter().any(|i| i == current) {
                visited.insert(entry.name.as_str());
                frontier.push_back(entry.name.as_str());
            }
        }
    }

    let mut out: Vec<&RbacEntry> = all_after
        .iter()
        .filter(|e| visited.contains(e.name.as_str()))
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Compile a parent RBAC entry plus its transitive dependents into a
/// `CompiledPermits` ready to push to VP.
///
/// Each permit carries its canonical `cp-rbac-{name}` policy name. The
/// dependents are alphabetically ordered (see `compute_dependents_in_order`).
///
/// Compile failures from any single entry are surfaced as
/// `GroupValidationError::BadActionFormat` (the only validation failure mode
/// that `compile_rbac_to_cedar` currently signals through its `String` error
/// — `validate_cedar_ident` rejects non-conforming names and actions).
pub(crate) fn compile_for_active(
    parent: &RbacEntry,
    all_after: &[RbacEntry],
    vp_ctx: &VpContext,
) -> std::result::Result<CompiledPermits, GroupValidationError> {
    let parent_permit = compile_one(parent, vp_ctx)?;
    let dependents = compute_dependents_in_order(&parent.name, all_after)
        .into_iter()
        .map(|entry| compile_one(entry, vp_ctx))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(CompiledPermits {
        parent: parent_permit,
        dependents,
    })
}

fn compile_one(
    entry: &RbacEntry,
    vp_ctx: &VpContext,
) -> std::result::Result<NamedPermit, GroupValidationError> {
    let statement = compile_rbac_to_cedar(entry, &vp_ctx.tenant, &vp_ctx.namespace)
        .map_err(|msg| GroupValidationError::BadActionFormat { action: msg })?;
    Ok(NamedPermit {
        name: policy_name_for_group(&entry.name),
        statement,
    })
}

// ---------------------------------------------------------------------------
// Wire body for the V3 error variants
// ---------------------------------------------------------------------------

/// 503 body when the Active write path can't push to VP.
#[derive(Debug, Serialize)]
pub(crate) struct VpPushFailedBody<'a> {
    /// Always `"vp_push_failed"`.
    pub(crate) error: &'static str,
    /// `"parent"` or `"fanout"`.
    pub(crate) stage: &'static str,
    pub(crate) completed: &'a [String],
    pub(crate) failed: Option<&'a str>,
    pub(crate) remaining: &'a [String],
}

/// 500 body when DDB and VP have diverged and rollback failed.
#[derive(Debug, Serialize)]
pub(crate) struct InconsistentStateBody {
    /// Always `"inconsistent_state"`.
    pub(crate) error: &'static str,
    pub(crate) ddb_committed: bool,
    pub(crate) vp_committed: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::TimeZone;
    use forgeguard_core::{Organization, OrganizationId};

    use super::*;
    use crate::config::OrgConfig;
    use crate::store::{ConfiguredConfig, OrgRecord};

    // -----------------------------------------------------------------------
    // VpStage label
    // -----------------------------------------------------------------------

    #[test]
    fn vp_stage_parent_label() {
        assert_eq!(VpStage::Parent.as_label(), "parent");
    }

    #[test]
    fn vp_stage_fanout_label() {
        assert_eq!(VpStage::Fanout.as_label(), "fanout");
    }

    // -----------------------------------------------------------------------
    // OrgWriteContext::from_record
    // -----------------------------------------------------------------------

    fn make_org(status: OrgStatus) -> Organization {
        let now = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        Organization::new(
            OrganizationId::new("org-1").unwrap(),
            "Org One".to_owned(),
            status,
            now,
        )
    }

    fn config_with_vp_store(vp_store_id: Option<&str>) -> OrgConfig {
        let mut value = serde_json::json!({
            "version": "2026-04-07",
            "project_id": "proj",
            "upstream_url": "https://example.com",
            "default_policy": "deny",
            "namespace": "customer-app",
            "tenant": {"enabled": true, "principal_attribute": "tenant_id", "resource_attribute": "tenant_id"}
        });
        if let Some(id) = vp_store_id {
            value["vp_store_id"] = serde_json::Value::String(id.to_owned());
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn from_record_draft_org_returns_draft() {
        let record = OrgRecord::new(make_org(OrgStatus::Draft), None);
        let ctx = OrgWriteContext::from_record(&record).unwrap();
        assert!(matches!(ctx, OrgWriteContext::Draft));
    }

    #[test]
    fn from_record_active_with_vp_store_returns_active() {
        let cfg = config_with_vp_store(Some("ps-abc"));
        let configured = ConfiguredConfig::compute(cfg).unwrap();
        let record = OrgRecord::new(make_org(OrgStatus::Active), Some(configured));
        let ctx = OrgWriteContext::from_record(&record).unwrap();
        match ctx {
            OrgWriteContext::Active(vp) => {
                assert_eq!(vp.store_id, "ps-abc");
                assert_eq!(vp.namespace, "customer-app");
                assert!(vp.tenant.enabled);
            }
            OrgWriteContext::Draft => panic!("expected Active"),
        }
    }

    #[test]
    fn from_record_active_without_config_errors() {
        let record = OrgRecord::new(make_org(OrgStatus::Active), None);
        let err = OrgWriteContext::from_record(&record).unwrap_err();
        assert_eq!(err, ActiveStateError::ActiveWithoutVpStore);
    }

    #[test]
    fn from_record_active_without_vp_store_errors() {
        let cfg = config_with_vp_store(None);
        let configured = ConfiguredConfig::compute(cfg).unwrap();
        let record = OrgRecord::new(make_org(OrgStatus::Active), Some(configured));
        let err = OrgWriteContext::from_record(&record).unwrap_err();
        assert_eq!(err, ActiveStateError::ActiveWithoutVpStore);
    }

    // -----------------------------------------------------------------------
    // compute_dependents_in_order
    // -----------------------------------------------------------------------

    fn entry(name: &str, inherits: Vec<&str>) -> RbacEntry {
        RbacEntry {
            name: name.to_owned(),
            description: None,
            inherits: inherits.into_iter().map(str::to_owned).collect(),
            allow: vec!["cp:x:read".to_owned()],
            tenant_scoped: false,
        }
    }

    #[test]
    fn dependents_no_inheritors_returns_empty() {
        let all = vec![entry("member", vec![]), entry("editor", vec![])];
        let deps = compute_dependents_in_order("member", &all);
        assert!(deps.is_empty());
    }

    #[test]
    fn dependents_direct_inheritor() {
        let all = vec![entry("member", vec![]), entry("admin", vec!["member"])];
        let deps = compute_dependents_in_order("member", &all);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "admin");
    }

    #[test]
    fn dependents_transitive_chain() {
        // member <- admin <- owner
        let all = vec![
            entry("member", vec![]),
            entry("admin", vec!["member"]),
            entry("owner", vec!["admin"]),
        ];
        let deps = compute_dependents_in_order("member", &all);
        let names: Vec<&str> = deps.iter().map(|e| e.name.as_str()).collect();
        // Sorted alphabetically: admin, owner.
        assert_eq!(names, ["admin", "owner"]);
    }

    #[test]
    fn dependents_alphabetical_order_independent_of_input_order() {
        // Insertion order: zeta, alpha, mu — all directly inherit from member.
        let all = vec![
            entry("member", vec![]),
            entry("zeta", vec!["member"]),
            entry("alpha", vec!["member"]),
            entry("mu", vec!["member"]),
        ];
        let deps = compute_dependents_in_order("member", &all);
        let names: Vec<&str> = deps.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["alpha", "mu", "zeta"]);
    }

    #[test]
    fn dependents_excludes_parent_itself() {
        let all = vec![entry("member", vec![]), entry("admin", vec!["member"])];
        let deps = compute_dependents_in_order("member", &all);
        assert!(deps.iter().all(|e| e.name != "member"));
    }

    #[test]
    fn dependents_unrelated_groups_not_included() {
        let all = vec![
            entry("member", vec![]),
            entry("admin", vec!["member"]),
            entry("isolated", vec![]),
        ];
        let deps = compute_dependents_in_order("member", &all);
        let names: Vec<&str> = deps.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["admin"]);
    }

    // -----------------------------------------------------------------------
    // compile_for_active
    // -----------------------------------------------------------------------

    fn vp_ctx() -> VpContext {
        VpContext {
            store_id: "ps-test".to_owned(),
            namespace: "app".to_owned(),
            tenant: TenantConfig::default(),
        }
    }

    #[test]
    fn compile_for_active_parent_only() {
        let parent = entry("admin", vec![]);
        let all = vec![parent.clone()];
        let compiled = compile_for_active(&parent, &all, &vp_ctx()).unwrap();
        assert_eq!(compiled.parent.name, "cp-rbac-admin");
        assert!(compiled.parent.statement.contains("app::Group::\"admin\""));
        assert!(compiled.dependents.is_empty());
    }

    #[test]
    fn compile_for_active_with_dependents_in_order() {
        let parent = entry("member", vec![]);
        let all = vec![
            parent.clone(),
            entry("zeta", vec!["member"]),
            entry("alpha", vec!["member"]),
        ];
        let compiled = compile_for_active(&parent, &all, &vp_ctx()).unwrap();
        let dep_names: Vec<&str> = compiled
            .dependents
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(dep_names, ["cp-rbac-alpha", "cp-rbac-zeta"]);
    }

    #[test]
    fn compile_for_active_propagates_compile_error() {
        // An entry with an empty allow list fails compilation.
        let bad = RbacEntry {
            name: "broken".to_owned(),
            description: None,
            inherits: vec![],
            allow: vec![],
            tenant_scoped: false,
        };
        let all = vec![bad.clone()];
        let err = compile_for_active(&bad, &all, &vp_ctx()).unwrap_err();
        assert!(matches!(err, GroupValidationError::BadActionFormat { .. }));
    }

    #[test]
    fn compile_for_active_byte_stable_across_runs() {
        let parent = entry("admin", vec![]);
        let all = vec![parent.clone()];
        let a = compile_for_active(&parent, &all, &vp_ctx()).unwrap();
        let b = compile_for_active(&parent, &all, &vp_ctx()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn compile_for_active_propagates_dependent_compile_error() {
        // The parent compiles fine, but the dependent has an empty allow list
        // (same failing pattern as `compile_for_active_propagates_compile_error`).
        let parent = entry("member", vec![]);
        let bad_dependent = RbacEntry {
            name: "broken-child".to_owned(),
            description: None,
            inherits: vec!["member".to_owned()],
            allow: vec![],
            tenant_scoped: false,
        };
        let all = vec![parent.clone(), bad_dependent];
        let err = compile_for_active(&parent, &all, &vp_ctx()).unwrap_err();
        assert!(matches!(err, GroupValidationError::BadActionFormat { .. }));
    }

    // -----------------------------------------------------------------------
    // OrgWriteContext::from_record — Draft short-circuit
    // -----------------------------------------------------------------------

    #[test]
    fn from_record_draft_org_with_config_still_returns_draft() {
        // Status check MUST short-circuit ahead of config inspection.
        // A Draft org with a populated config (including vp_store_id) must still
        // resolve as Draft rather than Active.
        let cfg = config_with_vp_store(Some("ps-draft-with-store"));
        let configured = ConfiguredConfig::compute(cfg).unwrap();
        let record = OrgRecord::new(make_org(OrgStatus::Draft), Some(configured));
        let ctx = OrgWriteContext::from_record(&record).unwrap();
        assert!(
            matches!(ctx, OrgWriteContext::Draft),
            "expected Draft, got Active — status must short-circuit before config inspection"
        );
    }

    // -----------------------------------------------------------------------
    // compute_dependents_in_order — self-loop terminates
    // -----------------------------------------------------------------------

    #[test]
    fn compute_dependents_terminates_on_self_loop() {
        // `root` inherits from itself — a cycle that validate_rbac_entry would
        // reject at write time. The BFS must still terminate and must NOT include
        // the self-looping entry in the output (since `root` == parent_name and
        // the parent is always excluded from results).
        let root = RbacEntry {
            name: "root".to_owned(),
            description: None,
            inherits: vec!["root".to_owned()],
            allow: vec!["cp:x:read".to_owned()],
            tenant_scoped: false,
        };
        let entries = vec![root];
        // Must return without hanging.
        let result = compute_dependents_in_order("root", &entries);
        // The self-looping entry is the parent itself, so it must be excluded.
        assert!(
            result.is_empty(),
            "expected empty Vec, got: {result:?} — self-loop should not appear in dependents"
        );
    }
}
