#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod context;
pub mod cp_model;
pub mod decision;
pub mod engine;
pub mod engine_cedar;
pub mod engine_cp;
pub mod error;
pub mod event;
pub mod query;
pub mod rbac;
pub mod snapshot;
pub mod store;

#[cfg(feature = "test-support")]
pub mod static_engine;

pub use context::PolicyContext;
pub use cp_model::compile_cp_model;
pub use decision::{DenyReason, PolicyDecision};
pub use engine::{CacheStats, PolicyEngine};
pub use engine_cedar::{
    CedarEngine, Decision, DecisionQuery, DecisionRecord, EmbeddedPolicyEngine,
};
pub use engine_cp::CpCedarEngine;
pub use error::{Error, Result};
#[cfg(feature = "test-support")]
pub use event::InMemoryEventLog;
pub use event::{
    canonical_envelope_bytes, canonical_event_bytes, decide_upsert, fold_events,
    group_deleted_payload, group_put_payload, key_event_payload, org_event_payload,
    org_semantic_view, principal_event_payload, Actor, EventDraft, EventDraftParams, EventEnvelope,
    EventId, EventKind, EventLog, FoldedState, UpsertDecision,
};
pub use query::PolicyQuery;
pub use rbac::{
    compile_rbac_to_cedar, groups_to_permits, policy_name_for_group, resolve_inherits,
    validate_action_format, validate_cedar_ident, validate_group_name, validate_rbac_entry,
    GroupValidationError, MaterializeCompileError, NamedPermit, RbacEntry, TenantConfig,
    ValidatedRbacEntry,
};
pub use snapshot::{Snapshot, SnapshotVersion};
pub use store::{
    select_slice, AuthzStore, EntitySlice, MemoryStore, ModelState, Revision, SliceQuery,
    StoreWrite,
};

#[cfg(feature = "test-support")]
pub use static_engine::StaticPolicyEngine;
