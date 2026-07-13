#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod context;
pub mod decision;
pub mod engine;
pub mod error;
pub mod query;
pub mod rbac;
pub mod store;

#[cfg(feature = "test-support")]
pub mod static_engine;

pub use context::PolicyContext;
pub use decision::{DenyReason, PolicyDecision};
pub use engine::{CacheStats, PolicyEngine};
pub use error::{Error, Result};
pub use query::PolicyQuery;
pub use rbac::{
    compile_rbac_to_cedar, groups_to_permits, policy_name_for_group, resolve_inherits,
    validate_action_format, validate_cedar_ident, validate_group_name, validate_rbac_entry,
    GroupValidationError, MaterializeCompileError, NamedPermit, RbacEntry, TenantConfig,
    ValidatedRbacEntry,
};
pub use store::{
    select_slice, AuthzStore, EntitySlice, MemoryStore, ModelState, Revision, SliceQuery,
    StoreWrite,
};

#[cfg(feature = "test-support")]
pub use static_engine::StaticPolicyEngine;
