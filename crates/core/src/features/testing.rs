//! Test-only constructors for feature-flag types.
//!
//! Gated behind `cfg(any(test, feature = "testing"))` so the helpers are
//! available to in-crate tests automatically and to other crates' tests
//! when they opt in via `[dev-dependencies] forgeguard_core = { ..., features = ["testing"] }`.
//!
//! These are pure builders (Functional Core). They wrap the public
//! `new()` constructors and exist solely to keep test-site syntax close
//! to the legacy struct-literal style.
//!
//! For `FlagDefinition`, call `FlagDefinition::new(FlagDefinitionParams { ... })` directly —
//! no wrapper is needed.

use crate::{
    FlagConfig, FlagDefinition, FlagName, FlagOverride, FlagValue, GroupName, TenantId, UserId,
};

/// Build a `FlagOverride` from individual scope parts. Equivalent to `FlagOverride::new`,
/// kept here so test-site syntax will be uniform with `make_flag_config`.
pub fn make_flag_override(
    tenant: Option<TenantId>,
    user: Option<UserId>,
    group: Option<GroupName>,
    value: FlagValue,
) -> FlagOverride {
    FlagOverride::new(tenant, user, group, value)
}

/// Build a `FlagConfig` from an iterable of `(FlagName, FlagDefinition)` pairs.
pub fn make_flag_config(pairs: impl IntoIterator<Item = (FlagName, FlagDefinition)>) -> FlagConfig {
    FlagConfig::new(pairs.into_iter().collect())
}
