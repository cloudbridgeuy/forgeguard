//! Test-only constructors for feature-flag types whose constructors take
//! enough positional arguments to make call sites hard to read.
//!
//! Not every flag type has a builder here. `FlagDefinition` is intentionally
//! absent: `FlagDefinitionParams` (the workspace Params-struct pattern) already
//! provides named-field construction, so callers should use
//! `FlagDefinition::new(FlagDefinitionParams { ... })` directly.
//!
//! Available to in-crate tests automatically. Other crates opt in via
//! `[dev-dependencies] forgeguard_core = { ..., features = ["testing"] }`.

use crate::{
    FlagConfig, FlagDefinition, FlagName, FlagOverride, FlagValue, GroupName, TenantId, UserId,
};

/// Build a `FlagOverride` from individual scope parts.
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
