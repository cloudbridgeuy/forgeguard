//! Feature flag types and pure evaluation logic.

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, GroupName, Namespace, Result, Segment, TenantId, UserId};

// ---------------------------------------------------------------------------
// FlagName
// ---------------------------------------------------------------------------

/// A feature flag name, either global or scoped to a namespace.
///
/// - Global: `"maintenance-mode"` — a single segment
/// - Scoped: `"todo:ai-suggestions"` — `namespace:name`
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum FlagName {
    Global(Segment),
    Scoped { namespace: Namespace, name: Segment },
}

impl FlagName {
    /// Parse a string into a `FlagName`.
    ///
    /// If the string contains `":"`, it is split into `namespace:name` (Scoped).
    /// Otherwise it is treated as a Global flag backed by a single `Segment`.
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::Parse {
                field: "flag_name",
                value: s.to_string(),
                reason: "cannot be empty",
            });
        }

        if let Some((ns, name)) = s.split_once(':') {
            let namespace = Namespace::parse(ns)?;
            let name = Segment::try_new(name)?;
            Ok(Self::Scoped { namespace, name })
        } else {
            let seg = Segment::try_new(s)?;
            Ok(Self::Global(seg))
        }
    }

    /// Returns `true` if this flag is scoped and its namespace matches `ns`.
    pub fn is_in_namespace(&self, ns: &Namespace) -> bool {
        match self {
            Self::Global(_) => false,
            Self::Scoped { namespace, .. } => namespace == ns,
        }
    }
}

impl fmt::Display for FlagName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global(seg) => write!(f, "{seg}"),
            Self::Scoped { namespace, name } => write!(f, "{namespace}:{name}"),
        }
    }
}

impl Serialize for FlagName {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FlagName {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// FlagValue
// ---------------------------------------------------------------------------

/// The resolved value of a feature flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FlagValue {
    Bool(bool),
    String(String),
    Number(f64),
}

// ---------------------------------------------------------------------------
// FlagType
// ---------------------------------------------------------------------------

/// The declared type of a feature flag.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagType {
    Boolean,
    String,
    Number,
}

// ---------------------------------------------------------------------------
// FlagOverride
// ---------------------------------------------------------------------------

/// A targeted override for a feature flag.
#[derive(Debug, Clone, Deserialize)]
pub struct FlagOverride {
    tenant: Option<TenantId>,
    user: Option<UserId>,
    #[serde(default)]
    group: Option<GroupName>,
    value: FlagValue,
}

impl FlagOverride {
    /// Construct a new override targeting the given (optional) tenant/user/group with the given value.
    pub fn new(
        tenant: Option<TenantId>,
        user: Option<UserId>,
        group: Option<GroupName>,
        value: FlagValue,
    ) -> Self {
        Self {
            tenant,
            user,
            group,
            value,
        }
    }

    /// Tenant scope of this override, if any.
    pub fn tenant(&self) -> Option<&TenantId> {
        self.tenant.as_ref()
    }

    /// User scope of this override, if any.
    pub fn user(&self) -> Option<&UserId> {
        self.user.as_ref()
    }

    /// Group scope of this override, if any.
    pub fn group(&self) -> Option<&GroupName> {
        self.group.as_ref()
    }

    /// Value to return when this override matches.
    pub fn value(&self) -> &FlagValue {
        &self.value
    }
}

// ---------------------------------------------------------------------------
// FlagDefinition
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

/// Named constructor arguments for [`FlagDefinition::new`].
///
/// This is a Params struct (the one carve-out from the no-public-fields rule)
/// because `FlagDefinition::new` takes six arguments — above the workspace
/// `too-many-arguments-threshold = 5`.
pub struct FlagDefinitionParams {
    /// The declared type of the flag.
    pub flag_type: FlagType,
    /// The default value returned when no override or rollout applies.
    pub default: FlagValue,
    /// Whether the flag is enabled. `false` acts as a kill switch.
    pub enabled: bool,
    /// Targeted overrides. First match wins; callers are responsible for ordering.
    pub overrides: Vec<FlagOverride>,
    /// Rollout percentage (0–100). `None` disables rollout evaluation.
    pub rollout_percentage: Option<u8>,
    /// Value returned when a user falls within the rollout. Defaults to
    /// `FlagValue::Bool(true)` when `None`.
    pub rollout_variant: Option<FlagValue>,
}

/// A complete feature flag definition including overrides and rollout config.
#[derive(Debug, Clone, Deserialize)]
pub struct FlagDefinition {
    #[serde(rename = "type")]
    flag_type: FlagType,
    default: FlagValue,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    overrides: Vec<FlagOverride>,
    rollout_percentage: Option<u8>,
    rollout_variant: Option<FlagValue>,
}

impl FlagDefinition {
    /// Construct a new flag definition from named parameters.
    pub fn new(params: FlagDefinitionParams) -> Self {
        Self {
            flag_type: params.flag_type,
            default: params.default,
            enabled: params.enabled,
            overrides: params.overrides,
            rollout_percentage: params.rollout_percentage,
            rollout_variant: params.rollout_variant,
        }
    }

    /// The declared type of this flag.
    pub fn flag_type(&self) -> &FlagType {
        &self.flag_type
    }

    /// The default value returned when no override or rollout applies.
    pub fn default_value(&self) -> &FlagValue {
        &self.default
    }

    /// Whether the flag is enabled. When `false`, acts as a kill switch and
    /// returns the default value regardless of overrides or rollout.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The list of targeted overrides for this flag.
    pub fn overrides(&self) -> &[FlagOverride] {
        &self.overrides
    }

    /// The rollout percentage (0–100), if set.
    pub fn rollout_percentage(&self) -> Option<u8> {
        self.rollout_percentage
    }

    /// The value to return when a user falls within the rollout, if set.
    pub fn rollout_variant(&self) -> Option<&FlagValue> {
        self.rollout_variant.as_ref()
    }
}

// ---------------------------------------------------------------------------
// FlagConfig
// ---------------------------------------------------------------------------

/// A collection of feature flag definitions.
#[derive(Debug, Clone, Default)]
pub struct FlagConfig {
    pub flags: HashMap<FlagName, FlagDefinition>,
}

// ---------------------------------------------------------------------------
// ResolvedFlags
// ---------------------------------------------------------------------------

/// The result of evaluating all flags for a specific user/tenant context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolvedFlags {
    flags: HashMap<String, FlagValue>,
}

impl ResolvedFlags {
    /// Returns `true` only if the flag exists and is `FlagValue::Bool(true)`.
    pub fn enabled(&self, flag: &str) -> bool {
        matches!(self.flags.get(flag), Some(FlagValue::Bool(true)))
    }

    /// Get the resolved value of a flag.
    pub fn get(&self, flag: &str) -> Option<&FlagValue> {
        self.flags.get(flag)
    }

    /// Returns `true` if no flags were resolved.
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Resolution reasons (debug endpoint)
// ---------------------------------------------------------------------------

/// Why a particular flag resolved to its value.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolutionReason {
    /// Flag is disabled (kill switch). Returned the default value.
    KillSwitch,
    /// Matched an override entry. Fields show which dimensions matched.
    Override {
        tenant: Option<String>,
        user: Option<String>,
        group: Option<String>,
    },
    /// User fell within the rollout percentage.
    Rollout { bucket: u64, threshold: u64 },
    /// User fell outside the rollout percentage. Returned the default value.
    RolloutExcluded { bucket: u64, threshold: u64 },
    /// No override or rollout matched. Returned the default value.
    Default,
}

/// A flag value paired with the reason it resolved that way.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedFlag {
    value: FlagValue,
    reason: ResolutionReason,
}

impl ResolvedFlag {
    /// The resolved value.
    pub fn value(&self) -> &FlagValue {
        &self.value
    }

    /// Why this value was chosen.
    pub fn reason(&self) -> &ResolutionReason {
        &self.reason
    }
}

/// Detailed evaluation result with resolution reasons for every flag.
#[derive(Debug, Clone, Serialize)]
pub struct DetailedResolvedFlags {
    flags: HashMap<String, ResolvedFlag>,
}

impl DetailedResolvedFlags {
    /// Get a flag's detailed resolution.
    pub fn get(&self, flag: &str) -> Option<&ResolvedFlag> {
        self.flags.get(flag)
    }

    /// Iterate over all resolved flags.
    pub fn flags(&self) -> &HashMap<String, ResolvedFlag> {
        &self.flags
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate all flags in the config for a given tenant/user context.
///
/// This is a pure function — no I/O, no side effects.
pub fn evaluate_flags(
    config: &FlagConfig,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
    groups: &[GroupName],
) -> ResolvedFlags {
    let mut flags = HashMap::new();
    for (name, def) in &config.flags {
        let display_name = name.to_string();
        flags.insert(
            display_name,
            resolve_single_flag(name, def, tenant_id, user_id, groups),
        );
    }
    ResolvedFlags { flags }
}

/// Evaluate all flags with full resolution reasons. Used by the debug endpoint.
pub fn evaluate_flags_detailed(
    config: &FlagConfig,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
    groups: &[GroupName],
) -> DetailedResolvedFlags {
    let mut flags = HashMap::new();
    for (name, def) in &config.flags {
        let display_name = name.to_string();
        flags.insert(
            display_name,
            resolve_single_flag_detailed(name, def, tenant_id, user_id, groups),
        );
    }
    DetailedResolvedFlags { flags }
}

fn resolve_single_flag_detailed(
    name: &FlagName,
    flag: &FlagDefinition,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
    groups: &[GroupName],
) -> ResolvedFlag {
    // 0. Kill switch
    if !flag.enabled {
        return ResolvedFlag {
            value: flag.default.clone(),
            reason: ResolutionReason::KillSwitch,
        };
    }

    // 1. Override scan (first match wins)
    for ov in &flag.overrides {
        let user_matches = ov.user().is_none_or(|u| u == user_id);
        let tenant_matches = match (ov.tenant(), tenant_id) {
            (Some(t), Some(tid)) => t == tid,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let group_matches = ov.group().is_none_or(|g| groups.iter().any(|ug| ug == g));
        if user_matches && tenant_matches && group_matches {
            return ResolvedFlag {
                value: ov.value().clone(),
                reason: ResolutionReason::Override {
                    tenant: ov.tenant().map(|t| t.as_str().to_string()),
                    user: ov.user().map(|u| u.as_str().to_string()),
                    group: ov.group().map(|g| g.as_str().to_string()),
                },
            };
        }
    }

    // 2. Rollout bucket
    if let Some(pct) = flag.rollout_percentage {
        let name_str = name.to_string();
        let bucket = deterministic_bucket(&name_str, tenant_id, user_id);
        if bucket < pct {
            return ResolvedFlag {
                value: flag
                    .rollout_variant
                    .clone()
                    .unwrap_or(FlagValue::Bool(true)),
                reason: ResolutionReason::Rollout {
                    bucket: bucket as u64,
                    threshold: pct as u64,
                },
            };
        }
        return ResolvedFlag {
            value: flag.default.clone(),
            reason: ResolutionReason::RolloutExcluded {
                bucket: bucket as u64,
                threshold: pct as u64,
            },
        };
    }

    // 3. Default
    ResolvedFlag {
        value: flag.default.clone(),
        reason: ResolutionReason::Default,
    }
}

fn resolve_single_flag(
    name: &FlagName,
    flag: &FlagDefinition,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
    groups: &[GroupName],
) -> FlagValue {
    // 0. Kill switch
    if !flag.enabled {
        return flag.default.clone();
    }

    // 1. Override scan (first match wins — config author controls order)
    for ov in &flag.overrides {
        let user_matches = ov.user().is_none_or(|u| u == user_id);
        let tenant_matches = match (ov.tenant(), tenant_id) {
            (Some(t), Some(tid)) => t == tid,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let group_matches = ov.group().is_none_or(|g| groups.iter().any(|ug| ug == g));
        if user_matches && tenant_matches && group_matches {
            return ov.value().clone();
        }
    }

    // 2. Rollout bucket
    if let Some(pct) = flag.rollout_percentage {
        let name_str = name.to_string();
        let bucket = deterministic_bucket(&name_str, tenant_id, user_id);
        if bucket < pct {
            return flag
                .rollout_variant
                .clone()
                .unwrap_or(FlagValue::Bool(true));
        }
    }

    // 3. Default
    flag.default.clone()
}

fn deterministic_bucket(flag: &str, tenant: Option<&TenantId>, user: &UserId) -> u8 {
    use std::hash::Hasher;
    let mut hasher = xxhash_rust::xxh64::Xxh64::new(0);
    hasher.write(flag.as_bytes());
    hasher.write_u8(0xFF);
    if let Some(t) = tenant {
        hasher.write(t.as_str().as_bytes());
    }
    hasher.write_u8(0xFF);
    hasher.write(user.as_str().as_bytes());
    (hasher.finish() % 100) as u8
}

#[cfg(test)]
mod tests;
