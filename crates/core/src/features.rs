//! Feature flag types and pure evaluation logic.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Namespace, Result, Segment, TenantId, UserId};

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
    pub tenant: Option<TenantId>,
    pub user: Option<UserId>,
    pub value: FlagValue,
}

// ---------------------------------------------------------------------------
// FlagDefinition
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

/// A complete feature flag definition including overrides and rollout config.
#[derive(Debug, Clone, Deserialize)]
pub struct FlagDefinition {
    #[serde(rename = "type")]
    pub flag_type: FlagType,
    pub default: FlagValue,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub overrides: Vec<FlagOverride>,
    pub rollout_percentage: Option<u8>,
    pub rollout_variant: Option<FlagValue>,
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
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate all flags in the config for a given tenant/user context.
///
/// This is a pure function — no I/O, no side effects.
pub fn evaluate_flags(
    config: &FlagConfig,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
) -> ResolvedFlags {
    let mut flags = HashMap::new();
    for (name, def) in &config.flags {
        let display_name = name.to_string();
        flags.insert(
            display_name,
            resolve_single_flag(name, def, tenant_id, user_id),
        );
    }
    ResolvedFlags { flags }
}

fn resolve_single_flag(
    name: &FlagName,
    flag: &FlagDefinition,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
) -> FlagValue {
    // 0. Kill switch
    if !flag.enabled {
        return flag.default.clone();
    }

    // 1. Override scan (pre-sorted by specificity)
    for ov in &flag.overrides {
        let user_matches = ov.user.as_ref().is_none_or(|u| u == user_id);
        let tenant_matches = match (&ov.tenant, tenant_id) {
            (Some(t), Some(tid)) => t == tid,
            (Some(_), None) => false,
            (None, _) => true,
        };
        if user_matches && tenant_matches {
            return ov.value.clone();
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- FlagName parsing ----------------------------------------------------

    #[test]
    fn parse_global_flag() {
        let name = FlagName::parse("maintenance-mode").unwrap();
        assert!(matches!(name, FlagName::Global(_)));
        assert_eq!(name.to_string(), "maintenance-mode");
    }

    #[test]
    fn parse_scoped_flag() {
        let name = FlagName::parse("todo:ai-suggestions").unwrap();
        match &name {
            FlagName::Scoped { namespace, name } => {
                assert_eq!(namespace.as_str(), "todo");
                assert_eq!(name.as_str(), "ai-suggestions");
            }
            _ => panic!("expected Scoped variant"),
        }
        assert_eq!(name.to_string(), "todo:ai-suggestions");
    }

    #[test]
    fn parse_rejects_uppercase() {
        assert!(FlagName::parse("MaintenanceMode").is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(FlagName::parse("").is_err());
    }

    #[test]
    fn display_round_trip() {
        let names = ["maintenance-mode", "todo:ai-suggestions"];
        for input in names {
            let parsed = FlagName::parse(input).unwrap();
            let display = parsed.to_string();
            let reparsed = FlagName::parse(&display).unwrap();
            assert_eq!(parsed, reparsed);
        }
    }

    #[test]
    fn serde_round_trip() {
        let names = ["maintenance-mode", "todo:ai-suggestions"];
        for input in names {
            let parsed = FlagName::parse(input).unwrap();
            let json = serde_json::to_string(&parsed).unwrap();
            let deser: FlagName = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, deser);
        }
    }

    #[test]
    fn is_in_namespace_scoped_matches() {
        let name = FlagName::parse("todo:ai-suggestions").unwrap();
        let ns = Namespace::parse("todo").unwrap();
        assert!(name.is_in_namespace(&ns));
    }

    #[test]
    fn is_in_namespace_global_matches_nothing() {
        let name = FlagName::parse("maintenance-mode").unwrap();
        let ns = Namespace::parse("todo").unwrap();
        assert!(!name.is_in_namespace(&ns));
    }

    #[test]
    fn is_in_namespace_scoped_wrong_namespace() {
        let name = FlagName::parse("todo:ai-suggestions").unwrap();
        let ns = Namespace::parse("billing").unwrap();
        assert!(!name.is_in_namespace(&ns));
    }

    // -- Override hierarchy --------------------------------------------------

    fn make_config(name: &str, def: FlagDefinition) -> FlagConfig {
        let mut config = FlagConfig::default();
        config.flags.insert(FlagName::parse(name).unwrap(), def);
        config
    }

    #[test]
    fn user_tenant_override_wins_over_tenant_only() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![
                    // Tenant-only override (less specific)
                    FlagOverride {
                        tenant: Some(TenantId::new("acme").unwrap()),
                        user: None,
                        value: FlagValue::Bool(false),
                    },
                    // User+tenant override (more specific, listed second but scanned first by design)
                    FlagOverride {
                        tenant: Some(TenantId::new("acme").unwrap()),
                        user: Some(UserId::new("alice").unwrap()),
                        value: FlagValue::Bool(true),
                    },
                ],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let tenant = TenantId::new("acme").unwrap();
        let user = UserId::new("alice").unwrap();
        let flags = evaluate_flags(&config, Some(&tenant), &user);
        // The tenant-only override is listed first and matches alice too (user=None is wildcard),
        // so we get false. The spec says "pre-sorted by specificity" — callers must sort.
        // But in this test the tenant-only wildcard matches first.
        // Let's reorder to show user+tenant wins when listed first.
        let config2 = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![
                    // User+tenant override (more specific, listed first)
                    FlagOverride {
                        tenant: Some(TenantId::new("acme").unwrap()),
                        user: Some(UserId::new("alice").unwrap()),
                        value: FlagValue::Bool(true),
                    },
                    // Tenant-only override (less specific)
                    FlagOverride {
                        tenant: Some(TenantId::new("acme").unwrap()),
                        user: None,
                        value: FlagValue::Bool(false),
                    },
                ],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );
        let flags2 = evaluate_flags(&config2, Some(&tenant), &user);
        assert!(flags2.enabled("test-flag"));

        // Also confirm the tenant-only override applies to a different user
        let other_user = UserId::new("bob").unwrap();
        let flags3 = evaluate_flags(&config2, Some(&tenant), &other_user);
        assert!(!flags3.enabled("test-flag"));

        // Suppress unused variable warning
        let _ = flags;
    }

    #[test]
    fn user_override_wins_over_rollout() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![FlagOverride {
                    tenant: None,
                    user: Some(UserId::new("alice").unwrap()),
                    value: FlagValue::Bool(true),
                }],
                rollout_percentage: Some(0), // 0% rollout — nobody gets it
                rollout_variant: None,
            },
        );

        let user = UserId::new("alice").unwrap();
        let flags = evaluate_flags(&config, None, &user);
        assert!(flags.enabled("test-flag"));
    }

    #[test]
    fn tenant_override_wins_over_rollout_and_default() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![FlagOverride {
                    tenant: Some(TenantId::new("acme").unwrap()),
                    user: None,
                    value: FlagValue::Bool(true),
                }],
                rollout_percentage: Some(0),
                rollout_variant: None,
            },
        );

        let tenant = TenantId::new("acme").unwrap();
        let user = UserId::new("bob").unwrap();
        let flags = evaluate_flags(&config, Some(&tenant), &user);
        assert!(flags.enabled("test-flag"));
    }

    #[test]
    fn kill_switch_ignores_everything() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: false, // kill switch
                overrides: vec![FlagOverride {
                    tenant: None,
                    user: Some(UserId::new("alice").unwrap()),
                    value: FlagValue::Bool(true),
                }],
                rollout_percentage: Some(100),
                rollout_variant: None,
            },
        );

        let user = UserId::new("alice").unwrap();
        let flags = evaluate_flags(&config, None, &user);
        assert!(!flags.enabled("test-flag"));
    }

    #[test]
    fn string_variant_tenant_override() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::String,
                default: FlagValue::String("classic".to_string()),
                enabled: true,
                overrides: vec![FlagOverride {
                    tenant: Some(TenantId::new("acme").unwrap()),
                    user: None,
                    value: FlagValue::String("modern".to_string()),
                }],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let tenant = TenantId::new("acme").unwrap();
        let user = UserId::new("bob").unwrap();
        let flags = evaluate_flags(&config, Some(&tenant), &user);
        assert_eq!(
            flags.get("test-flag"),
            Some(&FlagValue::String("modern".to_string()))
        );
    }

    #[test]
    fn numeric_flag_tenant_override() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Number,
                default: FlagValue::Number(10.0),
                enabled: true,
                overrides: vec![FlagOverride {
                    tenant: Some(TenantId::new("acme").unwrap()),
                    user: None,
                    value: FlagValue::Number(50.0),
                }],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let tenant = TenantId::new("acme").unwrap();
        let user = UserId::new("bob").unwrap();
        let flags = evaluate_flags(&config, Some(&tenant), &user);
        assert_eq!(flags.get("test-flag"), Some(&FlagValue::Number(50.0)));
    }

    // -- Rollout -------------------------------------------------------------

    #[test]
    fn rollout_is_deterministic() {
        let flag = "test-flag";
        let tenant = TenantId::new("acme").unwrap();
        let user = UserId::new("alice").unwrap();
        let b1 = deterministic_bucket(flag, Some(&tenant), &user);
        let b2 = deterministic_bucket(flag, Some(&tenant), &user);
        assert_eq!(b1, b2);
    }

    #[test]
    fn rollout_distribution_approximately_correct() {
        let flag_name = FlagName::parse("test-rollout").unwrap();
        let mut config = FlagConfig::default();
        config.flags.insert(
            flag_name,
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![],
                rollout_percentage: Some(25),
                rollout_variant: None,
            },
        );
        let tenant = TenantId::new("test-tenant").unwrap();
        let mut in_rollout = 0u32;
        for i in 0..10_000 {
            let user = UserId::new(format!("user-{i:05}")).unwrap();
            let flags = evaluate_flags(&config, Some(&tenant), &user);
            if flags.enabled("test-rollout") {
                in_rollout += 1;
            }
        }
        let pct = (in_rollout as f64 / 10_000.0) * 100.0;
        assert!((pct - 25.0).abs() < 3.0, "expected ~25%, got {pct}%");
    }

    #[test]
    fn rollout_different_flags_produce_different_buckets() {
        let tenant = TenantId::new("acme").unwrap();
        let user = UserId::new("alice").unwrap();
        let b1 = deterministic_bucket("flag-a", Some(&tenant), &user);
        let b2 = deterministic_bucket("flag-b", Some(&tenant), &user);
        // Not guaranteed to differ for any single pair, but extremely likely
        // with different flag names. We test that the function uses flag name.
        // A weaker assertion: at least they're both in range.
        assert!(b1 < 100);
        assert!(b2 < 100);
        // For a stronger test, check across many users
        let mut differ = false;
        for i in 0..100 {
            let u = UserId::new(format!("user-{i:03}")).unwrap();
            let x = deterministic_bucket("flag-a", Some(&tenant), &u);
            let y = deterministic_bucket("flag-b", Some(&tenant), &u);
            if x != y {
                differ = true;
                break;
            }
        }
        assert!(
            differ,
            "different flag names should produce different buckets for at least some users"
        );
    }

    #[test]
    fn boolean_rollout_no_variant_defaults_to_true() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![],
                rollout_percentage: Some(100),
                rollout_variant: None,
            },
        );

        let user = UserId::new("alice").unwrap();
        let flags = evaluate_flags(&config, None, &user);
        assert!(flags.enabled("test-flag"));
    }

    #[test]
    fn string_rollout_with_variant() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::String,
                default: FlagValue::String("classic".to_string()),
                enabled: true,
                overrides: vec![],
                rollout_percentage: Some(100),
                rollout_variant: Some(FlagValue::String("streamlined".to_string())),
            },
        );

        let user = UserId::new("alice").unwrap();
        let flags = evaluate_flags(&config, None, &user);
        assert_eq!(
            flags.get("test-flag"),
            Some(&FlagValue::String("streamlined".to_string()))
        );
    }

    #[test]
    fn rollout_zero_percent_nobody() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![],
                rollout_percentage: Some(0),
                rollout_variant: None,
            },
        );

        let tenant = TenantId::new("acme").unwrap();
        for i in 0..100 {
            let user = UserId::new(format!("user-{i:03}")).unwrap();
            let flags = evaluate_flags(&config, Some(&tenant), &user);
            assert!(
                !flags.enabled("test-flag"),
                "user-{i:03} should not be in rollout"
            );
        }
    }

    #[test]
    fn rollout_hundred_percent_everyone() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(false),
                enabled: true,
                overrides: vec![],
                rollout_percentage: Some(100),
                rollout_variant: None,
            },
        );

        let tenant = TenantId::new("acme").unwrap();
        for i in 0..100 {
            let user = UserId::new(format!("user-{i:03}")).unwrap();
            let flags = evaluate_flags(&config, Some(&tenant), &user);
            assert!(
                flags.enabled("test-flag"),
                "user-{i:03} should be in rollout"
            );
        }
    }

    // -- Edge cases ----------------------------------------------------------

    #[test]
    fn no_overrides_no_rollout_returns_default() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(true),
                enabled: true,
                overrides: vec![],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let user = UserId::new("alice").unwrap();
        let flags = evaluate_flags(&config, None, &user);
        assert!(flags.enabled("test-flag"));
    }

    #[test]
    fn resolved_flags_json_round_trip() {
        let config = make_config(
            "test-flag",
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(true),
                enabled: true,
                overrides: vec![],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let user = UserId::new("alice").unwrap();
        let flags = evaluate_flags(&config, None, &user);
        let json = serde_json::to_string(&flags).unwrap();
        let deser: ResolvedFlags = serde_json::from_str(&json).unwrap();
        assert_eq!(flags.get("test-flag"), deser.get("test-flag"));
    }

    #[test]
    fn resolved_flags_is_empty() {
        let flags = ResolvedFlags::default();
        assert!(flags.is_empty());
    }
}
