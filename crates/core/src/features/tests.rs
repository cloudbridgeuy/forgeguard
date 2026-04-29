#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::features::testing::make_flag_override;

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
    use crate::features::testing::make_flag_config;
    make_flag_config([(FlagName::parse(name).unwrap(), def)])
}

/// Build a Boolean `FlagDefinition` for test sites that only care about
/// `default`, `enabled`, and `overrides`. Fixes `rollout_percentage` and
/// `rollout_variant` to `None` — use `FlagDefinitionParams` directly when
/// rollout fields matter.
fn boolean_flag(default: FlagValue, enabled: bool, overrides: Vec<FlagOverride>) -> FlagDefinition {
    FlagDefinition::new(FlagDefinitionParams {
        flag_type: FlagType::Boolean,
        default,
        enabled,
        overrides,
        rollout_percentage: None,
        rollout_variant: None,
    })
}

#[test]
fn user_tenant_override_wins_over_tenant_only() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![
                // Tenant-only override (less specific)
                make_flag_override(
                    Some(TenantId::new("acme").unwrap()),
                    None,
                    None,
                    FlagValue::Bool(false),
                ),
                // User+tenant override (more specific, listed second but scanned first by design)
                make_flag_override(
                    Some(TenantId::new("acme").unwrap()),
                    Some(UserId::new("alice").unwrap()),
                    None,
                    FlagValue::Bool(true),
                ),
            ],
        ),
    );

    let tenant = TenantId::new("acme").unwrap();
    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, Some(&tenant), &user, &[]);
    // The tenant-only override is listed first and matches alice too (user=None is wildcard),
    // so we get false. The spec says "pre-sorted by specificity" — callers must sort.
    // But in this test the tenant-only wildcard matches first.
    // Let's reorder to show user+tenant wins when listed first.
    let config2 = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![
                // User+tenant override (more specific, listed first)
                make_flag_override(
                    Some(TenantId::new("acme").unwrap()),
                    Some(UserId::new("alice").unwrap()),
                    None,
                    FlagValue::Bool(true),
                ),
                // Tenant-only override (less specific)
                make_flag_override(
                    Some(TenantId::new("acme").unwrap()),
                    None,
                    None,
                    FlagValue::Bool(false),
                ),
            ],
        ),
    );
    let flags2 = evaluate_flags(&config2, Some(&tenant), &user, &[]);
    assert!(flags2.enabled("test-flag"));

    // Also confirm the tenant-only override applies to a different user
    let other_user = UserId::new("bob").unwrap();
    let flags3 = evaluate_flags(&config2, Some(&tenant), &other_user, &[]);
    assert!(!flags3.enabled("test-flag"));

    // Suppress unused variable warning
    let _ = flags;
}

#[test]
fn user_override_wins_over_rollout() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![make_flag_override(
                None,
                Some(UserId::new("alice").unwrap()),
                None,
                FlagValue::Bool(true),
            )],
            rollout_percentage: Some(0), // 0% rollout — nobody gets it
            rollout_variant: None,
        }),
    );

    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    assert!(flags.enabled("test-flag"));
}

#[test]
fn tenant_override_wins_over_rollout_and_default() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![make_flag_override(
                Some(TenantId::new("acme").unwrap()),
                None,
                None,
                FlagValue::Bool(true),
            )],
            rollout_percentage: Some(0),
            rollout_variant: None,
        }),
    );

    let tenant = TenantId::new("acme").unwrap();
    let user = UserId::new("bob").unwrap();
    let flags = evaluate_flags(&config, Some(&tenant), &user, &[]);
    assert!(flags.enabled("test-flag"));
}

#[test]
fn kill_switch_ignores_everything() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: false, // kill switch
            overrides: vec![make_flag_override(
                None,
                Some(UserId::new("alice").unwrap()),
                None,
                FlagValue::Bool(true),
            )],
            rollout_percentage: Some(100),
            rollout_variant: None,
        }),
    );

    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    assert!(!flags.enabled("test-flag"));
}

#[test]
fn string_variant_tenant_override() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::String,
            default: FlagValue::String("classic".to_string()),
            enabled: true,
            overrides: vec![make_flag_override(
                Some(TenantId::new("acme").unwrap()),
                None,
                None,
                FlagValue::String("modern".to_string()),
            )],
            rollout_percentage: None,
            rollout_variant: None,
        }),
    );

    let tenant = TenantId::new("acme").unwrap();
    let user = UserId::new("bob").unwrap();
    let flags = evaluate_flags(&config, Some(&tenant), &user, &[]);
    assert_eq!(
        flags.get("test-flag"),
        Some(&FlagValue::String("modern".to_string()))
    );
}

#[test]
fn numeric_flag_tenant_override() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Number,
            default: FlagValue::Number(10.0),
            enabled: true,
            overrides: vec![make_flag_override(
                Some(TenantId::new("acme").unwrap()),
                None,
                None,
                FlagValue::Number(50.0),
            )],
            rollout_percentage: None,
            rollout_variant: None,
        }),
    );

    let tenant = TenantId::new("acme").unwrap();
    let user = UserId::new("bob").unwrap();
    let flags = evaluate_flags(&config, Some(&tenant), &user, &[]);
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
    use crate::features::testing::make_flag_config;
    let flag_name = FlagName::parse("test-rollout").unwrap();
    let config = make_flag_config([(
        flag_name,
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(25),
            rollout_variant: None,
        }),
    )]);
    let tenant = TenantId::new("test-tenant").unwrap();
    let mut in_rollout = 0u32;
    for i in 0..10_000 {
        let user = UserId::new(format!("user-{i:05}")).unwrap();
        let flags = evaluate_flags(&config, Some(&tenant), &user, &[]);
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
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(100),
            rollout_variant: None,
        }),
    );

    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    assert!(flags.enabled("test-flag"));
}

#[test]
fn string_rollout_with_variant() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::String,
            default: FlagValue::String("classic".to_string()),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(100),
            rollout_variant: Some(FlagValue::String("streamlined".to_string())),
        }),
    );

    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    assert_eq!(
        flags.get("test-flag"),
        Some(&FlagValue::String("streamlined".to_string()))
    );
}

#[test]
fn rollout_zero_percent_nobody() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(0),
            rollout_variant: None,
        }),
    );

    let tenant = TenantId::new("acme").unwrap();
    for i in 0..100 {
        let user = UserId::new(format!("user-{i:03}")).unwrap();
        let flags = evaluate_flags(&config, Some(&tenant), &user, &[]);
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
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(100),
            rollout_variant: None,
        }),
    );

    let tenant = TenantId::new("acme").unwrap();
    for i in 0..100 {
        let user = UserId::new(format!("user-{i:03}")).unwrap();
        let flags = evaluate_flags(&config, Some(&tenant), &user, &[]);
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
        boolean_flag(FlagValue::Bool(true), true, vec![]),
    );

    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    assert!(flags.enabled("test-flag"));
}

#[test]
fn resolved_flags_json_round_trip() {
    let config = make_config(
        "test-flag",
        boolean_flag(FlagValue::Bool(true), true, vec![]),
    );

    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    let json = serde_json::to_string(&flags).unwrap();
    let deser: ResolvedFlags = serde_json::from_str(&json).unwrap();
    assert_eq!(flags.get("test-flag"), deser.get("test-flag"));
}

#[test]
fn resolved_flags_is_empty() {
    let flags = ResolvedFlags::default();
    assert!(flags.is_empty());
}

// -- Group-based overrides (A6) ------------------------------------------

#[test]
fn group_override_matches_when_user_in_group() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![make_flag_override(
                None,
                None,
                Some(GroupName::new("admin").unwrap()),
                FlagValue::Bool(true),
            )],
        ),
    );

    let user = UserId::new("alice").unwrap();
    let groups = vec![GroupName::new("admin").unwrap()];
    let flags = evaluate_flags(&config, None, &user, &groups);
    assert!(flags.enabled("test-flag"));
}

#[test]
fn group_override_skipped_when_user_not_in_group() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![make_flag_override(
                None,
                None,
                Some(GroupName::new("admin").unwrap()),
                FlagValue::Bool(true),
            )],
        ),
    );

    let user = UserId::new("alice").unwrap();
    let groups = vec![GroupName::new("viewer").unwrap()];
    let flags = evaluate_flags(&config, None, &user, &groups);
    assert!(!flags.enabled("test-flag"));
}

#[test]
fn group_override_matches_any_of_users_groups() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![make_flag_override(
                None,
                None,
                Some(GroupName::new("ops").unwrap()),
                FlagValue::Bool(true),
            )],
        ),
    );

    let user = UserId::new("alice").unwrap();
    let groups = vec![
        GroupName::new("admin").unwrap(),
        GroupName::new("ops").unwrap(),
    ];
    let flags = evaluate_flags(&config, None, &user, &groups);
    assert!(flags.enabled("test-flag"));
}

#[test]
fn tenant_and_group_override_both_must_match() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![make_flag_override(
                Some(TenantId::new("acme").unwrap()),
                None,
                Some(GroupName::new("admin").unwrap()),
                FlagValue::Bool(true),
            )],
        ),
    );

    let user = UserId::new("alice").unwrap();
    let admin = vec![GroupName::new("admin").unwrap()];
    let viewer = vec![GroupName::new("viewer").unwrap()];
    let acme = TenantId::new("acme").unwrap();
    let other = TenantId::new("other").unwrap();

    // Right tenant + right group -> match
    let flags = evaluate_flags(&config, Some(&acme), &user, &admin);
    assert!(flags.enabled("test-flag"));

    // Right tenant + wrong group -> no match
    let flags = evaluate_flags(&config, Some(&acme), &user, &viewer);
    assert!(!flags.enabled("test-flag"));

    // Wrong tenant + right group -> no match
    let flags = evaluate_flags(&config, Some(&other), &user, &admin);
    assert!(!flags.enabled("test-flag"));
}

#[test]
fn no_group_override_field_matches_any_groups() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![make_flag_override(None, None, None, FlagValue::Bool(true))],
        ),
    );

    let user = UserId::new("alice").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    assert!(flags.enabled("test-flag"));
}

// -- Detailed evaluation and ResolutionReason (A7) -----------------------

#[test]
fn detailed_kill_switch_reason() {
    let config = make_config(
        "test-flag",
        boolean_flag(FlagValue::Bool(false), false, vec![]),
    );

    let user = UserId::new("alice").unwrap();
    let result = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = result.get("test-flag").unwrap();
    assert_eq!(*flag.value(), FlagValue::Bool(false));
    assert_eq!(*flag.reason(), ResolutionReason::KillSwitch);
}

#[test]
fn detailed_override_reason_with_tenant() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![make_flag_override(
                Some(TenantId::new("acme").unwrap()),
                None,
                None,
                FlagValue::Bool(true),
            )],
        ),
    );

    let tenant = TenantId::new("acme").unwrap();
    let user = UserId::new("alice").unwrap();
    let result = evaluate_flags_detailed(&config, Some(&tenant), &user, &[]);
    let flag = result.get("test-flag").unwrap();
    assert_eq!(*flag.value(), FlagValue::Bool(true));
    assert_eq!(
        *flag.reason(),
        ResolutionReason::Override {
            tenant: Some("acme".to_string()),
            user: None,
            group: None,
        }
    );
}

#[test]
fn detailed_override_reason_with_group() {
    let config = make_config(
        "test-flag",
        boolean_flag(
            FlagValue::Bool(false),
            true,
            vec![make_flag_override(
                None,
                None,
                Some(GroupName::new("admin").unwrap()),
                FlagValue::Bool(true),
            )],
        ),
    );

    let user = UserId::new("alice").unwrap();
    let groups = vec![GroupName::new("admin").unwrap()];
    let result = evaluate_flags_detailed(&config, None, &user, &groups);
    let flag = result.get("test-flag").unwrap();
    assert_eq!(*flag.value(), FlagValue::Bool(true));
    assert_eq!(
        *flag.reason(),
        ResolutionReason::Override {
            tenant: None,
            user: None,
            group: Some("admin".to_string()),
        }
    );
}

#[test]
fn detailed_rollout_included_reason() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(100),
            rollout_variant: None,
        }),
    );

    let user = UserId::new("alice").unwrap();
    let result = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = result.get("test-flag").unwrap();
    assert_eq!(*flag.value(), FlagValue::Bool(true));
    match flag.reason() {
        ResolutionReason::Rollout { threshold, .. } => {
            assert_eq!(*threshold, 100);
        }
        other => panic!("expected Rollout, got {other:?}"),
    }
}

#[test]
fn detailed_rollout_excluded_reason() {
    let config = make_config(
        "test-flag",
        FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(0),
            rollout_variant: None,
        }),
    );

    let user = UserId::new("alice").unwrap();
    let result = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = result.get("test-flag").unwrap();
    assert_eq!(*flag.value(), FlagValue::Bool(false));
    match flag.reason() {
        ResolutionReason::RolloutExcluded { threshold, .. } => {
            assert_eq!(*threshold, 0);
        }
        other => panic!("expected RolloutExcluded, got {other:?}"),
    }
}

#[test]
fn detailed_default_reason() {
    let config = make_config(
        "test-flag",
        boolean_flag(FlagValue::Bool(true), true, vec![]),
    );

    let user = UserId::new("alice").unwrap();
    let result = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = result.get("test-flag").unwrap();
    assert_eq!(*flag.value(), FlagValue::Bool(true));
    assert_eq!(*flag.reason(), ResolutionReason::Default);
}

#[test]
fn detailed_json_serialization() {
    let config = make_config(
        "test-flag",
        boolean_flag(FlagValue::Bool(false), true, vec![]),
    );

    let user = UserId::new("alice").unwrap();
    let result = evaluate_flags_detailed(&config, None, &user, &[]);
    let json = serde_json::to_value(&result).unwrap();

    // Verify structure: flags.test-flag.value and flags.test-flag.reason.kind
    let flag_obj = json
        .get("flags")
        .expect("top-level 'flags' key")
        .get("test-flag")
        .expect("'test-flag' entry");
    assert!(flag_obj.get("value").is_some(), "missing 'value' field");
    let reason = flag_obj.get("reason").expect("'reason' field");
    assert_eq!(
        reason.get("kind").and_then(|v| v.as_str()),
        Some("default"),
        "reason.kind should be 'default'"
    );
}

// -- FlagDefinition construction (V2) ------------------------------------

mod flag_definition_construction {
    use crate::features::testing::make_flag_override;
    use crate::{FlagDefinition, FlagDefinitionParams, FlagType, FlagValue};

    #[test]
    fn new_minimal_definition() {
        let def = FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: None,
            rollout_variant: None,
        });
        assert!(def.enabled());
        assert!(def.overrides().is_empty());
        assert!(def.rollout_percentage().is_none());
        assert!(matches!(def.flag_type(), FlagType::Boolean));
        assert_eq!(*def.default_value(), FlagValue::Bool(false));
    }

    #[test]
    fn new_with_overrides_and_rollout() {
        let ov = make_flag_override(None, None, None, FlagValue::Bool(true));
        let def = FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![ov],
            rollout_percentage: Some(50),
            rollout_variant: Some(FlagValue::Bool(true)),
        });
        assert_eq!(def.overrides().len(), 1);
        assert_eq!(def.rollout_percentage(), Some(50));
        assert!(matches!(def.flag_type(), FlagType::Boolean));
        assert_eq!(*def.default_value(), FlagValue::Bool(false));
        assert_eq!(def.rollout_variant(), Some(&FlagValue::Bool(true)));
    }
}

// -- FlagConfig construction (V3) ----------------------------------------

mod flag_config_construction {
    use crate::features::testing::make_flag_config;
    use crate::{FlagConfig, FlagDefinition, FlagDefinitionParams, FlagName, FlagType, FlagValue};
    use std::collections::HashMap;

    #[test]
    fn default_is_empty() {
        let cfg = FlagConfig::default();
        assert!(cfg.is_empty());
        assert!(cfg.flags().is_empty());
    }

    #[test]
    fn new_from_hashmap_round_trips() {
        let mut map = HashMap::new();
        let name = FlagName::parse("foo").unwrap();
        let def = FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(true),
            enabled: true,
            overrides: vec![],
            rollout_percentage: None,
            rollout_variant: None,
        });
        map.insert(name.clone(), def);
        let cfg = FlagConfig::new(map);
        assert!(!cfg.is_empty());
        assert!(cfg.flags().contains_key(&name));
    }

    #[test]
    fn make_flag_config_collects_pairs() {
        let name = FlagName::parse("bar").unwrap();
        let def = FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: None,
            rollout_variant: None,
        });
        let cfg = make_flag_config([(name.clone(), def)]);
        assert!(cfg.flags().contains_key(&name));
    }

    #[test]
    fn insert_mutator_adds_entry() {
        let mut cfg = FlagConfig::default();
        let name = FlagName::parse("baz").unwrap();
        let def = FlagDefinition::new(FlagDefinitionParams {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: None,
            rollout_variant: None,
        });
        let prev = cfg.insert(name.clone(), def);
        assert!(prev.is_none());
        assert!(cfg.flags().contains_key(&name));
        assert!(!cfg.is_empty());
    }
}

// -- FlagOverride construction (V1) --------------------------------------

mod flag_override_construction {
    use crate::features::testing::make_flag_override;
    use crate::{FlagOverride, FlagValue, GroupName, TenantId, UserId};

    fn sample_value() -> FlagValue {
        FlagValue::Bool(true)
    }

    #[test]
    fn new_with_all_scopes_populated() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let user = UserId::new("user-1").unwrap();
        let group = GroupName::new("admins").unwrap();
        let ov = FlagOverride::new(
            Some(tenant.clone()),
            Some(user.clone()),
            Some(group.clone()),
            sample_value(),
        );
        assert_eq!(ov.tenant(), Some(&tenant));
        assert_eq!(ov.user(), Some(&user));
        assert_eq!(ov.group(), Some(&group));
        assert_eq!(*ov.value(), FlagValue::Bool(true));
    }

    #[test]
    fn new_with_no_scopes_is_unconditional() {
        let ov = FlagOverride::new(None, None, None, sample_value());
        assert!(ov.tenant().is_none());
        assert!(ov.user().is_none());
        assert!(ov.group().is_none());
        assert_eq!(*ov.value(), FlagValue::Bool(true));
    }

    #[test]
    fn make_flag_override_roundtrips_through_new() {
        let user = UserId::new("user-1").unwrap();
        let ov = make_flag_override(None, Some(user.clone()), None, sample_value());
        assert_eq!(ov.user(), Some(&user));
    }
}
