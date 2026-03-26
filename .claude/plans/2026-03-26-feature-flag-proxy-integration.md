# Feature Flag Proxy Integration (Issue #16) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Wire feature flag evaluation into the HTTP/proxy layer with group-based overrides, resolution reasons, a debug endpoint gated by `--debug`, and correct JSON 404 responses.

**Architecture:** Three layers of change, bottom-up. (1) Pure core: add `group` to overrides, add `ResolutionReason` + detailed evaluation. (2) Pure HTTP: add debug response builder + query parsing. (3) Imperative proxy shell: wire debug endpoint, fix 404 body, pass groups, add `--debug` flag. All new logic is pure and unit-tested; the proxy shell stays thin.

**Tech Stack:** Rust, `forgeguard_core` (pure), `forgeguard_http` (pure), `forgeguard_proxy` (Pingora I/O shell), `serde`, `url::form_urlencoded`.

---

## Group A — Core: Group Overrides + Resolution Reasons

These tasks modify `crates/core/src/features.rs` and `crates/core/src/lib.rs`. They are independent of Groups B and C.

### Task A1 — Add `group` field to `FlagOverride`

**File:** `crates/core/src/features.rs`

Add `GroupName` to the import on line 8:

```rust
use crate::{Error, GroupName, Namespace, Result, Segment, TenantId, UserId};
```

Add the `group` field to `FlagOverride` (after line 118):

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct FlagOverride {
    pub tenant: Option<TenantId>,
    pub user: Option<UserId>,
    #[serde(default)]
    pub group: Option<GroupName>,
    pub value: FlagValue,
}
```

**Test:** Existing tests should still compile and pass. The `#[serde(default)]` ensures backward compatibility.

**Run:** `cargo test -p forgeguard_core` — all existing tests pass (the new field defaults to `None`).

---

### Task A2 — Add `groups` parameter to `evaluate_flags` and `resolve_single_flag`

**File:** `crates/core/src/features.rs`

Change `evaluate_flags` signature (line 188):

```rust
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
```

Change `resolve_single_flag` signature (line 204) and add group matching in the override scan:

```rust
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
        let user_matches = ov.user.as_ref().is_none_or(|u| u == user_id);
        let tenant_matches = match (&ov.tenant, tenant_id) {
            (Some(t), Some(tid)) => t == tid,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let group_matches = ov
            .group
            .as_ref()
            .is_none_or(|g| groups.iter().any(|ug| ug == g));
        if user_matches && tenant_matches && group_matches {
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
```

**Fix all existing test calls** that call `evaluate_flags` — add `&[]` as the groups argument. Every call site in the test module looks like:

```rust
evaluate_flags(&config, Some(&tenant), &user)
// becomes:
evaluate_flags(&config, Some(&tenant), &user, &[])
```

There are ~15 call sites in the tests. Search for `evaluate_flags(` in the test module and add `, &[]` before the closing `)`.

**Run:** `cargo test -p forgeguard_core` — all tests pass with the new parameter.

---

### Task A3 — Add `ResolutionReason` and `ResolvedFlag` types

**File:** `crates/core/src/features.rs`

Add these types after `ResolvedFlags` (after line 179), before the `// Evaluation` section:

```rust
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
```

**Run:** `cargo check -p forgeguard_core` — compiles.

---

### Task A4 — Implement `evaluate_flags_detailed` and `resolve_single_flag_detailed`

**File:** `crates/core/src/features.rs`

Add after `evaluate_flags` (after the existing function):

```rust
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
        let user_matches = ov.user.as_ref().is_none_or(|u| u == user_id);
        let tenant_matches = match (&ov.tenant, tenant_id) {
            (Some(t), Some(tid)) => t == tid,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let group_matches = ov
            .group
            .as_ref()
            .is_none_or(|g| groups.iter().any(|ug| ug == g));
        if user_matches && tenant_matches && group_matches {
            return ResolvedFlag {
                value: ov.value.clone(),
                reason: ResolutionReason::Override {
                    tenant: ov.tenant.as_ref().map(|t| t.as_str().to_string()),
                    user: ov.user.as_ref().map(|u| u.as_str().to_string()),
                    group: ov.group.as_ref().map(|g| g.as_str().to_string()),
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
```

**Run:** `cargo check -p forgeguard_core` — compiles.

---

### Task A5 — Export new types from `crates/core/src/lib.rs`

**File:** `crates/core/src/lib.rs`

Update the `features` re-export line (line 16-18):

```rust
pub use features::{
    evaluate_flags, evaluate_flags_detailed, DetailedResolvedFlags, FlagConfig, FlagDefinition,
    FlagName, FlagOverride, FlagType, FlagValue, ResolvedFlag, ResolvedFlags, ResolutionReason,
};
```

**Run:** `cargo check -p forgeguard_core` — compiles.

---

### Task A6 — Write tests for group-based overrides

**File:** `crates/core/src/features.rs`, inside the `#[cfg(test)] mod tests` block.

Add these tests after the existing override tests:

```rust
// -- Group override tests -------------------------------------------------

#[test]
fn group_override_matches_when_user_in_group() {
    let config = make_config(
        "test-flag",
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![FlagOverride {
                tenant: None,
                user: None,
                group: Some(GroupName::new("admin").unwrap()),
                value: FlagValue::Bool(true),
            }],
            rollout_percentage: None,
            rollout_variant: None,
        },
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
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![FlagOverride {
                tenant: None,
                user: None,
                group: Some(GroupName::new("admin").unwrap()),
                value: FlagValue::Bool(true),
            }],
            rollout_percentage: None,
            rollout_variant: None,
        },
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
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![FlagOverride {
                tenant: None,
                user: None,
                group: Some(GroupName::new("ops").unwrap()),
                value: FlagValue::Bool(true),
            }],
            rollout_percentage: None,
            rollout_variant: None,
        },
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
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![FlagOverride {
                tenant: Some(TenantId::new("acme").unwrap()),
                user: None,
                group: Some(GroupName::new("admin").unwrap()),
                value: FlagValue::Bool(true),
            }],
            rollout_percentage: None,
            rollout_variant: None,
        },
    );

    let tenant = TenantId::new("acme").unwrap();
    let user = UserId::new("bob").unwrap();

    // Right tenant, right group -> matches
    let groups = vec![GroupName::new("admin").unwrap()];
    let flags = evaluate_flags(&config, Some(&tenant), &user, &groups);
    assert!(flags.enabled("test-flag"));

    // Right tenant, wrong group -> no match
    let groups = vec![GroupName::new("viewer").unwrap()];
    let flags = evaluate_flags(&config, Some(&tenant), &user, &groups);
    assert!(!flags.enabled("test-flag"));

    // Wrong tenant, right group -> no match
    let wrong_tenant = TenantId::new("initech").unwrap();
    let groups = vec![GroupName::new("admin").unwrap()];
    let flags = evaluate_flags(&config, Some(&wrong_tenant), &user, &groups);
    assert!(!flags.enabled("test-flag"));
}

#[test]
fn no_group_override_field_matches_any_groups() {
    let config = make_config(
        "test-flag",
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![FlagOverride {
                tenant: None,
                user: None,
                group: None,
                value: FlagValue::Bool(true),
            }],
            rollout_percentage: None,
            rollout_variant: None,
        },
    );

    let user = UserId::new("anyone").unwrap();
    let flags = evaluate_flags(&config, None, &user, &[]);
    assert!(flags.enabled("test-flag"));
}
```

Also update all existing `FlagOverride` constructors in the test module to include `group: None`. Search for `FlagOverride {` in the tests and add the field.

**Run:** `cargo test -p forgeguard_core` — all tests pass.

---

### Task A7 — Write tests for `evaluate_flags_detailed` and `ResolutionReason`

**File:** `crates/core/src/features.rs`, inside the `#[cfg(test)] mod tests` block.

```rust
// -- Detailed evaluation tests --------------------------------------------

#[test]
fn detailed_kill_switch_reason() {
    let config = make_config(
        "test-flag",
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: false,
            overrides: vec![],
            rollout_percentage: None,
            rollout_variant: None,
        },
    );

    let user = UserId::new("alice").unwrap();
    let detailed = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = detailed.get("test-flag").unwrap();
    assert_eq!(flag.value(), &FlagValue::Bool(false));
    assert_eq!(flag.reason(), &ResolutionReason::KillSwitch);
}

#[test]
fn detailed_override_reason_with_tenant() {
    let config = make_config(
        "test-flag",
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![FlagOverride {
                tenant: Some(TenantId::new("acme").unwrap()),
                user: None,
                group: None,
                value: FlagValue::Bool(true),
            }],
            rollout_percentage: None,
            rollout_variant: None,
        },
    );

    let tenant = TenantId::new("acme").unwrap();
    let user = UserId::new("bob").unwrap();
    let detailed = evaluate_flags_detailed(&config, Some(&tenant), &user, &[]);
    let flag = detailed.get("test-flag").unwrap();
    assert_eq!(flag.value(), &FlagValue::Bool(true));
    assert_eq!(
        flag.reason(),
        &ResolutionReason::Override {
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
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![FlagOverride {
                tenant: None,
                user: None,
                group: Some(GroupName::new("admin").unwrap()),
                value: FlagValue::Bool(true),
            }],
            rollout_percentage: None,
            rollout_variant: None,
        },
    );

    let user = UserId::new("alice").unwrap();
    let groups = vec![GroupName::new("admin").unwrap()];
    let detailed = evaluate_flags_detailed(&config, None, &user, &groups);
    let flag = detailed.get("test-flag").unwrap();
    assert_eq!(flag.value(), &FlagValue::Bool(true));
    assert_eq!(
        flag.reason(),
        &ResolutionReason::Override {
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
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(100), // everyone in
            rollout_variant: None,
        },
    );

    let user = UserId::new("alice").unwrap();
    let detailed = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = detailed.get("test-flag").unwrap();
    assert_eq!(flag.value(), &FlagValue::Bool(true));
    match flag.reason() {
        ResolutionReason::Rollout { threshold, .. } => assert_eq!(*threshold, 100),
        other => panic!("expected Rollout, got {other:?}"),
    }
}

#[test]
fn detailed_rollout_excluded_reason() {
    let config = make_config(
        "test-flag",
        FlagDefinition {
            flag_type: FlagType::Boolean,
            default: FlagValue::Bool(false),
            enabled: true,
            overrides: vec![],
            rollout_percentage: Some(0), // nobody in
            rollout_variant: None,
        },
    );

    let user = UserId::new("alice").unwrap();
    let detailed = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = detailed.get("test-flag").unwrap();
    assert_eq!(flag.value(), &FlagValue::Bool(false));
    match flag.reason() {
        ResolutionReason::RolloutExcluded { threshold, .. } => assert_eq!(*threshold, 0),
        other => panic!("expected RolloutExcluded, got {other:?}"),
    }
}

#[test]
fn detailed_default_reason() {
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
    let detailed = evaluate_flags_detailed(&config, None, &user, &[]);
    let flag = detailed.get("test-flag").unwrap();
    assert_eq!(flag.value(), &FlagValue::Bool(true));
    assert_eq!(flag.reason(), &ResolutionReason::Default);
}

#[test]
fn detailed_json_serialization() {
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
    let detailed = evaluate_flags_detailed(&config, None, &user, &[]);
    let json = serde_json::to_string(&detailed).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(val["flags"]["test-flag"]["value"], true);
    assert_eq!(val["flags"]["test-flag"]["reason"]["kind"], "default");
}
```

**Run:** `cargo test -p forgeguard_core` — all tests pass.

---

## Group B — HTTP: Debug Endpoint Response Builder

These tasks modify `crates/http/`. They depend on Group A (they use `DetailedResolvedFlags`, `evaluate_flags_detailed`).

### Task B1 — Create `crates/http/src/debug.rs` with query parsing and response types

**File:** `crates/http/src/debug.rs` (new file)

```rust
//! Debug endpoint: flag evaluation with resolution reasons.
//!
//! Pure functions — no I/O. The proxy shell calls these and writes the response.

use forgeguard_core::{
    evaluate_flags_detailed, DetailedResolvedFlags, FlagConfig, GroupName, TenantId, UserId,
};

use crate::error::{Error, Result};

/// Parsed query parameters for the flags debug endpoint.
pub struct FlagDebugQuery {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
}

impl FlagDebugQuery {
    /// Parse from raw query string (e.g., `"user_id=alice&tenant_id=acme&groups=admin,ops"`).
    ///
    /// `user_id` is required. `tenant_id` and `groups` are optional.
    /// `groups` is a comma-separated list of group names.
    pub fn parse(query: &str) -> Result<Self> {
        let mut user_id: Option<String> = None;
        let mut tenant_id: Option<String> = None;
        let mut groups_raw: Option<String> = None;

        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "user_id" => user_id = Some(value.into_owned()),
                "tenant_id" => tenant_id = Some(value.into_owned()),
                "groups" => groups_raw = Some(value.into_owned()),
                _ => {} // ignore unknown params
            }
        }

        let user_id_str = user_id.ok_or_else(|| Error::Validation {
            message: "missing required query parameter: user_id".to_string(),
        })?;

        let user_id =
            UserId::new(&user_id_str).map_err(|e| Error::Validation {
                message: format!("invalid user_id: {e}"),
            })?;

        let tenant_id = tenant_id
            .map(|t| {
                TenantId::new(&t).map_err(|e| Error::Validation {
                    message: format!("invalid tenant_id: {e}"),
                })
            })
            .transpose()?;

        let groups = match groups_raw {
            Some(raw) if !raw.is_empty() => raw
                .split(',')
                .map(|g| {
                    GroupName::new(g.trim()).map_err(|e| Error::Validation {
                        message: format!("invalid group name '{g}': {e}"),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => Vec::new(),
        };

        Ok(Self {
            user_id,
            tenant_id,
            groups,
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }
}

/// Evaluate flags for a debug query and return the detailed result.
pub fn evaluate_debug(config: &FlagConfig, query: &FlagDebugQuery) -> DetailedResolvedFlags {
    evaluate_flags_detailed(
        config,
        query.tenant_id(),
        query.user_id(),
        query.groups(),
    )
}
```

**Note:** This requires `Error::Validation` to exist. Check if `crates/http/src/error.rs` has a `Validation` variant. If not, add one:

```rust
#[error("validation error: {message}")]
Validation { message: String },
```

**Run:** `cargo check -p forgeguard_http` — compiles.

---

### Task B2 — Export debug module from `crates/http/src/lib.rs`

**File:** `crates/http/src/lib.rs`

Add after line 6 (`pub mod headers;`):

```rust
pub mod debug;
```

Add to the re-exports:

```rust
pub use debug::{evaluate_debug, FlagDebugQuery};
```

**Run:** `cargo check -p forgeguard_http` — compiles.

---

### Task B3 — Write tests for `FlagDebugQuery::parse`

**File:** `crates/http/src/debug.rs`, add at the bottom:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_params() {
        let query = FlagDebugQuery::parse("user_id=alice&tenant_id=acme&groups=admin,ops").unwrap();
        assert_eq!(query.user_id().as_str(), "alice");
        assert_eq!(query.tenant_id().unwrap().as_str(), "acme");
        assert_eq!(query.groups().len(), 2);
        assert_eq!(query.groups()[0].as_str(), "admin");
        assert_eq!(query.groups()[1].as_str(), "ops");
    }

    #[test]
    fn parse_user_id_only() {
        let query = FlagDebugQuery::parse("user_id=bob").unwrap();
        assert_eq!(query.user_id().as_str(), "bob");
        assert!(query.tenant_id().is_none());
        assert!(query.groups().is_empty());
    }

    #[test]
    fn parse_missing_user_id_errors() {
        let result = FlagDebugQuery::parse("tenant_id=acme");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_user_id_errors() {
        let result = FlagDebugQuery::parse("user_id=INVALID_UPPERCASE");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_group_name_errors() {
        let result = FlagDebugQuery::parse("user_id=alice&groups=admin,INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_groups_is_empty_vec() {
        let query = FlagDebugQuery::parse("user_id=alice&groups=").unwrap();
        assert!(query.groups().is_empty());
    }

    #[test]
    fn parse_ignores_unknown_params() {
        let query = FlagDebugQuery::parse("user_id=alice&foo=bar").unwrap();
        assert_eq!(query.user_id().as_str(), "alice");
    }

    #[test]
    fn evaluate_debug_returns_detailed_flags() {
        use forgeguard_core::{FlagConfig, FlagDefinition, FlagName, FlagType, FlagValue};

        let mut config = FlagConfig::default();
        config.flags.insert(
            FlagName::parse("test-flag").unwrap(),
            FlagDefinition {
                flag_type: FlagType::Boolean,
                default: FlagValue::Bool(true),
                enabled: true,
                overrides: vec![],
                rollout_percentage: None,
                rollout_variant: None,
            },
        );

        let query = FlagDebugQuery::parse("user_id=alice").unwrap();
        let result = evaluate_debug(&config, &query);
        let flag = result.get("test-flag").unwrap();
        assert_eq!(flag.value(), &FlagValue::Bool(true));
    }
}
```

**Run:** `cargo test -p forgeguard_http` — all tests pass.

---

## Group C — Proxy: Wire Debug Endpoint, Fix 404, Pass Groups

These tasks modify `crates/proxy/`. They depend on Groups A and B.

### Task C1 — Add `--debug` flag to CLI

**File:** `crates/proxy/src/cli.rs`

Add to `RunOptions` struct (after the `default_policy` field):

```rust
    /// Enable debug endpoints (e.g., /.well-known/forgeguard/flags).
    #[arg(long, env = "FORGEGUARD_DEBUG")]
    pub debug: bool,
```

**Run:** `cargo check -p forgeguard_proxy` — compiles.

---

### Task C2 — Add `debug_mode` to `ProxyParams` and `ForgeGuardProxy`

**File:** `crates/proxy/src/proxy.rs`

Add `debug_mode: bool` field to `ProxyParams` (after `auth_providers`):

```rust
pub(crate) struct ProxyParams {
    pub identity_chain: IdentityChain,
    pub policy_engine: Arc<dyn PolicyEngine>,
    pub route_matcher: RouteMatcher,
    pub public_matcher: PublicRouteMatcher,
    pub flag_config: FlagConfig,
    pub upstream_addr: String,
    pub upstream_tls: bool,
    pub upstream_sni: String,
    pub default_policy: DefaultPolicy,
    pub client_ip_source: ClientIpSource,
    pub project_id: ProjectId,
    pub auth_providers: Vec<String>,
    pub debug_mode: bool,
}
```

Add `debug_mode: bool` to `ForgeGuardProxy` (after `auth_providers`):

```rust
    auth_providers: Vec<String>,
    debug_mode: bool,
```

Wire it in `ForgeGuardProxy::new`:

```rust
    debug_mode: params.debug_mode,
```

**File:** `crates/proxy/src/main.rs`

Add `debug_mode: opts.debug` to the `ProxyParams` construction (after `auth_providers`):

```rust
    let proxy = ForgeGuardProxy::new(ProxyParams {
        // ... existing fields ...
        auth_providers: config.auth().chain_order().to_vec(),
        debug_mode: opts.debug,
    });
```

Add a startup log line for debug mode (after the existing `tracing::info!`):

```rust
    if opts.debug {
        tracing::warn!("debug mode enabled — flag debug endpoint is accessible");
    }
```

**Run:** `cargo check -p forgeguard_proxy` — compiles.

---

### Task C3 — Wire debug endpoint and fix 404 body in `request_filter`

**File:** `crates/proxy/src/proxy.rs`

Add imports at the top:

```rust
use forgeguard_http::{evaluate_debug, FlagDebugQuery};
```

Add the debug endpoint constant (after `HEALTH_PATH`):

```rust
/// Debug endpoint for flag evaluation (requires --debug flag).
const FLAGS_DEBUG_PATH: &str = "/.well-known/forgeguard/flags";
```

In `request_filter`, add after the health check block (after line 121, before `// 2. Public route check`):

```rust
        // 1b. Debug endpoint — flag evaluation with reasons (requires --debug)
        if self.debug_mode && ctx.path == FLAGS_DEBUG_PATH {
            let query_str = req.uri.query().unwrap_or("");
            match FlagDebugQuery::parse(query_str) {
                Ok(query) => {
                    let result = evaluate_debug(&self.flag_config, &query);
                    match serde_json::to_string(&result) {
                        Ok(json) => {
                            let _ = session
                                .respond_error_with_body(200, Bytes::from(json))
                                .await;
                        }
                        Err(_) => {
                            let body = serde_json::json!({"error": "Internal Server Error"});
                            let _ = session
                                .respond_error_with_body(500, Bytes::from(body.to_string()))
                                .await;
                        }
                    }
                }
                Err(e) => {
                    let body = serde_json::json!({"error": format!("{e}")});
                    let _ = session
                        .respond_error_with_body(400, Bytes::from(body.to_string()))
                        .await;
                }
            }
            return Ok(true);
        }
```

Fix the 404 body in the feature gate check (around line 186). Replace:

```rust
                    let _ = session.respond_error(404).await;
```

With:

```rust
                    let body = serde_json::json!({"error": "Not Found"});
                    let _ = session
                        .respond_error_with_body(404, Bytes::from(body.to_string()))
                        .await;
```

**Run:** `cargo check -p forgeguard_proxy` — compiles.

---

### Task C4 — Pass `identity.groups()` to `evaluate_flags`

**File:** `crates/proxy/src/proxy.rs`

Update the `evaluate_flags` call (around line 170-171). Replace:

```rust
            let resolved =
                evaluate_flags(&self.flag_config, identity.tenant_id(), identity.user_id());
```

With:

```rust
            let resolved = evaluate_flags(
                &self.flag_config,
                identity.tenant_id(),
                identity.user_id(),
                identity.groups(),
            );
```

**Run:** `cargo check -p forgeguard_proxy` — compiles.

---

### Task C5 — Add startup log for flag count

**File:** `crates/proxy/src/main.rs`

Update the startup log (around line 55) to include flag count:

```rust
    tracing::info!(
        listen = %config.listen_addr(),
        upstream = %config.upstream_url(),
        project = %config.project_id(),
        flags = config.features().flags.len(),
        "starting forgeguard-proxy"
    );
```

**Run:** `cargo check -p forgeguard_proxy` — compiles.

---

## Group D — Final Verification

### Task D1 — Run `cargo xtask lint`

**Run:** `cargo xtask lint`

This is the single source of truth. Fix any errors that come up (formatting, clippy, test failures).

**Expected:** Exit code 0.

---

### Task D2 — Update `crates/http/README.md` if it mentions feature flags

Check if `crates/http/README.md` or `crates/core/README.md` list public API items. If they do, add mentions of:
- `ResolutionReason`, `ResolvedFlag`, `DetailedResolvedFlags`, `evaluate_flags_detailed` (core)
- `FlagDebugQuery`, `evaluate_debug` (http)
- `debug.rs` module (http)

If the READMEs don't list API items, skip this task.

---

## Dependency Graph

```
Group A (core) ──> Group B (http) ──> Group C (proxy) ──> Group D (verify)
   A1 → A2 → A3 → A4 → A5 → A6 → A7
                                        B1 → B2 → B3
                                                        C1 → C2 → C3 → C4 → C5
                                                                                   D1 → D2
```

Groups A, B, C are sequential (each depends on the previous). Within each group, tasks are sequential. Group D runs last.

---

## Error Variant Check

Task B1 requires `Error::Validation { message: String }` in `crates/http/src/error.rs`. Before implementing B1, read `crates/http/src/error.rs` and check if this variant exists. If not, add it.
