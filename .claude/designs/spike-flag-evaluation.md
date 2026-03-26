---
shaping: true
---

# A6 Spike: Feature Flag Override Hierarchy and Rollout Bucketing

## Context

Shape A part A6 (Feature flags) is flagged ⚠️. The issue and design doc describe the feature flag system, but two mechanisms needed concrete verification: (1) the override hierarchy walk, and (2) the deterministic bucketing approach. This spike reads the design doc to extract the concrete answers.

## Goal

Understand exactly how `evaluate_flags` resolves a single flag, step by step, and confirm the XxHash64 bucketing mechanism is fully specified.

## Questions

| #        | Question                                                              | Answer |
| -------- | --------------------------------------------------------------------- | ------ |
| **Q1**   | How does `resolve_single_flag` walk the override hierarchy?           | ✅ Answered below |
| **Q2**   | What is the specificity sorting rule for overrides?                   | ✅ Answered below |
| **Q3**   | How does `deterministic_bucket` work?                                 | ✅ Answered below |
| **Q4**   | Is XxHash64 the right dependency? Is it WASM-compatible?              | ✅ Answered below |

---

## Findings

### Q1: Override hierarchy walk

The design doc (lines 1404–1437) provides the **complete implementation**:

```rust
fn resolve_single_flag(name: &FlagName, flag: &FlagDefinition, tenant_id: Option<&TenantId>, user_id: &UserId) -> FlagValue {
    // 0. Kill switch — short-circuit to default
    if !flag.enabled { return flag.default.clone(); }

    // 1. Check overrides (pre-sorted by specificity: user+tenant > user > tenant)
    for ov in &flag.overrides {
        let user_matches = ov.user.as_ref().map_or(true, |u| u == user_id);
        let tenant_matches = ...similar...;
        if user_matches && tenant_matches {
            return ov.value.clone();
        }
    }

    // 2. Check percentage rollout
    if let Some(pct) = flag.rollout_percentage {
        let bucket = deterministic_bucket(&name.to_string(), tenant_id, user_id);
        if bucket < pct {
            return flag.rollout_variant.clone().unwrap_or(FlagValue::Bool(true));
        }
    }

    // 3. Default
    flag.default.clone()
}
```

**The algorithm is a linear scan over pre-sorted overrides.** First match wins. The sorting happens at parse time (when TOML is loaded), not at evaluation time.

### Q2: Specificity sorting

From the design doc (line 1378): *"Overrides are pre-sorted by specificity: user+tenant (3) > user (2) > tenant (1)."*

The specificity score:
- **3** — both `user` and `tenant` are `Some` (most specific)
- **2** — only `user` is `Some`
- **1** — only `tenant` is `Some`
- **0** — neither is `Some` (catch-all, matches everyone — the doc says to warn on this)

Sorting is descending by specificity, so the first match in the linear scan is always the most specific applicable override.

**Match logic per override:**
- `ov.user == None` means "matches any user" (not "matches no user")
- `ov.tenant == None` means "matches any tenant"
- Both `None` means "matches everyone" — effectively shadows the default

### Q3: Deterministic bucketing

The design doc (lines 1440–1448) specifies:

```rust
fn deterministic_bucket(flag: &str, tenant: Option<&TenantId>, user: &UserId) -> u8 {
    use std::hash::Hasher;
    // XxHash64, feed flag name + tenant + user, mod 100 → 0..99
}
```

The input is `(flag_name_string, tenant_id_string_or_empty, user_id_string)` fed into an XxHash64 hasher. The result is `hash % 100`, giving a bucket in `0..99`. The comparison is `bucket < pct`, so:
- `rollout_percentage = 0` → nobody (0 < 0 is false for all buckets)
- `rollout_percentage = 100` → everyone (0..99 are all < 100)
- `rollout_percentage = 25` → ~25% of users

**Conformance requirement:** Every SDK language must produce the same bucket for the same inputs. XxHash64 has a well-defined spec, making this portable.

### Q4: XxHash64 and WASM compatibility

`xxhash-rust` is a pure Rust implementation with no `std` requirement. It compiles to `wasm32-unknown-unknown` without issues. The `xxh64` feature flag enables only the 64-bit variant, keeping the dependency minimal.

Added to workspace `Cargo.toml` and `crates/core/Cargo.toml` as `xxhash-rust = { version = "0.8", features = ["xxh64"] }`.

---

## Summary

**The flag evaluation mechanism is fully specified in the design doc.** There are no remaining unknowns:

1. **Kill switch** → short-circuit to default, ignore everything
2. **Override scan** → pre-sorted by specificity at parse time, linear scan, first match wins
3. **Rollout** → XxHash64 bucket, `bucket < pct` check, fallback to `rollout_variant` or `Bool(true)`
4. **Default** → final fallback

The ⚠️ flag on A6 can be removed.
