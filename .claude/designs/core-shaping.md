---
shaping: true
---

# forgeguard_core — Shaping

**GitHub Issue:** [#7 — forgeguard_core — Shared primitives and config types](https://github.com/cloudbridgeuy/forgeguard/issues/7)
**Labels:** core, pure, layer-1
**Blocked by:** nothing (foundation crate)
**Unblocks:** #8, #9, #10, #11, #12, #13, #16

---

## Frame

### Source

> Define the foundational types that every other crate depends on. These are the typed IDs, error infrastructure, permission model types (Policy, Group, Effect), feature flag types and evaluation, and `ResolvedFlags`.
>
> This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`.

### Problem

Every crate in the ForgeGuard workspace needs shared primitives: typed IDs, the FGRN addressing scheme, an action vocabulary, permission model types, feature flag evaluation, and Cedar policy compilation. Without a pure foundation crate, these types would either be duplicated or mixed with I/O, breaking WASM compilation and the Functional Core / Imperative Shell boundary.

### Outcome

A single `forgeguard_core` crate that provides all shared domain types with zero I/O dependencies, compiles to `wasm32-unknown-unknown`, and is depended on by every other crate in the workspace.

---

## Requirements (R)

| ID   | Requirement                                                                 | Status    |
| ---- | --------------------------------------------------------------------------- | --------- |
| R0   | Provide typed, validated domain primitives for all ForgeGuard crates        | Core goal |
| R1   | Zero I/O dependencies — compiles to `wasm32-unknown-unknown`                | Must-have |
| R2   | FGRN: universal addressing for every entity (`fgrn:proj:tenant:ns:type:id`) | Must-have |
| R3   | Typed IDs with Parse Don't Validate (Segment, UserId, TenantId, etc.)      | Must-have |
| R4   | Action vocabulary types (Namespace, Action, Entity, QualifiedAction)        | Must-have |
| R5   | Permission model types (Effect, Policy, Group, Cedar compilation)           | Must-have |
| R6   | Feature flag types and pure evaluation (`evaluate_flags`)                   | Must-have |
| R7   | Error infrastructure (`Error` enum, `Result<T>` alias, `thiserror`)        | Must-have |
| R8   | All public types: `Display`, `FromStr`, `Serialize`, `Deserialize`          | Must-have |

---

## Shape A: Issue-as-spec (follow the acceptance criteria directly)

The issue's acceptance criteria are already concrete and mechanism-level. Shape A follows them as the implementation spec, organized into vertical parts.

| Part   | Mechanism                                                                                              | Flag |
| ------ | ------------------------------------------------------------------------------------------------------ | :--: |
| **A1** | **Segment + Typed IDs** — `Segment` newtype (lowercase, digits, hyphens, validated). `define_id!` macro for `UserId`, `TenantId`, `ProjectId`, `GroupName`, `PolicyName`. `FlowId(Uuid)`. |      |
| **A2** | **FGRN** — `Fgrn` struct with `Option<FgrnSegment>` positions. `FgrnSegment` enum (Value/Wildcard). `FromStr` parser, `Display`, `as_vp_entity_id()`, builder helpers, wildcard matching. |      |
| **A3** | **Action vocabulary** — `Namespace` (with reserved rejection), `Action`, `Entity`, `QualifiedAction` (`ns:action:entity`). VP/Cedar helper methods. `ResourceId`, `ResourceRef`, `PrincipalRef`. |      |
| **A4** | **Permission model** — `Effect` (Allow/Deny), `PatternSegment`, `ActionPattern` with wildcard matching, `CedarEntityRef`, `ResourceConstraint`, `PolicyStatement`, `Policy`, `GroupDefinition`. |      |
| **A5** | **Cedar compilation** — `compile_policy_to_cedar()` (Allow->permit, Deny->forbid with unless for except groups), `compile_all_to_cedar()` (reference validation, circular nesting detection). Pure functions. |      |
| **A6** | **Feature flags** — `FlagName` (Global/Scoped), `FlagValue` (Bool/String/Number), `FlagDefinition`, `FlagConfig`, `ResolvedFlags`. `evaluate_flags()` pure function: kill switch → pre-sorted override scan (specificity 3/2/1) → XxHash64 rollout bucket → default. `deterministic_bucket()` via `xxhash-rust`. Override sort at parse time. |      |
| **A7** | **Error infrastructure** — `Error` enum (Parse, Config, InvalidFlagType), `Result<T>` alias.          |      |

### Notes

- **A6 flagged ⚠️:** The issue specifies XxHash64 for deterministic bucketing, but `xxhash` is not in `Cargo.toml` today. We need to decide: add `xxhash-rust` as a dependency, or use a different stable hash. Also: the override hierarchy (user+tenant > user > tenant > rollout > default) needs concrete implementation detail — how does `evaluate_flags` walk the hierarchy?

---

## Fit Check: R x A

| Req  | Requirement                                                                 | Status    |  A  |
| ---- | --------------------------------------------------------------------------- | --------- | :-: |
| R0   | Provide typed, validated domain primitives for all ForgeGuard crates        | Core goal | ✅  |
| R1   | Zero I/O dependencies — compiles to `wasm32-unknown-unknown`                | Must-have | ✅  |
| R2   | FGRN: universal addressing for every entity (`fgrn:proj:tenant:ns:type:id`) | Must-have | ✅  |
| R3   | Typed IDs with Parse Don't Validate (Segment, UserId, TenantId, etc.)      | Must-have | ✅  |
| R4   | Action vocabulary types (Namespace, Action, Entity, QualifiedAction)        | Must-have | ✅  |
| R5   | Permission model types (Effect, Policy, Group, Cedar compilation)           | Must-have | ✅  |
| R6   | Feature flag types and pure evaluation (`evaluate_flags`)                   | Must-have | ✅  |
| R7   | Error infrastructure (`Error` enum, `Result<T>` alias, `thiserror`)        | Must-have | ✅  |
| R8   | All public types: `Display`, `FromStr`, `Serialize`, `Deserialize`          | Must-have | ✅  |

**Notes:**

- All requirements pass. A6 resolved via [spike](spike-flag-evaluation.md): override hierarchy and bucketing are fully specified in the design doc.

---

## Implementation Plan

See [`.claude/plans/2026-03-25-forgeguard-core.md`](../plans/2026-03-25-forgeguard-core.md) — 8 tasks, 7 modules, dependency-ordered.

---

## Current State

- `crates/core/` exists with scaffolded `Cargo.toml` and empty `src/lib.rs` (only `#![deny(clippy::unwrap_used, clippy::expect_used)]`)
- Dependencies declared: `serde`, `serde_json`, `thiserror`, `uuid`, `chrono`, `xxhash-rust`
