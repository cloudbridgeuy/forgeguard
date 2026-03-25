---
shaping: true
---

# forgeguard_authz_core — Shaping

**GitHub Issue:** [#9 — forgeguard_authz_core — Policy engine trait and authorization types](https://github.com/cloudbridgeuy/forgeguard/issues/9)
**Labels:** pure, layer-1, authz
**Blocked by:** #7 (done)
**Unblocks:** #11 (`forgeguard_authz`), #12 (`forgeguard_http`), #13 (`forgeguard_proxy`)

---

## Frame

### Source

> Define the authorization domain: "can principal P perform action A on resource R given context C?" This crate provides a pure trait for answering that question.
>
> The `PolicyEngine` trait takes a `PolicyQuery` (principal + action + resource + context) and returns a `PolicyDecision` (allow or deny).
>
> This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`.
>
> **NOTE:** The `build_query` helper (which bridges `Identity` from `authn_core` into a `PolicyQuery`) lives in `forgeguard_http`, not here. This keeps `authz_core` independent of `authn_core`.

### Problem

The proxy and downstream crates need a uniform way to ask "is this allowed?" without coupling to a specific policy engine (Cedar, Verified Permissions, or an in-memory stub). Without a pure abstraction, authorization logic would either be hardcoded to a provider or scattered. The abstraction must be I/O-free for WASM compilation and FCIS compliance.

### Outcome

A `forgeguard_authz_core` crate that defines `PolicyQuery`, `PolicyContext`, `PolicyDecision`, `DenyReason`, the `PolicyEngine` trait, and a `StaticPolicyEngine` for testing. No I/O. No dependency on `authn_core`. Compiles to `wasm32-unknown-unknown`.

---

## Requirements (R)

| ID  | Requirement                                                                                                | Status    |
| --- | ---------------------------------------------------------------------------------------------------------- | --------- |
| R0  | Pure authorization query/decision abstraction: "can P do A on R given C?"                                  | Core goal |
| R1  | Zero I/O dependencies — compiles to `wasm32-unknown-unknown`                                               | Must-have |
| R2  | `PolicyQuery`: protocol-agnostic input (`PrincipalRef`, `QualifiedAction`, `Option<ResourceRef>`, context) | Must-have |
| R3  | `PolicyContext`: tenant, groups, IP address, arbitrary attributes                                           | Must-have |
| R4  | `PolicyDecision`: binary Allow/Deny with structured deny reasons                                            | Must-have |
| R5  | `PolicyEngine` trait: async, pluggable, `Send + Sync`                                                      | Must-have |
| R6  | No dependency on `authn_core` — `build_query` bridge lives in `forgeguard_http`                             | Must-have |
| R7  | Error infrastructure (`Error` enum, `Result<T>` alias, `thiserror`)                                         | Must-have |
| R8  | `PolicyQuery` cannot be constructed with raw strings — consumes `forgeguard_core` typed IDs                 | Must-have |
| R9  | `StaticPolicyEngine`: in-memory engine behind `test-support` feature flag for testing consumers             | Must-have |

---

## Shape A: Issue-as-spec

The issue's acceptance criteria are concrete and mechanism-level. Shape A follows them directly, with the addition of `StaticPolicyEngine` (R9) which the issue omitted.

| Part   | Mechanism                                                                                                     | Flag |
| ------ | ------------------------------------------------------------------------------------------------------------- | :--: |
| **A1** | **PolicyQuery** — struct with `principal: PrincipalRef`, `action: QualifiedAction`, `resource: Option<ResourceRef>`, `context: PolicyContext`. Consumes `forgeguard_core` typed IDs. Constructor function (no raw string fields). |      |
| **A2** | **PolicyContext** — struct with `tenant_id: Option<TenantId>`, `groups: Vec<GroupName>`, `ip_address: Option<IpAddr>`, `attributes: HashMap<String, serde_json::Value>`. Constructor + builder methods. `IpAddr` from `std::net` (no I/O dependency). |      |
| **A3** | **PolicyDecision + DenyReason** — `PolicyDecision` enum: `Allow`, `Deny { reason: DenyReason }`. `DenyReason` enum: `NoMatchingPolicy`, `ExplicitDeny { policy_id: String }`, `EvaluationError(String)`. `Display` impl with useful messages per variant. |      |
| **A4** | **PolicyEngine trait** — `Send + Sync`. Single method: `evaluate(&self, query: &PolicyQuery) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>`. Async to support I/O implementations (Verified Permissions). Pure implementations use `Box::pin(std::future::ready(...))`. |      |
| **A5** | **StaticPolicyEngine** — `#[cfg(feature = "test-support")]`. `new(default: PolicyDecision)` sets default answer. `.with_override(action: QualifiedAction, decision: PolicyDecision)` for per-action overrides. `Box::pin(std::future::ready(...))` for async. Mirrors `StaticApiKeyResolver` pattern from authn-core. |      |
| **A6** | **Error enum** — `Error` with variants for evaluation failures. `Result<T>` alias. `thiserror` derives.       |      |

### Resolved Decisions

**A4 — Async in a pure crate:** `Future` is in `core::future` — no runtime dependency. The trait is *defined* here, *implemented* in I/O crates. Pure implementations wrap sync results with `std::future::ready`. `Send` bound needed for tokio multi-threaded runtime on server side; harmless for WASM (single-threaded, types-only consumption). Same pattern as authn-core's `IdentityResolver`.

**A5 — StaticPolicyEngine scope:** Minimal first version — default decision + per-action overrides. No matching on principal or resource. Action-level is the most common test scenario. Expand if a consumer needs finer granularity.

---

## Fit Check: R × A

| Req | Requirement                                                                                                | Status    |  A  |
| --- | ---------------------------------------------------------------------------------------------------------- | --------- | :-: |
| R0  | Pure authorization query/decision abstraction: "can P do A on R given C?"                                  | Core goal | ✅  |
| R1  | Zero I/O dependencies — compiles to `wasm32-unknown-unknown`                                               | Must-have | ✅  |
| R2  | `PolicyQuery`: protocol-agnostic input (`PrincipalRef`, `QualifiedAction`, `Option<ResourceRef>`, context) | Must-have | ✅  |
| R3  | `PolicyContext`: tenant, groups, IP address, arbitrary attributes                                           | Must-have | ✅  |
| R4  | `PolicyDecision`: binary Allow/Deny with structured deny reasons                                            | Must-have | ✅  |
| R5  | `PolicyEngine` trait: async, pluggable, `Send + Sync`                                                      | Must-have | ✅  |
| R6  | No dependency on `authn_core` — `build_query` bridge lives in `forgeguard_http`                             | Must-have | ✅  |
| R7  | Error infrastructure (`Error` enum, `Result<T>` alias, `thiserror`)                                         | Must-have | ✅  |
| R8  | `PolicyQuery` cannot be constructed with raw strings — consumes `forgeguard_core` typed IDs                 | Must-have | ✅  |
| R9  | `StaticPolicyEngine`: in-memory engine behind `test-support` feature flag for testing consumers             | Must-have | ✅  |

**Notes:**

- All requirements pass. No flagged unknowns remain.

---

## Current State

- Implementation complete. 6 modules: `error`, `decision`, `context`, `query`, `engine`, `static_engine`.
- 12 tests passing (with `test-support` feature).
- No `authn_core` dependency. No I/O dependencies.
- `cargo xtask lint` passes.
