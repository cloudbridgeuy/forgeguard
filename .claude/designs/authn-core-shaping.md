---
shaping: true
---

# forgeguard_authn_core — Shaping

**GitHub Issue:** [#8 — forgeguard_authn_core — Identity resolution trait, chain, and credential types](https://github.com/cloudbridgeuy/forgeguard/issues/8)
**Labels:** pure, layer-1, authn
**Blocked by:** #7 (done)
**Unblocks:** #10 (`forgeguard_authn`), #12 (`forgeguard_http`), #13 (`forgeguard_proxy`)

---

## Frame

### Source

> Define the pluggable identity resolution abstraction — modeled after the AWS SDK's credential provider chain. This crate answers one question: "given a credential, who is this?"
>
> This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`. The `IdentityResolver` trait takes a `Credential` and returns an `Identity`.

### Problem

The proxy and downstream crates need a uniform way to resolve raw credentials (JWT bearer tokens, API keys) into trusted `Identity` values. Without a pure abstraction layer, identity resolution logic would either be coupled to specific providers (Cognito) or scattered across crates. The abstraction must be I/O-free so it compiles to WASM and lives in the functional core.

### Outcome

A `forgeguard_authn_core` crate that defines `Credential`, `Identity`, `IdentityResolver` (trait), `IdentityChain` (orchestrator), `StaticApiKeyResolver` (pure in-memory), and `JwtClaims` (data type). No I/O. Compiles to `wasm32-unknown-unknown`.

---

## Requirements (R)

| ID  | Requirement                                                                                          | Status    |
| --- | ---------------------------------------------------------------------------------------------------- | --------- |
| R0  | Pluggable identity resolution: "given a credential, who is this?"                                    | Core goal |
| R1  | Zero I/O dependencies — compiles to `wasm32-unknown-unknown`                                         | Must-have |
| R2  | `Credential` enum: protocol-agnostic input (Bearer, ApiKey) — no HTTP concepts                       | Must-have |
| R3  | `Identity` struct: validated output with UserId, TenantId, groups, expiry, resolver name, extra      | Must-have |
| R4  | `IdentityResolver` trait: async, pluggable, `can_resolve` + `resolve` (AWS SDK ProvideCredentials)   | Must-have |
| R5  | `IdentityChain`: tries resolvers in order, first `can_resolve()` match owns the outcome              | Must-have |
| R6  | `StaticApiKeyResolver`: pure in-memory HashMap lookup, no I/O                                        | Must-have |
| R7  | `JwtClaims`: raw JWT claims data type (used by CognitoJwtResolver in #10, defined here)              | Must-have |
| R8  | `Identity` cannot be constructed outside the crate — `pub(crate)` constructor, getter methods only   | Must-have |
| R9  | `IdentityBuilder` behind `test-support` feature flag for test construction                           | Must-have |

---

## Shape A: Issue-as-spec (follow the acceptance criteria directly)

The issue's acceptance criteria are concrete and mechanism-level. Shape A follows them as the implementation spec.

| Part   | Mechanism                                                                                                                                                                       | Flag |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--: |
| **A1** | **Credential enum** — `Bearer(String)`, `ApiKey(String)`. `type_name()` method for diagnostics. No HTTP concepts. `Display`, `Serialize`, `Deserialize`.                        |      |
| **A2** | **Identity struct** — private fields (`user_id: UserId`, `tenant_id: Option<TenantId>`, `groups: Vec<GroupName>`, `expiry: Option<DateTime<Utc>>`, `resolver: &'static str`, `extra: Option<serde_json::Value>`). `pub(crate)` constructor. Public getter methods. Consumes `forgeguard_core` typed IDs. |      |
| **A3** | **IdentityResolver trait** — `Send + Sync`. `name() -> &'static str`, `can_resolve(&Credential) -> bool`, `resolve(&Credential) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>>`. No HTTP, no tokio dependency. Keep `Send` — WASM consumers use types only; server-side needs `Send` for tokio. |      |
| **A4** | **IdentityChain** — `Vec<Arc<dyn IdentityResolver>>`. `resolve()` iterates, first `can_resolve()` match owns outcome. `Error::NoResolver` if none match.                       |      |
| **A5** | **StaticApiKeyResolver** — `HashMap<String, ApiKeyEntry>` in-memory lookup. `ApiKeyEntry { user_id, tenant_id, groups, description }`. `Box::pin(std::future::ready(...))` for async wrapper. |      |
| **A6** | **JwtClaims struct** — `sub`, `iss`, `aud`, `exp`, `iat`, `token_use`, `scope`, `cognito_groups`, `custom_claims`. Pure data type with `Deserialize`.                           |      |
| **A7** | **IdentityBuilder** — `#[cfg(feature = "test-support")]`. Builder pattern: `new(UserId)`, `.tenant()`, `.groups()`, `.resolver()`, `.expiry()`, `.extra()`, `.build() -> Identity`. |      |
| **A8** | **Error enum** — `NoResolver`, `TokenExpired`, `InvalidIssuer`, `InvalidAudience`, `MissingClaim`, `MalformedToken`, `InvalidCredential`. `Result<T>` alias.                    |      |

### Resolved Decisions

**A2 — `expiry` field type:** `DateTime<Utc>` (not `SystemTime`). Consistent with workspace, serializes cleanly.

**A3 — `Send` bound on async future:** Keep `Send`. WASM consumers use the types (`Credential`, `Identity`, `JwtClaims`) but won't poll futures directly. Server-side needs `Send` for tokio's multi-threaded runtime.

---

## Fit Check: R x A

| Req | Requirement                                                                                        | Status    |  A  |
| --- | -------------------------------------------------------------------------------------------------- | --------- | :-: |
| R0  | Pluggable identity resolution: "given a credential, who is this?"                                  | Core goal | ✅  |
| R1  | Zero I/O dependencies — compiles to `wasm32-unknown-unknown`                                       | Must-have | ✅  |
| R2  | `Credential` enum: protocol-agnostic input (Bearer, ApiKey) — no HTTP concepts                     | Must-have | ✅  |
| R3  | `Identity` struct: validated output with UserId, TenantId, groups, expiry, resolver name, extra    | Must-have | ✅  |
| R4  | `IdentityResolver` trait: async, pluggable, `can_resolve` + `resolve`                              | Must-have | ✅  |
| R5  | `IdentityChain`: tries resolvers in order, first `can_resolve()` match owns the outcome            | Must-have | ✅  |
| R6  | `StaticApiKeyResolver`: pure in-memory HashMap lookup, no I/O                                      | Must-have | ✅  |
| R7  | `JwtClaims`: raw JWT claims data type                                                              | Must-have | ✅  |
| R8  | `Identity` cannot be constructed outside the crate                                                 | Must-have | ✅  |
| R9  | `IdentityBuilder` behind `test-support` feature flag                                               | Must-have | ✅  |

**Notes:**

- All requirements pass. Both flagged unknowns resolved (see Resolved Decisions above).

---

## Implementation Plan

See [`.claude/plans/2026-03-25-authn-core.md`](../plans/2026-03-25-authn-core.md) — 5 groups, 10 tasks, dependency-ordered with parallel execution within groups.

---

## Current State

- `crates/authn-core/` exists with scaffolded `Cargo.toml` and empty `src/lib.rs`
- Dependencies declared: `forgeguard_core`, `serde`, `serde_json`, `thiserror`, `chrono`
- `forgeguard_core` is complete — typed IDs (`UserId`, `TenantId`, `GroupName`) are available
