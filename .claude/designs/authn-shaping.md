---
shaping: true
---

# forgeguard_authn — Shaping

**GitHub Issue:** [#10 — forgeguard_authn — Cognito JWT identity resolver](https://github.com/cloudbridgeuy/forgeguard/issues/10)
**Labels:** io, layer-2, authn
**Blocked by:** #7 (done), #8 (done)
**Unblocks:** #13 (`forgeguard_proxy`)
**Integration tests require:** #14 (Cognito User Pool — not yet done)

---

## Frame

### Source

> Implement `IdentityResolver` for Cognito JWTs. This resolver takes a `Credential::Bearer(token)`, fetches the JWKS from Cognito, verifies the signature, validates claims, and produces an `Identity`.

### Problem

The proxy needs to resolve JWT bearer tokens into `Identity` values. The pure `IdentityResolver` trait exists in `authn_core`, but there's no concrete implementation that talks to Cognito. This crate is the I/O shell that wraps `jsonwebtoken` verification and JWKS fetching behind that trait.

### Outcome

A `forgeguard_authn` crate that implements `IdentityResolver` for Cognito JWTs with JWKS caching. No `http` crate dependency (HTTP types live in `forgeguard_http`). Dependencies: `reqwest` (JWKS fetch), `jsonwebtoken` (verification), `forgeguard_core`, `forgeguard_authn_core`.

---

## Requirements (R)

| ID  | Requirement                                                                                    | Status    |
| --- | ---------------------------------------------------------------------------------------------- | --------- |
| R0  | Resolve `Credential::Bearer(token)` into `Identity` via Cognito JWT verification               | Core goal |
| R1  | Implement `IdentityResolver` trait from `authn_core`                                           | Must-have |
| R2  | Fetch and cache JWKS from Cognito's well-known endpoint                                        | Must-have |
| R3  | RS256 signature verification via `jsonwebtoken`                                                | Must-have |
| R4  | Configurable claim extraction (user_id, tenant, groups claims)                                 | Must-have |
| R5  | TTL-based JWKS cache with refresh on unknown `kid`                                             | Must-have |
| R6  | No `http` crate dependency — HTTP types live in `forgeguard_http`                              | Must-have |
| R7  | Unit-testable without network (generate RSA keys, sign test JWTs)                              | Must-have |
| R8  | Crate-level `Error` and `Result<T>` types following workspace convention                       | Must-have |

---

## Shape A: Issue-as-spec

| Part   | Mechanism                                                                                                                                                                       | Flag |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--: |
| **A1** | **JwtResolverConfig** — `jwks_url: Url`, `issuer: String`, `audience: Option<String>`, `user_id_claim: String` (default "sub"), `tenant_claim: String` (default "custom:org_id"), `groups_claim: String` (default "cognito:groups"). Private fields, constructor function with defaults.  | |
| **A2** | **CognitoJwtResolver** — `jwks_cache: JwksCache`, `config: JwtResolverConfig`. Implements `IdentityResolver`: `name() → "cognito_jwt"`, `can_resolve(Bearer(_)) → true`, `can_resolve(ApiKey(_)) → false`. | |
| **A3** | **JwksCache** — `RwLock<HashMap<String, DecodingKey>>` keyed by `kid`. Configurable TTL (default 1h). On miss: fetch JWKS, parse, store all keys. On hit: return key. The `RwLock` is correct here — reads are common, writes (fetches) are rare. | |
| **A4** | **JWKS fetcher** — `reqwest::Client` fetches from `jwks_url`. Parses JWK set, extracts RSA keys, converts to `DecodingKey`. This is the only I/O in the crate. | |
| **A5** | **JWT verification** — `jsonwebtoken::decode` with `Validation` (issuer, audience, RS256). Extract claims into `JwtClaims` (from `authn_core`). Map claims → `Identity` using configured claim names. | |
| **A6** | **Claim-to-Identity mapping** — Pure function: `fn map_claims(claims: &JwtClaims, config: &JwtResolverConfig) -> Result<Identity>`. Extracts user_id, tenant_id, groups from configured claim paths. This is the testable core. | |
| **A7** | **Error enum** — `Core(forgeguard_authn_core::Error)`, `JwksFetch(String)`, `KeyNotFound(String)`, `SignatureInvalid`, `TokenDecode(String)`. Implements `From<authn_core::Error>`. | |

### FCIS Split

The crate is an I/O shell by definition, but it still has an extractable pure core:

- **Pure (unit-testable):** A6 — claim-to-Identity mapping. Given a `JwtClaims` and config, produce an `Identity`. No I/O, no crypto. This is where most of the business logic lives (which claim becomes `user_id`, how groups are extracted, etc.).
- **I/O (integration-testable):** A3/A4 — JWKS fetch and cache. A5 — JWT signature verification (depends on cached keys). A2 — the `resolve()` orchestration that wires it all together.

### Resolved Decisions

**A1 — Config field visibility:** Private fields with a constructor `JwtResolverConfig::new(jwks_url, issuer)` that sets defaults for claim names. Builder methods for overrides: `.with_audience()`, `.with_user_id_claim()`, etc.

**A3 — Cache stampede prevention:** First implementation uses simple `RwLock` — upgrade lock to write, fetch, store. If two threads race, the second fetch is wasted but harmless. A `tokio::sync::OnceCell` or notify pattern is an optimization for later. YAGNI for now.

**A4 — reqwest vs. raw HTTP:** Use `reqwest` — it's already needed, well-tested, and the JWKS endpoint is a simple GET. No reason to hand-roll.

**A5 — `jsonwebtoken` API:** `jsonwebtoken::decode::<JwtClaims>(token, &key, &validation)` returns `TokenData<JwtClaims>`. The `JwtClaims` struct in `authn_core` needs `Deserialize` (it already has it). Claims beyond the standard set go into `custom_claims: HashMap`.

---

## Rabbit Holes

| Risk | Mitigation |
| ---- | ---------- |
| JWKS refresh thundering herd under load | Accept double-fetch for now. Cache write is idempotent. Optimize with `tokio::sync::Notify` only if profiling shows contention. |
| Supporting multiple JWT algorithms | RS256 only (Cognito default). Add algorithm config later if needed. |
| Token introspection / opaque token support | Out of scope. This resolver handles JWTs only. Opaque tokens would be a separate `IdentityResolver` implementation. |
| `reqwest` pulling in too many features | Use `reqwest` with `rustls-tls` feature only. No cookies, no redirects, no multipart. |

---

## Fit Check: R × A

| Req | Requirement                                                     | Status    |  A  |
| --- | --------------------------------------------------------------- | --------- | :-: |
| R0  | Resolve Bearer token → Identity via Cognito JWT                 | Core goal | A2,A5,A6 |
| R1  | Implement `IdentityResolver` trait                              | Must-have | A2 |
| R2  | Fetch and cache JWKS                                            | Must-have | A3,A4 |
| R3  | RS256 signature verification                                    | Must-have | A5 |
| R4  | Configurable claim extraction                                   | Must-have | A1,A6 |
| R5  | TTL-based JWKS cache with refresh on miss                       | Must-have | A3 |
| R6  | No `http` crate dependency                                      | Must-have | ✅ (reqwest, not http) |
| R7  | Unit-testable without network                                   | Must-have | A6 (pure), A5 (mock keys) |
| R8  | Crate-level Error/Result                                        | Must-have | A7 |

All requirements covered. No gaps.

---

## File Sketch

```
crates/authn/src/
├── lib.rs              — pub exports, #![deny(...)]
├── error.rs            — Error enum, Result alias
├── config.rs           — JwtResolverConfig (A1)
├── jwks.rs             — JwksCache + JWKS fetcher (A3, A4)
├── claims.rs           — map_claims pure function (A6)
└── resolver.rs         — CognitoJwtResolver + IdentityResolver impl (A2, A5)
```

Estimated ~400 lines total. Well under the 1000-line limit.
