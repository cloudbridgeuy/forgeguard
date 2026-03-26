---
shaping: true
---

# forgeguard_http — Shaping

**GitHub Issue:** [#12 — forgeguard_http — Route mapping, config, and HTTP adapter types](https://github.com/cloudbridgeuy/forgeguard/issues/12)
**Labels:** layer-2, http, config
**Blocked by:** #7 (done), #8 (done), #9 (done)
**Unblocks:** #13 (`forgeguard_proxy`), CLI subcommands (`check`, `config`, `routes`, `policies sync`)

---

## Frame

### Source

> The HTTP adapter library. All HTTP-specific types and logic live here — separated from the Pingora runtime so that config validation, route inspection, and other utility operations compile and run cross-platform (including macOS).

### Problem

The proxy needs to translate HTTP requests into authorization queries and back. This logic — route matching, config parsing, credential extraction, header injection — must live *outside* the Pingora crate so it compiles on macOS (Pingora is Linux-only) and is reusable by the CLI for config validation and route inspection.

### Outcome

A `forgeguard_http` crate with four capabilities: (1) route matching — `(method, path)` → `(action, resource)`, (2) config parsing — `forgeguard.toml` → validated `ProxyConfig`, (3) HTTP translation — credential extraction and header injection, (4) authn→authz glue — `build_query` bridges `Identity` into `PolicyQuery`.

### Why This Is the Largest of the Three

Issues #10 and #11 are thin I/O shells around external services. This crate is different — it's almost entirely **pure logic**: route matching, config validation, header building, query construction. It's the connective tissue between authn, authz, and the proxy. It has the most types and the most validation rules, but no external service dependencies.

---

## Requirements (R)

| ID   | Requirement                                                                                    | Status    |
| ---- | ---------------------------------------------------------------------------------------------- | --------- |
| R0   | Translate HTTP requests into authorization queries and responses                               | Core goal |
| R1   | Route matching: `(method, path)` → `(action, resource)` for policy engine                     | Must-have |
| R2   | Public route matching: bypass auth for configured paths (anonymous or opportunistic)           | Must-have |
| R3   | Config parsing: `forgeguard.toml` → validated `ProxyConfig`                                   | Must-have |
| R4   | Config validation: duplicates, invalid references, circular groups, action format              | Must-have |
| R5   | Credential extraction from HTTP headers (`Authorization: Bearer`, `X-API-Key`)                | Must-have |
| R6   | Identity header injection (`X-ForgeGuard-*` headers) for upstream                             | Must-have |
| R7   | Authn→authz glue: `build_query(Identity, MatchedRoute, ProjectId) → PolicyQuery`              | Must-have |
| R8   | Config override precedence: CLI flags > env vars > config file > defaults                     | Must-have |
| R9   | Compiles on macOS — no Pingora, no Linux-only deps                                            | Must-have |
| R10  | No `http` crate dependency — define own `HttpMethod` enum                                     | Must-have |
| R11  | Crate-level `Error` and `Result<T>` types                                                     | Must-have |

---

## Shape A: Issue-as-spec

### Part A1 — Route Matching (pure)

| Sub  | Mechanism |
| ---- | --------- |
| A1.1 | **HttpMethod** — `Get`, `Post`, `Put`, `Patch`, `Delete`, `Any`. Parsed from string. `Any` matches all methods. |
| A1.2 | **PathPattern** — literal segments, `{param}` captures, and `{*catch_all}` tail captures. Case-sensitive. Trailing-slash tolerant (with and without match the same). Parsed via `FromStr`. Maps directly to `matchit` syntax. |
| A1.3 | **RouteMapping** — `method: HttpMethod`, `path_pattern: PathPattern`, `action: QualifiedAction`, `resource_param: Option<String>`, `feature_gate: Option<FlagName>`. Links an HTTP route to a policy action. |
| A1.4 | **MatchedRoute** — `action: QualifiedAction`, `resource: Option<ResourceRef>`, `path_params: HashMap<String, String>`, `feature_gate: Option<FlagName>`. The result of a successful match. |
| A1.5 | **RouteMatcher** — radix trie backed by `matchit`. Routes inserted at build time; `match_request(method: &str, path: &str) → Option<MatchedRoute>`. Most-specific path wins, then method specificity (`GET` beats `ANY`). See **Resolved Decisions — A1.5** for details. |

### Part A2 — Public Routes (pure)

| Sub  | Mechanism |
| ---- | --------- |
| A2.1 | **PublicAuthMode** — `Anonymous` (no auth attempted) or `Opportunistic` (try auth, don't reject on failure). |
| A2.2 | **PublicRoute** — `method: HttpMethod`, `path_pattern: PathPattern`, `auth_mode: PublicAuthMode`. |
| A2.3 | **PublicMatch** — `NotPublic`, `Anonymous`, `Opportunistic`. The result of checking a request against public routes. |
| A2.4 | **PublicRouteMatcher** — same trie structure as `RouteMatcher`. `check(method: &str, path: &str) → PublicMatch`. Checked *before* the auth pipeline. |

### Part A3 — Configuration (pure, except file read)

| Sub  | Mechanism |
| ---- | --------- |
| A3.1 | **ProxyConfig** — top-level config struct. Fields: `project_id: ProjectId`, `listen_addr: SocketAddr`, `upstream_url: Url`, `default_policy: DefaultPolicy`, `client_ip_source: ClientIpSource`, `auth: AuthConfig`, `authz: AuthzConfig`, `policies: Vec<Policy>`, `groups: Vec<GroupDefinition>`, `features: FlagConfig`, `routes: Vec<RouteMapping>`, `public_routes: Vec<PublicRoute>`, `metrics: MetricsConfig`. All private fields, getter methods. |
| A3.2 | **AuthConfig** — `chain_order: Vec<String>`, JWT provider config, API key provider config. |
| A3.3 | **AuthzConfig** — `policy_store_id: String`, `aws_region: String`, `cache_ttl: Duration`, `cache_max_entries: usize`. |
| A3.4 | **DefaultPolicy** — `Passthrough` (allow if no route matches) or `Deny` (reject if no route matches). |
| A3.5 | **ClientIpSource** — `Peer`, `XForwardedFor`, `CfConnectingIp`. |
| A3.6 | **MetricsConfig** — `enabled: bool`, `listen_addr: Option<SocketAddr>`. Disabled by default. |
| A3.7 | **load_config(path) → Result\<ProxyConfig\>** — reads TOML file, deserializes, validates. The only I/O in this crate. |
| A3.8 | **apply_overrides(config, overrides) → ProxyConfig** — pure function. CLI flags > env vars > config file > defaults. |

### Part A4 — Config Validation (pure)

| Sub  | Mechanism |
| ---- | --------- |
| A4.1 | **validate(config) → Result\<(), Vec\<ValidationError\>\>** — runs all validation rules, collects all errors (not fail-fast). |
| A4.2 | No duplicate routes (same method + path pattern). |
| A4.3 | Actions are three-part `Namespace:Action:Entity` (already enforced by `QualifiedAction::parse`). |
| A4.4 | `feature_gate` references a defined flag in `features`. |
| A4.5 | `rollout_percentage` is 0..=100 (already enforced by `FlagDefinition` in core). |
| A4.6 | Public route overlapping auth route → warning (not error). Return warnings alongside errors. |
| A4.7 | Policy/group reference validation — all referenced policies exist, all group member-groups exist. |
| A4.8 | Circular group nesting detection (delegate to `forgeguard_core::compile_all_to_cedar` which already does this). |

### Part A5 — HTTP Translation (pure)

| Sub  | Mechanism |
| ---- | --------- |
| A5.1 | **extract_credential(headers) → Option\<Credential\>** — checks `Authorization: Bearer <token>`, then `X-API-Key: <key>`. Returns first found. Takes headers as `&[(String, String)]` slice — no `http` crate types. |
| A5.2 | **IdentityProjection** — per-request identity data to inject as upstream headers. Fields: `user_id`, `tenant_id`, `groups`, `auth_provider`, `principal_fgrn`, `features_json`, `client_ip`. |
| A5.3 | **inject_headers(projection) → Vec\<(String, String)\>** — produces `X-ForgeGuard-User-Id`, `-Tenant-Id`, `-Groups`, `-Auth-Provider`, `-Principal`, `-Features`, `-Client-Ip` header pairs. Returns owned pairs — the proxy layer maps to its own header types. |
| A5.4 | **inject_client_ip(ip) → (String, String)** — for anonymous/failed-opportunistic, inject only client IP. |

### Part A6 — Authn→Authz Glue (pure)

| Sub  | Mechanism |
| ---- | --------- |
| A6.1 | **build_query(identity, matched_route, project_id, client_ip) → PolicyQuery** — constructs `PrincipalRef` from identity, uses `MatchedRoute::action` and `MatchedRoute::resource`, builds `PolicyContext` with tenant, groups, IP, and extra claims. Pure function. |

### Part A7 — Error Types

| Sub  | Mechanism |
| ---- | --------- |
| A7.1 | **Error enum** — `Config(String)`, `Validation(Vec<ValidationError>)`, `RouteNotFound`, `Core(forgeguard_core::Error)`. |
| A7.2 | **ValidationError** — `kind: ValidationErrorKind`, `message: String`, `path: String` (e.g., "routes[2].action"). Structured for good CLI output. |
| A7.3 | **ValidationWarning** — same shape as error but non-fatal. Returned alongside `Ok(config)`. |

---

## FCIS Split

This crate is **almost entirely pure**. The only I/O is `load_config()` reading a file.

- **Pure core (unit-testable):** Route matching (A1), public route matching (A2), config validation (A4), credential extraction (A5.1), header injection (A5.3), query building (A6), config override merging (A3.8).
- **I/O shell:** `load_config()` (A3.7) — reads and deserializes a TOML file.

This means the crate could arguably be a `_core` crate except for the TOML file reading. Consider: make `load_config` the only function that touches the filesystem, and everything else is pure. The proxy passes the loaded config in — it never re-reads the file.

---

## Resolved Decisions

**A1.5 — Trie router via `matchit`:** Radix trie, not linear scan. Three reasons: (1) specificity-based matching (most-specific path wins) is what reverse proxy users expect — it eliminates ordering bugs in `forgeguard.toml`; (2) method-aware specificity means `GET /users/{id}` wins over `ANY /users/{id}` without the user thinking about config order; (3) this is what other reverse proxies do (Nginx, Envoy, and Rust frameworks like axum use `matchit` internally). The trie is built once at config load time and is immutable at runtime. `matchit` is zero-alloc at match time, so it's faster than linear scan as a bonus — but correctness of matching semantics is the real reason. Method-aware dispatch: internally we build one `matchit::Router` per `HttpMethod` variant plus one for `Any`. Lookup checks the method-specific router first; if no match, falls back to `Any`.

**A3.1 — Config field visibility:** All private with getters. The config is immutable after loading — no setters. Builder pattern not needed; parsing from TOML produces the config directly.

**A5.1 — Header representation:** `&[(String, String)]` for input, `Vec<(String, String)>` for output. No `http::HeaderMap`, no `http::Method`. The proxy layer does the conversion to/from Pingora types. This keeps the crate cross-platform.

**A3.7 — TOML crate:** Use `toml` crate with serde `Deserialize`. Define intermediate "raw" config structs for deserialization, then parse into validated domain types (Parse Don't Validate). The raw structs use `String` where domain types use `Segment`, `QualifiedAction`, etc.

**A4.1 — Collect-all vs. fail-fast validation:** Collect all errors. Users want to see every problem at once, not fix one and re-run.

---

## Rabbit Holes

| Risk | Mitigation |
| ---- | ---------- |
| Config format scope creep — too many options | Only implement what the proxy MVP needs. Start with the fields listed in the issue. Add fields only when a consumer needs them. |
| Path pattern complexity — regex, wildcards, glob | `{param}` captures, `{*catch_all}` tails, and literal segments only — all native `matchit` syntax. No regex. Catch-all enables patterns like `/admin/{*rest}` → require admin role. |
| TOML → domain type deserialization complexity | Two-phase parse: `toml::from_str` into raw serde structs, then `TryFrom<RawConfig>` into validated domain types. The raw structs mirror the TOML shape; the domain types enforce invariants. |
| Config hot-reload | Out of scope (that's issue #18). Config is loaded once at startup. |
| Header name casing | Use lowercase header names consistently. HTTP/2 mandates lowercase. HTTP/1.1 is case-insensitive but lowercase is conventional. |
| `PublicRoute` overlapping `RouteMapping` — ordering semantics | Public routes are checked first, always. If a path is both public and auth-protected, public wins. Emit a warning during validation but don't error. |

---

## Fit Check: R × A

| Req  | Requirement                                         | Status    | A |
| ---- | --------------------------------------------------- | --------- | :-: |
| R0   | Translate HTTP requests into auth queries/responses  | Core goal | A1,A5,A6 |
| R1   | Route matching: (method, path) → (action, resource) | Must-have | A1 |
| R2   | Public route matching                                | Must-have | A2 |
| R3   | Config parsing: forgeguard.toml → ProxyConfig        | Must-have | A3 |
| R4   | Config validation                                    | Must-have | A4 |
| R5   | Credential extraction                                | Must-have | A5.1 |
| R6   | Identity header injection                            | Must-have | A5.2,A5.3 |
| R7   | Authn→authz glue: build_query                        | Must-have | A6 |
| R8   | Config override precedence                           | Must-have | A3.8 |
| R9   | Compiles on macOS                                    | Must-have | ✅ (no Pingora) |
| R10  | No `http` crate dependency                           | Must-have | A1.1 (own HttpMethod) |
| R11  | Crate-level Error/Result                             | Must-have | A7 |

All requirements covered. No gaps.

---

## File Sketch

```
crates/http/src/
├── lib.rs              — pub exports, #![deny(...)]
├── error.rs            — Error, ValidationError, ValidationWarning (A7)
├── method.rs           — HttpMethod enum (A1.1)
├── path.rs             — PathPattern, path matching (A1.2)
├── route.rs            — RouteMapping, MatchedRoute, RouteMatcher (A1.3–A1.5)
├── public.rs           — PublicAuthMode, PublicRoute, PublicMatch, PublicRouteMatcher (A2)
├── config.rs           — ProxyConfig, AuthConfig, AuthzConfig, etc. (A3)
├── config_raw.rs       — Raw serde structs for TOML deserialization (A3)
├── validate.rs         — validation rules, collect-all strategy (A4)
├── credential.rs       — extract_credential (A5.1)
├── headers.rs          — IdentityProjection, inject_headers (A5.2–A5.4)
└── query.rs            — build_query (A6)
```

Estimated ~800–900 lines across all files. Largest files will be `config.rs` (~150) and `validate.rs` (~150). Individual files stay well under 300 lines.

---

## Dependency Note

This crate depends on `forgeguard_core`, `forgeguard_authn_core`, and `forgeguard_authz_core` — it bridges all three. It also needs `toml`, `serde`, `url` (for `Url` type), and `tracing`. No `tokio`, no `reqwest`, no AWS SDKs.
