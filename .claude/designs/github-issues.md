# ForgeGuard — GitHub Issues: Target B Milestone

> **Goal:** A developer runs the ForgeGuard proxy in front of their app. The proxy resolves identity, checks authorization, injects identity headers, and proxies the request upstream. The policy domain (identity resolution + authorization decisions) is protocol-agnostic — the HTTP proxy is one adapter consuming it. No Smithy, no dashboard, no SDK generation — just auth enforcement on a real app.

---

## Milestone: `target-b-proxy-enforces-auth`

## Architecture: Policy Domain + Protocol Adapter

The design enforces a clean separation between the **policy domain** (protocol-agnostic rules about identity and authorization) and the **HTTP adapter** (one protocol binding that translates HTTP into policy queries and policy decisions into HTTP responses).

```
POLICY DOMAIN (pure, no HTTP, no I/O)          POLICY I/O
────────────────────────────────────            ──────────

forgeguard_core                                  forgeguard_authn
  UserId, TenantId, config types                  CognitoJwtResolver
                                                  (Credential → Identity)
forgeguard_authn_core
  Credential, Identity,                         forgeguard_authz
  IdentityResolver trait, chain                   VpPolicyEngine
                                                  (PolicyQuery → PolicyDecision)
forgeguard_authz_core
  PolicyQuery, PolicyDecision,
  PolicyEngine trait


HTTP ADAPTER (protocol binding — split into library + runtime)
──────────────────────────────────────────────────────────────

forgeguard_http (library, compiles everywhere — no Pingora)
  ProxyConfig, RouteMapping, RouteMatcher, PathPattern
  PublicRoute, PublicRouteMatcher, PublicAuthMode
  HTTP header → Credential extraction
  (method, path) → (action, resource) route matching
  Identity → X-ForgeGuard-* header injection
  PolicyDecision → 401/403/200 response translation
  Config loading, validation, override merging

forgeguard_proxy (binary, Linux-only — Pingora runtime)
  Pingora ProxyHttp impl (ForgeGuardProxy, RequestCtx)
  Wires forgeguard_http types into Pingora phases
  `run` subcommand only

forgeguard_cli (binary, cross-platform — no Pingora)
  `check`, `config`, `routes` subcommands (use forgeguard_http)
```

Tomorrow a gRPC interceptor, a WebSocket middleware, an MCP tool gate, or a queue consumer would be different adapters consuming the same policy domain. None of them would need to change `authn_core` or `authz_core`. The `forgeguard_http` / `forgeguard_proxy` split also means a future `forgeguard_grpc` adapter would sit at the same level as `forgeguard_http`.

## Dependency Graph

```
                    ┌─────────────────────┐
                    │  #1 forgeguard_core  │
                    │  shared primitives   │
                    └──────┬──────────────┘
                           │
              ┌────────────┼────────────────┐
              ▼            │                ▼
┌──────────────────┐       │    ┌──────────────────────────┐
│ #2 authn_core    │       │    │ #3 authz_core            │
│ Credential,      │       │    │ PolicyQuery,              │
│ Identity,        │       │    │ PolicyDecision,           │
│ IdentityResolver │       │    │ PolicyEngine trait         │
└────────┬─────────┘       │    └────────────┬─────────────┘
         │                 │                 │
         ▼                 │                 ▼
┌──────────────────┐       │    ┌──────────────────────────┐
│ #4 authn (I/O)   │       │    │ #5 authz (I/O)           │
│ CognitoJwt       │       │    │ Verified Permissions      │
│ Resolver         │       │    │ client + cache            │
└────────┬─────────┘       │    └────────────┬─────────────┘
         │                 │                 │
         └─────────┬───────┘─────────────────┘
                   ▼
         ┌───────────────────────┐
         │ #6 forgeguard_http    │
         │ config, route matcher │
         │ credential extraction │
         │ header injection      │
         │ (compiles everywhere) │
         └───┬──────────────┬────┘
             │              │
             ▼              │
  ┌───────────────────┐     │
  │ #10 flag proxy    │     │
  │ integration       │     │
  └───────┬───────────┘     │
          │                 │
          ▼                 ▼
  ┌──────────────────┐  ┌─────────────────────┐
  │ #7 proxy binary  │  │ forgeguard_cli      │
  │ Pingora runtime  │  │ check, config,      │
  │ `run` only       │  │ routes, policies    │
  │ (Linux-only)     │  │ (cross-platform)    │
  └────────┬─────────┘  └─────────────────────┘
           ▼
  ┌──────────────────┐       ┌──────────────────────────┐
  │ #8a Cognito      │──────►│ #8b Verified Permissions │
  │ (identity infra) │       │ + Cedar (authz infra)    │
  └──────┬───────────┘       └────────────┬─────────────┘
         │ also unblocks                  │
         │ #4 integration tests           │
         └────────────┬───────────────────┘
                      ▼
           ┌──────────────────┐
           │ #9 e2e demo      │
           │ TODO app + proxy │
           └──────────────────┘
```

Note: The `http` types crate is a dependency of `forgeguard_http` and `forgeguard_proxy`. Pure domain crates (`core`, `authn_core`, `authz_core`) have no `http` dependency.

---

## Crate Ownership Map

| Crate                   | Owns                                                                                                                                                                                                                                                                                                                                              | Classification             |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| `forgeguard_core`       | `UserId`, `TenantId`, `GroupName`, `PolicyName`, `Fgrn`, `Segment`, `QualifiedAction`, `ActionPattern`, `CedarEntityRef`, `Effect`, `PolicyStatement`, `Policy`, `ResourceConstraint`, `FlagName`, `FlagValue`, `FlagConfig`, `ResolvedFlags`                                                                                                     | Pure (no I/O)              |
| `forgeguard_authn_core` | `Credential`, `Identity`, `IdentityResolver` trait, `IdentityChain`, `StaticApiKeyResolver`                                                                                                                                                                                                                                                                       | Pure (no I/O)              |
| `forgeguard_authz_core` | `PolicyQuery`, `PolicyDecision`, `PolicyContext`, `PolicyEngine` trait                                                                                                                                                                                                                                                                            | Pure (no I/O)              |
| `forgeguard_authn`      | `CognitoJwtResolver`, JWKS fetching                                                                                                                                                                                                                                                                                             | I/O (`reqwest`)            |
| `forgeguard_authz`      | `VpPolicyEngine`, Verified Permissions API calls, decision cache                                                                                                                                                                                                                                                                                  | I/O (`aws-sdk`)            |
| `forgeguard_http`       | `ProxyConfig`, `AuthConfig`, `AuthzConfig`, `MetricsConfig`, `RouteMapping`, `RouteMatcher`, `PublicRoute`, `PublicAuthMode`, `PublicMatch`, `PublicRouteMatcher`, `PathPattern`, `HttpMethod`, `IdentityProjection`, `build_query`, credential extraction from headers, header injection, HTTP status code translation, `forgeguard.toml` loading, config validation | Library (`http` types, no Pingora) |
| `forgeguard_proxy`      | `ForgeGuardProxy`, `RequestCtx`, Pingora `ProxyHttp` impl, `run` subcommand                                                                                                                                                                                                                                                                         | Binary (`pingora`, Linux-only)     |
| `forgeguard_cli`        | `check`, `config`, `routes`, `policies sync` subcommands (cross-platform, uses `forgeguard_http` + `aws-sdk` for `policies sync`)                                                                                                                                                                                                                                    | Binary (cross-platform, I/O for policy sync) |

**CI gate:** `cargo tree -p forgeguard_authn_core | grep -E "^.* http "` must return nothing. Same for `core`, `authz_core`. (I/O crates `authn` and `authz` transitively depend on `http` via `reqwest`/`aws-sdk` — that's expected.)

---

## Permission Model

ForgeGuard's authorization model uses four primitives: **Actions**, **Policies**, **Groups**, and **Users**. Everything is default-deny — access must be explicitly granted.

### Actions

The atomic unit. A fully qualified action is `namespace:verb:entity` (e.g., `todo:read:list`, `billing:refund:invoice`). Already modeled as `QualifiedAction` in `forgeguard_core`. Actions are what the system protects — every route maps to an action.

### Policies

A **Policy** is a named collection of **statements**. Each statement has an **effect** (Allow or Deny), a set of **actions**, and a **resource constraint**:

```
Policy "todo-viewer":
  ALLOW [todo:read:list, todo:list:list, todo:read:item] on *

Policy "todo-admin":
  ALLOW [todo:*:*] on *

Policy "top-secret-deny":
  DENY [todo:*:*] on todo::list::top-secret
    EXCEPT group:top-secret-readers
```

- **Allow** statements grant access to the specified actions on the specified resources.
- **Deny** statements block access. Deny always wins over allow for the same action+resource — this is Cedar's evaluation model.
- Deny statements may include an `except` clause listing groups that are excepted from the deny.
- Policies are reusable documents — they are authored once and **attached** to Groups or Users.

### Groups

A **Group** is a collection of users with policies attached. Groups can also contain other groups, forming a hierarchy.

A user's effective permissions are **additive**: the union of all policies from all groups the user belongs to (including ancestor groups), plus any policies attached directly to the user.

```
Group "admin":
  policies: [todo-admin]

Group "member":
  policies: [todo-viewer, todo-editor]

Group "engineering":
  member_groups: [backend, frontend, devops]
  policies: [infra-viewer]
```

A user in `backend` inherits policies from `backend` + `engineering` — all additive. Cedar resolves transitive group membership natively via its `in` operator on entity hierarchies.

### Users

Users belong to groups and may have policies attached directly. For target-b, group membership comes from two sources:

- **JWT claims** — the `groups_claim` field (default: `cognito:groups`) maps Cognito group membership to ForgeGuard groups.
- **Static API keys** — the `groups` field on each key entry in `forgeguard.toml`.

### Evaluation (Cedar / Verified Permissions)

ForgeGuard does **not** evaluate permissions locally. All authorization decisions go through AWS Verified Permissions (VP), which uses Cedar as its policy language.

ForgeGuard's abstractions compile to Cedar primitives:

| ForgeGuard                                | Cedar                                                          |
| ----------------------------------------- | -------------------------------------------------------------- |
| Policy statement with `effect: allow`     | `permit(...)`                                                  |
| Policy statement with `effect: deny`      | `forbid(...)` with optional `unless` clause                    |
| Policy statement with `except: [group-a]` | `forbid(...) unless { principal in iam::group::"...group-a" }` |
| Group                                     | `iam::group` entity                                            |
| Group in group (nesting)                  | `iam::group` entity with `parents: [iam::group]`               |
| User in group                             | `iam::user` entity with `parents: [iam::group]`                |
| Policy attached to group                  | Cedar `permit`/`forbid` with `principal in iam::group::...`    |
| Project-wide deny policy                  | Cedar `forbid` with unconstrained `principal`                  |

Cedar's evaluation order:

1. If **any** `forbid` matches → **DENY** (explicit deny always wins)
2. If **any** `permit` matches → **ALLOW**
3. If **nothing** matches → **DENY** (default)

A deny policy **always** overrides an allow policy for the same action+resource, unless the deny has an `except` clause that exempts the principal's group.

### Resource-Level Access Control

Action-level RBAC uses `on *` (all resources). For restricting access to specific resources, combine allow and deny policies:

```
Group "all-users":
  policies: [todo-full-access, top-secret-deny]

Group "top-secret-readers":
  policies: [todo-viewer]

Policy "todo-full-access":
  ALLOW [todo:*:*] on *

Policy "top-secret-deny":
  DENY [todo:*:*] on todo::list::top-secret
    EXCEPT group:top-secret-readers
```

Everyone in `all-users` can access all TODO resources. The deny blocks access to `top-secret` — but the `except` clause means users in `top-secret-readers` are not matched by the deny, so their allow policies apply normally.

### Future: Roles (Assume-Role)

Not in target-b scope. A **Role** is a standalone entity with permission policies and **trust policies** (who can assume it — individual users or entire groups). When a user assumes a role, their effective permissions are **replaced** by the role's policies — group and user-level policies are shed. Roles act as a privilege ceiling, not a privilege floor. The architecture accounts for this by keeping the principal in `PolicyQuery` swappable (user or role FGRN).

---

## Binary CLI Convention

Every binary crate in ForgeGuard is exposed as a CLI application using `clap` with the derive API. This convention ensures consistency across `forgeguard_proxy`, `forgeguard_control_plane`, `forgeguard_agent`, `forgeguard_cli`, and `forgeguard_back_office`.

### Structure

```rust
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "forgeguard-proxy", version, about = "ForgeGuard auth-enforcing reverse proxy")]
pub(crate) struct App {
    #[command(subcommand)]
    pub command: Commands,
    #[clap(flatten)]
    pub global: Global,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Global {
    /// Enable verbose logging (debug level)
    #[clap(long, short, env = "FORGEGUARD_VERBOSE", global = true)]
    pub verbose: bool,
}
```

Every service binary has at minimum a `run` subcommand (start the service). Config validation (`check`), config inspection (`config`), and route listing (`routes`) subcommands live in `forgeguard_cli` (cross-platform). Additional utility subcommands are encouraged.

### Configuration Loading Precedence

Binary configuration follows a four-level precedence chain (highest wins):

```
CLI flags  →  env vars  →  config file  →  defaults
```

1. **CLI flags** (`--listen 0.0.0.0:9000`) — highest priority, explicit operator intent
2. **Environment variables** (`FORGEGUARD_LISTEN=0.0.0.0:9000`) — 12-factor, container-friendly
3. **Config file** (`forgeguard.toml`) — structured, version-controllable
4. **Defaults** — sensible out-of-the-box behavior

The config file is loaded first, then env vars override matching fields, then CLI flags override on top. `clap`'s `env` attribute handles the env-var-to-flag mapping. The binary's `run` subcommand merges the layers:

```rust
/// Merge CLI overrides on top of the config file.
/// CLI flags > env vars > config file > defaults.
fn apply_overrides(config: &mut ProxyConfig, opts: &RunOptions) {
    if let Some(listen) = &opts.listen {
        config.listen_addr = *listen;
    }
    if let Some(upstream) = &opts.upstream {
        config.upstream_url = upstream.clone();
    }
    if let Some(policy) = &opts.default_policy {
        config.default_policy = policy.clone();
    }
    // ... other overridable fields
}
```

### Error Handling and Logging

Every binary `main`:

- Returns `color_eyre::Result<()>` — no `.unwrap()` calls (enforced by workspace clippy `deny(clippy::unwrap_used)`)
- Calls `color_eyre::install()?` before anything else
- Initializes `tracing-subscriber` with the `--verbose` / `RUST_LOG` env var for level control

```rust
fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let app = App::parse();
    init_tracing(app.global.verbose);
    // dispatch subcommand...
}
```

### Standard Environment Variables

| Variable                     | Overrides               | Default           |
| ---------------------------- | ----------------------- | ----------------- |
| `FORGEGUARD_CONFIG`          | Config file path        | `forgeguard.toml` |
| `FORGEGUARD_VERBOSE`         | Verbose logging         | `false`           |
| `FORGEGUARD_LISTEN`          | `proxy.listen`          | `0.0.0.0:8000`    |
| `FORGEGUARD_UPSTREAM`        | `proxy.upstream`        | (required)        |
| `FORGEGUARD_DEFAULT_POLICY`  | `proxy.default_policy`  | `passthrough`     |
| `FORGEGUARD_POLICY_STORE_ID` | `authz.policy_store_id` | (required)        |
| `FORGEGUARD_AWS_REGION`      | `authz.aws_region`      | `us-east-1`       |
| `RUST_LOG`                   | Log level filter        | `info`            |

---

## Infrastructure Configuration Convention

Every CDK stack reads its configuration from a `.env` file at the infrastructure root (`infra/dev/.env`). This file is **never tracked by git** — it contains account-specific values (AWS account ID, region, naming prefixes) that vary per developer.

### Rules

1. **`.env`** — lives at `infra/dev/.env`, listed in `.gitignore`. Contains all CDK stack inputs.
2. **`.env.example`** — lives at `infra/dev/.env.example`, committed to git. Documents every variable the `.env` file expects, with sensible defaults or placeholder values. This is the canonical schema for infrastructure configuration.
3. **CDK stacks** — read all configurable values from `process.env`, populated by dotenv loading of `infra/dev/.env`. No hardcoded account IDs, regions, or resource names in stack code.
4. **`.gitignore`** — add `.env` (but not `.env.example`) to the repo root `.gitignore`:
   ```gitignore
   # Infrastructure secrets — never commit
   .env
   !.env.example
   ```
5. **`xtask dev-setup`** — on first run, if `infra/dev/.env` does not exist, copies `.env.example` → `.env` and prompts the developer to fill in account-specific values before proceeding.

### `.env.example` shape (minimum)

```env
# AWS account and region for CDK deployment
AWS_ACCOUNT_ID=123456789012
AWS_REGION=us-east-1

# Naming prefix to avoid resource collisions between developers
FORGEGUARD_DEV_PREFIX=forgeguard-dev

# Cognito (populated after xtask dev-setup --cognito)
COGNITO_USER_POOL_ID=
COGNITO_APP_CLIENT_ID=
COGNITO_JWKS_URL=
COGNITO_ISSUER=

# Verified Permissions (populated after xtask dev-setup --vp)
VP_POLICY_STORE_ID=
```

### Flow

```
.env.example  ──(copy on first run)──►  .env  ──(dotenv)──►  CDK stack
                                          │
                                          └──(xtask writes outputs)──►  forgeguard.dev.toml
```

CDK stack _outputs_ (pool IDs, JWKS URLs, policy store IDs) are written back to both `.env` (for subsequent CDK stacks that depend on them) and `forgeguard.dev.toml` (for the Rust binary at runtime).

---

## Issue #1: `forgeguard_core` — Shared primitives and config types

**Crate:** `crates/core/` (pure, no I/O)
**Labels:** `core`, `pure`, `layer-1`
**Blocked by:** nothing
**Unblocks:** #2, #3, #4, #5, #6, #7, #10

### Description

Define the foundational types that every other crate depends on. These are the typed IDs, error infrastructure, permission model types (Policy, Group, Effect), feature flag types and evaluation, and `ResolvedFlags`.

This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`.

### Acceptance Criteria

**ForgeGuard Resource Name (FGRN)** — the universal addressing scheme for every entity, modeled after AWS ARNs but organized by **namespace** (the customer's domain) rather than service (ForgeGuard's internals).

All concrete segments use `Segment` — a validated kebab-case identifier that survives every environment ForgeGuard touches without translation: URIs, Cedar entity IDs, S3 keys, HTTP headers, CloudWatch dimensions, structured logs. No case-sensitivity issues, no encoding needed.

```rust
/// A validated identifier segment.
///
/// Rules:
/// - Lowercase ASCII letters, digits, and hyphens only (a-z, 0-9, -)
/// - Must start with a lowercase letter or digit
/// - Must not end with a hyphen
/// - No consecutive hyphens (reserved, Punycode-style)
/// - Non-empty, no upper length limit
/// - Guaranteed visible ASCII only — no control chars, no whitespace, no
///   high bytes. This means any Segment value is safe to use directly as
///   an HTTP header value without encoding or escaping.
///
/// This format survives every environment without translation:
/// URIs, Cedar entity IDs, S3 keys, HTTP headers, CloudWatch dimensions,
/// DNS labels (RFC 1123 allows digit-first), structured logs, TOML values, JSON keys.
/// UUIDs are valid Segments: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".
///
/// Examples: "acme-corp", "todo-app", "list", "item-abc123", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
/// Invalid: "AcmeCorp", "my_project", "-leading", "trailing-", "no--double", "", "\x00hidden"
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Segment(String);

impl Segment {
    pub fn try_new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();

        if s.is_empty() {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "cannot be empty",
            });
        }
        if !s.as_bytes()[0].is_ascii_lowercase() && !s.as_bytes()[0].is_ascii_digit() {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "must start with a lowercase letter or digit",
            });
        }
        if s.ends_with('-') {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "must not end with a hyphen",
            });
        }
        if s.contains("--") {
            return Err(Error::Parse {
                field: "segment", value: s, reason: "consecutive hyphens are not allowed",
            });
        }
        if !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(Error::Parse {
                field: "segment", value: s,
                reason: "must contain only lowercase letters, digits, and hyphens",
            });
        }

        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// ForgeGuard Resource Name — a structured, validated identifier for any
/// entity in the ForgeGuard system.
///
/// Format: fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>
///
/// Six positions, always. Use `*` for wildcards, `-` for not-applicable.
/// All concrete segments are validated `Segment` values (lowercase, hyphens).
/// The `-` is a serialization convention for absent fields (Option::None),
/// NOT a valid Segment value.
///
/// Customer domain resources:
///   fgrn:acme-app:acme-corp:todo:list:list-001
///   fgrn:acme-app:acme-corp:todo:item:item-042
///   fgrn:acme-app:acme-corp:billing:invoice:inv-789
///   fgrn:acme-app:*:todo:list:*                    ← all lists, all tenants
///   fgrn:acme-app:acme-corp:todo:*:*               ← all todo resources in tenant
///
/// Identity resources (reserved "iam" namespace):
///   fgrn:acme-app:acme-corp:iam:user:alice
///   fgrn:acme-app:acme-corp:iam:group:admin
///   fgrn:acme-app:acme-corp:iam:user:*             ← all users in tenant
///
/// System resources (reserved "forgeguard" namespace):
///   fgrn:acme-app:-:forgeguard:policy:pol-001       ← tenant is None (not tenant-scoped)
///   fgrn:acme-app:-:forgeguard:feature-flag:ai-suggestions
///   fgrn:acme-app:-:forgeguard:webhook:wh-001
///   fgrn:-:-:forgeguard:project:acme-app             ← project and tenant both None (back office)
///
/// Used as:
///   - Cedar/Verified Permissions entity IDs (single identifier everywhere — no mapping)
///   - Audit log entity references
///   - API resource identifiers
///   - Webhook event payloads
///   - Event log references
///
/// Parse Don't Validate: if you hold a Fgrn, every segment is guaranteed valid.
///
/// Design note: `-` in the string form is a serialization convention for absent
/// fields (None at the type level). It is NOT a valid Segment — Segment stays
/// strict (must start with a letter, no lone hyphens). The "not applicable"
/// semantics live in the Fgrn type's parse/display logic, not in Segment.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Fgrn {
    project: Option<FgrnSegment>,   // None for platform-level resources (back office)
    tenant: Option<FgrnSegment>,    // None for non-tenant-scoped resources
    namespace: FgrnSegment,         // always present
    resource_type: FgrnSegment,     // always present
    resource_id: FgrnSegment,       // always present
    raw: String,                    // cached canonical form for Display + Verified Permissions entity ID
}

/// A single concrete-or-wildcard segment in an FGRN.
/// Either a validated Segment or a wildcard (*).
///
/// "Not applicable" is NOT a variant here — it's represented as
/// Option<FgrnSegment>::None at the Fgrn field level. The `-` character
/// only appears during serialization/deserialization of the FGRN string.
/// This keeps Segment's validation rules strict and uncompromised.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum FgrnSegment {
    Value(Segment),
    Wildcard,
}

/// Reserved namespaces — customers cannot use these.
const RESERVED_NS_IAM: &str = "iam";
const RESERVED_NS_FORGEGUARD: &str = "forgeguard";

/// Pre-validated constant segments for known-good FGRN components.
/// Avoids `expect()` (denied by workspace clippy) in builder methods.
/// Validated once at first access via `std::sync::LazyLock` (stable since Rust 1.80).
mod known_segments {
    use super::*;
    use std::sync::LazyLock;

    pub static IAM: LazyLock<Segment> = LazyLock::new(|| Segment::try_new("iam").unwrap_or_else(|_| unreachable!()));
    pub static FORGEGUARD: LazyLock<Segment> = LazyLock::new(|| Segment::try_new("forgeguard").unwrap_or_else(|_| unreachable!()));
    pub static USER: LazyLock<Segment> = LazyLock::new(|| Segment::try_new("user").unwrap_or_else(|_| unreachable!()));
    pub static GROUP: LazyLock<Segment> = LazyLock::new(|| Segment::try_new("group").unwrap_or_else(|_| unreachable!()));
    pub static POLICY: LazyLock<Segment> = LazyLock::new(|| Segment::try_new("policy").unwrap_or_else(|_| unreachable!()));
}

impl Fgrn {
    /// Parse from canonical string form.
    /// `-` is deserialized as None (absent), not as a Segment value.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        match parts.as_slice() {
            ["fgrn", project, tenant, namespace, rtype, rid] => {
                Ok(Self {
                    project: parse_optional_segment(project)?,
                    tenant: parse_optional_segment(tenant)?,
                    namespace: FgrnSegment::parse(namespace)?,
                    resource_type: FgrnSegment::parse(rtype)?,
                    resource_id: FgrnSegment::parse(rid)?,
                    raw: s.to_string(),
                })
            }
            _ => Err(Error::Parse {
                field: "fgrn",
                value: s.to_string(),
                reason: "expected fgrn:<project>:<tenant>:<namespace>:<resource-type>:<resource-id>",
            }),
        }
    }

    /// Construct from validated parts. Builds canonical string once.
    pub fn new(
        project: Option<FgrnSegment>,
        tenant: Option<FgrnSegment>,
        namespace: FgrnSegment,
        resource_type: FgrnSegment,
        resource_id: FgrnSegment,
    ) -> Self {
        let raw = format!(
            "fgrn:{}:{}:{}:{}:{}",
            optional_segment_str(&project),
            optional_segment_str(&tenant),
            namespace.as_str(),
            resource_type.as_str(),
            resource_id.as_str(),
        );
        Self { project, tenant, namespace, resource_type, resource_id, raw }
    }

    /// Builder helpers for common FGRN patterns.
    /// Use pre-validated `known_segments` for constant components (iam, user, group, etc.)
    /// and `as_segment()` for typed IDs (which are already validated Segments).
    pub fn user(project: &ProjectId, tenant: &TenantId, user_id: &UserId) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            Some(FgrnSegment::from_segment(tenant.as_segment())),
            FgrnSegment::from_segment(&known_segments::IAM),
            FgrnSegment::from_segment(&known_segments::USER),
            FgrnSegment::from_segment(user_id.as_segment()),
        )
    }

    pub fn group(project: &ProjectId, tenant: &TenantId, group_name: &GroupName) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            Some(FgrnSegment::from_segment(tenant.as_segment())),
            FgrnSegment::from_segment(&known_segments::IAM),
            FgrnSegment::from_segment(&known_segments::GROUP),
            FgrnSegment::from_segment(group_name.as_segment()),
        )
    }

    pub fn policy(project: &ProjectId, policy_name: &PolicyName) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            None,  // policies are not tenant-scoped
            FgrnSegment::from_segment(&known_segments::FORGEGUARD),
            FgrnSegment::from_segment(&known_segments::POLICY),
            FgrnSegment::from_segment(policy_name.as_segment()),
        )
    }

    pub fn resource(
        project: &ProjectId, tenant: &TenantId,
        namespace: &Namespace, entity: &Entity, id: &ResourceId,
    ) -> Self {
        Self::new(
            Some(FgrnSegment::from_segment(project.as_segment())),
            Some(FgrnSegment::from_segment(tenant.as_segment())),
            FgrnSegment::from_segment(namespace.as_segment()),
            FgrnSegment::from_segment(entity.as_segment()),
            FgrnSegment::from_segment(id.as_segment()),
        )
    }

    /// Cedar entity type: "{namespace}::{resource_type}" e.g., "todo::list"
    pub fn cedar_entity_type(&self) -> Option<String> {
        match (&self.namespace, &self.resource_type) {
            (FgrnSegment::Value(ns), FgrnSegment::Value(rt)) => {
                Some(format!("{ns}::{rt}"))
            }
            _ => None,
        }
    }

    /// This string is used directly as the Verified Permissions entity ID.
    /// Single identifier everywhere — no mapping at any boundary.
    pub fn as_vp_entity_id(&self) -> &str {
        &self.raw
    }

    /// Does this FGRN match another (potentially wildcarded) FGRN?
    pub fn matches(&self, pattern: &Fgrn) -> bool {
        optional_matches(&self.project, &pattern.project)
            && optional_matches(&self.tenant, &pattern.tenant)
            && self.namespace.matches(&pattern.namespace)
            && self.resource_type.matches(&pattern.resource_type)
            && self.resource_id.matches(&pattern.resource_id)
    }

    pub fn project(&self) -> Option<&FgrnSegment> { self.project.as_ref() }
    pub fn tenant(&self) -> Option<&FgrnSegment> { self.tenant.as_ref() }
    pub fn namespace(&self) -> &FgrnSegment { &self.namespace }
    pub fn resource_type(&self) -> &FgrnSegment { &self.resource_type }
    pub fn resource_id(&self) -> &FgrnSegment { &self.resource_id }
}

impl FgrnSegment {
    /// Parse a required FGRN segment (must be a value or wildcard, not `-`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "*" => Ok(Self::Wildcard),
            _ => Ok(Self::Value(Segment::try_new(s)?)),
        }
    }

    /// Wrap a pre-validated Segment as a concrete FgrnSegment.
    fn from_segment(seg: &Segment) -> Self {
        Self::Value(seg.clone())
    }

    pub fn matches(&self, pattern: &FgrnSegment) -> bool {
        match pattern {
            FgrnSegment::Wildcard => true,
            FgrnSegment::Value(v) => matches!(self, FgrnSegment::Value(sv) if sv == v),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Value(v) => v.as_str(),
            Self::Wildcard => "*",
        }
    }
}

/// Parse an optional FGRN segment: `-` becomes None, everything else is parsed.
fn parse_optional_segment(s: &str) -> Result<Option<FgrnSegment>> {
    match s {
        "-" => Ok(None),
        _ => Ok(Some(FgrnSegment::parse(s)?)),
    }
}

/// Serialize an optional segment: None becomes `-`.
fn optional_segment_str(seg: &Option<FgrnSegment>) -> &str {
    match seg {
        Some(s) => s.as_str(),
        None => "-",
    }
}

/// Match logic for optional segments:
/// - None pattern matches only None values (both are "not applicable")
/// - Some(Wildcard) matches anything including None
/// - Some(Value) matches only the same value
fn optional_matches(value: &Option<FgrnSegment>, pattern: &Option<FgrnSegment>) -> bool {
    match (pattern, value) {
        (None, None) => true,                // both not-applicable
        (None, Some(_)) => false,            // pattern says absent, value is present
        (Some(FgrnSegment::Wildcard), _) => true, // wildcard matches anything
        (Some(_), None) => false,            // pattern expects value, but absent
        (Some(p), Some(v)) => v.matches(p),  // both present, delegate to FgrnSegment
    }
}

impl fmt::Display for Fgrn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for Fgrn {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> { Self::parse(s) }
}

/// Serialize as canonical string, deserialize via parse.
impl Serialize for Fgrn { /* serialize_str(&self.raw) */ }
impl<'de> Deserialize<'de> for Fgrn { /* parse from string */ }
```

<!-- TODO: create spike-fgrn-design.md with full design rationale, Cedar mapping, and how FGRNs flow through the proxy, Verified Permissions, audit log, webhooks, and dashboard. -->

**Typed IDs** — newtype wrappers built on `Segment`, with `Display`, `FromStr`, `Serialize`, `Deserialize`, `Clone`, `Eq`, `Hash`:

```rust
// Internal define_id! macro generates newtype over Segment + Display, FromStr,
// Serialize, Deserialize, Clone, Eq, Hash, and a validating constructor.
// Defined once in this crate, used for all ID types. No external crate dependency.
define_id!(UserId);               // kebab-case Segment, no prefix — "alice", "bob-smith"
define_id!(TenantId);             // kebab-case Segment, no prefix — "acme-corp", "initech"
define_id!(ProjectId);            // kebab-case Segment, no prefix — "acme-app", "my-project"
define_id!(GroupName);            // no prefix — "admin", "backend-team", "top-secret-readers"
define_id!(PolicyName);           // no prefix — "todo-viewer", "todo-admin", "top-secret-deny"

pub struct FlowId(Uuid);          // FlowId uses Uuid, not Segment
```

- Constructor delegates to `Segment::try_new` — same kebab-case validation for all IDs
- `UserId::new("alice")` succeeds, `UserId::new("bob-smith")` succeeds, `UserId::new("Alice")` returns `Err` (uppercase), `UserId::new("user_abc")` returns `Err` (underscore), `UserId::new("")` returns `Err`
- All IDs are `pub(crate)` inner field, exposed via `.as_str()` / `.as_segment()`

**Action vocabulary types** — the core modeling for `namespace:action:entity`:

ForgeGuard actions follow the pattern `namespace:action:entity` (e.g., `todo:read:list`, `billing:refund:invoice`). This mirrors AWS IAM's `service:VerbNoun` (e.g., `s3:GetObject`), but with three explicit segments instead of two. The third segment eliminates parsing ambiguity — no guessing where the verb ends and the resource begins.

All three segments are validated `Segment` values (kebab-case). If you hold a `QualifiedAction`, every component is guaranteed valid. No downstream code ever re-validates.

```rust
/// A namespace within a project. Groups related resources and actions.
/// The customer's domain organizing principle.
///
/// Reserved namespaces:
///   "iam"       — user, group, role entities (identity primitives)
///   "forgeguard" — policy, feature-flag, webhook entities (system internals)
///
/// Customer namespaces must be valid Segment values and cannot use reserved names.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Namespace(NamespaceInner);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum NamespaceInner {
    User(Segment),
    Reserved(Segment),
}

const RESERVED_NAMESPACES: &[&str] = &["iam", "forgeguard"];

impl Namespace {
    /// Parse a user-provided namespace. Rejects reserved names.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if RESERVED_NAMESPACES.contains(&s.as_str()) {
            return Err(Error::Parse {
                field: "namespace",
                value: s,
                reason: "reserved namespace — 'iam' and 'forgeguard' cannot be used by customers",
            });
        }
        Ok(Self(NamespaceInner::User(Segment::try_new(s)?)))
    }

    /// The iam namespace where user and group entities live.
    pub fn iam() -> Self {
        Self(NamespaceInner::Reserved(known_segments::IAM.clone()))
    }

    /// The forgeguard namespace where policy, feature-flag, webhook entities live.
    pub fn forgeguard() -> Self {
        Self(NamespaceInner::Reserved(known_segments::FORGEGUARD.clone()))
    }

    pub fn as_segment(&self) -> &Segment {
        match &self.0 {
            NamespaceInner::User(seg) | NamespaceInner::Reserved(seg) => seg,
        }
    }

    pub fn is_reserved(&self) -> bool {
        matches!(self.0, NamespaceInner::Reserved(_))
    }

    pub fn as_str(&self) -> &str {
        match &self.0 {
            NamespaceInner::User(seg) => seg.as_str(),
            NamespaceInner::Reserved(seg) => seg.as_str(),
        }
    }
}

/// An action verb. Kebab-case — any verb the developer wants.
/// e.g., "read", "create", "force-delete", "bulk-export", "countersign"
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Action(Segment);

impl Action {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }
    pub fn as_str(&self) -> &str { self.0.as_str() }
    pub fn as_segment(&self) -> &Segment { &self.0 }
}

/// A resource/entity type. Kebab-case.
/// e.g., "invoice", "payment-tracker", "shipping-label"
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Entity(Segment);

impl Entity {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }
    pub fn as_str(&self) -> &str { self.0.as_str() }
    pub fn as_segment(&self) -> &Segment { &self.0 }

    /// Cedar entity type: "billing::invoice"
    pub fn cedar_entity_type(&self, ns: &Namespace) -> String {
        format!("{}::{}", ns.as_str(), self.as_str())
    }
}

/// A fully qualified action: namespace:action:entity
///
/// ForgeGuard:     "todo:read:list"
/// AWS analog:    "s3:GetObject"
/// Cedar maps:    namespace=todo, action="read-list", entity=todo::list
///
/// Three explicit segments — no parsing heuristics to split verb from entity.
/// If you hold a QualifiedAction, every component is guaranteed valid.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct QualifiedAction {
    namespace: Namespace,
    action: Action,
    entity: Entity,
}

impl QualifiedAction {
    /// Construct from already-parsed parts. No validation — types carry the proof.
    pub fn new(namespace: Namespace, action: Action, entity: Entity) -> Self {
        Self { namespace, action, entity }
    }

    /// Parse from the canonical format: "todo:read:list"
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        match parts.as_slice() {
            [ns, action, entity] => Ok(Self {
                namespace: Namespace::parse(*ns)?,
                action: Action::parse(*action)?,
                entity: Entity::parse(*entity)?,
            }),
            _ => Err(Error::Parse {
                field: "qualified_action",
                value: s.to_string(),
                reason: "expected namespace:action:entity (e.g., 'todo:read:list')",
            }),
        }
    }

    pub fn namespace(&self) -> &Namespace { &self.namespace }
    pub fn action(&self) -> &Action { &self.action }
    pub fn entity(&self) -> &Entity { &self.entity }

    /// Verified Permissions `IsAuthorized`: actionType — "todo::action"
    pub fn vp_action_type(&self) -> String {
        format!("{}::action", self.namespace.as_str())
    }

    /// Verified Permissions `IsAuthorized`: actionId — "read-list" (action + entity, hyphen-joined)
    pub fn vp_action_id(&self) -> String {
        format!("{}-{}", self.action.as_str(), self.entity.as_str())
    }

    /// Cedar action reference: todo::action::"read-list"
    pub fn cedar_action_ref(&self) -> String {
        format!("{}::action::\"{}\"", self.namespace.as_str(), self.vp_action_id())
    }

    /// Cedar entity type for the resource: todo::list
    pub fn cedar_entity_type(&self) -> String {
        self.entity.cedar_entity_type(&self.namespace)
    }
}

/// Serde: serializes as "todo:read:list", deserializes via parse.
impl Serialize for QualifiedAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for QualifiedAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A validated, non-empty resource ID. Built on Segment (kebab-case).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ResourceId(Segment);

impl ResourceId {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        Ok(Self(Segment::try_new(s)?))
    }
    pub fn as_str(&self) -> &str { self.0.as_str() }
    pub fn as_segment(&self) -> &Segment { &self.0 }
}

/// A concrete resource instance for authorization checks.
/// Constructed from a QualifiedAction (namespace + entity) + extracted path param.
pub struct ResourceRef {
    namespace: Namespace,
    entity: Entity,
    id: ResourceId,
}

impl ResourceRef {
    /// Construct from a matched route's action + extracted resource ID.
    /// No validation needed — QualifiedAction and ResourceId carry the proof.
    pub fn from_route(action: &QualifiedAction, id: ResourceId) -> Self {
        Self {
            namespace: action.namespace().clone(),
            entity: action.entity().clone(),
            id,
        }
    }

    /// Verified Permissions entity type: "todo::list"
    pub fn vp_entity_type(&self) -> String {
        self.entity.cedar_entity_type(&self.namespace)
    }

    /// Build the FGRN for this resource. Used as the Verified Permissions entity ID.
    /// Requires tenant because FGRNs include the tenant segment.
    pub fn to_fgrn(&self, project: &ProjectId, tenant: &TenantId) -> Fgrn {
        Fgrn::resource(project, tenant, &self.namespace, &self.entity, self.id.as_str())
    }
}

/// Principal reference — always in the iam::user entity type.
pub struct PrincipalRef {
    user_id: UserId,
}

impl PrincipalRef {
    pub fn new(user_id: UserId) -> Self { Self { user_id } }

    /// Verified Permissions entity type for principals.
    pub fn vp_entity_type() -> &'static str {
        "iam::user"
    }

    /// Build the FGRN for this principal. Used as the Verified Permissions entity ID.
    /// Requires tenant because FGRNs include the tenant segment.
    pub fn to_fgrn(&self, project: &ProjectId, tenant: &TenantId) -> Fgrn {
        Fgrn::user(project, tenant, &self.user_id)
    }
}
```

**Permission model types** — Policies, Groups, and their Cedar compilation (pure, no I/O):

```rust
/// The effect of a policy statement.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// A pattern segment that matches either a specific value or any value (wildcard).
/// Used in action patterns within policy statements.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum PatternSegment {
    Exact(Segment),
    Wildcard,
}

impl PatternSegment {
    pub fn matches(&self, segment: &Segment) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Exact(s) => s == segment,
        }
    }
}

/// An action pattern used in policy statements. Supports wildcards in any position.
///
/// "todo:read:list"  → exact match on one action
/// "todo:read:*"     → all read actions in the todo namespace
/// "todo:*:*"        → all actions in the todo namespace
/// "*:*:*"           → all actions (god mode)
///
/// Parsed from strings like "todo:read:list" or "todo:*:*".
/// Wildcards in ForgeGuard are expanded to explicit Cedar action lists at compile time,
/// or to unconstrained `action` in the Cedar statement when namespace:*:* is used.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ActionPattern {
    namespace: PatternSegment,
    action: PatternSegment,
    entity: PatternSegment,
}

impl ActionPattern {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        match parts.as_slice() {
            [ns, action, entity] => Ok(Self {
                namespace: parse_pattern_segment(ns)?,
                action: parse_pattern_segment(action)?,
                entity: parse_pattern_segment(entity)?,
            }),
            _ => Err(Error::Parse {
                field: "action_pattern",
                value: s.to_string(),
                reason: "expected namespace:action:entity (e.g., 'todo:read:list' or 'todo:*:*')",
            }),
        }
    }

    /// Does this pattern match a specific qualified action?
    pub fn matches(&self, action: &QualifiedAction) -> bool {
        self.namespace.matches(action.namespace().as_segment())
            && self.action.matches(action.action().as_segment())
            && self.entity.matches(action.entity().as_segment())
    }
}

fn parse_pattern_segment(s: &str) -> Result<PatternSegment> {
    match s {
        "*" => Ok(PatternSegment::Wildcard),
        _ => Ok(PatternSegment::Exact(Segment::try_new(s)?)),
    }
}

/// A validated Cedar entity reference: "namespace::entity::id".
/// Parse Don't Validate — if you hold a CedarEntityRef, all three segments
/// are guaranteed valid kebab-case.
///
/// Examples: "todo::list::top-secret", "billing::invoice::inv-789"
/// Invalid: "Todo::List::TopSecret", "todo::list" (missing id), ""
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CedarEntityRef {
    namespace: Segment,
    entity: Segment,
    id: Segment,
}

impl CedarEntityRef {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, "::").collect();
        match parts.as_slice() {
            [ns, entity, id] => Ok(Self {
                namespace: Segment::try_new(*ns)?,
                entity: Segment::try_new(*entity)?,
                id: Segment::try_new(*id)?,
            }),
            _ => Err(Error::Parse {
                field: "cedar_entity_ref",
                value: s.to_string(),
                reason: "expected namespace::entity::id (e.g., 'todo::list::top-secret')",
            }),
        }
    }

    pub fn namespace(&self) -> &Segment { &self.namespace }
    pub fn entity(&self) -> &Segment { &self.entity }
    pub fn id(&self) -> &Segment { &self.id }

    /// Cedar string form: "todo::list::top-secret"
    pub fn as_cedar_str(&self) -> String {
        format!("{}::{}::{}", self.namespace, self.entity, self.id)
    }
}

impl fmt::Display for CedarEntityRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.namespace, self.entity, self.id)
    }
}

/// Serde: deserialize from "todo::list::top-secret" via parse.
impl<'de> Deserialize<'de> for CedarEntityRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Resource constraint in a policy statement.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ResourceConstraint {
    /// All resources — default when omitted.
    All,
    /// Specific resources identified by validated Cedar entity references.
    Specific(Vec<CedarEntityRef>),
}

impl Default for ResourceConstraint {
    fn default() -> Self { Self::All }
}

/// A single statement within a policy.
///
/// Compiles to a Cedar `permit` (effect=Allow) or `forbid` (effect=Deny).
/// The `except` field maps to Cedar's `unless` clause on forbid statements.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyStatement {
    pub effect: Effect,
    pub actions: Vec<ActionPattern>,
    #[serde(default)]
    pub resources: ResourceConstraint,
    /// Groups excepted from this deny statement.
    /// Only meaningful when effect is Deny — ignored for Allow.
    /// Compiles to Cedar: `forbid(...) unless { principal in iam::group::"..." }`
    #[serde(default)]
    pub except: Vec<GroupName>,
}

/// A named, reusable policy — a collection of allow/deny statements.
///
/// Policies are authored in `forgeguard.toml` and compiled to Cedar permit/forbid
/// statements. They are attached to Groups (or Users) to grant/restrict access.
///
/// FGRN: fgrn:<project>:-:forgeguard:policy:<policy-name>
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub name: PolicyName,
    #[serde(default)]
    pub description: Option<String>,
    pub statements: Vec<PolicyStatement>,
}

/// A group definition — a collection of users and/or other groups with policies attached.
///
/// Groups can nest: a group may contain other groups via `member_groups`.
/// Cedar resolves transitive membership natively via entity parent edges.
///
/// FGRN: fgrn:<project>:<tenant>:iam:group:<group-name>
#[derive(Debug, Clone, Deserialize)]
pub struct GroupDefinition {
    pub name: GroupName,
    #[serde(default)]
    pub description: Option<String>,
    /// Policies attached to this group.
    pub policies: Vec<PolicyName>,
    /// Child groups whose members inherit this group's policies.
    #[serde(default)]
    pub member_groups: Vec<GroupName>,
}
```

**Cedar compilation** — pure functions that compile ForgeGuard policy/group definitions to Cedar `permit`/`forbid` statements. Used by `forgeguard policies sync` to push policies to Verified Permissions.

```rust
/// Compile a Policy + its group attachment into Cedar permit/forbid statements.
/// Pure function — no I/O, no VP client. Output is a Vec of Cedar policy strings.
pub fn compile_policy_to_cedar(
    policy: &Policy,
    attached_to_group: &GroupName,
    project: &ProjectId,
    tenant: &TenantId,
) -> Vec<String>;

/// Compile all policies and groups from config into a complete Cedar policy set.
pub fn compile_all_to_cedar(
    policies: &HashMap<PolicyName, Policy>,
    groups: &HashMap<GroupName, GroupDefinition>,
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<Vec<String>>;
```

- `compile_policy_to_cedar` maps `Effect::Allow` → `permit(...)`, `Effect::Deny` → `forbid(...)` with `unless` for `except` groups
- `ActionPattern` wildcards expand to explicit Cedar action lists or unconstrained `action`
- `ResourceConstraint::Specific` entries map to Cedar `resource ==` clauses using `CedarEntityRef::as_cedar_str()`
- Group attachments produce `principal in iam::group::"fgrn:..."` using FGRN builders
- `compile_all_to_cedar` validates that all policy references in groups exist, detects circular group nesting

**Error infrastructure:**

```rust
// Pattern: each crate has Error + Result<T>
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid {field}: '{value}' — {reason}")]
    Parse {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    #[error("configuration error: {0}")]
    Config(String),
    #[error("unknown feature flag type: {0}")]
    InvalidFlagType(String),
}
```

**Feature flag types and evaluation** (pure — no I/O, WASM-compatible):

```rust
/// A feature flag name. Either project-wide or namespace-scoped.
/// Kebab-case enforced — same Segment validation as everything else.
///
/// "maintenance-mode"         → global, project-wide
/// "todo:ai-suggestions"      → scoped to todo namespace
///
/// Parsed at the TOML boundary. If you hold a FlagName, it's valid.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum FlagName {
    /// Project-wide flag. Kebab-case, no namespace.
    Global(Segment),
    /// Namespace-scoped flag. namespace:name.
    Scoped { namespace: Namespace, name: Segment },
}

impl FlagName {
    pub fn parse(s: &str) -> Result<Self> {
        if let Some((ns, name)) = s.split_once(':') {
            Ok(Self::Scoped {
                namespace: Namespace::parse(ns)?,
                name: Segment::try_new(name)?,
            })
        } else {
            Ok(Self::Global(Segment::try_new(s)?))
        }
    }

    /// Check if this flag is in a specific namespace.
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
            Self::Global(name) => write!(f, "{}", name),
            Self::Scoped { namespace, name } => write!(f, "{}:{}", namespace, name),
        }
    }
}

impl Serialize for FlagName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FlagName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A resolved feature flag value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum FlagValue {
    Bool(bool),
    String(String),
    Number(f64),
}

/// All flags resolved for a specific request context.
/// Keys are the canonical FlagName display form: "maintenance-mode" or "todo:ai-suggestions".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolvedFlags {
    flags: HashMap<String, FlagValue>,
}

impl ResolvedFlags {
    pub fn enabled(&self, flag: &str) -> bool {
        matches!(self.flags.get(flag), Some(FlagValue::Bool(true)))
    }

    pub fn get(&self, flag: &str) -> Option<&FlagValue> {
        self.flags.get(flag)
    }

    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }
}

/// Definition of a single feature flag (from config).
#[derive(Debug, Clone, Deserialize)]
pub struct FlagDefinition {
    #[serde(rename = "type")]
    pub flag_type: FlagType,
    pub default: FlagValue,
    /// Kill switch — when false, evaluation short-circuits to default.
    /// Ignores all overrides and rollout.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub overrides: Vec<FlagOverride>,  // sorted by specificity at parse time
    pub rollout_percentage: Option<u8>,
    /// For non-boolean rollouts (A/B string variants). If absent, boolean
    /// rollout defaults to `true`. Must match the declared flag type.
    pub rollout_variant: Option<FlagValue>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagType {
    Boolean,
    String,
    Number,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlagOverride {
    pub tenant: Option<TenantId>,
    pub user: Option<UserId>,
    pub value: FlagValue,
}

/// All flag definitions loaded from config.
/// Keys are FlagName — parsed and validated at config load time.
/// Overrides are pre-sorted by specificity: user+tenant (3) > user (2) > tenant (1).
#[derive(Debug, Clone, Default)]
pub struct FlagConfig {
    pub flags: HashMap<FlagName, FlagDefinition>,
}
```

**Flag evaluation — pure function, deterministic, no I/O:**

```rust
/// Evaluate all flags for a given identity context.
/// Pure function — same inputs always produce same outputs.
/// Must produce identical results across all SDK languages (conformance-tested).
pub fn evaluate_flags(
    config: &FlagConfig,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
) -> ResolvedFlags {
    let mut flags = HashMap::new();
    for (name, def) in &config.flags {
        let display_name = name.to_string(); // "maintenance-mode" or "todo:ai-suggestions"
        flags.insert(display_name.clone(), resolve_single_flag(&display_name, def, tenant_id, user_id));
    }
    ResolvedFlags { flags }
}

fn resolve_single_flag(
    name: &FlagName,
    flag: &FlagDefinition,
    tenant_id: Option<&TenantId>,
    user_id: &UserId,
) -> FlagValue {
    // 0. Kill switch — short-circuit to default
    if !flag.enabled { return flag.default.clone(); }

    // 1. Check overrides (pre-sorted by specificity: user+tenant > user > tenant)
    for ov in &flag.overrides {
        let user_matches = ov.user.as_ref().map_or(true, |u| u == user_id);
        let tenant_matches = match (&ov.tenant, tenant_id) {
            (Some(t), Some(tid)) => t == tid,
            (Some(_), None) => false,
            (None, _) => true,
        };
        if user_matches && tenant_matches {
            return ov.value.clone();
        }
    }

    // 2. Check percentage rollout
    if let Some(pct) = flag.rollout_percentage {
        let name_str = name.to_string();
        let bucket = deterministic_bucket(&name_str, tenant_id, user_id);
        if bucket < pct {
            return flag.rollout_variant.clone()
                .unwrap_or(FlagValue::Bool(true));
        }
    }

    // 3. Default
    flag.default.clone()
}

/// Deterministic hash → 0..99 bucket.
/// Uses a stable, portable hash (NOT std HashMap hasher).
/// This function is part of the conformance test suite —
/// every SDK language must produce the same bucket for the same inputs.
fn deterministic_bucket(
    flag: &str,
    tenant: Option<&TenantId>,
    user: &UserId,
) -> u8 {
    use std::hash::Hasher;
    let mut hasher = XxHash64::with_seed(0);
    hasher.write(flag.as_bytes());
    hasher.write_u8(0xFF); // separator
    if let Some(t) = tenant {
        hasher.write(t.as_str().as_bytes());
    }
    hasher.write_u8(0xFF); // separator
    hasher.write(user.as_str().as_bytes());
    (hasher.finish() % 100) as u8
}
```

**Tests:**

- ID validation: valid formats accepted, empty/malformed rejected
- `Segment::try_new`: lowercase accepted, digit-first accepted (UUIDs valid), uppercase rejected, underscores rejected, empty rejected, leading hyphen rejected, trailing hyphen rejected, consecutive hyphens rejected, non-visible ASCII rejected (`"\x00hidden"`, `"tab\there"`, `"space here"`)
- `Segment::try_new("a1b2c3d4-e5f6-7890-abcd-ef1234567890")` → succeeds (UUID is valid)
- `Namespace::parse`: kebab-case accepted, `"iam"` rejected (reserved), `"forgeguard"` rejected (reserved), empty rejected, uppercase rejected
- `Namespace::iam()`: returns `iam`, `is_reserved()` is true
- `Action::parse`: `"read"`, `"force-delete"`, `"bulk-export"` all valid; `"Read"`, `""`, `"force_delete"` rejected
- `Entity::parse`: `"invoice"`, `"payment-tracker"`, `"shipping-label"` all valid; `"Invoice"` rejected
- `QualifiedAction::parse("todo:read:list")` → namespace=todo, action=read, entity=list
- `QualifiedAction::parse("billing:force-delete:payment-tracker")` → all three correct
- `QualifiedAction::parse("s3:get-object")` → error (only two segments)
- `QualifiedAction::parse("Todo:Read:List")` → error (uppercase)
- `QualifiedAction::parse("")` → error
- `QualifiedAction::vp_action_type()` → `"todo::action"`
- `QualifiedAction::vp_action_id()` → `"read-list"` (action-entity hyphen-joined)
- `QualifiedAction::cedar_action_ref()` → `"todo::action::\"read-list\""`
- `QualifiedAction::cedar_entity_type()` → `"todo::list"`
- `ResourceRef::from_route` constructs from parsed types — no validation at this point
- `ResourceId::parse("")` → error, `ResourceId::parse("list-123")` → ok, `ResourceId::parse("list_123")` → error (underscore)
- `PrincipalRef::vp_entity_type()` → `"iam::user"`
- `PrincipalRef::to_fgrn()` → `"fgrn:acme-app:acme-corp:iam:user:alice"`
- `ResourceRef::to_fgrn()` → `"fgrn:acme-app:acme-corp:todo:list:list-123"`
- **FGRN parsing:** `Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice")` → project=`acme-app`, tenant=`acme-corp`, namespace=`iam`, resource_type=`user`, resource_id=`alice`
- **FGRN parsing resources:** `Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-123")` → namespace=`todo`, resource_type=`list`, resource_id=`list-123`
- **FGRN wildcards:** `Fgrn::parse("fgrn:acme-app:*:todo:list:*")` → tenant=Wildcard, resource_id=Wildcard
- **FGRN not-applicable:** `Fgrn::parse("fgrn:acme-app:-:forgeguard:policy:pol-001")` → tenant=None (the `-` deserializes as `Option::None`, not as a `Segment`)
- **FGRN matching:** specific FGRN matches wildcard pattern, doesn't match wrong namespace
- **FGRN parse errors:** `Fgrn::parse("bad:format")` → error, `Fgrn::parse("fgrn:acme-app")` → error (too few segments), `Fgrn::parse("")` → error
- **FGRN segment validation:** `Fgrn::parse("fgrn:AcmeApp:acme:todo:list:list-1")` → error (uppercase in project segment)
- **FGRN construction:** `Fgrn::new()` → `Display` round-trips to identical string
- **FGRN helpers:** `Fgrn::user()` produces `"fgrn:{project}:{tenant}:iam:user:{user_id}"`, `Fgrn::group()` produces `"fgrn:{project}:{tenant}:iam:group:{name}"`, `Fgrn::resource()` produces `"fgrn:{project}:{tenant}:{ns}:{entity}:{id}"`
- **FGRN as Verified Permissions entity ID:** `Fgrn::as_vp_entity_id()` returns the same string as `Display` — single identifier everywhere
- **FGRN namespace validation:** reserved namespaces `"iam"` and `"forgeguard"` rejected for customer use via `Namespace::parse`, valid kebab-case accepted, empty rejected
- **FGRN serde:** serialize as canonical string, deserialize via parse, round-trip preserves equality
- Serde round-trip: `QualifiedAction` serializes as `"todo:read:list"` and deserializes back
- TOML deserialization of `QualifiedAction` in a route config works via the Deserialize impl
- `FlagName::parse("maintenance-mode")` → `FlagName::Global`
- `FlagName::parse("todo:ai-suggestions")` → `FlagName::Scoped { namespace: todo, name: ai-suggestions }`
- `FlagName::parse("MaintenanceMode")` → error (not kebab-case)
- `FlagName::parse("todo:aiSuggestions")` → error (not kebab-case)
- `FlagName::parse("")` → error
- `FlagName` display round-trip: parse → to_string → parse produces same value
- `FlagName` serde round-trip: serialize → deserialize produces same value
- `FlagName::is_in_namespace`: scoped flag matches its namespace, global flag matches nothing
- `FlagConfig` with `FlagName` keys: TOML like `[flags."todo:ai-suggestions"]` deserializes correctly
- `FlagConfig` with invalid key like `[flags.snake_case]` → rejected at parse time
- Config deserialization: round-trip TOML → struct → verify all fields including features
- Flag evaluation — override resolution hierarchy:
  - User+tenant override wins over tenant-only override (e.g., tenant=acme enabled, user+acme disabled → user gets disabled)
  - User override wins over rollout (e.g., 10% rollout, qa_alice always true)
  - Tenant override wins over rollout and default
  - Kill switch (`enabled = false`) ignores all overrides and rollout, returns default
  - String variant: tenant override returns the variant string, not the default
  - Numeric flag: tenant override returns the overridden number
- Flag evaluation — rollout behavior:
  - Deterministic: same (flag, tenant, user) always produces the same result
  - Distribution: 25% rollout gives ~25% ± 3% of 10,000 test users (statistical, stable with deterministic hash)
  - Independence: different flag names produce different rollout buckets for the same user population
  - Boolean rollout with no `rollout_variant` → defaults to `true`
  - String rollout with `rollout_variant = "streamlined"` → returns `"streamlined"` for users in bucket
  - `rollout_percentage = 0` → nobody gets the rollout
  - `rollout_percentage = 100` → everyone gets the rollout
- Flag evaluation — edge cases:
  - Nonexistent flag → `None`
  - Flag with no overrides and no rollout → always returns default
- Flag config validation:
  - `rollout_percentage = 150` → rejected at parse time
  - `type = "boolean"`, `default = "not a bool"` → rejected
  - `rollout_variant` must match the declared type
  - Warn (don't fail) on overrides with no tenant and no user (matches everything, shadows default)
- Deterministic hashing: same inputs → same bucket, different inputs → different buckets
- `ResolvedFlags` serialization: JSON round-trip
- Error display: messages include field name, value, and reason
- `GroupName` validation: `"admin"` valid, `"backend-team"` valid, `"Admin"` rejected, `""` rejected
- `PolicyName` validation: `"todo-viewer"` valid, `"top-secret-deny"` valid, `"TODO_VIEWER"` rejected
- `ActionPattern::parse("todo:read:list")` → all exact segments
- `ActionPattern::parse("todo:*:*")` → namespace exact, action+entity wildcard
- `ActionPattern::parse("*:*:*")` → all wildcard
- `ActionPattern::parse("todo:read")` → error (only two segments)
- `ActionPattern::matches`: `"todo:*:*"` matches `todo:read:list` and `todo:delete:item`, does not match `billing:read:invoice`
- `ActionPattern::matches`: `"*:read:*"` matches `todo:read:list` and `billing:read:invoice`, does not match `todo:delete:item`
- `Effect` serde: deserializes from `"allow"` and `"deny"`, rejects `"ALLOW"`, `"permit"`
- `PolicyStatement` with `effect: deny` + `except: [top-secret-readers]` — round-trip TOML deserialization
- `PolicyStatement` with `effect: allow` ignores `except` field
- `Policy` with multiple statements: one allow + one deny → both present after deserialization
- `GroupDefinition` with `member_groups`: nested groups deserialize correctly
- `GroupDefinition` with `policies`: policy name references deserialize correctly
- `ResourceConstraint::All` is the default when `resources` field is omitted
- `CedarEntityRef::parse("todo::list::top-secret")` → namespace=`todo`, entity=`list`, id=`top-secret`
- `CedarEntityRef::parse("todo::list")` → error (missing id segment)
- `CedarEntityRef::parse("Todo::List::TopSecret")` → error (uppercase)
- `CedarEntityRef::parse("")` → error
- `CedarEntityRef` display round-trip: parse → to_string → parse produces same value
- `CedarEntityRef` serde: deserializes from `"todo::list::top-secret"`, round-trip preserves equality
- `ResourceConstraint::Specific` with `["todo::list::top-secret"]` deserializes via `CedarEntityRef`
- `Fgrn::policy(&project, &policy_name)` with project=`acme-app`, policy_name=`todo-viewer` → `"fgrn:acme-app:-:forgeguard:policy:todo-viewer"`
- `Fgrn::group(&project, &tenant, &group_name)` with project=`acme-app`, tenant=`acme-corp`, group_name=`admin` → `"fgrn:acme-app:acme-corp:iam:group:admin"`
- Cedar compilation:
  - Allow policy attached to group → `permit(principal in iam::group::"fgrn:...", action in [...], resource)`
  - Deny policy with `except` → `forbid(...) unless { principal in iam::group::"fgrn:..." }`
  - Wildcard action `todo:*:*` → unconstrained `action` in Cedar (or expanded to explicit action list if namespace has known actions)
  - `ResourceConstraint::Specific(["todo::list::top-secret"])` → `resource == todo::list::"fgrn:..."`
  - `ResourceConstraint::All` → unconstrained `resource`
  - `compile_all_to_cedar` rejects undefined policy reference in group
  - `compile_all_to_cedar` detects circular group nesting

---

## Issue #2: `forgeguard_authn_core` — Identity resolution trait, chain, and credential types

**Crate:** `crates/authn-core/` (pure, no I/O, **no `http` dependency**)
**Labels:** `authn`, `pure`, `layer-1`
**Blocked by:** #1
**Unblocks:** #4, #6, #7

### Description

Define the pluggable identity resolution abstraction — modeled after the AWS SDK's credential provider chain. This crate answers one question: "given a credential, who is this?"

This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`. The `IdentityResolver` trait takes a `Credential` and returns an `Identity`.

### Design: Following the AWS SDK Pattern

The AWS SDK uses a `DefaultCredentialsChain` that tries providers in order (env vars → shared credentials file → SSO → ECS metadata → EC2 IMDS). Each implements `ProvideCredentials`, and the chain returns the first success. The rest of the SDK never knows which provider resolved the credential.

ForgeGuard mirrors this exactly:

```
Credential (extracted by the protocol adapter — not our concern)
    │
    ▼
IdentityChain tries resolvers in order:
    │
    ├─ CognitoJwtResolver: can_resolve(Bearer)? yes → validate → Identity ✅
    │
    ├─ StaticApiKeyResolver: can_resolve(ApiKey)? yes → lookup → Identity ✅
    │
    └─ OpaqueTokenResolver: can_resolve(Bearer)? yes → introspect → Identity
    │                                                                (future)
    │
Result: Identity (same type regardless of resolver)
```

`StaticApiKeyResolver` is a pure in-memory HashMap lookup — no I/O. It lives in this crate (`authn_core`). A future `DynamoApiKeyResolver` would live in `authn` (I/O).

### Acceptance Criteria

**Credential — the protocol-agnostic input:**

```rust
/// A raw, unvalidated credential. Protocol adapters produce these.
/// Identity resolvers consume them. Neither knows about the other's world.
///
/// This enum will grow as new auth mechanisms are added (mTLS, session tokens, etc.)
pub enum Credential {
    /// A bearer token (JWT or opaque)
    Bearer(String),
    /// An API key
    ApiKey(String),
}
```

No mention of `Authorization: Bearer` or `X-API-Key` headers — those are HTTP concepts. This enum describes what the credential _is_, not where it came from.

**Identity — the validated output:**

```rust
/// A resolved, trusted identity. Produced only by IdentityResolver implementations.
/// Protocol adapters and the authz layer consume this without knowing how it was produced.
///
/// This is ForgeGuard's equivalent of aws_credential_types::Credentials.
pub struct Identity {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    expiry: Option<SystemTime>,
    /// Which resolver produced this — for logging/metrics, never for branching.
    resolver: &'static str,
    /// Resolver-specific claims preserved for custom policy evaluation.
    /// JWT: decoded claims. API key: key metadata. None if not applicable.
    extra: Option<serde_json::Value>,
}
```

- Fields are `pub(crate)` with getter methods
- Constructor is `pub(crate)` — only resolver implementations can create one
- `resolver` field is purely diagnostic

**Identity resolver trait — the pluggable socket:**

```rust
/// Each resolver knows whether it can handle a credential type
/// and how to resolve it into a trusted Identity.
///
/// Modeled after aws_credential_types::provider::ProvideCredentials.
///
/// NOTE: No `http` dependency. No `extract` method. This trait operates
/// on Credentials, not on protocol-specific request types. The protocol
/// adapter (HTTP proxy, gRPC interceptor, etc.) is responsible for
/// extracting credentials from its own transport.
pub trait IdentityResolver: Send + Sync {
    /// Name for logging and diagnostics: "cognito_jwt", "static_api_key", etc.
    fn name(&self) -> &'static str;

    /// Can this resolver handle this credential type?
    /// Fast, synchronous check — typically just a match on the variant.
    fn can_resolve(&self, credential: &Credential) -> bool;

    /// Validate the credential and produce a trusted Identity.
    /// Async because it may involve I/O (JWKS fetch, token introspection).
    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>>;
}
```

**Identity chain — the orchestrator:**

```rust
/// Tries identity resolvers in order. First one that can resolve the
/// credential owns the outcome — success or failure, the chain stops.
///
/// Mirrors the AWS SDK's DefaultCredentialsChain pattern.
///
/// The chain order (configured in forgeguard.toml) is the tiebreaker for
/// ambiguous credentials, e.g., a Bearer token that could be a JWT or
/// an opaque token. Whichever resolver is first in the chain gets first crack.
pub struct IdentityChain {
    resolvers: Vec<Arc<dyn IdentityResolver>>,
}

impl IdentityChain {
    pub fn new(resolvers: Vec<Arc<dyn IdentityResolver>>) -> Self {
        Self { resolvers }
    }

    /// Resolve a credential into an Identity.
    /// First resolver that can_resolve() owns the outcome.
    pub async fn resolve(&self, credential: &Credential) -> Result<Identity> {
        for resolver in &self.resolvers {
            if !resolver.can_resolve(credential) {
                continue;
            }

            // This resolver claims the credential. Its result is authoritative.
            return resolver.resolve(credential).await;
        }

        Err(Error::NoResolver {
            credential_type: credential.type_name().to_string(),
        })
    }
}
```

**Static API key resolver** (pure, in-memory HashMap lookup):

```rust
/// In-memory API key resolver. Keys are loaded from config at startup.
/// No I/O — the key map is passed in at construction time.
pub struct StaticApiKeyResolver {
    /// key string → (user_id, tenant_id, groups)
    keys: HashMap<String, ApiKeyEntry>,
}

struct ApiKeyEntry {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    description: String,
}

impl IdentityResolver for StaticApiKeyResolver {
    fn name(&self) -> &'static str { "static_api_key" }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::ApiKey(_))
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
        let result = match credential {
            Credential::ApiKey(key) => {
                match self.keys.get(key.as_str()) {
                    Some(entry) => Ok(Identity::new(/* ... */)),
                    None => Err(Error::InvalidCredential("unknown API key".into())),
                }
            }
            _ => Err(Error::InvalidCredential("expected ApiKey credential".into())),
        };
        Box::pin(std::future::ready(result))
    }
}
```

**JWT claims structure** (used by the CognitoJwtResolver in #4, defined here because it's a data type):

```rust
/// Raw JWT claims as deserialized from the token payload.
/// This is untrusted input — it becomes an Identity after validation.
pub struct JwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Option<String>,
    pub exp: u64,
    pub iat: u64,
    pub token_use: String,
    pub scope: Option<String>,
    pub cognito_groups: Option<Vec<String>>,
    pub custom_claims: HashMap<String, serde_json::Value>,
}
```

**Provide a test builder** (behind feature flag):

```rust
#[cfg(feature = "test-support")]
pub struct IdentityBuilder { /* ... */ }

#[cfg(feature = "test-support")]
impl IdentityBuilder {
    pub fn new(user_id: UserId) -> Self { /* ... */ }
    pub fn tenant(mut self, id: TenantId) -> Self { /* ... */ }
    pub fn groups(mut self, groups: Vec<GroupName>) -> Self { /* ... */ }
    pub fn resolver(mut self, name: &'static str) -> Self { /* ... */ }
    pub fn build(self) -> Identity { /* ... */ }
}
```

**Errors:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no resolver available for credential type: {credential_type}")]
    NoResolver { credential_type: String },
    #[error("token expired")]
    TokenExpired,
    #[error("invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },
    #[error("invalid audience")]
    InvalidAudience,
    #[error("missing required claim: {0}")]
    MissingClaim(String),
    #[error("malformed token: {0}")]
    MalformedToken(String),
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
}
```

**Tests:**

- `IdentityChain` with JWT resolver + API key resolver: Bearer credential → JWT resolver handles it, ApiKey credential → API key resolver handles it
- `IdentityChain`: resolver returns `can_resolve() == false` → skipped, next resolver tried
- `IdentityChain`: resolver claims credential but fails to resolve → error returned (no fallthrough)
- `IdentityChain`: no resolver matches → `Error::NoResolver`
- `StaticApiKeyResolver`: known key → correct `Identity`
- `StaticApiKeyResolver`: unknown key → `Error::InvalidCredential`
- `Identity` cannot be constructed outside the crate (compile-time verification)
- `test-support` feature enables the builder
- **No `http` import anywhere in this crate** — verified by CI (`cargo tree -p forgeguard_authn_core | grep -c "http"` == 0)

---

## Issue #3: `forgeguard_authz_core` — Policy engine trait and authorization types

**Crate:** `crates/authz-core/` (pure, no I/O, **no `http` dependency**)
**Labels:** `authz`, `pure`, `layer-1`
**Blocked by:** #1
**Unblocks:** #5, #6, #7

### Description

Define the authorization domain: "can principal P perform action A on resource R given context C?" This crate provides a pure trait for answering that question.

The `PolicyEngine` trait takes a `PolicyQuery` (principal + action + resource + context) and returns a `PolicyDecision` (allow or deny).

This crate has zero dependencies on `http`, `tokio`, AWS SDKs, or any I/O library. It compiles to `wasm32-unknown-unknown`.

### Acceptance Criteria

**Policy query — the protocol-agnostic input:**

```rust
use forgeguard_core::{QualifiedAction, ResourceRef, PrincipalRef, TenantId};

/// The question: "can this principal do this action on this resource?"
/// No HTTP methods, no URL paths, no protocol-specific anything.
pub struct PolicyQuery {
    pub principal: PrincipalRef,
    pub action: QualifiedAction,
    pub resource: Option<ResourceRef>,
    pub context: PolicyContext,
}

/// Additional context for policy evaluation.
/// Groups are passed as context for Verified Permissions to resolve
/// group membership in Cedar entity hierarchy lookups.
pub struct PolicyContext {
    pub tenant_id: Option<TenantId>,
    pub groups: Vec<GroupName>,
    pub ip_address: Option<IpAddr>,
    pub attributes: HashMap<String, serde_json::Value>,
}
```

**Policy decision — the answer:**

```rust
pub enum PolicyDecision {
    Allow,
    Deny { reason: DenyReason },
}

pub enum DenyReason {
    /// No matching ALLOW policy found
    NoMatchingPolicy,
    /// An explicit DENY policy matched
    ExplicitDeny { policy_id: String },
    /// Authorization service returned an error
    EvaluationError(String),
}
```

**Policy engine trait — the pluggable socket:**

```rust
/// Pure: takes a query, returns a decision.
/// No Verified Permissions, no HTTP, no I/O. The Verified Permissions client implements this trait
/// in the I/O crate.
pub trait PolicyEngine: Send + Sync {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>;
}
```

**NOTE:** The `build_query` helper (which bridges `Identity` from `authn_core` into a `PolicyQuery`) lives in `forgeguard_http`, not here. This keeps `authz_core` independent of `authn_core` — both depend only downward on `core`.

**Tests:**

- `PolicyQuery` construction with explicit fields
- `PolicyDecision` display: useful messages for each deny reason
- **No `authn_core` dependency in this crate**
- **No `http` import anywhere in this crate**
- **No route matching, path patterns, or HTTP methods in this crate**

---

## Issue #4: `forgeguard_authn` — Cognito JWT identity resolver

**Crate:** `crates/authn/` (I/O crate, **no `http` dependency**)
**Labels:** `authn`, `io`, `layer-2`
**Blocked by:** #1, #2
**Unblocks:** #7
**Integration tests require:** #8a (Cognito User Pool — for testing against real JWKS and real tokens)

### Description

Implement `IdentityResolver` for Cognito JWTs. This resolver takes a `Credential::Bearer(token)`, fetches the JWKS from Cognito, verifies the signature, validates claims, and produces an `Identity`.

The `CognitoJwtResolver` implements `IdentityResolver` from `authn_core`. It receives a `Credential::Bearer(token)` and returns an `Identity` by validating the JWT against Cognito's JWKS endpoint.

Dependencies: `reqwest` (JWKS fetch), `jsonwebtoken` (JWT decode/verify), `forgeguard_core`, `forgeguard_authn_core`.

### Acceptance Criteria

**`CognitoJwtResolver` implements `IdentityResolver`:**

```rust
pub struct CognitoJwtResolver {
    jwks_cache: JwksCache,
    config: JwtResolverConfig,
}

pub struct JwtResolverConfig {
    pub jwks_url: Url,
    pub issuer: String,
    pub audience: Option<String>,
    pub user_id_claim: String,  // default: "sub" — which JWT claim maps to UserId
    pub tenant_claim: String,   // default: "custom:org_id" — which JWT claim maps to TenantId
    pub groups_claim: String,   // default: "cognito:groups" — which JWT claim maps to groups
}

impl IdentityResolver for CognitoJwtResolver {
    fn name(&self) -> &'static str { "cognito_jwt" }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::Bearer(_))
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
        Box::pin(async move {
            let token = match credential {
                Credential::Bearer(t) => t,
                _ => return Err(Error::Core(
                    forgeguard_authn_core::Error::InvalidCredential(
                        "expected Bearer credential".into()
                    )
                )),
            };

            // 1. Decode header (no verification) to get kid
            // 2. Look up kid in JWKS cache (fetch if miss)
            // 3. Verify signature (RS256)
            // 4. Deserialize claims into JwtClaims
            // 5. Validate: exp, iss, aud, token_use
            // 6. Extract user_id from configured user_id_claim (default: sub),
            //    tenant_id from configured tenant_claim, groups from configured groups_claim
            // 7. Construct Identity with resolver = "cognito_jwt"
        })
    }
}
```

**JWKS fetcher and cache:**

- Fetch JWKS from the configured URL (Cognito's `/.well-known/jwks.json`)
- Cache in memory with a configurable TTL (default: 1 hour)
- Refresh on cache miss (key ID not found — Cognito may have rotated keys)
- Use `reqwest` for HTTP (the only network dependency in this crate)
- `RwLock<HashMap<String, DecodingKey>>` — read-heavy, rare writes

**JWT processing:**

- Use `jsonwebtoken` crate for decoding and signature verification
- Support RS256 (Cognito default)
- Extract `user_id` from the claim name configured in `user_id_claim` (default: `sub`)
- Extract `tenant_id` from the claim name configured in `tenant_claim` (default: `custom:org_id`)
- Extract groups from the claim name configured in `groups_claim` (default: `cognito:groups`)

**Errors:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] forgeguard_authn_core::Error),
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),
    #[error("key not found: kid={0}")]
    KeyNotFound(String),
    #[error("signature verification failed")]
    SignatureInvalid,
}
```

**Tests:**

Unit tests (no network):

- Generate an RSA key pair, sign a JWT, create a `CognitoJwtResolver` with a pre-loaded JWKS cache, call `resolve(Credential::Bearer(token))` → correct `Identity`
- `can_resolve(Credential::Bearer(_))` → true
- `can_resolve(Credential::ApiKey(_))` → false
- Expired token → `TokenExpired`
- Wrong issuer → `InvalidIssuer`
- Unknown kid triggers JWKS refresh logic
- Default `user_id_claim = "sub"` extracts UUID from `sub` → valid `UserId` (UUID is a valid Segment)
- Custom `user_id_claim = "preferred_username"` extracts from that claim instead
- Missing claim for configured `user_id_claim` → `MissingClaim`
- Custom claim extraction: `tenant_claim = "custom:org_id"` reads the right field
- `resolver` field on the resulting `Identity` is `"cognito_jwt"`
- **No `http` import in this crate** — verified by CI

Integration test (gated by `#[cfg(feature = "integration")]` or `#[ignore]`):

- Fetch real Cognito JWKS from a test user pool and validate structure

---

## Issue #5: `forgeguard_authz` — Verified Permissions client with caching

**Crate:** `crates/authz/` (I/O crate)
**Labels:** `authz`, `io`, `layer-2`
**Blocked by:** #1, #3
**Unblocks:** #7
**Integration tests require:** #8b (Verified Permissions Policy Store — for testing against real Cedar policies)

### Description

Implement `PolicyEngine` for AWS Verified Permissions. Takes a `PolicyQuery` (from `authz_core`), calls Verified Permissions `IsAuthorized`, caches the result, and returns a `PolicyDecision`. This is the I/O boundary for authorization — the pure `PolicyEngine` trait is defined in `authz_core`, this crate provides the Verified Permissions-backed implementation.

The `VpPolicyEngine` implements `PolicyEngine` from `authz_core`. It receives a `PolicyQuery` and returns a `PolicyDecision` by calling Verified Permissions `IsAuthorized` API, with an LRU cache in front.

Dependencies: `aws-sdk-verifiedpermissions`, `tokio`, `forgeguard_core`, `forgeguard_authz_core`.

### Acceptance Criteria

**`VpPolicyEngine` implements `PolicyEngine`:**

```rust
pub struct VpPolicyEngine {
    vp_client: aws_sdk_verifiedpermissions::Client,
    policy_store_id: String,
    project_id: ProjectId,  // from ProxyConfig, set at construction — used to build FGRNs for VP entity IDs
    cache: AuthzCache,
}

impl PolicyEngine for VpPolicyEngine {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        Box::pin(async move {
            // 1. Check cache
            // 2. If miss, call Verified Permissions `IsAuthorized`
            // 3. Map Verified Permissions response to PolicyDecision
            // 4. Cache the result
            // 5. Return
        })
    }
}
```

- Use `aws-sdk-verifiedpermissions` crate
- The `PolicyQuery` already contains `QualifiedAction` and `ResourceRef` with Verified Permissions-ready methods.
  FGRN strings are used directly as Verified Permissions entity IDs — single identifier everywhere, no mapping:
  - Principal → entity type `"iam::user"`, entity ID = `to_fgrn()` = `"fgrn:acme-app:acme-corp:iam:user:alice"`
  - Action → `QualifiedAction::vp_action_type()` = `"todo::action"`, `.vp_action_id()` = `"read-list"`
  - Resource → entity type `"todo::list"`, entity ID = `to_fgrn()` = `"fgrn:acme-app:acme-corp:todo:list:list-123"`
  - Context → Verified Permissions context map (groups, tenant_id, etc.)

**Decision cache:**

```rust
pub struct AuthzCache {
    inner: Mutex<LruCache<CacheKey, CachedDecision>>,
    ttl: Duration,
    max_entries: usize,
}

struct CacheKey {
    principal: UserId,
    action: QualifiedAction,    // full three-part action
    resource: Option<ResourceId>,
    tenant_id: Option<TenantId>,
}

struct CachedDecision {
    decision: PolicyDecision,
    cached_at: Instant,
}
```

- LRU eviction when max entries exceeded
- TTL-based expiry (configurable, default 60s)
- Cache key is `(user, action, resource, tenant)` tuple
- Expose cache hit/miss counters for metrics (just `AtomicU64` counters for now — no full metrics pipeline yet)

**Errors:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] forgeguard_authz_core::Error),
    #[error("Verified Permissions error: {0}")]
    VerifiedPermissions(String),
    #[error("policy store not found: {0}")]
    PolicyStoreNotFound(String),
}
```

**Tests:**

- Unit tests with a trait-based mock: define `MockPolicyEngine` implementing `PolicyEngine` in `#[cfg(test)]` that returns preconfigured decisions
- Cache hit: second `evaluate` call with same `PolicyQuery` doesn't call Verified Permissions
- Cache miss: expired entry triggers new Verified Permissions call
- Cache eviction: LRU behavior when max entries exceeded
- Verified Permissions error → `PolicyDecision::Deny { reason: EvaluationError }`
- Verified Permissions ALLOW response → `PolicyDecision::Allow`
- Verified Permissions DENY response → `PolicyDecision::Deny { reason: NoMatchingPolicy }`
- **No `http` import in this crate** — verified by CI

Integration test (gated, requires real AWS credentials + test policy store):

- Create a simple policy in Verified Permissions, call `check`, verify ALLOW
- Call `check` for unpermitted action, verify DENY

---

## Issue #6: `forgeguard_http` — Route mapping, config, and HTTP adapter types

**Crate:** `crates/http/` (HTTP adapter library — compiles everywhere, no Pingora dependency)
**Labels:** `http`, `config`, `layer-2`
**Blocked by:** #1, #2, #3
**Unblocks:** #7, #10, CLI `check`/`config`/`routes`/`policies sync` subcommands

### Description

The HTTP adapter library. All HTTP-specific types and logic live here — separated from the Pingora runtime so that config validation, route inspection, and other utility operations compile and run cross-platform (including macOS).

The crate needs four things:

1. **Route matching** — translating `(method, path)` into `(action, resource)` for the policy engine. `RouteMapping`, `PathPattern`, `RouteMatcher`, `HttpMethod` live here.
2. **Config file** — `forgeguard.toml` defines the proxy configuration: listen address, upstream URL, route mappings, provider chain order, and feature flags.
3. **HTTP translation** — credential extraction from headers, identity header injection, response status code mapping.
4. **Authn→Authz glue** — `build_query` bridges `Identity` (from `authn_core`) into `PolicyQuery` (from `authz_core`). This function lives here (not in `authz_core`) to keep `authz_core` independent of `authn_core`.

Since we don't have Smithy parsing yet, routes are defined manually in the TOML. This is also the permanent format for prototyping and small projects that don't need the full model pipeline.

### Route Matching Types (in `crates/http/`)

```rust
use forgeguard_core::{QualifiedAction, ResourceRef, ResourceId};
use forgeguard_core::features::FlagName;

/// A single HTTP route → policy action mapping.
/// This is HTTP-specific: method + path pattern → authorization query inputs.
pub struct RouteMapping {
    pub method: HttpMethod,
    pub path_pattern: PathPattern,     // e.g., "/lists/{listId}"
    pub action: QualifiedAction,       // e.g., "todo:read:list"
    pub resource_param: Option<String>,// path param name for resource ID
    pub feature_gate: Option<FlagName>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get, Post, Put, Patch, Delete, Any,
}

pub struct PathPattern { /* literal segments + {param} captures */ }

pub struct RouteMatcher {
    routes: Vec<RouteMapping>,
}

impl RouteMatcher {
    pub fn from_mappings(routes: Vec<RouteMapping>) -> Self { /* ... */ }
    pub fn match_request(&self, method: &http::Method, path: &str) -> Option<MatchedRoute> { /* ... */ }
}

pub struct MatchedRoute {
    pub action: QualifiedAction,
    pub resource: Option<ResourceRef>,
    pub path_params: HashMap<String, String>,
    pub feature_gate: Option<FlagName>,
}
```

- `PathPattern` supports literal segments and `{param}` captures
- `PathPattern::matches("/lists/abc123")` returns `Some(params)` where `params["listId"] = "abc123"`
- Path matching is case-sensitive, trailing-slash tolerant

### Public Route Types (in `crates/http/`)

Public routes are matched **before** the auth pipeline runs, following the same pattern as the built-in health check endpoint. They are never rejected — no 401, no 403 — and they never run authorization.

This solves a fundamental gap: without public routes, `default_policy = "deny"` blocks all unauthenticated requests, while `default_policy = "passthrough"` lets all unmatched routes through after auth. There is no middle ground for endpoints that genuinely need no authentication (health checks, docs, incoming webhooks, OAuth callbacks, static assets).

Public routes support two auth modes:

- **Anonymous** (default): Skip auth entirely. No credential extraction, no identity resolution, no `X-ForgeGuard-*` identity headers. The upstream sees only `X-ForgeGuard-Client-Ip`.
- **Opportunistic**: Try to resolve identity if credentials are present, but never reject. If a valid credential is found and identity resolves, inject `X-ForgeGuard-*` identity headers. If no credential or resolution fails, proxy without identity headers. The upstream checks for the presence of `X-ForgeGuard-User-Id` to decide whether to render an authenticated or anonymous experience.

This models the common pattern where documentation pages, landing pages, or public API endpoints work for everyone but render differently when the user is logged in.

```rust
/// How a public route handles credentials.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicAuthMode {
    /// Skip auth entirely. No credential extraction, no identity resolution.
    /// Upstream sees only X-ForgeGuard-Client-Ip.
    #[default]
    Anonymous,
    /// Try to resolve identity if credentials are present, but never reject.
    /// If identity resolves → inject X-ForgeGuard-* identity headers.
    /// If no credential or resolution fails → proxy without identity headers.
    /// No authorization check in either case.
    Opportunistic,
}

/// A route that bypasses the auth pipeline's reject logic.
/// Always proxied to upstream — never returns 401 or 403.
/// Only method + path pattern — no action, no feature gate, no resource mapping.
///
/// Public routes are checked before the auth pipeline runs.
pub struct PublicRoute {
    pub method: HttpMethod,
    pub path_pattern: PathPattern,
    #[serde(default)]
    pub auth_mode: PublicAuthMode,
}

/// Result of matching a request against public routes.
pub enum PublicMatch {
    /// Not a public route — continue to the auth pipeline.
    NotPublic,
    /// Anonymous public route — skip auth entirely, proxy with only Client-Ip.
    Anonymous,
    /// Opportunistic — try auth, never reject. Proxy regardless of outcome.
    Opportunistic,
}

pub struct PublicRouteMatcher {
    routes: Vec<PublicRoute>,
}

impl PublicRouteMatcher {
    pub fn from_routes(routes: Vec<PublicRoute>) -> Self { /* ... */ }

    /// Check if this (method, path) matches a public route.
    /// Returns the match kind so the caller knows whether to attempt auth.
    pub fn check(&self, method: &http::Method, path: &str) -> PublicMatch { /* ... */ }
}
```

- Reuses `HttpMethod` and `PathPattern` from the auth route types
- No `action` field — public routes don't produce policy queries
- No `feature_gate` — anonymous mode has no tenant/user context; opportunistic mode could evaluate flags if identity resolves, but this is deferred (not needed for Target B)
- `check()` returns `PublicMatch` instead of `bool` — the caller branches on anonymous vs opportunistic
- `auth_mode` defaults to `Anonymous` via `#[serde(default)]` — fully backward compatible, existing configs work unchanged
- Opportunistic mode reuses the same `extract_credential` + `IdentityChain.resolve` functions from the protected pipeline, but wraps them in a try-and-ignore flow (errors become "no identity" rather than 401)

### Configuration Struct Definitions (in `crates/http/`)

These types are the Rust-side representation of `forgeguard.toml`.

```rust
pub struct ProxyConfig {
    pub project_id: ProjectId,
    pub listen_addr: SocketAddr,
    pub upstream_url: Url,
    pub default_policy: DefaultPolicy,
    pub client_ip_source: ClientIpSource,
    pub auth: AuthConfig,
    pub authz: AuthzConfig,
    pub policies: PoliciesConfig,
    pub groups: GroupsConfig,
    pub features: FeaturesConfig,
    pub routes: Vec<RouteMapping>,
    #[serde(default)]
    pub public_routes: Vec<PublicRoute>,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// Prometheus metrics endpoint configuration.
/// Disabled by default — the proxy runs with zero overhead unless opted in.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,                          // default: false
    #[serde(default = "default_metrics_ip")]
    pub ip: IpAddr,                             // default: 127.0.0.1
    #[serde(default = "default_metrics_port")]
    pub port: u16,                              // default: 9090
}

/// How to determine the client's real IP address.
#[serde(rename_all = "kebab-case")]
pub enum ClientIpSource {
    /// Use the TCP connection's peer address. Default.
    Peer,
    /// Use the leftmost IP in the X-Forwarded-For header (behind LB/CDN).
    XForwardedFor,
    /// Use Cloudflare's CF-Connecting-IP header.
    CfConnectingIp,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    Passthrough,
    Deny,
}

pub struct AuthConfig {
    pub chain_order: Option<Vec<String>>,
    pub jwt: Option<JwtProviderConfig>,
    pub api_key: Option<ApiKeyProviderConfig>,
}

pub struct JwtProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub jwks_url: Url,
    pub issuer: String,
    pub audience: Option<String>,
    pub user_id_claim: String,     // default: "sub"
    pub tenant_claim: String,      // default: "custom:org_id"
    pub groups_claim: String,      // default: "cognito:groups"
}

pub struct ApiKeyProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub header: String,            // default: "X-API-Key"
    pub prefix: Option<String>,
    pub keys: Vec<StaticApiKey>,
}

pub struct StaticApiKey {
    pub key: String,              // raw key value (plaintext, dev-only)
    pub user_id: UserId,          // parsed at TOML boundary
    pub tenant_id: Option<TenantId>,
    pub groups: Vec<GroupName>,
    pub description: Option<String>,
}

pub struct AuthzConfig {
    pub policy_store_id: String,
    pub aws_region: String,
    pub cache_ttl_seconds: u64,
    pub cache_max_entries: usize,
}

pub struct PoliciesConfig {
    #[serde(default)]
    pub policies: HashMap<PolicyName, Policy>,
}

pub struct GroupsConfig {
    #[serde(default)]
    pub groups: HashMap<GroupName, GroupDefinition>,
}

pub struct FeaturesConfig {
    pub sync_interval_seconds: Option<u64>,
    #[serde(default)]
    pub flags: HashMap<FlagName, FlagDefinition>,
}
```

All derive `Deserialize` + `Debug`. `FeaturesConfig.flags` uses `FlagName` as key — TOML keys like `"todo:ai-suggestions"` are parsed through `FlagName::Deserialize` at load time. Invalid flag names are rejected at the TOML boundary.

### Header Injection (in `crates/http/`)

The proxy builds an `IdentityProjection` from the resolved `Identity` and translates it into HTTP headers. It also injects the client's origin IP on **all** proxied requests (including anonymous and opportunistic public routes), since the upstream app loses visibility of the real client IP when traffic flows through the proxy.

For opportunistic public routes, the `upstream_request_filter` phase already handles this correctly: identity headers are only injected when `ctx.identity` is `Some`. If the opportunistic resolution succeeded, headers are injected; if it failed or no credential was present, only `X-ForgeGuard-Client-Ip` is injected — no code changes needed in this phase.

```rust
/// Per-request identity data projected into key-value pairs for upstream injection.
pub struct IdentityProjection {
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub groups: Vec<String>,
    pub auth_provider: String,
    pub principal_fgrn: String,
    pub features: HashMap<String, serde_json::Value>,
}

fn inject_headers(
    projection: &IdentityProjection,
    client_ip: &str,
    headers: &mut http::HeaderMap,
) -> Result<()> {
    // Origin IP — injected on ALL requests (including public routes)
    headers.insert("X-ForgeGuard-Client-Ip", http::HeaderValue::from_str(client_ip)?);

    // Identity headers — only injected on authenticated requests
    headers.insert("X-ForgeGuard-User-Id", http::HeaderValue::from_str(&projection.user_id)?);
    if let Some(tenant) = &projection.tenant_id {
        headers.insert("X-ForgeGuard-Tenant-Id", http::HeaderValue::from_str(tenant)?);
    }
    headers.insert("X-ForgeGuard-Groups", http::HeaderValue::from_str(&projection.groups.join(","))?);
    headers.insert("X-ForgeGuard-Auth-Provider", http::HeaderValue::from_str(&projection.auth_provider)?);
    headers.insert("X-ForgeGuard-Principal", http::HeaderValue::from_str(&projection.principal_fgrn)?);
    // features as JSON header
    Ok(())
}

/// Inject only the origin IP header (for anonymous public routes, or opportunistic
/// public routes where identity resolution failed or no credential was present).
fn inject_client_ip(client_ip: &str, headers: &mut http::HeaderMap) -> Result<()> {
    headers.insert("X-ForgeGuard-Client-Ip", http::HeaderValue::from_str(client_ip)?);
    Ok(())
}
```

The client IP is extracted from the connection's peer address (`session.client_addr()`). When the proxy itself sits behind a load balancer or CDN, it reads the standard `X-Forwarded-For` header instead (first untrusted hop). This is configurable:

```toml
[proxy]
# How to determine the client's real IP.
# "peer" (default) — use the TCP connection's peer address.
# "x-forwarded-for" — use the leftmost IP in X-Forwarded-For (when behind a LB/CDN).
# "cf-connecting-ip" — use Cloudflare's CF-Connecting-IP header.
client_ip_source = "peer"
```

| Header                       | Source                              | Injected on                     | Example                                                 |
| ---------------------------- | ----------------------------------- | ------------------------------- | ------------------------------------------------------- |
| `X-ForgeGuard-Client-Ip`     | connection peer / `X-Forwarded-For` | All requests (including public) | `203.0.113.42`                                          |
| `X-ForgeGuard-User-Id`       | `identity.user_id`                  | Authenticated only              | `alice`                                           |
| `X-ForgeGuard-Tenant-Id`     | `identity.tenant_id`                | Authenticated only              | `acme-corp`                                             |
| `X-ForgeGuard-Groups`        | `identity.groups`                   | Authenticated only              | `admin,top-secret-readers`                              |
| `X-ForgeGuard-Auth-Provider` | `identity.provider`                 | Authenticated only              | `cognito_jwt`                                           |
| `X-ForgeGuard-Principal`     | `identity.to_fgrn()`                | Authenticated only              | `fgrn:acme-app:acme-corp:iam:user:alice`          |
| `X-ForgeGuard-Features`      | `features` (JSON)                   | Authenticated only              | `{"todo:ai-suggestions":true,"todo:max-upload-mb":100}` |

### Acceptance Criteria

**Config file format** (`forgeguard.toml`):

```toml
project_id = "acme-app"   # Used in FGRNs — every entity ID includes this

[proxy]
listen = "0.0.0.0:8000"
upstream = "http://127.0.0.1:3000"
default_policy = "passthrough"   # "passthrough" or "deny" for unmatched routes
# client_ip_source = "peer"      # "peer" (default), "x-forwarded-for", or "cf-connecting-ip"

# ── Metrics ──
# Prometheus metrics endpoint on a separate port. Disabled by default.
# [metrics]
# enabled = true
# ip = "127.0.0.1"
# port = 9090

[auth]
# No providers list needed. Sections present + enabled = providers active.
# Default chain order: api_key → jwt (cheapest first).
# Uncomment to override:
# chain_order = ["cognito_jwt", "static_api_key"]

# ── Static API Key Provider (testing only) ──
# ⚠ For local development. NEVER use static keys in production.
[auth.api_key]
# enabled = true           # default — set to false to disable without removing config
header = "X-API-Key"
prefix = "sk-test-"

[[auth.api_key.keys]]
key = "sk-test-alice-admin"
user_id = "alice"
tenant_id = "acme-corp"
groups = ["admin", "top-secret-readers"]
description = "Alice — admin + top-secret access"

[[auth.api_key.keys]]
key = "sk-test-bob-member"
user_id = "bob"
tenant_id = "acme-corp"
groups = ["member", "top-secret-readers"]
description = "Bob — member + top-secret access"

[[auth.api_key.keys]]
key = "sk-test-charlie-viewer"
user_id = "charlie"
tenant_id = "acme-corp"
groups = ["viewer"]
description = "Charlie — viewer, no top-secret access"

[[auth.api_key.keys]]
key = "sk-test-eve-other-tenant"
user_id = "eve"
tenant_id = "initech"
groups = ["admin"]
description = "Eve — admin of a DIFFERENT tenant (for isolation tests)"

# ── JWT Provider (Cognito) ──
[auth.jwt]
jwks_url = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123/.well-known/jwks.json"
issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123"
audience = "your-app-client-id"
# user_id_claim = "sub"         # default — which JWT claim maps to UserId
tenant_claim = "custom:org_id"
groups_claim = "cognito:groups"

[authz]
policy_store_id = "ps-abc123"
aws_region = "us-east-1"
cache_ttl_seconds = 60
cache_max_entries = 10000

# ── Policies ──
# Named permission bundles. Each statement is ALLOW or DENY.
# Attached to groups below.

[policies.todo-viewer]
description = "Read-only access to TODO lists and items"
[[policies.todo-viewer.statements]]
effect = "allow"
actions = ["todo:read:list", "todo:list:list", "todo:read:item"]

[policies.todo-editor]
description = "Create, update, delete TODO items and lists"
[[policies.todo-editor.statements]]
effect = "allow"
actions = ["todo:create:list", "todo:create:item", "todo:update:item", "todo:delete:item", "todo:complete:item"]

[policies.todo-admin]
description = "Full access to all TODO resources"
[[policies.todo-admin.statements]]
effect = "allow"
actions = ["todo:*:*"]

[policies.top-secret-deny]
description = "Block access to the top-secret list except for top-secret-readers"
[[policies.top-secret-deny.statements]]
effect = "deny"
actions = ["todo:*:*"]
resources = ["todo::list::top-secret"]
except = ["top-secret-readers"]

# ── Groups ──
# Collections of users with policies attached. Groups can nest.

[groups.admin]
description = "Full access administrators"
policies = ["todo-admin"]

[groups.member]
description = "Can read and write TODO items"
policies = ["todo-viewer", "todo-editor"]

[groups.viewer]
description = "Read-only access"
policies = ["todo-viewer"]

[groups.top-secret-readers]
description = "Can access the top-secret list"
policies = ["todo-viewer"]

# ── Feature Flags ──
# Inline flag definitions. This is a permanent feature, not a stopgap.
# Even with a control plane, inline flags are always evaluated.
# Inline flags take precedence over remote flags (local override).

[features.flags."todo:ai-suggestions"]
type = "boolean"
default = false
overrides = [
    { tenant = "acme-corp", value = true },
]

[features.flags."todo:checkout-flow"]
type = "string"
default = "multi_step"
overrides = [
    { tenant = "acme-corp", value = "single_page" },
]

[features.flags."todo:max-upload-mb"]
type = "number"
default = 50
overrides = [
    { tenant = "acme-corp", value = 100 },
]

[features.flags."todo:premium-ai"]
type = "boolean"
default = false
rollout_percentage = 25   # deterministic hash of (flag, tenant, user)

# ── Public Routes ──
# Matched BEFORE authentication. Never rejected (no 401/403).
# Reuses the same path pattern syntax as auth routes ({param} captures).
#
# auth_mode (optional, default "anonymous"):
#   "anonymous"     — skip auth entirely, no identity headers
#   "opportunistic" — try auth if credentials present, inject identity headers
#                     on success, proxy without them on failure. Never rejects.

[[public_routes]]
method = "GET"
path = "/health"
# auth_mode defaults to "anonymous" — no auth attempted

[[public_routes]]
method = "GET"
path = "/docs/{page}"
auth_mode = "opportunistic"
# Docs work for everyone. Authenticated users see personalized UI
# (bookmarks, edit buttons). Upstream checks X-ForgeGuard-User-Id presence.

[[public_routes]]
method = "ANY"
path = "/webhooks/{provider}"
# auth_mode defaults to "anonymous" — incoming webhooks have no user

# ── Routes ──
# Actions use three-part format: namespace:action:entity
# Entity IS the resource type — no separate resource_type field.
# resource_param names the path segment that holds the instance ID.

[[routes]]
method = "GET"
path = "/lists"
action = "todo:list:list"

[[routes]]
method = "POST"
path = "/lists"
action = "todo:create:list"

[[routes]]
method = "GET"
path = "/lists/{listId}"
action = "todo:read:list"
resource_param = "listId"

[[routes]]
method = "DELETE"
path = "/lists/{listId}"
action = "todo:delete:list"
resource_param = "listId"

[[routes]]
method = "POST"
path = "/lists/{listId}/archive"
action = "todo:archive:list"
resource_param = "listId"

[[routes]]
method = "POST"
path = "/lists/{listId}/items"
action = "todo:create:item"
resource_param = "listId"

[[routes]]
method = "POST"
path = "/items/{itemId}/complete"
action = "todo:complete:item"
resource_param = "itemId"

# Feature-gated route: proxy returns 404 when flag is disabled for this tenant.
# The app never sees the request.
[[routes]]
method = "GET"
path = "/lists/{listId}/suggestions"
action = "todo:read:list"
resource_param = "listId"
feature_gate = "todo:ai-suggestions"
```

**Config loader** (in the proxy binary):

```rust
/// Load config from TOML file, validate, and return.
/// This handles step 1 (config file) of the precedence chain.
/// CLI flag / env var overrides are applied separately by the caller.
pub fn load_config(path: &Path) -> Result<ProxyConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("failed to read {}: {e}", path.display())))?;
    let config: ProxyConfig = toml::from_str(&content)
        .map_err(|e| Error::Config(format!("invalid TOML in {}: {e}", path.display())))?;
    config.validate()?;
    Ok(config)
}

/// Merge CLI/env overrides on top of the parsed config file.
/// Follows the Binary CLI Convention precedence:
///   CLI flags > env vars > config file > defaults
///
/// clap's `env` attribute means env vars are already merged into
/// the RunOptions by the time we get here — so this function just
/// applies any `Some` overrides from RunOptions onto the config.
// NOTE: apply_overrides lives in the binary (proxy or CLI), not in forgeguard_http,
// because RunOptions is a clap struct specific to each binary's CLI.
// forgeguard_http provides load_config() and ProxyConfig with pub(crate) field setters.
pub fn apply_overrides(config: &mut ProxyConfig, opts: &RunOptions) {
    if let Some(listen) = &opts.listen {
        config.listen_addr = *listen;
    }
    if let Some(upstream) = &opts.upstream {
        config.upstream_url = upstream.clone();
    }
    if let Some(policy) = &opts.default_policy {
        config.default_policy = policy.clone();
    }
    if let Some(store_id) = &opts.policy_store_id {
        config.authz.policy_store_id = store_id.clone();
    }
    if let Some(region) = &opts.aws_region {
        config.authz.aws_region = region.clone();
    }
}
```

**Configuration precedence chain:**

The proxy loads config in layers. `clap`'s `env` attribute on `RunOptions` fields means environment variables are automatically merged into the CLI options — if a CLI flag is absent, `clap` checks the env var before falling back to `None`. The flow is:

1. Parse CLI args (including env var fallbacks) via `App::parse()`
2. Load and validate `forgeguard.toml` via `load_config()`
3. Apply `RunOptions` overrides via `apply_overrides()`

This means a single field like `listen_addr` resolves as: `--listen` flag (if provided) → `FORGEGUARD_LISTEN` env var (if set) → `proxy.listen` in TOML → default `0.0.0.0:8000`.

**Validation rules:**

- No duplicate routes (same method + path pattern)
- All actions are three-part `Namespace:Action:Entity` (enforced by `QualifiedAction::Deserialize`), paths start with `/`
- `feature_gate` references must match a defined flag name in `[features.flags.*]`
- `rollout_percentage` must be 0..=100
- No duplicate public routes (same method + path pattern)
- Public route path overlapping an auth route → startup **warning** (not error), public wins at runtime
- Public route paths must start with `/`
- `auth_mode` must be `"anonymous"` or `"opportunistic"` (or omitted for default `anonymous`)
- Missing `resource_param` is allowed (for collection endpoints like `GET /lists`)
- Missing `[[public_routes]]` section is valid (no public routes configured, `#[serde(default)]`)

**Tests:**

- Valid config parses correctly, including policies, groups, feature flags, feature-gated routes, anonymous public routes, and opportunistic public routes
- Missing required fields → clear error message
- Duplicate routes detected
- Duplicate public routes detected
- `feature_gate` referencing undefined flag → validation error
- `rollout_percentage` > 100 → validation error
- Policy with invalid action pattern → validation error
- Policy referenced by group but not defined → validation error
- Group referenced in `except` but not defined → validation error
- Group with `member_groups` referencing undefined group → validation error
- Circular group nesting detected → validation error
- Empty `[policies]` section is valid (no policies configured)
- Empty `[groups]` section is valid (no groups configured)
- `apply_overrides` with `listen = Some(...)` overrides the TOML `proxy.listen` value
- `apply_overrides` with all `None` fields leaves config unchanged
- CLI flag `--listen` overrides `FORGEGUARD_LISTEN` env var (verified via clap precedence)
- `FORGEGUARD_LISTEN` env var overrides TOML `proxy.listen` (verified via `apply_overrides`)
- `load_config` error messages include the file path and parse location
- Empty `[features]` section is valid (no flags configured)
- Empty or absent `[[public_routes]]` is valid (no public routes)
- Public route with `method = "ANY"` matches all HTTP methods
- Public route with `{param}` captures parses correctly (reuses `PathPattern`)
- Overlapping public + auth route → parses with warning, no error
- Example `forgeguard.toml` committed to `examples/todo-app/`

---

## Issue #7: `forgeguard_proxy` — Pingora runtime with auth enforcement

**Crate:** `crates/proxy/` (binary, Linux-only)
**Labels:** `proxy`, `binary`, `layer-3`, `pingora`
**Blocked by:** #2, #3, #4, #5, #6, #10
**Unblocks:** #9

### Description

The Pingora runtime binary. This crate wires all the pieces together: it implements Pingora's `ProxyHttp` trait using types from `forgeguard_http` (config, route matching, credential extraction, header injection) and domain crates (`authn_core`, `authz_core`, `authn`, `authz`).

All HTTP-to-domain translation logic (credential extraction, route matching, header injection, response mapping) lives in `forgeguard_http`. This crate maps those operations into Pingora's request lifecycle phases (`request_filter`, `upstream_peer`, `upstream_request_filter`, `logging`).

The `check`, `config`, and `routes` utility subcommands live in `forgeguard_cli` (cross-platform). This crate only provides the `run` subcommand.

Dependencies: `pingora`, `pingora-proxy`, `pingora-http`, `forgeguard_http`, `forgeguard_authn`, `forgeguard_authz`.

Built on Cloudflare's Pingora framework (`pingora 0.8`, `pingora-proxy 0.8`). Pingora gives us connection pooling to upstream, HTTP/1.1 + HTTP/2 + gRPC + WebSocket proxying, zero-downtime graceful restarts, and a work-stealing async scheduler — all battle-tested at 40M+ requests/second at Cloudflare.

**Platform:** Linux-only (Pingora's tier 1 target). Local development on macOS uses Docker. Config validation and route inspection run natively via `forgeguard_cli`.

### Acceptance Criteria

**Request lifecycle mapped to Pingora phases:**

```
Client → Proxy(:8000)
  │
  ├─ request_filter (Pingora phase)
  │   │
  │   ├─ 0. Health check (/.well-known/forgeguard/health)
  │   │     └─ Match? → 200 JSON, return Ok(true)
  │   │
  │   ├─ 1. Match public routes (PublicRouteMatcher::check)
  │   │     └─ Anonymous?      → return Ok(false) — skip auth, proxy directly
  │   │        No X-ForgeGuard-* identity headers. No credential needed.
  │   │        Logged with user="-", action="-", public=true.
  │   │     └─ Opportunistic?  → try extract credential
  │   │        └─ No credential?      → return Ok(false), no identity headers
  │   │        └─ Credential found?   → try IdentityChain.resolve()
  │   │           └─ Resolved?        → store Identity in CTX (headers injected later)
  │   │           └─ Failed?          → ignore error, return Ok(false), no identity headers
  │   │        Never returns 401/403. Always proxied.
  │   │        Logged with user=<id|"-">, action="-", public=true, opportunistic=true.
  │   │
  │   ├─ 2. Extract Credential from HTTP headers
  │   │     Authorization: Bearer <token> → Credential::Bearer(token)
  │   │     X-API-Key: sk-... → Credential::ApiKey(key)
  │   │     └─ No recognized header? → 401, return Ok(true)
  │   │
  │   ├─ 3. IdentityChain.resolve(credential)   [domain — no HTTP]
  │   │     First resolver that can_resolve() owns the outcome.
  │   │     └─ Resolver failed? → 401, return Ok(true)
  │   │     └─ Resolved? → Identity stored in CTX
  │   │
  │   ├─ 4. Evaluate feature flags (pure, no I/O)
  │   │     evaluate_flags(config, tenant_id, user_id) → ResolvedFlags
  │   │
  │   ├─ 5. Match auth route (RouteMatcher)
  │   │     (method, path) → (action, resource)
  │   │     └─ No match? → depends on default_policy (passthrough or deny)
  │   │
  │   ├─ 6. Check feature gate (if route has feature_gate)
  │   │     └─ Flag disabled? → 404, return Ok(true)
  │   │
  │   └─ 7. Build PolicyQuery + call PolicyEngine.evaluate()  [domain — no HTTP]
  │         └─ PolicyDecision::Deny → 403, return Ok(true)
  │         └─ PolicyDecision::Allow → return Ok(false) [continue to upstream]
  │
  ├─ upstream_peer (Pingora phase)
  │   └─ Return HttpPeer pointing to configured upstream
  │
  ├─ upstream_request_filter (Pingora phase)
  │   └─ Always inject origin IP:
  │      X-ForgeGuard-Client-Ip: 203.0.113.42
  │   └─ If identity present: Build IdentityProjection from Identity
  │   └─ Inject identity + feature headers (authenticated requests only):
  │      X-ForgeGuard-User-Id: alice
  │      X-ForgeGuard-Tenant-Id: acme-corp
  │      X-ForgeGuard-Groups: admin,top-secret-readers
  │      X-ForgeGuard-Auth-Provider: static_api_key
  │      X-ForgeGuard-Principal: fgrn:acme-app:acme-corp:iam:user:alice
  │      X-ForgeGuard-Features: {"todo:ai-suggestions":true,"todo:max-upload-mb":100}
  │   └─ Anonymous public routes: only X-ForgeGuard-Client-Ip, no identity headers
  │   └─ Opportunistic public routes: X-ForgeGuard-Client-Ip always; identity headers if resolved
  │
  └─ logging (Pingora phase)
      └─ Structured tracing with status, user, action, latency
         Anonymous public routes logged with user="-", action="-", public=true
         Opportunistic public routes logged with user=<id|"-">, action="-", public=true, opportunistic=true
```

Note: `request_filter` returning `Ok(true)` means "I already sent a response, don't proxy." This is Pingora's mechanism for short-circuiting — perfect for 401/403/404 rejections.

**Implementation outline:**

```rust
use async_trait::async_trait;
use pingora::prelude::*;
use pingora_proxy::{ProxyHttp, Session};
use pingora_http::RequestHeader;

/// Per-request context, carried across all Pingora phases.
pub struct RequestCtx {
    pub identity: Option<Identity>,
    pub flags: Option<ResolvedFlags>,
    pub matched_route: Option<MatchedRoute>,
    pub request_start: Instant,
    pub method: String,
    pub path: String,
}

/// The ForgeGuard proxy — implements Pingora's ProxyHttp trait.
/// This is the HTTP adapter: it translates between HTTP and the policy domain.
pub struct ForgeGuardProxy {
    identity_chain: IdentityChain,        // domain: Credential → Identity
    policy_engine: Arc<dyn PolicyEngine>,  // domain: PolicyQuery → PolicyDecision
    route_matcher: RouteMatcher,           // adapter: (method, path) → (action, resource)
    public_matcher: PublicRouteMatcher,    // adapter: public routes bypass auth
    flag_config: FlagConfig,
    upstream: HttpPeer,
    default_policy: DefaultPolicy,
    client_ip_source: ClientIpSource,
}

#[async_trait]
impl ProxyHttp for ForgeGuardProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            identity: None,
            flags: None,
            matched_route: None,
            request_start: Instant::now(),
            method: String::new(),
            path: String::new(),
        }
    }

    /// Phase 1: Auth, flags, route matching, authorization.
    /// Returns Ok(true) to short-circuit with an error response.
    /// Returns Ok(false) to continue proxying.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let req = session.req_header();
        ctx.method = req.method.to_string();
        ctx.path = req.uri.path().to_string();

        // Handle health check before auth
        if ctx.path == "/.well-known/forgeguard/health" {
            let body = self.health_check_json();
            session.respond_json(200, &body).await?;
            return Ok(true);
        }

        // ── ADAPTER: Match public routes — never reject ──
        match self.public_matcher.check(&req.method, &ctx.path) {
            PublicMatch::Anonymous => {
                tracing::info!(
                    method = %ctx.method,
                    path = %ctx.path,
                    public = true,
                    "public route (anonymous) — skipping auth pipeline"
                );
                return Ok(false);
            }
            PublicMatch::Opportunistic => {
                // Try to resolve identity, but never reject.
                // Reuses the same credential extraction + identity resolution
                // as the protected pipeline, but errors are swallowed.
                if let Some(credential) = extract_credential(&req.headers) {
                    match self.identity_chain.resolve(&credential).await {
                        Ok(identity) => {
                            tracing::info!(
                                method = %ctx.method,
                                path = %ctx.path,
                                user = %identity.user_id,
                                public = true,
                                opportunistic = true,
                                "public route (opportunistic) — identity resolved"
                            );
                            ctx.identity = Some(identity);
                        }
                        Err(e) => {
                            tracing::debug!(
                                method = %ctx.method,
                                path = %ctx.path,
                                error = %e,
                                public = true,
                                opportunistic = true,
                                "public route (opportunistic) — identity resolution failed, continuing anonymous"
                            );
                        }
                    }
                } else {
                    tracing::info!(
                        method = %ctx.method,
                        path = %ctx.path,
                        public = true,
                        opportunistic = true,
                        "public route (opportunistic) — no credential, continuing anonymous"
                    );
                }
                // Always proxy — identity headers injected in upstream_request_filter
                // only if ctx.identity is Some.
                return Ok(false);
            }
            PublicMatch::NotPublic => {
                // Fall through to the protected auth pipeline below.
            }
        }

        // ── ADAPTER: Extract Credential from HTTP headers ──
        let credential = match extract_credential(&req.headers) {
            Some(c) => c,
            None => {
                let body = json!({ "error": "Unauthorized", "detail": "no credential" });
                session.respond_json(401, &body).await?;
                return Ok(true);
            }
        };

        // ── DOMAIN: Resolve identity ──
        let identity = match self.identity_chain.resolve(&credential).await {
            Ok(id) => id,
            Err(e) => {
                let body = json!({ "error": "Unauthorized", "detail": e.to_string() });
                session.respond_json(401, &body).await?;
                return Ok(true);
            }
        };

        // ── DOMAIN: Evaluate feature flags (pure, no I/O) ──
        let flags = evaluate_flags(
            &self.flag_config,
            identity.tenant_id(),
            identity.user_id(),
        );

        // ── ADAPTER: Match route (HTTP method + path → action + resource) ──
        let matched = self.route_matcher.match_request(
            &req.method,
            req.uri.path(),
        );

        if let Some(ref route) = matched {
            // ── ADAPTER: Check feature gate ──
            if let Some(ref gate) = route.feature_gate {
                if !flags.enabled(&gate.to_string()) {
                    let body = json!({ "error": "Not Found" });
                    session.respond_json(404, &body).await?;
                    return Ok(true);
                }
            }

            // ── DOMAIN: Build PolicyQuery and evaluate ──
            let query = build_query(
                &identity,
                route.action.clone(),
                route.resource.clone(),
                HashMap::new(),
            );
            match self.policy_engine.evaluate(&query).await? {
                PolicyDecision::Allow => {}
                PolicyDecision::Deny { reason } => {
                    // ── ADAPTER: Translate domain decision to HTTP response ──
                    let body = json!({
                        "error": "Forbidden",
                        "action": route.action.to_string(),
                    });
                    session.respond_json(403, &body).await?;
                    return Ok(true);
                }
            }
        } else if self.default_policy == DefaultPolicy::Deny {
            let body = json!({ "error": "Forbidden", "detail": "unmatched route" });
            session.respond_json(403, &body).await?;
            return Ok(true);
        }

        // Store in CTX for header injection in upstream_request_filter
        ctx.identity = Some(identity);
        ctx.flags = Some(flags);
        ctx.matched_route = matched;

        Ok(false) // Continue to upstream
    }

    /// Phase 2: Select upstream target.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(self.upstream.clone()))
    }

    /// Phase 3: Inject identity + feature flag + client IP headers before sending to upstream.
    /// Client IP is injected on ALL requests (including public routes).
    /// Identity and feature headers are only injected on authenticated requests.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // ADAPTER: Always inject client IP (including public routes)
        let client_ip = resolve_client_ip(session, &self.client_ip_source);
        inject_client_ip(&client_ip, &mut upstream_request.headers);

        // ADAPTER: Inject identity + feature headers (authenticated requests only)
        if let Some(ref identity) = ctx.identity {
            // DOMAIN: Build projection (pure data transformation)
            let projection = IdentityProjection::from_identity(identity);

            // ADAPTER: Inject into HTTP headers
            inject_headers(&projection, &client_ip, &mut upstream_request.headers);
        }
        if let Some(ref flags) = ctx.flags {
            inject_feature_headers(flags, &mut upstream_request.headers);
        }
        Ok(())
    }

    /// Phase 4: Structured logging after request completes.
    async fn logging(
        &self,
        session: &mut Session,
        _error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session.response_written()
            .map_or(0, |r| r.status.as_u16());
        let latency_ms = ctx.request_start.elapsed().as_millis();

        tracing::info!(
            method = %ctx.method,
            path = %ctx.path,
            status,
            user = ctx.identity.as_ref().map(|a| a.user_id().as_str()).unwrap_or("-"),
            tenant = ctx.identity.as_ref().and_then(|a| a.tenant_id()).map(|t| t.as_str()).unwrap_or("-"),
            resolver = ctx.identity.as_ref().map(|a| a.resolver()).unwrap_or("-"),
            action = ctx.matched_route.as_ref().map(|r| r.action.as_str()).unwrap_or("-"),
            latency_ms,
        );
    }
}

// ── CLI definition (follows Binary CLI Convention) ──

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "forgeguard-proxy",
    version,
    about = "ForgeGuard auth-enforcing reverse proxy (Pingora)"
)]
pub(crate) struct App {
    #[command(subcommand)]
    pub command: Commands,
    #[clap(flatten)]
    pub global: Global,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Global {
    /// Enable verbose logging (debug level)
    #[clap(long, short, env = "FORGEGUARD_VERBOSE", global = true)]
    pub verbose: bool,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Commands {
    /// Start the proxy server
    Run(RunOptions),
    // NOTE: `check`, `config`, and `routes` subcommands live in forgeguard_cli
    // (cross-platform). This binary only provides `run` (Pingora, Linux-only).
}

#[derive(Debug, clap::Args)]
pub(crate) struct RunOptions {
    /// Path to configuration file
    #[clap(short, long, default_value = "forgeguard.toml", env = "FORGEGUARD_CONFIG")]
    pub config: PathBuf,

    /// Listen address (overrides config file)
    #[clap(long, env = "FORGEGUARD_LISTEN")]
    pub listen: Option<SocketAddr>,

    /// Upstream URL (overrides config file)
    #[clap(long, env = "FORGEGUARD_UPSTREAM")]
    pub upstream: Option<Url>,

    /// Default policy for unmatched routes: "passthrough" or "deny"
    #[clap(long, env = "FORGEGUARD_DEFAULT_POLICY")]
    pub default_policy: Option<DefaultPolicy>,

    /// Verified Permissions policy store ID (overrides config file)
    #[clap(long, env = "FORGEGUARD_POLICY_STORE_ID")]
    pub policy_store_id: Option<String>,

    /// AWS region (overrides config file)
    #[clap(long, env = "FORGEGUARD_AWS_REGION")]
    pub aws_region: Option<String>,
}

// NOTE: CheckOptions, ConfigOptions, RoutesOptions, and their implementations
// (cmd_check, cmd_config, cmd_routes) live in forgeguard_cli, not here.
// See the forgeguard_cli binary for cross-platform config validation and inspection.

/// `forgeguard-proxy run` — start the proxy server.
fn cmd_run(opts: RunOptions, global: Global) -> color_eyre::Result<()> {
    let mut config = load_config(&opts.config)?;
    apply_overrides(&mut config, &opts);

    let mut server = Server::new(None)?;
    server.bootstrap();

    let identity_chain = build_identity_chain(&config.auth)?;
    let policy_engine: Arc<dyn PolicyEngine> = Arc::new(
        VpPolicyEngine::new(&config.authz, config.project_id.clone())?
    );
    let route_matcher = RouteMatcher::from_mappings(config.routes.clone());
    let public_matcher = PublicRouteMatcher::from_routes(config.public_routes.clone());
    let flag_config = FlagConfig { flags: config.features.flags.clone() };

    let upstream = HttpPeer::new(
        config.upstream_url.as_str(),
        false,  // no TLS to upstream (local dev)
        String::new(),
    );

    let proxy = ForgeGuardProxy {
        identity_chain,
        policy_engine,
        route_matcher,
        public_matcher,
        flag_config,
        upstream,
        default_policy: config.default_policy,
        client_ip_source: config.client_ip_source,
    };

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.listen_addr.to_string());

    // Prometheus metrics — only when opted in via [metrics] config
    if config.metrics.enabled {
        let mut prometheus = Service::prometheus_http_service();
        let addr = format!("{}:{}", config.metrics.ip, config.metrics.port);
        prometheus.add_tcp(&addr);
        server.add_service(prometheus);
        tracing::info!(metrics_listen = %addr, "Prometheus metrics enabled");
    }

    server.add_service(proxy_service);

    tracing::info!(
        listen = %config.listen_addr,
        upstream = %config.upstream_url,
        routes = config.routes.len(),
        public_routes = config.public_routes.len(),
        flags = flag_config.flags.len(),
        "ForgeGuard proxy started (Pingora)"
    );

    server.run_forever();
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let app = App::parse();
    init_tracing(app.global.verbose);

    match app.command {
        Commands::Run(opts) => cmd_run(opts, app.global),
    }
}

/// Initialize tracing-subscriber with level from --verbose flag or RUST_LOG env.
fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = if verbose {
        EnvFilter::new("debug,forgeguard=trace")
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,forgeguard=debug"))
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}
```

**What Pingora gives us for free:**

- Connection pooling to upstream (reuses connections)
- HTTP/1.1 + HTTP/2 end-to-end, gRPC, WebSocket proxying
- Zero-downtime graceful restarts (`SIGQUIT` → drain connections → replace binary)
- Work-stealing async scheduler
- Built-in Prometheus metrics endpoint (on separate port, opt-in via `[metrics]` config)
- Rate limiting via `pingora-limits` (future use)
- `request_filter` returning `true` short-circuits without touching upstream

**Health check:** `GET /.well-known/forgeguard/health` is handled in `request_filter` before auth, returning 200 with:

```json
{
  "status": "healthy",
  "upstream": "reachable",
  "identity_providers": ["static_api_key", "cognito_jwt"],
  "jwks_cached": true,
  "authz_cache_entries": 42,
  "authz_cache_hit_rate": 0.87,
  "feature_flags": 4,
  "public_routes": 3
}
```

**Error responses:**

- `401 Unauthorized`: no provider recognized the credential, or provider failed validation
- `403 Forbidden`: authorization denied (include action in response body for debugging)
- `404 Not Found`: feature-gated route where the flag is disabled for this tenant/user
- `502 Bad Gateway`: upstream unreachable (Pingora handles this via `fail_to_proxy`)
- All error responses are JSON: `{ "error": "...", "detail": "..." }`

**Structured logging:**

```
INFO  forgeguard_proxy: started listen=0.0.0.0:8000 upstream=http://127.0.0.1:3000 routes=12 public_routes=3 flags=4 runtime=pingora
INFO  forgeguard_proxy: request method=GET path=/lists status=200 user=alice tenant=acme-corp action=todo:read:list provider=cognito_jwt latency_ms=4
INFO  forgeguard_proxy: request method=GET path=/health status=200 user=- action=- public=true latency_ms=1
INFO  forgeguard_proxy: request method=GET path=/docs/getting-started status=200 user=alice action=- public=true opportunistic=true latency_ms=3
INFO  forgeguard_proxy: request method=GET path=/docs/getting-started status=200 user=- action=- public=true opportunistic=true latency_ms=2
INFO  forgeguard_proxy: request method=GET path=/lists/abc/suggestions status=200 user=alice tenant=acme-corp action=todo:read:list provider=cognito_jwt gate=todo:ai-suggestions latency_ms=6
WARN  forgeguard_proxy: request method=GET path=/lists/abc/suggestions status=404 user=dave tenant=initech gate=todo:ai-suggestions latency_ms=1
WARN  forgeguard_proxy: request method=POST path=/lists status=403 user=charlie tenant=acme-corp action=todo:create:list provider=cognito_jwt latency_ms=3
WARN  forgeguard_proxy: request method=GET path=/lists status=401 user=- error="token expired" latency_ms=2
ERROR forgeguard_proxy: request method=GET path=/lists status=502 error="connection refused" latency_ms=1
```

**Docker for local dev on macOS:**

```dockerfile
# Dockerfile.proxy (in crates/proxy/)
FROM rust:1.91-slim AS builder
RUN apt-get update && apt-get install -y cmake clang libssl-dev pkg-config
WORKDIR /app
COPY . .
RUN cargo build --release -p forgeguard_proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/forgeguard_proxy /usr/local/bin/
ENTRYPOINT ["forgeguard_proxy"]
```

```yaml
# docker-compose.yml (in examples/todo-app/)
services:
  proxy:
    build:
      context: ../../
      dockerfile: crates/proxy/Dockerfile.proxy
    ports:
      - "8000:8000"
      - "9090:9090" # Prometheus metrics (requires [metrics] enabled = true)
    volumes:
      - ./forgeguard.toml:/etc/forgeguard/forgeguard.toml:ro
    command: ["run", "--config", "/etc/forgeguard/forgeguard.toml"]
    environment:
      - AWS_REGION=us-east-1
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY
      - RUST_LOG=info,forgeguard=debug
```

**Dependencies for `crates/proxy/Cargo.toml`:**

```toml
[dependencies]
forgeguard_http = { path = "../http" }
forgeguard_authn = { path = "../authn" }
forgeguard_authz = { path = "../authz" }

pingora = { version = "0.8", features = ["proxy"] }
pingora-core = "0.8"
pingora-proxy = "0.8"
pingora-http = "0.8"
async-trait = "0.1"
clap = { workspace = true }

tracing = { workspace = true }
tracing-subscriber = { workspace = true }
color-eyre = { workspace = true }
```

Pingora owns the HTTP runtime. `forgeguard_http` provides all config, route matching, credential extraction, and header injection types.

**Tests:**

- Unit tests for the `ForgeGuardProxy` with mocked `IdentityChain` and mocked `PolicyEngine` — Pingora provides `Session` test utilities
- Valid credential + allowed action → upstream receives request with all 7 injected headers (`Client-Ip`, `User-Id`, `Tenant-Id`, `Groups`, `Auth-Provider`, `Principal` FGRN, `Features` JSON)
- Valid credential + denied action → 403 JSON response
- No credential extracted by any provider → 401
- Provider extracts but fails to resolve (expired token) → 401 (chain stops)
- Unmatched route + `default_policy = "passthrough"` → proxied without auth check, flags still injected
- Unmatched route + `default_policy = "deny"` → 403
- Feature-gated route + flag enabled → 200 (proceeds to authz)
- Feature-gated route + flag disabled → 404 (never reaches authz)
- Non-gated route still has `X-ForgeGuard-Features` header with all resolved flags
- Health check at `/.well-known/forgeguard/health` returns 200 before auth (no token needed)
- Anonymous public route + no credential → proxied to upstream (200), only `X-ForgeGuard-Client-Ip` header (no identity headers)
- Anonymous public route + valid credential → proxied to upstream (200), credential ignored, only `X-ForgeGuard-Client-Ip` header
- Opportunistic public route + no credential → proxied to upstream (200), only `X-ForgeGuard-Client-Ip` header (no identity headers)
- Opportunistic public route + valid credential → proxied to upstream (200), all `X-ForgeGuard-*` identity headers injected
- Opportunistic public route + expired/invalid credential → proxied to upstream (200), no identity headers (resolution failure swallowed, NOT 401)
- Non-public route + no credential → 401 (unchanged — public routes don't affect non-public routes)
- `X-ForgeGuard-Client-Ip` is present on all proxied requests (authenticated, anonymous public, and opportunistic public)
- Public route + `default_policy = "deny"` → still proxied (public overrides default policy)
- Public route with `{param}` pattern matches correctly
- Public route with `method = "ANY"` matches GET, POST, PUT, DELETE, PATCH
- Path matching both public and auth route → public wins, auth pipeline never runs
- Anonymous public route logged with `user="-"`, `action="-"`, `public=true`
- Opportunistic public route + identity resolved → logged with `user=<id>`, `action="-"`, `public=true`, `opportunistic=true`
- Opportunistic public route + no identity → logged with `user="-"`, `action="-"`, `public=true`, `opportunistic=true`
- Config with `auth_mode = "opportunistic"` parses correctly
- Config with no `auth_mode` defaults to anonymous (backward compatible)
- Prometheus metrics endpoint on separate port, controlled by `[metrics]` config (disabled by default)
- Docker build succeeds and proxy starts in container

`forgeguard-proxy` CLI (runtime only):

- `forgeguard-proxy run --config forgeguard.toml` starts the proxy
- `forgeguard-proxy run --config forgeguard.toml --listen 0.0.0.0:9000` overrides the listen address
- `forgeguard-proxy run` with `FORGEGUARD_LISTEN=0.0.0.0:9000` env var overrides the listen address
- CLI flag `--listen` takes precedence over `FORGEGUARD_LISTEN` env var
- `forgeguard-proxy run --help` prints run-specific options with env var hints
- `forgeguard-proxy --version` prints version
- `forgeguard-proxy -v run --config forgeguard.toml` enables verbose/debug logging
- `FORGEGUARD_VERBOSE=true forgeguard-proxy run` enables verbose logging via env var
- `main()` returns `color_eyre::Result<()>` — no `.unwrap()` calls anywhere in the binary

`forgeguard` CLI (cross-platform, lives in `forgeguard_cli`):

- `forgeguard check --config forgeguard.toml` validates config and exits 0 on success
- `forgeguard check --config bad.toml` exits non-zero with a clear error message
- `forgeguard config --config forgeguard.toml` prints the fully-resolved config as TOML
- `forgeguard config --config forgeguard.toml --format json` prints as JSON
- `forgeguard routes --config forgeguard.toml` prints the route table (public + auth)
- `forgeguard policies sync --config forgeguard.toml` compiles policies/groups to Cedar and pushes to VP
- `forgeguard --help` prints usage with all subcommands

---

## Issue #8a: AWS bootstrap — Cognito User Pool for development

**Labels:** `infra`, `devex`, `authn`
**Blocked by:** nothing (can run in parallel with all code issues)
**Unblocks:** #4 (integration tests), #8b, #9

### Description

Provision the minimal Cognito infrastructure needed to issue real JWTs for development and testing. This is intentionally scoped to identity only — no Verified Permissions, no Cedar, no authorization. It unblocks Issue #4's integration tests and lets developers get real tokens flowing through the proxy early.

### Acceptance Criteria

**Cognito User Pool:**

- Email-based sign-up
- App client with SRP auth enabled
- Custom attribute: `org_id` (string)
- Groups: `admin`, `member`, `viewer`, `top-secret-readers` (these become JWT `cognito:groups` claims)

**Two test tenants with users:**

Tenant `acme-corp`:

- `alice` — `admin` + `top-secret-readers` groups, `custom:org_id = "acme-corp"`
- `bob` — `member` + `top-secret-readers` groups, `custom:org_id = "acme-corp"`
- `charlie` — `viewer` group, `custom:org_id = "acme-corp"`

Tenant `initech`:

- `dave` — `admin` group, `custom:org_id = "initech"`
- `eve` — `member` group, `custom:org_id = "initech"`

Two tenants are required to test tenant isolation and feature flag scoping later.

**Delivery format:**

- CDK stack in `infra/dev/cognito/` — reads all inputs from `infra/dev/.env` (see Infrastructure Configuration Convention)
- `infra/dev/.env.example` committed to git with sensible defaults (creates or extends if already present)
- `infra/dev/.env` added to `.gitignore`
- A `README.md` with manual setup instructions as fallback
- Script to create test users: `xtask dev-setup --cognito`
  - On first run: copies `.env.example` → `.env` if missing, prompts for account-specific values
  - After deploy: writes Cognito outputs (`COGNITO_USER_POOL_ID`, `COGNITO_APP_CLIENT_ID`, `COGNITO_JWKS_URL`, `COGNITO_ISSUER`) back to `.env` and to `forgeguard.dev.toml`

**Output:**

- Populated values in both `infra/dev/.env` (for downstream CDK stacks) and `forgeguard.dev.toml` (for the Rust binary)
- A helper command to get a test JWT: `xtask dev-token --user alice`
- A helper to list all test users and their tenants: `xtask dev-users`

**Verification:** After running `xtask dev-setup --cognito`:

```bash
# Get a token for alice
TOKEN=$(cargo xtask dev-token --user alice)

# Decode it (no verification, just inspect claims)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .
# Should show: sub, iss, cognito:groups=["admin","top-secret-readers"], custom:org_id="acme-corp"
```

This is everything Issue #4 needs for its integration tests. Verified Permissions comes separately in #8b.

---

## Issue #8b: AWS bootstrap — Verified Permissions policy store for development

**Labels:** `infra`, `devex`, `authz`
**Blocked by:** #8a (Cognito must exist first — Verified Permissions policies reference user/group entities)
**Unblocks:** #5 (integration tests), #9

### Description

Provision the Verified Permissions policy store infrastructure for the TODO app example. This is the authorization infrastructure — separated from Cognito (#8a) so that identity and authorization can be developed and tested independently.

This issue covers two concerns with a clean split:

1. **Infrastructure provisioning** (`xtask dev-setup --vp`) — creates the empty VP policy store via CDK, writes `VP_POLICY_STORE_ID` to `.env` and `forgeguard.dev.toml`. One-time per environment.
2. **Policy sync** (`forgeguard policies sync --config forgeguard.toml`) — reads policy and group definitions from `forgeguard.toml`, compiles them to Cedar `permit`/`forbid` statements, and pushes them to Verified Permissions via the AWS SDK. Repeatable — run every time policies change.

The proxy only *queries* VP at runtime — it never writes policies. This keeps the proxy read-only (simpler, fewer IAM permissions) and makes policy deployment an explicit, auditable step.

Cedar actions use the three-part `Namespace:Action:Entity` format (e.g., `todo:read:list`, `todo:complete:item`). Policies reference these actions directly.

### Acceptance Criteria

**Verified Permissions Policy Store:**

- Cedar schema using `iam` for principals and `todo` namespace for resources.
  Namespace names are lowercase to match ForgeGuard's `Segment` convention and the entity type strings used in code (`iam::user`, `todo::list`).
  Entity IDs are FGRNs — the same string that appears in headers, logs, and API responses:

```cedar
namespace iam {
    entity user in [group] {};
    entity group {};
}

namespace todo {
    entity list {};
    entity item {};

    action "read-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "list-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "create-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "delete-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "archive-list" appliesTo { principal: [iam::user, iam::group], resource: [list] };
    action "read-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "create-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "update-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "delete-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
    action "complete-item" appliesTo { principal: [iam::user, iam::group], resource: [item] };
}
```

Note: Cedar action IDs are `Action+Entity` concatenated (e.g., `"read-list"`, `"complete-item"`) — this is the output of `QualifiedAction::vp_action_id()`. The three-part `Namespace:Action:Entity` format is ForgeGuard's canonical format; Cedar sees the concatenated form.

- Cedar policies compiled from the ForgeGuard policy/group definitions in `forgeguard.toml`. Each ForgeGuard policy statement becomes a Cedar `permit` or `forbid`:

**Allow policies → Cedar `permit` statements (one per group attachment):**

```cedar
// From Policy "todo-viewer" attached to Group "viewer"
permit(
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:viewer",
    action in [
        todo::action::"read-list",
        todo::action::"list-list",
        todo::action::"read-item"
    ],
    resource
);

// From Policy "todo-viewer" + "todo-editor" attached to Group "member"
permit(
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:member",
    action in [
        todo::action::"read-list",
        todo::action::"list-list",
        todo::action::"read-item",
        todo::action::"create-list",
        todo::action::"create-item",
        todo::action::"update-item",
        todo::action::"delete-item",
        todo::action::"complete-item"
    ],
    resource
);

// From Policy "todo-admin" attached to Group "admin"
permit(
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:admin",
    action,
    resource
);

// From Policy "todo-viewer" attached to Group "top-secret-readers"
permit(
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:top-secret-readers",
    action in [
        todo::action::"read-list",
        todo::action::"list-list",
        todo::action::"read-item"
    ],
    resource
);
```

**Deny policies → Cedar `forbid` statements with `unless` for `except` groups:**

```cedar
// From Policy "top-secret-deny" (project-wide deny with except)
// Blocks ALL principals from the top-secret list,
// UNLESS they are in the top-secret-readers group.
forbid(
    principal,
    action,
    resource == todo::list::"fgrn:acme-app:acme-corp:todo:list:top-secret"
) unless {
    principal in iam::group::"fgrn:acme-app:acme-corp:iam:group:top-secret-readers"
};
```

**Verified Permissions entity registration** — entities must be registered in the policy store with FGRN entity IDs:

```
# Groups
iam::group  "fgrn:acme-app:acme-corp:iam:group:admin"
iam::group  "fgrn:acme-app:acme-corp:iam:group:member"
iam::group  "fgrn:acme-app:acme-corp:iam:group:viewer"
iam::group  "fgrn:acme-app:acme-corp:iam:group:top-secret-readers"

# Users (members of groups — may belong to multiple groups)
iam::user  "fgrn:acme-app:acme-corp:iam:user:alice"    parents: [iam::group::"...:admin", iam::group::"...:top-secret-readers"]
iam::user  "fgrn:acme-app:acme-corp:iam:user:bob"      parents: [iam::group::"...:member", iam::group::"...:top-secret-readers"]
iam::user  "fgrn:acme-app:acme-corp:iam:user:charlie"   parents: [iam::group::"...:viewer"]
iam::user  "fgrn:acme-app:initech:iam:user:dave"        parents: [iam::group::"...:admin"]  # initech tenant
iam::user  "fgrn:acme-app:initech:iam:user:eve"         parents: [iam::group::"...:member"]  # initech tenant

# Resources (for resource-level authorization)
todo::list  "fgrn:acme-app:acme-corp:todo:list:top-secret"
```

The proxy constructs these same FGRNs at runtime from `project_id` + identity claims. The Verified Permissions entity IDs match exactly — no mapping, no translation.

**Verification scenarios after `xtask dev-setup --vp`:**

- Alice (admin + top-secret-readers) → `delete-list` on any list → ALLOW
- Alice → `read-list` on top-secret → ALLOW (excepted from forbid, has permit via admin)
- Charlie (viewer) → `read-list` on regular list → ALLOW
- Charlie → `read-list` on top-secret → DENY (forbid matches, charlie not in top-secret-readers)
- Charlie → `create-list` → DENY (viewer has no create permit)
- Bob (member + top-secret-readers) → `create-item` → ALLOW
- Bob → `read-list` on top-secret → ALLOW (excepted from forbid)

**Delivery format:**

- CDK stack in `infra/dev/verified-permissions/` — reads all inputs (including Cognito outputs from #8a) from `infra/dev/.env` (see Infrastructure Configuration Convention)
- Infrastructure provisioning: `xtask dev-setup --vp` (reads `COGNITO_USER_POOL_ID` from `.env`; fails with a clear error if Cognito outputs are missing)
  - After deploy: writes VP outputs (`VP_POLICY_STORE_ID`) back to `.env` and to `forgeguard.dev.toml`
- Policy sync: `forgeguard policies sync --config forgeguard.toml` (reads `VP_POLICY_STORE_ID` from config or env; compiles policies/groups to Cedar; pushes to VP)
  - Run after every policy/group change in `forgeguard.toml`
  - Logs each Cedar statement it creates and each VP API call it makes
  - Idempotent — safe to run repeatedly
- `xtask dev-setup --all` runs both #8a and #8b infrastructure provisioning together, chaining outputs. Run `forgeguard policies sync` after to push the initial policies.

**Verification:** After running `xtask dev-setup --vp` + `forgeguard policies sync`:

```bash
# Alice (admin) can delete any list
aws verifiedpermissions is-authorized \
  --policy-store-id $POLICY_STORE_ID \
  --principal '{"entityType":"iam::user","entityId":"fgrn:acme-app:acme-corp:iam:user:alice"}' \
  --action '{"actionType":"todo::action","actionId":"delete-list"}' \
  --resource '{"entityType":"todo::list","entityId":"any"}' \
  --entities '...'
# → ALLOW (alice is in admin group)

# Charlie (viewer) cannot delete lists
aws verifiedpermissions is-authorized \
  --policy-store-id $POLICY_STORE_ID \
  --principal '{"entityType":"iam::user","entityId":"fgrn:acme-app:acme-corp:iam:user:charlie"}' \
  --action '{"actionType":"todo::action","actionId":"delete-list"}' \
  --resource '{"entityType":"todo::list","entityId":"any"}' \
  --entities '...'
# → DENY (charlie is in viewer group — no delete permit)

# Alice can read the top-secret list (excepted from forbid via top-secret-readers)
aws verifiedpermissions is-authorized \
  --policy-store-id $POLICY_STORE_ID \
  --principal '{"entityType":"iam::user","entityId":"fgrn:acme-app:acme-corp:iam:user:alice"}' \
  --action '{"actionType":"todo::action","actionId":"read-list"}' \
  --resource '{"entityType":"todo::list","entityId":"fgrn:acme-app:acme-corp:todo:list:top-secret"}' \
  --entities '...'
# → ALLOW (alice is in top-secret-readers — forbid's unless exempts her)

# Charlie cannot read the top-secret list (forbid matches, not in top-secret-readers)
aws verifiedpermissions is-authorized \
  --policy-store-id $POLICY_STORE_ID \
  --principal '{"entityType":"iam::user","entityId":"fgrn:acme-app:acme-corp:iam:user:charlie"}' \
  --action '{"actionType":"todo::action","actionId":"read-list"}' \
  --resource '{"entityType":"todo::list","entityId":"fgrn:acme-app:acme-corp:todo:list:top-secret"}' \
  --entities '...'
# → DENY (charlie is NOT in top-secret-readers — forbid applies)
```

---

## Issue #9: End-to-end demo — TODO app behind the proxy

**Labels:** `demo`, `e2e`, `layer-4`
**Blocked by:** #7, #8a, #8b, #10
**Unblocks:** nothing (this IS the milestone)

### Description

A working end-to-end demonstration: a simple TODO API in Python (FastAPI) running behind the ForgeGuard proxy, with real Cognito JWTs for human users, static API keys for service-to-service callers, and real Verified Permissions authorization. Python is deliberate — it matches the tutorial in Doc 14 and proves the proxy is language-agnostic.

The demo app has zero ForgeGuard imports — it reads `X-ForgeGuard-*` headers injected by the proxy. It never sees a JWT, never calls Verified Permissions, never checks a policy.

### Acceptance Criteria

**Demo app** in `examples/todo-app/`:

- 6-8 endpoints matching the TODO tutorial (lists CRUD + items CRUD + complete + archive)
- One feature-gated endpoint: `GET /lists/{listId}/suggestions` (gated by `todo:ai-suggestions`)
- One endpoint that reads a flag from `X-ForgeGuard-Features` for branching behavior (e.g., `todo:max-upload-mb`)
- Reads `X-ForgeGuard-User-Id`, `X-ForgeGuard-Tenant-Id`, `X-ForgeGuard-Groups`, and `X-ForgeGuard-Features` from headers
- One resource-level access control demo: a `top-secret` list that only `top-secret-readers` group members can access (demonstrates DENY policy with `except`)
- In-memory data store (HashMap, no database dependency)
- Zero auth code in the app
- Zero feature flag code in the app (except reading the header)

**`forgeguard.toml`** in `examples/todo-app/`:

- Route mappings for all endpoints
- Public routes: `GET /health` (anonymous), `GET /docs/{page}` (opportunistic — personalized when logged in), `POST /webhooks/{provider}` (anonymous)
- Points to the Cognito + Verified Permissions resources from #8
- Policy definitions: `todo-viewer`, `todo-editor`, `todo-admin`, `top-secret-deny` (DENY with `except`)
- Group definitions: `admin`, `member`, `viewer`, `top-secret-readers` (with policy attachments)
- Inline feature flag definitions:
  - `todo:ai-suggestions`: boolean, default false, enabled for `acme-corp`, disabled for `initech` (the default)
  - `todo:max-upload-mb`: number, default 50, overridden to 100 for `acme-corp`, default for `initech`
  - `todo:premium-ai`: boolean, default false, 25% rollout (tenant-independent — tests deterministic hashing)

**Demo script** (`examples/todo-app/demo.sh` or documented in README):

```bash
# Terminal 1: Start the app (Python, runs natively on macOS/Linux)
cd examples/todo-app && python -m uvicorn app:app --port 3000

# Terminal 2: Start the proxy (Pingora, via Docker on macOS or native on Linux)
# On macOS:
docker compose -f examples/todo-app/docker-compose.yml up proxy
# On Linux (native):
cargo run -p forgeguard_proxy -- run --config examples/todo-app/forgeguard.toml

# ── CLI utility subcommands (cross-platform, no Pingora needed) ──

# Validate config without starting the proxy
cargo run -p forgeguard_cli -- check --config examples/todo-app/forgeguard.toml
# → ✓ examples/todo-app/forgeguard.toml is valid (12 routes, 3 public routes, 4 flags)

# Inspect the resolved route table
cargo run -p forgeguard_cli -- routes --config examples/todo-app/forgeguard.toml
# → Public routes (no auth):
# →   GET    /health                                  auth_mode=anonymous
# →   GET    /docs/{page}                             auth_mode=opportunistic
# →   ANY    /webhooks/{provider}                     auth_mode=anonymous
# →
# → Auth routes:
# →   GET    /lists                                   → todo:list:list               resource_param=-
# →   POST   /lists                                   → todo:create:list             resource_param=-
# →   GET    /lists/{listId}                          → todo:read:list               resource_param=listId
# →   ...

# Dump fully resolved config as JSON (useful for debugging env var overrides)
FORGEGUARD_LISTEN=0.0.0.0:9000 cargo run -p forgeguard_cli -- config --config examples/todo-app/forgeguard.toml --format json | jq .listen_addr
# → "0.0.0.0:9000"

# Terminal 3: Test it
TOKEN_ALICE=$(cargo xtask dev-token --user alice)       # admin, acme-corp
TOKEN_BOB=$(cargo xtask dev-token --user bob)           # member, acme-corp
TOKEN_CHARLIE=$(cargo xtask dev-token --user charlie)   # viewer, acme-corp
TOKEN_DAVE=$(cargo xtask dev-token --user dave)         # admin, initech
TOKEN_EVE=$(cargo xtask dev-token --user eve)           # member, initech

# ── Public routes (no auth required) ──

# Health check — anonymous, no token, no API key, just works
curl -s http://localhost:8000/health | jq .
# → 200 {"status": "ok"}
# No X-ForgeGuard-* identity headers — only X-ForgeGuard-Client-Ip.

# Incoming webhook — anonymous, no auth required
curl -s -X POST http://localhost:8000/webhooks/stripe \
  -H "Content-Type: application/json" \
  -d '{"event":"payment.completed"}' | jq .
# → 200 {"received": true}

# ── Opportunistic public routes ──

# Docs page without credentials — works, anonymous view
curl -s http://localhost:8000/docs/getting-started | jq .
# → 200 (app renders public docs view)
# Upstream sees X-ForgeGuard-Client-Ip but no identity headers.

# Docs page with credentials — works, personalized view
curl -s http://localhost:8000/docs/getting-started \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .
# → 200 (app renders personalized view: bookmarks, edit buttons)
# Upstream sees X-ForgeGuard-User-Id, X-ForgeGuard-Tenant-Id, etc.

# Docs page with expired token — still works, falls back to anonymous
curl -s http://localhost:8000/docs/getting-started \
  -H "Authorization: Bearer expired-token-here" | jq .
# → 200 (app renders public docs view — NOT 401)
# Upstream sees X-ForgeGuard-Client-Ip but no identity headers.

# But auth routes still require credentials (public routes don't weaken anything)
curl -s http://localhost:8000/lists | jq .
# → 401 {"error":"Unauthorized"}

# ── Auth enforcement ──

# alice (admin) creates a list — should succeed
curl -s -X POST http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{"name":"Sprint tasks"}' | jq .
# → 201

# charlie (viewer) tries to create a list — should be denied
curl -s -X POST http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_CHARLIE" \
  -H "Content-Type: application/json" \
  -d '{"name":"My list"}' | jq .
# → 403 {"error":"Forbidden","action":"todo:create:list"}

# charlie (viewer) reads lists — should succeed
curl -s http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_CHARLIE" | jq .
# → 200

# no token — should be rejected
curl -s http://localhost:8000/lists | jq .
# → 401 {"error":"Unauthorized"}

# ── API key authentication (service-to-service) ──

# API keys are defined in forgeguard.toml in plaintext (dev/testing only).
# The proxy tries api_key first (fast HashMap lookup), then jwt.

# CI pipeline key (member group) creates an item — should succeed
curl -s -X POST http://localhost:8000/lists/list-001/items \
  -H "X-API-Key: sk-test-bob-member" \
  -H "Content-Type: application/json" \
  -d '{"title":"Deployed by CI"}' | jq .
# → 201

# viewer key tries to create — should be denied
curl -s -X POST http://localhost:8000/lists \
  -H "X-API-Key: sk-test-charlie-viewer" \
  -H "Content-Type: application/json" \
  -d '{"name":"Nope"}' | jq .
# → 403 {"error":"Forbidden","action":"todo:create:list"}

# invalid key — should be rejected
curl -s http://localhost:8000/lists \
  -H "X-API-Key: sk-does-not-exist" | jq .
# → 401 {"error":"Unauthorized"}

# debug/context shows provider = "static_api_key" for API key auth
curl -s http://localhost:8000/debug/context \
  -H "X-API-Key: sk-test-alice-admin" | jq .provider
# → "static_api_key"

# debug/context shows provider = "cognito_jwt" for JWT auth
curl -s http://localhost:8000/debug/context \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .provider
# → "cognito_jwt"

# ── Feature flags: the enabled path ──

# alice (acme-corp) requests AI suggestions — should succeed
# (todo:ai-suggestions is enabled for acme-corp in forgeguard.toml)
curl -s http://localhost:8000/lists/list-001/suggestions \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .
# → 200 {"suggestions": ["Buy groceries", "Review PR #42"]}

# ── Feature flags: the disabled path ──

# dave (initech) requests the same endpoint — should get 404
# (todo:ai-suggestions is NOT enabled for initech — default is false)
curl -s http://localhost:8000/lists/list-001/suggestions \
  -H "Authorization: Bearer $TOKEN_DAVE" | jq .
# → 404 {"error":"Not Found"}
# The proxy never forwarded the request. The endpoint doesn't exist for this tenant.

# dave CAN access non-gated endpoints — he's authenticated and authorized
curl -s http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_DAVE" | jq .
# → 200 (empty list — different tenant, different data)

# ── Feature flags: header injection ──

# All proxied requests get the resolved flags as a JSON header,
# regardless of whether the route is gated:
curl -s http://localhost:8000/debug/context \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .
# → {
#     "user_id": "alice",
#     "tenant_id": "acme-corp",
#     "groups": "admin,top-secret-readers",
#     "provider": "cognito_jwt",
#     "client_ip": "127.0.0.1",
#     "features": {"todo:ai-suggestions": true, "todo:max-upload-mb": 100, "todo:premium-ai": false},
#     "max_upload_mb": 100
#   }

curl -s http://localhost:8000/debug/context \
  -H "Authorization: Bearer $TOKEN_DAVE" | jq .
# → {
#     "user_id": "dave",
#     "tenant_id": "initech",
#     "groups": "admin",
#     "client_ip": "127.0.0.1",
#     "features": {"todo:ai-suggestions": false, "todo:max-upload-mb": 50, "todo:premium-ai": false},
#     "max_upload_mb": 50
#   }
# Same app, same proxy, different tenant → different flag values.

# ── Resource-level access control: top-secret list ──

# alice (admin + top-secret-readers) reads the top-secret list — should succeed
# The forbid policy has an except for top-secret-readers, so alice is not blocked.
curl -s http://localhost:8000/lists/top-secret \
  -H "Authorization: Bearer $TOKEN_ALICE" | jq .
# → 200

# bob (member + top-secret-readers) reads the top-secret list — should succeed
curl -s http://localhost:8000/lists/top-secret \
  -H "Authorization: Bearer $TOKEN_BOB" | jq .
# → 200

# charlie (viewer, NOT in top-secret-readers) reads the top-secret list — should be denied
# The forbid policy matches charlie (he's not excepted), so access is blocked.
curl -s http://localhost:8000/lists/top-secret \
  -H "Authorization: Bearer $TOKEN_CHARLIE" | jq .
# → 403 {"error":"Forbidden","action":"todo:read:list"}

# charlie CAN still read regular lists — the forbid only applies to the top-secret resource
curl -s http://localhost:8000/lists \
  -H "Authorization: Bearer $TOKEN_CHARLIE" | jq .
# → 200
```

**Demo app feature flag usage** (in `app.py`):

```python
import json

@app.get("/health")
async def health():
    """Public endpoint — no auth required, no X-ForgeGuard-* headers expected."""
    return {"status": "ok"}


@app.post("/webhooks/{provider}")
async def webhook(provider: str, request: Request):
    """Public endpoint — incoming webhooks from third parties, no auth."""
    body = await request.json()
    return {"received": True, "provider": provider}


@app.get("/lists/{list_id}/suggestions")
async def get_suggestions(list_id: str, request: Request):
    # This endpoint only receives requests when todo:ai-suggestions is enabled
    # for this tenant — the proxy returns 404 otherwise.
    # The app doesn't check the flag. It just handles the request.
    return {"suggestions": ["Buy groceries", "Review PR #42"]}


@app.get("/debug/context")
async def debug_context(request: Request):
    """Debug endpoint that echoes the full resolved context."""
    features = json.loads(request.headers.get("X-ForgeGuard-Features", "{}"))
    return {
        "user_id": request.headers.get("X-ForgeGuard-User-Id"),
        "tenant_id": request.headers.get("X-ForgeGuard-Tenant-Id"),
        "groups": request.headers.get("X-ForgeGuard-Groups"),
        "provider": request.headers.get("X-ForgeGuard-Auth-Provider"),
        "principal": request.headers.get("X-ForgeGuard-Principal"),
        "client_ip": request.headers.get("X-ForgeGuard-Client-Ip"),
        "features": features,
        "max_upload_mb": features.get("todo:max-upload-mb", 50),
    }
```

**Acceptance:**

Public routes:

- `GET /health` with no credential → 200 (proxied, no auth)
- `POST /webhooks/stripe` with no credential → 200 (proxied, no auth)
- Public routes have only `X-ForgeGuard-Client-Ip` header (no identity/feature headers)
- Auth routes still require credentials (`GET /lists` with no token → 401)
- Public routes work regardless of `default_policy` setting

Origin IP:

- `X-ForgeGuard-Client-Ip` present on all proxied requests (authenticated and public)
- Debug endpoint shows `client_ip` field from the injected header

Auth enforcement:

- Admin creates a resource → 201
- Viewer tries to create → 403
- Viewer reads → 200
- No token → 401

API key authentication:

- API key with member group creates item → 201
- API key with viewer group tries to create → 403 (same authz rules as JWT — provider doesn't matter)
- Invalid API key → 401
- `X-ForgeGuard-Auth-Provider` is `static_api_key` for API key requests
- `X-ForgeGuard-Auth-Provider` is `cognito_jwt` for JWT requests
- Request with both `Authorization: Bearer` and `X-API-Key` → api_key provider wins (first in chain)
- API key resolves to correct tenant, correct groups, correct user_id as configured in TOML

Resource-level access control (top-secret list):

- Alice (admin + top-secret-readers) reads top-secret list → 200 (excepted from forbid)
- Bob (member + top-secret-readers) reads top-secret list → 200 (excepted from forbid)
- Charlie (viewer, NOT in top-secret-readers) reads top-secret list → 403 (forbid matches)
- Charlie reads a regular list → 200 (forbid only applies to the top-secret resource)
- DENY policy with `except` compiles correctly to Cedar `forbid...unless`

Feature flags — the critical scenarios:

- `acme-corp` user hits gated endpoint (flag enabled) → 200 (request reaches the app)
- `initech` user hits the same gated endpoint (flag disabled, default) → 404 (proxy blocks, app never sees the request)
- Both tenants hit a non-gated endpoint → 200 (flags don't block, but the `X-ForgeGuard-Features` header shows different values per tenant)
- `X-ForgeGuard-Features` header is present on ALL proxied requests, contains valid JSON, and correctly reflects per-tenant flag resolution
- Debug endpoint for `acme-corp` shows `todo:max-upload-mb: 100` (overridden)
- Debug endpoint for `initech` shows `todo:max-upload-mb: 50` (default)
- Proxy logs show `gate=todo:ai-suggestions` on feature-gated requests

CLI subcommands (cross-platform via `forgeguard_cli` — no Pingora/Docker needed):

- `forgeguard check --config examples/todo-app/forgeguard.toml` exits 0 with route/flag/policy/group counts
- `forgeguard routes --config examples/todo-app/forgeguard.toml` prints all public + auth routes
- `forgeguard config --config examples/todo-app/forgeguard.toml --format json` prints resolved config
- `FORGEGUARD_LISTEN=0.0.0.0:9000 forgeguard config --config ... --format json` shows overridden listen address
- `forgeguard --help` shows all subcommands with descriptions
- `forgeguard-proxy run --help` shows env var hints for each flag

General:

- Proxy startup log shows flag count and provider list
- Health check returns `healthy` with correct flag count
- README explains the full demo from scratch including both tenants and both auth methods (JWT + API key) (prerequisites: Rust, Python, AWS credentials, CDK-deployed infra from #8a + #8b)

---

## Issue #10: Feature flag proxy integration

**Crate:** `crates/http/` (HTTP adapter)
**Labels:** `feature-flags`, `http`, `proxy`
**Blocked by:** #1 (flag types + evaluation logic), #6 (config structure with `FeaturesConfig`)
**Unblocks:** #9 (demo gates the `/suggestions` endpoint)

### Description

Wire the feature flag evaluation from `forgeguard_core` (Issue #1) into the HTTP adapter and proxy request lifecycle. The pure flag types, evaluation logic, `deterministic_bucket`, kill switch, rollout variants, and override hierarchy are all defined in Issue #1. This issue is exclusively about the HTTP/proxy integration layer.

### Acceptance Criteria

**Route-level gating** (in `forgeguard_http`):

- If `feature_gate` is set on a `RouteMapping` and the flag evaluates to false/disabled for the current user+tenant, the proxy returns 404 before the authorization check
- The flag check happens after identity resolution (needs `user_id` + `tenant_id`) but before `PolicyEngine::evaluate`
- 404 response body: `{ "error": "Not Found" }` — the endpoint doesn't "exist" for this user
- Unknown flag name in `feature_gate` → startup validation error (caught by config validation in #6)

**Header injection** (in `forgeguard_http`):

- `X-ForgeGuard-Features` header injected on all authenticated proxied requests, containing JSON of all evaluated flags:
  ```
  X-ForgeGuard-Features: {"todo:ai-suggestions":true,"todo:max-upload-mb":100,"todo:premium-ai":false}
  ```
- Non-gated routes still receive the features header — the app can branch on flags without route gating

**Debug endpoint** (in `forgeguard_http`, served by proxy):

- `GET /.well-known/forgeguard/flags?user_id=X&tenant_id=Y` returns all flag evaluations with resolution reasons (default, rollout, tenant_override, user_override, user_tenant_override, disabled)
- Health check includes `flags_count` field

### Tests

- Feature-gated route + flag enabled → 200 (proceeds to authz)
- Feature-gated route + flag disabled → 404 (never reaches authz)
- Feature-gated route + kill switch (`enabled = false`) → 404 (kill switch returns default=false)
- Non-gated route → `X-ForgeGuard-Features` header present with all resolved flags as JSON
- `X-ForgeGuard-Features` header values differ per tenant (acme-corp vs initech)
- Debug endpoint returns resolution reasons for each flag
- Health check `flags_count` matches number of configured flags

---

## Issue #11 (optional): Config hot-reload without proxy restart

**Labels:** `proxy`, `operational`, `optional`, `post-target-b`
**Blocked by:** #7
**Unblocks:** nothing (operational improvement)

### Description

The proxy loads `forgeguard.toml` at startup and holds the parsed config in memory for the lifetime of the process. Changes to routes, feature flags, static API keys, public routes, or policy/group definitions require a proxy restart.

Pingora's zero-downtime graceful restart (`SIGQUIT` → drain → replace) covers binary upgrades, but a full restart is heavyweight for config-only changes. This issue adds SIGHUP-triggered config reload so operators can update `forgeguard.toml` and apply changes without dropping connections.

**Note on authorization model freshness:** Cedar policy changes in Verified Permissions are already picked up without restart — the `AuthzCache` TTL (default 60s) handles this. Group membership changes flow through JWT claims per-request. This issue is specifically about **local config** that the proxy holds in memory.

### What reloads on SIGHUP

| Component | Current (target-b) | After this issue |
|---|---|---|
| Route mappings (`[[routes]]`) | Restart required | SIGHUP reload |
| Public routes (`[[public_routes]]`) | Restart required | SIGHUP reload |
| Feature flag definitions (`[features.flags.*]`) | Restart required | SIGHUP reload |
| Static API keys (`[[auth.api_key.keys]]`) | Restart required | SIGHUP reload |
| Policy/group definitions | Restart + `forgeguard policies sync` | SIGHUP reload + Cedar recompile + VP push |
| Auth provider config (JWKS URL, issuer) | Restart required | Restart required (rare, structural change) |
| Listen address, upstream URL | Restart required | Restart required (socket-level change) |

### Approach

Use `ArcSwap` for hot-swappable config behind the `ForgeGuardProxy`:

```rust
pub struct ForgeGuardProxy {
    config: Arc<ArcSwap<ReloadableConfig>>,
    // ... non-reloadable fields (upstream peer, identity chain structure)
}

pub struct ReloadableConfig {
    route_matcher: RouteMatcher,
    public_matcher: PublicRouteMatcher,
    flag_config: FlagConfig,
    api_key_resolver: StaticApiKeyResolver,
}
```

On `SIGHUP`:
1. Re-read and validate `forgeguard.toml`
2. Diff against current config, log changes
3. Swap `ReloadableConfig` atomically via `ArcSwap::store`
4. In-flight requests see the old config (they already hold an `Arc`); new requests pick up the new config

### Acceptance Criteria

- `kill -HUP <proxy_pid>` triggers config reload
- Invalid config on reload → log error, keep running with previous config (never crash)
- Route table changes take effect on next request after reload
- Feature flag changes take effect on next request after reload
- Static API key additions/removals take effect on next request after reload
- Structured log entry on successful reload: `INFO reload config_path=forgeguard.toml routes=12 public_routes=3 flags=4`
- Structured log entry on failed reload: `ERROR reload_failed config_path=forgeguard.toml error="..."`
- Auth provider config changes logged as warning: "auth provider config changed — restart required to apply"

---

## Issue Priority and Parallelism

```
Week 1:  #1 (core) + #8a (Cognito infra) in parallel
         #2 (authn-core) + #3 (authz-core) can start after #1
         #10 (feature flags) can start after #1

Week 2:  #4 (authn I/O) + #5 (authz I/O) in parallel (after their core deps)
         #4 integration tests unblocked once #8a lands
         #8b (Verified Permissions infra) can start once #8a is done
         #6 (forgeguard_http) in parallel
         #10 (feature flags) finishes — pure crate work done, HTTP adapter integration ready

Week 3:  #5 integration tests unblocked once #8b lands
         #7 (proxy binary) — Pingora runtime wiring (authn + authz + flags + forgeguard_http)
         CLI subcommands (check, config, routes) available cross-platform via forgeguard_cli
         #9 (e2e demo) — the milestone
```

All Layer 1 issues (#1, #2, #3, #10) can be one-developer work. #4 and #5 can be done in parallel by two developers. #7 is the integration point where `forgeguard_http` types meet Pingora's `ProxyHttp` lifecycle. #8a (Cognito infra) is independent and should start immediately — it's the long pole that unblocks #4 integration tests and #8b.

**Platform note:** The proxy (#7) is Linux-only (Pingora). macOS developers run it via Docker (`docker-compose.yml` provided in #9). All pure crates (#1, #2, #3, #10), I/O crates (#4, #5), and the HTTP adapter library (#6 `forgeguard_http`) compile on macOS. Config validation and route inspection run natively via `forgeguard_cli` — only the `forgeguard_proxy` runtime requires Linux.
