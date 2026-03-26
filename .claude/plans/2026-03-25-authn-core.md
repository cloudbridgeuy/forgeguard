# forgeguard_authn_core Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Implement the identity resolution abstraction for `forgeguard_authn_core` — `Credential`, `Identity`, `IdentityResolver` trait, `IdentityChain`, `StaticApiKeyResolver`, `JwtClaims`, and `IdentityBuilder`.

**Architecture:** Pure crate (no I/O) in the Functional Core. Every type uses Parse Don't Validate — constructors are `pub(crate)`, inner fields are private. All types compile to `wasm32-unknown-unknown`. Module-per-concern, flat file structure.

**Tech Stack:** Rust, `thiserror`, `serde`/`serde_json`, `chrono`, `forgeguard_core` (typed IDs)

**Patterns applied:**

- **MUST:** Functional Core / Imperative Shell (`~/.claude/patterns/functional-core-imperative-shell.md`) — entire crate is the functional core, zero I/O
- **MUST:** Parse Don't Validate (`~/.claude/patterns/parse-dont-validate.md`) — `Identity` only constructed via `pub(crate)` constructor; `Credential` variants carry raw strings parsed at boundary
- **MUST:** Type-Driven Development (`~/.claude/patterns/type-driven-development.md`) — types are the spec; private fields with getter methods
- **MUST:** Make Impossible States Impossible (`~/.claude/patterns/make-impossible-states-impossible.md`) — `Credential` as sum type, `Identity` uncreatable outside crate
- **MUST:** Algebraic Data Types (`~/.claude/patterns/algebraic-data-types.md`) — `Credential` enum, `Error` enum with per-variant data
- **SHOULD:** Composition over Inheritance (`~/.claude/patterns/composition-over-inheritance.md`) — `IdentityChain` composes `IdentityResolver` trait objects via `Vec<Arc<dyn IdentityResolver>>`

**Does NOT apply:**

- CQRS — no command/query separation needed; this is a pure type library
- Data-Oriented Design — small number of entities, not a hot-path batch processor

**Design doc:** `.claude/designs/authn-core-shaping.md`
**Issue spec:** `.claude/designs/github-issues.md` (Issue #2 section, starting at line 1571)

---

## Module Layout

```
crates/authn-core/src/
  lib.rs              — re-exports, clippy denials, module declarations
  error.rs            — Error enum, Result<T> alias
  credential.rs       — Credential enum (Bearer, ApiKey)
  identity.rs         — Identity struct (private fields, getters, pub(crate) constructor)
  resolver.rs         — IdentityResolver trait
  chain.rs            — IdentityChain orchestrator
  static_api_key.rs   — StaticApiKeyResolver (in-memory HashMap)
  jwt_claims.rs       — JwtClaims data type
  builder.rs          — IdentityBuilder (behind test-support feature)
```

---

## Parallel Groups

### Group 1 — Foundation types (independent, can run in parallel)

These modules have no dependencies on each other. They only depend on `forgeguard_core` and `std`.

#### Task 1.1: `error.rs` — Error enum and Result alias

**File:** `crates/authn-core/src/error.rs`

```rust
//! Error types for forgeguard_authn_core.

/// The error type for all authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No resolver configured for the given credential type.
    #[error("no resolver available for credential type: {credential_type}")]
    NoResolver { credential_type: String },
    /// JWT token has expired.
    #[error("token expired")]
    TokenExpired,
    /// Invalid issuer in the token.
    #[error("invalid issuer: expected '{expected}', got '{actual}'")]
    InvalidIssuer { expected: String, actual: String },
    /// Invalid audience claim.
    #[error("invalid audience")]
    InvalidAudience,
    /// Required claim is missing from the token.
    #[error("missing required claim: {0}")]
    MissingClaim(String),
    /// Token structure or format is malformed.
    #[error("malformed token: {0}")]
    MalformedToken(String),
    /// Credential is invalid or unrecognized.
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;
```

**Tests:** Verify `Display` output for every variant.

#### Task 1.2: `credential.rs` — Credential enum

**File:** `crates/authn-core/src/credential.rs`

```rust
//! Protocol-agnostic credential types.

use serde::{Deserialize, Serialize};

/// A raw, unvalidated credential. Protocol adapters produce these.
/// Identity resolvers consume them. Neither knows about the other's world.
///
/// No mention of `Authorization: Bearer` or `X-API-Key` headers — those are
/// HTTP concepts. This enum describes what the credential _is_, not where
/// it came from.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Credential {
    /// A bearer token (JWT or opaque).
    Bearer(String),
    /// An API key.
    ApiKey(String),
}

impl Credential {
    /// Diagnostic label for this credential type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Credential::Bearer(_) => "bearer",
            Credential::ApiKey(_) => "api-key",
        }
    }
}
```

**Tests:** `type_name()` returns correct values, serde round-trip.

#### Task 1.3: `jwt_claims.rs` — JwtClaims data type

**File:** `crates/authn-core/src/jwt_claims.rs`

```rust
//! Raw JWT claims structure.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Raw JWT claims as deserialized from the token payload.
/// This is untrusted input — it becomes an Identity only after validation
/// by a resolver (e.g., CognitoJwtResolver in forgeguard_authn).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject — the principal identifier.
    pub sub: String,
    /// Issuer — the token issuer URL.
    pub iss: String,
    /// Audience — intended recipient of the token.
    pub aud: Option<String>,
    /// Expiration time (seconds since epoch).
    pub exp: u64,
    /// Issued-at time (seconds since epoch).
    pub iat: u64,
    /// Token use — "access" or "id".
    pub token_use: String,
    /// OAuth scopes (space-separated in the original token).
    pub scope: Option<String>,
    /// Cognito group membership.
    #[serde(rename = "cognito:groups")]
    pub cognito_groups: Option<Vec<String>>,
    /// Any additional claims not captured above.
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}
```

**Tests:** Serde round-trip, deserialization from JSON with `cognito:groups` field.

---

### Group 2 — Identity struct (depends on Group 1 for Error)

#### Task 2.1: `identity.rs` — Identity struct

**File:** `crates/authn-core/src/identity.rs`

Depends on: `error.rs` (for crate::Result), `forgeguard_core` types.

```rust
//! Resolved, trusted identity type.

use chrono::{DateTime, Utc};
use serde::Serialize;

use forgeguard_core::{GroupName, TenantId, UserId};

/// A resolved, trusted identity. Produced only by IdentityResolver implementations.
/// Protocol adapters and the authz layer consume this without knowing how it was produced.
///
/// This is ForgeGuard's equivalent of `aws_credential_types::Credentials`.
#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    expiry: Option<DateTime<Utc>>,
    /// Which resolver produced this — for logging/metrics, never for branching.
    resolver: &'static str,
    /// Resolver-specific claims preserved for custom policy evaluation.
    extra: Option<serde_json::Value>,
}

impl Identity {
    /// Construct a new Identity. Only callable within this crate.
    pub(crate) fn new(
        user_id: UserId,
        tenant_id: Option<TenantId>,
        groups: Vec<GroupName>,
        expiry: Option<DateTime<Utc>>,
        resolver: &'static str,
        extra: Option<serde_json::Value>,
    ) -> Self {
        Self {
            user_id,
            tenant_id,
            groups,
            expiry,
            resolver,
            extra,
        }
    }

    pub fn user_id(&self) -> &UserId { &self.user_id }
    pub fn tenant_id(&self) -> Option<&TenantId> { self.tenant_id.as_ref() }
    pub fn groups(&self) -> &[GroupName] { &self.groups }
    pub fn expiry(&self) -> Option<&DateTime<Utc>> { self.expiry.as_ref() }
    pub fn resolver(&self) -> &'static str { self.resolver }
    pub fn extra(&self) -> Option<&serde_json::Value> { self.extra.as_ref() }

    /// Whether this identity has expired relative to `now`.
    pub fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        self.expiry.as_ref().is_some_and(|exp| exp < now)
    }
}
```

**Tests:**
- Construct via `Identity::new(...)` inside the test module (same crate = `pub(crate)` visible)
- Getters return correct values
- `is_expired()`: expired, not expired, no expiry

---

### Group 3 — Resolver trait + implementations (depends on Groups 1-2)

These three tasks depend on Identity and Credential but are **independent of each other**.

#### Task 3.1: `resolver.rs` — IdentityResolver trait

**File:** `crates/authn-core/src/resolver.rs`

```rust
//! Pluggable identity resolution trait.

use std::future::Future;
use std::pin::Pin;

use crate::credential::Credential;
use crate::identity::Identity;
use crate::error::Result;

/// Each resolver knows whether it can handle a credential type
/// and how to resolve it into a trusted Identity.
///
/// Modeled after `aws_credential_types::provider::ProvideCredentials`.
///
/// NOTE: No `http` dependency. This trait operates on Credentials,
/// not on protocol-specific request types.
pub trait IdentityResolver: Send + Sync {
    /// Name for logging and diagnostics.
    fn name(&self) -> &'static str;

    /// Can this resolver handle this credential type?
    /// Fast, synchronous check — typically just a match on the variant.
    fn can_resolve(&self, credential: &Credential) -> bool;

    /// Validate the credential and produce a trusted Identity.
    /// Async because I/O implementations (JWKS fetch, token introspection)
    /// will need it.
    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>>;
}
```

**Tests:** No unit tests (trait definition only). Tested via implementations in tasks 3.2, 3.3, and 4.1.

#### Task 3.2: `static_api_key.rs` — StaticApiKeyResolver

**File:** `crates/authn-core/src/static_api_key.rs`

```rust
//! In-memory API key resolver. Pure, no I/O.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use forgeguard_core::{GroupName, TenantId, UserId};

use crate::credential::Credential;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::resolver::IdentityResolver;

/// Metadata for a static API key entry.
pub(crate) struct ApiKeyEntry {
    pub(crate) user_id: UserId,
    pub(crate) tenant_id: Option<TenantId>,
    pub(crate) groups: Vec<GroupName>,
    pub(crate) description: String,
}

/// In-memory API key resolver. Keys are loaded from config at startup.
/// No I/O — the key map is passed in at construction time.
pub struct StaticApiKeyResolver {
    keys: HashMap<String, ApiKeyEntry>,
}

impl StaticApiKeyResolver {
    /// Create a new resolver with the given key map.
    pub fn new(keys: HashMap<String, ApiKeyEntry>) -> Self {
        Self { keys }
    }
}

impl IdentityResolver for StaticApiKeyResolver {
    fn name(&self) -> &'static str {
        "static_api_key"
    }

    fn can_resolve(&self, credential: &Credential) -> bool {
        matches!(credential, Credential::ApiKey(_))
    }

    fn resolve(
        &self,
        credential: &Credential,
    ) -> Pin<Box<dyn Future<Output = Result<Identity>> + Send + '_>> {
        let result = match credential {
            Credential::ApiKey(key) => match self.keys.get(key.as_str()) {
                Some(entry) => Ok(Identity::new(
                    entry.user_id.clone(),
                    entry.tenant_id.clone(),
                    entry.groups.clone(),
                    None, // API keys don't expire via this resolver
                    "static_api_key",
                    None,
                )),
                None => Err(Error::InvalidCredential("unknown API key".into())),
            },
            _ => Err(Error::InvalidCredential(
                "expected ApiKey credential".into(),
            )),
        };
        Box::pin(std::future::ready(result))
    }
}
```

**Tests:**
- Known key resolves to correct Identity (user_id, tenant_id, groups)
- Unknown key returns `Error::InvalidCredential`
- Bearer credential returns `can_resolve() == false`

#### Task 3.3: `builder.rs` — IdentityBuilder (test-support feature)

**File:** `crates/authn-core/src/builder.rs`

**Cargo.toml change:** Add `[features] test-support = []`

```rust
//! Test builder for Identity.

use chrono::{DateTime, Utc};
use forgeguard_core::{GroupName, TenantId, UserId};

use crate::identity::Identity;

/// Builder for constructing Identity values in tests.
/// Available only with the `test-support` feature.
pub struct IdentityBuilder {
    user_id: UserId,
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    expiry: Option<DateTime<Utc>>,
    resolver: &'static str,
    extra: Option<serde_json::Value>,
}

impl IdentityBuilder {
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            tenant_id: None,
            groups: Vec::new(),
            expiry: None,
            resolver: "test",
            extra: None,
        }
    }

    pub fn tenant(mut self, id: TenantId) -> Self {
        self.tenant_id = Some(id);
        self
    }

    pub fn groups(mut self, groups: Vec<GroupName>) -> Self {
        self.groups = groups;
        self
    }

    pub fn resolver(mut self, name: &'static str) -> Self {
        self.resolver = name;
        self
    }

    pub fn expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.expiry = Some(expiry);
        self
    }

    pub fn extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = Some(extra);
        self
    }

    pub fn build(self) -> Identity {
        Identity::new(
            self.user_id,
            self.tenant_id,
            self.groups,
            self.expiry,
            self.resolver,
            self.extra,
        )
    }
}
```

**Tests:** Build with all fields set, verify getters. Build with defaults only, verify defaults.

---

### Group 4 — Chain orchestrator (depends on Groups 1-3)

#### Task 4.1: `chain.rs` — IdentityChain

**File:** `crates/authn-core/src/chain.rs`

Depends on: `resolver.rs`, `credential.rs`, `identity.rs`, `error.rs`.

```rust
//! Identity resolution chain — tries resolvers in order.

use std::sync::Arc;

use crate::credential::Credential;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::resolver::IdentityResolver;

/// Tries identity resolvers in order. First one that can resolve the
/// credential owns the outcome — success or failure, the chain stops.
///
/// Mirrors the AWS SDK's DefaultCredentialsChain pattern.
pub struct IdentityChain {
    resolvers: Vec<Arc<dyn IdentityResolver>>,
}

impl IdentityChain {
    /// Create a new chain with the given resolvers (tried in order).
    pub fn new(resolvers: Vec<Arc<dyn IdentityResolver>>) -> Self {
        Self { resolvers }
    }

    /// Resolve a credential into an Identity.
    /// First resolver that `can_resolve()` owns the outcome.
    pub async fn resolve(&self, credential: &Credential) -> Result<Identity> {
        for resolver in &self.resolvers {
            if !resolver.can_resolve(credential) {
                continue;
            }
            return resolver.resolve(credential).await;
        }
        Err(Error::NoResolver {
            credential_type: credential.type_name().to_string(),
        })
    }
}
```

**Tests (using mock resolvers):**
- Chain with two resolvers: Bearer → first handles, ApiKey → second handles
- Resolver returns `can_resolve() == false` → skipped, next tried
- Resolver claims credential but fails → error returned (no fallthrough)
- No resolver matches → `Error::NoResolver`
- Empty chain → `Error::NoResolver`

---

### Group 5 — Wiring and finalization (depends on all above)

#### Task 5.1: `lib.rs` — Module declarations and re-exports

**File:** `crates/authn-core/src/lib.rs`

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod chain;
pub mod credential;
pub mod error;
pub mod identity;
pub mod jwt_claims;
pub mod resolver;
pub mod static_api_key;

#[cfg(feature = "test-support")]
pub mod builder;

pub use chain::IdentityChain;
pub use credential::Credential;
pub use error::{Error, Result};
pub use identity::Identity;
pub use jwt_claims::JwtClaims;
pub use resolver::IdentityResolver;
pub use static_api_key::StaticApiKeyResolver;

#[cfg(feature = "test-support")]
pub use builder::IdentityBuilder;
```

#### Task 5.2: `Cargo.toml` — Add test-support feature

Add to `crates/authn-core/Cargo.toml`:

```toml
[features]
test-support = []

[dev-dependencies]
tokio = { workspace = true, features = ["rt", "macros"] }
```

Note: `tokio` as a dev-dependency only — needed to run `#[tokio::test]` for async chain tests. NOT a runtime dependency.

#### Task 5.3: Run `cargo xtask lint` and fix

Run `cargo xtask lint` to verify all changes pass. Fix any issues.

#### Task 5.4: Update `crates/authn-core/README.md`

Update README to reflect actual crate contents (currently describes typestate flows which are not what this crate does).

---

## Dependency Graph

```
Group 1 (parallel):  error.rs  |  credential.rs  |  jwt_claims.rs
                          \            |            /
Group 2:                    identity.rs
                          /      |        \
Group 3 (parallel): resolver.rs | static_api_key.rs | builder.rs
                          \      |        /
Group 4:                   chain.rs
                               |
Group 5:              lib.rs + Cargo.toml + lint + README
```

---

## Verification

After all tasks complete:

1. `cargo xtask lint` exits 0
2. `cargo tree -p forgeguard_authn_core` shows NO `http`, `tokio`, `reqwest`, or AWS SDK dependencies (tokio only in dev-dependencies)
3. All tests pass including chain tests with mock resolvers
4. `Identity` cannot be constructed outside the crate (verified by chain/static_api_key tests using the `pub(crate)` constructor within the crate)
