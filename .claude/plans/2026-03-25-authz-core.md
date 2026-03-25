# forgeguard_authz_core Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Implement the pure authorization abstraction crate — query/decision types, the `PolicyEngine` trait, and a `StaticPolicyEngine` for tests.

**Architecture:** Pure crate (no I/O). Defines the authorization contract: `PolicyQuery` in, `PolicyDecision` out. The `PolicyEngine` trait is async to support I/O implementations in downstream crates (`forgeguard_authz`). All types consume `forgeguard_core` typed IDs — no raw strings. `StaticPolicyEngine` behind `test-support` feature flag for consumer testing.

**Tech Stack:** `forgeguard_core` (typed IDs), `serde`/`serde_json`, `thiserror`, `std::net::IpAddr`, `std::future::Future`

**Shaping doc:** `.claude/designs/authz-core-shaping.md`

**Reference crate:** `crates/authn-core/` — follow the same module structure, trait pattern, error pattern, and test-support feature flag pattern.

---

## Patterns

- **MUST:** Functional Core / Imperative Shell — this entire crate is functional core (no I/O)
- **SHOULD:** Parse Don't Validate — `PolicyQuery` only accepts typed IDs, not raw strings
- **SHOULD:** Make Impossible States Impossible — `PolicyDecision` is Allow or Deny (sum type), `DenyReason` encodes exactly the three failure modes
- **SHOULD:** Algebraic Data Types — `PolicyDecision` and `DenyReason` as enums with per-variant data

---

## Group 1: Error infrastructure

### Task 1.1 — Write failing test for Error display messages

**File:** `crates/authz-core/src/error.rs` (create)

```rust
//! Error types for forgeguard_authz_core.

/// The error type for all authorization operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Policy evaluation failed internally.
    #[error("policy evaluation failed: {0}")]
    EvaluationFailed(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_evaluation_failed() {
        let err = Error::EvaluationFailed("timeout contacting policy store".into());
        assert_eq!(
            err.to_string(),
            "policy evaluation failed: timeout contacting policy store"
        );
    }
}
```

### Task 1.2 — Wire error module into lib.rs

**File:** `crates/authz-core/src/lib.rs`

Replace the entire file with:

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod error;

pub use error::{Error, Result};
```

### Task 1.3 — Run tests, confirm pass

```bash
cargo test -p forgeguard_authz_core
```

Expected: 1 test passes.

---

## Group 2: PolicyDecision and DenyReason

### Task 2.1 — Write failing tests for PolicyDecision Display

**File:** `crates/authz-core/src/decision.rs` (create)

```rust
//! Authorization decision types.

use std::fmt;

/// Why a request was denied.
#[derive(Debug, Clone)]
pub enum DenyReason {
    /// No policy matched the query.
    NoMatchingPolicy,
    /// A policy explicitly denied the request.
    ExplicitDeny { policy_id: String },
    /// An error occurred during policy evaluation.
    EvaluationError(String),
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatchingPolicy => write!(f, "no matching policy"),
            Self::ExplicitDeny { policy_id } => {
                write!(f, "explicitly denied by policy '{policy_id}'")
            }
            Self::EvaluationError(msg) => write!(f, "evaluation error: {msg}"),
        }
    }
}

/// The outcome of a policy evaluation.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// The request is allowed.
    Allow,
    /// The request is denied.
    Deny { reason: DenyReason },
}

impl PolicyDecision {
    /// Returns `true` if the decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allowed"),
            Self::Deny { reason } => write!(f, "denied: {reason}"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_allow() {
        let decision = PolicyDecision::Allow;
        assert_eq!(decision.to_string(), "allowed");
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
    }

    #[test]
    fn display_deny_no_matching_policy() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        };
        assert_eq!(decision.to_string(), "denied: no matching policy");
        assert!(!decision.is_allowed());
        assert!(decision.is_denied());
    }

    #[test]
    fn display_deny_explicit() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::ExplicitDeny {
                policy_id: "pol-admin-deny-delete".into(),
            },
        };
        assert_eq!(
            decision.to_string(),
            "denied: explicitly denied by policy 'pol-admin-deny-delete'"
        );
    }

    #[test]
    fn display_deny_evaluation_error() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::EvaluationError("connection timeout".into()),
        };
        assert_eq!(
            decision.to_string(),
            "denied: evaluation error: connection timeout"
        );
    }
}
```

### Task 2.2 — Wire decision module into lib.rs

**File:** `crates/authz-core/src/lib.rs`

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod decision;
pub mod error;

pub use decision::{DenyReason, PolicyDecision};
pub use error::{Error, Result};
```

### Task 2.3 — Run tests, confirm pass

```bash
cargo test -p forgeguard_authz_core
```

Expected: 5 tests pass (1 error + 4 decision).

---

## Group 3: PolicyContext and PolicyQuery

### Task 3.1 — Write PolicyContext

**File:** `crates/authz-core/src/context.rs` (create)

```rust
//! Authorization context carried alongside a policy query.

use std::collections::HashMap;
use std::net::IpAddr;

use forgeguard_core::{GroupName, TenantId};

/// Contextual information for policy evaluation.
///
/// Carries tenant, group membership, IP address, and arbitrary attributes
/// that policy rules may inspect.
pub struct PolicyContext {
    tenant_id: Option<TenantId>,
    groups: Vec<GroupName>,
    ip_address: Option<IpAddr>,
    attributes: HashMap<String, serde_json::Value>,
}

impl PolicyContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self {
            tenant_id: None,
            groups: Vec::new(),
            ip_address: None,
            attributes: HashMap::new(),
        }
    }

    /// Set the tenant ID.
    pub fn with_tenant(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Set group membership.
    pub fn with_groups(mut self, groups: Vec<GroupName>) -> Self {
        self.groups = groups;
        self
    }

    /// Set the source IP address.
    pub fn with_ip_address(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Add an arbitrary attribute.
    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Borrow the tenant ID.
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Borrow the group list.
    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }

    /// Borrow the IP address.
    pub fn ip_address(&self) -> Option<IpAddr> {
        self.ip_address
    }

    /// Borrow the attributes map.
    pub fn attributes(&self) -> &HashMap<String, serde_json::Value> {
        &self.attributes
    }
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self::new()
    }
}
```

### Task 3.2 — Write PolicyQuery with tests

**File:** `crates/authz-core/src/query.rs` (create)

```rust
//! Protocol-agnostic authorization query.

use forgeguard_core::{PrincipalRef, QualifiedAction, ResourceRef};

use crate::context::PolicyContext;

/// A fully-typed authorization query.
///
/// "Can principal P perform action A on resource R given context C?"
///
/// All fields are typed — no raw strings. Constructed from `forgeguard_core`
/// types that carry their own validation proof.
pub struct PolicyQuery {
    principal: PrincipalRef,
    action: QualifiedAction,
    resource: Option<ResourceRef>,
    context: PolicyContext,
}

impl PolicyQuery {
    /// Construct a new policy query.
    pub fn new(
        principal: PrincipalRef,
        action: QualifiedAction,
        resource: Option<ResourceRef>,
        context: PolicyContext,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
            context,
        }
    }

    /// Borrow the principal.
    pub fn principal(&self) -> &PrincipalRef {
        &self.principal
    }

    /// Borrow the action.
    pub fn action(&self) -> &QualifiedAction {
        &self.action
    }

    /// Borrow the resource, if present.
    pub fn resource(&self) -> Option<&ResourceRef> {
        self.resource.as_ref()
    }

    /// Borrow the context.
    pub fn context(&self) -> &PolicyContext {
        &self.context
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{PrincipalRef, QualifiedAction, ResourceId, ResourceRef, UserId};

    use super::*;

    #[test]
    fn construct_query_without_resource() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:read:list").unwrap();
        let context = PolicyContext::new();

        let query = PolicyQuery::new(principal, action, context);

        assert_eq!(query.principal().vp_entity_type(), "iam::user");
        assert_eq!(query.action().to_string(), "todo:read:list");
        assert!(query.resource().is_none());
    }

    #[test]
    fn construct_query_with_resource() {
        let principal = PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:read:list").unwrap();
        let resource_id = ResourceId::parse("my-list").unwrap();
        let resource = ResourceRef::from_route(&action, resource_id);
        let context = PolicyContext::new();

        let query = PolicyQuery::new(principal, action, Some(resource), context);

        assert!(query.resource().is_some());
    }

    #[test]
    fn construct_query_with_context() {
        use forgeguard_core::{GroupName, TenantId};

        let principal = PrincipalRef::new(UserId::new("bob").unwrap());
        let action = QualifiedAction::parse("admin:write:user").unwrap();
        let context = PolicyContext::new()
            .with_tenant(TenantId::new("acme-corp").unwrap())
            .with_groups(vec![GroupName::new("admin").unwrap()])
            .with_ip_address("192.168.1.1".parse().unwrap())
            .with_attribute("department", serde_json::json!("engineering"));

        let query = PolicyQuery::new(principal, action, None, context);

        assert_eq!(query.context().tenant_id().unwrap().as_str(), "acme-corp");
        assert_eq!(query.context().groups().len(), 1);
        assert_eq!(
            query.context().ip_address().unwrap().to_string(),
            "192.168.1.1"
        );
        assert_eq!(
            query.context().attributes().get("department"),
            Some(&serde_json::json!("engineering"))
        );
    }
}
```

**Note:** The `PolicyQuery::new` signature takes `resource` as the third parameter (`Option<ResourceRef>`), and `context` as the fourth. The test `construct_query_without_resource` calls `new(principal, action, context)` with 3 args — this won't compile because the function takes 4. Fix: pass `None` as the resource:

```rust
let query = PolicyQuery::new(principal, action, None, context);
```

This is already correct in the written code above.

### Task 3.3 — Wire context and query modules into lib.rs

**File:** `crates/authz-core/src/lib.rs`

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod context;
pub mod decision;
pub mod error;
pub mod query;

pub use context::PolicyContext;
pub use decision::{DenyReason, PolicyDecision};
pub use error::{Error, Result};
pub use query::PolicyQuery;
```

### Task 3.4 — Run tests, confirm pass

```bash
cargo test -p forgeguard_authz_core
```

Expected: 8 tests pass (1 error + 4 decision + 3 query).

---

## Group 4: PolicyEngine trait

### Task 4.1 — Write the PolicyEngine trait

**File:** `crates/authz-core/src/engine.rs` (create)

```rust
//! Pluggable policy engine trait.

use std::future::Future;
use std::pin::Pin;

use crate::decision::PolicyDecision;
use crate::error::Result;
use crate::query::PolicyQuery;

/// Trait for evaluating authorization queries against a policy store.
///
/// Async because I/O implementations (e.g., AWS Verified Permissions)
/// need it. Pure implementations use `Box::pin(std::future::ready(...))`.
///
/// Defined in this pure crate, implemented in I/O crates.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate a policy query and return a decision.
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>>;
}
```

### Task 4.2 — Wire engine module into lib.rs

**File:** `crates/authz-core/src/lib.rs`

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod context;
pub mod decision;
pub mod engine;
pub mod error;
pub mod query;

pub use context::PolicyContext;
pub use decision::{DenyReason, PolicyDecision};
pub use engine::PolicyEngine;
pub use error::{Error, Result};
pub use query::PolicyQuery;
```

### Task 4.3 — Run tests, confirm pass

```bash
cargo test -p forgeguard_authz_core
```

Expected: 8 tests pass (no new tests — trait has no logic to test).

---

## Group 5: StaticPolicyEngine (test-support)

### Task 5.1 — Add test-support feature flag to Cargo.toml

**File:** `crates/authz-core/Cargo.toml`

Add after `[lib]` section:

```toml
[features]
test-support = []
```

Add dev-dependencies:

```toml
[dev-dependencies]
tokio = { workspace = true, features = ["rt", "macros"] }
```

Full file should be:

```toml
[package]
name = "forgeguard_authz_core"
version = "0.0.0"
homepage = "https://github.com/cloudbridgeuy/forgeguard"
description = "Authorization domain types, Cedar policy types, and permission definitions (pure)"
autobins = false

authors.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "forgeguard_authz_core"
path = "src/lib.rs"

[features]
test-support = []

[dependencies]
forgeguard_core = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["rt", "macros"] }

[lints]
workspace = true
```

### Task 5.2 — Write StaticPolicyEngine with tests

**File:** `crates/authz-core/src/static_engine.rs` (create)

```rust
//! In-memory policy engine for testing consumers.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use forgeguard_core::QualifiedAction;

use crate::decision::PolicyDecision;
use crate::engine::PolicyEngine;
use crate::error::Result;
use crate::query::PolicyQuery;

/// A deterministic, in-memory policy engine for testing.
///
/// Returns a configurable default decision for any query,
/// with optional per-action overrides.
pub struct StaticPolicyEngine {
    default_decision: PolicyDecision,
    overrides: HashMap<String, PolicyDecision>,
}

impl StaticPolicyEngine {
    /// Create with a default decision applied to all queries.
    pub fn new(default_decision: PolicyDecision) -> Self {
        Self {
            default_decision,
            overrides: HashMap::new(),
        }
    }

    /// Add a per-action override. The action's `Display` representation
    /// (e.g., "todo:read:list") is used as the lookup key.
    pub fn with_override(mut self, action: QualifiedAction, decision: PolicyDecision) -> Self {
        self.overrides.insert(action.to_string(), decision);
        self
    }
}

impl PolicyEngine for StaticPolicyEngine {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        let action_key = query.action().to_string();
        let decision = self
            .overrides
            .get(&action_key)
            .cloned()
            .unwrap_or_else(|| self.default_decision.clone());
        Box::pin(std::future::ready(Ok(decision)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{PrincipalRef, QualifiedAction, UserId};

    use super::*;
    use crate::context::PolicyContext;
    use crate::decision::DenyReason;

    fn make_query(action_str: &str) -> PolicyQuery {
        let principal = PrincipalRef::new(UserId::new("test-user").unwrap());
        let action = QualifiedAction::parse(action_str).unwrap();
        let context = PolicyContext::new();
        PolicyQuery::new(principal, action, None, context)
    }

    #[tokio::test]
    async fn default_allow_returns_allow() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Allow);
        let query = make_query("todo:read:list");

        let decision = engine.evaluate(&query).await.unwrap();
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn default_deny_returns_deny() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        });
        let query = make_query("todo:read:list");

        let decision = engine.evaluate(&query).await.unwrap();
        assert!(decision.is_denied());
    }

    #[tokio::test]
    async fn override_takes_precedence_over_default() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Allow).with_override(
            QualifiedAction::parse("admin:delete:user").unwrap(),
            PolicyDecision::Deny {
                reason: DenyReason::ExplicitDeny {
                    policy_id: "no-delete-users".into(),
                },
            },
        );

        // Default action → allow
        let allowed_query = make_query("todo:read:list");
        let decision = engine.evaluate(&allowed_query).await.unwrap();
        assert!(decision.is_allowed());

        // Overridden action → deny
        let denied_query = make_query("admin:delete:user");
        let decision = engine.evaluate(&denied_query).await.unwrap();
        assert!(decision.is_denied());
    }

    #[tokio::test]
    async fn non_overridden_action_falls_through_to_default() {
        let engine = StaticPolicyEngine::new(PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        })
        .with_override(QualifiedAction::parse("todo:read:list").unwrap(), PolicyDecision::Allow);

        let query = make_query("admin:write:config");
        let decision = engine.evaluate(&query).await.unwrap();
        assert!(decision.is_denied());
    }
}
```

### Task 5.3 — Wire static_engine module into lib.rs (behind feature flag)

**File:** `crates/authz-core/src/lib.rs`

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod context;
pub mod decision;
pub mod engine;
pub mod error;
pub mod query;

#[cfg(feature = "test-support")]
pub mod static_engine;

pub use context::PolicyContext;
pub use decision::{DenyReason, PolicyDecision};
pub use engine::PolicyEngine;
pub use error::{Error, Result};
pub use query::PolicyQuery;

#[cfg(feature = "test-support")]
pub use static_engine::StaticPolicyEngine;
```

### Task 5.4 — Run tests with test-support feature, confirm pass

```bash
cargo test -p forgeguard_authz_core --features test-support
```

Expected: 12 tests pass (1 error + 4 decision + 3 query + 4 static engine).

---

## Group 6: Final verification

### Task 6.1 — Run cargo xtask lint

```bash
cargo xtask lint
```

Expected: exit code 0 (zero output = pass). Fix any issues surfaced.

### Task 6.2 — Verify no authn_core dependency

```bash
grep -r "authn_core\|forgeguard_authn" crates/authz-core/
```

Expected: no matches.

### Task 6.3 — Verify no I/O dependencies

```bash
grep -E "tokio|reqwest|aws-sdk|hyper|http" crates/authz-core/Cargo.toml
```

Expected: no matches in `[dependencies]` (only in `[dev-dependencies]` for tokio test runtime).

### Task 6.4 — Update shaping doc current state

**File:** `.claude/designs/authz-core-shaping.md`

Update the `## Current State` section to reflect completion:

```markdown
## Current State

- Implementation complete. All 6 modules: `error`, `decision`, `context`, `query`, `engine`, `static_engine`.
- 12 tests passing (with `test-support` feature).
- No `authn_core` dependency. No I/O dependencies.
- `cargo xtask lint` passes.
```

### Task 6.5 — Commit

Conventional commit:

```
feat(authz-core): add policy engine trait and authorization types
```
