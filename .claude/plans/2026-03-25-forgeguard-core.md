# forgeguard_core Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Implement all shared primitives, typed IDs, FGRN addressing, action vocabulary, permission model, Cedar compilation, and feature flag evaluation for the `forgeguard_core` crate.

**Architecture:** Pure crate (no I/O) following Functional Core / Imperative Shell. Every type uses Parse Don't Validate — constructors return `Result`, inner fields are private. All types compile to `wasm32-unknown-unknown`. Module-per-concern, flat file structure unless a file exceeds ~300 lines.

**Tech Stack:** Rust, `thiserror`, `serde`/`serde_json`, `uuid`, `chrono`, `xxhash-rust` (xxh64)

**Patterns applied:**
- **MUST:** Functional Core / Imperative Shell (`~/.claude/patterns/functional-core-imperative-shell.md`)
- **SHOULD:** Parse Don't Validate (`~/.claude/patterns/parse-dont-validate.md`)
- **SHOULD:** Type-Driven Development (`~/.claude/patterns/type-driven-development.md`)
- **SHOULD:** Make Impossible States Impossible (`~/.claude/patterns/make-impossible-states-impossible.md`)
- **SHOULD:** Algebraic Data Types (`~/.claude/patterns/algebraic-data-types.md`)

**Design doc:** `.claude/designs/github-issues.md` (Issue #1 section, starting at line 384)
**Shaping doc:** `.claude/designs/core-shaping.md`
**Spike:** `.claude/designs/spike-flag-evaluation.md`

---

## Module Layout

```
crates/core/src/
  lib.rs          — re-exports, clippy denials, module declarations
  error.rs        — Error enum, Result<T> alias
  segment.rs      — Segment newtype, define_id! macro, typed IDs (UserId, etc.)
  fgrn.rs         — Fgrn, FgrnSegment, known_segments, builders, matching
  action.rs       — Namespace, Action, Entity, QualifiedAction, ResourceId, ResourceRef, PrincipalRef
  permission.rs   — Effect, PatternSegment, ActionPattern, CedarEntityRef, ResourceConstraint, PolicyStatement, Policy, GroupDefinition
  cedar.rs        — compile_policy_to_cedar, compile_all_to_cedar
  features.rs     — FlagName, FlagValue, FlagType, FlagDefinition, FlagOverride, FlagConfig, ResolvedFlags, evaluate_flags, deterministic_bucket
```

Each file stays under ~300 lines. If `permission.rs` grows too large during implementation, split `CedarEntityRef` and `ActionPattern` into sub-modules.

---

## Task 1: Error infrastructure

**File:** `crates/core/src/error.rs`

### 1.1 — Write the error module

Create `crates/core/src/error.rs`:

```rust
//! Error types for forgeguard_core.

/// The error type for all forgeguard_core operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A parse/validation error with structured context.
    #[error("invalid {field}: '{value}' — {reason}")]
    Parse {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    /// A configuration error.
    #[error("configuration error: {0}")]
    Config(String),
    /// An unknown feature flag type.
    #[error("unknown feature flag type: {0}")]
    InvalidFlagType(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;
```

### 1.2 — Wire error module into lib.rs

Replace the contents of `crates/core/src/lib.rs` with:

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod error;

pub use error::{Error, Result};
```

### 1.3 — Verify it compiles

Run:

```bash
cargo check -p forgeguard_core
```

Expected: no errors.

### 1.4 — Write error display tests

Add to the bottom of `crates/core/src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_display_includes_all_fields() {
        let err = Error::Parse {
            field: "segment",
            value: "BAD".to_string(),
            reason: "must be lowercase",
        };
        let msg = err.to_string();
        assert!(msg.contains("segment"), "should contain field name");
        assert!(msg.contains("BAD"), "should contain value");
        assert!(msg.contains("must be lowercase"), "should contain reason");
    }

    #[test]
    fn config_error_display() {
        let err = Error::Config("missing field".to_string());
        assert_eq!(err.to_string(), "configuration error: missing field");
    }

    #[test]
    fn invalid_flag_type_display() {
        let err = Error::InvalidFlagType("complex".to_string());
        assert_eq!(err.to_string(), "unknown feature flag type: complex");
    }
}
```

### 1.5 — Run the tests

```bash
cargo test -p forgeguard_core
```

Expected: 3 tests pass.

---

## Task 2: Segment and Typed IDs

**File:** `crates/core/src/segment.rs`

### 2.1 — Write the Segment type

Create `crates/core/src/segment.rs` with the `Segment` newtype. The implementation is specified verbatim in the design doc (lines 403–468). Key points:

- Private inner `String` field
- `try_new(impl Into<String>) -> Result<Self>` constructor with all validation rules:
  - non-empty
  - starts with lowercase letter or digit
  - does not end with hyphen
  - no consecutive hyphens
  - only lowercase ASCII letters, digits, hyphens
- `as_str() -> &str` accessor
- `Display` impl (delegates to inner string)
- `FromStr` impl (delegates to `try_new`)
- `Serialize` via `#[serde(try_from = "String", into = "String")]`
- `TryFrom<String>` and `Into<String>` impls
- Derive: `Debug, Clone, Eq, PartialEq, Hash`

```rust
//! Validated identifier segments and typed ID newtypes.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A validated identifier segment.
///
/// Rules:
/// - Lowercase ASCII letters, digits, and hyphens only (a-z, 0-9, -)
/// - Must start with a lowercase letter or digit
/// - Must not end with a hyphen
/// - No consecutive hyphens (reserved, Punycode-style)
/// - Non-empty, no upper length limit
///
/// UUIDs are valid Segments: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Segment(String);

impl Segment {
    /// Parse and validate a raw string into a `Segment`.
    pub fn try_new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();

        if s.is_empty() {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "cannot be empty",
            });
        }
        if !s.as_bytes()[0].is_ascii_lowercase() && !s.as_bytes()[0].is_ascii_digit() {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "must start with a lowercase letter or digit",
            });
        }
        if s.ends_with('-') {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "must not end with a hyphen",
            });
        }
        if s.contains("--") {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "consecutive hyphens are not allowed",
            });
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::Parse {
                field: "segment",
                value: s,
                reason: "must contain only lowercase letters, digits, and hyphens",
            });
        }

        Ok(Self(s))
    }

    /// The inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Segment {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::try_new(s)
    }
}

impl TryFrom<String> for Segment {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        Self::try_new(value)
    }
}

impl From<Segment> for String {
    fn from(seg: Segment) -> Self {
        seg.0
    }
}
```

### 2.2 — Write the `define_id!` macro and typed IDs

Append to `crates/core/src/segment.rs`:

```rust
/// Generates a newtype wrapper over `Segment` with standard trait impls.
macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Eq, PartialEq, Hash)]
        pub struct $name(Segment);

        impl $name {
            /// Parse and validate a raw string into this ID type.
            pub fn new(raw: impl Into<String>) -> Result<Self> {
                Ok(Self(Segment::try_new(raw)?))
            }

            /// The inner string value.
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            /// The underlying validated segment.
            pub fn as_segment(&self) -> &Segment {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::new(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

// Use the macro before exporting it so it's available within the crate.
define_id!(UserId);
define_id!(TenantId);
define_id!(ProjectId);
define_id!(GroupName);
define_id!(PolicyName);

/// A unique flow/request identifier.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct FlowId(uuid::Uuid);

impl FlowId {
    /// Create a new random FlowId.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Create from an existing UUID.
    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }

    /// The inner UUID.
    pub fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }
}

impl Default for FlowId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // UUID display is lowercase-hyphenated, which is a valid Segment format
        write!(f, "{}", self.0)
    }
}
```

### 2.3 — Wire into lib.rs

Update `crates/core/src/lib.rs`:

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod error;
pub mod segment;

pub use error::{Error, Result};
pub use segment::{
    FlowId, GroupName, PolicyName, ProjectId, Segment, TenantId, UserId,
};
```

### 2.4 — Verify it compiles

```bash
cargo check -p forgeguard_core
```

### 2.5 — Write Segment tests

Add at bottom of `crates/core/src/segment.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_lowercase() {
        assert!(Segment::try_new("acme-corp").is_ok());
    }

    #[test]
    fn valid_digit_first() {
        assert!(Segment::try_new("1password").is_ok());
    }

    #[test]
    fn valid_uuid() {
        assert!(Segment::try_new("a1b2c3d4-e5f6-7890-abcd-ef1234567890").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(Segment::try_new("").is_err());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(Segment::try_new("AcmeCorp").is_err());
    }

    #[test]
    fn rejects_underscores() {
        assert!(Segment::try_new("my_project").is_err());
    }

    #[test]
    fn rejects_leading_hyphen() {
        assert!(Segment::try_new("-leading").is_err());
    }

    #[test]
    fn rejects_trailing_hyphen() {
        assert!(Segment::try_new("trailing-").is_err());
    }

    #[test]
    fn rejects_consecutive_hyphens() {
        assert!(Segment::try_new("no--double").is_err());
    }

    #[test]
    fn rejects_non_visible_ascii() {
        assert!(Segment::try_new("\x00hidden").is_err());
        assert!(Segment::try_new("tab\there").is_err());
        assert!(Segment::try_new("space here").is_err());
    }

    #[test]
    fn display_round_trip() {
        let seg = Segment::try_new("acme-corp").unwrap();
        let parsed: Segment = seg.to_string().parse().unwrap();
        assert_eq!(seg, parsed);
    }

    #[test]
    fn serde_round_trip() {
        let seg = Segment::try_new("acme-corp").unwrap();
        let json = serde_json::to_string(&seg).unwrap();
        let parsed: Segment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, parsed);
    }

    #[test]
    fn user_id_valid() {
        assert!(UserId::new("alice").is_ok());
        assert!(UserId::new("bob-smith").is_ok());
    }

    #[test]
    fn user_id_rejects_uppercase() {
        assert!(UserId::new("Alice").is_err());
    }

    #[test]
    fn user_id_rejects_empty() {
        assert!(UserId::new("").is_err());
    }

    #[test]
    fn group_name_valid() {
        assert!(GroupName::new("admin").is_ok());
        assert!(GroupName::new("backend-team").is_ok());
    }

    #[test]
    fn group_name_rejects_uppercase() {
        assert!(GroupName::new("Admin").is_err());
    }

    #[test]
    fn policy_name_valid() {
        assert!(PolicyName::new("todo-viewer").is_ok());
        assert!(PolicyName::new("top-secret-deny").is_ok());
    }

    #[test]
    fn policy_name_rejects_uppercase() {
        assert!(PolicyName::new("TODO_VIEWER").is_err());
    }

    #[test]
    fn user_id_serde_round_trip() {
        let id = UserId::new("alice").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: UserId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn flow_id_display_is_uuid_format() {
        let fid = FlowId::new();
        let s = fid.to_string();
        // UUID v4 format: 8-4-4-4-12 hex digits
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);
    }
}
```

### 2.6 — Run tests

```bash
cargo test -p forgeguard_core
```

Expected: all tests pass (3 error + ~18 segment/ID tests).

---

## Task 3: FGRN

**File:** `crates/core/src/fgrn.rs`

### 3.1 — Write the FGRN module

Create `crates/core/src/fgrn.rs` using the code from the design doc (lines 470–745). This includes:

- `known_segments` module with `LazyLock<Segment>` constants for `iam`, `forgeguard`, `user`, `group`, `policy`
- `FgrnSegment` enum (`Value(Segment)`, `Wildcard`)
- `Fgrn` struct with private fields: `project`, `tenant`, `namespace`, `resource_type`, `resource_id`, `raw`
- `Fgrn::parse()`, `Fgrn::new()`, builders (`user()`, `group()`, `policy()`, `resource()`)
- `as_vp_entity_id()`, `cedar_entity_type()`, `matches()`
- Helper functions: `parse_optional_segment`, `optional_segment_str`, `optional_matches`
- `Display`, `FromStr`, `Serialize`, `Deserialize` impls

**Important detail:** The `known_segments` module uses `LazyLock` (stable since Rust 1.80) to avoid `expect()`/`unwrap()` which are denied by clippy. Use `unwrap_or_else(|_| unreachable!())` inside the LazyLock initializer — this only runs once and the values are statically known-good.

Follow the design doc code exactly. The `Fgrn::resource` builder signature takes `&ResourceId` — but `ResourceId` hasn't been defined yet (it's in the action module). For now, accept `&str` and convert:

```rust
pub fn resource(
    project: &ProjectId,
    tenant: &TenantId,
    namespace: &Namespace,
    entity: &Entity,
    id: &ResourceId,
) -> Self {
```

Actually, since `Namespace`, `Entity`, and `ResourceId` are in the action module which hasn't been created yet — define `Fgrn::resource` to take generic segment references. The simplest approach: **create Task 3 after Task 4 (action types)**, or use forward declarations.

**Practical approach:** Create the FGRN module with all builders except `resource()`. Add `resource()` after the action module exists (Task 4). Wire into lib.rs with the types available so far.

### 3.2 — Wire into lib.rs

Add to `crates/core/src/lib.rs`:

```rust
pub mod fgrn;

pub use fgrn::{Fgrn, FgrnSegment};
```

### 3.3 — Verify it compiles

```bash
cargo check -p forgeguard_core
```

### 3.4 — Write FGRN tests

Add at bottom of `crates/core/src/fgrn.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProjectId, TenantId, UserId, GroupName, PolicyName};

    #[test]
    fn parse_user_fgrn() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice").unwrap();
        assert_eq!(fgrn.as_vp_entity_id(), "fgrn:acme-app:acme-corp:iam:user:alice");
    }

    #[test]
    fn parse_resource_fgrn() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-123").unwrap();
        assert_eq!(fgrn.cedar_entity_type(), Some("todo::list".to_string()));
    }

    #[test]
    fn parse_wildcard() {
        let fgrn = Fgrn::parse("fgrn:acme-app:*:todo:list:*").unwrap();
        assert_eq!(fgrn.tenant(), Some(&FgrnSegment::Wildcard));
        assert_eq!(fgrn.resource_id(), &FgrnSegment::Wildcard);
    }

    #[test]
    fn parse_not_applicable() {
        let fgrn = Fgrn::parse("fgrn:acme-app:-:forgeguard:policy:pol-001").unwrap();
        assert!(fgrn.tenant().is_none());
    }

    #[test]
    fn matching_wildcard() {
        let specific = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-001").unwrap();
        let pattern = Fgrn::parse("fgrn:acme-app:*:todo:list:*").unwrap();
        assert!(specific.matches(&pattern));
    }

    #[test]
    fn matching_wrong_namespace() {
        let specific = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-001").unwrap();
        let pattern = Fgrn::parse("fgrn:acme-app:*:billing:list:*").unwrap();
        assert!(!specific.matches(&pattern));
    }

    #[test]
    fn parse_errors() {
        assert!(Fgrn::parse("bad:format").is_err());
        assert!(Fgrn::parse("fgrn:acme-app").is_err());
        assert!(Fgrn::parse("").is_err());
        assert!(Fgrn::parse("fgrn:AcmeApp:acme:todo:list:list-1").is_err());
    }

    #[test]
    fn builder_user() {
        let project = ProjectId::new("acme-app").unwrap();
        let tenant = TenantId::new("acme-corp").unwrap();
        let user = UserId::new("alice").unwrap();
        let fgrn = Fgrn::user(&project, &tenant, &user);
        assert_eq!(fgrn.to_string(), "fgrn:acme-app:acme-corp:iam:user:alice");
    }

    #[test]
    fn builder_group() {
        let project = ProjectId::new("acme-app").unwrap();
        let tenant = TenantId::new("acme-corp").unwrap();
        let group = GroupName::new("admin").unwrap();
        let fgrn = Fgrn::group(&project, &tenant, &group);
        assert_eq!(fgrn.to_string(), "fgrn:acme-app:acme-corp:iam:group:admin");
    }

    #[test]
    fn builder_policy() {
        let project = ProjectId::new("acme-app").unwrap();
        let policy = PolicyName::new("todo-viewer").unwrap();
        let fgrn = Fgrn::policy(&project, &policy);
        assert_eq!(fgrn.to_string(), "fgrn:acme-app:-:forgeguard:policy:todo-viewer");
    }

    #[test]
    fn display_equals_vp_entity_id() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:iam:user:alice").unwrap();
        assert_eq!(fgrn.to_string(), fgrn.as_vp_entity_id());
    }

    #[test]
    fn serde_round_trip() {
        let fgrn = Fgrn::parse("fgrn:acme-app:acme-corp:todo:list:list-001").unwrap();
        let json = serde_json::to_string(&fgrn).unwrap();
        let parsed: Fgrn = serde_json::from_str(&json).unwrap();
        assert_eq!(fgrn, parsed);
    }

    #[test]
    fn new_and_display_round_trip() {
        let fgrn = Fgrn::new(
            Some(FgrnSegment::Value(Segment::try_new("proj").unwrap())),
            None,
            FgrnSegment::Value(Segment::try_new("ns").unwrap()),
            FgrnSegment::Value(Segment::try_new("type").unwrap()),
            FgrnSegment::Value(Segment::try_new("id").unwrap()),
        );
        let reparsed = Fgrn::parse(&fgrn.to_string()).unwrap();
        assert_eq!(fgrn, reparsed);
    }
}
```

### 3.5 — Run tests

```bash
cargo test -p forgeguard_core
```

---

## Task 4: Action Vocabulary

**File:** `crates/core/src/action.rs`

### 4.1 — Write the action module

Create `crates/core/src/action.rs` using the code from the design doc (lines 775–1007). This includes:

- `Namespace` with `NamespaceInner` enum (User/Reserved), `parse()`, `iam()`, `forgeguard()`, `is_reserved()`, `as_segment()`, `as_str()`
- `Action` newtype over `Segment`
- `Entity` newtype over `Segment` with `cedar_entity_type()`
- `QualifiedAction` struct with `parse()`, `new()`, `vp_action_type()`, `vp_action_id()`, `cedar_action_ref()`, `cedar_entity_type()`, custom `Serialize`/`Deserialize`
- `ResourceId` newtype over `Segment`
- `ResourceRef` struct with `from_route()`, `vp_entity_type()`, `to_fgrn()`
- `PrincipalRef` struct with `new()`, `vp_entity_type()`, `to_fgrn()`

**Important:** `Namespace` needs `Display`, `Serialize`, `Deserialize` for use in `FlagName`. Implement:
- `Display` — delegates to inner segment
- `Serialize` — serialize as string
- `Deserialize` — deserialize via `parse()`. Note: `Namespace::parse` rejects reserved namespaces, but `FlagName` scoped flags use customer namespaces, so this is correct.
- `PartialEq` — derive won't work on `NamespaceInner` because it compares variant tags. Implement manually: compare the inner segment strings.

### 4.2 — Add `Fgrn::resource()` builder

Now that `Namespace`, `Entity`, and `ResourceId` exist, add the `resource()` builder to `fgrn.rs`. This requires importing from `action.rs`.

### 4.3 — Wire into lib.rs

Add to `crates/core/src/lib.rs`:

```rust
pub mod action;

pub use action::{
    Action, Entity, Namespace, PrincipalRef, QualifiedAction, ResourceId, ResourceRef,
};
```

### 4.4 — Verify it compiles

```bash
cargo check -p forgeguard_core
```

### 4.5 — Write action tests

Add at bottom of `crates/core/src/action.rs`. Key tests from the design doc (lines 1467–1484):

- `Namespace::parse("todo")` succeeds, `Namespace::parse("iam")` fails (reserved), `Namespace::parse("forgeguard")` fails (reserved), `Namespace::parse("")` fails, `Namespace::parse("Todo")` fails
- `Namespace::iam().is_reserved()` is true
- `Action::parse("read")`, `"force-delete"`, `"bulk-export"` all valid; `"Read"`, `""`, `"force_delete"` rejected
- `Entity::parse("invoice")`, `"payment-tracker"` valid; `"Invoice"` rejected
- `QualifiedAction::parse("todo:read:list")` → fields correct
- `QualifiedAction::parse("s3:get-object")` → error (two segments)
- `QualifiedAction::parse("Todo:Read:List")` → error
- `vp_action_type()` → `"todo::action"`
- `vp_action_id()` → `"read-list"`
- `cedar_action_ref()` → `"todo::action::\"read-list\""`
- `cedar_entity_type()` → `"todo::list"`
- `QualifiedAction` serde round-trip
- `ResourceId::parse("")` fails, `"list-123"` ok, `"list_123"` fails
- `PrincipalRef::vp_entity_type()` → `"iam::user"`
- `PrincipalRef::to_fgrn()` produces correct FGRN string
- `ResourceRef::to_fgrn()` produces correct FGRN string

### 4.6 — Run tests

```bash
cargo test -p forgeguard_core
```

---

## Task 5: Permission Model Types

**File:** `crates/core/src/permission.rs`

### 5.1 — Write the permission module

Create `crates/core/src/permission.rs` using the code from the design doc (lines 1009–1202). This includes:

- `Effect` enum (Allow/Deny) with `Deserialize` (`rename_all = "lowercase"`)
- `PatternSegment` enum (Exact/Wildcard) with `matches()`
- `ActionPattern` struct with `parse()` and `matches()`
- `parse_pattern_segment()` helper
- `CedarEntityRef` struct with `parse()`, `as_cedar_str()`, `Display`, `Deserialize`
- `ResourceConstraint` enum (All/Specific) with `Default`
- `PolicyStatement` struct with `effect`, `actions`, `resources`, `except`
- `Policy` struct with `name`, `description`, `statements`
- `GroupDefinition` struct with `name`, `description`, `policies`, `member_groups`

**Key design patterns:**
- All structs use `Deserialize` for TOML config loading
- `ResourceConstraint` uses `#[serde(untagged)]` — `All` is the default, `Specific` deserializes from a Vec
- `PolicyStatement.except` and `GroupDefinition.member_groups` use `#[serde(default)]`
- `Policy` and `GroupDefinition` have `pub` fields because they're data transfer types from config

### 5.2 — Wire into lib.rs

```rust
pub mod permission;

pub use permission::{
    ActionPattern, CedarEntityRef, Effect, GroupDefinition, PatternSegment, Policy,
    PolicyStatement, ResourceConstraint,
};
```

### 5.3 — Verify it compiles

```bash
cargo check -p forgeguard_core
```

### 5.4 — Write permission tests

Key tests from the design doc (lines 1538–1557):

- `ActionPattern::parse("todo:read:list")` → all exact
- `ActionPattern::parse("todo:*:*")` → namespace exact, action+entity wildcard
- `ActionPattern::parse("*:*:*")` → all wildcard
- `ActionPattern::parse("todo:read")` → error (two segments)
- `ActionPattern::matches`: `"todo:*:*"` matches `todo:read:list`, not `billing:read:invoice`
- `ActionPattern::matches`: `"*:read:*"` matches `todo:read:list`, not `todo:delete:item`
- `Effect` serde: `"allow"` and `"deny"` work, `"ALLOW"` and `"permit"` fail
- `CedarEntityRef::parse("todo::list::top-secret")` → fields correct
- `CedarEntityRef::parse("todo::list")` → error
- `CedarEntityRef::parse("Todo::List::TopSecret")` → error
- `CedarEntityRef` display round-trip
- `CedarEntityRef` serde round-trip
- `ResourceConstraint::default()` is `All`
- `PolicyStatement` with deny + except deserializes from TOML-like JSON
- `GroupDefinition` with `member_groups` deserializes correctly

### 5.5 — Run tests

```bash
cargo test -p forgeguard_core
```

---

## Task 6: Cedar Compilation

**File:** `crates/core/src/cedar.rs`

### 6.1 — Write the Cedar compilation module

Create `crates/core/src/cedar.rs` with the two pure functions from the design doc (lines 1204–1229):

- `compile_policy_to_cedar(policy, attached_to_group, project, tenant) -> Vec<String>`
  - For each statement in the policy:
    - `Effect::Allow` → `permit(principal in iam::group::"<fgrn>", action in [<actions>], resource)`
    - `Effect::Deny` → `forbid(...)` with optional `unless { principal in iam::group::"<fgrn>" }` for each except group
  - `ActionPattern` wildcards → unconstrained `action` or explicit Cedar action list
  - `ResourceConstraint::All` → unconstrained `resource`
  - `ResourceConstraint::Specific` → `resource == <cedar_entity_type>::"<fgrn>"`
  - Uses `Fgrn::group()` builder for the group FGRN in `principal in`

- `compile_all_to_cedar(policies, groups, project, tenant) -> Result<Vec<String>>`
  - Validates that all policy references in groups resolve to defined policies
  - Detects circular group nesting (DFS cycle detection)
  - Calls `compile_policy_to_cedar` for each group→policy attachment

**Important:** This is the most complex logic module. The Cedar output format must be exact — Cedar is whitespace-sensitive in string literals. Use the test cases from the design doc (lines 1560–1567) to validate.

### 6.2 — Wire into lib.rs

```rust
pub mod cedar;

pub use cedar::{compile_all_to_cedar, compile_policy_to_cedar};
```

### 6.3 — Verify it compiles

```bash
cargo check -p forgeguard_core
```

### 6.4 — Write Cedar compilation tests

Key tests from the design doc (lines 1560–1567):

- Allow policy attached to group → `permit(principal in iam::group::"fgrn:...", action in [...], resource)`
- Deny policy with `except` → `forbid(...) unless { principal in iam::group::"fgrn:..." }`
- Wildcard action `todo:*:*` → unconstrained `action` in Cedar
- `ResourceConstraint::Specific(["todo::list::top-secret"])` → `resource == todo::list::"fgrn:..."`
- `ResourceConstraint::All` → unconstrained `resource`
- `compile_all_to_cedar` rejects undefined policy reference in group
- `compile_all_to_cedar` detects circular group nesting

### 6.5 — Run tests

```bash
cargo test -p forgeguard_core
```

---

## Task 7: Feature Flags

**File:** `crates/core/src/features.rs`

### 7.1 — Write the feature flags module

Create `crates/core/src/features.rs` using the code from the design doc (lines 1252–1460) and the spike findings (`.claude/designs/spike-flag-evaluation.md`). This includes:

**Types:**
- `FlagName` enum (Global/Scoped) with `parse()`, `Display`, `Serialize`, `Deserialize`, `is_in_namespace()`
- `FlagValue` enum (Bool/String/Number) with `#[serde(untagged)]`
- `FlagType` enum (Boolean/String/Number) with `#[serde(rename_all = "snake_case")]`
- `FlagOverride` struct with `tenant: Option<TenantId>`, `user: Option<UserId>`, `value: FlagValue`
- `FlagDefinition` struct with all fields, `#[serde(default = "default_true")]` for `enabled`
- `FlagConfig` struct with `HashMap<FlagName, FlagDefinition>`
- `ResolvedFlags` struct with `enabled()`, `get()`, `is_empty()`

**Evaluation:**
- `pub fn evaluate_flags(config, tenant_id, user_id) -> ResolvedFlags`
- `fn resolve_single_flag(name, flag, tenant_id, user_id) -> FlagValue`
  - Step 0: kill switch (`!flag.enabled` → return `default`)
  - Step 1: linear override scan (pre-sorted by specificity)
  - Step 2: rollout bucket (`deterministic_bucket`)
  - Step 3: return default
- `fn deterministic_bucket(flag, tenant, user) -> u8` using `xxhash_rust::xxh64::XxHash64`

**Helper:**
```rust
fn default_true() -> bool {
    true
}
```

**Override match logic** (from design doc lines 1414–1424):
```rust
let user_matches = ov.user.as_ref().map_or(true, |u| u == user_id);
let tenant_matches = match (&ov.tenant, tenant_id) {
    (Some(t), Some(tid)) => t == tid,
    (Some(_), None) => false,
    (None, _) => true,
};
```

**Bucketing** (from design doc lines 1449–1458):
```rust
fn deterministic_bucket(flag: &str, tenant: Option<&TenantId>, user: &UserId) -> u8 {
    use std::hash::Hasher;
    let mut hasher = xxhash_rust::xxh64::XxHash64::with_seed(0);
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

### 7.2 — Wire into lib.rs

```rust
pub mod features;

pub use features::{
    evaluate_flags, FlagConfig, FlagDefinition, FlagName, FlagOverride, FlagType,
    FlagValue, ResolvedFlags,
};
```

### 7.3 — Verify it compiles

```bash
cargo check -p forgeguard_core
```

### 7.4 — Write feature flag tests

Key tests from the design doc (lines 1499–1534):

**FlagName parsing:**
- `FlagName::parse("maintenance-mode")` → `Global`
- `FlagName::parse("todo:ai-suggestions")` → `Scoped`
- `FlagName::parse("MaintenanceMode")` → error
- `FlagName::parse("")` → error
- Display round-trip, serde round-trip
- `is_in_namespace`: scoped matches its namespace, global matches nothing

**Override hierarchy:**
- User+tenant override wins over tenant-only
- User override wins over rollout
- Tenant override wins over rollout and default
- Kill switch ignores everything, returns default
- String variant: tenant override returns the string
- Numeric flag: tenant override returns the number

**Rollout:**
- Deterministic: same inputs → same result
- Distribution: 25% rollout gives ~25% ± 3% of 10,000 test users
- Independence: different flag names → different buckets
- Boolean rollout with no `rollout_variant` → `true`
- String rollout with variant → returns variant for users in bucket
- `rollout_percentage = 0` → nobody
- `rollout_percentage = 100` → everyone

**Edge cases:**
- Flag with no overrides and no rollout → default
- `ResolvedFlags` JSON round-trip

### 7.5 — Run tests

```bash
cargo test -p forgeguard_core
```

---

## Task 8: Final Verification

### 8.1 — Run all tests

```bash
cargo test -p forgeguard_core
```

All tests must pass.

### 8.2 — Run clippy

```bash
cargo clippy -p forgeguard_core -- -D warnings
```

Must pass with zero warnings.

### 8.3 — Check WASM compatibility

```bash
rustup target add wasm32-unknown-unknown 2>/dev/null
cargo check -p forgeguard_core --target wasm32-unknown-unknown
```

Must compile — this is a hard requirement (R1).

### 8.4 — Check file sizes

No file in `crates/core/src/` should exceed ~300 lines (soft limit) or 1000 lines (hard limit enforced by xtask). If any file is too large, split it using the module organization pattern from CLAUDE.md.

### 8.5 — Final lib.rs review

Ensure `crates/core/src/lib.rs` re-exports all public types. The public API surface should be:

```rust
// Types
pub use segment::{Segment, UserId, TenantId, ProjectId, GroupName, PolicyName, FlowId};
pub use fgrn::{Fgrn, FgrnSegment};
pub use action::{Namespace, Action, Entity, QualifiedAction, ResourceId, ResourceRef, PrincipalRef};
pub use permission::{Effect, PatternSegment, ActionPattern, CedarEntityRef, ResourceConstraint, PolicyStatement, Policy, GroupDefinition};
pub use features::{FlagName, FlagValue, FlagType, FlagDefinition, FlagOverride, FlagConfig, ResolvedFlags, evaluate_flags};
pub use cedar::{compile_policy_to_cedar, compile_all_to_cedar};
pub use error::{Error, Result};
```

---

## Dependency Order

```
Task 1 (error) → Task 2 (segment/IDs) → Task 3 (FGRN) → Task 4 (action)
                                                                    ↓
Task 5 (permission) → Task 6 (cedar) → Task 7 (features) → Task 8 (verify)
```

Tasks 3 and 4 have a circular reference (FGRN builders use action types, but action types are independent). Resolution: implement FGRN without `resource()` builder first, add it after Task 4.

Tasks 5, 6, and 7 are independent of each other but all depend on Tasks 1–4. They can be implemented in any order.
