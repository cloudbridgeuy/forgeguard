# Newtypes

How the workspace wraps primitives in domain types, where validation runs, and what the wire-format vs. domain-value split looks like.

This is the project-specific complement to `~/.claude/patterns/parse-dont-validate.md` and `~/.claude/patterns/type-driven-development.md`. It documents the catalog of newtypes in use, the canonical shape we expect them to follow, and the lessons baked in from the issue-74 rollout.

## Why Newtypes

The proxy and control plane sit at the seam between untrusted JSON/TOML on one side and a Cedar/Pingora domain core on the other. Primitive types (`String`, `u8`, `u16`) at that seam carry no invariants and force every consumer to re-validate or trust upstream. Newtypes move that validation to the deserialize boundary so the rest of the program holds a value that **cannot** be wrong.

Concretely: a `Percentage(u8)` proven `0..=100` at parse time means no `if pct > 100 { return Err(...) }` at use site. A `ConfigVersion(NaiveDate)` means no string-shaped dates leak past the API boundary.

## Anatomy of a Newtype

The canonical shape, distilled from the eight types we propagated in issue-74:

```rust
//! crates/core/src/percentage.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct Percentage(u8);

impl Percentage {
    pub fn try_new(value: u8) -> crate::Result<Self> {
        if value > 100 {
            return Err(crate::Error::InvalidPercentage(value));
        }
        Ok(Self(value))
    }

    pub fn value(&self) -> u8 { self.0 }
}

impl<'de> serde::Deserialize<'de> for Percentage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = u8::deserialize(d)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}
```

Five things are non-negotiable:

1. **Private inner field.** No `pub struct Percentage(pub u8)`. The whole point is that constructing the type requires going through the validator.
2. **`try_new` for fallible construction**, returning the crate's local `Result<T>`. Use `new` only when construction is infallible (e.g. `KeyId::generate`).
3. **Custom `Deserialize` that funnels through `try_new`.** `#[serde(try_from = "...")]` is acceptable but the explicit `impl` makes the validation seam visible in grep.
4. **`#[serde(transparent)]` on `Serialize`** — wire format is the inner value, never `{ "value": ... }`.
5. **One-way display via `as_str()` / `value()` accessors** — never expose `&mut` access to the inner.

## Wire Format vs. Domain Value

A newtype's domain representation and its on-wire representation are **not** always identical. `Etag` is the worked example:

```rust
// Domain: Etag carries a *quoted* string, e.g. `"\"abc123\""`.
// Wire:   The HTTP header value is the same quoted string, byte-for-byte.
// Why:    RFC 7232 strong etags include the surrounding double-quotes;
//         the quotes belong to the value, not the framing.
let e = Etag::try_new("\"abc123\"")?; // accepted
let e = Etag::try_new("abc123")?;     // rejected — missing quotes
```

The implementation lesson: **decide once, document at the constructor**. If a value's wire form has decoration (quotes, prefixes, format strings), include that decoration in the inner representation and reject anything that doesn't match. The alternative — storing a bare value and re-quoting at the boundary — leaks framing into business logic and gives you two sources of truth for "what's a valid etag."

`SagaId` is the contrast: the wire form is `"SAGA#01HXYZ..."` (DynamoDB partition key), but the domain stores the bare `01HXYZ...`. The decoration is structural, not semantic, so we strip it at parse time:

```rust
let saga_id = SagaId::from_pk("SAGA#01HXYZ...")?; // strips prefix
let saga_id = SagaId::try_new("01HXYZ...")?;      // bare form
```

The rule: include framing in the value when the framing IS part of the value's identity (etags, qualified names). Strip framing when it's a transport detail (DynamoDB PK prefixes, URL path segments).

## Where Validation Runs

Validation lives at **deserialization**, not at use site. Across the workspace this means:

- TOML configs — `forgeguard_http::load_config` parses through `serde::Deserialize`, so a malformed `rollout_percentage = 200` fails at config-load time, before any flag evaluation runs.
- HTTP request bodies — Axum `Json<T>` extracts through `serde_json`, so a malformed `"version": "2026-13-01"` produces an Axum `JsonRejection::JsonDataError` (HTTP 422) with the field path in the error chain. **Note**: typed deserialization failures surface as 422 (Unprocessable Entity), not 400 (Bad Request) — 400 is reserved for syntactically malformed JSON.
- DynamoDB rows — every "parse on read" boundary calls `Etag::try_new` / `ConfigVersion::try_new` / etc. and maps failures to `Error::Store`. A poisoned row fails the read, not the next twelve handler invocations.

The test for "is this newtype shaped correctly?" is: can a downstream consumer ever observe an invalid value? If yes, the validation seam is too late.

## Catalog

| Type | Crate | Module | Validation rule | Wire form |
| --- | --- | --- | --- | --- |
| `KeyId` | `core` | `key_id` | `fg-YYYYMMDD-XXXXXX` (8 lowercase hex) | identical |
| `UserId` | `core` | `segment` | non-empty, no `#` | identical |
| `TenantId` | `core` | `segment` | non-empty, no `#` | identical |
| `OrganizationId` | `core` | `segment` | non-empty, no `#` | identical |
| `Percentage` | `core` | `percentage` | `0..=100` (u8) | bare integer |
| `ConfigVersion` | `core` | `config_version` | `chrono::NaiveDate`, formatted `YYYY-MM-DD` | string |
| `SagaId` | `core` | `saga_id` | non-empty, no `#`; `from_pk` strips `SAGA#` | bare; PK form `SAGA#<id>` |
| `Etag` | `control-plane` | `etag` | quoted strong etag, non-empty | identical (RFC 7232) |
| `Fgrn` | `core` | `fgrn` | namespaced resource name | identical |
| `FlagName` | `core` | `features` | non-empty identifier | identical |
| `PolicyName` | `core` | `segment` | non-empty, no `#` | identical |
| `ProjectId` | `core` | `segment` | non-empty, no `#` | identical |
| `GroupName` | `core` | `segment` | non-empty, no `#` | identical |

Two extra points of consistency:

- **`*_core` crates own newtype types**; I/O crates consume them. `Etag` lives in `control-plane` only because it has no use outside the optimistic-locking machinery — if a second consumer appears, it moves to `forgeguard_core`.
- **Error variants live in the owning crate's `Error`.** `Error::InvalidPercentage(u8)`, `Error::InvalidConfigVersion { raw: String }`, `Error::InvalidEtag { raw: String }`. Don't reuse a generic `Error::Validation(String)` — the typed variant lets callers match on the specific failure.

## How to Add a New Newtype

1. Pick the owning crate. Pure-crate newtypes go in `crates/{domain}-core` or `crates/core`. I/O-only newtypes (e.g. `Etag` for now) can live in their I/O crate, with the understanding that adding a second consumer triggers a move down to `*_core`.
2. Create the module file (`crates/core/src/my_newtype.rs`) with the constructor + `as_str()`/`value()` accessor + `Display` + custom `Deserialize` + `#[serde(transparent)]` `Serialize`. Match the shape in [Anatomy](#anatomy-of-a-newtype).
3. Add a typed error variant to the crate's `Error` enum (`#[error("invalid my_newtype: {0}")]`). Include the offending raw value so error messages tell you what went wrong without needing logs.
4. Re-export from `lib.rs`: `pub use my_newtype::MyNewtype;`. Add a row to the crate's `README.md` Domain Types table.
5. Write unit tests covering: construction with a valid value, rejection of every documented-invalid case, round-trip through serde for a wire-format example, `Display` correctness, and `FromStr` if implemented.
6. Migrate consumers in a single commit per call-site cluster (CLI handlers, store impls, HTTP boundaries). Don't dual-house a `String` field and a typed field "for compatibility" — flip the field type in the same commit as the consumer updates.

The `cargo xtask lint` pipeline does not enforce newtype usage directly. The check is a manual grep at PR time:

```bash
# Forbidden primitive patterns in domain types
grep -rn 'rollout_percentage: u8\|version: String\|etag: String\|method: String' crates lib --include='*.rs'
```

Hits in test code or wire-DTO structs (`PreconditionFailedBody`) are fine; hits in domain types are regressions.

## Lessons from Issue #74

The eight-stream rollout that propagated `Percentage` / `ConfigVersion` / `SagaId` / `Etag` / `http::StatusCode` / `http::Method` produced a few patterns worth lifting up:

- **Don't double-wrap errors.** When the inner `Error` variant already prefixes its message (e.g. `forgeguard_http::Error::Config` displays as `"config error: ..."`), the binary wrapper should add **context** (`failed to load config from '/path'`), not re-prefix. The doubled-prefix pattern showed up in `crates/cli/src/check.rs` before the fix and was caught only by the QA walkthrough — not by lint, not by tests. Use `wrap_err_with(|| format!("failed to <verb> <noun> from '<path>'"))` and let the inner error's `Display` carry its own framing. The canonical example is `crates/cli/src/policies/test.rs`.
- **`Result` returns must have a real failure path.** During the Etag migration, `from_stored -> Result<Self>` and `compute_etag -> Result<Etag>` both ended up with no reachable error case after the inner type became infallible. Code review caught both. When migrating away from primitives, audit `Result` returns at every layer — if `?` is never reachable, drop the wrapper.
- **`Option<T>` is a real signal, not a "maybe later" placeholder.** The Draft / Configured split in optimistic locking surfaced as `EtagCheck::Mismatch.current: Option<Etag>` — Draft orgs genuinely have no etag, and the `Option` encodes that. Resist the urge to invent a "null etag" sentinel value.
- **Tests behind a Cargo feature or external service won't run on `xtask lint`.** The DynamoDB integration tests in `crates/control-plane/src/dynamo_store/tests.rs` need `cargo xtask control-plane test` (which auto-starts dynamodb-local). When refactoring a type that's used in those tests, run that command before claiming the migration is complete.
- **Wire-format DTO structs keep primitives.** `PreconditionFailedBody.current_etag: String` stays a `String` — it's a JSON shape, not a domain value. The conversion from `Option<Etag>` to wire `String` happens at the handler boundary (`match Option<Etag> -> String`). Don't push newtypes into the wire layer just because they exist in the domain.

## Related

- [`visibility-conventions.md`](./visibility-conventions.md) — constructor + accessor shape, `pub(crate)` default, `testing` Cargo feature for cross-crate fixtures.
- [`params-struct-rule.md`](./params-struct-rule.md) — when constructors grow past five args.
- [`optimistic-locking.md`](./optimistic-locking.md) — `Etag` newtype in context, RFC 7232 wire semantics, V5 typed 412.
- [`linting-and-clippy.md`](./linting-and-clippy.md) — workspace lints that back the pattern.
- `~/.claude/patterns/parse-dont-validate.md` — the upstream principle.
- `~/.claude/patterns/type-driven-development.md` — types as specification.
