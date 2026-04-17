# Optimistic Locking — Control Plane `PUT /api/v1/organizations/{org_id}`

Implements RFC 7232 `If-Match` / `412 Precondition Failed` on proxy-config updates
so that two concurrent writers cannot silently overwrite each other.

Scope: **V3 shipped** — both `InMemoryOrgStore` and `DynamoOrgStore` enforce
`If-Match` identically. The backend choice (`--store=memory` vs
`--store=dynamodb`) is observationally indistinguishable for PUT semantics.

## Semantics

| Request | Stored | Result |
|---|---|---|
| `PUT` with `If-Match: "X"` — body has `config` — current etag is `"X"` | match | `200 OK`, `ETag: "<new>"`, writes |
| `PUT` with `If-Match: "Y"` — body has `config` — current etag is `"X"` | mismatch | `412 Precondition Failed`, `ETag: "X"`, body `{"error":"etag mismatch","current_etag":"\"X\""}` |
| `PUT` with `If-Match: "Y"` — body has `config` — org is Draft (no config) | mismatch (empty) | `412`, body `{"error":"etag mismatch","current_etag":""}` |
| `PUT` with stale `If-Match` — body has **both** `name` and `config` | mismatch | `412 Precondition Failed`, neither name nor config applied |
| `PUT` without `If-Match` — body has `config` | skipped | `200 OK`, unconditional write (backwards-compat) |
| `PUT` with or without `If-Match` — body has **no** `config` (name-only) | skipped | `200 OK`, name updated, etag unchanged |
| `PUT` first-config on Draft without `If-Match` | n/a | `200 OK`, new etag |

Etag format: `"<xxh64 hex>"` — 16-char hex hash of canonical OrgConfig JSON,
double-quotes included (RFC 7232 strong etag).

## Architecture — Functional Core / Imperative Shell

```
handlers::update_handler          ← imperative shell (HTTP extraction + response)
  │
  ├─ etag::parse_if_match          ← pure: header → Option<String>
  ├─ etag::derive_expected_etag    ← pure: (body_has_config, if_match) → Option<String>
  └─ store::update(..., expected_etag)
        │
        └─ etag::check_etag         ← pure: (stored, expected) → EtagCheck
              │
              └─ EtagCheck::Mismatch { current } → Err(Error::PreconditionFailed { current_etag })
```

### Pure core — `crates/control-plane/src/etag.rs`

- `EtagCheck` enum — algebraic data type for the three possible outcomes
  (`Unchecked`, `Match`, `Mismatch { current: String }`). Impossible states are
  impossible: you cannot have a "mismatch with no current" or a "match with
  different strings".
- `parse_if_match(raw: &str) -> Option<String>` — trim + empty-to-None.
- `derive_expected_etag(body_has_config: bool, if_match: Option<&str>) -> Option<String>` — returns `None` for name-only bodies, forwards `if_match` when the body touches config.
- `check_etag(stored: Option<&str>, expected: Option<&str>) -> EtagCheck` — the decision. Draft-org case: `stored = None` + `expected = Some(_)` → `Mismatch { current: "" }` (fail closed).

15 unit tests — every branch and boundary covered.

### Imperative shell — `store::OrgStore::update`

Signature carries `expected_etag: Option<&str>`. `None` means unconditional
(backwards-compat). `Some(e)` means enforce.

```rust
let stored_etag = current.configured().map(ConfiguredConfig::etag);
if let EtagCheck::Mismatch { current: current_etag } =
    check_etag(stored_etag, expected_etag)
{
    return Err(Error::PreconditionFailed { current_etag });
}
```

`AnyOrgStore::update` forwards `expected_etag` to both backends.
`DynamoOrgStore::update` issues a conditional `PutItem` with
`ConditionExpression = attribute_exists(#pk) AND #etag = :expected_etag`
when `expected_etag.is_some()`; on `ConditionalCheckFailedException` it
recovers the current etag via a follow-up `GetItem` and returns the same
`Error::PreconditionFailed { current_etag }` the memory store uses. When
the stored item has no etag attribute (Draft race), the recovered current
is `""`, matching the memory store's fail-closed contract.

### Handler — `handlers::update_handler`

1. Read `If-Match` header → `parse_if_match` → `Option<String>`.
2. `derive_expected_etag(body.config.is_some(), if_match)` produces the check.
3. Store returns `Ok(updated)` (emit new etag), `Err(PreconditionFailed)` (emit
   current etag + 412), or `Err(NotFound)` (404).
4. `ETag` header comes from `updated.configured().and_then(|c| c.etag().parse().ok())`.

`Json<T>` is the last extractor (consumes the body).

## Error variant

```rust
// crates/control-plane/src/error.rs
#[error("precondition failed (current etag: {current_etag:?})")]
PreconditionFailed { current_etag: String },
```

`current_etag` is carried as an owned `String` so the handler can set it both in
the response header and in the JSON body without coupling to the store's
lifetime.

## Client expectations

ForgeGuard-owned callers (`forgeguard_cli`, dashboard, xtask) **should** send
`If-Match` on every PUT that touches `config`. Missing `If-Match` is tolerated
solely to avoid breaking ad-hoc scripts and existing automation.

```sh
ETAG=$(curl -s -I -H 'x-api-key: test-key' \
  http://localhost:3001/api/v1/organizations/org-acme/proxy-config \
  | awk 'tolower($1)=="etag:" {print $2}' | tr -d '\r')

curl -is -H 'x-api-key: test-key' -H "If-Match: $ETAG" \
  -H 'content-type: application/json' \
  -X PUT http://localhost:3001/api/v1/organizations/org-acme \
  -d '{"config": { ... }}'
```

On a 412, the client should GET `/proxy-config` to fetch the fresh etag, rebase
the change, and retry.

## Tests

| Layer | Count | Where |
|---|---|---|
| Pure core — `etag.rs` | 15 unit tests | `crates/control-plane/src/etag.rs#[cfg(test)]` |
| Pure core — `build_update_condition` | 2 unit tests | `crates/control-plane/src/dynamo_store/mod.rs#[cfg(test)]` |
| Store — `InMemoryOrgStore` | 4 direct tests | `crates/control-plane/src/store/tests.rs` |
| Store — `DynamoOrgStore` | 6 direct tests (feature `dynamodb-tests`) | `crates/control-plane/src/dynamo_store/tests.rs` |
| Handler — integration | 7 wire-level tests | `crates/control-plane/src/handlers/tests/` |

V1 ships 4 of the handler tests (matching / stale / absent / name-only ignored). V2 adds 3 more pinning Draft first-PUT and mixed name+config semantics (`draft_first_put_without_if_match_succeeds_and_returns_etag`, `draft_put_with_any_if_match_returns_412`, `name_plus_config_put_honors_if_match`). V3 adds 6 direct `DynamoOrgStore` tests mirroring the V1 + V2 scenarios against a live `dynamodb-local` — run via `cargo xtask control-plane test`.

Run via `cargo xtask lint` (includes `cargo test -p forgeguard_control_plane`).

## DynamoDB enforcement (V3)

`DynamoOrgStore::update` issues a conditional `PutItem` with
`ConditionExpression = attribute_exists(#pk) AND #etag = :expected_etag`
when `If-Match` is present. On `ConditionalCheckFailedException` the store
does a follow-up `GetItem` to recover the current etag and returns
`Error::PreconditionFailed { current_etag }`. On the Draft case (no stored
etag yet), the recovered current is `""` — matching the memory store's
fail-closed behaviour.

The pure condition builder (`build_update_condition`) and the shell
(`DynamoOrgStore::update`) sit on opposite sides of the FCIS boundary:
the builder is a total function with no I/O, while the shell binds its
output to an AWS SDK call. A `ConditionParts` struct bundles the condition
expression, its placeholder names, and its values so half-formed
conditions are structurally impossible.

When `expected_etag` is `None` and the `PutItem` still fails CCFE, the
code treats it as a TOCTOU race (item deleted between the pre-flight
`GetItem` for signing-key preservation and the `PutItem`) and returns
`Error::NotFound` rather than `PreconditionFailed`.

Verify end-to-end with `cargo xtask control-plane test` (boots
`dynamodb-local`).

## References

- Issue: anthropics-internal-tracked as GitHub issue #56
- Plan: `.claude/plans/2026-04-17-issue-56-v1-optimistic-locking.md` (local-only)
- Pattern files: `~/.claude/patterns/functional-core-imperative-shell.md`,
  `~/.claude/patterns/algebraic-data-types.md`,
  `~/.claude/patterns/parse-dont-validate.md`
