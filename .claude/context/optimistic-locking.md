# Optimistic Locking — Control Plane `PUT /api/v1/organizations/{org_id}`

Implements RFC 7232 `If-Match` / `412 Precondition Failed` on proxy-config updates
so that two concurrent writers cannot silently overwrite each other.

Scope: **V5 shipped** — both `InMemoryOrgStore` and `DynamoOrgStore` enforce
`If-Match` / `If-None-Match` identically. V5 adds conditional GET (304) on
`GET /api/v1/organizations/{org_id}` and a typed `reason` field on all 412
bodies. The backend choice (`--store=memory` vs `--store=dynamodb`) is
observationally indistinguishable for PUT semantics.

## Semantics

| Request | Stored | Result |
|---|---|---|
| `PUT` with `If-Match: "X"` — body has `config` — current etag is `"X"` | match | `200 OK`, `ETag: "<new>"`, writes |
| `PUT` with `If-Match: "Y"` — body has `config` — current etag is `"X"` | mismatch | `412 Precondition Failed`, `ETag: "X"`, body `{"error":"etag mismatch","reason":"stale_etag","current_etag":"\"X\""}` |
| `PUT` with `If-Match: "Y"` — body has `config` — org is Draft (no config) | mismatch (empty) | `412`, body `{"error":"etag mismatch","reason":"draft_fail_closed","current_etag":""}` |
| `PUT` with stale `If-Match` — body has **both** `name` and `config` | mismatch | `412 Precondition Failed`, neither name nor config applied |
| `PUT` without `If-Match` — body has `config` | skipped | `200 OK`, unconditional write (backwards-compat) |
| `PUT` with or without `If-Match` — body has **no** `config` (name-only) | skipped | `200 OK`, name updated, etag unchanged |
| `PUT` first-config on Draft without `If-Match` | n/a | `200 OK`, new etag |
| `PUT` with `If-Match: *` — body has `config` — org is Configured | wildcard match | `200 OK`, writes, fresh ETag |
| `PUT` with `If-Match: *` — body has `config` — org is Draft | wildcard fail-closed | `412`, body `{"error":"etag mismatch","reason":"wildcard_on_draft","current_etag":""}`, no ETag response header |
| `PUT` with `If-Match: *` — body has **no** `config` (name-only) | wildcard ignored | `200 OK`, name updated, wildcard ignored with the rest |
| `POST /api/v1/organizations` — body has `config` | n/a (create) | `201 Created`, `ETag: "<new>"` |
| `POST /api/v1/organizations` — body has **no** `config` (Draft create) | n/a (create) | `201 Created`, no ETag header |

### Conditional GET — `If-None-Match` on `GET /api/v1/organizations/{org_id}`

| Request | Stored | Result |
|---|---|---|
| `GET` with `If-None-Match: "X"` — stored etag is `"X"` | match | `304 Not Modified`, `ETag: "X"`, empty body |
| `GET` with `If-None-Match: "Y"` — stored etag is `"X"` | mismatch | `200 OK`, full body, `ETag: "X"` |
| `GET` with `If-None-Match: *` — org is Configured | wildcard match | `304 Not Modified`, `ETag: "<stored>"`, empty body |
| `GET` with `If-None-Match: *` — org is Draft (no stored etag) | wildcard on draft | `200 OK`, full body, no ETag header |
| `GET` with `If-None-Match: "X"` — org is Draft (no stored etag) | no etag to match | `200 OK`, full body, no ETag header |
| `GET` without `If-None-Match` or malformed header | skipped | `200 OK`, full body, `ETag: "<stored>"` when Configured |

Etag format: `"<xxh64 hex>"` — 16-char hex hash of canonical OrgConfig JSON,
double-quotes included (RFC 7232 strong etag).

## Architecture — Functional Core / Imperative Shell

```
handlers::update_handler          ← imperative shell (HTTP extraction + response)
  │
  ├─ etag::parse_if_match          ← pure: header → Option<IfMatch>
  ├─ etag::resolve_if_match        ← pure: (Option<IfMatch>, stored) → ResolvedIfMatch
  │       │
  │       ├─ ResolvedIfMatch::Absent          → pass through (unconditional write)
  │       ├─ ResolvedIfMatch::Strong(s)       → forward expected etag to store
  │       ├─ ResolvedIfMatch::WildcardMatched → unconditional write (configured org)
  │       └─ ResolvedIfMatch::WildcardOnDraft → 412 fail-closed (no store call)
  └─ store::update(..., expected_etag)
        │
        └─ etag::check_etag         ← pure: (stored, expected) → EtagCheck
              │
              └─ EtagCheck::Mismatch { current } → Err(Error::PreconditionFailed { current_etag })

handlers::show_handler            ← imperative shell (HTTP extraction + response)
  │
  ├─ etag::parse_if_match          ← pure: header → Option<IfMatch>
  └─ etag::check_if_none_match     ← pure: (Option<IfMatch>, stored) → IfNoneMatchResult
          │
          ├─ IfNoneMatchResult::Matched           → 304, ETag header, empty body
          ├─ IfNoneMatchResult::WildcardMatched   → 304, ETag header, empty body
          ├─ IfNoneMatchResult::NotMatched        → 200, full body, ETag header when Configured
          └─ IfNoneMatchResult::WildcardOnDraft   → 200, full body, no ETag
```

### Pure core — `crates/control-plane/src/etag.rs`

- `IfMatch` enum — parsed form of the `If-Match` header: `Wildcard` or
  `Strong(String)`. No raw strings escape the parser.
- `ResolvedIfMatch` enum — result of comparing the header against the stored
  etag: `Absent` (no header), `Strong(String)` (forward to store),
  `WildcardMatched` (configured org, write proceeds), `WildcardOnDraft` (fail
  closed, 412).
- `EtagCheck` enum — algebraic data type for the three possible outcomes
  (`Unchecked`, `Match`, `Mismatch { current: String }`). Impossible states are
  impossible: you cannot have a "mismatch with no current" or a "match with
  different strings".
- `parse_if_match(raw: &str) -> Option<IfMatch>` — parses `*` into
  `IfMatch::Wildcard`, any other non-empty value into `IfMatch::Strong`.
  Returns `None` for absent / empty headers.
- `resolve_if_match(header: Option<IfMatch>, stored: Option<&str>) -> ResolvedIfMatch` —
  combines the parsed header with the stored etag into one of the four
  `ResolvedIfMatch` arms. The handler dispatches entirely on this result.
- `check_etag(stored: Option<&str>, expected: Option<&str>) -> EtagCheck` — the
  decision for the strong-match path. Draft-org case: `stored = None` +
  `expected = Some(_)` → `Mismatch { current: "" }` (fail closed).
- `IfNoneMatchResult` enum — four-variant ADT covering all dispatch arms for
  the GET handler: `NotMatched` (no header, or strong header with no stored
  etag or mismatch → 200), `Matched` (strong header equals stored etag → 304),
  `WildcardMatched` (`*` against Configured org → 304), `WildcardOnDraft` (`*`
  against Draft org → 200).
- `check_if_none_match(header: Option<IfMatch>, stored: Option<&str>) -> IfNoneMatchResult` —
  pure conditional-GET decision. Wildcard / strong-match on a Configured org →
  `Matched` / `WildcardMatched` (304). Draft org, mismatch, or absent header →
  `NotMatched` / `WildcardOnDraft` (200).

`derive_expected_etag` was removed; its logic is subsumed by `resolve_if_match`.

21 unit tests — every branch and boundary covered (7 `parse_if_match` + 4
`resolve_if_match` + 4 `check_etag` + 6 `check_if_none_match`).

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

1. Read `If-Match` header → `parse_if_match` → `Option<IfMatch>`.
2. `resolve_if_match(if_match, stored_etag)` produces a `ResolvedIfMatch` arm.
3. `WildcardOnDraft` short-circuits to 412 before the store is called.
   `WildcardMatched` passes `None` expected-etag (unconditional write).
   `Strong(s)` passes `Some(&s)` for the store to enforce.
   `Absent` passes `None` (backwards-compat unconditional write).
4. Store returns `Ok(updated)` (emit new etag), `Err(PreconditionFailed)` (emit
   current etag + 412), or `Err(NotFound)` (404).
5. `ETag` header comes from `updated.configured().and_then(|c| c.etag().parse().ok())`.

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

## 412 body schema

Every 412 response includes a `reason` field that identifies which precondition
check fired. The label values are the single source of truth shared between the
JSON body and the `forgeguard_control_plane_put_org_412_total{reason=...}`
Prometheus metric.

| `reason` value | When it fires |
|---|---|
| `stale_etag` | Strong `If-Match` value did not match the stored etag |
| `draft_fail_closed` | Strong `If-Match` sent against a Draft org (no stored etag) |
| `wildcard_on_draft` | `If-Match: *` sent against a Draft org |

JSON body shape (strong-match / stale case):

```json
{"error":"etag mismatch","reason":"stale_etag","current_etag":"\"abc\""}
```

Draft fail-closed body (`current_etag` is empty string, `reason` distinguishes
it from a regular stale-etag):

```json
{"error":"etag mismatch","reason":"draft_fail_closed","current_etag":""}
```

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
| Pure core — `etag.rs` | 21 unit tests (7 `parse_if_match` + 4 `resolve_if_match` + 4 `check_etag` + 6 `check_if_none_match`) | `crates/control-plane/src/etag.rs#[cfg(test)]` |
| Pure core — `precondition_reason` | 4 unit tests | `crates/control-plane/src/metrics.rs#[cfg(test)]` |
| Pure core — `build_update_condition` | 2 unit tests | `crates/control-plane/src/dynamo_store/mod.rs#[cfg(test)]` |
| Store — `InMemoryOrgStore` | 4 direct tests | `crates/control-plane/src/store/tests.rs` |
| Store — `DynamoOrgStore` | 6 direct tests (feature `dynamodb-tests`) | `crates/control-plane/src/dynamo_store/tests.rs` |
| Handler — `basic.rs` | 5 wire-level tests | `crates/control-plane/src/handlers/tests/basic.rs` |
| Handler — `draft.rs` | 5 wire-level tests | `crates/control-plane/src/handlers/tests/draft.rs` |
| Handler — `optimistic_locking.rs` | 13 wire-level tests | `crates/control-plane/src/handlers/tests/optimistic_locking.rs` |
| Handler — `crud.rs` | 16 wire-level tests | `crates/control-plane/src/handlers/tests/crud.rs` |
| Handler — `conditional_get.rs` | 7 wire-level tests | `crates/control-plane/src/handlers/tests/conditional_get.rs` |
| Handler — `metrics_412.rs` | 3 wire-level tests | `crates/control-plane/src/handlers/tests/metrics_412.rs` |
| Handler — `metrics_endpoint.rs` | 1 wire-level test | `crates/control-plane/src/handlers/tests/metrics_endpoint.rs` |

V1 ships 4 of the handler tests (matching / stale / absent / name-only ignored). V2 adds 3 more pinning Draft first-PUT and mixed name+config semantics (`draft_first_put_without_if_match_succeeds_and_returns_etag`, `draft_put_with_any_if_match_returns_412`, `name_plus_config_put_honors_if_match`). V3 adds 6 direct `DynamoOrgStore` tests mirroring the V1 + V2 scenarios against a live `dynamodb-local` — run via `cargo xtask control-plane test`. V4 adds wildcard handler tests, POST ETag tests, 412 metric counter tests, and metrics endpoint smoke test. V5 adds 7 `conditional_get.rs` handler tests and 6 `check_if_none_match` pure core tests.

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

## Metrics (V4)

412 responses increment a Prometheus counter exposed on `GET /metrics`
(anonymous, no auth required):

```
forgeguard_control_plane_put_org_412_total{reason="<value>"}
```

The `reason` label values are defined in [412 body schema](#412-body-schema).

No `org_id` label is included — adding per-org cardinality would produce an
unbounded label set. Per-org attribution is available via structured logs
instead (the `update_org` tracing span carries a `precondition_reason`
attribute that mirrors the `reason` label).

```sh
curl -s http://localhost:3001/metrics | grep put_org_412_total
# forgeguard_control_plane_put_org_412_total{reason="draft_fail_closed"} 0
# forgeguard_control_plane_put_org_412_total{reason="stale_etag"} 0
# forgeguard_control_plane_put_org_412_total{reason="wildcard_on_draft"} 0
```

## V4 — Wildcard, POST ETag, and 412 Metrics

V4 is an observability and ergonomics slice on top of V3.

**What V4 delivers:**

- `IfMatch` / `ResolvedIfMatch` ADTs replace the raw `Option<String>` threading.
  `parse_if_match` returns `Option<IfMatch>`; the new `resolve_if_match`
  function computes `ResolvedIfMatch` in a single pure call, covering all four
  dispatch arms (`Absent`, `Strong`, `WildcardMatched`, `WildcardOnDraft`).
  `derive_expected_etag` is removed.
- `If-Match: *` (wildcard) is now honoured: matches any configured org
  unconditionally, fails closed (412) on Draft orgs.
- `POST /api/v1/organizations` with a `config` field returns an `ETag` header in
  the 201 response. Draft creates (no `config`) return no ETag. This allows
  create-then-update without a pre-flight GET.
- 412 Prometheus counter (`forgeguard_control_plane_put_org_412_total`) with
  `reason` label and matching `precondition_reason` span attribute.

No client crate wiring is included in V4.

## V5 — Conditional GET and typed 412 body

V5 is an ergonomics and observability slice on top of V4.

**What V5 delivers:**

- `If-None-Match` on `GET /api/v1/organizations/{org_id}` — four handler
  branches: strong-match → 304; strong-mismatch or Draft → 200; wildcard on
  Configured → 304; wildcard on Draft → 200. Behaviour is symmetric with the
  existing `If-None-Match` on `/proxy-config`.
- `check_if_none_match(header: Option<IfMatch>, stored: Option<&str>) -> IfNoneMatchResult`
  pure core in `etag.rs` — the decision lives entirely outside the HTTP layer.
  `IfNoneMatchResult` is a four-variant ADT (`NotMatched` / `Matched` /
  `WildcardMatched` / `WildcardOnDraft`).
- `reason` field on all 412 response bodies — values and schema documented in
  [412 body schema](#412-body-schema); the same label drives the
  `forgeguard_control_plane_put_org_412_total{reason=...}` Prometheus counter.

## References

- Issue: anthropics-internal-tracked as GitHub issue #56
- Plan: `.claude/plans/2026-04-17-issue-56-v1-optimistic-locking.md` (local-only)
- Pattern files: `~/.claude/patterns/functional-core-imperative-shell.md`,
  `~/.claude/patterns/algebraic-data-types.md`,
  `~/.claude/patterns/parse-dont-validate.md`
