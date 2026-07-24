# RLS Session Bridge

Issue #111 V4. `forgeguard-axum` bridges the request's `DecisionRecord` /
`Identity` into Postgres row-level security via three transaction-local
session variables, plus ships four reference RLS policy templates.

## Behavior

- `forgeguard_axum::RlsContext` — infallible `FromRequestParts` extractor.
  Reads `ForgeGuardDecision`/`ForgeGuardIdentity` from request extensions via
  `.get().cloned()` (never `.remove()`, so it coexists with the other
  extractors in the same handler). Degrades every field to empty when the
  middleware didn't run, produced no record, or the route is public — never
  fails the request.
- `RlsContext::session_statements(Dialect)` — pure, dialect-parameterized
  builder. Returns a `Vec<Statement>`, each `sql()` + `params()` pair using
  Postgres `set_config(name, value, true)` — the `true` third argument makes
  it transaction-local (`SET LOCAL` semantics, resets at `COMMIT`/`ROLLBACK`).
  Building statements is data-in/data-out; running them inside the caller's
  own transaction, alongside their queries, is the embedding app's job
  (Functional Core / Imperative Shell — this crate has no DB driver
  dependency).
- `Dialect` — `#[non_exhaustive]` enum; `Postgres` is the only variant today.
  Make Impossible States Impossible: adding a dialect later is additive, not
  a breaking match change for downstream code that doesn't exhaustively match.
- `Statement` — `sql()` / `params()` accessors, no public fields (PDV).
- Values are always bound as `$1` parameters, never spliced into SQL text.

## Session variables

| Variable | Source | Format |
| --- | --- | --- |
| `fg.scope_path` | `DecisionRecord::scope_path()` | `root/unit/subunit`, or empty |
| `fg.granted_ids` | `DecisionRecord::granted_ids()` | comma-joined native ids, or empty |
| `fg.principal_id` | `Identity::user_id()` | the app's own user id, or empty |

All three are always set (empty string when absent), so the session state a
policy predicate sees is deterministic — never "variable doesn't exist."

## `granted_ids` — scope limitation and escape hatch

`DecisionRecord::granted_ids()` (`crates/authz-core/src/engine_cedar/enrich.rs`,
`granted_ids_of`) collects grants directly targeting the principal, filtered
to the resource(s) actually referenced by the `EntitySlice` built for this
request's decision — i.e. the resource the request queried, not a
cross-table exception list. A principal can hold a direct grant on some
other resource this request never touched, and it will not appear in
`fg.granted_ids`.

This is a deliberate scope choice, not an oversight: a true cross-resource
grant list would require a dedicated store query with no current consumer
(YAGNI at V4). The escape hatch is straightforward when a real caller needs
it — add a store-backed lookup (e.g. `GrantStore::grants_for_principal`)
and feed its result into `RlsValues` instead of (or in addition to)
`granted_ids_of`'s slice-scoped list; `session_statements_for` doesn't care
where its `RlsValues` came from.

## Mode catalog (reference templates)

`forgeguard_axum::rls::templates` ships four Postgres policies as
`include_str!` consts, mirrored as files under
`lib/forgeguard-axum/templates/rls/postgres/*.sql` for direct `psql`
application (`cargo package --list` may not surface the files themselves,
but `include_str!` still embeds their contents in the published crate).

| Mode | Const / File | Predicate | When to use |
| --- | --- | --- | --- |
| `scope` | `SCOPE` / `scope.sql` | row's `scope_path` at/under `fg.scope_path` | default — org-unit-scoped visibility |
| `scope-with-grants` | `SCOPE_WITH_GRANTS` / `scope-with-grants.sql` | scope predicate OR `id` in `fg.granted_ids` | scope, plus occasional direct grants outside it |
| `grants-only` | `GRANTS_ONLY` / `grants-only.sql` | `id` in `fg.granted_ids` | rows visible only via explicit grant, no scope fallback |
| `owner` | `OWNER` / `owner.sql` | `owner_id` equals `fg.principal_id` | per-user ownership, no org-unit scoping |

Every template is fail-closed: `current_setting(..., true)` returns `NULL`
when a session variable is unset, and each predicate is written so
`NULL`/empty never matches a row. Templates note the `FORCE ROW LEVEL
SECURITY` requirement for connections that own the table (`ENABLE ROW LEVEL
SECURITY` alone doesn't restrict table owners/superusers).

## See also

- `lib/forgeguard-axum/README.md` — "RLS Session Bridge" section (extractor
  usage, sqlx-flavored example, mode catalog).
- `lib/forgeguard-axum/templates/rls/postgres/README.md` — template catalog,
  apply instructions, session-variable table.
- `crates/authz-core/src/engine_cedar/enrich.rs` — `granted_ids_of`.
- `crates/authz-core/src/engine_cedar/record.rs` — `DecisionRecord::granted_ids()`.
