# ForgeGuard Postgres RLS templates

Reference row-level security policies keyed to the three session variables
`forgeguard_axum::RlsContext` projects per request. Each file targets one
visibility mode; pick the one matching your table's access model, or use
them as a starting point for a custom policy.

## Session variables

| Variable | Source | Format |
| --- | --- | --- |
| `fg.scope_path` | `DecisionRecord::scope_path()` | `root/unit/subunit`, or empty |
| `fg.granted_ids` | `DecisionRecord::granted_ids()` | comma-joined native ids, or empty |
| `fg.principal_id` | `Identity::user_id()` | the app's own user id, or empty |

All three are always set (empty string when absent) so session state is
deterministic; every template treats an empty/unset variable as "grant
nothing" (fail closed).

## Mode catalog

| Mode | File | Predicate | When to use |
| --- | --- | --- | --- |
| `scope` | `scope.sql` | row's `scope_path` at/under `fg.scope_path` | default — org-unit-scoped visibility |
| `scope-with-grants` | `scope-with-grants.sql` | scope predicate OR `id` in `fg.granted_ids` | scope, plus occasional direct grants outside it |
| `grants-only` | `grants-only.sql` | `id` in `fg.granted_ids` | rows visible only via explicit grant, no scope fallback |
| `owner` | `owner.sql` | `owner_id` equals `fg.principal_id` | per-user ownership, no org-unit scoping |

## How to apply

1. Copy the template for your mode and replace every `{{table}}` with your
   table name.
2. Apply it with `psql`, e.g.:

   ```text
   psql "$DATABASE_URL" -f scope.sql
   ```

3. Run the three `set_config` statements from
   `RlsContext::session_statements(Dialect::Postgres)` **and** your queries
   inside the **same transaction** — `set_config(..., true)` is
   transaction-local (`SET LOCAL` semantics) and resets at `COMMIT`/`ROLLBACK`.

## Non-superuser roles only

`ENABLE ROW LEVEL SECURITY` does not restrict table owners or superusers —
policies are bypassed for those roles unless the table also has `FORCE ROW
LEVEL SECURITY`. Add `ALTER TABLE {{table}} FORCE ROW LEVEL SECURITY;` if
your application connects as the table owner.

## `granted_ids` scope note

`fg.granted_ids` today reflects only grants on the resource actually
queried by the request that produced the `DecisionRecord` — not a
cross-table exception list. See `.claude/context/rls-bridge.md` for the
full rationale and the future store-query escape hatch.

## See also

`forgeguard_axum::RlsContext` and `forgeguard_axum::rls::templates` (the
same file contents as `include_str!` consts, guaranteed to ship with the
published crate).
