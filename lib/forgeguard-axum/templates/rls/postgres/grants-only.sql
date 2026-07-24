-- ForgeGuard RLS template: visibility mode "grants-only".
-- Rows are visible ONLY when the row's id was directly granted to the
-- principal (fg.granted_ids, set per-transaction by the app from
-- forgeguard_axum::RlsContext::session_statements) — no scope fallback.
--
-- Session vars read: fg.granted_ids
-- Assumes: an `id` primary key whose text form matches the granted native
-- ids; adapt the `id::text` cast to your schema.
-- Fail-closed: string_to_array(NULL, ',') is NULL, and ANY(NULL) is never
-- true — an empty fg.granted_ids matches nothing.
--
-- Replace {{table}} with your table name before applying.

ALTER TABLE {{table}} ENABLE ROW LEVEL SECURITY;

CREATE POLICY fg_grants_only ON {{table}}
    USING (
        id::text = ANY (
            string_to_array(NULLIF(current_setting('fg.granted_ids', true), ''), ',')
        )
    );
