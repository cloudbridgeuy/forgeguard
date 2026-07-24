-- ForgeGuard RLS template: visibility mode "owner".
-- Rows are visible ONLY when the row's owner_id matches the authenticated
-- principal (fg.principal_id, set per-transaction by the app from
-- forgeguard_axum::RlsContext::session_statements).
--
-- Session vars read: fg.principal_id
-- Assumes: an `owner_id` column whose text form matches the identity's
-- user id; adapt the `owner_id::text` cast to your schema.
-- Fail-closed: current_setting(..., true) yields NULL when unset, and an
-- empty fg.principal_id matches nothing.
--
-- Replace {{table}} with your table name before applying.

ALTER TABLE {{table}} ENABLE ROW LEVEL SECURITY;

CREATE POLICY fg_owner ON {{table}}
    USING (
        NULLIF(current_setting('fg.principal_id', true), '') IS NOT NULL
        AND owner_id::text = current_setting('fg.principal_id', true)
    );
