-- ForgeGuard RLS template: visibility mode "scope" (default).
-- Rows are visible when the row's scope_path sits at or under the
-- principal's scope path (fg.scope_path, set per-transaction by the app
-- from forgeguard_axum::RlsContext::session_statements).
--
-- Session vars read: fg.scope_path
-- Assumes: a `scope_path text NOT NULL` column holding the row's org-unit
-- path in ForgeGuard's `root/unit/subunit` form.
-- Fail-closed: current_setting(..., true) yields NULL when unset, and an
-- empty fg.scope_path matches nothing.
--
-- Replace {{table}} with your table name before applying.

ALTER TABLE {{table}} ENABLE ROW LEVEL SECURITY;

CREATE POLICY fg_scope ON {{table}}
    USING (
        NULLIF(current_setting('fg.scope_path', true), '') IS NOT NULL
        AND (
            scope_path = current_setting('fg.scope_path', true)
            OR starts_with(scope_path, current_setting('fg.scope_path', true) || '/')
        )
    );
