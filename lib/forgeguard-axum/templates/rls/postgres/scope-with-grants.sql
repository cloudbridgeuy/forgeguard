-- ForgeGuard RLS template: visibility mode "scope-with-grants".
-- Rows are visible when EITHER the scope predicate matches (see scope.sql)
-- OR the row's id was directly granted to the principal outside their
-- scope (fg.granted_ids, set per-transaction by the app from
-- forgeguard_axum::RlsContext::session_statements).
--
-- Session vars read: fg.scope_path, fg.granted_ids
-- Assumes: a `scope_path text NOT NULL` column and an `id` primary key
-- whose text form matches the granted native ids; adapt the `id::text`
-- cast to your schema.
-- Fail-closed: string_to_array(NULL, ',') is NULL, and ANY(NULL) is never
-- true — the grants arm fails closed when fg.granted_ids is empty.
--
-- Replace {{table}} with your table name before applying.

ALTER TABLE {{table}} ENABLE ROW LEVEL SECURITY;

CREATE POLICY fg_scope_with_grants ON {{table}}
    USING (
        (
            NULLIF(current_setting('fg.scope_path', true), '') IS NOT NULL
            AND (
                scope_path = current_setting('fg.scope_path', true)
                OR starts_with(scope_path, current_setting('fg.scope_path', true) || '/')
            )
        )
        OR id::text = ANY (
            string_to_array(NULLIF(current_setting('fg.granted_ids', true), ''), ',')
        )
    );
