//! RLS session bridge (#111 V4): project the request's decision context
//! into per-transaction Postgres session variables.
//!
//! Pure core: [`Statement`] is plain data (`sql` + positional `params`);
//! executing it on a connection is the embedding app's job — run all
//! statements INSIDE the transaction that performs your queries, because
//! `set_config(..., true)` is transaction-local (`SET LOCAL` semantics):
//!
//! ```text
//! let ctx: RlsContext = /* extractor */;
//! let mut txn = pool.begin().await?;
//! for stmt in ctx.session_statements(Dialect::Postgres) {
//!     sqlx::query(stmt.sql())
//!         .bind(&stmt.params()[0])
//!         .execute(&mut *txn).await?;   // adapt to your driver
//! }
//! // ... your queries, now filtered by the RLS policies ...
//! txn.commit().await?;
//! ```
//!
//! Reference policy templates for each visibility mode ship in
//! [`crate::rls::templates`] and under `templates/rls/postgres/` in the
//! repository.

/// SQL dialect for [`RlsContext::session_statements`].
///
/// Postgres only in this phase; the enum is non-exhaustive so adding
/// dialects later is not a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// Postgres: `SELECT set_config('fg.*', $1, true)` — transaction-local.
    Postgres,
}

/// One executable statement: SQL text plus positional string parameters.
///
/// Values are always bound, never spliced into the SQL — injection-safe by
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    sql: String,
    params: Vec<String>,
}

impl Statement {
    /// The SQL text, with `$n` placeholders (Postgres).
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Positional parameter values for the placeholders.
    pub fn params(&self) -> &[String] {
        &self.params
    }
}

/// The three session values, already stringified. Empty strings mean
/// "absent" — all three vars are ALWAYS set so session state is
/// deterministic and templates fail closed on empty.
pub(crate) struct RlsValues {
    pub(crate) scope_path: String,
    pub(crate) granted_ids: Vec<String>,
    pub(crate) principal_id: String,
}

/// The `set_config` variable name in each tuple below is a compile-time
/// constant from this array — not request data — so the `format!` is not an
/// injection surface; only `params` ever carries request-derived values.
pub(crate) fn session_statements_for(values: &RlsValues, dialect: Dialect) -> Vec<Statement> {
    match dialect {
        Dialect::Postgres => [
            ("fg.scope_path", values.scope_path.clone()),
            ("fg.granted_ids", values.granted_ids.join(",")),
            ("fg.principal_id", values.principal_id.clone()),
        ]
        .into_iter()
        .map(|(var, value)| Statement {
            sql: format!("SELECT set_config('{var}', $1, true)"),
            params: vec![value],
        })
        .collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn values() -> RlsValues {
        RlsValues {
            scope_path: "root/eng".to_string(),
            granted_ids: vec!["doc-1".to_string(), "doc-9".to_string()],
            principal_id: "alice".to_string(),
        }
    }

    #[test]
    fn postgres_emits_three_parameterized_set_configs() {
        let stmts = session_statements_for(&values(), Dialect::Postgres);
        assert_eq!(stmts.len(), 3);
        assert_eq!(
            stmts[0].sql(),
            "SELECT set_config('fg.scope_path', $1, true)"
        );
        assert_eq!(stmts[0].params(), ["root/eng"]);
        assert_eq!(
            stmts[1].sql(),
            "SELECT set_config('fg.granted_ids', $1, true)"
        );
        assert_eq!(stmts[1].params(), ["doc-1,doc-9"]);
        assert_eq!(
            stmts[2].sql(),
            "SELECT set_config('fg.principal_id', $1, true)"
        );
        assert_eq!(stmts[2].params(), ["alice"]);
    }

    #[test]
    fn absent_values_still_set_all_three_vars_empty() {
        let empty = RlsValues {
            scope_path: String::new(),
            granted_ids: vec![],
            principal_id: String::new(),
        };
        let stmts = session_statements_for(&empty, Dialect::Postgres);
        assert_eq!(stmts.len(), 3);
        assert!(stmts.iter().all(|s| s.params() == [""]));
    }

    #[test]
    fn values_never_appear_in_sql_text() {
        let hostile = RlsValues {
            scope_path: "'; DROP TABLE users; --".to_string(),
            granted_ids: vec![],
            principal_id: String::new(),
        };
        let stmts = session_statements_for(&hostile, Dialect::Postgres);
        assert!(stmts.iter().all(|s| !s.sql().contains("DROP TABLE")));
    }
}
