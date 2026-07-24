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

/// Extractor bridging the request's decision context to database RLS.
///
/// Built from the [`crate::ForgeGuardDecision`] and
/// [`crate::ForgeGuardIdentity`] extensions; all fields degrade to empty
/// when the middleware didn't run, no record was produced, or the route is
/// public — empty values still SET the session vars, and the reference
/// policies fail closed on empty (no rows visible).
#[derive(Debug, Clone)]
pub struct RlsContext {
    scope_path: String,
    granted_ids: Vec<String>,
    principal_id: String,
}

impl RlsContext {
    /// The principal's org-unit ancestry (`root/eng`), or empty.
    pub fn scope_path(&self) -> &str {
        &self.scope_path
    }

    /// Directly-granted resource IDs — the exception list, usually empty.
    pub fn granted_ids(&self) -> &[String] {
        &self.granted_ids
    }

    /// The authenticated user id, or empty.
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Statements to run inside the app's transaction, in order.
    pub fn session_statements(&self, dialect: Dialect) -> Vec<Statement> {
        session_statements_for(
            &RlsValues {
                scope_path: self.scope_path.clone(),
                granted_ids: self.granted_ids.clone(),
                principal_id: self.principal_id.clone(),
            },
            dialect,
        )
    }
}

impl<S> axum::extract::FromRequestParts<S> for RlsContext
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // `.get().cloned()`, NOT `.remove()`: handlers commonly extract
        // RlsContext ALONGSIDE ForgeGuardDecision/ForgeGuardIdentity, and
        // removal here would make those extractors come up empty depending
        // on parameter order — an action-at-a-distance bug.
        let record = parts
            .extensions
            .get::<crate::ForgeGuardDecision>()
            .cloned()
            .and_then(|d| d.0);
        let identity = parts
            .extensions
            .get::<crate::ForgeGuardIdentity>()
            .cloned()
            .and_then(|i| i.0);

        Ok(Self {
            scope_path: record
                .as_ref()
                .map(|r| r.scope_path().to_string())
                .unwrap_or_default(),
            granted_ids: record
                .as_ref()
                .map(|r| r.granted_ids().iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            principal_id: identity
                .as_ref()
                .map(|i| i.user_id().as_str().to_string())
                .unwrap_or_default(),
        })
    }
}

/// Reference Postgres RLS policy templates, one per visibility mode.
/// Also available as files under `templates/rls/postgres/` in the repo.
pub mod templates {
    /// Mode `scope`: rows at/under the principal's scope path.
    pub const SCOPE: &str = include_str!("../templates/rls/postgres/scope.sql");
    /// Mode `scope-with-grants`: scope OR directly-granted resource ids.
    pub const SCOPE_WITH_GRANTS: &str =
        include_str!("../templates/rls/postgres/scope-with-grants.sql");
    /// Mode `grants-only`: directly-granted resource ids only.
    pub const GRANTS_ONLY: &str = include_str!("../templates/rls/postgres/grants-only.sql");
    /// Mode `owner`: rows owned by the principal.
    pub const OWNER: &str = include_str!("../templates/rls/postgres/owner.sql");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::extract::FromRequestParts;
    use forgeguard_authn_core::{Identity, IdentityParams};
    use forgeguard_authz_core::{
        AuthzStore as _, CedarEngine, DecisionQuery, DecisionRecord, MemoryStore, ModelState,
        Snapshot, StoreWrite,
    };
    use forgeguard_core::principal::PrincipalKind as AuthzPrincipalKind;
    use forgeguard_core::{
        Fgrn, Grant, NativeId, OrgUnit, Principal, PrincipalKind, Segment, Spine, UserId,
    };

    use super::*;
    use crate::{ForgeGuardDecision, ForgeGuardIdentity};

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    fn maria() -> Fgrn {
        Fgrn::principal(&org(), &nid("maria"))
    }

    fn doc() -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_1"),
        )
    }

    fn make_identity() -> Identity {
        Identity::new(IdentityParams {
            user_id: UserId::new("alice").unwrap(),
            tenant_id: None,
            groups: vec![],
            expiry: None,
            resolver: "jwt",
            extra: None,
            principal_kind: PrincipalKind::User,
        })
    }

    /// Mirrors `headers.rs`'s `decision_record` fixture — `DecisionRecord::new`
    /// is `pub(crate)` to authz-core, so a record can only be produced here
    /// by running the real engine against a store.
    async fn decision_record() -> DecisionRecord {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let spine = Spine::try_new(vec![OrgUnit::try_new(root.clone(), None).unwrap()]).unwrap();
        let mut model = ModelState::new(spine);
        model.upsert_principal(
            Principal::try_new(maria(), AuthzPrincipalKind::Human, root).unwrap(),
        );
        let store = MemoryStore::new(model);

        store
            .apply(StoreWrite::PutGrant(
                Grant::try_new(
                    doc(),
                    vec![forgeguard_core::Verb::try_new("read").unwrap()],
                    maria(),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let engine = CedarEngine::new(
            Snapshot::from_policy_text(
                r#"permit(principal, action == Action::"unrelated-action", resource);"#,
            )
            .unwrap(),
        );
        let query = DecisionQuery::new(
            maria(),
            forgeguard_core::Verb::try_new("read").unwrap(),
            doc(),
        );

        engine.decide(&store, &query).await.unwrap()
    }

    fn bare_parts() -> axum::http::request::Parts {
        let (parts, _) = axum::http::Request::builder()
            .uri("/")
            .body(())
            .unwrap()
            .into_parts();
        parts
    }

    #[tokio::test]
    async fn extractor_defaults_to_empty_without_extensions() {
        let mut parts = bare_parts();
        let ctx = RlsContext::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(ctx.scope_path(), "");
        assert!(ctx.granted_ids().is_empty());
        assert_eq!(ctx.principal_id(), "");

        let stmts = ctx.session_statements(Dialect::Postgres);
        assert_eq!(stmts.len(), 3);
        assert!(stmts.iter().all(|s| s.params() == [""]));
    }

    #[tokio::test]
    async fn extractor_projects_record_and_identity() {
        let record = decision_record().await;
        let identity = make_identity();
        let mut parts = bare_parts();
        parts.extensions.insert(ForgeGuardDecision(Some(record)));
        parts.extensions.insert(ForgeGuardIdentity(Some(identity)));

        let ctx = RlsContext::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(ctx.scope_path(), "root");
        assert_eq!(ctx.granted_ids(), ["doc_1"]);
        assert_eq!(ctx.principal_id(), "alice");
    }

    #[tokio::test]
    async fn coexists_with_decision_extractor_in_any_order() {
        let record = decision_record().await;
        let identity = make_identity();
        let mut parts = bare_parts();
        parts.extensions.insert(ForgeGuardDecision(Some(record)));
        parts.extensions.insert(ForgeGuardIdentity(Some(identity)));

        // RlsContext extracted first, then ForgeGuardDecision — both must
        // still see the record (non-destructive extraction).
        let ctx = RlsContext::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        let ForgeGuardDecision(decision) = ForgeGuardDecision::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(ctx.scope_path(), "root");
        assert!(decision.is_some());
    }

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

    #[test]
    fn all_templates_are_nonempty_rls_and_reference_table_placeholder() {
        for tpl in [
            templates::SCOPE,
            templates::SCOPE_WITH_GRANTS,
            templates::GRANTS_ONLY,
            templates::OWNER,
        ] {
            assert!(!tpl.is_empty());
            assert!(tpl.contains("ROW LEVEL SECURITY"));
            assert!(tpl.contains("{{table}}"));
        }
    }

    #[test]
    fn scope_template_reads_only_scope_path() {
        assert!(templates::SCOPE.contains("fg.scope_path"));
        assert!(!templates::SCOPE.contains("fg.granted_ids"));
        assert!(!templates::SCOPE.contains("fg.principal_id"));
    }

    #[test]
    fn scope_with_grants_template_reads_scope_and_grants() {
        assert!(templates::SCOPE_WITH_GRANTS.contains("fg.scope_path"));
        assert!(templates::SCOPE_WITH_GRANTS.contains("fg.granted_ids"));
        assert!(!templates::SCOPE_WITH_GRANTS.contains("fg.principal_id"));
    }

    #[test]
    fn grants_only_template_reads_only_granted_ids() {
        assert!(templates::GRANTS_ONLY.contains("fg.granted_ids"));
        assert!(!templates::GRANTS_ONLY.contains("fg.scope_path"));
        assert!(!templates::GRANTS_ONLY.contains("fg.principal_id"));
    }

    #[test]
    fn owner_template_reads_only_principal_id() {
        assert!(templates::OWNER.contains("fg.principal_id"));
        assert!(!templates::OWNER.contains("fg.scope_path"));
        assert!(!templates::OWNER.contains("fg.granted_ids"));
    }
}
