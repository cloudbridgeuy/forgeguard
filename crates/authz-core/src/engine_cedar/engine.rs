//! The embedded engine: one consistent read, in-process Cedar evaluation,
//! versioned decision records.

use std::str::FromStr;

use cedar_policy::{Authorizer, Context, EntityId, EntityTypeName, EntityUid, PolicySet, Request};

use crate::engine_cedar::record::{Decision, DecisionQuery, DecisionRecord};
use crate::engine_cedar::translate::{
    cedar_principal_type, grant_policies, slice_to_entities, uid,
};
use crate::error::{Error, Result};
use crate::snapshot::Snapshot;
use crate::store::{AuthzStore, EntitySlice, SliceQuery};

/// In-process Cedar evaluation against a pinned snapshot.
pub struct CedarEngine {
    snapshot: Snapshot,
}

impl CedarEngine {
    /// An engine evaluating against `snapshot`.
    pub fn new(snapshot: Snapshot) -> Self {
        Self { snapshot }
    }

    /// The pinned snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Decide one query: ONE store read at ONE revision (R2), evaluate,
    /// record snapshot version + revision (R3).
    pub async fn decide(
        &self,
        store: &dyn AuthzStore,
        query: &DecisionQuery,
    ) -> Result<DecisionRecord> {
        let mut slice_query = SliceQuery::new(query.principal().clone(), query.resource().clone());
        if let Some(revision) = query.revision() {
            slice_query = slice_query.at_revision(revision);
        }
        let slice = store.slice(&slice_query).await?;

        let entities = slice_to_entities(&slice, query.resource())?;

        let grants = grant_policies(&slice)?;
        let combined = format!("{}\n\n{}", self.snapshot.policy_text(), grants);
        let policies = PolicySet::from_str(&combined)
            .map_err(|e| Error::InvalidPolicy(format!("snapshot+grants: {e}")))?;

        let request = build_request(&slice, query)?;
        let answer = Authorizer::new().is_authorized(&request, &policies, &entities);
        let decision = match answer.decision() {
            cedar_policy::Decision::Allow => Decision::Allow,
            cedar_policy::Decision::Deny => Decision::Deny,
        };

        Ok(DecisionRecord::new(
            decision,
            self.snapshot.version().clone(),
            slice.revision(),
        ))
    }
}

/// Assemble the Cedar `Request` from the entity-mapping contract: principal
/// UID typed by the slice principal's kind, action `Action::"<verb>"`,
/// resource `Resource::"<FGRN>"`, empty context, no schema.
fn build_request(slice: &EntitySlice, query: &DecisionQuery) -> Result<Request> {
    let principal = slice.principal();
    let principal_uid = uid(cedar_principal_type(principal.kind()), principal.fgrn())?;

    let action_type = EntityTypeName::from_str("Action")
        .map_err(|e| Error::EvaluationFailed(format!("bad entity type Action: {e}")))?;
    let action_uid =
        EntityUid::from_type_name_and_id(action_type, EntityId::new(query.action().to_string()));

    let resource_uid = uid("Resource", query.resource())?;

    Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        Context::empty(),
        None,
    )
    .map_err(|e| Error::EvaluationFailed(format!("invalid request: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::principal::PrincipalKind;
    use forgeguard_core::{Grant, NativeId, OrgUnit, Principal, Segment, Spine, Verb};

    use super::*;
    use crate::store::{MemoryStore, ModelState, StoreWrite};

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    fn maria() -> forgeguard_core::Fgrn {
        forgeguard_core::Fgrn::principal(&org(), &nid("maria"))
    }

    fn doc() -> forgeguard_core::Fgrn {
        forgeguard_core::Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_1"),
        )
    }

    /// Store at revision 1: spine + maria, no grant. Revision 2: a grant on
    /// `doc()` to maria.
    async fn store_with_grant_at_revision_2() -> MemoryStore {
        let root = forgeguard_core::Fgrn::org_unit(&org(), &nid("root"));
        let spine = Spine::try_new(vec![OrgUnit::try_new(root.clone(), None).unwrap()]).unwrap();
        let mut model = ModelState::new(spine);
        model.upsert_principal(Principal::try_new(maria(), PrincipalKind::Human, root).unwrap());
        let store = MemoryStore::new(model);

        store
            .apply(StoreWrite::PutGrant(
                Grant::try_new(doc(), vec![Verb::try_new("read").unwrap()], maria()).unwrap(),
            ))
            .await
            .unwrap();

        store
    }

    fn engine() -> CedarEngine {
        // Snapshot deliberately does NOT cover the query; only the
        // grant-synthesized permit does.
        CedarEngine::new(
            Snapshot::from_policy_text(
                r#"permit(principal, action == Action::"unrelated-action", resource);"#,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn grant_allows_at_latest() {
        let store = store_with_grant_at_revision_2().await;
        let engine = engine();
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc());

        let record = engine.decide(&store, &query).await.unwrap();

        assert!(record.is_allow());
        assert_eq!(record.revision(), crate::store::Revision::new(2));
    }

    #[tokio::test]
    async fn pinned_revision_predating_grant_denies() {
        let store = store_with_grant_at_revision_2().await;
        let engine = engine();
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc())
            .at_revision(crate::store::Revision::new(1));

        let record = engine.decide(&store, &query).await.unwrap();

        assert!(!record.is_allow());
    }

    #[tokio::test]
    async fn record_carries_snapshot_version() {
        let store = store_with_grant_at_revision_2().await;
        let engine = engine();
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc());

        let record = engine.decide(&store, &query).await.unwrap();

        assert_eq!(record.snapshot_version(), engine.snapshot().version());
    }
}
