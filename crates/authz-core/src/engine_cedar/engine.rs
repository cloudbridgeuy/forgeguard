//! The embedded engine: one consistent read, in-process Cedar evaluation,
//! versioned decision records.

use std::str::FromStr;

use cedar_policy::{Authorizer, Context, EntityId, EntityTypeName, EntityUid, PolicySet, Request};

use forgeguard_core::{Fgrn, Verb};

use crate::engine_cedar::enrich::{entitlements_of, scope_path_of};
use crate::engine_cedar::record::{Decision, DecisionQuery, DecisionRecord};
use crate::engine_cedar::translate::{
    cedar_principal_type, grant_policies, slice_to_entities, uid,
};
use crate::error::{Error, Result};
use crate::snapshot::Snapshot;
use crate::store::{AuthzStore, EntitySlice, Revision, SliceQuery};

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
    ///
    /// Without a delegation chain, evaluates `query.principal()` alone.
    /// With a chain, evaluates every link (actor through subject), each
    /// against its own entity slice read at the same pinned revision —
    /// Allow iff every link allows (Brief v1.4's chain intersection); the
    /// first Deny short-circuits the rest.
    pub async fn decide(
        &self,
        store: &dyn AuthzStore,
        query: &DecisionQuery,
    ) -> Result<DecisionRecord> {
        let revision = match query.revision() {
            Some(revision) => revision,
            None => store.latest_revision().await?,
        };

        let links: Vec<&Fgrn> = match query.chain() {
            Some(chain) => chain.links().collect(),
            None => vec![query.principal()],
        };

        // First link is the acting principal (chain actor == query
        // principal, enforced by `DecisionQuery::with_chain`). Its slice is
        // kept for enrichment (scope_path, entitlements) — no extra read.
        let Some((first, rest)) = links.split_first() else {
            return Err(Error::EvaluationFailed(
                "delegation chain produced no links".to_string(),
            ));
        };
        let first_query = LinkQuery {
            principal: first,
            action: query.action(),
            resource: query.resource(),
            revision,
        };
        let (mut decision, principal_slice) = self.evaluate_link(store, &first_query).await?;
        for link in rest {
            if decision == Decision::Deny {
                break;
            }
            let link_query = LinkQuery {
                principal: link,
                action: query.action(),
                resource: query.resource(),
                revision,
            };
            let (link_decision, _slice) = self.evaluate_link(store, &link_query).await?;
            decision = link_decision;
        }

        let scope_path = scope_path_of(&principal_slice);
        let entitlements = entitlements_of(&principal_slice);

        Ok(DecisionRecord::new(
            decision,
            self.snapshot.version().clone(),
            revision,
            scope_path,
            entitlements,
        ))
    }

    /// Evaluate one principal's entity slice, read at `link.revision`.
    /// Returns the slice alongside the decision — the caller keeps the first
    /// link's slice for record enrichment.
    async fn evaluate_link(
        &self,
        store: &dyn AuthzStore,
        link: &LinkQuery<'_>,
    ) -> Result<(Decision, EntitySlice)> {
        let slice_query = SliceQuery::new(link.principal.clone(), link.resource.clone())
            .at_revision(link.revision);
        let slice = store.slice(&slice_query).await?;

        let entities = slice_to_entities(&slice, link.resource)?;

        let grants = grant_policies(&slice)?;
        let combined = format!("{}\n\n{}", self.snapshot.policy_text(), grants);
        let policies = PolicySet::from_str(&combined)
            .map_err(|e| Error::InvalidPolicy(format!("snapshot+grants: {e}")))?;

        let request = build_request(&slice, link.action, link.resource)?;
        let answer = Authorizer::new().is_authorized(&request, &policies, &entities);
        let decision = match answer.decision() {
            cedar_policy::Decision::Allow => Decision::Allow,
            cedar_policy::Decision::Deny => Decision::Deny,
        };
        Ok((decision, slice))
    }
}

/// One delegation-chain link's evaluation inputs — one principal's slice,
/// read at the chain-wide pinned revision. Params struct (see
/// .claude/context/params-struct-rule.md) to keep `evaluate_link` under the
/// argument-count lint.
struct LinkQuery<'a> {
    principal: &'a Fgrn,
    action: &'a Verb,
    resource: &'a Fgrn,
    revision: Revision,
}

/// Assemble the Cedar `Request` from the entity-mapping contract: principal
/// UID typed by the slice principal's kind, action `Action::"<verb>"`,
/// resource `Resource::"<FGRN>"`, empty context, no schema.
fn build_request(slice: &EntitySlice, action: &Verb, resource: &Fgrn) -> Result<Request> {
    let principal = slice.principal();
    let principal_uid = uid(cedar_principal_type(principal.kind()), principal.fgrn())?;

    let action_type = EntityTypeName::from_str("Action")
        .map_err(|e| Error::EvaluationFailed(format!("bad entity type Action: {e}")))?;
    let action_uid =
        EntityUid::from_type_name_and_id(action_type, EntityId::new(action.to_string()));

    let resource_uid = uid("Resource", resource)?;

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

    fn maria2() -> forgeguard_core::Fgrn {
        forgeguard_core::Fgrn::principal(&org(), &nid("maria2"))
    }

    fn bob() -> forgeguard_core::Fgrn {
        forgeguard_core::Fgrn::principal(&org(), &nid("bob"))
    }

    fn chain(links: Vec<forgeguard_core::Fgrn>) -> forgeguard_core::DelegationChain {
        forgeguard_core::DelegationChain::try_new(links).unwrap()
    }

    /// Store at revision 1: spine + maria + maria2 + bob, each granted
    /// `read` on `doc()` except bob.
    async fn store_with_chain_world() -> MemoryStore {
        let root = forgeguard_core::Fgrn::org_unit(&org(), &nid("root"));
        let spine = Spine::try_new(vec![OrgUnit::try_new(root.clone(), None).unwrap()]).unwrap();
        let mut model = ModelState::new(spine);
        model.upsert_principal(
            Principal::try_new(maria(), PrincipalKind::Human, root.clone()).unwrap(),
        );
        model.upsert_principal(
            Principal::try_new(maria2(), PrincipalKind::Human, root.clone()).unwrap(),
        );
        model.upsert_principal(Principal::try_new(bob(), PrincipalKind::Human, root).unwrap());
        let store = MemoryStore::new(model);

        let read = Verb::try_new("read").unwrap();
        store
            .apply(StoreWrite::PutGrant(
                Grant::try_new(doc(), vec![read.clone()], maria()).unwrap(),
            ))
            .await
            .unwrap();
        store
            .apply(StoreWrite::PutGrant(
                Grant::try_new(doc(), vec![read], maria2()).unwrap(),
            ))
            .await
            .unwrap();

        store
    }

    #[tokio::test]
    async fn chain_all_allow_allows() {
        let store = store_with_chain_world().await;
        let engine = engine();
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc())
            .with_chain(chain(vec![maria(), maria2()]))
            .unwrap();

        let record = engine.decide(&store, &query).await.unwrap();

        assert!(record.is_allow());
    }

    #[tokio::test]
    async fn chain_one_deny_denies() {
        let store = store_with_chain_world().await;
        let engine = engine();
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc())
            .with_chain(chain(vec![maria(), bob()]))
            .unwrap();

        let record = engine.decide(&store, &query).await.unwrap();

        assert!(!record.is_allow());
    }

    #[tokio::test]
    async fn chain_uses_one_revision() {
        let store = store_with_chain_world().await;
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc())
            .with_chain(chain(vec![maria(), bob()]))
            .unwrap()
            .at_revision(crate::store::Revision::new(2));
        let engine = engine();

        // Pre-check: at revision 2, bob had no grant yet.
        let record = engine.decide(&store, &query).await.unwrap();
        assert!(!record.is_allow());

        // Grant bob read AFTER the pinned revision; the chained decision,
        // still pinned to revision 2, must not see it (R2 chain-wide).
        store
            .apply(StoreWrite::PutGrant(
                Grant::try_new(doc(), vec![Verb::try_new("read").unwrap()], bob()).unwrap(),
            ))
            .await
            .unwrap();

        let record = engine.decide(&store, &query).await.unwrap();
        assert!(!record.is_allow());
    }

    #[tokio::test]
    async fn chainless_behavior_unchanged() {
        let store = store_with_grant_at_revision_2().await;
        let engine = engine();
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc());

        let record = engine.decide(&store, &query).await.unwrap();

        assert!(record.is_allow());
    }

    #[tokio::test]
    async fn record_carries_scope_path_and_entitlements() {
        let store = store_with_grant_at_revision_2().await;
        let engine = engine();
        let query = DecisionQuery::new(maria(), Verb::try_new("read").unwrap(), doc());

        let record = engine.decide(&store, &query).await.unwrap();

        assert_eq!(record.scope_path().to_string(), "root");
        assert_eq!(
            record
                .entitlements()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["read"]
        );
    }
}
