//! Pure mapping from the flat `PolicyQuery` world to the FGRN-scoped
//! `DecisionQuery` world.
//!
//! ## Mapping contract
//!
//! | `PolicyQuery` | `DecisionQuery` | Rule |
//! | --- | --- | --- |
//! | `principal()` | principal FGRN | `Fgrn::principal(org, principal id as NativeId)` |
//! | `action()` | `Verb` | namespace/entity/action segments joined by `--` (e.g. `todo:list:read` → `todo--list--read`) — `--` is unambiguous because `Segment` forbids consecutive hyphens within a component, unlike a single-`-` join which collides when a component itself contains a hyphen |
//! | `resource()` = `Some(r)` | resource FGRN | `Fgrn::resource(org, <entity as type segment>, <resource id as NativeId>)` |
//! | `resource()` = `None` | resource FGRN | `Fgrn::resource(org, Segment("app"), NativeId("app"))` — the "whole application" resource for route-level checks with no specific resource |
//! | `context()` | dropped | tenant/groups/IP have no phase-2 embedded representation; the store's model carries membership. |
//!
//! This module maps FGRNs only — it does not re-handle principal-kind
//! collapse or grantee-clause typing; that lives in `CedarEngine`/`translate.rs`.

use forgeguard_core::{Fgrn, NativeId, Segment, Verb};

use crate::query::PolicyQuery;
use crate::Result;

use super::{CedarEngine, DecisionQuery};

/// The embedded engine's native `PolicyEngine` face: maps flat
/// `PolicyQuery`s into FGRN-scoped `DecisionQuery`s and evaluates through
/// `CedarEngine`, passing the resulting `DecisionRecord` through intact
/// (`EvaluatedDecision::with_record`) rather than discarding it.
pub struct EmbeddedPolicyEngine {
    engine: CedarEngine,
    store: std::sync::Arc<dyn crate::store::AuthzStore>,
    org: Segment,
}

impl EmbeddedPolicyEngine {
    /// Adapter over `engine` reading from `store`, mapping flat queries
    /// into `org`-scoped FGRNs.
    pub fn new(
        engine: CedarEngine,
        store: std::sync::Arc<dyn crate::store::AuthzStore>,
        org: Segment,
    ) -> Self {
        Self { engine, store, org }
    }
}

impl crate::PolicyEngine for EmbeddedPolicyEngine {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::Result<crate::EvaluatedDecision>> + Send + '_>,
    > {
        let mapped = map_query(&self.org, query);
        Box::pin(async move {
            let decision_query = match mapped {
                Ok(q) => q,
                Err(e) => {
                    return Ok(crate::EvaluatedDecision::bare(
                        crate::PolicyDecision::Deny {
                            reason: crate::DenyReason::EvaluationError(e.to_string()),
                        },
                    ))
                }
            };
            let record = self
                .engine
                .decide(self.store.as_ref(), &decision_query)
                .await?;
            let decision = if record.is_allow() {
                crate::PolicyDecision::Allow
            } else {
                crate::PolicyDecision::Deny {
                    reason: crate::DenyReason::NoMatchingPolicy,
                }
            };
            Ok(crate::EvaluatedDecision::with_record(decision, record))
        })
    }
}

/// Map a flat `PolicyQuery` into an org-scoped `DecisionQuery`.
pub(crate) fn map_query(org: &Segment, query: &PolicyQuery) -> Result<DecisionQuery> {
    let principal_id = NativeId::try_new(query.principal().user_id().as_str())?;
    let principal = Fgrn::principal(org, &principal_id);

    let action = Verb::try_new(format!(
        "{}--{}--{}",
        query.action().namespace().as_str(),
        query.action().entity().as_str(),
        query.action().action().as_str()
    ))?;

    let (resource_type, native_id) = match query.resource() {
        Some(r) => (
            Segment::try_new(r.entity().as_str())?,
            NativeId::try_new(r.id().as_str())?,
        ),
        None => (Segment::try_new("app")?, NativeId::try_new("app")?),
    };
    let resource = Fgrn::resource(org, &resource_type, &native_id);

    Ok(DecisionQuery::new(principal, action, resource))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{QualifiedAction, ResourceId, ResourceRef, UserId};

    use super::*;
    use crate::context::PolicyContext;

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    #[test]
    fn maps_principal_action_and_explicit_resource() {
        let principal = forgeguard_core::PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:list:read").unwrap();
        let resource_id = ResourceId::parse("my-list").unwrap();
        let resource = ResourceRef::from_route(&action, resource_id);
        let query = PolicyQuery::new(principal, action, Some(resource), PolicyContext::new());

        let mapped = map_query(&org(), &query).unwrap();

        assert_eq!(mapped.principal().to_string(), "fgrn:acme:principal:alice");
        assert_eq!(mapped.action().as_str(), "todo--list--read");
        assert_eq!(
            mapped.resource().to_string(),
            "fgrn:acme:resource:list/my-list"
        );
    }

    #[test]
    fn none_resource_maps_to_app_fgrn() {
        let principal = forgeguard_core::PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:list:read").unwrap();
        let query = PolicyQuery::new(principal, action, None, PolicyContext::new());

        let mapped = map_query(&org(), &query).unwrap();

        assert_eq!(mapped.resource().to_string(), "fgrn:acme:resource:app/app");
    }

    // `UserId`/`ResourceId`/`Entity` are all `Segment`-backed (kebab-case),
    // a strict subset of `NativeId`'s charset, so every valid `PolicyQuery`
    // maps successfully — there is no reachable id-rejection path to test
    // here. `map_query`'s `Result` return still guards the invariant should
    // either type's ruleset diverge in the future.

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    async fn store_with_grant() -> crate::store::MemoryStore {
        use forgeguard_core::principal::PrincipalKind;
        use forgeguard_core::{Grant, OrgUnit, Principal, Spine};

        use crate::store::AuthzStore as _;

        let org = org();
        let alice = Fgrn::principal(&org, &nid("alice"));
        let app_resource = Fgrn::resource(&org, &Segment::try_new("app").unwrap(), &nid("app"));
        let root = Fgrn::org_unit(&org, &nid("root"));
        let spine = Spine::try_new(vec![OrgUnit::try_new(root.clone(), None).unwrap()]).unwrap();
        let mut model = crate::store::ModelState::new(spine);
        model.upsert_principal(
            Principal::try_new(alice.clone(), PrincipalKind::Human, root).unwrap(),
        );
        let store = crate::store::MemoryStore::new(model);

        store
            .apply(crate::store::StoreWrite::PutGrant(
                Grant::try_new(
                    app_resource,
                    vec![Verb::try_new("todo--list--read").unwrap()],
                    alice,
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        store
    }

    #[tokio::test]
    async fn embedded_engine_allows_through_trait_object() {
        use crate::PolicyEngine;

        let store: std::sync::Arc<dyn crate::store::AuthzStore> =
            std::sync::Arc::new(store_with_grant().await);
        let engine = super::super::CedarEngine::new(
            crate::Snapshot::from_policy_text(
                r#"permit(principal, action == Action::"unrelated-action", resource);"#,
            )
            .unwrap(),
        );
        let embedded: std::sync::Arc<dyn PolicyEngine> =
            std::sync::Arc::new(EmbeddedPolicyEngine::new(engine, store, org()));

        let principal = forgeguard_core::PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:list:read").unwrap();
        let query = PolicyQuery::new(principal, action, None, PolicyContext::new());

        let decision = embedded.evaluate(&query).await.unwrap();

        assert_eq!(decision.decision(), &crate::PolicyDecision::Allow);
        assert!(decision.into_record().is_some());
    }

    #[tokio::test]
    async fn embedded_engine_denies_when_no_grant_matches() {
        use crate::PolicyEngine;

        let store: std::sync::Arc<dyn crate::store::AuthzStore> =
            std::sync::Arc::new(store_with_grant().await);
        let engine = super::super::CedarEngine::new(
            crate::Snapshot::from_policy_text(
                r#"permit(principal, action == Action::"unrelated-action", resource);"#,
            )
            .unwrap(),
        );
        let embedded: std::sync::Arc<dyn PolicyEngine> =
            std::sync::Arc::new(EmbeddedPolicyEngine::new(engine, store, org()));

        let principal = forgeguard_core::PrincipalRef::new(UserId::new("alice").unwrap());
        let action = QualifiedAction::parse("todo:list:write").unwrap();
        let query = PolicyQuery::new(principal, action, None, PolicyContext::new());

        let decision = embedded.evaluate(&query).await.unwrap();

        assert_eq!(
            decision.decision(),
            &crate::PolicyDecision::Deny {
                reason: crate::DenyReason::NoMatchingPolicy
            }
        );
        assert!(decision.into_record().is_some());
    }
}
