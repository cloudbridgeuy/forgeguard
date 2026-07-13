//! In-memory reference implementation of [`AuthzStore`]: one full
//! `ModelState` clone per revision. Trivially correct snapshot-at-revision;
//! performance is a non-goal (conformance and tests only).

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::store::model::ModelState;
use crate::store::revision::Revision;
use crate::store::slice::{select_slice, EntitySlice};
use crate::store::traits::{AuthzStore, SliceQuery, StoreWrite};

/// In-memory store: revision `n` is `history[n-1]`.
pub struct MemoryStore {
    history: Mutex<Vec<ModelState>>,
}

impl MemoryStore {
    /// Create a store whose revision 1 is `initial`.
    pub fn new(initial: ModelState) -> Self {
        Self {
            history: Mutex::new(vec![initial]),
        }
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Vec<ModelState>>> {
        self.history
            .lock()
            .map_err(|e| Error::EvaluationFailed(format!("memory store lock poisoned: {e}")))
    }
}

fn ready<T: Send + 'static>(
    value: Result<T>,
) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 'static>> {
    Box::pin(std::future::ready(value))
}

impl AuthzStore for MemoryStore {
    fn slice(
        &self,
        query: &SliceQuery,
    ) -> Pin<Box<dyn Future<Output = Result<EntitySlice>> + Send + '_>> {
        let result = (|| {
            let history = self.locked()?;
            let latest = history.len() as u64;
            let revision = query.revision().unwrap_or(Revision::new(latest));
            let index = revision.value();
            if index == 0 || index > latest {
                return Err(Error::UnknownRevision {
                    requested: index,
                    latest,
                });
            }
            #[allow(clippy::cast_possible_truncation)]
            let model = &history[(index - 1) as usize];
            select_slice(model, query.principal(), query.resource(), revision)
        })();
        ready(result)
    }

    fn apply(
        &self,
        write: StoreWrite,
    ) -> Pin<Box<dyn Future<Output = Result<Revision>> + Send + '_>> {
        let result = (|| {
            let mut history = self.locked()?;
            let mut next = history
                .last()
                .ok_or_else(|| Error::EvaluationFailed("memory store has no state".into()))?
                .clone();
            match write {
                StoreWrite::PutOrgUnit(unit) => next.spine_mut().add(unit)?,
                StoreWrite::PutPrincipal(p) => next.upsert_principal(p),
                StoreWrite::PutPrincipalSet(s) => next.upsert_principal_set(s),
                StoreWrite::PutGrant(g) => next.add_grant(g),
                StoreWrite::RemoveGrant { resource, to } => {
                    next.remove_grant(&resource, &to);
                }
                StoreWrite::PutPromotion(p) => next.upsert_promotion(p),
            }
            history.push(next);
            Ok(Revision::new(history.len() as u64))
        })();
        ready(result)
    }

    fn latest_revision(&self) -> Pin<Box<dyn Future<Output = Result<Revision>> + Send + '_>> {
        let result = self.locked().map(|h| Revision::new(h.len() as u64));
        ready(result)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use forgeguard_core::principal::PrincipalKind;
    use forgeguard_core::{Fgrn, Grant, NativeId, OrgUnit, Principal, Segment, Spine, Verb};

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    fn initial() -> ModelState {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let finance = Fgrn::org_unit(&org(), &nid("finance"));
        let spine = Spine::try_new(vec![
            OrgUnit::try_new(root.clone(), None).unwrap(),
            OrgUnit::try_new(finance.clone(), Some(root)).unwrap(),
        ])
        .unwrap();
        let mut m = ModelState::new(spine);
        m.upsert_principal(
            Principal::try_new(
                Fgrn::principal(&org(), &nid("maria")),
                PrincipalKind::Human,
                finance,
            )
            .unwrap(),
        );
        m
    }

    fn doc() -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_123"),
        )
    }

    fn maria() -> Fgrn {
        Fgrn::principal(&org(), &nid("maria"))
    }

    fn grant_to_maria() -> Grant {
        Grant::try_new(doc(), vec![Verb::try_new("read").unwrap()], maria()).unwrap()
    }

    #[tokio::test]
    async fn writes_return_increasing_revisions() {
        let store = MemoryStore::new(initial());
        assert_eq!(store.latest_revision().await.unwrap(), Revision::new(1));
        let r2 = store
            .apply(StoreWrite::PutGrant(grant_to_maria()))
            .await
            .unwrap();
        assert_eq!(r2, Revision::new(2));
        let r3 = store
            .apply(StoreWrite::RemoveGrant {
                resource: doc(),
                to: maria(),
            })
            .await
            .unwrap();
        assert_eq!(r3, Revision::new(3));
    }

    /// R2: a slice read at revision N never sees writes after N.
    #[tokio::test]
    async fn slice_at_old_revision_is_blind_to_later_writes() {
        let store = MemoryStore::new(initial());
        let r1 = store.latest_revision().await.unwrap();
        store
            .apply(StoreWrite::PutGrant(grant_to_maria()))
            .await
            .unwrap();

        let old = store
            .slice(&SliceQuery::new(maria(), doc()).at_revision(r1))
            .await
            .unwrap();
        assert!(old.grants().is_empty(), "revision 1 predates the grant");
        assert_eq!(old.revision(), r1);

        let latest = store.slice(&SliceQuery::new(maria(), doc())).await.unwrap();
        assert_eq!(latest.grants().len(), 1);
        assert_eq!(latest.revision(), Revision::new(2));
    }

    /// The revocation mirror: a removed grant stays visible at the revision
    /// where it existed.
    #[tokio::test]
    async fn removed_grant_still_visible_at_its_revision() {
        let store = MemoryStore::new(initial());
        let r2 = store
            .apply(StoreWrite::PutGrant(grant_to_maria()))
            .await
            .unwrap();
        store
            .apply(StoreWrite::RemoveGrant {
                resource: doc(),
                to: maria(),
            })
            .await
            .unwrap();

        let at_grant = store
            .slice(&SliceQuery::new(maria(), doc()).at_revision(r2))
            .await
            .unwrap();
        assert_eq!(at_grant.grants().len(), 1);

        let latest = store.slice(&SliceQuery::new(maria(), doc())).await.unwrap();
        assert!(latest.grants().is_empty());
    }

    #[tokio::test]
    async fn unknown_revision_is_an_error() {
        let store = MemoryStore::new(initial());
        let err = store
            .slice(&SliceQuery::new(maria(), doc()).at_revision(Revision::new(9)))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::UnknownRevision {
                requested: 9,
                latest: 1
            }
        ));
    }

    #[tokio::test]
    async fn revision_zero_is_an_error() {
        let store = MemoryStore::new(initial());
        let err = store
            .slice(&SliceQuery::new(maria(), doc()).at_revision(Revision::new(0)))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::UnknownRevision {
                requested: 0,
                latest: 1
            }
        ));
    }
}
