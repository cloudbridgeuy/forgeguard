//! In-memory `SagaTicketStore` for control-plane tests.
//!
//! Mirrors the future DynamoDB layout strictly enough that saga driver tests
//! exercise the same control flow they will see in production:
//!
//! - `put_saga_ticket` rejects duplicate ticket ids (parallels the
//!   `attribute_not_exists(PK)` condition the DDB impl will use).
//! - `advance_saga_stage` validates the expected previous cursor and surfaces
//!   `Error::Conflict` on a mismatch — same wire that the DDB
//!   `ConditionalCheckFailedException` path lands on.
//! - `find_in_flight_saga_by_email` linear-scans the map, filtering on
//!   `(org, email, status == InFlight)`. The DDB version uses `gsi_in_flight`;
//!   the linear scan here gives strong consistency in tests (plan Risk 4).

use std::collections::BTreeMap;

use async_trait::async_trait;
use forgeguard_authn_core::saga::{
    SagaStage, SagaStatus, SagaTicket, SagaTicketFromStorage, TicketId,
};
use forgeguard_core::OrganizationId;
use tokio::sync::RwLock;

use crate::error::{Error, Result};
use crate::store::saga::{SagaStageUpdate, SagaTicketStore};

/// Test stub that keeps saga tickets in a `RwLock<BTreeMap>`.
#[derive(Debug, Default)]
pub(crate) struct InMemorySagaTicketStore {
    tickets: RwLock<BTreeMap<TicketId, SagaTicket>>,
}

impl InMemorySagaTicketStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SagaTicketStore for InMemorySagaTicketStore {
    async fn get_saga_ticket(&self, ticket_id: &TicketId) -> Result<Option<SagaTicket>> {
        let guard = self.tickets.read().await;
        Ok(guard.get(ticket_id).cloned())
    }

    async fn put_saga_ticket(&self, ticket: SagaTicket) -> Result<()> {
        let mut guard = self.tickets.write().await;
        let ticket_id = ticket.ticket_id().clone();
        if guard.contains_key(&ticket_id) {
            return Err(Error::Conflict(format!(
                "saga ticket '{ticket_id}' already exists"
            )));
        }
        guard.insert(ticket_id, ticket);
        Ok(())
    }

    async fn find_in_flight_saga_by_email(
        &self,
        org_id: &OrganizationId,
        email: &str,
    ) -> Result<Option<TicketId>> {
        let guard = self.tickets.read().await;
        // Strong-consistency linear scan — see module doc.
        Ok(guard
            .values()
            .find(|t| {
                t.status() == SagaStatus::InFlight && t.org_id() == org_id && t.email() == email
            })
            .map(|t| t.ticket_id().clone()))
    }

    async fn advance_saga_stage(
        &self,
        ticket_id: &TicketId,
        expected_prev: SagaStage,
        next: SagaStage,
        update_fields: SagaStageUpdate,
    ) -> Result<()> {
        let mut guard = self.tickets.write().await;
        let Some(current) = guard.get(ticket_id).cloned() else {
            return Err(Error::NotFound(format!(
                "saga ticket '{ticket_id}' not found"
            )));
        };
        if current.current_stage() != expected_prev {
            return Err(Error::Conflict(format!(
                "saga ticket '{ticket_id}' stage mismatch: expected {expected_prev}, found {}",
                current.current_stage()
            )));
        }
        let SagaStageUpdate {
            sub,
            status,
            failure_reason,
        } = update_fields;
        let mutated = SagaTicket::from(SagaTicketFromStorage {
            ticket_id: current.ticket_id().clone(),
            org_id: current.org_id().clone(),
            email: current.email().to_owned(),
            status: status.unwrap_or_else(|| current.status()),
            current_stage: next,
            groups: current.groups().to_vec(),
            attributes: current.attributes().clone(),
            created_at: current.created_at(),
            updated_at: chrono::Utc::now(),
            sub: sub.or_else(|| current.sub().cloned()),
            failure_reason: failure_reason.or_else(|| current.failure_reason().map(str::to_owned)),
            created_by: current.created_by().clone(),
        });
        guard.insert(ticket_id.clone(), mutated);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};
    use forgeguard_authn_core::saga::{SagaTicketParams, TicketId};
    use forgeguard_core::UserId;

    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn user(id: &str) -> UserId {
        UserId::new(id).unwrap()
    }

    fn org(id: &str) -> OrganizationId {
        OrganizationId::new(id).unwrap()
    }

    fn ticket(email: &str, org_id: &str) -> SagaTicket {
        SagaTicket::new(SagaTicketParams {
            ticket_id: TicketId::generate(),
            org_id: org(org_id),
            email: email.to_owned(),
            groups: vec![],
            attributes: BTreeMap::new(),
            created_at: now(),
            created_by: user("admin"),
        })
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let store = InMemorySagaTicketStore::new();
        let t = ticket("alice@example.com", "acme");
        let id = t.ticket_id().clone();
        store.put_saga_ticket(t.clone()).await.unwrap();
        let fetched = store.get_saga_ticket(&id).await.unwrap().unwrap();
        assert_eq!(fetched, t);
    }

    #[tokio::test]
    async fn duplicate_put_returns_conflict() {
        let store = InMemorySagaTicketStore::new();
        let t = ticket("alice@example.com", "acme");
        store.put_saga_ticket(t.clone()).await.unwrap();
        let err = store.put_saga_ticket(t).await.unwrap_err();
        assert!(matches!(err, Error::Conflict(_)));
    }

    #[tokio::test]
    async fn find_in_flight_by_email_returns_match() {
        let store = InMemorySagaTicketStore::new();
        let t = ticket("alice@example.com", "acme");
        let id = t.ticket_id().clone();
        store.put_saga_ticket(t).await.unwrap();

        let found = store
            .find_in_flight_saga_by_email(&org("acme"), "alice@example.com")
            .await
            .unwrap();
        assert_eq!(found.as_ref(), Some(&id));

        let missing = store
            .find_in_flight_saga_by_email(&org("acme"), "bob@example.com")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn find_in_flight_filters_out_terminated() {
        let store = InMemorySagaTicketStore::new();
        let t = ticket("alice@example.com", "acme");
        let id = t.ticket_id().clone();
        store.put_saga_ticket(t).await.unwrap();

        // Walk the saga to terminal `Done`.
        store
            .advance_saga_stage(
                &id,
                SagaStage::S1,
                SagaStage::S2,
                SagaStageUpdate::default(),
            )
            .await
            .unwrap();
        store
            .advance_saga_stage(
                &id,
                SagaStage::S2,
                SagaStage::S3,
                SagaStageUpdate {
                    sub: Some(user("cognito-sub")),
                    ..SagaStageUpdate::default()
                },
            )
            .await
            .unwrap();
        store
            .advance_saga_stage(
                &id,
                SagaStage::S3,
                SagaStage::Done,
                SagaStageUpdate {
                    status: Some(SagaStatus::Succeeded),
                    ..SagaStageUpdate::default()
                },
            )
            .await
            .unwrap();

        let found = store
            .find_in_flight_saga_by_email(&org("acme"), "alice@example.com")
            .await
            .unwrap();
        assert!(found.is_none(), "Done sagas must not be returned");
    }

    #[tokio::test]
    async fn advance_returns_conflict_on_stage_mismatch() {
        let store = InMemorySagaTicketStore::new();
        let t = ticket("alice@example.com", "acme");
        let id = t.ticket_id().clone();
        store.put_saga_ticket(t).await.unwrap();

        let err = store
            .advance_saga_stage(
                &id,
                SagaStage::S2,
                SagaStage::S3,
                SagaStageUpdate::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Conflict(_)));
    }

    #[tokio::test]
    async fn advance_returns_not_found_for_unknown_ticket() {
        let store = InMemorySagaTicketStore::new();
        let err = store
            .advance_saga_stage(
                &TicketId::generate(),
                SagaStage::S1,
                SagaStage::S2,
                SagaStageUpdate::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }
}
