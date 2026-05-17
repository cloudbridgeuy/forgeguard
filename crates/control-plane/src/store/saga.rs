//! Saga ticket store abstraction.
//!
//! - `SagaTicketStore` — async I/O trait over the saga ticket table.
//! - `SagaStageUpdate` — fields that change alongside a stage cursor advance.
//! - `DynamoSagaTicketStore` (V3 sub-commit (c)) — production impl backed by
//!   `forgeguard-{env}-sagas` with the `gsi_in_flight` sparse GSI.
//! - `InMemorySagaTicketStore` (V3 sub-commit (b)) — test impl.

use async_trait::async_trait;
use forgeguard_authn_core::saga::{SagaStage, SagaStatus, SagaTicket, TicketId};
use forgeguard_core::{OrganizationId, UserId};

use crate::error::Result;

/// Mutations that travel alongside a [`SagaTicketStore::advance_saga_stage`]
/// call. Every field is optional so callers fill in whichever change at the
/// transition they are recording.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // consumed by the saga driver in sub-commit (d)
pub(crate) struct SagaStageUpdate {
    /// Populated when S2 succeeds — Cognito sub.
    pub(crate) sub: Option<UserId>,
    /// Populated on terminal transitions.
    pub(crate) status: Option<SagaStatus>,
    /// Populated on failure transitions.
    pub(crate) failure_reason: Option<String>,
}

/// Async I/O trait over the saga ticket table.
///
/// Implementations:
/// - `dynamo_store::saga::DynamoSagaTicketStore` — production
/// - `store::in_memory_saga::InMemorySagaTicketStore` — tests
#[async_trait]
#[allow(dead_code)] // consumers added in sub-commits (b)/(c)/(d)
pub(crate) trait SagaTicketStore: Send + Sync {
    /// Fetch a saga ticket by id, or `None` if no row exists.
    async fn get_saga_ticket(&self, ticket_id: &TicketId) -> Result<Option<SagaTicket>>;

    /// Write the initial ticket row.
    ///
    /// Precondition: `ticket.status() == InFlight` and
    /// `ticket.current_stage() == S1`. The implementation writes the
    /// `gsi_in_flight` key attributes simultaneously; they are removed by
    /// `advance_saga_stage` when the saga terminates.
    async fn put_saga_ticket(&self, ticket: SagaTicket) -> Result<()>;

    /// Find the ticket id of an in-flight saga for the given `(org, email)`
    /// pair, or `None` if no such saga is currently in flight.
    ///
    /// Backed by `gsi_in_flight` on the saga table. Returns `None` when the
    /// saga has terminated (the GSI entry is removed on terminal transitions).
    async fn find_in_flight_saga_by_email(
        &self,
        org_id: &OrganizationId,
        email: &str,
    ) -> Result<Option<TicketId>>;

    /// Atomically advance the saga stage cursor.
    ///
    /// Uses `ConditionExpression: current_stage = :expected_prev`. Returns
    /// `Error::Conflict` if the condition fails (concurrent update).
    ///
    /// Terminal transitions (`next` is `SagaStage::Done` or
    /// `SagaStage::CompensationFailed`) MUST delete the `gsi_in_flight`
    /// attributes from the item so the email can be reused in a future saga.
    async fn advance_saga_stage(
        &self,
        ticket_id: &TicketId,
        expected_prev: SagaStage,
        next: SagaStage,
        update_fields: SagaStageUpdate,
    ) -> Result<()>;
}
