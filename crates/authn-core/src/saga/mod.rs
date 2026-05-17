//! Saga ticket domain types — pure, no I/O.
//!
//! A `SagaTicket` represents one in-flight `POST /users` invocation. The
//! control-plane handler creates it before stage S1 runs and updates it as
//! each stage transitions. DDB serialization lives in V3
//! (`control-plane::dynamo_store::saga`); this crate owns only the domain
//! shape.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use forgeguard_core::{GroupName, OrganizationId, UserId};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::error::Error;

/// Sortable opaque identifier for a saga ticket. Wraps a `Ulid` so the
/// natural ordering matches creation time, which keeps DDB sort keys
/// chronological.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TicketId(String);

impl TicketId {
    /// Mint a fresh ticket id from a new ULID.
    pub fn generate() -> Self {
        Self(Ulid::new().to_string())
    }

    /// Validate + wrap a raw ticket id string. Accepts only well-formed ULIDs.
    pub fn try_new(raw: impl Into<String>) -> Result<Self, Error> {
        let s = raw.into();
        Ulid::from_string(&s).map_err(|_| Error::InvalidTicketId { raw: s.clone() })?;
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TicketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TicketId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl<'de> Deserialize<'de> for TicketId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_new(s).map_err(serde::de::Error::custom)
    }
}

/// Terminal-or-in-flight status of a saga ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaStatus {
    InFlight,
    Succeeded,
    Failed,
    CompensationFailed,
}

impl SagaStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::InFlight)
    }
}

impl fmt::Display for SagaStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InFlight => "in_flight",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::CompensationFailed => "compensation_failed",
        };
        f.write_str(s)
    }
}

/// Per-stage cursor inside a saga. Names mirror the plan §5 stage labels.
///
/// Wire format follows plan §7 DDB Serialization Layout: the three pre-terminal
/// stages serialize as uppercase `S1`/`S2`/`S3`, while the post-terminal cursor
/// values serialize as snake_case (`done`/`compensating`/`compensation_failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaStage {
    /// Ticket created; S1 (validation) about to run.
    #[serde(rename = "S1")]
    S1,
    /// S1 succeeded; S2 (AdminCreateUser) about to run.
    #[serde(rename = "S2")]
    S2,
    /// S2 succeeded; S3 (PutMembership) about to run.
    #[serde(rename = "S3")]
    S3,
    /// Terminal: S3 succeeded.
    #[serde(rename = "done")]
    Done,
    /// S3 failed transiently; C2 (AdminDeleteUser) about to run.
    #[serde(rename = "compensating")]
    Compensating,
    /// Terminal: C2 also failed.
    #[serde(rename = "compensation_failed")]
    CompensationFailed,
}

impl SagaStage {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::CompensationFailed)
    }
}

impl fmt::Display for SagaStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::S1 => "S1",
            Self::S2 => "S2",
            Self::S3 => "S3",
            Self::Done => "done",
            Self::Compensating => "compensating",
            Self::CompensationFailed => "compensation_failed",
        };
        f.write_str(s)
    }
}

/// Inputs for [`SagaTicket::new`]. Public params struct per
/// `params-struct-rule.md` (more than five fields, no cross-field invariants).
#[derive(Debug, Clone)]
pub struct SagaTicketParams {
    pub ticket_id: TicketId,
    pub org_id: OrganizationId,
    pub email: String,
    pub groups: Vec<GroupName>,
    pub attributes: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub created_by: UserId,
}

/// One row in the saga store. Constructed with `status = InFlight`,
/// `current_stage = S1`; later transitions are recorded by the store via
/// `advance_saga_stage` rather than mutating this value in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaTicket {
    ticket_id: TicketId,
    org_id: OrganizationId,
    email: String,
    status: SagaStatus,
    current_stage: SagaStage,
    groups: Vec<GroupName>,
    attributes: BTreeMap<String, String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    sub: Option<UserId>,
    failure_reason: Option<String>,
    created_by: UserId,
}

impl SagaTicket {
    /// Build a fresh in-flight ticket parked at stage S1.
    pub fn new(params: SagaTicketParams) -> Self {
        let SagaTicketParams {
            ticket_id,
            org_id,
            email,
            groups,
            attributes,
            created_at,
            created_by,
        } = params;
        Self {
            ticket_id,
            org_id,
            email,
            status: SagaStatus::InFlight,
            current_stage: SagaStage::S1,
            groups,
            attributes,
            created_at,
            updated_at: created_at,
            sub: None,
            failure_reason: None,
            created_by,
        }
    }

    pub fn ticket_id(&self) -> &TicketId {
        &self.ticket_id
    }

    pub fn org_id(&self) -> &OrganizationId {
        &self.org_id
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn status(&self) -> SagaStatus {
        self.status
    }

    pub fn current_stage(&self) -> SagaStage {
        self.current_stage
    }

    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }

    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn sub(&self) -> Option<&UserId> {
        self.sub.as_ref()
    }

    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }

    pub fn created_by(&self) -> &UserId {
        &self.created_by
    }
}

/// Rehydration shape for converting a stored row back into a [`SagaTicket`].
///
/// Used by store implementations (DynamoDB, in-memory) to reconstitute a ticket
/// from persisted fields. Convert with `SagaTicket::from(params)`.
#[derive(Debug, Clone)]
pub struct SagaTicketFromStorage {
    pub ticket_id: TicketId,
    pub org_id: OrganizationId,
    pub email: String,
    pub status: SagaStatus,
    pub current_stage: SagaStage,
    pub groups: Vec<GroupName>,
    pub attributes: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sub: Option<UserId>,
    pub failure_reason: Option<String>,
    pub created_by: UserId,
}

impl From<SagaTicketFromStorage> for SagaTicket {
    fn from(params: SagaTicketFromStorage) -> Self {
        let SagaTicketFromStorage {
            ticket_id,
            org_id,
            email,
            status,
            current_stage,
            groups,
            attributes,
            created_at,
            updated_at,
            sub,
            failure_reason,
            created_by,
        } = params;
        Self {
            ticket_id,
            org_id,
            email,
            status,
            current_stage,
            groups,
            attributes,
            created_at,
            updated_at,
            sub,
            failure_reason,
            created_by,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn user(id: &str) -> UserId {
        UserId::new(id).unwrap()
    }

    fn org(id: &str) -> OrganizationId {
        OrganizationId::new(id).unwrap()
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn ticket_id_generate_is_valid_ulid() {
        let id = TicketId::generate();
        assert_eq!(id.as_str().len(), 26);
        let parsed = TicketId::try_new(id.as_str()).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn ticket_id_rejects_garbage() {
        assert!(matches!(
            TicketId::try_new("not-a-ulid"),
            Err(Error::InvalidTicketId { .. })
        ));
    }

    #[test]
    fn ticket_id_roundtrip_serde() {
        let id = TicketId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: TicketId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn saga_status_serde_snake_case() {
        for (status, wire) in [
            (SagaStatus::InFlight, "\"in_flight\""),
            (SagaStatus::Succeeded, "\"succeeded\""),
            (SagaStatus::Failed, "\"failed\""),
            (SagaStatus::CompensationFailed, "\"compensation_failed\""),
        ] {
            let encoded = serde_json::to_string(&status).unwrap();
            assert_eq!(encoded, wire, "encode {status:?}");
            let decoded: SagaStatus = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, status, "roundtrip {status:?}");
        }
    }

    #[test]
    fn saga_stage_serde_matches_ddb_layout() {
        for (stage, wire) in [
            (SagaStage::S1, "\"S1\""),
            (SagaStage::S2, "\"S2\""),
            (SagaStage::S3, "\"S3\""),
            (SagaStage::Done, "\"done\""),
            (SagaStage::Compensating, "\"compensating\""),
            (SagaStage::CompensationFailed, "\"compensation_failed\""),
        ] {
            let encoded = serde_json::to_string(&stage).unwrap();
            assert_eq!(encoded, wire, "encode {stage:?}");
            let decoded: SagaStage = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, stage, "roundtrip {stage:?}");
        }
    }

    #[test]
    fn saga_status_terminality() {
        assert!(!SagaStatus::InFlight.is_terminal());
        assert!(SagaStatus::Succeeded.is_terminal());
        assert!(SagaStatus::Failed.is_terminal());
        assert!(SagaStatus::CompensationFailed.is_terminal());
    }

    #[test]
    fn saga_stage_terminality() {
        for s in [
            SagaStage::S1,
            SagaStage::S2,
            SagaStage::S3,
            SagaStage::Compensating,
        ] {
            assert!(!s.is_terminal(), "{s:?} should be non-terminal");
        }
        assert!(SagaStage::Done.is_terminal());
        assert!(SagaStage::CompensationFailed.is_terminal());
    }

    #[test]
    fn saga_ticket_new_starts_in_flight_at_s1() {
        let t = now();
        let ticket = SagaTicket::new(SagaTicketParams {
            ticket_id: TicketId::generate(),
            org_id: org("acme"),
            email: "alice@example.com".to_owned(),
            groups: vec![],
            attributes: BTreeMap::new(),
            created_at: t,
            created_by: user("admin"),
        });
        assert_eq!(ticket.status(), SagaStatus::InFlight);
        assert_eq!(ticket.current_stage(), SagaStage::S1);
        assert_eq!(ticket.created_at(), t);
        assert_eq!(ticket.updated_at(), t);
        assert!(ticket.sub().is_none());
        assert!(ticket.failure_reason().is_none());
    }
}
