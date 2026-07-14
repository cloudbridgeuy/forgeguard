//! Read side of the per-org event log (D9: separate from [`crate::AuthzStore`]
//! so the cursor handler depends on the narrow contract).

use std::future::Future;
use std::pin::Pin;

#[cfg(any(test, feature = "test-support"))]
use crate::error::Error;
use crate::error::Result;
use crate::event::envelope::EventEnvelope;
use crate::store::revision::Revision;

/// Replay access to a per-org append-only event log.
pub trait EventLog: Send + Sync {
    /// Events with seq > after, ascending, at most limit.
    fn events_after(
        &self,
        after: Revision,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<EventEnvelope>>> + Send + '_>>;

    /// Current revision (0 = empty log).
    fn latest_revision(&self) -> Pin<Box<dyn Future<Output = Result<Revision>> + Send + '_>>;
}

/// In-memory reference implementation of [`EventLog`], for handler tests.
#[cfg(any(test, feature = "test-support"))]
pub struct InMemoryEventLog {
    events: std::sync::Mutex<Vec<EventEnvelope>>,
}

#[cfg(any(test, feature = "test-support"))]
fn ready<T: Send + 'static>(
    value: Result<T>,
) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 'static>> {
    Box::pin(std::future::ready(value))
}

#[cfg(any(test, feature = "test-support"))]
impl InMemoryEventLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Vec<EventEnvelope>>> {
        self.events
            .lock()
            .map_err(|e| Error::EvaluationFailed(format!("in-memory event log lock poisoned: {e}")))
    }

    /// Append an envelope directly (test-only — production appends go
    /// through the transactional shell implementation).
    pub fn push(&self, envelope: EventEnvelope) {
        if let Ok(mut events) = self.locked() {
            events.push(envelope);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Default for InMemoryEventLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl EventLog for InMemoryEventLog {
    fn events_after(
        &self,
        after: Revision,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<EventEnvelope>>> + Send + '_>> {
        let result = self.locked().map(|events| {
            events
                .iter()
                .filter(|e| e.seq() > after)
                .take(limit)
                .cloned()
                .collect()
        });
        ready(result)
    }

    fn latest_revision(&self) -> Pin<Box<dyn Future<Output = Result<Revision>> + Send + '_>> {
        let result = self.locked().map(|events| {
            events
                .last()
                .map(super::envelope::EventEnvelope::seq)
                .unwrap_or(Revision::new(0))
        });
        ready(result)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::event::envelope::{Actor, EventDraft, EventDraftParams, EventId};
    use crate::event::kind::EventKind;
    use forgeguard_core::{Fgrn, NativeId, Segment};

    fn envelope(seq: u64) -> EventEnvelope {
        let draft = EventDraft::new(EventDraftParams {
            event_id: EventId::try_new(format!("01J{seq:022}")).unwrap(),
            seq: Revision::new(seq),
            kind: EventKind::PrincipalUpserted,
            occurred_at: "2026-07-14T00:00:00Z".to_string(),
            actor: Actor::Principal(Fgrn::principal(
                &Segment::try_new("acme").unwrap(),
                &NativeId::try_new("usr_1").unwrap(),
            )),
            payload: serde_json::json!({ "seq": seq }),
        });
        EventEnvelope::from_signed(draft, "key-1".to_string(), "sig".to_string())
    }

    #[tokio::test]
    async fn events_after_returns_ascending_tail() {
        let log = InMemoryEventLog::new();
        log.push(envelope(1));
        log.push(envelope(2));
        log.push(envelope(3));

        let page = log.events_after(Revision::new(1), 10).await.unwrap();
        let seqs: Vec<u64> = page.iter().map(|e| e.seq().value()).collect();
        assert_eq!(seqs, vec![2, 3]);
    }

    #[tokio::test]
    async fn limit_truncates() {
        let log = InMemoryEventLog::new();
        log.push(envelope(1));
        log.push(envelope(2));
        log.push(envelope(3));

        let page = log.events_after(Revision::new(0), 2).await.unwrap();
        assert_eq!(page.len(), 2);
    }

    #[tokio::test]
    async fn empty_log_has_zero_latest_revision() {
        let log = InMemoryEventLog::new();
        assert_eq!(log.latest_revision().await.unwrap(), Revision::new(0));
    }
}
