//! Pure principal-upsert decision (D6): whether an incoming payload changes
//! the stored state, with no I/O and no clock.

/// Outcome of comparing an incoming principal payload against its existing state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertDecision {
    /// The incoming payload is canonically identical to the existing one.
    NoOp,
    /// The incoming payload differs (or nothing existed yet); this payload
    /// becomes the new state.
    Changed {
        /// The payload to persist and to embed in the appended event.
        payload: serde_json::Value,
    },
}

/// Decide whether `incoming` changes `existing`.
///
/// Canonical compare = `serde_json::Value` equality. `Value`'s `PartialEq`
/// treats JSON objects as maps, so key order never affects the comparison —
/// that map-equality IS the canonical form here, not a serialized byte
/// comparison.
pub fn decide_upsert(
    existing: Option<&serde_json::Value>,
    incoming: &serde_json::Value,
) -> UpsertDecision {
    match existing {
        Some(current) if current == incoming => UpsertDecision::NoOp,
        _ => UpsertDecision::Changed {
            payload: incoming.clone(),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn same_json_different_key_order_is_noop() {
        let existing = serde_json::json!({ "a": 1, "b": 2 });
        let incoming = serde_json::json!({ "b": 2, "a": 1 });
        assert_eq!(
            decide_upsert(Some(&existing), &incoming),
            UpsertDecision::NoOp
        );
    }

    #[test]
    fn changed_field_is_changed() {
        let existing = serde_json::json!({ "a": 1 });
        let incoming = serde_json::json!({ "a": 2 });
        assert_eq!(
            decide_upsert(Some(&existing), &incoming),
            UpsertDecision::Changed { payload: incoming }
        );
    }

    #[test]
    fn no_existing_state_is_changed() {
        let incoming = serde_json::json!({ "a": 1 });
        assert_eq!(
            decide_upsert(None, &incoming),
            UpsertDecision::Changed { payload: incoming }
        );
    }
}
