//! Authorization decision types.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_cedar::DecisionRecord;

/// Why a request was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    /// No policy matched the query.
    NoMatchingPolicy,
    /// A policy explicitly denied the request.
    ExplicitDeny { policy_id: String },
    /// An error occurred during policy evaluation.
    EvaluationError(String),
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatchingPolicy => write!(f, "no matching policy"),
            Self::ExplicitDeny { policy_id } => {
                write!(f, "explicitly denied by policy '{policy_id}'")
            }
            Self::EvaluationError(msg) => write!(f, "evaluation error: {msg}"),
        }
    }
}

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// The request is allowed.
    Allow,
    /// The request is denied.
    Deny { reason: DenyReason },
}

impl PolicyDecision {
    /// Returns `true` if the decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allowed"),
            Self::Deny { reason } => write!(f, "denied: {reason}"),
        }
    }
}

/// A policy verdict plus, when the engine is record-producing (embedded
/// Cedar), the versioned record behind it. Non-record engines (static, VP,
/// CP) return `record: None` — impossible states stay impossible: a record
/// is never fabricated.
#[derive(Debug, Clone)]
pub struct EvaluatedDecision {
    decision: PolicyDecision,
    record: Option<DecisionRecord>,
}

impl EvaluatedDecision {
    /// A verdict with no backing record (static / VP / CP engines).
    pub fn bare(decision: PolicyDecision) -> Self {
        Self {
            decision,
            record: None,
        }
    }

    /// A verdict backed by an embedded-Cedar decision record.
    pub fn with_record(decision: PolicyDecision, record: DecisionRecord) -> Self {
        Self {
            decision,
            record: Some(record),
        }
    }

    /// The verdict.
    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
    }

    /// Convenience mirror of `PolicyDecision::is_denied`.
    pub fn is_denied(&self) -> bool {
        self.decision.is_denied()
    }

    /// Take the record, if the engine produced one.
    pub fn into_record(self) -> Option<DecisionRecord> {
        self.record
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_allow() {
        let decision = PolicyDecision::Allow;
        assert_eq!(decision.to_string(), "allowed");
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
    }

    #[test]
    fn display_deny_no_matching_policy() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        };
        assert_eq!(decision.to_string(), "denied: no matching policy");
        assert!(!decision.is_allowed());
        assert!(decision.is_denied());
    }

    #[test]
    fn display_deny_explicit() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::ExplicitDeny {
                policy_id: "pol-admin-deny-delete".into(),
            },
        };
        assert_eq!(
            decision.to_string(),
            "denied: explicitly denied by policy 'pol-admin-deny-delete'"
        );
    }

    #[test]
    fn display_deny_evaluation_error() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::EvaluationError("connection timeout".into()),
        };
        assert_eq!(
            decision.to_string(),
            "denied: evaluation error: connection timeout"
        );
    }

    #[test]
    fn serde_round_trip_allow() {
        let decision = PolicyDecision::Allow;
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn serde_round_trip_deny_explicit() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::ExplicitDeny {
                policy_id: "pol-1".into(),
            },
        };
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn serde_round_trip_deny_no_matching() {
        let decision = PolicyDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    fn record() -> DecisionRecord {
        use crate::engine_cedar::Decision;
        use crate::snapshot::SnapshotVersion;
        use crate::store::Revision;
        use crate::ScopePath;

        let root: forgeguard_core::Fgrn = "fgrn:acme:orgunit:root".parse().unwrap();
        DecisionRecord::new(
            Decision::Allow,
            SnapshotVersion::of("permit();"),
            Revision::new(1),
            ScopePath::try_new(vec![root]).unwrap(),
            vec![],
        )
    }

    #[test]
    fn bare_has_no_record_and_preserves_verdict() {
        let evaluated = EvaluatedDecision::bare(PolicyDecision::Allow);
        assert_eq!(evaluated.decision(), &PolicyDecision::Allow);
        assert!(!evaluated.is_denied());
        assert!(evaluated.into_record().is_none());
    }

    #[test]
    fn with_record_round_trips_the_record() {
        let evaluated = EvaluatedDecision::with_record(PolicyDecision::Allow, record());
        assert_eq!(evaluated.decision(), &PolicyDecision::Allow);
        let record = evaluated.into_record().unwrap();
        assert_eq!(record.revision(), crate::store::Revision::new(1));
    }
}
