//! Pipeline outcome types — the result of running the auth pipeline.

use forgeguard_authn_core::Identity;
use forgeguard_core::ResolvedFlags;
use forgeguard_http::MatchedRoute;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// PipelineOutcome
// ---------------------------------------------------------------------------

/// The result of running the auth pipeline on a single request.
///
/// This is a closed enum — every possible pipeline result is a variant.
/// Protocol adapters pattern-match on this to produce framework-specific responses.
#[derive(Debug)]
pub enum PipelineOutcome {
    /// The request matched the health-check endpoint.
    Health(String),
    /// The request matched the debug endpoint.
    Debug(String),
    /// The pipeline rejected the request (auth failure, no route, etc.).
    Reject {
        /// HTTP status code to return (e.g. 401, 403, 404).
        status: u16,
        /// Response body (error message or JSON).
        body: String,
    },
    /// The pipeline approved the request for forwarding to upstream.
    Forward {
        /// The resolved identity, if authentication succeeded.
        identity: Option<Identity>,
        /// Evaluated feature flags, if flag config is present.
        flags: Option<ResolvedFlags>,
        /// The matched route with action/resource, if a route matched.
        /// Boxed to reduce enum variant size disparity.
        matched_route: Option<Box<MatchedRoute>>,
    },
}

impl PipelineOutcome {
    /// Create a `Health` outcome.
    pub fn health(body: impl Into<String>) -> Self {
        Self::Health(body.into())
    }

    /// Create a `Debug` outcome.
    pub fn debug(body: impl Into<String>) -> Self {
        Self::Debug(body.into())
    }

    /// Create a `Reject` outcome.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRejectStatus`] if `status` is outside the
    /// 400..=599 range (HTTP client-error and server-error codes).
    pub fn reject(status: u16, body: impl Into<String>) -> Result<Self> {
        if !(400..=599).contains(&status) {
            return Err(Error::InvalidRejectStatus(status));
        }
        Ok(Self::Reject {
            status,
            body: body.into(),
        })
    }

    /// Create a `Forward` outcome with no identity, flags, or matched route.
    pub fn forward_anonymous() -> Self {
        Self::Forward {
            identity: None,
            flags: None,
            matched_route: None,
        }
    }

    /// Returns `true` if this outcome is a forward (request should proceed).
    pub fn is_forward(&self) -> bool {
        matches!(self, Self::Forward { .. })
    }

    /// Returns `true` if this outcome is a rejection.
    pub fn is_reject(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn health_outcome() {
        let outcome = PipelineOutcome::health("ok");
        match outcome {
            PipelineOutcome::Health(body) => assert_eq!(body, "ok"),
            _ => panic!("expected Health variant"),
        }
    }

    #[test]
    fn debug_outcome() {
        let outcome = PipelineOutcome::debug("{\"flags\":{}}");
        match outcome {
            PipelineOutcome::Debug(body) => assert_eq!(body, "{\"flags\":{}}"),
            _ => panic!("expected Debug variant"),
        }
    }

    #[test]
    fn reject_outcome() {
        let outcome = PipelineOutcome::reject(403, "forbidden").unwrap();
        match outcome {
            PipelineOutcome::Reject { status, body } => {
                assert_eq!(status, 403);
                assert_eq!(body, "forbidden");
            }
            _ => panic!("expected Reject variant"),
        }
    }

    #[test]
    fn forward_anonymous_outcome() {
        let outcome = PipelineOutcome::forward_anonymous();
        match outcome {
            PipelineOutcome::Forward {
                identity,
                flags,
                matched_route,
            } => {
                assert!(identity.is_none());
                assert!(flags.is_none());
                assert!(matched_route.is_none());
            }
            _ => panic!("expected Forward variant"),
        }
    }

    #[test]
    fn is_forward_returns_false_for_debug() {
        assert!(!PipelineOutcome::debug("info").is_forward());
    }

    #[test]
    fn is_forward_returns_false_for_health() {
        assert!(!PipelineOutcome::health("ok").is_forward());
    }

    #[test]
    fn is_reject_returns_false_for_debug() {
        assert!(!PipelineOutcome::debug("info").is_reject());
    }

    #[test]
    fn is_forward_returns_true_for_forward() {
        assert!(PipelineOutcome::forward_anonymous().is_forward());
    }

    #[test]
    fn is_forward_returns_false_for_reject() {
        assert!(!PipelineOutcome::reject(401, "unauthorized")
            .unwrap()
            .is_forward());
    }

    #[test]
    fn is_reject_returns_true_for_reject() {
        assert!(PipelineOutcome::reject(403, "forbidden")
            .unwrap()
            .is_reject());
    }

    #[test]
    fn is_reject_returns_false_for_health() {
        assert!(!PipelineOutcome::health("ok").is_reject());
    }

    #[test]
    fn is_reject_returns_false_for_forward() {
        assert!(!PipelineOutcome::forward_anonymous().is_reject());
    }

    #[test]
    fn reject_accepts_400() {
        assert!(PipelineOutcome::reject(400, "bad request").is_ok());
    }

    #[test]
    fn reject_accepts_599() {
        assert!(PipelineOutcome::reject(599, "error").is_ok());
    }

    #[test]
    fn reject_rejects_200() {
        let err = PipelineOutcome::reject(200, "ok").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("200") && msg.contains("400..=599"),
            "expected status-range message in: {msg}"
        );
    }

    #[test]
    fn reject_rejects_399() {
        assert!(PipelineOutcome::reject(399, "redirect").is_err());
    }

    #[test]
    fn reject_rejects_600() {
        assert!(PipelineOutcome::reject(600, "invalid").is_err());
    }
}
