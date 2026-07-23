//! Embedded Cedar engine for the control plane's own `cp:*` authorization.
//!
//! Pure core: immutable snapshot + per-query entity construction from the
//! `PolicyQuery` alone. No I/O in `evaluate` — group membership arrives in
//! `PolicyContext` from the middleware's membership resolution.

use std::future::Future;
use std::pin::Pin;

use cedar_policy::Authorizer;
use forgeguard_core::ProjectId;

use crate::decision::{DenyReason, EvaluatedDecision, PolicyDecision};
use crate::engine::PolicyEngine;
use crate::engine_cp::entities::{build_cp_entities, build_cp_request};
use crate::error::Result;
use crate::query::PolicyQuery;
use crate::snapshot::Snapshot;

pub struct CpCedarEngine {
    snapshot: Snapshot,
    project: ProjectId,
}

impl CpCedarEngine {
    pub fn new(snapshot: Snapshot, project: ProjectId) -> Self {
        Self { snapshot, project }
    }

    fn decide(&self, query: &PolicyQuery) -> PolicyDecision {
        // No tenant → nothing can satisfy tenant-scoped policies. Deny,
        // don't error: an unauthenticated-shaped query is a policy miss.
        let Some(tenant) = query.context().tenant_id() else {
            return PolicyDecision::Deny {
                reason: DenyReason::NoMatchingPolicy,
            };
        };
        let built = build_cp_entities(
            query.principal(),
            query.context().groups(),
            query.resource(),
            &self.project,
            tenant,
        )
        .and_then(|entities| {
            build_cp_request(
                query.principal(),
                query.action(),
                query.resource(),
                &self.project,
                tenant,
            )
            .map(|request| (entities, request))
        });
        match built {
            Ok((entities, request)) => {
                let answer =
                    Authorizer::new().is_authorized(&request, self.snapshot.policies(), &entities);
                match answer.decision() {
                    cedar_policy::Decision::Allow => PolicyDecision::Allow,
                    cedar_policy::Decision::Deny => PolicyDecision::Deny {
                        reason: DenyReason::NoMatchingPolicy,
                    },
                }
            }
            Err(e) => PolicyDecision::Deny {
                reason: DenyReason::EvaluationError(e),
            },
        }
    }
}

// `forgeguard-axum` maps an `Err` from `PolicyEngine::evaluate` to a 500
// (evaluation-infrastructure failure), while a `Deny` maps to 403 (policy
// miss). A malformed entity/request build here is a query shape problem,
// not an infrastructure failure, so it must surface as `Deny`, never `Err`.
impl PolicyEngine for CpCedarEngine {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = Result<EvaluatedDecision>> + Send + '_>> {
        let decision = self.decide(query);
        Box::pin(std::future::ready(Ok(EvaluatedDecision::bare(decision))))
    }
}
