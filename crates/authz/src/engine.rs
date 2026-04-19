//! Verified Permissions policy engine — the I/O shell.

use std::future::Future;
use std::pin::Pin;

use aws_sdk_verifiedpermissions::types::EntitiesDefinition;
use forgeguard_authz_core::{CacheStats, DenyReason, PolicyDecision, PolicyEngine, PolicyQuery};
use forgeguard_core::ProjectId;

use crate::cache::{build_cache_key, CacheKey};
use crate::config::VpEngineConfig;
use crate::tiered_cache::TieredCache;
use crate::translate::{
    build_vp_entities, build_vp_request, translate_vp_decision, VpRequestComponents,
};

/// AWS Verified Permissions policy engine.
///
/// Implements [`PolicyEngine`] by calling the VP `IsAuthorized` API.
/// Results are cached in an LRU cache with TTL-based expiry.
///
/// The VP client is injected at construction time for testability.
pub struct VpPolicyEngine {
    client: aws_sdk_verifiedpermissions::Client,
    policy_store_id: String,
    project_id: ProjectId,
    cache: TieredCache,
}

/// Return an immediately-resolved deny future carrying an `EvaluationError`.
///
/// Used by `evaluate()` to consolidate the three early-return arms that all
/// produce the same shape: `Ok(Deny { EvaluationError(msg) })`.
fn deny_eval_error(
    msg: impl Into<String>,
) -> Pin<Box<dyn Future<Output = forgeguard_authz_core::Result<PolicyDecision>> + Send + 'static>> {
    let decision = PolicyDecision::Deny {
        reason: DenyReason::EvaluationError(msg.into()),
    };
    Box::pin(std::future::ready(Ok(decision)))
}

impl VpPolicyEngine {
    /// Create a new engine with an injected VP client.
    pub fn new(
        client: aws_sdk_verifiedpermissions::Client,
        config: &VpEngineConfig,
        project_id: ProjectId,
        cache: TieredCache,
    ) -> Self {
        Self {
            client,
            policy_store_id: config.policy_store_id().to_string(),
            project_id,
            cache,
        }
    }

    /// Internal evaluation: cache check -> VP call -> cache insert.
    async fn call_vp(
        &self,
        cache_key: CacheKey,
        components: VpRequestComponents,
        entities: EntitiesDefinition,
    ) -> PolicyDecision {
        tracing::debug!(
            principal_type = %components.principal.entity_type(),
            principal_id = %components.principal.entity_id(),
            action_type = %components.action.action_type(),
            action_id = %components.action.action_id(),
            resource = ?components.resource.as_ref().map(|r| format!("{}::{}", r.entity_type(), r.entity_id())),
            "VP IsAuthorized request"
        );

        let mut req = self
            .client
            .is_authorized()
            .policy_store_id(&self.policy_store_id)
            .principal(components.principal)
            .action(components.action)
            .entities(entities);

        if let Some(resource) = components.resource {
            req = req.resource(resource);
        }

        let decision = match req.send().await {
            Ok(output) => {
                for err in output.errors() {
                    tracing::warn!(
                        error = %err.error_description(),
                        "VP evaluation error"
                    );
                }
                for policy in output.determining_policies() {
                    tracing::debug!(
                        policy_id = %policy.policy_id(),
                        "determining policy"
                    );
                }
                translate_vp_decision(output.decision())
            }
            Err(sdk_err) => {
                tracing::warn!(error = ?sdk_err, "VP SDK error — returning deny");
                PolicyDecision::Deny {
                    reason: DenyReason::EvaluationError(sdk_err.to_string()),
                }
            }
        };

        self.cache.insert(&cache_key, &decision);
        decision
    }
}

impl PolicyEngine for VpPolicyEngine {
    fn evaluate(
        &self,
        query: &PolicyQuery,
    ) -> Pin<Box<dyn Future<Output = forgeguard_authz_core::Result<PolicyDecision>> + Send + '_>>
    {
        let groups: Vec<&str> = query
            .context()
            .groups()
            .iter()
            .map(forgeguard_core::GroupName::as_str)
            .collect();
        tracing::debug!(
            ?groups,
            principal_kind = ?query.principal().kind(),
            "VP evaluate — query context"
        );

        let Some(tenant_id) = query.context().tenant_id() else {
            tracing::warn!(
                principal_kind = ?query.principal().kind(),
                "VP evaluate denied: no tenant_id in query context — check X-ForgeGuard-Org-Id header and membership resolver wiring"
            );
            return deny_eval_error("no tenant_id in query context");
        };

        tracing::debug!(tenant_id = %tenant_id, "VP evaluate — tenant resolved");

        let cache_key = build_cache_key(query);

        // Build VP request components (pure translation, no I/O).
        let components = match build_vp_request(query, &self.project_id, tenant_id) {
            Ok(c) => c,
            Err(e) => return deny_eval_error(e.to_string()),
        };

        // Build inline entities (principal + groups + resource).
        let entities = match build_vp_entities(
            query.principal(),
            query.context().groups(),
            query.resource(),
            &self.project_id,
            tenant_id,
        ) {
            Ok(e) => e,
            Err(e) => return deny_eval_error(e.to_string()),
        };

        Box::pin(async move {
            // Check cache (async — may hit L2/Redis)
            if let Some(cached) = self.cache.get(&cache_key).await {
                tracing::debug!("cache hit");
                return Ok(cached);
            }

            Ok(self.call_vp(cache_key, components, entities).await)
        })
    }

    fn cache_stats(&self) -> Option<CacheStats> {
        let mut stats = CacheStats::new(
            self.cache.l1_hits() + self.cache.l2_hits(),
            self.cache.l1_misses(),
        );
        if self.cache.has_l2() {
            stats = stats.with_l2(
                self.cache.l2_hits(),
                self.cache.l2_misses(),
                self.cache.l2_errors(),
            );
        }
        Some(stats)
    }
}
