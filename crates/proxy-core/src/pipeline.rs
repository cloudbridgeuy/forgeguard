//! Auth pipeline evaluation — the pure decision function.
//!
//! [`evaluate_pipeline`] encodes every phase of the ForgeGuard request filter
//! as a pure async function with no framework dependencies. Protocol adapters
//! (Pingora, Axum, Lambda) call this and pattern-match on [`PipelineOutcome`].

use forgeguard_authn_core::{Identity, IdentityChain, IdentityParams};
use forgeguard_authz_core::PolicyEngine;
use forgeguard_core::evaluate_flags;
use forgeguard_http::{
    build_query, evaluate_debug, extract_credential, DefaultPolicy, FlagDebugQuery, PublicMatch,
};
use http::StatusCode;

use crate::{PipelineConfig, PipelineOutcome, RequestInput};

/// Health check path served before any auth logic.
const HEALTH_PATH: &str = "/.well-known/forgeguard/health";

/// Debug endpoint for flag evaluation (requires debug mode).
const FLAGS_DEBUG_PATH: &str = "/.well-known/forgeguard/flags";

/// Run the full auth pipeline on a single request.
///
/// This is the pure decision function — it performs no I/O itself but awaits
/// the `identity_chain` and `policy_engine` trait methods (which may perform
/// I/O in production but are pure in tests).
///
/// The phases exactly mirror `ForgeGuardProxy::request_filter` in the Pingora
/// adapter, minus CORS handling and metrics (which remain in the adapter).
///
/// # Phases
///
/// 1. **Health check** — `/.well-known/forgeguard/health`
/// 2. **Debug endpoint** — `/.well-known/forgeguard/flags` (debug mode only)
/// 3. **Public route check** — determines auth requirement
/// 4. **Credential extraction** — from headers
/// 5. **Identity resolution** — via the identity chain
///    5b. **Org membership enrichment** — enrich identity with tenant + groups
/// 6. **Feature flags** — evaluated for authenticated requests
/// 7. **Route matching** — `(method, path)` to action/resource
/// 8. **Feature gate** — reject if gated route's flag is disabled
/// 9. **Policy evaluation** — authz decision for authenticated + matched routes
/// 10. **Default policy** — fallback for unmatched, non-public requests
pub async fn evaluate_pipeline(
    config: &PipelineConfig,
    input: &RequestInput,
    identity_chain: &IdentityChain,
    policy_engine: &dyn PolicyEngine,
) -> PipelineOutcome {
    let method = input.method().to_string();
    let path = input.path();

    // Phase 1: Health check
    if path == HEALTH_PATH {
        return health_response(config, policy_engine);
    }

    // Phase 2: Debug endpoint (requires debug mode)
    if config.debug_mode() && path == FLAGS_DEBUG_PATH {
        return debug_response(config, input);
    }

    // Phase 3: Public route check
    let public_match = config.public_route_matcher().check(&method, path);
    let require_credential = matches!(public_match, PublicMatch::NotPublic);
    let try_credential = matches!(
        public_match,
        PublicMatch::NotPublic | PublicMatch::Opportunistic
    );

    // Phase 4–5: Credential extraction and identity resolution
    let mut identity = None;

    if try_credential {
        let credential = extract_credential(input.headers());

        match credential {
            Some(cred) => match identity_chain.resolve(&cred).await {
                Ok(id) => {
                    identity = Some(id);
                }
                Err(_) if require_credential => {
                    return reject_json(StatusCode::UNAUTHORIZED, "Unauthorized");
                }
                Err(_) => {
                    // Opportunistic: resolution failed, continue without identity
                }
            },
            None if require_credential => {
                return reject_json(StatusCode::UNAUTHORIZED, "Unauthorized");
            }
            None => {
                // Opportunistic or Anonymous: no credential, continue
            }
        }
    }

    // Phase 5b: Org membership enrichment
    // If a resolver is configured AND the identity has no tenant_id yet
    // (JWT auth never sets one; Ed25519 machine auth always does), read
    // X-ForgeGuard-Org-Id, validate membership, and enrich the identity.
    if let Some(resolver) = config.membership_resolver() {
        if identity.as_ref().is_some_and(|id| id.tenant_id().is_none()) {
            let org_header = input
                .headers()
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-forgeguard-org-id"))
                .map(|(_, value)| value.as_str());

            // Validate/parse the header before consuming the identity, so the
            // early-return paths leave `identity` untouched.
            let org_id = match org_header {
                None if require_credential => {
                    return reject_json(
                        StatusCode::BAD_REQUEST,
                        "Missing X-ForgeGuard-Org-Id header",
                    );
                }
                None => {
                    // No org header on an optional/public route — skip enrichment.
                    None
                }
                Some(org_str) => match forgeguard_core::OrganizationId::new(org_str) {
                    Ok(id) => Some(id),
                    Err(_) => {
                        return reject_json(
                            StatusCode::BAD_REQUEST,
                            "Invalid X-ForgeGuard-Org-Id header",
                        )
                    }
                },
            };

            // `org_id` is `Some` only when the header was present and valid.
            // Only drain `identity` when `org_id` is `Some`; if the header was
            // absent on an optional/public route we must leave `identity` intact
            // so downstream phases (flags, policy, forward) still see it.
            if let Some(org_id) = org_id {
                // The `is_some_and(|id| id.tenant_id().is_none())` guard above
                // ensures `identity` is `Some` here — the inner `if let` is
                // always true; the `None` arm is a no-op safety net.
                if let Some(id) = identity.take() {
                    match resolver.resolve(id.user_id(), &org_id).await {
                        Ok(Some(membership)) => {
                            identity = Some(Identity::new(IdentityParams {
                                user_id: id.user_id().clone(),
                                tenant_id: Some(org_id.into()),
                                groups: membership.groups().to_vec(),
                                expiry: id.expiry().copied(),
                                resolver: id.resolver(),
                                extra: id.extra().cloned(),
                                principal_kind: id.principal_kind(),
                            }));
                        }
                        Ok(None) => {
                            return reject_json(
                                StatusCode::FORBIDDEN,
                                "Not a member of this organization",
                            );
                        }
                        Err(_) => {
                            return reject_json(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Internal Server Error",
                            );
                        }
                    }
                }
            }
        }
    }

    // Phase 6: Feature flags (pure, no I/O)
    let flags = identity.as_ref().map(|id| {
        evaluate_flags(
            config.flag_config(),
            id.tenant_id(),
            id.user_id(),
            id.groups(),
        )
    });

    // Phase 7: Route matching
    let matched = config.route_matcher().match_request(&method, path);

    if let Some(matched_route) = matched {
        // Phase 8: Feature gate check
        if let Some(gate) = matched_route.feature_gate() {
            let gate_enabled = flags.as_ref().is_some_and(|f| f.enabled(&gate.to_string()));
            if !gate_enabled {
                return reject_json(StatusCode::NOT_FOUND, "Not Found");
            }
        }

        // Phase 9: Policy evaluation — only for authenticated requests.
        // Fail-safe: both explicit deny and evaluation errors result in rejection.
        if let Some(id) = &identity {
            let query = build_query(id, &matched_route, config.project_id(), input.client_ip());
            let allowed = policy_engine
                .evaluate(&query)
                .await
                .is_ok_and(|d| !d.is_denied());

            if !allowed {
                return reject_forbidden_with_action(&matched_route.action().to_string());
            }
        }

        PipelineOutcome::Forward {
            identity,
            flags,
            matched_route: Some(Box::new(matched_route)),
        }
    } else if public_match.is_public() {
        // Public route with no [[routes]] entry — passthrough to upstream
        PipelineOutcome::Forward {
            identity,
            flags,
            matched_route: None,
        }
    } else {
        // Phase 10: No route matched and not a public route
        match config.default_policy() {
            DefaultPolicy::Deny => {
                let body = serde_json::json!({"error": "Forbidden", "reason": "no matching route"});
                PipelineOutcome::Reject {
                    status: StatusCode::FORBIDDEN,
                    body: body.to_string(),
                }
            }
            DefaultPolicy::Passthrough => PipelineOutcome::Forward {
                identity,
                flags,
                matched_route: None,
            },
        }
    }
}

/// Build the health check response body.
fn health_response(config: &PipelineConfig, policy_engine: &dyn PolicyEngine) -> PipelineOutcome {
    let mut body = serde_json::json!({
        "status": "ok",
        "providers": config.auth_providers(),
        "flags": config.flag_config().flags().len(),
    });
    if let Some(stats) = policy_engine.cache_stats() {
        body["cache_hits"] = stats.hits().into();
        body["cache_misses"] = stats.misses().into();
        if let Some(l2_hits) = stats.l2_hits() {
            body["l2_cache_hits"] = l2_hits.into();
        }
        if let Some(l2_misses) = stats.l2_misses() {
            body["l2_cache_misses"] = l2_misses.into();
        }
        if let Some(l2_errors) = stats.l2_errors() {
            body["l2_cache_errors"] = l2_errors.into();
        }
    }
    PipelineOutcome::Health(body.to_string())
}

/// Build the debug endpoint response.
fn debug_response(config: &PipelineConfig, input: &RequestInput) -> PipelineOutcome {
    let query_str = input.query_string().unwrap_or("");

    let query = match FlagDebugQuery::parse(query_str) {
        Ok(q) => q,
        Err(e) => return reject_json(StatusCode::BAD_REQUEST, &format!("{e}")),
    };

    let result = evaluate_debug(config.flag_config(), &query);

    match serde_json::to_string(&result) {
        Ok(json) => PipelineOutcome::Debug(json),
        Err(_) => reject_json(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
    }
}

/// Build a JSON `{"error": <msg>}` reject outcome.
fn reject_json(status: StatusCode, error: &str) -> PipelineOutcome {
    let body = serde_json::json!({"error": error});
    PipelineOutcome::Reject {
        status,
        body: body.to_string(),
    }
}

/// Convenience: build a Forbidden reject with action context.
fn reject_forbidden_with_action(action: &str) -> PipelineOutcome {
    let body = serde_json::json!({
        "error": "Forbidden",
        "action": action,
    });
    PipelineOutcome::Reject {
        status: StatusCode::FORBIDDEN,
        body: body.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "pipeline_tests.rs"]
mod tests;
