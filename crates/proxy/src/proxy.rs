use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_proxy::{ProxyHttp, Session};

use forgeguard_authn_core::{Identity, IdentityChain};
use forgeguard_authz_core::PolicyEngine;
use forgeguard_core::{evaluate_flags, FlagConfig, ProjectId, ResolvedFlags};
use forgeguard_http::{
    build_query, extract_credential, inject_headers, ClientIpSource, DefaultPolicy,
    IdentityProjection, MatchedRoute, PublicMatch, PublicRouteMatcher, RouteMatcher,
};

/// Health check path served before any auth logic.
const HEALTH_PATH: &str = "/.well-known/forgeguard/health";

/// Configuration consumed by [`ForgeGuardProxy`] at construction time.
pub(crate) struct ProxyParams {
    pub identity_chain: IdentityChain,
    pub policy_engine: Arc<dyn PolicyEngine>,
    pub route_matcher: RouteMatcher,
    pub public_matcher: PublicRouteMatcher,
    pub flag_config: FlagConfig,
    pub upstream_addr: String,
    pub upstream_tls: bool,
    pub upstream_sni: String,
    pub default_policy: DefaultPolicy,
    pub client_ip_source: ClientIpSource,
    pub project_id: ProjectId,
    pub auth_providers: Vec<String>,
}

/// The Pingora `ProxyHttp` implementation.
///
/// Thin imperative shell: all business decisions delegate to pure functions
/// in domain crates. Pingora I/O stays here.
pub(crate) struct ForgeGuardProxy {
    identity_chain: IdentityChain,
    policy_engine: Arc<dyn PolicyEngine>,
    route_matcher: RouteMatcher,
    public_matcher: PublicRouteMatcher,
    flag_config: FlagConfig,
    upstream_addr: String,
    upstream_tls: bool,
    upstream_sni: String,
    default_policy: DefaultPolicy,
    client_ip_source: ClientIpSource,
    project_id: ProjectId,
    auth_providers: Vec<String>,
}

impl ForgeGuardProxy {
    pub(crate) fn new(params: ProxyParams) -> Self {
        Self {
            identity_chain: params.identity_chain,
            policy_engine: params.policy_engine,
            route_matcher: params.route_matcher,
            public_matcher: params.public_matcher,
            flag_config: params.flag_config,
            upstream_addr: params.upstream_addr,
            upstream_tls: params.upstream_tls,
            upstream_sni: params.upstream_sni,
            default_policy: params.default_policy,
            client_ip_source: params.client_ip_source,
            project_id: params.project_id,
            auth_providers: params.auth_providers,
        }
    }
}

/// Per-request state passed through all Pingora lifecycle phases.
pub(crate) struct RequestCtx {
    identity: Option<Identity>,
    flags: Option<ResolvedFlags>,
    matched_route: Option<MatchedRoute>,
    request_start: Instant,
    method: String,
    path: String,
    client_ip: Option<IpAddr>,
}

#[async_trait]
impl ProxyHttp for ForgeGuardProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            identity: None,
            flags: None,
            matched_route: None,
            request_start: Instant::now(),
            method: String::new(),
            path: String::new(),
            client_ip: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.downstream_session.req_header();
        ctx.method = req.method.to_string();
        ctx.path = req.uri.path().to_string();
        ctx.client_ip = extract_client_ip(session, self.client_ip_source);

        // 1. Health check — respond before any auth
        if ctx.path == HEALTH_PATH {
            let body = serde_json::json!({
                "status": "ok",
                "providers": self.auth_providers,
                "flags": self.flag_config.flags.len(),
            });
            let _ = session
                .respond_error_with_body(200, Bytes::from(body.to_string()))
                .await;
            return Ok(true);
        }

        // 2. Public route check
        let public_match = self.public_matcher.check(&ctx.method, &ctx.path);

        // 3. Auth flow based on public match result
        let require_credential = matches!(public_match, PublicMatch::NotPublic);
        let try_credential = matches!(
            public_match,
            PublicMatch::NotPublic | PublicMatch::Opportunistic
        );

        if try_credential {
            let headers = extract_headers(req);
            let credential = extract_credential(&headers);

            match credential {
                Some(cred) => {
                    match self.identity_chain.resolve(&cred).await {
                        Ok(identity) => {
                            ctx.identity = Some(identity);
                        }
                        Err(_) if require_credential => {
                            let body = serde_json::json!({"error": "Unauthorized"});
                            let _ = session
                                .respond_error_with_body(401, Bytes::from(body.to_string()))
                                .await;
                            return Ok(true);
                        }
                        Err(_) => {
                            // Opportunistic: resolution failed, continue without identity
                        }
                    }
                }
                None if require_credential => {
                    let body = serde_json::json!({"error": "Unauthorized"});
                    let _ = session
                        .respond_error_with_body(401, Bytes::from(body.to_string()))
                        .await;
                    return Ok(true);
                }
                None => {
                    // Opportunistic or Anonymous: no credential, continue
                }
            }
        }

        // 4. Evaluate feature flags (pure, no I/O)
        if let Some(identity) = &ctx.identity {
            let resolved =
                evaluate_flags(&self.flag_config, identity.tenant_id(), identity.user_id());
            ctx.flags = Some(resolved);
        }

        // 5. Route matching
        let matched = self.route_matcher.match_request(&ctx.method, &ctx.path);

        if let Some(matched_route) = matched {
            // 6. Feature gate check
            if let Some(gate) = matched_route.feature_gate() {
                let gate_enabled = ctx
                    .flags
                    .as_ref()
                    .is_some_and(|flags| flags.enabled(&gate.to_string()));
                if !gate_enabled {
                    let _ = session.respond_error(404).await;
                    return Ok(true);
                }
            }

            // 7. Policy evaluation — only for authenticated requests
            if let Some(identity) = &ctx.identity {
                let query = build_query(identity, &matched_route, &self.project_id, ctx.client_ip);

                match self.policy_engine.evaluate(&query).await {
                    Ok(decision) => {
                        if decision.is_denied() {
                            let body = serde_json::json!({
                                "error": "Forbidden",
                                "action": matched_route.action().to_string(),
                            });
                            let _ = session
                                .respond_error_with_body(403, Bytes::from(body.to_string()))
                                .await;
                            return Ok(true);
                        }
                    }
                    Err(_) => {
                        let body = serde_json::json!({
                            "error": "Forbidden",
                            "action": matched_route.action().to_string(),
                        });
                        let _ = session
                            .respond_error_with_body(403, Bytes::from(body.to_string()))
                            .await;
                        return Ok(true);
                    }
                }
            }

            ctx.matched_route = Some(matched_route);
        } else {
            // No route matched
            match self.default_policy {
                DefaultPolicy::Deny => {
                    let body =
                        serde_json::json!({"error": "Forbidden", "reason": "no matching route"});
                    let _ = session
                        .respond_error_with_body(403, Bytes::from(body.to_string()))
                        .await;
                    return Ok(true);
                }
                DefaultPolicy::Passthrough => {
                    // Continue to upstream without authz
                }
            }
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new(
            &*self.upstream_addr,
            self.upstream_tls,
            self.upstream_sni.clone(),
        );
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(identity) = &ctx.identity {
            let projection = IdentityProjection::new(identity, ctx.flags.as_ref(), ctx.client_ip);
            let headers = inject_headers(&projection);
            for (name, value) in headers {
                let _ = upstream_request.insert_header(name, value);
            }
        }
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session
            .downstream_session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());

        let user = ctx.identity.as_ref().map_or("-", |i| i.user_id().as_str());

        let tenant = ctx
            .identity
            .as_ref()
            .and_then(|i| i.tenant_id())
            .map_or("-".to_string(), |t| t.as_str().to_string());

        let resolver = ctx.identity.as_ref().map_or("-", |i| i.resolver());

        let action = ctx
            .matched_route
            .as_ref()
            .map_or("-".to_string(), |r| r.action().to_string());

        let latency_ms = ctx.request_start.elapsed().as_millis();

        if let Some(e) = error {
            tracing::warn!(
                method = %ctx.method,
                path = %ctx.path,
                status,
                user,
                tenant = %tenant,
                resolver,
                action = %action,
                latency_ms,
                error = %e,
                "request"
            );
        } else {
            tracing::info!(
                method = %ctx.method,
                path = %ctx.path,
                status,
                user,
                tenant = %tenant,
                resolver,
                action = %action,
                latency_ms,
                "request"
            );
        }
    }
}

/// Convert Pingora `RequestHeader` to the `Vec<(String, String)>` format
/// that `forgeguard_http::extract_credential` expects.
fn extract_headers(req: &RequestHeader) -> Vec<(String, String)> {
    req.headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// Extract the client IP from the session based on the configured source.
fn extract_client_ip(session: &Session, source: ClientIpSource) -> Option<IpAddr> {
    match source {
        ClientIpSource::Peer => session
            .downstream_session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(std::net::SocketAddr::ip),
        ClientIpSource::XForwardedFor => {
            let req = session.downstream_session.req_header();
            req.headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .and_then(|v| v.trim().parse().ok())
        }
        ClientIpSource::CfConnectingIp => {
            let req = session.downstream_session.req_header();
            req.headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok())
        }
    }
}
