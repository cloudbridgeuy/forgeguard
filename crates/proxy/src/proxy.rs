use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

use std::sync::LazyLock;

use forgeguard_authn_core::{Identity, IdentityChain};
use forgeguard_authz_core::PolicyEngine;
use forgeguard_core::{evaluate_flags, FlagConfig, ProjectId, ResolvedFlags};
use forgeguard_http::{
    build_query, evaluate_debug, extract_credential, inject_headers, ClientIpSource, CorsConfig,
    DefaultPolicy, FlagDebugQuery, IdentityProjection, MatchedRoute, PublicMatch,
    PublicRouteMatcher, RouteMatcher, UpstreamTarget,
};

/// Health check path served before any auth logic.
const HEALTH_PATH: &str = "/.well-known/forgeguard/health";

/// Debug endpoint for flag evaluation (requires --debug flag).
const FLAGS_DEBUG_PATH: &str = "/.well-known/forgeguard/flags";

// ---------------------------------------------------------------------------
// Prometheus metrics — registered globally, collected by Pingora's PrometheusServer
// ---------------------------------------------------------------------------

static REQUEST_TOTAL: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "forgeguard_requests_total",
        "Total requests by method, path, and status",
        &["method", "status"]
    )
    .unwrap_or_else(|e| panic!("failed to register forgeguard_requests_total: {e}"))
});

static REQUEST_DURATION: LazyLock<prometheus::HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        "forgeguard_request_duration_seconds",
        "Request duration in seconds",
        &["method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
    )
    .unwrap_or_else(|e| panic!("failed to register forgeguard_request_duration_seconds: {e}"))
});

static AUTH_OUTCOMES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "forgeguard_auth_outcomes_total",
        "Authentication outcomes",
        &["outcome"]
    )
    .unwrap_or_else(|e| panic!("failed to register forgeguard_auth_outcomes_total: {e}"))
});

static POLICY_DECISIONS: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "forgeguard_policy_decisions_total",
        "Policy evaluation decisions",
        &["decision"]
    )
    .unwrap_or_else(|e| panic!("failed to register forgeguard_policy_decisions_total: {e}"))
});

/// Configuration consumed by [`ForgeGuardProxy`] at construction time.
pub(crate) struct ProxyParams {
    pub identity_chain: IdentityChain,
    pub policy_engine: Arc<dyn PolicyEngine>,
    pub route_matcher: RouteMatcher,
    pub public_matcher: PublicRouteMatcher,
    pub flag_config: FlagConfig,
    pub upstream: UpstreamTarget,
    pub default_policy: DefaultPolicy,
    pub client_ip_source: ClientIpSource,
    pub project_id: ProjectId,
    pub auth_providers: Vec<String>,
    pub debug_mode: bool,
    pub cors: Option<CorsConfig>,
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
    upstream: UpstreamTarget,
    default_policy: DefaultPolicy,
    client_ip_source: ClientIpSource,
    project_id: ProjectId,
    auth_providers: Vec<String>,
    debug_mode: bool,
    /// Optional CORS configuration for preflight and response header injection.
    cors: Option<CorsConfig>,
}

impl ForgeGuardProxy {
    pub(crate) fn new(params: ProxyParams) -> Self {
        Self {
            identity_chain: params.identity_chain,
            policy_engine: params.policy_engine,
            route_matcher: params.route_matcher,
            public_matcher: params.public_matcher,
            flag_config: params.flag_config,
            upstream: params.upstream,
            default_policy: params.default_policy,
            client_ip_source: params.client_ip_source,
            project_id: params.project_id,
            auth_providers: params.auth_providers,
            debug_mode: params.debug_mode,
            cors: params.cors,
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
    /// Captured Origin header — used by later CORS tasks.
    cors_origin: Option<String>,
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
            cors_origin: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.downstream_session.req_header();
        ctx.method = req.method.to_string();
        ctx.path = req.uri.path().to_string();
        ctx.client_ip = extract_client_ip(session, self.client_ip_source);

        // 1. Health check — respond before any auth
        if ctx.path == HEALTH_PATH {
            let mut body = serde_json::json!({
                "status": "ok",
                "providers": self.auth_providers,
                "flags": self.flag_config.flags.len(),
            });
            if let Some(stats) = self.policy_engine.cache_stats() {
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
            let _ = send_json_response(session, 200, body.to_string().as_bytes(), &[]).await;
            return Ok(true);
        }

        // 1a. CORS — extract Origin header once, reuse for preflight + response injection.
        let request_origin = session
            .downstream_session
            .req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        if ctx.method == "OPTIONS" {
            if let Some(cors) = &self.cors {
                let has_acrm = session
                    .downstream_session
                    .req_header()
                    .headers
                    .get("access-control-request-method")
                    .is_some();

                if let (Some(origin), true) = (request_origin.as_deref(), has_acrm) {
                    if let Some(matched) = cors.matches_origin(origin) {
                        let headers = cors.preflight_headers(matched);
                        let _ = send_json_response(session, 204, b"", &headers).await;
                        return Ok(true);
                    }
                    // Origin present + ACRM present but origin not in allowed list.
                    // Fall through intentionally: rather than returning a CORS-specific 403,
                    // let normal routing handle it. This avoids leaking "CORS is enabled" to
                    // arbitrary origins — a non-matching origin sees the same response as any
                    // other unauthenticated request (401/403 from the auth pipeline).
                }
            }
        }

        // 1b. Set CORS origin for response header injection (preflight already returned above)
        if let (Some(cors), Some(origin)) = (&self.cors, request_origin.as_deref()) {
            if cors.matches_origin(origin).is_some() {
                ctx.cors_origin = Some(origin.to_string());
            }
        }

        // 1c. Debug endpoint — flag evaluation with reasons (requires --debug)
        if self.debug_mode && ctx.path == FLAGS_DEBUG_PATH {
            let query_str = req.uri.query().unwrap_or("");
            match FlagDebugQuery::parse(query_str) {
                Ok(query) => {
                    let result = evaluate_debug(&self.flag_config, &query);
                    match serde_json::to_string(&result) {
                        Ok(json) => {
                            let _ = send_json_response(session, 200, json.as_bytes(), &[]).await;
                        }
                        Err(_) => {
                            let body = serde_json::json!({"error": "Internal Server Error"});
                            let _ =
                                send_json_response(session, 500, body.to_string().as_bytes(), &[])
                                    .await;
                        }
                    }
                }
                Err(e) => {
                    let body = serde_json::json!({"error": format!("{e}")});
                    let _ =
                        send_json_response(session, 400, body.to_string().as_bytes(), &[]).await;
                }
            }
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
                            AUTH_OUTCOMES.with_label_values(&["success"]).inc();
                            ctx.identity = Some(identity);
                        }
                        Err(_) if require_credential => {
                            AUTH_OUTCOMES.with_label_values(&["rejected"]).inc();
                            let body = serde_json::json!({"error": "Unauthorized"});
                            let headers =
                                cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
                            let _ = send_json_response(
                                session,
                                401,
                                body.to_string().as_bytes(),
                                &headers,
                            )
                            .await;
                            return Ok(true);
                        }
                        Err(_) => {
                            // Opportunistic: resolution failed, continue without identity
                        }
                    }
                }
                None if require_credential => {
                    AUTH_OUTCOMES.with_label_values(&["missing"]).inc();
                    let body = serde_json::json!({"error": "Unauthorized"});
                    let headers = cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
                    let _ = send_json_response(session, 401, body.to_string().as_bytes(), &headers)
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
            let resolved = evaluate_flags(
                &self.flag_config,
                identity.tenant_id(),
                identity.user_id(),
                identity.groups(),
            );
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
                    let body = serde_json::json!({"error": "Not Found"});
                    let headers = cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
                    let _ = send_json_response(session, 404, body.to_string().as_bytes(), &headers)
                        .await;
                    return Ok(true);
                }
            }

            // 7. Policy evaluation — only for authenticated requests
            if let Some(identity) = &ctx.identity {
                let query = build_query(identity, &matched_route, &self.project_id, ctx.client_ip);

                match self.policy_engine.evaluate(&query).await {
                    Ok(decision) => {
                        if decision.is_denied() {
                            POLICY_DECISIONS.with_label_values(&["deny"]).inc();
                            let body = serde_json::json!({
                                "error": "Forbidden",
                                "action": matched_route.action().to_string(),
                            });
                            let headers =
                                cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
                            let _ = send_json_response(
                                session,
                                403,
                                body.to_string().as_bytes(),
                                &headers,
                            )
                            .await;
                            return Ok(true);
                        }
                        POLICY_DECISIONS.with_label_values(&["allow"]).inc();
                    }
                    Err(_) => {
                        POLICY_DECISIONS.with_label_values(&["error"]).inc();
                        let body = serde_json::json!({
                            "error": "Forbidden",
                            "action": matched_route.action().to_string(),
                        });
                        let headers = cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
                        let _ =
                            send_json_response(session, 403, body.to_string().as_bytes(), &headers)
                                .await;
                        return Ok(true);
                    }
                }
            }

            ctx.matched_route = Some(matched_route);
        } else if public_match.is_public() {
            // Public route with no [[routes]] entry — passthrough to upstream.
            // Auth was already handled (skipped for anonymous, optional for opportunistic).
        } else {
            // No route matched and not a public route
            match self.default_policy {
                DefaultPolicy::Deny => {
                    let body =
                        serde_json::json!({"error": "Forbidden", "reason": "no matching route"});
                    let headers = cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
                    let _ = send_json_response(session, 403, body.to_string().as_bytes(), &headers)
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
            self.upstream.addr(),
            self.upstream.tls(),
            self.upstream.sni().to_string(),
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

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let headers = cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
        for (name, value) in headers {
            if name == "Vary" {
                let _ = upstream_response.append_header(name, value);
            } else {
                let _ = upstream_response.insert_header(name, value);
            }
        }
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        use pingora_core::ErrorSource;

        let (code, error_type) = match e.esource() {
            ErrorSource::Upstream => (502, "upstream_unavailable"),
            ErrorSource::Downstream => (0, "downstream_error"),
            ErrorSource::Internal | ErrorSource::Unset => (500, "internal_error"),
        };

        if code > 0 {
            tracing::error!(
                method = %ctx.method,
                path = %ctx.path,
                upstream = %self.upstream.addr(),
                error_type,
                error = %e,
                status = code,
                "proxy error"
            );

            let body = serde_json::json!({
                "error": error_type,
                "status": code,
            });
            let headers = cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());
            let _ = send_json_response(session, code, body.to_string().as_bytes(), &headers).await;
        }

        pingora_proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
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

        // Record Prometheus metrics
        REQUEST_TOTAL
            .with_label_values(&[&ctx.method, &status.to_string()])
            .inc();
        REQUEST_DURATION
            .with_label_values(&[&ctx.method])
            .observe(ctx.request_start.elapsed().as_secs_f64());
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

/// Send a JSON response with optional extra headers.
///
/// Replaces `respond_error_with_body` — supports CORS and other custom headers.
async fn send_json_response(
    session: &mut Session,
    status: u16,
    body: &[u8],
    extra_headers: &[(String, String)],
) -> pingora_core::Result<()> {
    let no_body = status == 204;
    // 204 only needs space for extra_headers (CORS); other responses add Content-Type + Content-Length.
    let base_headers = if no_body { 0 } else { 2 };
    let mut resp = ResponseHeader::build(status, Some(base_headers + extra_headers.len()))?;
    if !no_body {
        resp.insert_header("Content-Type", "application/json")?;
        resp.set_content_length(body.len())?;
    }
    for (name, value) in extra_headers {
        resp.insert_header(name.clone(), value.clone())?;
    }
    session
        .downstream_session
        .write_response_header(Box::new(resp))
        .await?;
    if !no_body {
        session
            .downstream_session
            .write_response_body(Bytes::from(body.to_vec()), true)
            .await?;
    }
    Ok(())
}

/// Build CORS response headers, or return an empty `Vec` if CORS is not configured.
fn cors_headers(cors: Option<&CorsConfig>, cors_origin: Option<&str>) -> Vec<(String, String)> {
    match (cors, cors_origin) {
        (Some(config), Some(origin)) => config.response_headers(origin),
        _ => Vec::new(),
    }
}
