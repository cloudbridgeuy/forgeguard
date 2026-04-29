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

use forgeguard_authn_core::signing::{KeyId, SigningKey, Timestamp};
use forgeguard_authn_core::{Identity, IdentityChain};
use forgeguard_authz_core::PolicyEngine;
use forgeguard_core::ResolvedFlags;
use forgeguard_http::{
    inject_signed_headers, ClientIpSource, CorsConfig, IdentityProjection, MatchedRoute,
    UpstreamTarget,
};
use forgeguard_proxy_core::{evaluate_pipeline, PipelineConfig, PipelineOutcome, RequestInput};

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
    pub(crate) pipeline_config: PipelineConfig,
    pub(crate) identity_chain: IdentityChain,
    pub(crate) policy_engine: Arc<dyn PolicyEngine>,
    pub(crate) upstream: UpstreamTarget,
    pub(crate) client_ip_source: ClientIpSource,
    pub(crate) cors: Option<CorsConfig>,
    pub(crate) signing: Option<(SigningKey, KeyId)>,
}

/// The Pingora `ProxyHttp` implementation.
///
/// Thin imperative shell: all business decisions delegate to pure functions
/// in domain crates. Pingora I/O stays here.
pub(crate) struct ForgeGuardProxy {
    pipeline_config: PipelineConfig,
    identity_chain: IdentityChain,
    policy_engine: Arc<dyn PolicyEngine>,
    upstream: UpstreamTarget,
    client_ip_source: ClientIpSource,
    /// Optional CORS configuration for preflight and response header injection.
    cors: Option<CorsConfig>,
    /// Optional Ed25519 signing key for request signing.
    signing: Option<(SigningKey, KeyId)>,
}

impl ForgeGuardProxy {
    pub(crate) fn new(params: ProxyParams) -> Self {
        Self {
            pipeline_config: params.pipeline_config,
            identity_chain: params.identity_chain,
            policy_engine: params.policy_engine,
            upstream: params.upstream,
            client_ip_source: params.client_ip_source,
            cors: params.cors,
            signing: params.signing,
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

        // --- CORS (transport concern — stays in adapter) ---
        let request_origin = req
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        if ctx.method == "OPTIONS" {
            if let Some(cors) = &self.cors {
                let has_acrm = req.headers.get("access-control-request-method").is_some();

                if let (Some(origin), true) = (request_origin.as_deref(), has_acrm) {
                    if let Some(matched) = cors.matches_origin(origin) {
                        let headers = cors.preflight_headers(matched);
                        let _ = send_json_response(session, 204, b"", &headers).await;
                        return Ok(true);
                    }
                }
            }
        }

        if let (Some(cors), Some(origin)) = (&self.cors, request_origin.as_deref()) {
            if cors.matches_origin(origin).is_some() {
                ctx.cors_origin = Some(origin.to_string());
            }
        }

        // --- Convert Session to RequestInput ---
        let input = request_input_from_session(session, ctx.client_ip);

        // --- Evaluate the pure pipeline ---
        let outcome = evaluate_pipeline(
            &self.pipeline_config,
            &input,
            &self.identity_chain,
            self.policy_engine.as_ref(),
        )
        .await;

        // --- Translate PipelineOutcome to Pingora response ---
        let cors_hdrs = cors_headers(self.cors.as_ref(), ctx.cors_origin.as_deref());

        match outcome {
            PipelineOutcome::Health(body) | PipelineOutcome::Debug(body) => {
                let _ = send_json_response(session, 200, body.as_bytes(), &cors_hdrs).await;
                Ok(true)
            }
            PipelineOutcome::Reject { status, body } => {
                record_outcome_metrics(status);
                let _ = send_json_response(session, status, body.as_bytes(), &cors_hdrs).await;
                Ok(true)
            }
            PipelineOutcome::Forward {
                identity,
                flags,
                matched_route,
            } => {
                if identity.is_some() {
                    AUTH_OUTCOMES.with_label_values(&["success"]).inc();
                }
                if matched_route.is_some() {
                    POLICY_DECISIONS.with_label_values(&["allow"]).inc();
                }
                ctx.identity = identity;
                ctx.flags = flags;
                ctx.matched_route = matched_route.map(|r| *r);
                Ok(false)
            }
        }
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
            let signing_ref = self.signing.as_ref().map(|(key, id)| (key, id));
            let trace_id = uuid::Uuid::now_v7().to_string();
            let now = Timestamp::from_system_time(std::time::SystemTime::now());
            let headers = inject_signed_headers(&projection, signing_ref, &trace_id, now);
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

/// Record metrics based on the reject status code.
fn record_outcome_metrics(status: u16) {
    match status {
        401 => AUTH_OUTCOMES.with_label_values(&["rejected"]).inc(),
        403 => POLICY_DECISIONS.with_label_values(&["deny"]).inc(),
        _ => {}
    }
}

/// Build a [`RequestInput`] from a Pingora `Session`.
///
/// Extracts method, path, query string, lowercased headers, and client IP.
/// The caller supplies the already-resolved `client_ip` so we avoid re-extracting it.
fn request_input_from_session(session: &Session, client_ip: Option<IpAddr>) -> RequestInput {
    let req = session.downstream_session.req_header();
    let method = req.method.as_str();
    let path = req.uri.path();
    let query_string = req.uri.query();

    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // method and path come from a valid HTTP request so this should not fail.
    let mut input = match RequestInput::new(method, path, headers, client_ip) {
        Ok(input) => input,
        Err(e) => {
            tracing::error!(error = %e, "failed to build RequestInput from session");
            // Fall back to a minimal valid input so the pipeline can reject it.
            #[allow(clippy::expect_used)]
            RequestInput::new("GET", "/", vec![], None)
                .expect("fallback RequestInput must be valid")
        }
    };

    if let Some(qs) = query_string {
        input = input.with_query_string(qs);
    }

    input
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
