#![deny(clippy::unwrap_used, clippy::expect_used)]

mod cli;
mod proxy;

use std::sync::Arc;

use clap::Parser;
use pingora_core::server::Server;
use tracing_subscriber::EnvFilter;

use forgeguard_authn_core::IdentityChain;
use forgeguard_authz::VpEngineConfig;
use forgeguard_authz::VpPolicyEngine;
use forgeguard_http::{
    apply_overrides, load_config, ConfigOverrides, PublicRouteMatcher, RouteMatcher,
};

use crate::cli::{App, Commands};
use crate::proxy::{ForgeGuardProxy, ProxyParams};

fn main() {
    let app = App::parse();

    let fallback = if app.verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(fallback));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(e) = run(app) {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

fn run(app: App) -> color_eyre::Result<()> {
    color_eyre::install()?;

    let Commands::Run(opts) = app.command;

    let config = load_config(&opts.config)
        .map_err(|e| color_eyre::eyre::eyre!("failed to load config: {e}"))?;

    let mut overrides = ConfigOverrides::new();
    if let Some(addr) = opts.listen {
        overrides = overrides.with_listen_addr(addr);
    }
    if let Some(url) = opts.upstream {
        overrides = overrides.with_upstream_url(url);
    }
    if let Some(policy) = opts.default_policy {
        overrides = overrides.with_default_policy(policy);
    }
    let config = apply_overrides(config, &overrides);

    tracing::info!(
        listen = %config.listen_addr(),
        upstream = %config.upstream_url(),
        project = %config.project_id(),
        flags = config.features().flags.len(),
        "starting forgeguard-proxy"
    );

    if opts.debug {
        tracing::warn!("debug mode enabled — flag debug endpoint is accessible");
    }

    let identity_chain = build_identity_chain(&config)?;
    let policy_engine = build_policy_engine(&config)?;

    let route_matcher = RouteMatcher::new(config.routes())
        .map_err(|e| color_eyre::eyre::eyre!("invalid routes: {e}"))?;
    let public_matcher = PublicRouteMatcher::new(config.public_routes())
        .map_err(|e| color_eyre::eyre::eyre!("invalid public routes: {e}"))?;

    let upstream_url = config.upstream_url();
    let tls = upstream_url.scheme() == "https";
    let host = upstream_url.host_str().unwrap_or("localhost");
    let port = upstream_url
        .port_or_known_default()
        .unwrap_or(if tls { 443 } else { 80 });

    let proxy = ForgeGuardProxy::new(ProxyParams {
        identity_chain,
        policy_engine,
        route_matcher,
        public_matcher,
        flag_config: config.features().clone(),
        upstream_addr: format!("{host}:{port}"),
        upstream_tls: tls,
        upstream_sni: host.to_string(),
        default_policy: config.default_policy(),
        client_ip_source: config.client_ip_source(),
        project_id: config.project_id().clone(),
        auth_providers: config.auth().chain_order().to_vec(),
        debug_mode: opts.debug,
    });

    let mut server =
        Server::new(None).map_err(|e| color_eyre::eyre::eyre!("failed to create server: {e}"))?;
    server.bootstrap();

    let listen_addr = config.listen_addr().to_string();
    let mut service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen_addr);

    server.add_service(service);
    server.run_forever();
}

fn build_identity_chain(
    config: &forgeguard_http::ProxyConfig,
) -> color_eyre::Result<IdentityChain> {
    let resolvers: Vec<Arc<dyn forgeguard_authn_core::IdentityResolver>> = Vec::new();

    for provider in config.auth().chain_order() {
        match provider.as_str() {
            "jwt" => {
                tracing::warn!(
                    "JWT resolver requires JWKS URL — skipping until auth config is extended"
                );
            }
            "api-key" => {
                tracing::warn!("API key resolver not yet configured — skipping");
            }
            other => {
                tracing::warn!(provider = other, "unknown auth provider — skipping");
            }
        }
    }

    Ok(IdentityChain::new(resolvers))
}

fn build_policy_engine(
    config: &forgeguard_http::ProxyConfig,
) -> color_eyre::Result<Arc<dyn forgeguard_authz_core::PolicyEngine>> {
    if let Some(authz) = config.authz() {
        let rt = tokio::runtime::Runtime::new()?;
        let aws_config = rt.block_on(
            aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new(authz.aws_region().to_string()))
                .load(),
        );
        let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

        let engine_config = VpEngineConfig::new(authz.policy_store_id())
            .with_cache_ttl(authz.cache_ttl())
            .with_cache_max_entries(authz.cache_max_entries());

        let project_id = config.project_id().clone();
        let tenant_id = forgeguard_core::TenantId::new("default")
            .map_err(|e| color_eyre::eyre::eyre!("invalid default tenant: {e}"))?;

        let engine = VpPolicyEngine::new(vp_client, &engine_config, project_id, tenant_id);
        Ok(Arc::new(engine))
    } else {
        Ok(Arc::new(AllowAllEngine))
    }
}

/// Fallback policy engine that allows all requests when no authz is configured.
struct AllowAllEngine;

impl forgeguard_authz_core::PolicyEngine for AllowAllEngine {
    fn evaluate(
        &self,
        _query: &forgeguard_authz_core::PolicyQuery,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = forgeguard_authz_core::Result<forgeguard_authz_core::PolicyDecision>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { Ok(forgeguard_authz_core::PolicyDecision::Allow) })
    }
}
