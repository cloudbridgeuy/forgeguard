#![deny(clippy::unwrap_used, clippy::expect_used)]

mod cli;
mod proxy;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use pingora_core::server::Server;
use tracing_subscriber::EnvFilter;

use forgeguard_authn_core::signing::SigningKey;
use forgeguard_authn_core::IdentityChain;
use forgeguard_authz::VpEngineConfig;
use forgeguard_authz::VpPolicyEngine;
use forgeguard_http::{
    apply_overrides, load_config, ConfigOverrides, PublicRouteMatcher, RouteMatcher,
};
use forgeguard_proxy_core::{PipelineConfig, PipelineConfigParams};

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
    let config = apply_overrides(config, &overrides)
        .map_err(|e| color_eyre::eyre::eyre!("failed to apply config overrides: {e}"))?;

    tracing::info!(
        listen = %config.listen_addr(),
        upstream = %config.upstream_url(),
        project = %config.project_id(),
        flags = config.features().flags.len(),
        providers = ?config.auth().chain_order(),
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

    let target = config.upstream_target().clone();

    match std::net::ToSocketAddrs::to_socket_addrs(&target.addr()) {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                    Ok(_) => tracing::info!(upstream = %target.addr(), "upstream is reachable"),
                    Err(e) => tracing::warn!(
                        upstream = %target.addr(),
                        error = %e,
                        "upstream is not reachable — requests will fail until it starts"
                    ),
                }
            }
        }
        Err(e) => tracing::warn!(
            upstream = %target.addr(),
            error = %e,
            "could not resolve upstream address — skipping probe"
        ),
    }

    let pipeline_config = PipelineConfig::new(PipelineConfigParams {
        route_matcher,
        public_route_matcher: public_matcher,
        flag_config: config.features().clone(),
        project_id: config.project_id().clone(),
        default_policy: config.default_policy(),
        debug_mode: opts.debug,
        auth_providers: config.auth().chain_order().to_vec(),
        membership_resolver: None,
    });

    let signing = if let Some(signing_config) = config.signing() {
        let pem = std::fs::read_to_string(signing_config.key_path()).map_err(|e| {
            color_eyre::eyre::eyre!(
                "failed to read signing key at '{}': {e}",
                signing_config.key_path().display()
            )
        })?;
        let key = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| color_eyre::eyre::eyre!("invalid signing key: {e}"))?;
        tracing::info!(key_id = %signing_config.key_id(), "request signing enabled");
        Some((key, signing_config.key_id().clone()))
    } else {
        None
    };

    let proxy = ForgeGuardProxy::new(ProxyParams {
        pipeline_config,
        identity_chain,
        policy_engine,
        upstream: target,
        client_ip_source: config.client_ip_source(),
        cors: config.cors().cloned(),
        signing,
    });

    let mut server =
        Server::new(None).map_err(|e| color_eyre::eyre::eyre!("failed to create server: {e}"))?;
    if let Some(conf) = Arc::get_mut(&mut server.configuration) {
        conf.grace_period_seconds = Some(3);
        conf.graceful_shutdown_timeout_seconds = Some(5);
    }
    server.bootstrap();

    let listen_addr = config.listen_addr().to_string();
    let mut service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&listen_addr);

    server.add_service(service);

    if config.metrics().enabled() {
        if let Some(addr) = config.metrics().listen_addr() {
            let mut prom_service =
                pingora_core::services::listening::Service::prometheus_http_service();
            prom_service.add_tcp(&addr.to_string());
            server.add_service(prom_service);
            tracing::info!(listen = %addr, "prometheus metrics endpoint enabled");
        }
    }

    server.run_forever();
}

fn build_identity_chain(
    config: &forgeguard_http::ProxyConfig,
) -> color_eyre::Result<IdentityChain> {
    let mut resolvers: Vec<Arc<dyn forgeguard_authn_core::IdentityResolver>> = Vec::new();

    for provider in config.auth().chain_order() {
        match provider.as_str() {
            "jwt" => {
                let Some(jwt) = config.jwt_config() else {
                    tracing::warn!(
                        "JWT listed in auth.chain_order but no [authn.jwt] config found — skipping"
                    );
                    continue;
                };
                let mut resolver_config =
                    forgeguard_authn::JwtResolverConfig::new(jwt.jwks_url().clone(), jwt.issuer());
                if let Some(aud) = jwt.audience() {
                    resolver_config = resolver_config.with_audience(aud);
                }
                if let Some(claim) = jwt.user_id_claim() {
                    resolver_config = resolver_config.with_user_id_claim(claim);
                }
                if let Some(ttl) = jwt.cache_ttl_secs() {
                    resolver_config = resolver_config.with_cache_ttl(Duration::from_secs(ttl));
                }

                let resolver = forgeguard_authn::CognitoJwtResolver::new(resolver_config);
                tracing::info!("JWT resolver configured (issuer={})", jwt.issuer());
                resolvers.push(Arc::new(resolver));
            }
            "api-key" => {
                if config.api_keys().is_empty() {
                    tracing::warn!(
                        "api-key listed in auth.chain_order but no [[api_keys]] defined — skipping"
                    );
                    continue;
                }
                let keys = build_api_key_map(config.api_keys());
                let resolver = forgeguard_authn_core::StaticApiKeyResolver::new(keys);
                tracing::info!(
                    count = config.api_keys().len(),
                    "static API key resolver configured"
                );
                resolvers.push(Arc::new(resolver));
            }
            other => {
                tracing::warn!(provider = other, "unknown auth provider — skipping");
            }
        }
    }

    Ok(IdentityChain::new(resolvers))
}

fn build_api_key_map(
    entries: &[forgeguard_http::ApiKeyConfig],
) -> HashMap<String, forgeguard_authn_core::static_api_key::ApiKeyEntry> {
    entries
        .iter()
        .map(|entry| {
            let api_entry = forgeguard_authn_core::static_api_key::ApiKeyEntry::new(
                entry.user_id().clone(),
                entry.tenant_id().cloned(),
                entry.groups().to_vec(),
            );
            (entry.key().to_string(), api_entry)
        })
        .collect()
}

fn build_policy_engine(
    config: &forgeguard_http::ProxyConfig,
) -> color_eyre::Result<Arc<dyn forgeguard_authz_core::PolicyEngine>> {
    if let Some(authz) = config.authz() {
        let rt = tokio::runtime::Runtime::new()?;
        let mut aws_defaults = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = config.aws().region() {
            aws_defaults = aws_defaults.region(aws_config::Region::new(region.to_string()));
        }
        if let Some(profile) = config.aws().profile() {
            aws_defaults = aws_defaults.profile_name(profile);
        }
        let aws_config = rt.block_on(aws_defaults.load());
        let vp_client = aws_sdk_verifiedpermissions::Client::new(&aws_config);

        let engine_config = VpEngineConfig::new(authz.policy_store_id())
            .with_cache_ttl(authz.cache_ttl())
            .with_cache_max_entries(authz.cache_max_entries());

        // Build L1 cache
        let l1 = forgeguard_authz::AuthzCache::new(authz.cache_ttl(), authz.cache_max_entries());

        // Build optional L2 (Redis) cache
        let l2 = if let Some(cluster) = config.cluster() {
            match redis::Client::open(cluster.redis_url().as_str()) {
                Ok(client) => match rt.block_on(client.get_connection_manager()) {
                    Ok(conn) => {
                        tracing::info!(url = %cluster.redis_url(), "Redis L2 cache connected");
                        Some(conn)
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Redis L2 cache unavailable — starting with L1 only"
                        );
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "invalid Redis URL — starting with L1 only"
                    );
                    None
                }
            }
        } else {
            None
        };

        let cache = forgeguard_authz::TieredCache::new(l1, l2, authz.cache_ttl());

        let project_id = config.project_id().clone();
        let engine = VpPolicyEngine::new(vp_client, &engine_config, project_id, cache);
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
