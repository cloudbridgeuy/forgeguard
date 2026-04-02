//! Validated proxy configuration types.
//!
//! Two-phase Parse Don't Validate: raw TOML → `RawProxyConfig` → `ProxyConfig`.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use forgeguard_core::{
    CedarEntityRef, DefaultPolicy, FlagConfig, FlagName, GroupDefinition, GroupName, Policy,
    ProjectId, QualifiedAction,
};

use url::Url;

use crate::config_raw::RawProxyConfig;
use crate::config_types::{
    AwsConfig, EntitySchema, PolicyTest, PolicyTestExpect, PolicyTestParams, SchemaConfig,
};
use crate::method::HttpMethod;
use crate::public::{PublicAuthMode, PublicRoute};
use crate::route::RouteMapping;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// ClientIpSource
// ---------------------------------------------------------------------------

/// Where to read the client IP address from.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ClientIpSource {
    /// The TCP peer address.
    Peer,
    /// The `X-Forwarded-For` header.
    XForwardedFor,
    /// The `CF-Connecting-IP` header (Cloudflare).
    CfConnectingIp,
}

// ---------------------------------------------------------------------------
// UpstreamTarget
// ---------------------------------------------------------------------------

/// Pre-validated upstream connection target derived from `upstream_url`.
///
/// Computed once during config validation (Parse Don't Validate).
/// The proxy shell consumes this directly — no re-parsing of host:port strings.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpstreamTarget {
    addr: String,
    tls: bool,
    sni: String,
}

impl UpstreamTarget {
    /// The `host:port` address string for Pingora's `HttpPeer`.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Whether the upstream connection should use TLS.
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// The SNI hostname for TLS connections.
    pub fn sni(&self) -> &str {
        &self.sni
    }
}

/// Derive an [`UpstreamTarget`] from a validated [`Url`].
///
/// Pure function — no I/O. Extracts host, port (with scheme-based defaults),
/// and TLS flag from the URL.
fn derive_upstream_target(url: &Url) -> Result<UpstreamTarget> {
    let tls = url.scheme() == "https";
    let host = url
        .host_str()
        .ok_or_else(|| Error::Config(format!("upstream_url '{}': missing host", url)))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::Config(format!("upstream_url '{}': cannot determine port", url)))?;

    Ok(UpstreamTarget {
        addr: format!("{host}:{port}"),
        tls,
        sni: host.to_string(),
    })
}

// ---------------------------------------------------------------------------
// AuthConfig
// ---------------------------------------------------------------------------

/// Authentication chain configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    chain_order: Vec<String>,
}

impl AuthConfig {
    /// The ordered list of auth providers to try.
    pub fn chain_order(&self) -> &[String] {
        &self.chain_order
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            chain_order: vec!["jwt".to_string(), "api-key".to_string()],
        }
    }
}

// ---------------------------------------------------------------------------
// JwtConfig
// ---------------------------------------------------------------------------

/// Validated JWT resolver configuration.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    jwks_url: Url,
    issuer: String,
    audience: Option<String>,
    user_id_claim: Option<String>,
    tenant_claim: Option<String>,
    groups_claim: Option<String>,
    cache_ttl_secs: Option<u64>,
}

impl JwtConfig {
    /// The JWKS endpoint URL.
    pub fn jwks_url(&self) -> &Url {
        &self.jwks_url
    }
    /// The expected token issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// The expected audience claim.
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }
    /// Claim to extract the user ID from.
    pub fn user_id_claim(&self) -> Option<&str> {
        self.user_id_claim.as_deref()
    }
    /// Claim to extract the tenant ID from.
    pub fn tenant_claim(&self) -> Option<&str> {
        self.tenant_claim.as_deref()
    }
    /// Claim to extract group memberships from.
    pub fn groups_claim(&self) -> Option<&str> {
        self.groups_claim.as_deref()
    }
    /// JWKS cache TTL in seconds.
    pub fn cache_ttl_secs(&self) -> Option<u64> {
        self.cache_ttl_secs
    }
}

// ---------------------------------------------------------------------------
// ApiKeyConfig
// ---------------------------------------------------------------------------

/// Validated static API key configuration.
#[derive(Clone)]
pub struct ApiKeyConfig {
    key: String,
    user_id: forgeguard_core::UserId,
    tenant_id: Option<forgeguard_core::TenantId>,
    groups: Vec<GroupName>,
}

impl fmt::Debug for ApiKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyConfig")
            .field("key", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("tenant_id", &self.tenant_id)
            .field("groups", &self.groups)
            .finish()
    }
}

impl ApiKeyConfig {
    /// The API key string.
    pub fn key(&self) -> &str {
        &self.key
    }
    /// The user identity this key maps to.
    pub fn user_id(&self) -> &forgeguard_core::UserId {
        &self.user_id
    }
    /// The tenant this key belongs to (if any).
    pub fn tenant_id(&self) -> Option<&forgeguard_core::TenantId> {
        self.tenant_id.as_ref()
    }
    /// The groups this key grants.
    pub fn groups(&self) -> &[GroupName] {
        &self.groups
    }
}

// ---------------------------------------------------------------------------
// AuthzConfig
// ---------------------------------------------------------------------------

/// Authorization engine configuration.
#[derive(Debug, Clone)]
pub struct AuthzConfig {
    policy_store_id: String,
    cache_ttl: Duration,
    cache_max_entries: usize,
}

impl AuthzConfig {
    /// The Verified Permissions policy store ID.
    pub fn policy_store_id(&self) -> &str {
        &self.policy_store_id
    }

    /// TTL for cached authorization decisions.
    pub fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    /// Maximum number of cached entries.
    pub fn cache_max_entries(&self) -> usize {
        self.cache_max_entries
    }
}

// ---------------------------------------------------------------------------
// MetricsConfig
// ---------------------------------------------------------------------------

/// Metrics endpoint configuration.
#[derive(Debug, Clone, Default)]
pub struct MetricsConfig {
    enabled: bool,
    listen_addr: Option<SocketAddr>,
}

impl MetricsConfig {
    /// Whether metrics are enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The address to serve metrics on.
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }
}

// ---------------------------------------------------------------------------
// ClusterConfig
// ---------------------------------------------------------------------------

/// Validated cluster configuration for Redis-backed coordination.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    redis_url: url::Url,
    instance_id: String,
    priority: u8,
    heartbeat_interval: Duration,
    min_quorum: usize,
    listen_cluster_addr: Option<SocketAddr>,
}

impl ClusterConfig {
    /// The Redis URL for cluster coordination.
    pub fn redis_url(&self) -> &url::Url {
        &self.redis_url
    }

    /// The unique instance identifier.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// The priority of this instance in the cluster.
    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// The interval between heartbeats.
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// The minimum number of nodes required for quorum.
    pub fn min_quorum(&self) -> usize {
        self.min_quorum
    }

    /// The address this instance listens on for cluster traffic.
    pub fn listen_cluster_addr(&self) -> Option<SocketAddr> {
        self.listen_cluster_addr
    }
}

// ---------------------------------------------------------------------------
// SigningConfig
// ---------------------------------------------------------------------------

/// Validated request signing configuration.
pub struct SigningConfig {
    key_path: std::path::PathBuf,
    key_id: forgeguard_authn_core::signing::KeyId,
}

impl SigningConfig {
    /// Path to the Ed25519 private key (PKCS#8 PEM).
    pub fn key_path(&self) -> &std::path::Path {
        &self.key_path
    }

    /// The key identifier injected into `X-ForgeGuard-Key-Id`.
    pub fn key_id(&self) -> &forgeguard_authn_core::signing::KeyId {
        &self.key_id
    }
}

impl fmt::Debug for SigningConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningConfig")
            .field("key_path", &self.key_path)
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl Clone for SigningConfig {
    fn clone(&self) -> Self {
        Self {
            key_path: self.key_path.clone(),
            key_id: self.key_id.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// ProxyConfig
// ---------------------------------------------------------------------------

/// Fully validated proxy configuration.
///
/// All fields are private. Use getters to access. Immutable after construction.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    project_id: ProjectId,
    listen_addr: SocketAddr,
    upstream_url: Url,
    upstream_target: UpstreamTarget,
    default_policy: DefaultPolicy,
    client_ip_source: ClientIpSource,
    auth: AuthConfig,
    jwt_config: Option<JwtConfig>,
    api_keys: Vec<ApiKeyConfig>,
    authz: Option<AuthzConfig>,
    metrics: MetricsConfig,
    routes: Vec<RouteMapping>,
    public_routes: Vec<PublicRoute>,
    policies: Vec<Policy>,
    groups: Vec<GroupDefinition>,
    features: FlagConfig,
    aws: AwsConfig,
    schema: SchemaConfig,
    policy_tests: Vec<PolicyTest>,
    cors: Option<crate::cors::CorsConfig>,
    cluster: Option<ClusterConfig>,
    signing: Option<SigningConfig>,
}

impl ProxyConfig {
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
    pub fn upstream_url(&self) -> &Url {
        &self.upstream_url
    }
    pub fn upstream_target(&self) -> &UpstreamTarget {
        &self.upstream_target
    }
    pub fn default_policy(&self) -> DefaultPolicy {
        self.default_policy
    }
    pub fn client_ip_source(&self) -> ClientIpSource {
        self.client_ip_source
    }
    pub fn auth(&self) -> &AuthConfig {
        &self.auth
    }
    pub fn jwt_config(&self) -> Option<&JwtConfig> {
        self.jwt_config.as_ref()
    }
    pub fn api_keys(&self) -> &[ApiKeyConfig] {
        &self.api_keys
    }
    pub fn authz(&self) -> Option<&AuthzConfig> {
        self.authz.as_ref()
    }
    pub fn metrics(&self) -> &MetricsConfig {
        &self.metrics
    }
    pub fn routes(&self) -> &[RouteMapping] {
        &self.routes
    }
    pub fn public_routes(&self) -> &[PublicRoute] {
        &self.public_routes
    }
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }
    pub fn groups(&self) -> &[GroupDefinition] {
        &self.groups
    }
    pub fn features(&self) -> &FlagConfig {
        &self.features
    }
    pub fn aws(&self) -> &AwsConfig {
        &self.aws
    }
    pub fn schema(&self) -> &SchemaConfig {
        &self.schema
    }
    pub fn policy_tests(&self) -> &[PolicyTest] {
        &self.policy_tests
    }
    pub fn cors(&self) -> Option<&crate::cors::CorsConfig> {
        self.cors.as_ref()
    }
    /// The cluster configuration, if present.
    pub fn cluster(&self) -> Option<&ClusterConfig> {
        self.cluster.as_ref()
    }
    /// The request signing configuration, if present.
    pub fn signing(&self) -> Option<&SigningConfig> {
        self.signing.as_ref()
    }
}

// ---------------------------------------------------------------------------
// ConfigOverrides
// ---------------------------------------------------------------------------

/// Override values from CLI flags or environment variables.
#[derive(Debug, Default)]
pub struct ConfigOverrides {
    listen_addr: Option<SocketAddr>,
    upstream_url: Option<Url>,
    default_policy: Option<DefaultPolicy>,
}

impl ConfigOverrides {
    /// Create empty overrides.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the listen address.
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }

    /// Override the upstream URL.
    pub fn with_upstream_url(mut self, url: Url) -> Self {
        self.upstream_url = Some(url);
        self
    }

    /// Override the default policy.
    pub fn with_default_policy(mut self, policy: DefaultPolicy) -> Self {
        self.default_policy = Some(policy);
        self
    }
}

/// Apply overrides to a config (pure function).
///
/// Precedence: CLI flags / env vars > config file > defaults.
pub fn apply_overrides(
    mut config: ProxyConfig,
    overrides: &ConfigOverrides,
) -> Result<ProxyConfig> {
    if let Some(addr) = overrides.listen_addr {
        config.listen_addr = addr;
    }
    if let Some(ref url) = overrides.upstream_url {
        config.upstream_url = url.clone();
        config.upstream_target = derive_upstream_target(url)?;
    }
    if let Some(policy) = overrides.default_policy {
        config.default_policy = policy;
    }
    Ok(config)
}

// ---------------------------------------------------------------------------
// TryFrom<RawProxyConfig> for ProxyConfig
// ---------------------------------------------------------------------------

impl TryFrom<RawProxyConfig> for ProxyConfig {
    type Error = Error;

    fn try_from(raw: RawProxyConfig) -> Result<Self> {
        let project_id = ProjectId::new(&raw.project_id)
            .map_err(|e| Error::Config(format!("invalid project_id: {e}")))?;

        let listen_addr: SocketAddr = raw.listen_addr.parse().map_err(|e| {
            Error::Config(format!("invalid listen_addr '{}': {e}", raw.listen_addr))
        })?;

        let upstream_url = Url::parse(&raw.upstream_url).map_err(|e| {
            Error::Config(format!("invalid upstream_url '{}': {e}", raw.upstream_url))
        })?;
        let upstream_target = derive_upstream_target(&upstream_url)?;

        let default_policy = parse_default_policy(&raw.default_policy)?;
        let client_ip_source = parse_client_ip_source(&raw.client_ip_source)?;

        let auth = raw
            .auth
            .map(|a| AuthConfig {
                chain_order: a.chain_order,
            })
            .unwrap_or_default();

        let jwt_config = raw
            .authn
            .and_then(|a| a.jwt)
            .map(parse_jwt_config)
            .transpose()?;

        let api_keys = raw
            .api_keys
            .into_iter()
            .enumerate()
            .map(|(i, entry)| parse_api_key(i, entry))
            .collect::<Result<Vec<_>>>()?;

        let authz = raw.authz.map(|a| {
            let ttl = Duration::from_secs(a.cache_ttl_secs);
            AuthzConfig {
                policy_store_id: a.policy_store_id.unwrap_or_default(),
                cache_ttl: ttl,
                cache_max_entries: a.cache_max_entries,
            }
        });

        let metrics = raw
            .metrics
            .map(|m| {
                let addr = m
                    .listen_addr
                    .as_deref()
                    .map(|s| {
                        s.parse::<SocketAddr>()
                            .map_err(|e| Error::Config(format!("invalid metrics.listen_addr: {e}")))
                    })
                    .transpose()?;
                Ok::<_, Error>(MetricsConfig {
                    enabled: m.enabled,
                    listen_addr: addr,
                })
            })
            .transpose()?
            .unwrap_or_default();

        let routes = raw
            .routes
            .into_iter()
            .enumerate()
            .map(|(i, r)| parse_route_mapping(i, r))
            .collect::<Result<Vec<_>>>()?;

        let public_routes = raw
            .public_routes
            .into_iter()
            .enumerate()
            .map(|(i, r)| parse_public_route(i, r))
            .collect::<Result<Vec<_>>>()?;

        let policies = raw.policies;
        let groups = raw.groups;
        let features = raw
            .features
            .map(|f| FlagConfig { flags: f.flags })
            .unwrap_or_default();

        let aws = raw
            .aws
            .map(|a| AwsConfig::new(a.region, a.profile))
            .unwrap_or_default();

        let schema = raw
            .schema
            .map(|s| {
                let entities = s
                    .entities
                    .into_iter()
                    .map(|(ns, entity_map)| {
                        let validated = entity_map
                            .into_iter()
                            .map(|(name, raw_schema)| {
                                (
                                    name,
                                    EntitySchema::new(raw_schema.member_of, raw_schema.attributes),
                                )
                            })
                            .collect();
                        (ns, validated)
                    })
                    .collect();
                SchemaConfig::new(entities)
            })
            .unwrap_or_default();

        let policy_tests = raw
            .policy_tests
            .into_iter()
            .enumerate()
            .map(|(i, t)| parse_policy_test(i, t))
            .collect::<Result<Vec<_>>>()?;

        let cors = raw
            .cors
            .map(crate::cors::CorsConfig::try_from)
            .transpose()
            .map_err(Error::Validation)?;

        let cluster = raw.cluster.as_ref().map(parse_cluster_config).transpose()?;

        let signing = raw.signing.map(parse_signing_config).transpose()?;

        Ok(ProxyConfig {
            project_id,
            listen_addr,
            upstream_url,
            upstream_target,
            default_policy,
            client_ip_source,
            auth,
            jwt_config,
            api_keys,
            authz,
            metrics,
            routes,
            public_routes,
            policies,
            groups,
            features,
            aws,
            schema,
            policy_tests,
            cors,
            cluster,
            signing,
        })
    }
}

fn parse_signing_config(raw: crate::config_raw::RawSigningConfig) -> Result<SigningConfig> {
    let key_id = forgeguard_authn_core::signing::KeyId::try_from(raw.key_id)
        .map_err(|_| Error::Config("signing.key_id must be non-empty".to_string()))?;
    Ok(SigningConfig {
        key_path: std::path::PathBuf::from(raw.key_path),
        key_id,
    })
}

fn parse_cluster_config(raw: &crate::config_raw::RawClusterConfig) -> Result<ClusterConfig> {
    let redis_url: url::Url = raw.redis_url.parse().map_err(|e| {
        Error::Config(format!(
            "cluster.redis_url: invalid URL '{}': {e}",
            raw.redis_url
        ))
    })?;

    let listen_cluster_addr = raw
        .listen_cluster_addr
        .as_deref()
        .map(|s| {
            s.parse::<SocketAddr>().map_err(|e| {
                Error::Config(format!(
                    "cluster.listen_cluster_addr: invalid socket address '{s}': {e}"
                ))
            })
        })
        .transpose()?;

    Ok(ClusterConfig {
        redis_url,
        instance_id: raw.instance_id.clone(),
        priority: raw.priority,
        heartbeat_interval: Duration::from_secs(raw.heartbeat_interval_secs),
        min_quorum: raw.min_quorum,
        listen_cluster_addr,
    })
}

fn parse_jwt_config(raw: crate::config_raw::RawJwtConfig) -> Result<JwtConfig> {
    let jwks_url = Url::parse(&raw.jwks_url).map_err(|e| {
        Error::Config(format!(
            "authn.jwt.jwks_url: invalid URL '{}': {e}",
            raw.jwks_url
        ))
    })?;
    if raw.issuer.is_empty() {
        return Err(Error::Config("authn.jwt.issuer: must not be empty".into()));
    }
    Ok(JwtConfig {
        jwks_url,
        issuer: raw.issuer,
        audience: raw.audience,
        user_id_claim: raw.user_id_claim,
        tenant_claim: raw.tenant_claim,
        groups_claim: raw.groups_claim,
        cache_ttl_secs: raw.cache_ttl_secs,
    })
}

fn parse_api_key(index: usize, raw: crate::config_raw::RawApiKeyEntry) -> Result<ApiKeyConfig> {
    if raw.key.is_empty() {
        return Err(Error::Config(format!(
            "api_keys[{index}].key: must not be empty"
        )));
    }
    let user_id = forgeguard_core::UserId::new(&raw.user_id)
        .map_err(|e| Error::Config(format!("api_keys[{index}].user_id: {e}")))?;
    let tenant_id = raw
        .tenant_id
        .map(|t| forgeguard_core::TenantId::new(&t))
        .transpose()
        .map_err(|e| Error::Config(format!("api_keys[{index}].tenant_id: {e}")))?;
    let groups = raw
        .groups
        .into_iter()
        .enumerate()
        .map(|(gi, g)| {
            GroupName::new(&g)
                .map_err(|e| Error::Config(format!("api_keys[{index}].groups[{gi}]: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ApiKeyConfig {
        key: raw.key,
        user_id,
        tenant_id,
        groups,
    })
}

fn parse_default_policy(s: &str) -> Result<DefaultPolicy> {
    match s.to_ascii_lowercase().as_str() {
        "passthrough" => Ok(DefaultPolicy::Passthrough),
        "deny" => Ok(DefaultPolicy::Deny),
        _ => Err(Error::Config(format!(
            "invalid default_policy '{s}': expected 'passthrough' or 'deny'"
        ))),
    }
}

fn parse_client_ip_source(s: &str) -> Result<ClientIpSource> {
    match s.to_ascii_lowercase().as_str() {
        "peer" => Ok(ClientIpSource::Peer),
        "x-forwarded-for" | "xforwardedfor" => Ok(ClientIpSource::XForwardedFor),
        "cf-connecting-ip" | "cfconnectingip" => Ok(ClientIpSource::CfConnectingIp),
        _ => Err(Error::Config(format!(
            "invalid client_ip_source '{s}': expected 'peer', 'x-forwarded-for', or 'cf-connecting-ip'"
        ))),
    }
}

fn parse_route_mapping(
    index: usize,
    raw: crate::config_raw::RawRouteMapping,
) -> Result<RouteMapping> {
    let method: HttpMethod = raw.method.parse().map_err(|_| {
        Error::Config(format!(
            "routes[{index}].method: invalid method '{}'",
            raw.method
        ))
    })?;

    let action = QualifiedAction::parse(&raw.action)
        .map_err(|e| Error::Config(format!("routes[{index}].action: {e}")))?;

    let feature_gate = raw
        .feature_gate
        .map(|fg| FlagName::parse(&fg))
        .transpose()
        .map_err(|e| Error::Config(format!("routes[{index}].feature_gate: {e}")))?;

    Ok(RouteMapping::new(
        method,
        raw.path,
        action,
        raw.resource_param,
        feature_gate,
    ))
}

fn parse_public_route(index: usize, raw: crate::config_raw::RawPublicRoute) -> Result<PublicRoute> {
    let method: HttpMethod = raw.method.parse().map_err(|_| {
        Error::Config(format!(
            "public_routes[{index}].method: invalid method '{}'",
            raw.method
        ))
    })?;

    let auth_mode = match raw.auth_mode.to_ascii_lowercase().as_str() {
        "anonymous" => PublicAuthMode::Anonymous,
        "opportunistic" => PublicAuthMode::Opportunistic,
        _ => {
            return Err(Error::Config(format!(
                "public_routes[{index}].auth_mode: expected 'anonymous' or 'opportunistic', got '{}'",
                raw.auth_mode
            )));
        }
    };

    Ok(PublicRoute::new(method, raw.path, auth_mode))
}

fn parse_policy_test(index: usize, raw: crate::config_raw::RawPolicyTest) -> Result<PolicyTest> {
    let action = QualifiedAction::parse(&raw.action)
        .map_err(|e| Error::Config(format!("policy_tests[{index}].action: {e}")))?;

    let groups = raw
        .groups
        .into_iter()
        .enumerate()
        .map(|(gi, g)| {
            GroupName::new(&g)
                .map_err(|e| Error::Config(format!("policy_tests[{index}].groups[{gi}]: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;

    let resource = raw
        .resource
        .map(|r| {
            CedarEntityRef::parse(&r)
                .map_err(|e| Error::Config(format!("policy_tests[{index}].resource: {e}")))
        })
        .transpose()?;

    let expect = match raw.expect.to_ascii_lowercase().as_str() {
        "allow" => PolicyTestExpect::Allow,
        "deny" => PolicyTestExpect::Deny,
        _ => {
            return Err(Error::Config(format!(
                "policy_tests[{index}].expect: expected 'allow' or 'deny', got '{}'",
                raw.expect
            )));
        }
    };

    Ok(PolicyTest::new(PolicyTestParams {
        name: raw.name,
        principal: raw.principal,
        groups,
        tenant: raw.tenant,
        action,
        resource,
        expect,
    }))
}

/// Load a proxy config from a TOML file path.
///
/// This is the only I/O function in this crate.
pub fn load_config(path: &std::path::Path) -> Result<ProxyConfig> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!(
            "failed to read config file '{}': {e}",
            path.display()
        ))
    })?;
    parse_config(&contents)
}

/// Parse a proxy config from a TOML string (pure — for testing).
pub fn parse_config(toml_str: &str) -> Result<ProxyConfig> {
    let raw: RawProxyConfig =
        toml::from_str(toml_str).map_err(|e| Error::Config(format!("TOML parse error: {e}")))?;
    ProxyConfig::try_from(raw)
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
