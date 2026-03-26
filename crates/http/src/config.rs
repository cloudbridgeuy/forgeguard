//! Validated proxy configuration types.
//!
//! Two-phase Parse Don't Validate: raw TOML → `RawProxyConfig` → `ProxyConfig`.

use std::net::SocketAddr;
use std::time::Duration;

use forgeguard_core::{FlagConfig, FlagName, GroupDefinition, Policy, ProjectId, QualifiedAction};
use url::Url;

use crate::config_raw::RawProxyConfig;
use crate::method::HttpMethod;
use crate::public::{PublicAuthMode, PublicRoute};
use crate::route::RouteMapping;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// DefaultPolicy
// ---------------------------------------------------------------------------

/// What happens when no route matches a request.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DefaultPolicy {
    /// Allow the request to pass through to upstream.
    Passthrough,
    /// Deny the request.
    Deny,
}

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
// AuthzConfig
// ---------------------------------------------------------------------------

/// Authorization engine configuration.
#[derive(Debug, Clone)]
pub struct AuthzConfig {
    policy_store_id: String,
    aws_region: String,
    cache_ttl: Duration,
    cache_max_entries: usize,
}

impl AuthzConfig {
    /// The Verified Permissions policy store ID.
    pub fn policy_store_id(&self) -> &str {
        &self.policy_store_id
    }

    /// The AWS region for Verified Permissions.
    pub fn aws_region(&self) -> &str {
        &self.aws_region
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
    default_policy: DefaultPolicy,
    client_ip_source: ClientIpSource,
    auth: AuthConfig,
    authz: Option<AuthzConfig>,
    metrics: MetricsConfig,
    routes: Vec<RouteMapping>,
    public_routes: Vec<PublicRoute>,
    policies: Vec<Policy>,
    groups: Vec<GroupDefinition>,
    features: FlagConfig,
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
    pub fn default_policy(&self) -> DefaultPolicy {
        self.default_policy
    }
    pub fn client_ip_source(&self) -> ClientIpSource {
        self.client_ip_source
    }
    pub fn auth(&self) -> &AuthConfig {
        &self.auth
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
pub fn apply_overrides(mut config: ProxyConfig, overrides: &ConfigOverrides) -> ProxyConfig {
    if let Some(addr) = overrides.listen_addr {
        config.listen_addr = addr;
    }
    if let Some(ref url) = overrides.upstream_url {
        config.upstream_url = url.clone();
    }
    if let Some(policy) = overrides.default_policy {
        config.default_policy = policy;
    }
    config
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

        let default_policy = parse_default_policy(&raw.default_policy)?;
        let client_ip_source = parse_client_ip_source(&raw.client_ip_source)?;

        let auth = raw
            .auth
            .map(|a| AuthConfig {
                chain_order: a.chain_order,
            })
            .unwrap_or_default();

        let authz = raw.authz.map(|a| {
            let ttl = Duration::from_secs(a.cache_ttl_secs);
            AuthzConfig {
                policy_store_id: a.policy_store_id.unwrap_or_default(),
                aws_region: a.aws_region.unwrap_or_default(),
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

        Ok(ProxyConfig {
            project_id,
            listen_addr,
            upstream_url,
            default_policy,
            client_ip_source,
            auth,
            authz,
            metrics,
            routes,
            public_routes,
            policies,
            groups,
            features,
        })
    }
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const MINIMAL_TOML: &str = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#;

    const FULL_TOML: &str = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
default_policy = "passthrough"
client_ip_source = "x-forwarded-for"

[auth]
chain_order = ["jwt", "api-key"]

[authz]
policy_store_id = "ps-123"
aws_region = "us-east-1"
cache_ttl_secs = 600
cache_max_entries = 5000

[metrics]
enabled = true
listen_addr = "127.0.0.1:9090"

[[routes]]
method = "GET"
path = "/users"
action = "todo:list:user"

[[routes]]
method = "GET"
path = "/users/{id}"
action = "todo:read:user"
resource_param = "id"

[[public_routes]]
method = "GET"
path = "/health"
auth_mode = "anonymous"
"#;

    #[test]
    fn parse_minimal_config() {
        let config = parse_config(MINIMAL_TOML).unwrap();
        assert_eq!(config.project_id().as_str(), "my-app");
        assert_eq!(config.listen_addr().to_string(), "127.0.0.1:8080");
        assert_eq!(config.upstream_url().as_str(), "http://localhost:3000/");
        assert_eq!(config.default_policy(), DefaultPolicy::Deny);
        assert_eq!(config.client_ip_source(), ClientIpSource::Peer);
        assert!(config.routes().is_empty());
        assert!(config.public_routes().is_empty());
    }

    #[test]
    fn parse_full_config() {
        let config = parse_config(FULL_TOML).unwrap();
        assert_eq!(config.default_policy(), DefaultPolicy::Passthrough);
        assert_eq!(config.client_ip_source(), ClientIpSource::XForwardedFor);
        assert_eq!(config.routes().len(), 2);
        assert_eq!(config.public_routes().len(), 1);

        let authz = config.authz().unwrap();
        assert_eq!(authz.policy_store_id(), "ps-123");
        assert_eq!(authz.aws_region(), "us-east-1");
        assert_eq!(authz.cache_ttl(), Duration::from_secs(600));
        assert_eq!(authz.cache_max_entries(), 5000);

        let metrics = config.metrics();
        assert!(metrics.enabled());
        assert_eq!(metrics.listen_addr().unwrap().to_string(), "127.0.0.1:9090");

        let auth = config.auth();
        assert_eq!(auth.chain_order(), &["jwt", "api-key"]);
    }

    #[test]
    fn missing_project_id_errors() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#;
        assert!(parse_config(toml).is_err());
    }

    #[test]
    fn invalid_listen_addr_errors() {
        let toml = r#"
project_id = "my-app"
listen_addr = "not-an-addr"
upstream_url = "http://localhost:3000"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("listen_addr"));
    }

    #[test]
    fn invalid_upstream_url_errors() {
        let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "not a url"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("upstream_url"));
    }

    #[test]
    fn invalid_default_policy_errors() {
        let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
default_policy = "yolo"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("default_policy"));
    }

    #[test]
    fn invalid_route_action_errors() {
        let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/users"
action = "bad-action"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("routes[0].action"));
    }

    #[test]
    fn apply_overrides_changes_listen_addr() {
        let config = parse_config(MINIMAL_TOML).unwrap();
        let overrides = ConfigOverrides::new().with_listen_addr("0.0.0.0:9999".parse().unwrap());
        let config = apply_overrides(config, &overrides);
        assert_eq!(config.listen_addr().to_string(), "0.0.0.0:9999");
    }

    #[test]
    fn apply_overrides_changes_default_policy() {
        let config = parse_config(MINIMAL_TOML).unwrap();
        assert_eq!(config.default_policy(), DefaultPolicy::Deny);
        let overrides = ConfigOverrides::new().with_default_policy(DefaultPolicy::Passthrough);
        let config = apply_overrides(config, &overrides);
        assert_eq!(config.default_policy(), DefaultPolicy::Passthrough);
    }

    #[test]
    fn apply_overrides_no_change_when_empty() {
        let config = parse_config(MINIMAL_TOML).unwrap();
        let addr_before = config.listen_addr();
        let config = apply_overrides(config, &ConfigOverrides::new());
        assert_eq!(config.listen_addr(), addr_before);
    }

    #[test]
    fn parse_route_with_feature_gate() {
        let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/beta"
action = "todo:read:beta"
feature_gate = "beta-feature"
"#;
        let config = parse_config(toml).unwrap();
        let route = &config.routes()[0];
        assert!(route.feature_gate().is_some());
        assert_eq!(route.feature_gate().unwrap().to_string(), "beta-feature");
    }

    #[test]
    fn parse_client_ip_source_variants() {
        assert_eq!(
            parse_client_ip_source("peer").unwrap(),
            ClientIpSource::Peer
        );
        assert_eq!(
            parse_client_ip_source("x-forwarded-for").unwrap(),
            ClientIpSource::XForwardedFor
        );
        assert_eq!(
            parse_client_ip_source("cf-connecting-ip").unwrap(),
            ClientIpSource::CfConnectingIp
        );
        assert!(parse_client_ip_source("unknown").is_err());
    }
}
