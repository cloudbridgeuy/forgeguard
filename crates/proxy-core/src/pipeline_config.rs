//! Pipeline configuration — the immutable config consumed by the auth pipeline.

use forgeguard_core::{FlagConfig, ProjectId};
use forgeguard_http::{DefaultPolicy, PublicRouteMatcher, RouteMatcher};

// ---------------------------------------------------------------------------
// PipelineConfig
// ---------------------------------------------------------------------------

/// Immutable configuration for a single auth pipeline instance.
///
/// Constructed once at startup (or when config is reloaded) and shared across
/// all requests. Contains everything the pipeline needs to route-match,
/// evaluate flags, and make auth decisions — without any I/O dependencies.
pub struct PipelineConfig {
    route_matcher: RouteMatcher,
    public_route_matcher: PublicRouteMatcher,
    flag_config: FlagConfig,
    project_id: ProjectId,
    default_policy: DefaultPolicy,
    debug_mode: bool,
    auth_providers: Vec<String>,
}

/// Parameters for constructing a [`PipelineConfig`].
pub struct PipelineConfigParams {
    pub route_matcher: RouteMatcher,
    pub public_route_matcher: PublicRouteMatcher,
    pub flag_config: FlagConfig,
    pub project_id: ProjectId,
    pub default_policy: DefaultPolicy,
    pub debug_mode: bool,
    pub auth_providers: Vec<String>,
}

impl PipelineConfig {
    /// Construct a new `PipelineConfig` from its constituent parts.
    pub fn new(params: PipelineConfigParams) -> Self {
        Self {
            route_matcher: params.route_matcher,
            public_route_matcher: params.public_route_matcher,
            flag_config: params.flag_config,
            project_id: params.project_id,
            default_policy: params.default_policy,
            debug_mode: params.debug_mode,
            auth_providers: params.auth_providers,
        }
    }

    /// The route matcher for mapping `(method, path)` to actions.
    pub fn route_matcher(&self) -> &RouteMatcher {
        &self.route_matcher
    }

    /// The public route matcher for bypassing auth on configured paths.
    pub fn public_route_matcher(&self) -> &PublicRouteMatcher {
        &self.public_route_matcher
    }

    /// Feature flag configuration.
    pub fn flag_config(&self) -> &FlagConfig {
        &self.flag_config
    }

    /// The project ID for this pipeline.
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    /// What happens when no route matches a request.
    pub fn default_policy(&self) -> DefaultPolicy {
        self.default_policy
    }

    /// Whether debug mode is enabled (exposes debug endpoints).
    pub fn debug_mode(&self) -> bool {
        self.debug_mode
    }

    /// The configured auth provider names (e.g. `["jwt", "api-key"]`).
    pub fn auth_providers(&self) -> &[String] {
        &self.auth_providers
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_http::{PublicRoute, RouteMapping};

    use super::*;

    /// Build a minimal `PipelineConfig` for testing.
    fn make_config(debug_mode: bool, default_policy: DefaultPolicy) -> PipelineConfig {
        let route_matcher = RouteMatcher::new(&[]).unwrap();
        let public_route_matcher = PublicRouteMatcher::new(&[]).unwrap();
        let flag_config = FlagConfig::default();
        let project_id = ProjectId::new("test-project").unwrap();

        PipelineConfig::new(PipelineConfigParams {
            route_matcher,
            public_route_matcher,
            flag_config,
            project_id,
            default_policy,
            debug_mode,
            auth_providers: vec!["jwt".to_string()],
        })
    }

    #[test]
    fn accessors_return_correct_values() {
        let config = make_config(true, DefaultPolicy::Deny);
        assert_eq!(config.project_id().as_str(), "test-project");
        assert_eq!(config.default_policy(), DefaultPolicy::Deny);
        assert!(config.debug_mode());
        assert_eq!(config.auth_providers(), &["jwt"]);
    }

    #[test]
    fn default_policy_passthrough() {
        let config = make_config(false, DefaultPolicy::Passthrough);
        assert_eq!(config.default_policy(), DefaultPolicy::Passthrough);
        assert!(!config.debug_mode());
    }

    #[test]
    fn route_matcher_delegates_correctly() {
        let routes = vec![RouteMapping::new(
            "GET".parse().unwrap(),
            "/health".to_string(),
            forgeguard_core::QualifiedAction::parse("app:read:health").unwrap(),
            None,
            None,
        )];
        let route_matcher = RouteMatcher::new(&routes).unwrap();
        let public_route_matcher = PublicRouteMatcher::new(&[]).unwrap();
        let config = PipelineConfig::new(PipelineConfigParams {
            route_matcher,
            public_route_matcher,
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test-project").unwrap(),
            default_policy: DefaultPolicy::Deny,
            debug_mode: false,
            auth_providers: vec![],
        });

        let matched = config.route_matcher().match_request("GET", "/health");
        assert!(matched.is_some());
    }

    #[test]
    fn public_route_matcher_delegates_correctly() {
        use forgeguard_http::PublicAuthMode;

        let public_routes = vec![PublicRoute::new(
            "GET".parse().unwrap(),
            "/public".to_string(),
            PublicAuthMode::Anonymous,
        )];
        let route_matcher = RouteMatcher::new(&[]).unwrap();
        let public_route_matcher = PublicRouteMatcher::new(&public_routes).unwrap();
        let config = PipelineConfig::new(PipelineConfigParams {
            route_matcher,
            public_route_matcher,
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test-project").unwrap(),
            default_policy: DefaultPolicy::Deny,
            debug_mode: false,
            auth_providers: vec![],
        });

        let result = config.public_route_matcher().check("GET", "/public");
        assert!(result.is_public());
    }

    #[test]
    fn multiple_auth_providers() {
        let route_matcher = RouteMatcher::new(&[]).unwrap();
        let public_route_matcher = PublicRouteMatcher::new(&[]).unwrap();
        let config = PipelineConfig::new(PipelineConfigParams {
            route_matcher,
            public_route_matcher,
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test-project").unwrap(),
            default_policy: DefaultPolicy::Deny,
            debug_mode: false,
            auth_providers: vec!["jwt".to_string(), "api-key".to_string()],
        });

        assert_eq!(config.auth_providers().len(), 2);
        assert_eq!(config.auth_providers()[0], "jwt");
        assert_eq!(config.auth_providers()[1], "api-key");
    }

    #[test]
    fn empty_auth_providers() {
        let config = PipelineConfig::new(PipelineConfigParams {
            route_matcher: RouteMatcher::new(&[]).unwrap(),
            public_route_matcher: PublicRouteMatcher::new(&[]).unwrap(),
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test-project").unwrap(),
            default_policy: DefaultPolicy::Passthrough,
            debug_mode: false,
            auth_providers: vec![],
        });

        assert!(config.auth_providers().is_empty());
    }
}
