//! Pipeline source — resolves a [`PipelineConfig`] for a given request.

use crate::{PipelineConfig, RequestInput};

/// Resolves which [`PipelineConfig`] should handle a given request.
///
/// For single-organization proxies (static and connected modes), this always
/// returns the same config. For multi-org SaaS proxies, the implementation
/// extracts the organization from the request and looks up per-org config.
///
/// Returns `None` when no config can be resolved (e.g., unknown org).
pub trait PipelineSource: Send + Sync {
    /// Look up the pipeline config for a request.
    fn resolve(&self, input: &RequestInput) -> Option<&PipelineConfig>;
}

// ---------------------------------------------------------------------------
// StaticSource
// ---------------------------------------------------------------------------

/// A [`PipelineSource`] that always returns the same config.
///
/// Used by single-organization proxies (static and connected modes) where
/// the pipeline config is fixed at startup.
pub struct StaticSource(PipelineConfig);

impl StaticSource {
    /// Wrap a `PipelineConfig` in a static source.
    pub fn new(config: PipelineConfig) -> Self {
        Self(config)
    }

    /// Return a reference to the inner config.
    pub fn config(&self) -> &PipelineConfig {
        &self.0
    }
}

impl PipelineSource for StaticSource {
    fn resolve(&self, _input: &RequestInput) -> Option<&PipelineConfig> {
        Some(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_core::{FlagConfig, ProjectId};
    use forgeguard_http::{DefaultPolicy, PublicRouteMatcher, RouteMatcher};

    use super::*;

    fn make_config() -> PipelineConfig {
        PipelineConfig::new(crate::PipelineConfigParams {
            route_matcher: RouteMatcher::new(&[]).unwrap(),
            public_route_matcher: PublicRouteMatcher::new(&[]).unwrap(),
            flag_config: FlagConfig::default(),
            project_id: ProjectId::new("test").unwrap(),
            default_policy: DefaultPolicy::Deny,
            debug_mode: false,
            auth_providers: vec![],
        })
    }

    #[test]
    fn static_source_always_returns_config() {
        let source = StaticSource::new(make_config());
        let input = RequestInput::new("GET", "/any", vec![], None).unwrap();
        assert!(source.resolve(&input).is_some());
    }

    #[test]
    fn static_source_config_accessor() {
        let source = StaticSource::new(make_config());
        assert_eq!(source.config().project_id().as_str(), "test");
    }
}
