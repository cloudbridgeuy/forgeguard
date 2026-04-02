#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod config;
pub(crate) mod config_raw;
pub mod config_types;
pub(crate) mod cors;
pub mod credential;
pub mod debug;
pub mod error;
pub mod headers;
pub mod method;
pub mod public;
pub mod query;
pub mod route;
pub mod validate;

pub use config::{
    apply_overrides, load_config, parse_config, ApiKeyConfig, AuthConfig, AuthzConfig,
    ClientIpSource, ClusterConfig, ConfigOverrides, DefaultPolicy, JwtConfig, MetricsConfig,
    ProxyConfig, UpstreamTarget,
};
pub use config_types::{AwsConfig, EntitySchema, PolicyTest, PolicyTestExpect, SchemaConfig};
pub use credential::extract_credential;
pub use debug::{evaluate_debug, FlagDebugQuery};
pub use error::{Error, Result, ValidationError, ValidationErrorKind, ValidationWarning};
pub use headers::{inject_client_ip, inject_headers, IdentityProjection};
pub use method::HttpMethod;
pub use public::{PublicAuthMode, PublicMatch, PublicRoute, PublicRouteMatcher};
pub use query::build_query;
pub use route::{MatchedRoute, RouteMapping, RouteMatcher};
pub use validate::validate;

pub use cors::CorsConfig;
