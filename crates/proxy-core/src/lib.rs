#![deny(clippy::unwrap_used, clippy::expect_used)]

pub(crate) mod error;
pub(crate) mod pipeline;
pub(crate) mod pipeline_config;
pub(crate) mod pipeline_outcome;
pub(crate) mod request_input;
pub(crate) mod source;
pub(crate) mod tenant;

pub use error::{Error, Result};
pub use pipeline::evaluate_pipeline;
pub use pipeline_config::{PipelineConfig, PipelineConfigParams};
pub use pipeline_outcome::PipelineOutcome;
pub use request_input::RequestInput;
pub use source::{PipelineSource, StaticSource};
pub use tenant::{
    HeaderExtractor, HostExtractor, PathPrefixExtractor, SubdomainExtractor, TenantExtractor,
    TenantExtractorChain,
};
