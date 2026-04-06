//! ForgeGuard state bundle — holds all runtime dependencies for the auth pipeline.

use std::sync::Arc;

use forgeguard_authn_core::IdentityChain;
use forgeguard_authz_core::PolicyEngine;
use forgeguard_proxy_core::PipelineConfig;

/// Runtime state for the ForgeGuard middleware.
///
/// Bundles the three dependencies that [`forgeguard_proxy_core::evaluate_pipeline`] needs:
/// pipeline configuration, identity resolution chain, and policy engine.
///
/// Wrap in `Arc<ForgeGuard>` and pass as Axum state.
///
/// # Example
///
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use forgeguard_axum::{ForgeGuard, forgeguard_layer};
/// # use forgeguard_authn_core::IdentityChain;
/// # use forgeguard_authz_core::PolicyEngine;
/// # use forgeguard_proxy_core::PipelineConfig;
/// # fn example(
/// #     config: PipelineConfig,
/// #     chain: IdentityChain,
/// #     engine: Arc<dyn PolicyEngine>,
/// # ) {
/// use axum::{Router, routing::get, middleware};
///
/// let fg = Arc::new(ForgeGuard::new(config, chain, engine));
/// let app: Router = Router::new()
///     .route("/api/items", get(handler))
///     .layer(middleware::from_fn_with_state(fg, forgeguard_layer));
/// # }
/// # async fn handler() -> &'static str { "ok" }
/// ```
pub struct ForgeGuard {
    pub(crate) config: PipelineConfig,
    pub(crate) identity_chain: IdentityChain,
    pub(crate) policy_engine: Arc<dyn PolicyEngine>,
}

impl ForgeGuard {
    /// Construct a new `ForgeGuard` state bundle.
    pub fn new(
        config: PipelineConfig,
        identity_chain: IdentityChain,
        policy_engine: Arc<dyn PolicyEngine>,
    ) -> Self {
        Self {
            config,
            identity_chain,
            policy_engine,
        }
    }
}
