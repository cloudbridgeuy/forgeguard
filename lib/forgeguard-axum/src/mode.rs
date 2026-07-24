//! Per-route enforcement-mode override (#111 V3).
//!
//! `observe()` is a plain [`axum::Extension`] layer that stamps
//! [`ModeOverride`] into request extensions; [`crate::forgeguard_layer`]
//! reads it and falls back to the guard's default mode.
//!
//! # Ordering (IMPORTANT)
//!
//! The stamp must run BEFORE `forgeguard_layer` on the request path, i.e.
//! it must be the OUTER layer. Axum applies layers on a single router in
//! last-added-wraps-outermost order (this holds for both `.layer(...)` and
//! `.route_layer(...)`), so this DOES NOT work:
//!
//! ```text
//! Router::new()
//!     .route("/x", get(h))
//!     .route_layer(observe())                 // inner — runs too late!
//!     .layer(from_fn_with_state(fg, forgeguard_layer))
//! ```
//!
//! Working shapes (stamp added AFTER the forgeguard layer = outer):
//!
//! ```text
//! // Per-route: both as route_layer, forgeguard first.
//! Router::new()
//!     .route("/x", get(h))
//!     .route_layer(from_fn_with_state(fg.clone(), forgeguard_layer))
//!     .route_layer(fg.observe())
//!
//! // Per-scope: observe a whole sub-router. Both layers go on the
//! // sub-router itself, forgeguard first — NOT on the parent after
//! // `.nest(...)`, which puts the parent's layer outside the whole
//! // nested stack and the stamp is never seen.
//! let beta_routes = Router::new()
//!     .route("/x", get(h))
//!     .layer(from_fn_with_state(fg.clone(), forgeguard_layer))
//!     .layer(fg.observe());
//!
//! Router::new().nest("/beta", beta_routes)
//! ```
//!
//! Misordering fails SAFE: the stamp is simply unseen and the route runs
//! in the guard's default mode (`Enforce` unless overridden).

use axum::Extension;
use forgeguard_proxy_core::EnforcementMode;

/// Request-extension marker carrying a per-route mode override.
#[derive(Debug, Clone, Copy)]
pub struct ModeOverride(pub(crate) EnforcementMode);

/// Layer that switches the wrapped routes to observe mode.
pub fn observe() -> Extension<ModeOverride> {
    Extension(ModeOverride(EnforcementMode::Observe))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn observe_stamps_observe_mode() {
        let Extension(ModeOverride(mode)) = observe();
        assert_eq!(mode, EnforcementMode::Observe);
    }
}
