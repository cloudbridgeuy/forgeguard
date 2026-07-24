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
//! // sub-router itself, forgeguard first, BEFORE nesting it into the
//! // parent — this is the only shape that scopes to just that subtree.
//! let beta_routes = Router::new()
//!     .route("/x", get(h))
//!     .layer(from_fn_with_state(fg.clone(), forgeguard_layer))
//!     .layer(fg.observe());
//!
//! Router::new().nest("/beta", beta_routes)
//! ```
//!
//! Misordering fails SAFE: the stamp is simply unseen and the route runs
//! in the guard's default mode (`Enforce` unless overridden). This is
//! confirmed by [`crate::middleware::tests::misordered_observe_stamp_fails_safe_to_enforce`].
//!
//! # `.nest()` is not a scope boundary for `.layer()`
//!
//! Axum's "last-added-wraps-outermost" rule applies to a router's *entire*
//! current route table at the point `.layer()`/`.route_layer()` is called —
//! `.nest(...)`ing a child router merges its routes into that table, it does
//! not fence them off. Two shapes that look like reasonable ways to observe
//! "just `/beta`" are both traps:
//!
//! ```text
//! // TRAP 1: stamp on the parent, added AFTER .nest(...). This IS seen by
//! // routes under /beta (it does not silently fail like the misordering
//! // above) — but .layer() wraps the parent's whole table as it stands at
//! // that call, so it ALSO leaks onto every sibling route already
//! // registered on `parent`, not just /beta. Not scoped — do not use this
//! // to observe a subtree.
//! parent.nest("/beta", beta_routes).layer(fg.observe())
//!
//! // TRAP 2: stamp on the parent, added BEFORE .nest(...). /beta's routes
//! // aren't in the parent's table yet when .layer() runs, so they never
//! // see the stamp at all — same "fails safe to Enforce" outcome as the
//! // single-router misordering case above.
//! parent.layer(fg.observe()).nest("/beta", beta_routes)
//! ```
//!
//! The sub-router shape above (`beta_routes` carrying both layers before
//! nesting) is the only one of these three that scopes correctly, confirmed
//! by [`crate::middleware::tests::nested_observe_scopes_to_subrouter_not_siblings`]
//! — the layers travel with the sub-router's own service and merging it into a
//! parent can't widen or narrow what they wrap.

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
