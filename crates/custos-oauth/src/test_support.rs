//! Fixtures for tests that drive the OAuth surface: everything in `custos_core::test_support`
//! (re-exported below) plus the router the tests send through ([`test_app`]).

use axum::Router;
pub use custos_core::test_support::*;
use custos_core::CoreState;

/// The OAuth router over `state`, wrapped the way `pds` wraps its public group: the shared layer
/// stack, the XRPC error dialect, and permissive CORS. The rest of the `pds` app is absent, so a
/// path no OAuth route claims is a plain 404 here.
pub fn test_app(state: CoreState) -> Router {
    let router = custos_core::apply_shared_layers(crate::router::<CoreState>(), &state)
        .layer(axum::middleware::from_fn(
            custos_core::xrpc_error_shape::flatten_xrpc_errors,
        ))
        .layer(tower_http::cors::CorsLayer::permissive());
    router.with_state(state)
}
