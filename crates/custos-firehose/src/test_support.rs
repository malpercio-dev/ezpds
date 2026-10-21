//! Fixtures for tests that drive the firehose serving surface: everything in
//! `custos_core::test_support` (re-exported below) plus the router the tests send through
//! ([`test_app`]).

use axum::Router;
pub use custos_core::test_support::*;
use custos_core::CoreState;

/// Both firehose routers over `state`, wrapped the way `pds` wraps them: the shared layer stack on
/// each group, plus the XRPC error dialect and permissive CORS on the public one. The rest of the
/// `pds` app is absent, so a path no firehose route claims is a plain 404 here.
pub fn test_app(state: CoreState) -> Router {
    let public = custos_core::apply_shared_layers(crate::router::<CoreState>(), &state)
        .layer(axum::middleware::from_fn(
            custos_core::xrpc_error_shape::flatten_xrpc_errors,
        ))
        .layer(tower_http::cors::CorsLayer::permissive());
    let internal = custos_core::apply_shared_layers(crate::internal_router::<CoreState>(), &state);
    public.merge(internal).with_state(state)
}
