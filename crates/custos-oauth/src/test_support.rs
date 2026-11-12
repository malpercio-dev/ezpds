//! Fixtures for tests that drive the OAuth surface: everything in `custos_core::test_support`
//! (re-exported below) plus the router the tests send through ([`test_app`]).

use axum::Router;
pub use custos_core::test_support::*;
use custos_core::CoreState;

/// The OAuth router over `state`, wrapped as `pds` wraps it (see
/// [`custos_core::test_support::test_app`]).
pub fn test_app(state: CoreState) -> Router {
    custos_core::test_support::test_app(crate::router(), Router::new(), state)
}

/// `state` with `[oauth] connector_resources` set to `resources`, turning connector sign-in
/// (ADR-0042) on for them.
pub fn with_connector_resources(state: CoreState, resources: &[&str]) -> CoreState {
    let mut config = (*state.config).clone();
    config.oauth.connector_resources = resources.iter().map(|r| r.to_string()).collect();
    CoreState {
        config: std::sync::Arc::new(config),
        ..state
    }
}
