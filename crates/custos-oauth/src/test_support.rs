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
