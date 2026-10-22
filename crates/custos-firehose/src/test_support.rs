//! Fixtures for tests that drive the firehose serving surface: everything in
//! `custos_core::test_support` (re-exported below) plus the router the tests send through
//! ([`test_app`]).

use axum::Router;
pub use custos_core::test_support::*;
use custos_core::CoreState;

/// Both firehose routers over `state`, wrapped as `pds` wraps them (see
/// [`custos_core::test_support::test_app`]).
pub fn test_app(state: CoreState) -> Router {
    custos_core::test_support::test_app(crate::router(), crate::internal_router(), state)
}
