//! The runtime every Custos feature crate shares: [`CoreState`], the access-token and DPoP
//! verification seam (`auth`), identity resolution, the lexicon registry, rate limiting, metrics,
//! the sweep scheduler, and the shared middleware stack. Feature crates and `pds` depend on it; it
//! depends on no feature crate. See `AGENTS.md`.

pub mod auth;
pub mod blob_store;
pub mod capability;
pub mod identity;
mod layers;
pub mod lexicon;
pub mod metrics;
pub mod no_input;
pub mod rate_limit;
pub mod request_host;
pub mod space_uri;
pub mod state;
pub mod sweep;
pub mod sweep_status;
pub mod time;
pub mod xrpc_error_shape;

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed seed panics the test
pub mod test_support;

pub use layers::apply_shared_layers;
pub use state::{CoreState, FailedLoginStore};
