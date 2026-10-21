// pattern: Imperative Shell

//! The OAuth authorization server: PAR, `/oauth/authorize` and its wallet-confirmed consent half,
//! the token endpoint (authorization code, refresh, and the two auth.md agent grants), revocation,
//! the discovery documents, the server's JWKS and client metadata, and the `walletConsent`
//! capability entry.
//!
//! `pds` is the composition root and consumes only what this file exports: [`router`] and
//! [`CAPABILITY`], plus (behind `test-support`) [`test_support`]. Handlers extract
//! `State<CoreState>`: the feature owns no state of its own. See `AGENTS.md`.

// Modules custos-core and common own, aliased at the crate root so `crate::identity::…` and its
// siblings resolve as they did in `pds`.
use common::code_gen;
use custos_core::{identity, rate_limit, time};

mod auth;
mod capability;
mod db;
mod oauth_dpop;
mod oauth_errors;
mod oauth_templates;
mod router;
mod routes;
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed request panics the test
pub mod test_support;

pub use capability::CAPABILITY;
pub use router::router;
