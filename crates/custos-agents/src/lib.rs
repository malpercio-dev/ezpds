// pattern: Imperative Shell

//! The auth.md agent surface: the `/auth.md` document, agent registration, the owner-confirmed
//! claim ceremony, sovereign child agents, the provider event endpoint, the owner's `/v1/agents`
//! management API, the claim-attempt expiry sweep, and the `agents` capability entry. The token
//! endpoint's agent grants are `custos-oauth`'s; the machinery both share is `custos-core`'s
//! (`auth::agent_assertion`) and `custos-db`'s (`agent_auth`, `agent_audit`).
//!
//! `pds` is the composition root and consumes only what this file exports: [`router`] /
//! [`internal_router`], [`spawn_sweeps`], [`CAPABILITY`], and (behind `test-support`)
//! [`test_support`]. Handlers extract `State<CoreState>`. See `AGENTS.md`.

use axum::extract::FromRef;
use custos_core::sweep::Scheduler;
use custos_core::CoreState;

// Modules custos-core and common own, aliased at the crate root so `crate::identity::…` and its
// siblings resolve as they did in `pds`.
use custos_core::{auth, firehose, identity, metrics, sweep, sweep_status};

mod agent_child_core;
mod agent_claim_sweep;
mod capability;
mod db;
mod router;
mod routes;
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed request panics the test
pub mod test_support;

pub use capability::CAPABILITY;
pub use router::{internal_router, router};

/// Register the claim-attempt expiry sweep on `pds`'s scheduler. Each pass flips lapsed pending
/// claim attempts to `expired` and records a `claim_expired` audit event for each, so a wallet's
/// per-agent history reports how every ceremony ended.
pub fn spawn_sweeps<St>(scheduler: &mut Scheduler<St>, config: &common::AgentAuthConfig)
where
    St: Clone + Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    scheduler.spawn(agent_claim_sweep::AgentClaimSweep {
        interval: std::time::Duration::from_secs(config.claim_sweep_interval_secs),
    });
    tracing::info!(
        interval_secs = config.claim_sweep_interval_secs,
        "agent claim-attempt expiry sweep started"
    );
}
