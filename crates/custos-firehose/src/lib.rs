// pattern: Imperative Shell

//! The firehose serving side: `com.atproto.sync.subscribeRepos` (live fan-out plus cursor replay
//! over the durable log), the `repo_seq` retention sweep, and the operator's federation-health
//! pair (`/v1/admin/relay-status`, `/v1/admin/request-crawl`). The sequencer every writer emits
//! through and the crawler notifier are `custos_core::{firehose, crawler}`; the event log queries
//! are `custos_db::firehose_seq`.
//!
//! `pds` is the composition root and consumes only what this file exports: [`router`] /
//! [`internal_router`], [`spawn_sweeps`], and (behind `test-support`) [`test_support`]. Handlers
//! extract `State<CoreState>`. See `AGENTS.md`.

use axum::extract::FromRef;
use custos_core::sweep::Scheduler;
use custos_core::CoreState;

// Modules custos-core owns, aliased at the crate root so `crate::firehose::…` and its siblings
// resolve as they did in `pds`.
use custos_core::{auth, crawler, firehose, metrics, sweep, sweep_status, time};

mod db;
mod firehose_gc;
mod relay_status;
mod router;
mod routes;
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed request panics the test
pub mod test_support;

pub use router::{internal_router, router};

/// Register the `repo_seq` retention sweep on `pds`'s scheduler. It prunes rows below the
/// configured age/count watermark so the durable log backing `subscribeRepos` cursor replay does
/// not grow without bound.
pub fn spawn_sweeps<St>(scheduler: &mut Scheduler<St>, config: &common::FirehoseConfig)
where
    St: Clone + Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    scheduler.spawn(firehose_gc::FirehoseGc {
        interval: std::time::Duration::from_secs(config.gc_interval_secs),
    });
    tracing::info!(
        interval_secs = config.gc_interval_secs,
        retention_secs = config.log_retention_secs,
        retention_count = config.log_retention_count,
        "firehose repo_seq retention sweep started"
    );
}
