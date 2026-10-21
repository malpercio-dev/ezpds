// pattern: Imperative Shell

//! The Atproto Spaces feature: the `com.atproto.space.*` and `com.atproto.simplespace.*` routes,
//! `/v1/space/import-repo` and the operator's `/v1/admin/spaces` pair, the space authorization
//! seam, the space query modules, both space sweeps, and the `spaces` capability entry.
//!
//! `pds` is the composition root and consumes only what this file exports: [`SpacesState`],
//! [`router`] / [`internal_router`], [`spawn_sweeps`], [`CAPABILITY`], [`purge_account_rows`],
//! the [`db`] query modules, the [`space_record_write`] choke point, and (behind `test-support`)
//! [`test_support`]. See `AGENTS.md`.

use axum::extract::FromRef;
use common::SpacesConfig;
use custos_core::sweep::Scheduler;
use custos_core::CoreState;
use sqlx::SqliteConnection;

// Modules custos-core owns, aliased at the crate root so `crate::identity::…` and its siblings
// resolve as they did in `pds`.
use custos_core::{
    blob_store, identity, lexicon, metrics, rate_limit, space_uri, sweep, sweep_status, time,
};

mod auth;
mod capability;
pub mod db;
mod router;
mod routes;
mod space_jti_sweep;
mod space_notify;
mod space_oplog_sweep;
pub mod space_record_write;
mod state;
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed request panics the test
pub mod test_support;
mod views;

pub use capability::CAPABILITY;
pub use router::{internal_router, router};
pub use state::SpacesState;

/// Register both space retention sweeps on `pds`'s scheduler, only while the surface is enabled.
/// Disabled, no route can write the tables they reclaim, and their `null` slots in the health
/// readout read as "not configured", like the blob mirror's. Rows already stored keep their data;
/// only reclamation pauses with the surface.
pub fn spawn_sweeps<St>(scheduler: &mut Scheduler<St>, config: &SpacesConfig)
where
    St: Clone + Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    if !config.enabled {
        return;
    }
    // The (scope, jti) primary key enforces anti-replay; each row's expires_at carries its own
    // token's acceptance horizon, so the sweep only bounds storage growth.
    scheduler.spawn(space_jti_sweep::SpaceJtiSweep);
    tracing::info!(
        interval_secs = space_jti_sweep::SWEEP_INTERVAL.as_secs(),
        "space jti retention sweep started"
    );
    // The oplog is droppable by spec; this bounds it to a backfill window, and a syncer further
    // behind heals via getRepo.
    scheduler.spawn(space_oplog_sweep::SpaceOplogSweep);
    tracing::info!(
        interval_secs = space_oplog_sweep::SWEEP_INTERVAL.as_secs(),
        retention_secs = space_oplog_sweep::OPLOG_RETENTION_SECS,
        "space oplog compaction sweep started"
    );
}

/// The statements [`purge_account_rows`] runs, in FK order (ops and records reference the repo
/// row). Public so `pds`'s schema-walking purge test sees every account-keyed table covered.
///
/// `spaces` rows deliberately survive even when the account is the authority: members' records are
/// their own, and an unanswerable space is exactly the spec's deletion semantics. `space_writers`
/// has no FK to `accounts` (most writers are foreign repos), so nothing removes those rows
/// implicitly, and a purged account left in `listRepos` advertises a repo every reader then gets
/// `RepoNotFound` for.
pub const PURGE_ACCOUNT_SQL: &[&str] = &[
    "DELETE FROM space_repo_ops WHERE account_did = ?",
    "DELETE FROM space_records WHERE account_did = ?",
    "DELETE FROM space_repos WHERE account_did = ?",
    "DELETE FROM space_members WHERE member_did = ?",
    "DELETE FROM space_notify_registrations WHERE subscriber_did = ?",
    "DELETE FROM space_writers WHERE repo_did = ?",
];

/// Delete every space-owned row of `did` inside the caller's account-purge transaction.
pub async fn purge_account_rows(tx: &mut SqliteConnection, did: &str) -> Result<(), sqlx::Error> {
    for sql in PURGE_ACCOUNT_SQL {
        sqlx::query(sql).bind(did).execute(&mut *tx).await?;
    }
    Ok(())
}
