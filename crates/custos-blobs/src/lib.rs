// pattern: Imperative Shell

//! The blob feature: `uploadBlob`, `listMissingBlobs`, `sync.getBlob`, `sync.listBlobs`, and the
//! three blob sweeps (garbage collection, the integrity scrub, and the optional S3 mirror with its
//! restore-on-boot reconcile). The blob file store itself (`blob_store`) and the `blobs` table
//! queries are core's (`custos_core::blob_store`, `custos_db::blobs`): every repo write reads them.
//!
//! `pds` is the composition root and consumes only what this file exports: [`router`],
//! [`prepare_mirror`], [`spawn_sweeps`], and (behind `test-support`) [`test_support`]. Handlers
//! extract `State<CoreState>`. See `AGENTS.md`.

use std::sync::Arc;

use anyhow::Context;
use axum::extract::FromRef;
use custos_core::sweep::Scheduler;
use custos_core::CoreState;

// Modules custos-core owns, aliased at the crate root so `crate::blob_store::…` and its siblings
// resolve as they did in `pds`.
use custos_core::{auth, blob_store, lexicon, metrics, sweep, sweep_status, time};

mod blob_gc;
mod blob_mirror;
mod blob_scrub;
mod db;
mod router;
mod routes;
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)] // fixtures: a failed seed panics the test
pub mod test_support;

pub use blob_mirror::BlobMirror;
pub use router::router;

/// Build the S3 mirror client when `[blob_mirror]` names a bucket, and reconcile the volume
/// against it. `pds` calls this BEFORE the listener binds: a (Litestream-)restored database must
/// never serve against a volume missing the files its rows point at when the mirror can heal
/// them. Blobs recoverable from neither place are surfaced per-CID (and in the summary below)
/// rather than aborting boot: their reads 404 exactly as they would have anyway, now with an
/// operator signal.
pub async fn prepare_mirror(state: &CoreState) -> anyhow::Result<Option<Arc<BlobMirror>>> {
    let mirror = BlobMirror::from_config(&state.config.blob_mirror)
        .with_context(|| "failed to build blob-mirror client")?
        .map(Arc::new);
    if let Some(mirror) = &mirror {
        let restore = blob_mirror::restore_missing_blobs(&state.db, &state.config.data_dir, mirror)
            .await
            .with_context(|| "failed to reconcile blob files against the mirror bucket")?;
        if restore.restored > 0 || restore.missing > 0 || restore.errors > 0 {
            tracing::warn!(
                restored = restore.restored,
                missing = restore.missing,
                errors = restore.errors,
                "blob restore-on-boot complete; `missing` blobs are recoverable from neither the volume nor the bucket"
            );
        } else {
            tracing::info!("blob restore-on-boot complete: volume and mirror bucket agree");
        }
    }
    Ok(mirror)
}

/// Register the three blob sweeps on `pds`'s scheduler. Each is best-effort and runs for the
/// life of the process; the scheduler stops them at shutdown.
pub fn spawn_sweeps<St>(
    scheduler: &mut Scheduler<St>,
    config: &common::Config,
    mirror: Option<Arc<BlobMirror>>,
) where
    St: Clone + Send + Sync + 'static,
    CoreState: FromRef<St>,
{
    // The garbage collector reclaims unreferenced and expired blobs.
    scheduler.spawn(blob_gc::BlobGc {
        interval: std::time::Duration::from_secs(config.blobs.gc_interval_secs),
    });
    tracing::info!(
        interval_secs = config.blobs.gc_interval_secs,
        "blob garbage collector started"
    );

    // When a bucket is configured, each mirror pass uploads stored blobs the bucket is missing
    // (verified against their CIDs first) and deletes bucket objects whose rows are gone.
    if let Some(mirror) = mirror.clone() {
        scheduler.spawn(blob_mirror::BlobMirrorSweep {
            interval: std::time::Duration::from_secs(config.blob_mirror.sync_interval_secs),
            mirror,
        });
        tracing::info!(
            interval_secs = config.blob_mirror.sync_interval_secs,
            bucket = config.blob_mirror.bucket.as_deref().unwrap_or(""),
            "blob-mirror sweep started"
        );
    }

    // The scrub re-hashes every stored blob against its row and walks the blob directory for
    // orphan files in both directions; when the mirror is configured and `[blob_scrub]
    // auto_heal` is on, a bad or missing file is repaired from the bucket's verified copy.
    scheduler.spawn(blob_scrub::BlobScrub {
        interval: std::time::Duration::from_secs(config.blob_scrub.interval_secs),
        mirror,
    });
    tracing::info!(
        interval_secs = config.blob_scrub.interval_secs,
        auto_heal = config.blob_scrub.auto_heal,
        "blob integrity scrub sweep started"
    );
}
