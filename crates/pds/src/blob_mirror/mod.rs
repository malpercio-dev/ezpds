// pattern: Imperative Shell
//
//! Off-volume blob replication: the bucket mirror.
//!
//! Litestream replicates only the SQLite database — the blob files at
//! `{data_dir}/blobs/{prefix}/{cid}` otherwise live solely on the deployment volume, where
//! volume loss destroys every user's media with no external heal path (AppView CDN
//! derivatives are re-encoded and can never match the original CIDs). This module is the
//! Litestream analogue for those files: a periodic sweep uploads every stored blob to an
//! S3-compatible bucket, and boot restores any file missing from the volume back out of the
//! bucket before the server takes traffic.
//!
//! Content addressing makes the sync trivially safe and incremental — files are immutable
//! and add-only, so a pass is "upload the keys the bucket is missing". Two integrity rules
//! keep the mirror trustworthy:
//!
//! - **Verify before replicating.** Every local file is re-hashed against its CID (and
//!   size-checked against its row) before upload; a corrupt or truncated local file must
//!   never become the trusted recovery copy. The same verification runs before a restore
//!   trusts a bucket copy.
//! - **Restore gates serving.** `restore_missing_blobs` runs to completion during startup,
//!   before the listener binds, so a Litestream-restored database never serves against a
//!   volume whose files it hasn't been reconciled with. A row whose bytes exist in neither
//!   place is surfaced loudly (per-CID error log + counted in the boot summary) rather than
//!   silently left to 404.
//!
//! Deletion propagates the other way on a lag: a bucket key whose `blobs` row is gone (blob
//! GC or account deletion reclaimed it) is deleted on the next pass. The worst case of the
//! lag is the bucket briefly retaining collected blobs — harmless. As a tripwire against
//! ever acting on a wrong (empty) database, a pass that finds no `blobs` rows at all while
//! the bucket has objects skips delete propagation entirely.

mod s3;
#[cfg(test)]
pub(crate) mod test_support;

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::blob_store;
use crate::db::blobs::{self, PhysicalBlob};

/// A configured mirror target: the bucket client plus the object-key namespace it owns.
pub struct BlobMirror {
    s3: s3::S3Client,
    key_prefix: String,
}

impl BlobMirror {
    /// Build the mirror from config. `Ok(None)` when the mirror is disabled (no bucket
    /// configured); an error only for a config the validation layer should have rejected.
    pub fn from_config(config: &common::BlobMirrorConfig) -> anyhow::Result<Option<Self>> {
        let Some(bucket) = config.bucket.as_deref() else {
            return Ok(None);
        };
        let endpoint = config
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("blob_mirror.endpoint missing"))?;
        let access_key_id = config
            .access_key_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("blob_mirror.access_key_id missing"))?;
        let secret_access_key = config
            .secret_access_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("blob_mirror.secret_access_key missing"))?;
        let s3 = s3::S3Client::new(
            endpoint,
            bucket,
            &config.region,
            access_key_id,
            &secret_access_key.0,
            config.force_path_style,
        )?;
        Ok(Some(Self {
            s3,
            key_prefix: config.key_prefix.clone(),
        }))
    }

    /// The bucket key for a blob CID: flat under the configured prefix (the bucket needs no
    /// two-character fanout — object stores have flat namespaces).
    fn key_for(&self, cid: &str) -> String {
        format!("{}{}", self.key_prefix, cid)
    }

    /// Fetch `row`'s bytes from the bucket and verify them against its CID/size before
    /// returning them. Shared by restore-on-boot and the integrity scrub's auto-heal path: a
    /// bucket copy is a trusted recovery source only after this check passes, never before.
    ///
    /// `Ok(None)` when the bucket has no copy either — nothing to heal from. An `Err` covers
    /// both a transfer failure and a copy that exists but fails verification (bitrot/tampering
    /// in the bucket itself); either way the caller must not trust or write the bytes.
    pub async fn fetch_verified(&self, row: &PhysicalBlob) -> Result<Option<Vec<u8>>, String> {
        match self.s3.get_object(&self.key_for(&row.cid)).await {
            Ok(Some(content)) => {
                verify_content(row, &content)?;
                Ok(Some(content))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("fetch bucket copy: {e}")),
        }
    }
}

/// Tally of what one mirror pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MirrorStats {
    /// Blobs uploaded to the bucket this pass.
    pub uploaded: u64,
    /// Bucket objects deleted because their `blobs` row is gone.
    pub deleted: u64,
    /// Blobs skipped due to an error (verification failure, unreadable file, failed
    /// transfer). Logged, never fatal to the pass.
    pub errors: u64,
}

/// Tally of one restore-on-boot pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RestoreStats {
    /// Files that were missing from the volume and restored from the bucket.
    pub restored: u64,
    /// Rows whose bytes exist in neither place — the unrecoverable set, surfaced loudly.
    pub missing: u64,
    /// Restore attempts that failed (transfer error, verification failure). The file is
    /// left absent; the next boot retries.
    pub errors: u64,
}

/// Spawn the periodic blob-mirror sweep.
///
/// The first interval tick is consumed without running a pass (restore-on-boot has just
/// reconciled the volume, and startup shouldn't pay for a bucket listing); the first pass
/// runs one `interval` after boot. The task loops for the life of the process and is dropped
/// on shutdown.
pub fn spawn_blob_mirror(
    state: AppState,
    mirror: Arc<BlobMirror>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // `interval`'s first tick fires immediately — skip it so the sweep doesn't run mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_blob_mirror(&state, &mirror).await;
        }
    })
}

/// Run one mirror pass: upload every verified blob the bucket is missing, then delete bucket
/// objects whose `blobs` row is gone.
///
/// Resilient by design, like the other sweeps: a per-blob error is logged and counted but
/// never aborts the pass. A failure to enumerate either side (the DB rows or the bucket
/// listing) skips the whole pass without recording, leaving the last-run timestamp stale —
/// the operator's signal that mirroring is not completing.
pub async fn run_blob_mirror(state: &AppState, mirror: &BlobMirror) -> MirrorStats {
    let mut stats = MirrorStats::default();

    let rows = match blobs::list_all_blobs(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "blob mirror: failed to list blob rows; skipping pass");
            return stats;
        }
    };
    let remote_cids: HashSet<String> = match mirror.s3.list_keys(&mirror.key_prefix).await {
        Ok(keys) => keys
            .into_iter()
            .filter_map(|key| {
                key.strip_prefix(&mirror.key_prefix)
                    .map(|cid| cid.to_string())
            })
            .collect(),
        Err(e) => {
            tracing::error!(error = %e, "blob mirror: failed to list bucket keys; skipping pass");
            return stats;
        }
    };

    // Upload what the bucket is missing, verifying every local file against its CID first.
    for row in &rows {
        if remote_cids.contains(&row.cid) {
            continue;
        }
        match upload_verified(state, mirror, row).await {
            Ok(()) => stats.uploaded += 1,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(cid = %row.cid, error = %e, "blob mirror: upload skipped");
            }
        }
    }

    // Propagate deletions: a bucket object with no `blobs` row was reclaimed locally (blob
    // GC / account deletion). Tripwire: a completely empty `blobs` table against a non-empty
    // bucket means the database this pass is reading is not the one the bucket was built
    // from (fresh volume, failed restore) — never let that state empty the recovery copy.
    let local_cids: HashSet<&str> = rows.iter().map(|row| row.cid.as_str()).collect();
    let stale: Vec<&String> = remote_cids
        .iter()
        .filter(|cid| !local_cids.contains(cid.as_str()))
        .collect();
    if rows.is_empty() && !stale.is_empty() {
        tracing::warn!(
            bucket_objects = stale.len(),
            "blob mirror: blobs table is empty but the bucket is not; refusing to propagate deletions"
        );
    } else {
        for cid in stale {
            match mirror.s3.delete_object(&mirror.key_for(cid)).await {
                Ok(()) => {
                    stats.deleted += 1;
                    tracing::info!(cid = %cid, "blob mirror: deleted bucket object with no blob row");
                }
                Err(e) => {
                    stats.errors += 1;
                    tracing::warn!(cid = %cid, error = %e, "blob mirror: failed to delete bucket object");
                }
            }
        }
    }

    if stats.uploaded > 0 || stats.deleted > 0 || stats.errors > 0 {
        tracing::info!(
            uploaded = stats.uploaded,
            deleted = stats.deleted,
            errors = stats.errors,
            "blob mirror pass complete"
        );
    } else {
        tracing::debug!(
            blobs = rows.len(),
            "blob mirror pass complete (bucket in sync)"
        );
    }

    // The failed-to-enumerate early returns above skip this on purpose: a stale
    // `blob_mirror_last_run_timestamp` is the operator's signal that passes are not
    // completing.
    state
        .metrics
        .blob_mirror_synced
        .add(stats.uploaded + stats.deleted, &[]);
    state
        .metrics
        .blob_mirror_last_run_timestamp
        .record(crate::metrics::unix_now(), &[]);
    state
        .sweeps
        .record_blob_mirror(crate::sweep_status::SweepRun::now(
            stats.uploaded + stats.deleted,
        ));

    stats
}

/// Read one blob's local file, verify it against its row, and upload it.
async fn upload_verified(
    state: &AppState,
    mirror: &BlobMirror,
    row: &PhysicalBlob,
) -> Result<(), String> {
    let content = tokio::fs::read(state.config.data_dir.join(&row.storage_path))
        .await
        .map_err(|e| format!("read local file: {e}"))?;
    verify_content(row, &content)?;
    mirror
        .s3
        .put_object(&mirror.key_for(&row.cid), content, &row.mime_type)
        .await
        .map_err(|e| format!("upload: {e}"))
}

/// Check `content` against a blob row's size and CID. The gate both directions of the mirror
/// run behind: corrupt bytes must neither become the recovery copy nor be restored from it.
fn verify_content(row: &PhysicalBlob, content: &[u8]) -> Result<(), String> {
    if content.len() as i64 != row.size_bytes {
        return Err(format!(
            "size mismatch: file is {} bytes, row says {}",
            content.len(),
            row.size_bytes
        ));
    }
    let computed = blob_store::compute_cid(content);
    if computed != row.cid {
        return Err(format!("content hash mismatch: bytes hash to {computed}"));
    }
    Ok(())
}

/// Restore every blob file the volume is missing from the mirror bucket. Runs during
/// startup, after migrations and before the listener binds, so a (Litestream-)restored
/// database is reconciled with the blob directory before anything is served.
///
/// Restored bytes are verified against the row's CID and size before they are written — a
/// corrupt bucket copy is refused (and counted) rather than materialised at a valid CID
/// path. Rows recoverable from neither place are the permanently-lost set: each is logged as
/// an error and counted in [`RestoreStats::missing`]; boot proceeds (their reads 404, the
/// same observable state as before the restore, now with an operator signal).
///
/// Errors only on a failure to enumerate the `blobs` table — per-blob failures are counted,
/// not propagated.
pub async fn restore_missing_blobs(
    db: &SqlitePool,
    data_dir: &Path,
    mirror: &BlobMirror,
) -> Result<RestoreStats, sqlx::Error> {
    let mut stats = RestoreStats::default();

    for row in blobs::list_all_blobs(db).await? {
        let abs_path = data_dir.join(&row.storage_path);
        match tokio::fs::metadata(&abs_path).await {
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(cid = %row.cid, error = %e, "blob restore: could not stat local file");
                continue;
            }
        }

        match mirror.fetch_verified(&row).await {
            Ok(Some(content)) => {
                if let Err(e) = write_restored(&abs_path, &content).await {
                    stats.errors += 1;
                    tracing::error!(cid = %row.cid, error = %e, "blob restore: failed to write restored file");
                    continue;
                }
                stats.restored += 1;
                tracing::info!(cid = %row.cid, "blob restore: restored missing blob from mirror bucket");
            }
            Ok(None) => {
                stats.missing += 1;
                tracing::error!(
                    cid = %row.cid,
                    "blob restore: blob is missing locally AND absent from the mirror bucket — bytes are unrecoverable"
                );
            }
            Err(e) => {
                stats.errors += 1;
                tracing::error!(cid = %row.cid, error = %e, "blob restore: bucket copy fetch or verification failed; not restoring it");
            }
        }
    }

    Ok(stats)
}

async fn write_restored(abs_path: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = abs_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(abs_path, content).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::{add_blob, build_test_mirror as mirror_state, local_path};

    // ── Sweep ───────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mirror_uploads_missing_blobs_and_is_idempotent() {
        let (state, _dir, fake, mirror) = mirror_state().await;
        let did = "did:plc:mirrorup";
        let a = add_blob(&state, did, b"first blob bytes", "image/png").await;
        let b = add_blob(&state, did, b"second blob bytes", "video/mp4").await;

        let stats = run_blob_mirror(&state, &mirror).await;
        assert_eq!(stats.uploaded, 2);
        assert_eq!(stats.deleted, 0);
        assert_eq!(stats.errors, 0);

        let (ct_a, bytes_a) = fake.object(&format!("blobs/{a}")).unwrap();
        assert_eq!(ct_a, "image/png");
        assert_eq!(bytes_a, b"first blob bytes");
        let (ct_b, bytes_b) = fake.object(&format!("blobs/{b}")).unwrap();
        assert_eq!(ct_b, "video/mp4");
        assert_eq!(bytes_b, b"second blob bytes");

        // The pass's instruments fire: the sync is counted and the pass is timestamped.
        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("blob_mirror_synced_total"),
            "missing blob_mirror_synced_total in:\n{rendered}"
        );
        assert!(
            rendered.contains("blob_mirror_last_run_timestamp"),
            "missing blob_mirror_last_run_timestamp in:\n{rendered}"
        );
        assert_eq!(state.sweeps.snapshot().blob_mirror.unwrap().swept, 2);

        // A second pass finds the bucket in sync and moves nothing.
        let stats = run_blob_mirror(&state, &mirror).await;
        assert_eq!(stats, MirrorStats::default());
        assert_eq!(state.sweeps.snapshot().blob_mirror.unwrap().swept, 0);
    }

    /// Five blobs against the fake's two-key listing pages: a sync judgment spanning
    /// multiple ListObjectsV2 pages must still see every remote key (a truncated listing
    /// read as complete would re-upload page 2+ forever — or worse, delete it).
    #[tokio::test]
    async fn mirror_listing_follows_continuation_tokens() {
        let (state, _dir, fake, mirror) = mirror_state().await;
        let did = "did:plc:mirrorpage";
        for i in 0..5 {
            add_blob(
                &state,
                did,
                format!("paged blob {i}").as_bytes(),
                "text/plain",
            )
            .await;
        }

        let stats = run_blob_mirror(&state, &mirror).await;
        assert_eq!(stats.uploaded, 5);
        assert_eq!(fake.keys().len(), 5);

        let stats = run_blob_mirror(&state, &mirror).await;
        assert_eq!(
            stats,
            MirrorStats::default(),
            "second pass must see all pages"
        );
    }

    #[tokio::test]
    async fn mirror_propagates_row_deletion_to_bucket() {
        let (state, _dir, fake, mirror) = mirror_state().await;
        let did = "did:plc:mirrordel";
        let kept = add_blob(&state, did, b"kept bytes", "image/png").await;
        let dropped = add_blob(&state, did, b"dropped bytes", "image/png").await;
        run_blob_mirror(&state, &mirror).await;
        assert_eq!(fake.keys().len(), 2);

        // Blob GC's endgame: the ownership row and the physical row are gone.
        sqlx::query("DELETE FROM blob_owners WHERE cid = ?")
            .bind(&dropped)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM blobs WHERE cid = ?")
            .bind(&dropped)
            .execute(&state.db)
            .await
            .unwrap();

        let stats = run_blob_mirror(&state, &mirror).await;
        assert_eq!(stats.deleted, 1);
        assert_eq!(stats.uploaded, 0);
        assert!(fake.object(&format!("blobs/{dropped}")).is_none());
        assert!(fake.object(&format!("blobs/{kept}")).is_some());
    }

    #[tokio::test]
    async fn mirror_never_uploads_bytes_that_fail_verification() {
        let (state, _dir, fake, mirror) = mirror_state().await;
        let did = "did:plc:mirrorbad";
        let cid = add_blob(&state, did, b"original bytes", "image/png").await;
        // The torn-write fault: valid CID path, wrong bytes underneath.
        tokio::fs::write(local_path(&state, &cid), b"corrupted bytes!")
            .await
            .unwrap();

        let stats = run_blob_mirror(&state, &mirror).await;
        assert_eq!(stats.uploaded, 0);
        assert_eq!(stats.errors, 1);
        assert!(
            fake.keys().is_empty(),
            "corrupt bytes must never reach the mirror bucket"
        );
    }

    #[tokio::test]
    async fn mirror_refuses_delete_propagation_against_an_empty_blobs_table() {
        let (state, _dir, fake, mirror) = mirror_state().await;
        // The bucket holds a recovery copy; the DB (fresh volume, failed restore) knows
        // nothing. The pass must not empty the bucket.
        fake.put("blobs/bafkreiorphan", "image/png", b"survivor".to_vec());

        let stats = run_blob_mirror(&state, &mirror).await;
        assert_eq!(stats.deleted, 0);
        assert!(fake.object("blobs/bafkreiorphan").is_some());
    }

    // ── Restore-on-boot ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn restore_fetches_and_verifies_missing_files() {
        let (state, _dir, _fake, mirror) = mirror_state().await;
        let did = "did:plc:restoreok";
        let cid = add_blob(&state, did, b"restorable bytes", "image/png").await;
        run_blob_mirror(&state, &mirror).await;

        // The disaster: the volume loses the file (the row, Litestream-protected, survives).
        tokio::fs::remove_file(local_path(&state, &cid))
            .await
            .unwrap();

        let stats = restore_missing_blobs(&state.db, &state.config.data_dir, &mirror)
            .await
            .unwrap();
        assert_eq!(stats.restored, 1);
        assert_eq!(stats.missing, 0);
        assert_eq!(stats.errors, 0);
        let restored = tokio::fs::read(local_path(&state, &cid)).await.unwrap();
        assert_eq!(restored, b"restorable bytes");

        // A volume already in sync restores nothing.
        let stats = restore_missing_blobs(&state.db, &state.config.data_dir, &mirror)
            .await
            .unwrap();
        assert_eq!(stats, RestoreStats::default());
    }

    #[tokio::test]
    async fn restore_refuses_a_corrupt_bucket_copy() {
        let (state, _dir, fake, mirror) = mirror_state().await;
        let did = "did:plc:restorebad";
        let cid = add_blob(&state, did, b"true bytes", "image/png").await;
        // The bucket copy is wrong (bitrot, tampering); the local file is lost.
        fake.put(
            &format!("blobs/{cid}"),
            "image/png",
            b"evil bytes!".to_vec(),
        );
        tokio::fs::remove_file(local_path(&state, &cid))
            .await
            .unwrap();

        let stats = restore_missing_blobs(&state.db, &state.config.data_dir, &mirror)
            .await
            .unwrap();
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.restored, 0);
        assert!(
            tokio::fs::metadata(local_path(&state, &cid)).await.is_err(),
            "unverified bytes must never be materialised at a CID path"
        );
    }

    #[tokio::test]
    async fn restore_surfaces_blobs_missing_everywhere() {
        let (state, _dir, _fake, mirror) = mirror_state().await;
        let did = "did:plc:restoregone";
        let cid = add_blob(&state, did, b"doomed bytes", "image/png").await;
        // Never mirrored; local file lost. The row now points at nothing anywhere.
        tokio::fs::remove_file(local_path(&state, &cid))
            .await
            .unwrap();

        let stats = restore_missing_blobs(&state.db, &state.config.data_dir, &mirror)
            .await
            .unwrap();
        assert_eq!(stats.missing, 1);
        assert_eq!(stats.restored, 0);
        assert_eq!(stats.errors, 0);
    }

    // ── Verification helper ─────────────────────────────────────────────────────

    #[test]
    fn verify_content_checks_size_and_hash() {
        let content = b"verify me";
        let row = PhysicalBlob {
            cid: blob_store::compute_cid(content),
            mime_type: "text/plain".to_string(),
            size_bytes: content.len() as i64,
            storage_path: "blobs/xx/whatever".to_string(),
        };
        assert!(verify_content(&row, content).is_ok());
        assert!(verify_content(&row, b"verify m!").is_err(), "hash mismatch");
        assert!(verify_content(&row, b"verify").is_err(), "size mismatch");
    }
}
