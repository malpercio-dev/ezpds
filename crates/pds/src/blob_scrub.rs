// pattern: Imperative Shell
//
//! Blob integrity scrub sweep.
//!
//! Nothing else ever re-verifies stored blob bytes against their CID after upload. Bitrot,
//! truncation, or a bad restore stays silent until a `getBlob` — or a migration drain — trips
//! over it: metadata present, reads failing, discovered mid-drain instead of months earlier
//! when it was still cheap to fix. This periodic background task (template: `blob_gc.rs`, same
//! failed-pass-leaves-timestamp-stale posture) walks every stored blob, re-hashes its file, and
//! compares hash + size against its `blobs` row.
//!
//! A full directory walk also catches both orphan directions, which nothing else scans for:
//!
//! * rows whose file is missing (the migration-blocking fault, surfaced as an operator alarm
//!   instead of a 500 mid-drain)
//! * files no row owns (a leak `blob_gc` never sees — it only ever works from DB rows outward)
//!
//! When a blob-mirror bucket (`[blob_mirror]`) is configured and `[blob_scrub] auto_heal` is
//! on, a bad or missing file is repaired from the bucket's verified-good copy
//! ([`BlobMirror::fetch_verified`] — the same "never trust an unverified copy" gate the mirror
//! itself runs behind); otherwise the problem is only ever flagged. Either way, silent rot
//! becomes a signal well before a migration depends on the bytes.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::blob_mirror::BlobMirror;
use crate::blob_store;
use crate::db::blobs::{self, PhysicalBlob};

/// Tally of what one scrub pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScrubStats {
    /// Physical blobs checked against their row (hash + size compared).
    pub scanned: u64,
    /// Bad or missing files repaired from the blob-mirror bucket.
    pub healed: u64,
    /// Rows whose file is missing on disk and could not be healed.
    pub missing_files: u64,
    /// Files present but whose hash/size didn't match their row, and could not be healed.
    pub corrupted_files: u64,
    /// On-disk blob files under `blobs/` that no `blobs` row owns — the leak direction
    /// `blob_gc` never scans for, since it only ever works from DB rows outward.
    pub orphan_files: u64,
    /// Checks skipped due to an I/O error unrelated to integrity (unreadable file, failed
    /// heal transfer). Logged, never fatal to the pass.
    pub errors: u64,
}

impl ScrubStats {
    /// Unhealed integrity problems this pass flagged — the operator alarm count surfaced via
    /// `blob_scrub_flagged_total` and the readable sweep status.
    pub fn flagged(&self) -> u64 {
        self.missing_files + self.corrupted_files + self.orphan_files
    }
}

/// Spawn the periodic blob-integrity scrub sweep.
///
/// The first interval tick is consumed without running a pass (a full re-hash of every stored
/// blob is I/O-heavy, so it shouldn't run mid-boot); the first pass runs one `interval` after
/// boot. The task loops for the life of the process and is dropped on shutdown.
pub fn spawn_blob_scrub(
    state: AppState,
    mirror: Option<Arc<BlobMirror>>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // `interval`'s first tick fires immediately — skip it so the sweep doesn't run mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_blob_scrub(&state, mirror.as_deref()).await;
        }
    })
}

/// The outcome of checking one physical blob's file against its row.
enum RowCheck {
    Ok,
    Missing,
    Mismatch(String),
}

/// Run a single scrub pass over every physical blob, then walk the blob directory for orphan
/// files.
///
/// Resilient by design, like the other sweeps: a per-blob I/O error is logged and counted but
/// never aborts the pass. A failure to enumerate the `blobs` table skips the whole pass without
/// recording, leaving the last-run timestamp stale — the operator's signal that scrubbing is
/// not completing.
pub async fn run_blob_scrub(state: &AppState, mirror: Option<&BlobMirror>) -> ScrubStats {
    let mut stats = ScrubStats::default();

    let rows = match blobs::list_all_blobs(&state.db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "blob scrub: failed to list blob rows; skipping pass");
            return stats;
        }
    };

    let heal_target = mirror.filter(|_| state.config.blob_scrub.auto_heal);

    for row in &rows {
        stats.scanned += 1;
        let check = match check_row(&state.config.data_dir, row).await {
            Ok(RowCheck::Ok) => continue,
            Ok(problem) => problem,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(cid = %row.cid, error = %e, "blob scrub: failed to check file; skipped");
                continue;
            }
        };

        if let Some(mirror) = heal_target {
            match heal(state, mirror, row).await {
                Ok(true) => {
                    stats.healed += 1;
                    tracing::warn!(cid = %row.cid, "blob scrub: healed from mirror bucket");
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    stats.errors += 1;
                    tracing::warn!(cid = %row.cid, error = %e, "blob scrub: heal attempt failed");
                }
            }
        }

        match check {
            RowCheck::Missing => {
                stats.missing_files += 1;
                tracing::error!(
                    cid = %row.cid,
                    storage_path = %row.storage_path,
                    "blob scrub: row's file is missing on disk"
                );
            }
            RowCheck::Mismatch(reason) => {
                stats.corrupted_files += 1;
                tracing::error!(cid = %row.cid, reason = %reason, "blob scrub: file failed integrity check");
            }
            RowCheck::Ok => unreachable!("handled by the early continue above"),
        }
    }

    // Orphan direction: files on disk no row owns. A full directory walk catches this — blob
    // GC only ever works from DB rows outward, so a leaked file (survived a botched delete, or
    // landed on the volume out of band) is invisible to it.
    let known_cids: HashSet<&str> = rows.iter().map(|r| r.cid.as_str()).collect();
    match walk_blob_files(&state.config.data_dir).await {
        Ok(files) => {
            for cid in files {
                if !known_cids.contains(cid.as_str()) {
                    stats.orphan_files += 1;
                    tracing::error!(cid = %cid, "blob scrub: file on disk has no owning blobs row (orphan)");
                }
            }
        }
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(error = %e, "blob scrub: failed to walk blob directory for orphans");
        }
    }

    let flagged = stats.flagged();
    if flagged > 0 || stats.healed > 0 || stats.errors > 0 {
        tracing::info!(
            scanned = stats.scanned,
            healed = stats.healed,
            missing_files = stats.missing_files,
            corrupted_files = stats.corrupted_files,
            orphan_files = stats.orphan_files,
            errors = stats.errors,
            "blob scrub pass complete"
        );
    } else {
        tracing::debug!(
            scanned = stats.scanned,
            "blob scrub pass complete (all verified)"
        );
    }

    // A failed-to-list pass returns early above, deliberately leaving these untouched: a stale
    // `blob_scrub_last_run_timestamp` is the operator's signal that scrubbing is not completing.
    state.metrics.blob_scrub_flagged.add(flagged, &[]);
    state.metrics.blob_scrub_healed.add(stats.healed, &[]);
    state
        .metrics
        .blob_scrub_last_run_timestamp
        .record(crate::metrics::unix_now(), &[]);
    state
        .sweeps
        .record_blob_scrub(crate::sweep_status::SweepRun::now(flagged));

    stats
}

/// Read one blob's local file and compare it against its row's size and CID.
async fn check_row(data_dir: &Path, row: &PhysicalBlob) -> Result<RowCheck, String> {
    let abs_path = data_dir.join(&row.storage_path);
    let content = match tokio::fs::read(&abs_path).await {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RowCheck::Missing),
        Err(e) => return Err(format!("read file: {e}")),
    };
    if content.len() as i64 != row.size_bytes {
        return Ok(RowCheck::Mismatch(format!(
            "size mismatch: file is {} bytes, row says {}",
            content.len(),
            row.size_bytes
        )));
    }
    let computed = blob_store::compute_cid(&content);
    if computed != row.cid {
        return Ok(RowCheck::Mismatch(format!(
            "content hash mismatch: bytes hash to {computed}"
        )));
    }
    Ok(RowCheck::Ok)
}

/// Attempt to repair a bad or missing file from the mirror bucket's verified copy. `Ok(true)`
/// on a successful heal, `Ok(false)` when the bucket has no copy either or the row is gone by
/// write time (an `Err` covers a transfer failure or a bucket copy that itself fails
/// verification — never trusted).
///
/// Writing goes through [`blob_store::store_blob`] — the same durable write path (temp file +
/// fsync + atomic rename) every upload uses — rather than a bespoke write, so a healed file is
/// exactly as crash-durable as a freshly uploaded one. Recomputing the CID here is redundant
/// (the content is already verified against `row.cid`) but harmless: the resulting path is
/// identical to `row.storage_path` by construction.
///
/// `row` comes from the scrub pass's `list_all_blobs` snapshot taken at the top of the pass,
/// but `blob_gc` runs independently and can reclaim the exact same CID (its last owner's grace
/// period expiring) between that snapshot and this write. Re-checking the row's existence
/// immediately before writing narrows that window to "one query, then one write" — without it,
/// a heal could resurrect bytes on disk with no owning row, creating precisely the orphan-file
/// leak this sweep exists to catch rather than cause.
async fn heal(state: &AppState, mirror: &BlobMirror, row: &PhysicalBlob) -> Result<bool, String> {
    let Some(content) = mirror.fetch_verified(row).await? else {
        return Ok(false);
    };
    if blobs::get_blob_by_cid(&state.db, &row.cid)
        .await
        .map_err(|e| format!("recheck row: {e}"))?
        .is_none()
    {
        return Ok(false);
    }
    blob_store::store_blob(&state.config.data_dir, &content, &row.mime_type)
        .await
        .map_err(|e| format!("write healed file: {e}"))?;
    Ok(true)
}

/// Walk `{data_dir}/blobs/{prefix}/{cid}` and return every stored CID found on disk (the
/// filename), skipping the durable write path's transient `.{cid}.{uuid}.tmp` staging files
/// (`blob_store::store_blob`) — a mid-write crash's leftover temp file is not a leaked blob.
///
/// `Ok(vec![])` when the blob directory doesn't exist yet (a fresh install with no uploads).
async fn walk_blob_files(data_dir: &Path) -> std::io::Result<Vec<String>> {
    let root = data_dir.join("blobs");
    let mut prefixes = match tokio::fs::read_dir(&root).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut cids = Vec::new();
    while let Some(prefix_entry) = prefixes.next_entry().await? {
        if !prefix_entry.file_type().await?.is_dir() {
            continue;
        }
        let mut files = tokio::fs::read_dir(prefix_entry.path()).await?;
        while let Some(file_entry) = files.next_entry().await? {
            if !file_entry.file_type().await?.is_file() {
                continue;
            }
            let name = file_entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue; // transient temp-write staging file, not a stored blob
            }
            cids.push(name);
        }
    }
    Ok(cids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_mirror::test_support::{add_blob, build_test_mirror, local_path};

    /// Test state with a real on-disk `data_dir` so file effects are observable, and no mirror
    /// configured (the "no bucket" scrub-only path).
    async fn scrub_state() -> (AppState, tempfile::TempDir) {
        let base = crate::app::test_state().await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = (*base.config).clone();
        config.data_dir = dir.path().to_path_buf();
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        (state, dir)
    }

    /// Store `content` under a freshly seeded account and return its CID (no mirror involved).
    async fn add_local_blob(state: &AppState, did: &str, content: &[u8]) -> String {
        add_blob(state, did, content, "application/octet-stream").await
    }

    #[tokio::test]
    async fn scrub_empty_instance_is_a_noop() {
        let (state, _dir) = scrub_state().await;
        let stats = run_blob_scrub(&state, None).await;
        assert_eq!(stats, ScrubStats::default());
    }

    #[tokio::test]
    async fn scrub_passes_healthy_blobs_untouched() {
        let (state, _dir) = scrub_state().await;
        add_local_blob(&state, "did:plc:scrubok", b"perfectly fine bytes").await;

        let stats = run_blob_scrub(&state, None).await;
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.flagged(), 0);
        assert_eq!(stats.healed, 0);
        assert_eq!(stats.errors, 0);

        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(rendered.contains("blob_scrub_flagged_total"));
        assert!(rendered.contains("blob_scrub_healed_total"));
        assert!(rendered.contains("blob_scrub_last_run_timestamp"));
        assert_eq!(state.sweeps.snapshot().blob_scrub.unwrap().swept, 0);
    }

    #[tokio::test]
    async fn scrub_flags_corrupted_file_without_mirror() {
        let (state, _dir) = scrub_state().await;
        let cid = add_local_blob(&state, "did:plc:scrubcorrupt", b"original bytes").await;
        tokio::fs::write(local_path(&state, &cid), b"corrupted bytes!")
            .await
            .unwrap();

        let stats = run_blob_scrub(&state, None).await;
        assert_eq!(stats.corrupted_files, 1);
        assert_eq!(stats.missing_files, 0);
        assert_eq!(stats.healed, 0);
        assert_eq!(stats.flagged(), 1);
        assert_eq!(state.sweeps.snapshot().blob_scrub.unwrap().swept, 1);

        // Never auto-heals with no mirror: the corrupt bytes are left exactly as they were.
        let on_disk = tokio::fs::read(local_path(&state, &cid)).await.unwrap();
        assert_eq!(on_disk, b"corrupted bytes!");
    }

    #[tokio::test]
    async fn scrub_flags_missing_file_without_mirror() {
        let (state, _dir) = scrub_state().await;
        let cid = add_local_blob(&state, "did:plc:scrubmissing", b"will be deleted").await;
        tokio::fs::remove_file(local_path(&state, &cid))
            .await
            .unwrap();

        let stats = run_blob_scrub(&state, None).await;
        assert_eq!(stats.missing_files, 1);
        assert_eq!(stats.corrupted_files, 0);
        assert_eq!(stats.flagged(), 1);
    }

    #[tokio::test]
    async fn scrub_heals_corrupted_file_from_mirror() {
        let (state, _dir, fake, mirror) = build_test_mirror().await;
        let cid = add_blob(&state, "did:plc:scrubheal", b"good bytes", "image/png").await;
        // Seed the bucket with the same good bytes, then corrupt the local file.
        fake.put(&format!("blobs/{cid}"), "image/png", b"good bytes".to_vec());
        tokio::fs::write(local_path(&state, &cid), b"corrupted!!")
            .await
            .unwrap();

        let stats = run_blob_scrub(&state, Some(&mirror)).await;
        assert_eq!(stats.healed, 1);
        assert_eq!(stats.flagged(), 0);
        assert_eq!(stats.errors, 0);

        let on_disk = tokio::fs::read(local_path(&state, &cid)).await.unwrap();
        assert_eq!(on_disk, b"good bytes", "the file must be repaired");
    }

    #[tokio::test]
    async fn scrub_heals_missing_file_from_mirror() {
        let (state, _dir, fake, mirror) = build_test_mirror().await;
        let cid = add_blob(&state, "did:plc:scrubhealmiss", b"restorable", "image/png").await;
        fake.put(&format!("blobs/{cid}"), "image/png", b"restorable".to_vec());
        tokio::fs::remove_file(local_path(&state, &cid))
            .await
            .unwrap();

        let stats = run_blob_scrub(&state, Some(&mirror)).await;
        assert_eq!(stats.healed, 1);
        assert_eq!(stats.missing_files, 0);
        let on_disk = tokio::fs::read(local_path(&state, &cid)).await.unwrap();
        assert_eq!(on_disk, b"restorable");
    }

    #[tokio::test]
    async fn heal_refuses_to_resurrect_a_blob_whose_row_was_deleted() {
        // The scrub pass's blob list is a snapshot taken at the top of the pass; blob_gc runs
        // independently and can reclaim the exact same CID (row + file) between that snapshot
        // and this heal's write. Simulate that race directly against `heal()`.
        let (state, _dir, fake, mirror) = build_test_mirror().await;
        let cid = add_blob(&state, "did:plc:scrubrace", b"raced bytes", "image/png").await;
        fake.put(
            &format!("blobs/{cid}"),
            "image/png",
            b"raced bytes".to_vec(),
        );

        let rows = blobs::list_all_blobs(&state.db).await.unwrap();
        let row = rows.iter().find(|r| r.cid == cid).unwrap().clone();

        // blob_gc reclaims the CID: ownership row, physical row, and file all gone.
        sqlx::query("DELETE FROM blob_owners WHERE cid = ?")
            .bind(&cid)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM blobs WHERE cid = ?")
            .bind(&cid)
            .execute(&state.db)
            .await
            .unwrap();
        tokio::fs::remove_file(local_path(&state, &cid))
            .await
            .unwrap();

        let healed = heal(&state, &mirror, &row).await.unwrap();
        assert!(
            !healed,
            "a CID blob_gc already reclaimed must never be resurrected"
        );
        assert!(
            tokio::fs::metadata(local_path(&state, &cid)).await.is_err(),
            "no file must appear on disk for a reclaimed CID with no owning row"
        );
    }

    #[tokio::test]
    async fn scrub_does_not_heal_when_auto_heal_disabled() {
        let (base, _dir, fake, mirror) = build_test_mirror().await;
        let mut config = (*base.config).clone();
        config.blob_scrub.auto_heal = false;
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        let cid = add_blob(&state, "did:plc:scrubnoheal", b"good bytes", "image/png").await;
        fake.put(&format!("blobs/{cid}"), "image/png", b"good bytes".to_vec());
        tokio::fs::write(local_path(&state, &cid), b"corrupted!!")
            .await
            .unwrap();

        let stats = run_blob_scrub(&state, Some(&mirror)).await;
        assert_eq!(stats.healed, 0, "auto_heal = false must never write a fix");
        assert_eq!(stats.corrupted_files, 1);
        let on_disk = tokio::fs::read(local_path(&state, &cid)).await.unwrap();
        assert_eq!(on_disk, b"corrupted!!", "local file must be left untouched");
    }

    #[tokio::test]
    async fn scrub_never_trusts_a_corrupt_bucket_copy() {
        let (state, _dir, fake, mirror) = build_test_mirror().await;
        let cid = add_blob(&state, "did:plc:scrubbadbucket", b"true bytes", "image/png").await;
        // The bucket copy is itself wrong (bitrot, tampering); the local file is also bad.
        fake.put(
            &format!("blobs/{cid}"),
            "image/png",
            b"evil bytes!".to_vec(),
        );
        tokio::fs::write(local_path(&state, &cid), b"also bad")
            .await
            .unwrap();

        let stats = run_blob_scrub(&state, Some(&mirror)).await;
        assert_eq!(
            stats.healed, 0,
            "an unverifiable bucket copy is never trusted"
        );
        assert_eq!(stats.corrupted_files, 1, "the problem is still flagged");
        assert_eq!(stats.errors, 1, "the failed heal attempt is counted");
        let on_disk = tokio::fs::read(local_path(&state, &cid)).await.unwrap();
        assert_eq!(
            on_disk, b"also bad",
            "unverified bytes must never overwrite the file"
        );
    }

    #[tokio::test]
    async fn scrub_detects_orphan_file_with_no_owning_row() {
        let (state, _dir) = scrub_state().await;
        // A file lands on the volume via the store's own writer, but no `blobs` row is ever
        // inserted for it (the leak direction blob_gc never scans for — it only works from
        // DB rows outward).
        let stored =
            blob_store::store_blob(&state.config.data_dir, b"nobody owns me", "text/plain")
                .await
                .unwrap();

        let stats = run_blob_scrub(&state, None).await;
        assert_eq!(stats.orphan_files, 1);
        assert_eq!(stats.flagged(), 1);
        // The orphan file is left alone — the scrub only ever reports, never deletes.
        assert!(
            tokio::fs::metadata(state.config.data_dir.join(&stored.storage_path))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn scrub_ignores_known_blobs_when_scanning_for_orphans() {
        let (state, _dir) = scrub_state().await;
        add_local_blob(&state, "did:plc:scrubknown", b"a known good blob").await;

        let stats = run_blob_scrub(&state, None).await;
        assert_eq!(stats.orphan_files, 0);
    }

    #[tokio::test]
    async fn walk_blob_files_returns_empty_for_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let files = walk_blob_files(dir.path()).await.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn walk_blob_files_skips_temp_files_and_finds_real_ones() {
        let dir = tempfile::tempdir().unwrap();
        let stored = blob_store::store_blob(dir.path(), b"real blob bytes", "text/plain")
            .await
            .unwrap();
        // A leftover temp-write staging file from a crashed store_blob call.
        let prefix_dir = dir
            .path()
            .join(stored.storage_path.rsplit_once('/').unwrap().0);
        tokio::fs::write(
            prefix_dir.join(format!(".{}.deadbeef.tmp", stored.cid)),
            b"partial",
        )
        .await
        .unwrap();

        let files = walk_blob_files(dir.path()).await.unwrap();
        assert_eq!(files, vec![stored.cid]);
    }

    #[tokio::test]
    async fn scrub_failed_list_leaves_timestamp_stale() {
        // Regression guard for the failed-pass posture: a scrub run against a pool whose
        // `blobs` table doesn't exist must not record any instrument.
        let (state, _dir) = scrub_state().await;
        sqlx::query("DROP TABLE blobs")
            .execute(&state.db)
            .await
            .unwrap();

        let stats = run_blob_scrub(&state, None).await;
        assert_eq!(stats, ScrubStats::default());
        assert!(state.sweeps.snapshot().blob_scrub.is_none());
        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(!rendered.contains("blob_scrub_last_run_timestamp"));
    }
}
