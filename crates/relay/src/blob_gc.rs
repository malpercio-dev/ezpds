// pattern: Imperative Shell
//
//! Blob garbage collection.
//!
//! A periodic background task that reclaims blobs no other part of the system needs. It runs
//! in two phases on each pass:
//!
//! 1. **Reconcile** — for every repo that owns blobs, recompute which blob CIDs its records
//!    actually reference (by walking the MST) and write that truth back to the `blobs` table:
//!    referenced blobs become permanent (`ref_count` set, `temp_until` cleared); a blob that
//!    has lost its last reference is *released* — its grace clock (`temp_until`) starts.
//! 2. **Sweep** — delete every blob whose grace period has expired and which nothing
//!    references (`temp_until < now AND ref_count = 0`), removing both the filesystem file and
//!    the SQLite row.
//!
//! Recomputing references from the MST each pass makes the collector authoritative rather than
//! trusting an incrementally maintained counter: a blob that is still reachable from a repo
//! record is never deleted, and a blob that fell out of every record is eventually collected
//! even if some earlier decrement was missed. The grace period means a blob is only ever
//! deleted on a *later* pass than the one that released it, leaving a window for in-flight
//! uploads and writes.

use std::collections::HashMap;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::blob_store;
use crate::db::accounts;
use crate::db::blobs::{self, BlobRow};
use crate::db::blocks::SqliteBlockStore;
use repo_engine::{Cid, Repository};

/// Records read per page when walking a collection to collect blob references.
const RECORD_PAGE_SIZE: usize = 100;

/// Errors that can abort garbage collection for a single account.
///
/// A failure here is logged and the offending account is skipped; it never aborts the whole
/// pass or the background task.
#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("repo error: {0}")]
    Repo(String),
    #[error("blob store error: {0}")]
    BlobStore(String),
}

/// Tally of what one garbage-collection pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcStats {
    /// Blobs confirmed still referenced and (re)marked permanent.
    pub reconciled: u64,
    /// Blobs that lost their last reference this pass and started their grace clock.
    pub released: u64,
    /// Blobs deleted (filesystem file + SQLite row).
    pub deleted: u64,
    /// Accounts or blobs skipped due to an error.
    pub errors: u64,
}

/// Spawn the periodic blob garbage collector.
///
/// The first interval tick is consumed without running GC, so the server does not perform a
/// full repo scan during startup; the first pass runs one `interval` after boot. The task
/// loops for the life of the process and is dropped on shutdown.
pub fn spawn_blob_gc(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // `interval`'s first tick fires immediately — skip it so GC doesn't run mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_blob_gc(&state).await;
        }
    })
}

/// Run a single garbage-collection pass over every repo that owns blobs.
///
/// Resilient by design: an error reconciling one account, or deleting one blob, is logged and
/// counted in [`GcStats::errors`] but does not stop the pass.
pub async fn run_blob_gc(state: &AppState) -> GcStats {
    let mut stats = GcStats::default();

    // Phase 1: reconcile each repo's blob references against its MST.
    let owner_dids = match blobs::list_blob_owner_dids(&state.db).await {
        Ok(dids) => dids,
        Err(e) => {
            tracing::error!(error = %e, "blob GC: failed to list blob owners; skipping pass");
            return stats;
        }
    };
    for did in owner_dids {
        match reconcile_account(state, &did).await {
            Ok((reconciled, released)) => {
                stats.reconciled += reconciled;
                stats.released += released;
            }
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(error = %e, did = %did, "blob GC: reconcile failed; account skipped");
            }
        }
    }

    // Phase 2: sweep blobs whose grace period has expired and which nothing references.
    match blobs::list_expired_temps(&state.db).await {
        Ok(expired) => {
            for blob in expired {
                match delete_blob_fully(state, &blob).await {
                    Ok(()) => stats.deleted += 1,
                    Err(e) => {
                        stats.errors += 1;
                        tracing::warn!(error = %e, cid = %blob.cid, "blob GC: failed to delete expired blob");
                    }
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "blob GC: failed to list expired blobs"),
    }

    if stats.deleted > 0 || stats.released > 0 || stats.errors > 0 {
        tracing::info!(
            reconciled = stats.reconciled,
            released = stats.released,
            deleted = stats.deleted,
            errors = stats.errors,
            "blob GC pass complete"
        );
    } else {
        tracing::debug!(
            reconciled = stats.reconciled,
            "blob GC pass complete (nothing to collect)"
        );
    }

    stats
}

/// Reconcile one account's blobs against the references in its repo.
///
/// Returns `(reconciled, released)`: the number of blobs (re)marked permanent and the number
/// that transitioned from permanent to temporary (lost their last reference) this pass.
async fn reconcile_account(state: &AppState, did: &str) -> Result<(u64, u64), GcError> {
    let referenced = collect_referenced_blob_cids(state, did).await?;
    let owned = blobs::list_blobs_for_account(&state.db, did).await?;

    // A fresh grace deadline for blobs that lose their last reference this pass.
    // Format must match SQLite's `datetime('now')` (`YYYY-MM-DD HH:MM:SS`): `temp_until` is
    // stored as TEXT and compared lexicographically, so a `T`/`Z` ISO form would sort after
    // the space-separated form and hide same-day deadlines from `list_expired_temps`.
    let grace =
        chrono::Utc::now() + chrono::Duration::seconds(state.config.blobs.temp_ttl_secs as i64);
    let grace_str = grace.format("%Y-%m-%d %H:%M:%S").to_string();

    let mut reconciled = 0;
    let mut released = 0;
    for blob in owned {
        match referenced.get(&blob.cid).copied() {
            Some(n) if n > 0 => {
                // Still referenced: pin it permanent with the true reference count.
                if blobs::set_blob_referenced(&state.db, &blob.cid, n).await? {
                    reconciled += 1;
                }
            }
            _ => {
                // No record references it. If it was permanent, start its grace clock;
                // a blob already counting down (temp_until set) is left to expire.
                if blobs::release_blob(&state.db, &blob.cid, &grace_str).await? {
                    released += 1;
                }
            }
        }
    }

    Ok((reconciled, released))
}

/// Walk an account's repo and count how many records reference each blob CID.
///
/// Returns an empty map when the account has no repo root (nothing can reference a blob).
async fn collect_referenced_blob_cids(
    state: &AppState,
    did: &str,
) -> Result<HashMap<String, i64>, GcError> {
    let mut counts: HashMap<String, i64> = HashMap::new();

    let root_str = match accounts::get_repo_root_cid(&state.db, did).await? {
        Some(root) => root,
        None => return Ok(counts),
    };
    let root_cid = Cid::try_from(root_str.as_str())
        .map_err(|e| GcError::Repo(format!("invalid root CID {root_str}: {e}")))?;

    let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = Repository::open(store, root_cid)
        .await
        .map_err(|e| GcError::Repo(format!("open repo: {e}")))?;

    let collections = repo_engine::list_collections(&mut repo)
        .await
        .map_err(|e| GcError::Repo(format!("list collections: {e}")))?;

    for collection in collections {
        let mut cursor: Option<String> = None;
        loop {
            let page = repo_engine::list_records_json(
                &mut repo,
                &collection,
                RECORD_PAGE_SIZE,
                cursor.as_deref(),
                false,
            )
            .await
            .map_err(|e| GcError::Repo(format!("list records: {e}")))?;

            for record in &page.records {
                collect_blob_links(&record.value, &mut counts);
            }

            match page.cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }

    Ok(counts)
}

/// Recursively collect CID-link strings from a record's JSON, tallying each occurrence.
///
/// A CID link is encoded as a single-key object `{"$link": "<cid>"}` (see
/// [`repo_engine::record_value_to_json`]); a blob reference embeds one under its `ref` field.
/// Non-blob links are collected too, but they simply never match a row in the `blobs` table,
/// so they are harmless noise to the caller.
fn collect_blob_links(value: &serde_json::Value, out: &mut HashMap<String, i64>) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            if map.len() == 1 {
                if let Some(Value::String(cid)) = map.get("$link") {
                    *out.entry(cid.clone()).or_insert(0) += 1;
                    return;
                }
            }
            for v in map.values() {
                collect_blob_links(v, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_blob_links(item, out);
            }
        }
        _ => {}
    }
}

/// Delete a blob entirely: remove its filesystem file, then its SQLite row.
///
/// A missing file is tolerated (the delete is idempotent) but logged, since file and row are
/// expected to stay in lockstep. The row is removed only after the file delete succeeds.
async fn delete_blob_fully(state: &AppState, blob: &BlobRow) -> Result<(), GcError> {
    let existed = blob_store::delete_blob_file(&state.config.data_dir, &blob.storage_path)
        .map_err(|e| GcError::BlobStore(format!("delete blob file: {e}")))?;
    if !existed {
        tracing::warn!(
            cid = %blob.cid,
            path = %blob.storage_path,
            "blob GC: file already absent on disk; removing row anyway"
        );
    }

    blobs::delete_blob(&state.db, &blob.cid).await?;

    tracing::info!(
        cid = %blob.cid,
        did = %blob.account_did,
        size = blob.size_bytes,
        "blob GC: deleted unreferenced blob"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_utils::{seed_account_with_repo, test_master_key};
    use serde_json::json;
    use std::sync::Arc;

    // ── Pure helper: collect_blob_links ─────────────────────────────────────────

    #[test]
    fn collect_blob_links_finds_nested_and_counts_occurrences() {
        let record = json!({
            "$type": "app.bsky.feed.post",
            "text": "hi",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    { "image": { "$type": "blob", "ref": { "$link": "bafkreiAAA" }, "mimeType": "image/png", "size": 10 } },
                    { "image": { "$type": "blob", "ref": { "$link": "bafkreiBBB" }, "mimeType": "image/png", "size": 20 } },
                    { "image": { "$type": "blob", "ref": { "$link": "bafkreiAAA" }, "mimeType": "image/png", "size": 10 } }
                ]
            }
        });
        let mut out = HashMap::new();
        collect_blob_links(&record, &mut out);

        assert_eq!(out.get("bafkreiAAA"), Some(&2));
        assert_eq!(out.get("bafkreiBBB"), Some(&1));
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn collect_blob_links_ignores_records_without_links() {
        let record = json!({ "text": "no blobs here", "count": 3, "nested": { "a": [1, 2, 3] } });
        let mut out = HashMap::new();
        collect_blob_links(&record, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn collect_blob_links_does_not_treat_multikey_object_as_link() {
        // A two-key object that happens to contain $link is not a CID link leaf.
        let record = json!({ "$link": "bafkreiX", "extra": 1 });
        let mut out = HashMap::new();
        collect_blob_links(&record, &mut out);
        assert!(out.is_empty());
    }

    // ── Integration: run_blob_gc ────────────────────────────────────────────────

    /// Test state with a real on-disk data_dir (so file deletes are observable) and the
    /// signing-key master key configured (so test records can be written into the repo).
    async fn gc_state() -> (AppState, tempfile::TempDir) {
        let base = crate::app::test_state().await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = (*base.config).clone();
        config.data_dir = dir.path().to_path_buf();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        (state, dir)
    }

    /// Store `content` as a blob on disk and insert its metadata row with the given
    /// `temp_until`. Returns the blob CID.
    async fn add_blob(state: &AppState, did: &str, content: &[u8], temp_until: &str) -> String {
        let stored = blob_store::store_blob(&state.config.data_dir, content).unwrap();
        blobs::insert_blob(
            &state.db,
            &stored.cid,
            did,
            &stored.mime_type,
            stored.size_bytes as i64,
            &stored.storage_path,
            temp_until,
        )
        .await
        .unwrap();
        stored.cid
    }

    /// True if a blob's file still exists on disk.
    fn blob_file_exists(state: &AppState, cid: &str) -> bool {
        let prefix = &cid[..2.min(cid.len())];
        state
            .config
            .data_dir
            .join(format!("blobs/{prefix}/{cid}"))
            .exists()
    }

    /// Write a record into the account's repo and advance the persisted root.
    async fn write_record(state: &AppState, did: &str, key: &str, value: serde_json::Value) {
        let master = test_master_key();
        let root_str = accounts::get_repo_root_cid(&state.db, did)
            .await
            .unwrap()
            .unwrap();
        let root = Cid::try_from(root_str.as_str()).unwrap();
        let signer = crate::auth::signing_key::load_repo_signer(&state.db, did, &master)
            .await
            .unwrap();
        let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let mut repo = Repository::open(store, root).await.unwrap();
        repo_engine::put_record_json(&mut repo, &signer, key, &value)
            .await
            .unwrap();
        let new_root = repo.root().to_string();
        sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ?")
            .bind(&new_root)
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
    }

    /// Delete a record from the account's repo and advance the persisted root.
    async fn delete_record(state: &AppState, did: &str, key: &str) {
        let master = test_master_key();
        let root_str = accounts::get_repo_root_cid(&state.db, did)
            .await
            .unwrap()
            .unwrap();
        let root = Cid::try_from(root_str.as_str()).unwrap();
        let signer = crate::auth::signing_key::load_repo_signer(&state.db, did, &master)
            .await
            .unwrap();
        let store = SqliteBlockStore::new(state.db.clone(), did.to_string());
        let mut repo = Repository::open(store, root).await.unwrap();
        repo_engine::delete_record(&mut repo, &signer, key)
            .await
            .unwrap();
        let new_root = repo.root().to_string();
        sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ?")
            .bind(&new_root)
            .bind(did)
            .execute(&state.db)
            .await
            .unwrap();
    }

    fn blob_record(cid: &str) -> serde_json::Value {
        json!({
            "$type": "app.bsky.feed.post",
            "text": "look at this",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    { "image": { "$type": "blob", "ref": { "$link": cid }, "mimeType": "image/png", "size": 10 } }
                ]
            }
        })
    }

    #[tokio::test]
    async fn gc_keeps_referenced_blob_and_deletes_unreferenced() {
        let (state, _dir) = gc_state().await;
        let did = "did:plc:gckeep";
        seed_account_with_repo(&state.db, did).await;

        // Both blobs start expired; the referenced one must be rescued before the sweep.
        let referenced = add_blob(
            &state,
            did,
            b"referenced blob bytes",
            "2020-01-01T00:00:00Z",
        )
        .await;
        let orphan = add_blob(&state, did, b"orphan blob bytes", "2020-01-01T00:00:00Z").await;

        write_record(
            &state,
            did,
            "app.bsky.feed.post/1",
            blob_record(&referenced),
        )
        .await;

        let stats = run_blob_gc(&state).await;
        assert_eq!(stats.deleted, 1, "exactly the orphan blob is deleted");
        assert_eq!(stats.errors, 0);

        // Referenced blob: pinned permanent, file intact.
        let kept = blobs::get_blob_by_cid(&state.db, &referenced)
            .await
            .unwrap()
            .expect("referenced blob must survive");
        assert_eq!(kept.ref_count, 1);
        assert!(
            kept.temp_until.is_none(),
            "referenced blob must be permanent"
        );
        assert!(blob_file_exists(&state, &referenced));

        // Orphan blob: row and file both gone.
        assert!(blobs::get_blob_by_cid(&state.db, &orphan)
            .await
            .unwrap()
            .is_none());
        assert!(!blob_file_exists(&state, &orphan));
    }

    #[tokio::test]
    async fn gc_releases_then_deletes_after_record_removed() {
        let (state, _dir) = gc_state().await;
        let did = "did:plc:gcrelease";
        seed_account_with_repo(&state.db, did).await;

        // Upload + reference a blob, then let GC pin it permanent.
        let cid = add_blob(&state, did, b"soon to be orphaned", "2020-01-01T00:00:00Z").await;
        write_record(&state, did, "app.bsky.feed.post/1", blob_record(&cid)).await;
        run_blob_gc(&state).await;
        assert!(blobs::get_blob_by_cid(&state.db, &cid)
            .await
            .unwrap()
            .unwrap()
            .temp_until
            .is_none());

        // Delete the referencing record; GC should release (not delete) the blob.
        delete_record(&state, did, "app.bsky.feed.post/1").await;
        let stats = run_blob_gc(&state).await;
        assert_eq!(stats.released, 1);
        assert_eq!(stats.deleted, 0, "still within grace period");
        let released = blobs::get_blob_by_cid(&state.db, &cid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(released.ref_count, 0);
        assert!(released.temp_until.is_some(), "grace clock must be started");
        assert!(blob_file_exists(&state, &cid), "file kept during grace");

        // Force the grace clock into the past; the next pass deletes the blob.
        sqlx::query("UPDATE blobs SET temp_until = '2020-01-01T00:00:00Z' WHERE cid = ?")
            .bind(&cid)
            .execute(&state.db)
            .await
            .unwrap();
        let stats = run_blob_gc(&state).await;
        assert_eq!(stats.deleted, 1);
        assert!(blobs::get_blob_by_cid(&state.db, &cid)
            .await
            .unwrap()
            .is_none());
        assert!(!blob_file_exists(&state, &cid));
    }

    #[tokio::test]
    async fn gc_no_blobs_is_a_noop() {
        let (state, _dir) = gc_state().await;
        let stats = run_blob_gc(&state).await;
        assert_eq!(stats, GcStats::default());
    }
}
