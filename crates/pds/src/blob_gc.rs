// pattern: Imperative Shell
//
//! Blob garbage collection.
//!
//! A periodic background task that reclaims blobs no other part of the system needs. Blob
//! ownership is per-account (`blob_owners`, V039) over globally content-addressed bytes, so the
//! collector works reference-by-reference and touches the shared file only when the last owner
//! is gone. It runs in two phases on each pass:
//!
//! 1. **Reconcile** — for every account that owns a blob reference *or has a repo*, recompute
//!    which blob CIDs its records actually reference (by walking the MST) and write that truth
//!    back to `blob_owners`: referenced blobs get a permanent ownership row (`ref_count` set,
//!    `temp_until` cleared — created on the spot if the account references a stored blob it
//!    never uploaded, which also heals pre-V039 rows that credited only the first uploader);
//!    a reference that has lost its last record is *released* — its grace clock starts.
//! 2. **Sweep** — delete every ownership row whose grace period has expired and which the
//!    account no longer references (`temp_until < now AND ref_count = 0`); when a CID's last
//!    ownership row goes, delete the physical metadata row and the filesystem file.
//!
//! Recomputing references from the MST each pass makes the collector authoritative rather than
//! trusting an incrementally maintained counter: a blob that is still reachable from any repo
//! record is never deleted, and a blob that fell out of every record is eventually collected
//! even if some earlier decrement was missed. The grace period means a reference is only ever
//! expired on a *later* pass than the one that released it, leaving a window for in-flight
//! uploads and writes.

use std::collections::HashMap;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::blob_store;
use crate::db::accounts;
use crate::db::blobs;
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
    /// Ownership rows confirmed still referenced and (re)marked permanent (or newly adopted).
    pub reconciled: u64,
    /// Ownership rows that lost their last reference this pass and started their grace clock.
    pub released: u64,
    /// Expired ownership rows removed this pass.
    pub expired: u64,
    /// Physical blobs deleted (filesystem file + SQLite row) after their last owner expired.
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

/// Run a single garbage-collection pass over every account that owns blobs or has a repo.
///
/// Resilient by design: an error reconciling one account, or deleting one blob, is logged and
/// counted in [`GcStats::errors`] but does not stop the pass. Reconciling (which adopts
/// referenced-but-unowned blobs into `blob_owners`) always runs before the sweep, so a
/// reference discovered this pass is protected before any file can be reclaimed.
pub async fn run_blob_gc(state: &AppState) -> GcStats {
    let mut stats = GcStats::default();

    // Phase 1: reconcile each account's blob references against its MST.
    let candidate_dids = match blobs::list_gc_candidate_dids(&state.db).await {
        Ok(dids) => dids,
        Err(e) => {
            tracing::error!(error = %e, "blob GC: failed to list candidate accounts; skipping pass");
            return stats;
        }
    };
    for did in candidate_dids {
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

    // Phase 2: sweep ownership rows whose grace period has expired; reclaim the physical row
    // and file once a CID's last owner is gone.
    match blobs::list_expired_temp_owners(&state.db).await {
        Ok(expired) => {
            for (did, cid) in expired {
                match sweep_expired_owner(state, &did, &cid).await {
                    Ok((owner_expired, file_deleted)) => {
                        stats.expired += u64::from(owner_expired);
                        stats.deleted += u64::from(file_deleted);
                    }
                    Err(e) => {
                        stats.errors += 1;
                        tracing::warn!(error = %e, did = %did, cid = %cid, "blob GC: failed to sweep expired blob reference");
                    }
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "blob GC: failed to list expired blob references"),
    }

    if stats.deleted > 0 || stats.expired > 0 || stats.released > 0 || stats.errors > 0 {
        tracing::info!(
            reconciled = stats.reconciled,
            released = stats.released,
            expired = stats.expired,
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

    // A failed-to-start pass (the early return above) deliberately does not touch the
    // timestamp: a stale `blob_gc_last_run_timestamp` is the operator's signal that
    // sweeps are not completing.
    state.metrics.blob_gc_swept.add(stats.deleted, &[]);
    state
        .metrics
        .blob_gc_last_run_timestamp
        .record(crate::metrics::unix_now(), &[]);

    stats
}

/// Reconcile one account's blob ownership rows against the references in its repo.
///
/// Returns `(reconciled, released)`: the number of ownership rows (re)marked permanent —
/// created on the spot when the account references a stored blob it has no row for — and the
/// number that transitioned from permanent to temporary (lost their last reference) this pass.
async fn reconcile_account(state: &AppState, did: &str) -> Result<(u64, u64), GcError> {
    let referenced = collect_referenced_blob_cids(state, did).await?;
    let owned = blobs::list_owned_blobs(&state.db, did).await?;

    // A fresh grace deadline for references that lose their last record this pass.
    // Format must match SQLite's `datetime('now')` (`YYYY-MM-DD HH:MM:SS`): `temp_until` is
    // stored as TEXT and compared lexicographically, so a `T`/`Z` ISO form would sort after
    // the space-separated form and hide same-day deadlines from `list_expired_temp_owners`.
    let grace =
        chrono::Utc::now() + chrono::Duration::seconds(state.config.blobs.temp_ttl_secs as i64);
    let grace_str = grace.format("%Y-%m-%d %H:%M:%S").to_string();

    let mut reconciled = 0;
    let mut released = 0;

    // Every CID this account's records reference: pin (or adopt) it permanent with the true
    // count. Non-blob CID links in the reference walk are no-ops (no physical `blobs` row).
    for (cid, n) in &referenced {
        if blobs::upsert_owner_referenced(&state.db, did, cid, *n).await? {
            reconciled += 1;
        }
    }

    // Every owned reference no record uses any longer: if it was permanent, start its grace
    // clock; a reference already counting down (temp_until set) is left to expire.
    for owner in owned {
        if !referenced.contains_key(&owner.cid)
            && blobs::release_owner(&state.db, did, &owner.cid, &grace_str).await?
        {
            released += 1;
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

/// Sweep one expired ownership row, reclaiming the physical blob when it was the last owner.
///
/// Returns `(owner_expired, file_deleted)`. The ownership delete re-checks the expiry
/// conditions (a reference re-pinned since the candidate scan survives), and the physical
/// delete checks for remaining owners in the same statement that removes the row, so a CID
/// another account still owns is never touched. The file is unlinked only after its row is
/// gone: the DB is the source of truth, and that ordering's failure mode is an orphaned file
/// (a benign leak, logged), never a live row pointing at deleted bytes.
async fn sweep_expired_owner(
    state: &AppState,
    did: &str,
    cid: &str,
) -> Result<(bool, bool), GcError> {
    if !blobs::delete_expired_owner(&state.db, did, cid).await? {
        return Ok((false, false));
    }
    tracing::debug!(cid = %cid, did = %did, "blob GC: expired blob reference removed");

    let Some(storage_path) = blobs::delete_blob_if_unowned(&state.db, cid).await? else {
        // Another account still owns the CID; its bytes stay.
        return Ok((true, false));
    };

    let existed = blob_store::delete_blob_file(&state.config.data_dir, &storage_path)
        .await
        .map_err(|e| GcError::BlobStore(format!("delete blob file: {e}")))?;
    if !existed {
        tracing::warn!(
            cid = %cid,
            path = %storage_path,
            "blob GC: file already absent on disk; row already removed"
        );
    }

    tracing::info!(cid = %cid, "blob GC: deleted unreferenced blob");
    Ok((true, true))
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
        let stored = blob_store::store_blob(&state.config.data_dir, content)
            .await
            .unwrap();
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
        assert_eq!(stats.expired, 1, "only the orphan's ownership row expired");
        assert_eq!(stats.errors, 0);

        // The sweep's instruments fire: the deletion is counted and the pass is timestamped.
        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("blob_gc_swept_total"),
            "missing blob_gc_swept_total in:\n{rendered}"
        );
        assert!(
            rendered.contains("blob_gc_last_run_timestamp"),
            "missing blob_gc_last_run_timestamp in:\n{rendered}"
        );

        // Referenced blob: pinned permanent, file intact.
        assert!(blobs::get_blob_by_cid(&state.db, &referenced)
            .await
            .unwrap()
            .is_some());
        let kept = blobs::get_owner(&state.db, did, &referenced)
            .await
            .unwrap()
            .expect("referenced blob's ownership row must survive");
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
        assert!(blobs::get_owner(&state.db, did, &cid)
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
        let released = blobs::get_owner(&state.db, did, &cid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(released.ref_count, 0);
        assert!(released.temp_until.is_some(), "grace clock must be started");
        assert!(blob_file_exists(&state, &cid), "file kept during grace");

        // Force the grace clock into the past; the next pass deletes the blob.
        sqlx::query("UPDATE blob_owners SET temp_until = '2020-01-01T00:00:00Z' WHERE cid = ?")
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

    /// Two accounts upload the same bytes; only B references them. A's expired
    /// reference must never destroy the file B's record still links.
    #[tokio::test]
    async fn gc_keeps_shared_blob_while_any_owner_references_it() {
        let (state, _dir) = gc_state().await;
        let did_a = "did:plc:gcshare-a";
        let did_b = "did:plc:gcshare-b";
        seed_account_with_repo(&state.db, did_a).await;
        seed_account_with_repo(&state.db, did_b).await;

        // Both upload identical bytes; A's grace clock is already expired, B references it.
        let cid = add_blob(&state, did_a, b"shared blob bytes", "2020-01-01T00:00:00Z").await;
        let cid_b = add_blob(&state, did_b, b"shared blob bytes", "2020-01-01T00:00:00Z").await;
        assert_eq!(cid, cid_b, "same content must produce the same CID");
        write_record(&state, did_b, "app.bsky.feed.post/1", blob_record(&cid)).await;

        let stats = run_blob_gc(&state).await;
        assert_eq!(stats.expired, 1, "A's unreferenced ownership row expires");
        assert_eq!(stats.deleted, 0, "the shared file must survive");
        assert_eq!(stats.errors, 0);

        assert!(
            blobs::get_owner(&state.db, did_a, &cid)
                .await
                .unwrap()
                .is_none(),
            "A's expired reference is gone"
        );
        let owner_b = blobs::get_owner(&state.db, did_b, &cid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner_b.ref_count, 1);
        assert!(owner_b.temp_until.is_none(), "B's reference is permanent");
        assert!(blobs::get_blob_by_cid(&state.db, &cid)
            .await
            .unwrap()
            .is_some());
        assert!(
            blob_file_exists(&state, &cid),
            "B's referenced file must survive"
        );

        // Once B's record goes too, the blob is released, expires, and only then is deleted.
        delete_record(&state, did_b, "app.bsky.feed.post/1").await;
        run_blob_gc(&state).await;
        sqlx::query("UPDATE blob_owners SET temp_until = '2020-01-01T00:00:00Z' WHERE cid = ?")
            .bind(&cid)
            .execute(&state.db)
            .await
            .unwrap();
        let stats = run_blob_gc(&state).await;
        assert_eq!(stats.deleted, 1);
        assert!(!blob_file_exists(&state, &cid));
    }

    /// Pre-V039 implicit sharing: B's record references a stored blob B has no ownership row
    /// for (the old single-owner row credited A). The reconcile pass must adopt the reference
    /// into `blob_owners` before any sweep can reclaim the file.
    #[tokio::test]
    async fn gc_adopts_referenced_blob_the_account_never_uploaded() {
        let (state, _dir) = gc_state().await;
        let did_a = "did:plc:gcadopt-a";
        let did_b = "did:plc:gcadopt-b";
        seed_account_with_repo(&state.db, did_a).await;
        seed_account_with_repo(&state.db, did_b).await;

        // Only A holds an (expired, unreferenced) ownership row; B references the CID.
        let cid = add_blob(
            &state,
            did_a,
            b"implicitly shared bytes",
            "2020-01-01T00:00:00Z",
        )
        .await;
        write_record(&state, did_b, "app.bsky.feed.post/1", blob_record(&cid)).await;

        let stats = run_blob_gc(&state).await;
        assert_eq!(stats.deleted, 0, "adoption must beat the sweep");
        assert_eq!(stats.errors, 0);

        let owner_b = blobs::get_owner(&state.db, did_b, &cid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner_b.ref_count, 1);
        assert!(owner_b.temp_until.is_none());
        assert!(blob_file_exists(&state, &cid), "adopted file must survive");
    }
}
