// pattern: Imperative Shell

//! Blob metadata store.
//!
//! Mirrors the repo-block split (`db/blocks.rs`, V035): `blobs` stores the physical
//! content-addressed metadata once per CID (the on-disk file is likewise stored once), while
//! `blob_owners` records each account's reference to that CID together with the per-account
//! lifecycle (`ref_count`, `temp_until`). One account releasing or deleting its reference never
//! destroys a file another account's records still link — the physical row and file are
//! reclaimed only when the last owner is gone.

use sqlx::SqlitePool;

use super::blocks::SqliteTransaction;

/// Row returned from the physical `blobs` table.
///
/// `account_did` is the first uploader, kept for diagnostics only — `blob_owners` is
/// authoritative for ownership. Lifecycle columns live on the ownership rows ([`BlobOwnerRow`]).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlobRow {
    // `account_did`/`size_bytes`/`created_at` are mapped from `SELECT *` so the row mirrors
    // the table, but the live read paths only consume `cid`/`mime_type`/`storage_path`;
    // the rest back tests and diagnostics.
    pub cid: String,
    #[allow(dead_code)]
    pub account_did: String,
    pub mime_type: String,
    #[allow(dead_code)]
    pub size_bytes: i64,
    pub storage_path: String,
    #[allow(dead_code)]
    pub created_at: String,
}

/// One account's ownership row for a blob CID.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlobOwnerRow {
    pub cid: String,
    /// Number of this account's repo records referencing the blob (maintained by blob GC).
    /// Read by tests; the lifecycle transitions themselves operate in SQL, not off the struct.
    #[allow(dead_code)]
    pub ref_count: i64,
    /// Grace-period deadline while the blob is unreferenced by this account; NULL = permanent.
    /// Read by tests; the expiry sweep operates in SQL, not off the struct.
    #[allow(dead_code)]
    pub temp_until: Option<String>,
}

/// Insert blob metadata for an upload: the physical row (once per CID) and this account's
/// ownership row.
///
/// `temp_until` should be set to now + the configured grace TTL for uploads that haven't been
/// referenced by a repo record yet.
///
/// Both statements are idempotent, matching ATProto's uploadBlob semantics (content-addressable,
/// same content = same CID = no error). The physical row keeps the first uploader's metadata;
/// the ownership upsert restarts *this account's* grace clock on a re-upload — but only while
/// the account's reference count is zero, so re-uploading an already-referenced (permanent)
/// blob never puts it back on a deletion countdown.
///
/// The two inserts run in one transaction (a single logical "record this upload" operation,
/// like the paired physical/ownership write in `blocks::put_block`): a physical row committed
/// without its ownership row would never be revisited by GC's sweep, which walks `blob_owners`.
pub async fn insert_blob(
    pool: &SqlitePool,
    cid: &str,
    account_did: &str,
    mime_type: &str,
    size_bytes: i64,
    storage_path: &str,
    temp_until: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(cid) DO NOTHING",
    )
    .bind(cid)
    .bind(account_did)
    .bind(mime_type)
    .bind(size_bytes)
    .bind(storage_path)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO blob_owners (cid, account_did, temp_until)
         VALUES (?, ?, ?)
         ON CONFLICT(account_did, cid) DO UPDATE SET temp_until = excluded.temp_until
         WHERE blob_owners.ref_count = 0",
    )
    .bind(cid)
    .bind(account_did)
    .bind(temp_until)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Sum of bytes referenced by a specific account's blob ownership rows.
///
/// Used to enforce per-user storage quotas. Content shared across accounts counts against
/// every owner — each account pays for what its records keep alive.
pub async fn account_storage_bytes(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(b.size_bytes), 0) FROM blob_owners o \
         JOIN blobs b ON b.cid = o.cid WHERE o.account_did = ?",
    )
    .bind(account_did)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Blob count and total bytes for a specific account, in a single query.
///
/// Counts every ownership row regardless of `ref_count`/`temp_until`: an operator's view of
/// "blobs stored" includes still-temporary uploads that occupy disk. Returns `(count, bytes)`.
pub async fn account_blob_metrics(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<(i64, i64), sqlx::Error> {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(b.size_bytes), 0) FROM blob_owners o \
         JOIN blobs b ON b.cid = o.cid WHERE o.account_did = ?",
    )
    .bind(account_did)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Return the account's largest owned blob as `(cid, size_bytes)`, or `None` when it has none.
///
/// Ties on size are broken by CID (lexicographic) so the result is deterministic.
pub async fn account_largest_blob(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<Option<(String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT b.cid, b.size_bytes FROM blob_owners o \
         JOIN blobs b ON b.cid = o.cid WHERE o.account_did = ? \
         ORDER BY b.size_bytes DESC, b.cid ASC LIMIT 1",
    )
    .bind(account_did)
    .fetch_optional(pool)
    .await
}

/// Look up a blob's physical metadata by CID, regardless of owner.
///
/// The live read paths are otherwise all ownership-scoped ([`get_owned_blob`]); this
/// ownership-independent lookup backs `blob_scrub`'s pre-write existence recheck (has
/// `blob_gc` reclaimed this exact CID since the scrub pass's snapshot?) and tests.
pub async fn get_blob_by_cid(pool: &SqlitePool, cid: &str) -> Result<Option<BlobRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobRow>("SELECT * FROM blobs WHERE cid = ?")
        .bind(cid)
        .fetch_optional(pool)
        .await
}

/// Look up a blob's physical metadata by CID, but only if `account_did` owns a reference to it.
///
/// Backs `com.atproto.sync.getBlob`'s ownership check: a CID owned solely by another account
/// reads as absent, so callers can return the same 404 for "no such CID" and "not this DID's
/// blob" (no CID enumeration).
pub async fn get_owned_blob(
    pool: &SqlitePool,
    account_did: &str,
    cid: &str,
) -> Result<Option<BlobRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobRow>(
        "SELECT b.* FROM blobs b \
         JOIN blob_owners o ON o.cid = b.cid \
         WHERE o.account_did = ? AND b.cid = ?",
    )
    .bind(account_did)
    .bind(cid)
    .fetch_optional(pool)
    .await
}

/// Look up one account's ownership row for a blob CID.
///
/// Part of the blob-store query surface; the live paths check ownership via joins
/// ([`get_owned_blob`], `present_cids`), so only tests consume the row directly.
#[allow(dead_code)]
pub async fn get_owner(
    pool: &SqlitePool,
    account_did: &str,
    cid: &str,
) -> Result<Option<BlobOwnerRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobOwnerRow>(
        "SELECT cid, ref_count, temp_until FROM blob_owners WHERE account_did = ? AND cid = ?",
    )
    .bind(account_did)
    .bind(cid)
    .fetch_optional(pool)
    .await
}

/// Return which of `cids` already have a blob ownership row for `account_did`.
///
/// Backs `com.atproto.repo.listMissingBlobs`: the repo's referenced blob CIDs minus this set is
/// exactly the blobs still to be uploaded. Scoped by `account_did` to mirror
/// `checkAccountStatus`'s imported-blob count. Batched to stay under SQLite's bound-parameter
/// limit; an empty input yields an empty set.
pub async fn present_cids(
    pool: &SqlitePool,
    account_did: &str,
    cids: &[String],
) -> Result<std::collections::HashSet<String>, sqlx::Error> {
    let mut present = std::collections::HashSet::new();
    if cids.is_empty() {
        return Ok(present);
    }
    for chunk in cids.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "SELECT cid FROM blob_owners WHERE account_did = ? AND cid IN ({placeholders})"
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql).bind(account_did);
        for cid in chunk {
            q = q.bind(cid);
        }
        present.extend(q.fetch_all(pool).await?);
    }
    Ok(present)
}

/// Return all ownership rows whose grace period has expired and whose account no longer
/// references the blob, as `(account_did, cid)` pairs.
///
/// These are the garbage-collection deletion candidates: a `temp_until` in the past with a
/// zero `ref_count` means this account uploaded the blob and never referenced it, or its last
/// reference outlived the grace period. The `ref_count = 0` guard ensures an in-use reference
/// is never returned even if its `temp_until` somehow lingered. Expiring one account's row
/// says nothing about the physical file — that goes only when the last owner is gone
/// ([`delete_blob_if_unowned`]).
pub async fn list_expired_temp_owners(
    pool: &SqlitePool,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT account_did, cid FROM blob_owners \
         WHERE temp_until IS NOT NULL AND temp_until < datetime('now') AND ref_count = 0",
    )
    .fetch_all(pool)
    .await
}

/// Return the DIDs blob GC must reconcile: every account that owns a blob reference, plus
/// every account with a repo (whose records may reference blob CIDs it has no ownership row
/// for yet — the reconcile pass adopts those, healing pre-V039 implicit sharing).
pub async fn list_gc_candidate_dids(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT account_did FROM blob_owners \
         UNION \
         SELECT did FROM accounts WHERE repo_root_cid IS NOT NULL",
    )
    .fetch_all(pool)
    .await
}

/// List one account's blob ownership rows.
pub async fn list_owned_blobs(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<Vec<BlobOwnerRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobOwnerRow>(
        "SELECT cid, ref_count, temp_until FROM blob_owners WHERE account_did = ?",
    )
    .bind(account_did)
    .fetch_all(pool)
    .await
}

/// Record that `account_did`'s repo references `cid` in `ref_count` records: upsert the
/// ownership row with that exact count and clear its `temp_until`, making the reference
/// permanent.
///
/// The INSERT arm *adopts* a blob the account references but never uploaded (possible for
/// records imported or written before the blob's owner rows existed, and for pre-V039 uploads
/// whose row credited the first uploader); the `WHERE EXISTS` guard makes the call a no-op for
/// CID links that aren't blobs at all, which the GC's reference walk cannot distinguish. The
/// count is assigned absolutely (not incremented), so the GC can recompute references from the
/// MST and call this repeatedly without inflating the counter; the conflict arm's change guard
/// skips rows already in the desired state. Returns true only when a row was inserted or
/// actually changed, letting callers count real churn.
pub async fn upsert_owner_referenced(
    pool: &SqlitePool,
    account_did: &str,
    cid: &str,
    ref_count: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO blob_owners (cid, account_did, ref_count, temp_until)
         SELECT ?, ?, ?, NULL WHERE EXISTS (SELECT 1 FROM blobs WHERE cid = ?)
         ON CONFLICT(account_did, cid) DO UPDATE SET ref_count = excluded.ref_count, temp_until = NULL
         WHERE blob_owners.ref_count != excluded.ref_count OR blob_owners.temp_until IS NOT NULL",
    )
    .bind(cid)
    .bind(account_did)
    .bind(ref_count)
    .bind(cid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Release one account's reference to a blob that none of its records use any longer: zero the
/// row's `ref_count` and start the grace clock by setting `temp_until`.
///
/// The `temp_until IS NULL` guard makes this a one-shot transition from permanent to
/// temporary: it only fires for a reference that was previously permanent. A row already
/// counting down its grace period is left untouched so each GC pass does not keep resetting
/// the clock and the reference can actually expire. Returns true if a row transitioned.
pub async fn release_owner(
    pool: &SqlitePool,
    account_did: &str,
    cid: &str,
    temp_until: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE blob_owners SET ref_count = 0, temp_until = ? \
         WHERE account_did = ? AND cid = ? AND temp_until IS NULL",
    )
    .bind(temp_until)
    .bind(account_did)
    .bind(cid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete one account's expired, unreferenced ownership row. Returns true if a row was removed.
///
/// Re-checks the expiry conditions in the DELETE itself so a reference that was re-uploaded or
/// re-referenced between the candidate scan and this call survives.
pub async fn delete_expired_owner(
    pool: &SqlitePool,
    account_did: &str,
    cid: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM blob_owners \
         WHERE account_did = ? AND cid = ? \
           AND temp_until IS NOT NULL AND temp_until < datetime('now') AND ref_count = 0",
    )
    .bind(account_did)
    .bind(cid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete a blob's physical row if no ownership row remains, returning its `storage_path` for
/// on-disk reclamation.
///
/// The no-owner check and the delete are one statement, so a concurrent upload that re-adds an
/// owner can never lose the physical row. Callers unlink the file *after* this returns a path:
/// the DB is the source of truth, and the failure mode of that ordering is an orphaned file (a
/// benign leak to log), never a live row pointing at deleted bytes.
pub async fn delete_blob_if_unowned(
    pool: &SqlitePool,
    cid: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "DELETE FROM blobs WHERE cid = ? \
           AND NOT EXISTS (SELECT 1 FROM blob_owners o WHERE o.cid = blobs.cid) \
         RETURNING storage_path",
    )
    .bind(cid)
    .fetch_optional(pool)
    .await
}

/// Delete every blob ownership row for an account and reclaim the physical rows that are left
/// with no owner, inside the caller's transaction. Returns the deleted physical blobs as
/// `(cid, storage_path)` pairs so the caller can unlink the files once the transaction commits.
///
/// The account-deletion counterpart to `blocks::delete_unowned_unprotected_blocks_in_tx`: a CID
/// still owned by another account keeps its row and file.
pub async fn delete_owners_and_unowned_blobs_in_tx(
    tx: &mut SqliteTransaction<'_>,
    account_did: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let cids: Vec<String> = sqlx::query_scalar("SELECT cid FROM blob_owners WHERE account_did = ?")
        .bind(account_did)
        .fetch_all(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM blob_owners WHERE account_did = ?")
        .bind(account_did)
        .execute(&mut **tx)
        .await?;

    let mut reclaimed = Vec::new();
    // Batch to stay well under SQLite's bound-parameter limit.
    for chunk in cids.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "DELETE FROM blobs \
             WHERE cid IN ({placeholders}) \
               AND NOT EXISTS (SELECT 1 FROM blob_owners o WHERE o.cid = blobs.cid) \
             RETURNING cid, storage_path"
        );
        let mut q = sqlx::query_as::<_, (String, String)>(&sql);
        for cid in chunk {
            q = q.bind(cid);
        }
        reclaimed.extend(q.fetch_all(&mut **tx).await?);
    }
    Ok(reclaimed)
}

/// List blob CIDs owned by a DID with cursor-based pagination.
///
/// Returns up to `limit` CIDs (default 500, max 2000) for blobs the given DID owns a reference
/// to. Results are ordered by CID (lexicographic). If `cursor` is provided, only CIDs
/// strictly greater than the cursor are returned.
pub async fn list_blob_cids(
    pool: &SqlitePool,
    account_did: &str,
    limit: i64,
    cursor: Option<&str>,
) -> Result<Vec<String>, sqlx::Error> {
    let limit = limit.clamp(1, 2000);

    match cursor {
        Some(cursor_cid) => {
            sqlx::query_scalar::<_, String>(
                "SELECT cid FROM blob_owners WHERE account_did = ? AND cid > ? \
                 ORDER BY cid ASC LIMIT ?",
            )
            .bind(account_did)
            .bind(cursor_cid)
            .bind(limit + 1) // fetch one extra to detect if there's a next page
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_scalar::<_, String>(
                "SELECT cid FROM blob_owners WHERE account_did = ? ORDER BY cid ASC LIMIT ?",
            )
            .bind(account_did)
            .bind(limit + 1)
            .fetch_all(pool)
            .await
        }
    }
}

/// One physical stored blob, as the mirror sweep and restore-on-boot see it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PhysicalBlob {
    pub cid: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub storage_path: String,
}

/// List every physical `blobs` row (one per stored CID, ownership-independent), CID-ordered.
///
/// The blob mirror's working set: the sweep diffs this against the bucket listing, and
/// restore-on-boot walks it to find rows whose file is missing from the volume. Reading the
/// table rather than the filesystem makes the DB the source of truth — an orphaned file no
/// row references is never replicated.
pub async fn list_all_blobs(pool: &SqlitePool) -> Result<Vec<PhysicalBlob>, sqlx::Error> {
    sqlx::query_as::<_, PhysicalBlob>(
        "SELECT cid, mime_type, size_bytes, storage_path FROM blobs ORDER BY cid ASC",
    )
    .fetch_all(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn test_pool() -> SqlitePool {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        pool
    }

    /// Insert a test account (required for the FK on blob_owners.account_did).
    async fn insert_account(pool: &SqlitePool, did: &str) -> String {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at)
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(pool)
        .await
        .unwrap();
        did.to_string()
    }

    async fn insert_test_account(pool: &SqlitePool) -> String {
        insert_account(pool, "did:plc:testblob").await
    }

    #[tokio::test]
    async fn insert_and_get_blob() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkreitest123",
            &account_did,
            "image/jpeg",
            1024,
            "blobs/ba/bafkreitest123",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();

        let blob = get_blob_by_cid(&pool, "bafkreitest123")
            .await
            .unwrap()
            .expect("blob must exist");

        assert_eq!(blob.cid, "bafkreitest123");
        assert_eq!(blob.account_did, account_did);
        assert_eq!(blob.mime_type, "image/jpeg");
        assert_eq!(blob.size_bytes, 1024);
        assert_eq!(blob.storage_path, "blobs/ba/bafkreitest123");

        let owner = get_owner(&pool, &account_did, "bafkreitest123")
            .await
            .unwrap()
            .expect("owner row must exist");
        assert_eq!(owner.ref_count, 0);
        assert!(owner.temp_until.is_some());
    }

    #[tokio::test]
    async fn get_nonexistent_blob_returns_none() {
        let pool = test_pool().await;
        let result = get_blob_by_cid(&pool, "bafkreinoexist").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn second_uploader_gets_own_ownership_row() {
        let pool = test_pool().await;
        let a = insert_account(&pool, "did:plc:sharea").await;
        let b = insert_account(&pool, "did:plc:shareb").await;

        insert_blob(
            &pool,
            "bafshared",
            &a,
            "image/png",
            64,
            "p",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafshared",
            &b,
            "image/png",
            64,
            "p",
            "2030-06-01 00:00:00",
        )
        .await
        .unwrap();

        // The physical row keeps the first uploader's diagnostics...
        let blob = get_blob_by_cid(&pool, "bafshared").await.unwrap().unwrap();
        assert_eq!(blob.account_did, a);

        // ...but both accounts own a reference, each with its own grace clock.
        let owner_a = get_owner(&pool, &a, "bafshared").await.unwrap().unwrap();
        let owner_b = get_owner(&pool, &b, "bafshared").await.unwrap().unwrap();
        assert_eq!(owner_a.temp_until.as_deref(), Some("2030-01-01 00:00:00"));
        assert_eq!(owner_b.temp_until.as_deref(), Some("2030-06-01 00:00:00"));

        // Both see the blob through the ownership-checked lookup.
        assert!(get_owned_blob(&pool, &a, "bafshared")
            .await
            .unwrap()
            .is_some());
        assert!(get_owned_blob(&pool, &b, "bafshared")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn get_owned_blob_hides_other_accounts_blob() {
        let pool = test_pool().await;
        let a = insert_account(&pool, "did:plc:ownedonly").await;
        insert_account(&pool, "did:plc:notowner").await;

        insert_blob(
            &pool,
            "bafowned",
            &a,
            "image/png",
            8,
            "p",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();

        assert!(get_owned_blob(&pool, &a, "bafowned")
            .await
            .unwrap()
            .is_some());
        assert!(get_owned_blob(&pool, "did:plc:notowner", "bafowned")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn reupload_refreshes_grace_clock_only_while_unreferenced() {
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafreup",
            &did,
            "image/png",
            8,
            "p",
            "2020-01-01 00:00:00",
        )
        .await
        .unwrap();

        // Re-upload while unreferenced: the grace clock restarts.
        insert_blob(
            &pool,
            "bafreup",
            &did,
            "image/png",
            8,
            "p",
            "2040-01-01 00:00:00",
        )
        .await
        .unwrap();
        let owner = get_owner(&pool, &did, "bafreup").await.unwrap().unwrap();
        assert_eq!(owner.temp_until.as_deref(), Some("2040-01-01 00:00:00"));

        // Once referenced (permanent), a re-upload must NOT restart a countdown.
        assert!(upsert_owner_referenced(&pool, &did, "bafreup", 1)
            .await
            .unwrap());
        insert_blob(
            &pool,
            "bafreup",
            &did,
            "image/png",
            8,
            "p",
            "2050-01-01 00:00:00",
        )
        .await
        .unwrap();
        let owner = get_owner(&pool, &did, "bafreup").await.unwrap().unwrap();
        assert_eq!(owner.ref_count, 1);
        assert!(
            owner.temp_until.is_none(),
            "referenced blob must stay permanent"
        );
    }

    #[tokio::test]
    async fn upsert_owner_referenced_sets_count_and_clears_temp() {
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkrisetref",
            &did,
            "image/png",
            512,
            "p",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();

        let changed = upsert_owner_referenced(&pool, &did, "bafkrisetref", 3)
            .await
            .unwrap();
        assert!(changed);

        let owner = get_owner(&pool, &did, "bafkrisetref")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner.ref_count, 3);
        assert!(owner.temp_until.is_none());

        // Idempotent and a true no-op: setting the same count again must not report a
        // change (so the GC's churn counter is not inflated) and keeps ref_count at 3.
        let unchanged = upsert_owner_referenced(&pool, &did, "bafkrisetref", 3)
            .await
            .unwrap();
        assert!(
            !unchanged,
            "re-setting the same state must report no change"
        );
        let owner = get_owner(&pool, &did, "bafkrisetref")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner.ref_count, 3);
    }

    #[tokio::test]
    async fn upsert_owner_referenced_adopts_unowned_blob() {
        let pool = test_pool().await;
        let a = insert_account(&pool, "did:plc:adopta").await;
        let b = insert_account(&pool, "did:plc:adoptb").await;

        insert_blob(
            &pool,
            "bafadopt",
            &a,
            "image/png",
            8,
            "p",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        assert!(get_owner(&pool, &b, "bafadopt").await.unwrap().is_none());

        // B's repo references the CID: the reconcile upsert creates B's ownership row.
        assert!(upsert_owner_referenced(&pool, &b, "bafadopt", 2)
            .await
            .unwrap());
        let owner = get_owner(&pool, &b, "bafadopt").await.unwrap().unwrap();
        assert_eq!(owner.ref_count, 2);
        assert!(owner.temp_until.is_none());
    }

    #[tokio::test]
    async fn upsert_owner_referenced_ignores_non_blob_cids() {
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        // A record cross-link that is not a blob: no physical row, so no adoption.
        let changed = upsert_owner_referenced(&pool, &did, "bafyreinotablob", 1)
            .await
            .unwrap();
        assert!(!changed);
        assert!(get_owner(&pool, &did, "bafyreinotablob")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn list_expired_temp_owners_finds_old_entries() {
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkriexpired",
            &did,
            "video/mp4",
            4096,
            "p",
            "2020-01-01 00:00:00",
        )
        .await
        .unwrap();

        let expired = list_expired_temp_owners(&pool).await.unwrap();
        assert_eq!(expired, vec![(did, "bafkriexpired".to_string())]);
    }

    #[tokio::test]
    async fn list_expired_temp_owners_skips_permanent_and_referenced() {
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        // A permanent reference (temp_until = NULL).
        insert_blob(
            &pool,
            "bafkriperm",
            &did,
            "image/png",
            100,
            "p1",
            "2020-01-01 00:00:00",
        )
        .await
        .unwrap();
        upsert_owner_referenced(&pool, &did, "bafkriperm", 1)
            .await
            .unwrap();

        // An expired temp_until but with a live reference must never be a deletion candidate.
        insert_blob(
            &pool,
            "bafkrirefexp",
            &did,
            "image/png",
            100,
            "p2",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE blob_owners SET ref_count = 2, temp_until = '2020-01-01 00:00:00' \
             WHERE account_did = ? AND cid = 'bafkrirefexp'",
        )
        .bind(&did)
        .execute(&pool)
        .await
        .unwrap();

        let expired = list_expired_temp_owners(&pool).await.unwrap();
        assert!(expired.is_empty());
    }

    #[tokio::test]
    async fn list_expired_temp_owners_uses_sqlite_comparable_format() {
        // Regression guard: temp_until must be stored in the same `YYYY-MM-DD HH:MM:SS` form
        // SQLite's datetime('now') returns. A `T`/`Z` ISO form sorts lexicographically after
        // the space-separated form, hiding same-day-expired blobs from this query.
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        let past = (chrono::Utc::now() - chrono::Duration::minutes(5))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        insert_blob(&pool, "bafkripast", &did, "image/png", 1, "p1", &past)
            .await
            .unwrap();

        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        insert_blob(&pool, "bafkrifuture", &did, "image/png", 1, "p2", &future)
            .await
            .unwrap();

        let expired = list_expired_temp_owners(&pool).await.unwrap();
        let cids: Vec<&str> = expired.iter().map(|(_, c)| c.as_str()).collect();
        assert!(
            cids.contains(&"bafkripast"),
            "a same-day past deadline must be collected"
        );
        assert!(
            !cids.contains(&"bafkrifuture"),
            "a future deadline must not be collected"
        );
    }

    #[tokio::test]
    async fn release_owner_only_transitions_permanent_references() {
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkrirelease",
            &did,
            "image/png",
            100,
            "p",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        upsert_owner_referenced(&pool, &did, "bafkrirelease", 1)
            .await
            .unwrap();

        let released = release_owner(&pool, &did, "bafkrirelease", "2030-01-01 00:00:00")
            .await
            .unwrap();
        assert!(released);

        let owner = get_owner(&pool, &did, "bafkrirelease")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner.ref_count, 0);
        assert_eq!(owner.temp_until.as_deref(), Some("2030-01-01 00:00:00"));

        // Second release must be a no-op: temp_until is already set, so the grace clock
        // is not reset to a new value.
        let released_again = release_owner(&pool, &did, "bafkrirelease", "2040-01-01 00:00:00")
            .await
            .unwrap();
        assert!(!released_again);
        let owner = get_owner(&pool, &did, "bafkrirelease")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner.temp_until.as_deref(), Some("2030-01-01 00:00:00"));
    }

    #[tokio::test]
    async fn delete_expired_owner_recheck_spares_live_rows() {
        let pool = test_pool().await;
        let did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkrialive",
            &did,
            "image/png",
            1,
            "p",
            "2020-01-01 00:00:00",
        )
        .await
        .unwrap();
        // The reference was pinned after the candidate scan: the delete must not fire.
        upsert_owner_referenced(&pool, &did, "bafkrialive", 1)
            .await
            .unwrap();
        assert!(!delete_expired_owner(&pool, &did, "bafkrialive")
            .await
            .unwrap());

        // A genuinely expired, unreferenced row is removed.
        insert_blob(
            &pool,
            "bafkrigone",
            &did,
            "image/png",
            1,
            "p2",
            "2020-01-01 00:00:00",
        )
        .await
        .unwrap();
        assert!(delete_expired_owner(&pool, &did, "bafkrigone")
            .await
            .unwrap());
        assert!(get_owner(&pool, &did, "bafkrigone")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn delete_blob_if_unowned_spares_shared_blob() {
        let pool = test_pool().await;
        let a = insert_account(&pool, "did:plc:sparea").await;
        let b = insert_account(&pool, "did:plc:spareb").await;

        insert_blob(
            &pool,
            "bafspare",
            &a,
            "image/png",
            8,
            "blobs/ba/bafspare",
            "2020-01-01 00:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafspare",
            &b,
            "image/png",
            8,
            "blobs/ba/bafspare",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();

        // A's reference expires and is removed; B still owns the CID → physical row stays.
        assert!(delete_expired_owner(&pool, &a, "bafspare").await.unwrap());
        assert!(delete_blob_if_unowned(&pool, "bafspare")
            .await
            .unwrap()
            .is_none());
        assert!(get_blob_by_cid(&pool, "bafspare").await.unwrap().is_some());

        // B's reference goes too → the physical row is reclaimed and its path returned.
        sqlx::query("DELETE FROM blob_owners WHERE account_did = ? AND cid = 'bafspare'")
            .bind(&b)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            delete_blob_if_unowned(&pool, "bafspare").await.unwrap(),
            Some("blobs/ba/bafspare".to_string())
        );
        assert!(get_blob_by_cid(&pool, "bafspare").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_owners_and_unowned_blobs_spares_shared_cids() {
        let pool = test_pool().await;
        let a = insert_account(&pool, "did:plc:purgea").await;
        let b = insert_account(&pool, "did:plc:purgeb").await;

        insert_blob(
            &pool,
            "bafsolo",
            &a,
            "image/png",
            8,
            "blobs/ba/bafsolo",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafboth",
            &a,
            "image/png",
            8,
            "blobs/ba/bafboth",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafboth",
            &b,
            "image/png",
            8,
            "blobs/ba/bafboth",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();

        let mut tx = pool.begin().await.unwrap();
        let mut reclaimed = delete_owners_and_unowned_blobs_in_tx(&mut tx, &a)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        reclaimed.sort();
        assert_eq!(
            reclaimed,
            vec![("bafsolo".to_string(), "blobs/ba/bafsolo".to_string())],
            "only the unshared blob is reclaimed"
        );
        assert!(get_owner(&pool, &a, "bafboth").await.unwrap().is_none());
        assert!(get_blob_by_cid(&pool, "bafboth").await.unwrap().is_some());
        assert!(get_blob_by_cid(&pool, "bafsolo").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn account_storage_bytes_sums_correctly() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        for i in 0..3 {
            insert_blob(
                &pool,
                &format!("bafkristorage{i}"),
                &account_did,
                "image/jpeg",
                100 * (i as i64 + 1),
                &format!("blobs/ba/bafkristorage{i}"),
                "2026-01-01 12:00:00",
            )
            .await
            .unwrap();
        }

        let total = account_storage_bytes(&pool, &account_did).await.unwrap();
        assert_eq!(total, 100 + 200 + 300); // 600
    }

    #[tokio::test]
    async fn account_storage_bytes_counts_shared_content_for_each_owner() {
        let pool = test_pool().await;
        let a = insert_account(&pool, "did:plc:quotaa").await;
        let b = insert_account(&pool, "did:plc:quotab").await;

        insert_blob(
            &pool,
            "bafquota",
            &a,
            "image/png",
            500,
            "p",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafquota",
            &b,
            "image/png",
            500,
            "p",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();

        assert_eq!(account_storage_bytes(&pool, &a).await.unwrap(), 500);
        assert_eq!(account_storage_bytes(&pool, &b).await.unwrap(), 500);
    }

    #[tokio::test]
    async fn account_storage_bytes_empty_account_returns_zero() {
        let pool = test_pool().await;
        let total = account_storage_bytes(&pool, "did:plc:empty").await.unwrap();
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn account_blob_metrics_counts_and_sums() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        assert_eq!(
            account_blob_metrics(&pool, &account_did).await.unwrap(),
            (0, 0)
        );

        for i in 0..3 {
            insert_blob(
                &pool,
                &format!("bafkricount{i}"),
                &account_did,
                "image/jpeg",
                100,
                &format!("blobs/ba/bafkricount{i}"),
                "2026-01-01 12:00:00",
            )
            .await
            .unwrap();
        }

        assert_eq!(
            account_blob_metrics(&pool, &account_did).await.unwrap(),
            (3, 300)
        );
    }

    #[tokio::test]
    async fn account_largest_blob_returns_biggest_by_size() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        // No blobs → None.
        assert!(account_largest_blob(&pool, &account_did)
            .await
            .unwrap()
            .is_none());

        insert_blob(
            &pool,
            "bafsmall",
            &account_did,
            "image/jpeg",
            100,
            "p1",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafbig",
            &account_did,
            "image/jpeg",
            9000,
            "p2",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafmid",
            &account_did,
            "image/jpeg",
            500,
            "p3",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();

        let (cid, size) = account_largest_blob(&pool, &account_did)
            .await
            .unwrap()
            .expect("a largest blob");
        assert_eq!(cid, "bafbig");
        assert_eq!(size, 9000);
    }

    #[tokio::test]
    async fn account_largest_blob_breaks_ties_by_cid() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        // Two equal-size blobs: the lexicographically smaller CID wins (deterministic).
        insert_blob(
            &pool,
            "bafbbb",
            &account_did,
            "image/jpeg",
            200,
            "p1",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();
        insert_blob(
            &pool,
            "bafaaa",
            &account_did,
            "image/jpeg",
            200,
            "p2",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();

        let (cid, _) = account_largest_blob(&pool, &account_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cid, "bafaaa");
    }

    #[tokio::test]
    async fn list_gc_candidate_dids_unions_owners_and_repo_accounts() {
        let pool = test_pool().await;
        let uploader = insert_account(&pool, "did:plc:gcuploader").await;
        let repo_only = insert_account(&pool, "did:plc:gcrepoonly").await;
        insert_account(&pool, "did:plc:gcneither").await;

        insert_blob(
            &pool,
            "bafgccand",
            &uploader,
            "image/png",
            8,
            "p",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();
        sqlx::query("UPDATE accounts SET repo_root_cid = 'bafyroot' WHERE did = ?")
            .bind(&repo_only)
            .execute(&pool)
            .await
            .unwrap();

        let mut dids = list_gc_candidate_dids(&pool).await.unwrap();
        dids.sort();
        assert_eq!(dids, vec![repo_only, uploader]);
    }

    #[tokio::test]
    async fn list_blob_cids_returns_all_cids() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        for i in 0..3 {
            insert_blob(
                &pool,
                &format!("bafkricid{i}"),
                &account_did,
                "image/jpeg",
                100,
                &format!("blobs/ba/bafkricid{i}"),
                "2026-01-01 12:00:00",
            )
            .await
            .unwrap();
        }

        let cids = list_blob_cids(&pool, &account_did, 500, None)
            .await
            .unwrap();
        assert_eq!(cids.len(), 3);
        // Results are ordered by CID (lexicographic).
        assert!(cids.windows(2).all(|w| w[0] <= w[1]));
    }

    #[tokio::test]
    async fn list_blob_cids_empty_for_unknown_did() {
        let pool = test_pool().await;
        let cids = list_blob_cids(&pool, "did:plc:unknown", 500, None)
            .await
            .unwrap();
        assert!(cids.is_empty());
    }

    #[tokio::test]
    async fn list_blob_cids_respects_limit() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        for i in 0..5 {
            insert_blob(
                &pool,
                &format!("bafkrilimit{i}"),
                &account_did,
                "image/jpeg",
                100,
                &format!("blobs/ba/bafkrilimit{i}"),
                "2026-01-01 12:00:00",
            )
            .await
            .unwrap();
        }

        let cids = list_blob_cids(&pool, &account_did, 3, None).await.unwrap();
        // DB function returns limit+1 for pagination detection.
        assert_eq!(cids.len(), 4);
    }

    #[tokio::test]
    async fn list_blob_cids_pagination_with_cursor() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        for i in 0..5 {
            insert_blob(
                &pool,
                &format!("bafkricursor{i}"),
                &account_did,
                "image/jpeg",
                100,
                &format!("blobs/ba/bafkricursor{i}"),
                "2026-01-01 12:00:00",
            )
            .await
            .unwrap();
        }

        // First page: limit=3, DB returns 4 (limit+1) for pagination detection.
        let page1 = list_blob_cids(&pool, &account_did, 3, None).await.unwrap();
        assert_eq!(page1.len(), 4);

        // The caller (route handler) uses page1[limit] as cursor and returns page1[..limit].
        // Simulate: cursor = page1[3], visible = page1[..3].
        let cursor = page1[3].clone();
        let page1_visible = &page1[..3];

        // Second page: cursor = extra item from page 1.
        let page2 = list_blob_cids(&pool, &account_did, 3, Some(&cursor))
            .await
            .unwrap();
        // Should return remaining CIDs (excluding the cursor itself).
        assert!(!page2.is_empty());
        assert!(page2.iter().all(|c| c > &cursor));

        // No overlap between visible page 1 and page 2.
        for cid in &page2 {
            assert!(!page1_visible.contains(cid));
        }
    }

    #[tokio::test]
    async fn list_blob_cids_clamps_limit_to_max() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkriclamp",
            &account_did,
            "image/jpeg",
            100,
            "blobs/ba/bafkriclamp",
            "2026-01-01 12:00:00",
        )
        .await
        .unwrap();

        // Limit of 0 should be clamped to 1.
        let cids = list_blob_cids(&pool, &account_did, 0, None).await.unwrap();
        assert_eq!(cids.len(), 1);

        // Limit of 9999 should be clamped to 2000.
        let cids = list_blob_cids(&pool, &account_did, 9999, None)
            .await
            .unwrap();
        assert_eq!(cids.len(), 1);
    }
}
