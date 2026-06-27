// pattern: Imperative Shell

// Dead code allow: these functions are consumed by routes that ship in subsequent issues
// (getBlob, listBlobs, GC cleanup). All functions are tested here.
#![allow(dead_code)]

use sqlx::SqlitePool;

/// Row returned from the `blobs` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlobRow {
    pub cid: String,
    pub account_did: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub storage_path: String,
    pub ref_count: i64,
    pub temp_until: Option<String>,
    pub created_at: String,
}

/// Insert a new blob metadata row.
///
/// `temp_until` should be set to now + 6 hours for newly uploaded blobs that
/// haven't been referenced by a repo record yet.
///
/// Uses `ON CONFLICT(cid) DO UPDATE` for idempotency: if the same content
/// (same CID) is uploaded by different users, the existing row is returned
/// and `ref_count` is unchanged. This matches ATProto's uploadBlob semantics
/// (content-addressable, same content = same CID = no error).
pub async fn insert_blob(
    pool: &SqlitePool,
    cid: &str,
    account_did: &str,
    mime_type: &str,
    size_bytes: i64,
    storage_path: &str,
    temp_until: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, temp_until)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(cid) DO UPDATE SET ref_count = ref_count",
    )
    .bind(cid)
    .bind(account_did)
    .bind(mime_type)
    .bind(size_bytes)
    .bind(storage_path)
    .bind(temp_until)
    .execute(pool)
    .await?;
    Ok(())
}

/// Sum of bytes uploaded by a specific account.
///
/// Used to enforce per-user storage quotas.
pub async fn account_storage_bytes(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) =
        sqlx::query_as("SELECT COALESCE(SUM(size_bytes), 0) FROM blobs WHERE account_did = ?")
            .bind(account_did)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Blob count and total bytes for a specific account, in a single query.
///
/// Counts every blob row regardless of `ref_count`/`temp_until`: an operator's view of
/// "blobs stored" includes still-temporary uploads that occupy disk. Returns `(count, bytes)`.
pub async fn account_blob_metrics(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<(i64, i64), sqlx::Error> {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM blobs WHERE account_did = ?",
    )
    .bind(account_did)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Return the account's largest blob as `(cid, size_bytes)`, or `None` when it has none.
///
/// Ties on size are broken by CID (lexicographic) so the result is deterministic.
pub async fn account_largest_blob(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<Option<(String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT cid, size_bytes FROM blobs WHERE account_did = ? \
         ORDER BY size_bytes DESC, cid ASC LIMIT 1",
    )
    .bind(account_did)
    .fetch_optional(pool)
    .await
}

/// Look up a blob by its CID.
pub async fn get_blob_by_cid(pool: &SqlitePool, cid: &str) -> Result<Option<BlobRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobRow>("SELECT * FROM blobs WHERE cid = ?")
        .bind(cid)
        .fetch_optional(pool)
        .await
}

/// Mark a blob as referenced: increment `ref_count` and clear `temp_until`.
///
/// Called when a repo record references an already-uploaded blob.
pub async fn mark_referenced(pool: &SqlitePool, cid: &str) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE blobs SET ref_count = ref_count + 1, temp_until = NULL WHERE cid = ?")
            .bind(cid)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

/// Return all blobs whose temporary period has expired and that no record references.
///
/// These are the garbage-collection deletion candidates: a `temp_until` in the past with a
/// zero `ref_count` means the blob was either uploaded and never referenced, or it lost its
/// last reference and outlived the grace period. The `ref_count = 0` guard ensures an
/// in-use blob is never returned even if its `temp_until` somehow lingered.
pub async fn list_expired_temps(pool: &SqlitePool) -> Result<Vec<BlobRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobRow>(
        "SELECT * FROM blobs \
         WHERE temp_until IS NOT NULL AND temp_until < datetime('now') AND ref_count = 0",
    )
    .fetch_all(pool)
    .await
}

/// Return the distinct DIDs that own at least one blob.
///
/// The garbage collector walks each such repo to reconcile blob references against the MST,
/// so bounding the scan to accounts that actually hold blobs avoids opening every repo.
pub async fn list_blob_owner_dids(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>("SELECT DISTINCT account_did FROM blobs")
        .fetch_all(pool)
        .await
}

/// Mark a blob as actively referenced by `ref_count` repo records.
///
/// Sets `ref_count` to the exact count and clears `temp_until`, making the blob permanent.
/// Unlike [`mark_referenced`] (which increments), this assigns an absolute count and is
/// therefore idempotent — the GC recomputes references from the MST on every pass and can
/// call this repeatedly without inflating the counter.
///
/// The `ref_count != ? OR temp_until IS NOT NULL` guard skips rows already in the desired
/// state, so the statement only writes blobs that actually need correcting. Returns true
/// only when a row was changed — letting callers count real churn rather than every
/// referenced blob they visited (SQLite reports a value-identical UPDATE as a changed row).
pub async fn set_blob_referenced(
    pool: &SqlitePool,
    cid: &str,
    ref_count: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE blobs SET ref_count = ?, temp_until = NULL \
         WHERE cid = ? AND (ref_count != ? OR temp_until IS NOT NULL)",
    )
    .bind(ref_count)
    .bind(cid)
    .bind(ref_count)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Release a blob that no record references any longer: zero its `ref_count` and start the
/// grace clock by setting `temp_until`.
///
/// The `temp_until IS NULL` guard makes this a one-shot transition from permanent to
/// temporary: it only fires for a blob that was previously referenced (and thus had a null
/// `temp_until`). A blob already counting down its grace period is left untouched so each GC
/// pass does not keep resetting the clock and the blob can actually expire. Returns true if
/// a row transitioned.
pub async fn release_blob(
    pool: &SqlitePool,
    cid: &str,
    temp_until: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE blobs SET ref_count = 0, temp_until = ? WHERE cid = ? AND temp_until IS NULL",
    )
    .bind(temp_until)
    .bind(cid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete blob metadata by CID. Returns true if a row was removed.
pub async fn delete_blob(pool: &SqlitePool, cid: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM blobs WHERE cid = ?")
        .bind(cid)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// List all blobs for an account.
pub async fn list_blobs_for_account(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<Vec<BlobRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobRow>(
        "SELECT * FROM blobs WHERE account_did = ? ORDER BY created_at DESC",
    )
    .bind(account_did)
    .fetch_all(pool)
    .await
}

/// List blob CIDs for a DID with cursor-based pagination.
///
/// Returns up to `limit` CIDs (default 500, max 2000) for blobs owned by the given DID.
/// Results are ordered by CID (lexicographic). If `cursor` is provided, only CIDs
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
                "SELECT cid FROM blobs WHERE account_did = ? AND cid > ? ORDER BY cid ASC LIMIT ?",
            )
            .bind(account_did)
            .bind(cursor_cid)
            .bind(limit + 1) // fetch one extra to detect if there's a next page
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_scalar::<_, String>(
                "SELECT cid FROM blobs WHERE account_did = ? ORDER BY cid ASC LIMIT ?",
            )
            .bind(account_did)
            .bind(limit + 1)
            .fetch_all(pool)
            .await
        }
    }
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

    /// Insert a test account (required for the FK on account_did).
    async fn insert_test_account(pool: &SqlitePool) -> String {
        let did = "did:plc:testblob";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at)
             VALUES (?, 'blob@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(pool)
        .await
        .unwrap();
        did.to_string()
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
            "2026-01-01T12:00:00Z",
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
        assert_eq!(blob.ref_count, 0);
        assert!(blob.temp_until.is_some());
    }

    #[tokio::test]
    async fn get_nonexistent_blob_returns_none() {
        let pool = test_pool().await;
        let result = get_blob_by_cid(&pool, "bafkreinoexist").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mark_referenced_clears_temp_until() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkrieref",
            &account_did,
            "image/png",
            512,
            "blobs/ba/bafkrieref",
            "2026-01-01T12:00:00Z",
        )
        .await
        .unwrap();

        let changed = mark_referenced(&pool, "bafkrieref").await.unwrap();
        assert!(changed, "row must be updated");

        let blob = get_blob_by_cid(&pool, "bafkrieref").await.unwrap().unwrap();
        assert_eq!(blob.ref_count, 1);
        assert!(
            blob.temp_until.is_none(),
            "temp_until must be cleared after reference"
        );
    }

    #[tokio::test]
    async fn mark_referenced_nonexistent_returns_false() {
        let pool = test_pool().await;
        let changed = mark_referenced(&pool, "bafkrinoexist").await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn delete_blob_removes_row() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkridel",
            &account_did,
            "image/gif",
            256,
            "blobs/ba/bafkridel",
            "2026-01-01T12:00:00Z",
        )
        .await
        .unwrap();

        let deleted = delete_blob(&pool, "bafkridel").await.unwrap();
        assert!(deleted);

        let blob = get_blob_by_cid(&pool, "bafkridel").await.unwrap();
        assert!(blob.is_none());
    }

    #[tokio::test]
    async fn list_expired_temps_finds_old_entries() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        // Insert a blob with temp_until in the past.
        insert_blob(
            &pool,
            "bafkriexpired",
            &account_did,
            "video/mp4",
            4096,
            "blobs/ba/bafkriexpired",
            "2020-01-01T00:00:00Z",
        )
        .await
        .unwrap();

        let expired = list_expired_temps(&pool).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].cid, "bafkriexpired");
    }

    #[tokio::test]
    async fn list_expired_temps_skips_null_temp_until() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        // Insert a permanent blob (temp_until = NULL).
        sqlx::query(
            "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, temp_until)
             VALUES ('bafkriperm', ?, 'image/png', 100, 'blobs/ba/bafkriperm', NULL)",
        )
        .bind(&account_did)
        .execute(&pool)
        .await
        .unwrap();

        let expired = list_expired_temps(&pool).await.unwrap();
        assert!(expired.is_empty());
    }

    #[tokio::test]
    async fn insert_duplicate_cid_is_idempotent() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkridup",
            &account_did,
            "image/jpeg",
            1024,
            "blobs/ba/bafkridup",
            "2026-01-01T12:00:00Z",
        )
        .await
        .unwrap();

        // Second insert with same CID — must succeed (upsert).
        insert_blob(
            &pool,
            "bafkridup",
            &account_did,
            "image/jpeg",
            1024,
            "blobs/ba/bafkridup",
            "2026-01-01T12:00:00Z",
        )
        .await
        .unwrap();

        // Verify only one row exists.
        let blob = get_blob_by_cid(&pool, "bafkridup").await.unwrap().unwrap();
        assert_eq!(blob.ref_count, 0);
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
                "2026-01-01T12:00:00Z",
            )
            .await
            .unwrap();
        }

        let total = account_storage_bytes(&pool, &account_did).await.unwrap();
        assert_eq!(total, 100 + 200 + 300); // 600
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
                "2026-01-01T12:00:00Z",
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
            "2026-01-01T12:00:00Z",
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
            "2026-01-01T12:00:00Z",
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
            "2026-01-01T12:00:00Z",
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
            "2026-01-01T12:00:00Z",
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
            "2026-01-01T12:00:00Z",
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
    async fn list_blobs_for_account_returns_owners_blobs() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        for i in 0..3 {
            insert_blob(
                &pool,
                &format!("bafkriacct{i}"),
                &account_did,
                "image/jpeg",
                100 * i as i64,
                &format!("blobs/ba/bafkriacct{i}"),
                "2026-01-01T12:00:00Z",
            )
            .await
            .unwrap();
        }

        let blobs = list_blobs_for_account(&pool, &account_did).await.unwrap();
        assert_eq!(blobs.len(), 3);
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
                "2026-01-01T12:00:00Z",
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
                "2026-01-01T12:00:00Z",
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
                "2026-01-01T12:00:00Z",
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
            "2026-01-01T12:00:00Z",
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

    #[tokio::test]
    async fn list_expired_temps_skips_referenced_blobs() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        // An expired temp_until but with a live reference must never be a deletion candidate.
        sqlx::query(
            "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, ref_count, temp_until)
             VALUES ('bafkrirefexpired', ?, 'image/png', 100, 'blobs/ba/bafkrirefexpired', 2, '2020-01-01T00:00:00Z')",
        )
        .bind(&account_did)
        .execute(&pool)
        .await
        .unwrap();

        let expired = list_expired_temps(&pool).await.unwrap();
        assert!(
            expired.is_empty(),
            "a referenced blob must not be returned even with an expired temp_until"
        );
    }

    #[tokio::test]
    async fn list_blob_owner_dids_returns_distinct() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        for i in 0..2 {
            insert_blob(
                &pool,
                &format!("bafkriowner{i}"),
                &account_did,
                "image/jpeg",
                100,
                &format!("blobs/ba/bafkriowner{i}"),
                "2026-01-01T12:00:00Z",
            )
            .await
            .unwrap();
        }

        let dids = list_blob_owner_dids(&pool).await.unwrap();
        assert_eq!(dids, vec![account_did]);
    }

    #[tokio::test]
    async fn set_blob_referenced_sets_count_and_clears_temp() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        insert_blob(
            &pool,
            "bafkrisetref",
            &account_did,
            "image/png",
            512,
            "blobs/ba/bafkrisetref",
            "2026-01-01T12:00:00Z",
        )
        .await
        .unwrap();

        let changed = set_blob_referenced(&pool, "bafkrisetref", 3).await.unwrap();
        assert!(changed);

        let blob = get_blob_by_cid(&pool, "bafkrisetref")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.ref_count, 3);
        assert!(blob.temp_until.is_none());

        // Idempotent and a true no-op: setting the same count again must not report a
        // change (so the GC's churn counter is not inflated) and keeps ref_count at 3.
        let unchanged = set_blob_referenced(&pool, "bafkrisetref", 3).await.unwrap();
        assert!(
            !unchanged,
            "re-setting the same state must report no change"
        );
        let blob = get_blob_by_cid(&pool, "bafkrisetref")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.ref_count, 3);
    }

    #[tokio::test]
    async fn list_expired_temps_uses_sqlite_comparable_format() {
        // Regression guard: temp_until must be stored in the same `YYYY-MM-DD HH:MM:SS` form
        // SQLite's datetime('now') returns. A `T`/`Z` ISO form sorts lexicographically after
        // the space-separated form, hiding same-day-expired blobs from this query.
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        let past = (chrono::Utc::now() - chrono::Duration::minutes(5))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        insert_blob(
            &pool,
            "bafkripast",
            &account_did,
            "image/png",
            1,
            "blobs/ba/bafkripast",
            &past,
        )
        .await
        .unwrap();

        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        insert_blob(
            &pool,
            "bafkrifuture",
            &account_did,
            "image/png",
            1,
            "blobs/ba/bafkrifuture",
            &future,
        )
        .await
        .unwrap();

        let expired = list_expired_temps(&pool).await.unwrap();
        let cids: Vec<&str> = expired.iter().map(|b| b.cid.as_str()).collect();
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
    async fn release_blob_only_transitions_permanent_blobs() {
        let pool = test_pool().await;
        let account_did = insert_test_account(&pool).await;

        // A permanent, referenced blob (temp_until NULL, ref_count 1).
        sqlx::query(
            "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, ref_count, temp_until)
             VALUES ('bafkrirelease', ?, 'image/png', 100, 'blobs/ba/bafkrirelease', 1, NULL)",
        )
        .bind(&account_did)
        .execute(&pool)
        .await
        .unwrap();

        let released = release_blob(&pool, "bafkrirelease", "2030-01-01T00:00:00Z")
            .await
            .unwrap();
        assert!(released);

        let blob = get_blob_by_cid(&pool, "bafkrirelease")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.ref_count, 0);
        assert_eq!(blob.temp_until.as_deref(), Some("2030-01-01T00:00:00Z"));

        // Second release must be a no-op: temp_until is already set, so the grace clock
        // is not reset to a new value.
        let released_again = release_blob(&pool, "bafkrirelease", "2040-01-01T00:00:00Z")
            .await
            .unwrap();
        assert!(!released_again);
        let blob = get_blob_by_cid(&pool, "bafkrirelease")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.temp_until.as_deref(), Some("2030-01-01T00:00:00Z"));
    }
}
