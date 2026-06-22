// pattern: Imperative Shell
//
// Allow dead_code: this module's public API is consumed by the upload_blob route (MM-108)
// which ships in the next commit. Functions are tested here; the warning is transient.
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
         VALUES (?, ?, ?, ?, ?, ?)",
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

/// Return all blobs whose temporary period has expired.
///
/// These are candidates for garbage collection — uploaded but never referenced.
pub async fn list_expired_temps(pool: &SqlitePool) -> Result<Vec<BlobRow>, sqlx::Error> {
    sqlx::query_as::<_, BlobRow>(
        "SELECT * FROM blobs WHERE temp_until IS NOT NULL AND temp_until < datetime('now')",
    )
    .fetch_all(pool)
    .await
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
}
