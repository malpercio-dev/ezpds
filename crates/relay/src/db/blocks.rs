// pattern: Imperative Shell

// Dead code allow: these functions are consumed by routes that ship in subsequent phases
// (getRepo, applyWrites, record CRUD). All functions are tested here.
#![allow(dead_code)]

//! Content-addressed block storage for ATProto repository blocks.
//!
//! Each block is a DAG-CBOR object (MST node or record) addressed by its CIDv1.
//! Blocks are scoped per account via `account_did` FK to `accounts`.
//!
//! Template: `db/blobs.rs` (content-addressed, `account_did` FK, `ON CONFLICT` idempotency).

use sqlx::SqlitePool;

/// Row returned from the `blocks` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlockRow {
    pub cid: String,
    pub account_did: String,
    pub bytes: Vec<u8>,
    // Dead code allow: created_at is populated by the DB default and will be
    // used when block lifecycle/GC is implemented.
    #[allow(dead_code)]
    pub created_at: String,
}

/// Insert a new block.
///
/// Uses `ON CONFLICT(cid) DO NOTHING` for idempotency: writing the same CID
/// twice is a no-op (the block is content-addressed, so the bytes are identical).
pub async fn put_block(
    pool: &SqlitePool,
    cid: &str,
    account_did: &str,
    bytes: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO blocks (cid, account_did, bytes)
         VALUES (?, ?, ?)
         ON CONFLICT(cid) DO NOTHING",
    )
    .bind(cid)
    .bind(account_did)
    .bind(bytes)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a block by its CID.
pub async fn get_block(pool: &SqlitePool, cid: &str) -> Result<Option<BlockRow>, sqlx::Error> {
    sqlx::query_as::<_, BlockRow>("SELECT * FROM blocks WHERE cid = ?")
        .bind(cid)
        .fetch_optional(pool)
        .await
}

/// Check whether a block exists.
pub async fn has_block(pool: &SqlitePool, cid: &str) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM blocks WHERE cid = ?)")
        .bind(cid)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Delete all blocks for an account.
///
/// Returns the number of blocks removed.
pub async fn delete_blocks_for_account(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM blocks WHERE account_did = ?")
        .bind(account_did)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
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
    async fn insert_test_account(pool: &SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at)
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn put_and_get_block() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:testblock").await;

        let cid = "bafkreitest123";
        let bytes = b"\xa1some dag-cbor";

        put_block(&pool, cid, "did:plc:testblock", bytes)
            .await
            .unwrap();

        let block = get_block(&pool, cid)
            .await
            .unwrap()
            .expect("block must exist");
        assert_eq!(block.cid, cid);
        assert_eq!(block.account_did, "did:plc:testblock");
        assert_eq!(block.bytes, bytes);
    }

    #[tokio::test]
    async fn get_nonexistent_block_returns_none() {
        let pool = test_pool().await;
        let result = get_block(&pool, "bafkreinoexist").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn put_duplicate_cid_is_idempotent() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:testblock").await;

        let cid = "bafkridup";
        let bytes = b"\xa1data";

        put_block(&pool, cid, "did:plc:testblock", bytes)
            .await
            .unwrap();
        // Second write with same CID — must succeed silently.
        put_block(&pool, cid, "did:plc:testblock", bytes)
            .await
            .unwrap();

        // Only one row exists.
        let block = get_block(&pool, cid)
            .await
            .unwrap()
            .expect("block must exist");
        assert_eq!(block.bytes, bytes);
    }

    #[tokio::test]
    async fn has_block_returns_true_for_existing() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:testblock").await;

        let cid = "bafkrihas";
        put_block(&pool, cid, "did:plc:testblock", b"\xa1x")
            .await
            .unwrap();

        assert!(has_block(&pool, cid).await.unwrap());
    }

    #[tokio::test]
    async fn has_block_returns_false_for_missing() {
        let pool = test_pool().await;
        assert!(!has_block(&pool, "bafkrinoexist").await.unwrap());
    }

    #[tokio::test]
    async fn blocks_scoped_by_account_did() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:alice").await;
        insert_test_account(&pool, "did:plc:bob").await;

        put_block(&pool, "bafkrialice", "did:plc:alice", b"\xa1alice")
            .await
            .unwrap();
        put_block(&pool, "bafkribob", "did:plc:bob", b"\xa1bob")
            .await
            .unwrap();

        // Alice's block exists, Bob's block exists, but they're separate.
        let alice_block = get_block(&pool, "bafkrialice")
            .await
            .unwrap()
            .expect("alice block");
        assert_eq!(alice_block.account_did, "did:plc:alice");

        let bob_block = get_block(&pool, "bafkribob")
            .await
            .unwrap()
            .expect("bob block");
        assert_eq!(bob_block.account_did, "did:plc:bob");
    }

    #[tokio::test]
    async fn delete_blocks_for_account_removes_all() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:delme").await;

        for i in 0..3 {
            let bytes = vec![0xa1, 0x64 + i as u8, 0x64, 0x61, 0x74, 0x61]; // dag-cbor-ish
            put_block(&pool, &format!("bafkridel{i}"), "did:plc:delme", &bytes)
                .await
                .unwrap();
        }

        let removed = delete_blocks_for_account(&pool, "did:plc:delme")
            .await
            .unwrap();
        assert_eq!(removed, 3);

        // All gone.
        for i in 0..3 {
            assert!(get_block(&pool, &format!("bafkridel{i}"))
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn delete_blocks_for_empty_account_returns_zero() {
        let pool = test_pool().await;
        let removed = delete_blocks_for_account(&pool, "did:plc:empty")
            .await
            .unwrap();
        assert_eq!(removed, 0);
    }
}
