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

use std::collections::HashSet;

use atrium_repo::blockstore::{self, AsyncBlockStoreRead, AsyncBlockStoreWrite};
use atrium_repo::Cid;
use sha2::Digest;
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

/// Delete an account's blocks whose CID is NOT in `keep` (the reachable set).
///
/// Returns the number of blocks reclaimed. The caller computes `keep` from the current
/// repo root (`repo_engine::collect_reachable_cids`); everything else for the account is
/// garbage (superseded MST nodes, orphans from conflicted writes).
pub async fn delete_unreachable_blocks(
    pool: &SqlitePool,
    account_did: &str,
    keep: &HashSet<String>,
) -> Result<u64, sqlx::Error> {
    let all: Vec<String> = sqlx::query_scalar("SELECT cid FROM blocks WHERE account_did = ?")
        .bind(account_did)
        .fetch_all(pool)
        .await?;
    let garbage: Vec<&String> = all.iter().filter(|c| !keep.contains(*c)).collect();

    let mut removed = 0u64;
    // Batch the deletes to stay well under SQLite's bound-parameter limit.
    for chunk in garbage.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(",");
        let sql = format!("DELETE FROM blocks WHERE account_did = ? AND cid IN ({placeholders})");
        let mut q = sqlx::query(&sql).bind(account_did);
        for cid in chunk {
            q = q.bind(*cid);
        }
        removed += q.execute(pool).await?.rows_affected();
    }
    Ok(removed)
}

/// Tag a specific set of an account's blocks with the revision of the commit that introduced them.
///
/// A write persists its new blocks (via `put_block`) with a NULL `rev` before the commit's
/// revision is final; once the root swap succeeds the caller stamps that commit's blocks with
/// `rev`. The caller passes the *exact* CID set the commit added (`collect_commit_diff_cids`),
/// not "every untagged block": two concurrent writes to the same repo have disjoint diff sets, so
/// scoping by CID prevents one commit's tag from stealing the other's still-NULL blocks (a blanket
/// `rev IS NULL` sweep could, silently dropping them from `getRepo?since` deltas). The UPDATE is
/// unconditional on rev, so a block re-introduced by a later commit is re-stamped with the newer
/// rev (correct: a consumer past the old rev must still receive it). Returns the number of rows
/// updated. Best-effort: a failure leaves blocks untagged (absent from `since` deltas but still in
/// a full export), never corrupts the repo.
pub async fn tag_blocks_rev(
    pool: &SqlitePool,
    account_did: &str,
    cids: &[String],
    rev: &str,
) -> Result<u64, sqlx::Error> {
    let mut updated = 0u64;
    // Batch to stay well under SQLite's bound-parameter limit.
    for chunk in cids.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(",");
        let sql =
            format!("UPDATE blocks SET rev = ? WHERE account_did = ? AND cid IN ({placeholders})");
        let mut q = sqlx::query(&sql).bind(rev).bind(account_did);
        for cid in chunk {
            q = q.bind(cid);
        }
        updated += q.execute(pool).await?.rows_affected();
    }
    Ok(updated)
}

/// List the CIDs of an account's blocks introduced after revision `since`.
///
/// Drives `com.atproto.sync.getRepo?since=<rev>`: returns exactly the blocks a consumer holding
/// the repo as of `since` is missing. Revisions are TIDs, so the `rev > since` string comparison
/// orders by commit time. Blocks with a NULL `rev` (an in-flight commit's, or a backfill gap) are
/// excluded — they are not part of any committed delta past `since`.
pub async fn list_block_cids_since(
    pool: &SqlitePool,
    account_did: &str,
    since: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT cid FROM blocks WHERE account_did = ? AND rev > ? ORDER BY cid")
        .bind(account_did)
        .bind(since)
        .fetch_all(pool)
        .await
}

/// Aggregate repo-block storage stats for a single account.
///
/// Backs the operator usage endpoint. `commit_count` counts the distinct non-NULL `rev`
/// values still represented among the account's blocks: because GC reclaims superseded
/// blocks (old MST nodes, replaced records), this is a lower bound on the repo's full
/// commit history, not an exact total — there is no separate commit log to count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStats {
    /// Number of blocks stored for the account.
    pub block_count: i64,
    /// Total size of those blocks' raw bytes.
    pub total_bytes: i64,
    /// Distinct non-NULL commit revisions among the account's blocks (see struct docs).
    pub commit_count: i64,
}

/// Compute [`BlockStats`] for an account in a single query.
///
/// An account with no blocks yields all-zero stats (the aggregates COALESCE to 0 and
/// `COUNT(DISTINCT rev)` of an empty set is 0).
pub async fn account_block_stats(
    pool: &SqlitePool,
    account_did: &str,
) -> Result<BlockStats, sqlx::Error> {
    let row: (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(LENGTH(bytes)), 0), COUNT(DISTINCT rev) \
         FROM blocks WHERE account_did = ?",
    )
    .bind(account_did)
    .fetch_one(pool)
    .await?;

    Ok(BlockStats {
        block_count: row.0,
        total_bytes: row.1,
        commit_count: row.2,
    })
}

// ── SqliteBlockStore adapter ─────────────────────────────────────────────────────

/// Adapter that implements atrium-repo's blockstore traits over SQLite.
///
/// Each block is written via `db::blocks::put_block` and read via `db::blocks::get_block`.
/// The CID is computed from `(codec, hash, contents)` using the same algorithm as
/// atrium-repo's `MemoryBlockStore`.
pub struct SqliteBlockStore {
    pool: SqlitePool,
    account_did: String,
}

impl SqliteBlockStore {
    pub fn new(pool: SqlitePool, account_did: String) -> Self {
        Self { pool, account_did }
    }
}

impl AsyncBlockStoreRead for SqliteBlockStore {
    async fn read_block_into(
        &mut self,
        cid: Cid,
        contents: &mut Vec<u8>,
    ) -> Result<(), blockstore::Error> {
        let cid_str = cid.to_string();
        let row = get_block(&self.pool, &cid_str)
            .await
            .map_err(|e| blockstore::Error::Other(Box::new(e)))?;

        match row {
            Some(block) => {
                contents.clear();
                contents.extend_from_slice(&block.bytes);
                Ok(())
            }
            None => Err(blockstore::Error::CidNotFound),
        }
    }
}

impl AsyncBlockStoreWrite for SqliteBlockStore {
    async fn write_block(
        &mut self,
        codec: u64,
        hash: u64,
        contents: &[u8],
    ) -> Result<Cid, blockstore::Error> {
        // Compute CID using the same algorithm as MemoryBlockStore.
        if hash != blockstore::SHA2_256 {
            return Err(blockstore::Error::UnsupportedHash(hash));
        }
        let digest = sha2::Sha256::digest(contents);
        let mh = atrium_repo::Multihash::wrap(hash, digest.as_slice())
            .expect("SHA2-256 digest is always 32 bytes");
        let cid = Cid::new_v1(codec, mh);

        let cid_str = cid.to_string();
        put_block(&self.pool, &cid_str, &self.account_did, contents)
            .await
            .map_err(|e| blockstore::Error::Other(Box::new(e)))?;

        Ok(cid)
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

    #[tokio::test]
    async fn account_block_stats_empty_account_is_all_zero() {
        let pool = test_pool().await;
        let stats = account_block_stats(&pool, "did:plc:nostats").await.unwrap();
        assert_eq!(
            stats,
            BlockStats {
                block_count: 0,
                total_bytes: 0,
                commit_count: 0,
            }
        );
    }

    #[tokio::test]
    async fn account_block_stats_counts_bytes_and_distinct_revs() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:stats").await;

        // Two blocks tagged with one rev, one block with another, one still NULL.
        put_block(&pool, "bafs1", "did:plc:stats", b"\xa1aa")
            .await
            .unwrap(); // 3 bytes
        put_block(&pool, "bafs2", "did:plc:stats", b"\xa1bbbb")
            .await
            .unwrap(); // 5 bytes
        tag_blocks_rev(
            &pool,
            "did:plc:stats",
            &["bafs1".to_string(), "bafs2".to_string()],
            "3aaa",
        )
        .await
        .unwrap();
        put_block(&pool, "bafs3", "did:plc:stats", b"\xa1c")
            .await
            .unwrap(); // 2 bytes
        tag_blocks_rev(&pool, "did:plc:stats", &["bafs3".to_string()], "3bbb")
            .await
            .unwrap();
        put_block(&pool, "bafs4", "did:plc:stats", b"\xa1dddddd")
            .await
            .unwrap(); // 7 bytes, NULL rev

        let stats = account_block_stats(&pool, "did:plc:stats").await.unwrap();
        assert_eq!(stats.block_count, 4);
        assert_eq!(stats.total_bytes, 3 + 5 + 2 + 7);
        // Two distinct non-NULL revs; the NULL-rev block is not counted as a commit.
        assert_eq!(stats.commit_count, 2);
    }

    #[tokio::test]
    async fn account_block_stats_scoped_per_account() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:mine").await;
        insert_test_account(&pool, "did:plc:theirs").await;
        put_block(&pool, "bafmine", "did:plc:mine", b"\xa1x")
            .await
            .unwrap();
        put_block(&pool, "baftheirs", "did:plc:theirs", b"\xa1yyyy")
            .await
            .unwrap();

        let stats = account_block_stats(&pool, "did:plc:mine").await.unwrap();
        assert_eq!(stats.block_count, 1);
        assert_eq!(stats.total_bytes, 2);
    }

    #[tokio::test]
    async fn delete_unreachable_keeps_reachable_blocks() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:gc").await;
        put_block(&pool, "bafkeep1", "did:plc:gc", b"\xa1a")
            .await
            .unwrap();
        put_block(&pool, "bafkeep2", "did:plc:gc", b"\xa1b")
            .await
            .unwrap();
        put_block(&pool, "bafgarbage", "did:plc:gc", b"\xa1c")
            .await
            .unwrap();

        let keep: HashSet<String> = ["bafkeep1".to_string(), "bafkeep2".to_string()]
            .into_iter()
            .collect();
        let removed = delete_unreachable_blocks(&pool, "did:plc:gc", &keep)
            .await
            .unwrap();

        assert_eq!(removed, 1, "only the unreachable block is reclaimed");
        assert!(get_block(&pool, "bafkeep1").await.unwrap().is_some());
        assert!(get_block(&pool, "bafkeep2").await.unwrap().is_some());
        assert!(get_block(&pool, "bafgarbage").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn tag_blocks_rev_stamps_only_the_named_cids() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:tag").await;
        for c in ["bafa", "bafb", "bafc"] {
            put_block(&pool, c, "did:plc:tag", b"\xa1x").await.unwrap();
        }

        // Commit A tags only its two blocks; the third stays NULL (it belongs to no committed set).
        let tagged = tag_blocks_rev(
            &pool,
            "did:plc:tag",
            &["bafa".to_string(), "bafb".to_string()],
            "3aaa",
        )
        .await
        .unwrap();
        assert_eq!(tagged, 2);

        // Commit B tags its own block, disjoint from A's — no contention, A's tags are untouched.
        tag_blocks_rev(&pool, "did:plc:tag", &["bafc".to_string()], "3bbb")
            .await
            .unwrap();

        // since == A's rev → only B's block is newer; A's blocks (rev == since) are excluded.
        assert_eq!(
            list_block_cids_since(&pool, "did:plc:tag", "3aaa")
                .await
                .unwrap(),
            vec!["bafc".to_string()]
        );
    }

    #[tokio::test]
    async fn tag_blocks_rev_restamps_reintroduced_block() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:restamp").await;
        put_block(&pool, "bafx", "did:plc:restamp", b"\xa1x")
            .await
            .unwrap();

        tag_blocks_rev(&pool, "did:plc:restamp", &["bafx".to_string()], "3aaa")
            .await
            .unwrap();
        // A later commit re-introduces the same CID: the unconditional UPDATE moves it forward, so
        // a consumer past the original rev still receives it.
        tag_blocks_rev(&pool, "did:plc:restamp", &["bafx".to_string()], "3ccc")
            .await
            .unwrap();

        assert_eq!(
            list_block_cids_since(&pool, "did:plc:restamp", "3bbb")
                .await
                .unwrap(),
            vec!["bafx".to_string()],
            "re-introduced block must carry the newer rev"
        );
    }

    #[tokio::test]
    async fn list_block_cids_since_excludes_at_or_before_and_null() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:since").await;
        put_block(&pool, "bafold", "did:plc:since", b"\xa1a")
            .await
            .unwrap();
        tag_blocks_rev(&pool, "did:plc:since", &["bafold".to_string()], "3kkk")
            .await
            .unwrap();
        put_block(&pool, "bafnew", "did:plc:since", b"\xa1b")
            .await
            .unwrap();
        tag_blocks_rev(&pool, "did:plc:since", &["bafnew".to_string()], "3mmm")
            .await
            .unwrap();
        // A still-untagged (NULL rev) block must never appear in a since delta.
        put_block(&pool, "bafnull", "did:plc:since", b"\xa1c")
            .await
            .unwrap();

        // since == latest rev → nothing new.
        assert!(list_block_cids_since(&pool, "did:plc:since", "3mmm")
            .await
            .unwrap()
            .is_empty());

        // since == first rev → only the second commit's block (NULL excluded).
        assert_eq!(
            list_block_cids_since(&pool, "did:plc:since", "3kkk")
                .await
                .unwrap(),
            vec!["bafnew".to_string()]
        );

        // since below everything → both tagged blocks (NULL still excluded).
        assert_eq!(
            list_block_cids_since(&pool, "did:plc:since", "3aaa")
                .await
                .unwrap(),
            vec!["bafnew".to_string(), "bafold".to_string()]
        );
    }

    // ── SqliteBlockStore adapter tests ──────────────────────────────────────────────

    use atrium_repo::blockstore::{
        AsyncBlockStoreRead, AsyncBlockStoreWrite, MemoryBlockStore, DAG_CBOR, SHA2_256,
    };
    use atrium_repo::mst::Tree;

    #[tokio::test]
    async fn sqlite_blockstore_read_write_roundtrip() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:adapter").await;

        let mut bs = SqliteBlockStore::new(pool.clone(), "did:plc:adapter".to_string());
        let data = b"\xa1hello";

        let cid = bs.write_block(DAG_CBOR, SHA2_256, data).await.unwrap();
        let mut buf = Vec::new();
        bs.read_block_into(cid, &mut buf).await.unwrap();

        assert_eq!(buf, data);
    }

    #[tokio::test]
    async fn sqlite_blockstore_read_missing_returns_cid_not_found() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:adapter").await;

        let mut bs = SqliteBlockStore::new(pool, "did:plc:adapter".to_string());

        // Write one block to get a valid CID, then try to read a different one.
        let _cid = bs
            .write_block(DAG_CBOR, SHA2_256, b"\xa1data")
            .await
            .unwrap();

        // Construct a different CID that doesn't exist.
        let digest = sha2::Sha256::digest(b"\xa1other");
        let mh = atrium_repo::Multihash::wrap(SHA2_256, &digest).unwrap();
        let missing_cid = atrium_repo::Cid::new_v1(DAG_CBOR, mh);

        let mut buf = Vec::new();
        let result = bs.read_block_into(missing_cid, &mut buf).await;
        assert!(result.is_err());
    }

    /// Build the same MST through SqliteBlockStore and MemoryBlockStore.
    /// Root CIDs must be identical — this is the core interop guarantee.
    #[tokio::test]
    async fn sqlite_blockstore_parity_with_memory() {
        let pool = test_pool().await;
        insert_test_account(&pool, "did:plc:parity").await;

        let keys = &[
            "A0/374913",
            "B1/986427",
            "C0/451630",
            "E0/670489",
            "F1/085263",
            "G0/765327",
        ];
        let leaf_data = b"\xa1dummy-record";

        // Build through MemoryBlockStore.
        let mut mem_bs = MemoryBlockStore::new();
        let leaf_cid = mem_bs
            .write_block(DAG_CBOR, SHA2_256, leaf_data)
            .await
            .unwrap();
        let mut mem_tree = Tree::create(&mut mem_bs).await.unwrap();
        for k in keys {
            mem_tree.add(k, leaf_cid).await.unwrap();
        }
        let mem_root = mem_tree.root();

        // Build through SqliteBlockStore.
        let mut sqlite_bs = SqliteBlockStore::new(pool, "did:plc:parity".to_string());
        let leaf_cid2 = sqlite_bs
            .write_block(DAG_CBOR, SHA2_256, leaf_data)
            .await
            .unwrap();
        assert_eq!(leaf_cid, leaf_cid2, "leaf CID must match");

        let mut sqlite_tree = Tree::create(&mut sqlite_bs).await.unwrap();
        for k in keys {
            sqlite_tree.add(k, leaf_cid2).await.unwrap();
        }
        let sqlite_root = sqlite_tree.root();

        assert_eq!(
            mem_root, sqlite_root,
            "SqliteBlockStore must produce the same root CID as MemoryBlockStore"
        );
    }
}
