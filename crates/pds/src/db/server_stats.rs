// pattern: Functional Core (SQL queries only; no business logic)

//! Server-wide row-count readouts for the operator health endpoint
//! (`GET /v1/admin/health`).
//!
//! Everything here is a whole-table aggregate — no per-account filtering. On a v0.1-scale
//! instance these are cheap; if the block/blob tables ever grow to where a full COUNT
//! hurts, this is the seam where sampling or cached counts would land.

use sqlx::SqlitePool;

/// Whole-server row counts, gathered in one pass for the health payload.
#[derive(Debug, Clone, Copy)]
pub struct ServerStats {
    pub accounts_total: i64,
    /// Derived-lifecycle buckets. Precedence mirrors
    /// [`super::accounts::AccountLifecycle::from_timestamps`]
    /// (takendown > suspended > deactivated), so the four buckets partition
    /// `accounts_total` exactly.
    pub accounts_active: i64,
    pub accounts_deactivated: i64,
    pub accounts_suspended: i64,
    pub accounts_takendown: i64,
    /// Physical blob rows (one per stored CID, shared across owners) and their total bytes.
    pub blob_count: i64,
    pub blob_bytes: i64,
    /// Physical repo-block rows (MST nodes + records, one per stored CID).
    pub block_count: i64,
    /// Retained firehose event-log rows (`repo_seq`) — the replayable backlog.
    pub firehose_events: i64,
}

#[derive(sqlx::FromRow)]
struct AccountBuckets {
    total: i64,
    active: i64,
    deactivated: i64,
    suspended: i64,
    takendown: i64,
}

/// Gather every readout. Four aggregate queries; each observes its own snapshot (SQLite
/// WAL), which is fine for an operator glance — the numbers move independently anyway.
pub async fn server_stats(db: &SqlitePool) -> Result<ServerStats, sqlx::Error> {
    // The CASE arms mirror AccountLifecycle::as_sql_predicate's precedence
    // (takendown > suspended > deactivated) so these buckets always match what the
    // account-listing status filter would return.
    let accounts: AccountBuckets = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN taken_down_at IS NULL AND suspended_at IS NULL
                                   AND deactivated_at IS NULL THEN 1 ELSE 0 END), 0) AS active,
            COALESCE(SUM(CASE WHEN taken_down_at IS NULL AND suspended_at IS NULL
                                   AND deactivated_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS deactivated,
            COALESCE(SUM(CASE WHEN taken_down_at IS NULL
                                   AND suspended_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS suspended,
            COALESCE(SUM(CASE WHEN taken_down_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS takendown
        FROM accounts
        "#,
    )
    .fetch_one(db)
    .await?;

    let (blob_count, blob_bytes): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM blobs")
            .fetch_one(db)
            .await?;

    let block_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks")
        .fetch_one(db)
        .await?;

    let firehose_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repo_seq")
        .fetch_one(db)
        .await?;

    Ok(ServerStats {
        accounts_total: accounts.total,
        accounts_active: accounts.active,
        accounts_deactivated: accounts.deactivated,
        accounts_suspended: accounts.suspended,
        accounts_takendown: accounts.takendown,
        blob_count,
        blob_bytes,
        block_count,
        firehose_events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let db = crate::db::open_pool("sqlite::memory:").await.unwrap();
        crate::db::run_migrations(&db).await.unwrap();
        db
    }

    async fn insert_account(
        db: &SqlitePool,
        did: &str,
        dea: Option<&str>,
        sus: Option<&str>,
        tak: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at,
                                   deactivated_at, suspended_at, taken_down_at)
             VALUES (?, ?, 'x', datetime('now'), datetime('now'), ?, ?, ?)",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .bind(dea)
        .bind(sus)
        .bind(tak)
        .execute(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn empty_database_reports_zeros() {
        let db = pool().await;
        let stats = server_stats(&db).await.unwrap();
        assert_eq!(stats.accounts_total, 0);
        assert_eq!(stats.accounts_active, 0);
        assert_eq!(stats.blob_count, 0);
        assert_eq!(stats.blob_bytes, 0);
        assert_eq!(stats.block_count, 0);
        assert_eq!(stats.firehose_events, 0);
    }

    #[tokio::test]
    async fn lifecycle_buckets_partition_total_with_precedence() {
        let db = pool().await;
        let ts = Some("2026-01-01T00:00:00Z");
        insert_account(&db, "did:plc:active", None, None, None).await;
        insert_account(&db, "did:plc:deactivated", ts, None, None).await;
        insert_account(&db, "did:plc:suspended", None, ts, None).await;
        // Deactivated AND suspended: suspension wins, exactly like the listing filter.
        insert_account(&db, "did:plc:both", ts, ts, None).await;
        // Takedown trumps everything.
        insert_account(&db, "did:plc:takendown", ts, ts, ts).await;

        let stats = server_stats(&db).await.unwrap();
        assert_eq!(stats.accounts_total, 5);
        assert_eq!(stats.accounts_active, 1);
        assert_eq!(stats.accounts_deactivated, 1);
        assert_eq!(stats.accounts_suspended, 2);
        assert_eq!(stats.accounts_takendown, 1);
        assert_eq!(
            stats.accounts_active
                + stats.accounts_deactivated
                + stats.accounts_suspended
                + stats.accounts_takendown,
            stats.accounts_total
        );
    }

    #[tokio::test]
    async fn blob_bytes_sum_and_counts_reflect_rows() {
        let db = pool().await;
        insert_account(&db, "did:plc:owner", None, None, None).await;
        for (cid, size) in [("bafkone", 100_i64), ("bafktwo", 250)] {
            sqlx::query(
                "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path)
                 VALUES (?, 'did:plc:owner', 'application/octet-stream', ?, ?)",
            )
            .bind(cid)
            .bind(size)
            .bind(format!("ba/{cid}"))
            .execute(&db)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO blocks (cid, account_did, bytes) VALUES ('bafyblock', 'did:plc:owner', x'00')")
            .execute(&db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO repo_seq (seq, did, event_type, event, sequenced_at)
             VALUES (1, 'did:plc:owner', 'commit', x'00', '2026-01-01T00:00:00.000Z')",
        )
        .execute(&db)
        .await
        .unwrap();

        let stats = server_stats(&db).await.unwrap();
        assert_eq!(stats.blob_count, 2);
        assert_eq!(stats.blob_bytes, 350);
        assert_eq!(stats.block_count, 1);
        assert_eq!(stats.firehose_events, 1);
    }
}
