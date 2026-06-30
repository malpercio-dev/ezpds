// pattern: Imperative Shell
//
// Query functions for the V028 `repo_seq` table — the persistent firehose event log that
// backs `com.atproto.sync.subscribeRepos` cursor replay across restarts. See
// V028__repo_seq.sql for the schema rationale; the sequencer that drives these queries lives
// in `firehose.rs`.

use sqlx::SqlitePool;

/// One persisted firehose event, as read back for cursor replay.
///
/// `seq` is stored as SQLite's signed `INTEGER`; the sequencer only ever assigns positive
/// values, so callers convert to `u64` at the boundary. `event` is the DAG-CBOR-serialized
/// payload (`firehose::decode_stored_event` turns it back into a `FirehoseEvent`).
#[derive(Debug, sqlx::FromRow)]
pub struct StoredEventRow {
    pub seq: i64,
    pub event_type: String,
    pub event: Vec<u8>,
}

/// The highest sequence number persisted so far, or 0 if the log is empty.
///
/// Read once at startup to seed the in-memory sequence counter so `seq` continues
/// monotonically across restarts rather than resetting to 0.
pub async fn max_seq(db: &SqlitePool) -> Result<u64, sqlx::Error> {
    // COALESCE keeps the empty-table case as 0 rather than NULL.
    let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM repo_seq")
        .fetch_one(db)
        .await?;
    Ok(seq.max(0) as u64)
}

/// Append one sequenced event to the log.
///
/// `seq` is assigned by the in-process sequencer (not AUTOINCREMENT) so a failed insert does
/// not consume a number; the caller persists *before* broadcasting, so every value visible to
/// a live subscriber is already durable here. A duplicate `seq` is a sequencer bug and surfaces
/// as a PRIMARY KEY violation rather than being silently ignored.
pub async fn insert_event(
    db: &SqlitePool,
    seq: u64,
    did: &str,
    event_type: &str,
    event: &[u8],
    sequenced_at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO repo_seq (seq, did, event_type, event, sequenced_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(seq as i64)
    .bind(did)
    .bind(event_type)
    .bind(event)
    .bind(sequenced_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Read up to `limit` events with `after < seq <= upper`, oldest first.
///
/// This is the cursor-replay page query: a subscriber that reconnects with `cursor = after`
/// receives exactly the events it missed, bounded above by `upper` (the sequence frontier
/// captured when the subscription attached, so replay and the live stream stay disjoint). The
/// caller pages by passing the last `seq` it received as the next `after` until a short page
/// signals the end.
pub async fn events_in_range(
    db: &SqlitePool,
    after: u64,
    upper: u64,
    limit: u32,
) -> Result<Vec<StoredEventRow>, sqlx::Error> {
    sqlx::query_as::<_, StoredEventRow>(
        "SELECT seq, event_type, event FROM repo_seq \
         WHERE seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ?",
    )
    .bind(after as i64)
    .bind(upper as i64)
    .bind(limit)
    .fetch_all(db)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn pool() -> SqlitePool {
        let db = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&db).await.unwrap();
        db
    }

    async fn insert(db: &SqlitePool, seq: u64, ty: &str) {
        insert_event(
            db,
            seq,
            "did:plc:a",
            ty,
            &[0xCA, 0xFE],
            "2026-06-30T00:00:00.000Z",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn max_seq_is_zero_when_empty() {
        let db = pool().await;
        assert_eq!(max_seq(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn max_seq_reflects_highest_inserted() {
        let db = pool().await;
        insert(&db, 1, "commit").await;
        insert(&db, 2, "account").await;
        insert(&db, 3, "commit").await;
        assert_eq!(max_seq(&db).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn events_in_range_returns_after_cursor_in_order() {
        let db = pool().await;
        for seq in 1..=5 {
            insert(&db, seq, "commit").await;
        }

        // Cursor at 2, upper at 5: exactly 3, 4, 5 in ascending order.
        let rows = events_in_range(&db, 2, 5, 100).await.unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![3, 4, 5]);
    }

    #[tokio::test]
    async fn events_in_range_excludes_above_upper_bound() {
        let db = pool().await;
        for seq in 1..=5 {
            insert(&db, seq, "commit").await;
        }

        // Upper bound 3 excludes 4 and 5 even though they exist (they belong to the live
        // stream for a subscription whose frontier was 3).
        let rows = events_in_range(&db, 0, 3, 100).await.unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn events_in_range_pages_with_limit() {
        let db = pool().await;
        for seq in 1..=5 {
            insert(&db, seq, "commit").await;
        }

        // First page of 2.
        let page1 = events_in_range(&db, 0, 5, 2).await.unwrap();
        assert_eq!(page1.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);

        // Next page resumes after the last seq of the previous page.
        let page2 = events_in_range(&db, page1.last().unwrap().seq as u64, 5, 2)
            .await
            .unwrap();
        assert_eq!(page2.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![3, 4]);
    }

    #[tokio::test]
    async fn stored_row_carries_type_and_blob() {
        let db = pool().await;
        insert(&db, 1, "account").await;

        let rows = events_in_range(&db, 0, 1, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "account");
        assert_eq!(rows[0].event, vec![0xCA, 0xFE]);
    }
}
