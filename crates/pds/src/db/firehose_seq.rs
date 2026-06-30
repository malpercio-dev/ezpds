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
    // `seq` is assigned by our own sequencer and never legitimately exceeds i64::MAX, but reject
    // rather than silently wrap (a wrapped negative would corrupt the ordering the PK enforces).
    let seq = i64::try_from(seq)
        .map_err(|_| sqlx::Error::Protocol("firehose seq exceeds i64 range".into()))?;
    sqlx::query(
        "INSERT INTO repo_seq (seq, did, event_type, event, sequenced_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(seq)
    .bind(did)
    .bind(event_type)
    .bind(event)
    .bind(sequenced_at)
    .execute(db)
    .await?;
    Ok(())
}

/// The highest sequence number whose `sequenced_at` is strictly older than the `cutoff`
/// (an RFC 3339 timestamp in the same fixed-width millis+`Z` format `insert_event` writes).
///
/// This is the age-based low-water mark for the retention sweep: every row at or below it is
/// older than the configured retention window and therefore prunable. Returns `None` when no row
/// is that old (the cutoff is in the past of no event), meaning age-based pruning prunes nothing
/// this pass. `sequenced_at` is stored as RFC 3339 text; because the writer always uses the same
/// fixed-width millis+`Z` form, a lexicographic `<` comparison is chronological.
///
/// `COALESCE(MAX(seq), 0)` collapses the no-matching-row case (NULL) to `0`, which is
/// unambiguous here because `seq` starts at `1` — a `0` result therefore means "nothing old
/// enough" and is mapped to `None`, matching the [`max_seq`] idiom.
pub async fn age_cutoff_seq(
    db: &SqlitePool,
    cutoff_rfc3339: &str,
) -> Result<Option<u64>, sqlx::Error> {
    let seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM repo_seq WHERE sequenced_at < ?")
            .bind(cutoff_rfc3339)
            .fetch_one(db)
            .await?;
    Ok(if seq > 0 { Some(seq as u64) } else { None })
}

/// Delete every row at or below `low_water_mark`, returning how many were removed.
///
/// `seq` is the `INTEGER PRIMARY KEY`, so the range delete is index-backed. The sweep computes
/// `low_water_mark` from the enabled retention knobs and **never** sets it at or above the live
/// frontier (`MAX(seq)`), so a reconnecting relay can always resume from the newest retained
/// row and `seq` stays monotonic (the PK guarantees numbers are never reused after a prune).
pub async fn prune_below(db: &SqlitePool, low_water_mark: u64) -> Result<u64, sqlx::Error> {
    let low = i64::try_from(low_water_mark)
        .map_err(|_| sqlx::Error::Protocol("firehose prune watermark exceeds i64 range".into()))?;
    let res = sqlx::query("DELETE FROM repo_seq WHERE seq <= ?")
        .bind(low)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
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
    // Reject (rather than wrap) sequence bounds SQLite can't represent; both are sequencer-derived
    // and never legitimately exceed i64::MAX, but a wrapped negative would silently skew the range.
    let after = i64::try_from(after)
        .map_err(|_| sqlx::Error::Protocol("firehose cursor exceeds i64 range".into()))?;
    let upper = i64::try_from(upper)
        .map_err(|_| sqlx::Error::Protocol("firehose frontier exceeds i64 range".into()))?;
    sqlx::query_as::<_, StoredEventRow>(
        "SELECT seq, event_type, event FROM repo_seq \
         WHERE seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ?",
    )
    .bind(after)
    .bind(upper)
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
    async fn age_cutoff_seq_is_none_when_nothing_old_enough() {
        let db = pool().await;
        insert(&db, 1, "commit").await; // sequenced_at = 2026-06-30T00:00:00.000Z

        // Nothing is older than 2020 → no age-based watermark.
        assert_eq!(
            age_cutoff_seq(&db, "2020-01-01T00:00:00.000Z")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn age_cutoff_seq_returns_highest_old_seq() {
        let db = pool().await;
        insert(&db, 1, "commit").await;
        insert(&db, 2, "commit").await;
        insert(&db, 3, "commit").await; // sequenced_at at the fixed 2026-06-30 instant

        // The cutoff sits just after the inserted instant, so all three rows are older and the
        // watermark is the highest of them (a contiguous age prefix, not a scattered set).
        assert_eq!(
            age_cutoff_seq(&db, "2026-06-30T00:00:01.000Z")
                .await
                .unwrap(),
            Some(3)
        );
    }

    #[tokio::test]
    async fn prune_below_deletes_only_at_or_below_watermark() {
        let db = pool().await;
        for seq in 1..=5 {
            insert(&db, seq, "commit").await;
        }

        let removed = prune_below(&db, 3).await.unwrap();
        assert_eq!(removed, 3, "seq 1, 2, 3 are removed");

        // The retained suffix is exactly 4, 5 — the frontier and everything above the watermark.
        let rows = events_in_range(&db, 0, 5, 100).await.unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![4, 5]);
    }

    #[tokio::test]
    async fn prune_below_at_zero_is_a_noop_when_all_seqs_positive() {
        let db = pool().await;
        insert(&db, 1, "commit").await;
        insert(&db, 2, "commit").await;

        // Watermark 0 deletes nothing because every seq is >= 1.
        assert_eq!(prune_below(&db, 0).await.unwrap(), 0);
        assert_eq!(events_in_range(&db, 0, 2, 100).await.unwrap().len(), 2);
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
