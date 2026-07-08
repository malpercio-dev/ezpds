// pattern: Imperative Shell
//
// Query functions for the V028 `repo_seq` table — the persistent firehose event log that
// backs `com.atproto.sync.subscribeRepos` cursor replay across restarts. See
// V028__repo_seq.sql for the schema rationale; the sequencer that drives these queries lives
// in `firehose.rs`.

use sqlx::{Sqlite, SqlitePool};

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
///
/// Generic over the executor so the sequencer can insert this row into a caller-owned
/// transaction (making it commit atomically with, e.g., the repo-root CAS) as well as against
/// the bare pool.
pub async fn insert_event<'e, E>(
    executor: E,
    seq: u64,
    did: &str,
    event_type: &str,
    event: &[u8],
    sequenced_at: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
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
    .execute(executor)
    .await?;
    Ok(())
}

/// The **lowest** retained sequence number whose `sequenced_at` is at or after the `cutoff`
/// (an RFC 3339 timestamp in the same fixed-width millis+`Z` format [`insert_event`] writes).
///
/// This is the age boundary for the retention sweep: every row strictly older than the
/// configured retention window (`sequenced_at < cutoff`) is prunable, so the age watermark is
/// `boundary − 1`. Returns `None` when *no* row is retained by age this pass (i.e. every row is
/// older than the window), in which case the sweep prunes the whole log up to the frontier guard.
/// `sequenced_at` is stored as RFC 3339 text; because the writer always uses the same fixed-width
/// millis+`Z` form, a lexicographic `>=` comparison is chronological.
///
/// Framing the cutoff as "first *retained* seq" (rather than `MAX(seq)` among old rows) makes
/// the sweep **over-prune-safe**: a row with a skewed-old timestamp can never lift the watermark
/// past fresh rows, because the boundary is the smallest seq that is *not* old. The worst case
/// under non-monotonic timestamps is that an oddly-timestamped row lingers (an under-prune the
/// next pass corrects), never that a fresh row is deleted.
pub async fn retained_boundary_seq(
    db: &SqlitePool,
    cutoff_rfc3339: &str,
) -> Result<Option<u64>, sqlx::Error> {
    let seq: Option<i64> =
        sqlx::query_scalar("SELECT MIN(seq) FROM repo_seq WHERE sequenced_at >= ?")
            .bind(cutoff_rfc3339)
            .fetch_one(db)
            .await?;
    match seq {
        Some(s) => u64::try_from(s)
            .map(Some)
            .map_err(|_| sqlx::Error::Protocol("stored firehose seq is negative".into())),
        None => Ok(None),
    }
}

/// The `sequenced_at` of the oldest retained event, or `None` when the log is empty.
///
/// Backs the `firehose_backfill_window_seconds` gauge: how far back a reconnecting
/// subscriber's cursor can reach before replay degrades to best-effort. Because the writer
/// always uses the same fixed-width RFC 3339 millis+`Z` form, `MIN()` over the text column
/// is chronological.
pub async fn oldest_sequenced_at(db: &SqlitePool) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT MIN(sequenced_at) FROM repo_seq")
        .fetch_one(db)
        .await
}

/// First replay page plus whether the cursor is inside the retained range.
///
/// `cursor_present` is computed in the same SQL statement as the first page (`EXISTS(seq <=
/// cursor)` projected onto each returned row), so the first-row pruned-prefix decision observes
/// the same SQLite snapshot as the rows it is deciding about. If the first page is empty the flag
/// is false; callers don't need it because an empty backlog before `upper` fails the frontier
/// check.
pub struct FirstReplayPage {
    pub rows: Vec<StoredEventRow>,
    pub cursor_present: bool,
}

/// Read the first cursor-replay page and the cursor-presence bit in one SQLite snapshot.
pub async fn first_events_in_range_with_cursor_presence(
    db: &SqlitePool,
    cursor: u64,
    upper: u64,
    limit: u32,
) -> Result<FirstReplayPage, sqlx::Error> {
    let cursor = i64::try_from(cursor)
        .map_err(|_| sqlx::Error::Protocol("firehose cursor exceeds i64 range".into()))?;
    let upper = i64::try_from(upper)
        .map_err(|_| sqlx::Error::Protocol("firehose frontier exceeds i64 range".into()))?;
    let rows: Vec<(i64, String, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT seq, event_type, event, \
         EXISTS(SELECT 1 FROM repo_seq WHERE seq <= ?) AS cursor_present \
         FROM repo_seq WHERE seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ?",
    )
    .bind(cursor)
    .bind(cursor)
    .bind(upper)
    .bind(i64::from(limit))
    .fetch_all(db)
    .await?;

    let cursor_present = rows.first().is_some_and(|(_, _, _, present)| *present != 0);
    let rows = rows
        .into_iter()
        .map(|(seq, event_type, event, _)| StoredEventRow {
            seq,
            event_type,
            event,
        })
        .collect();
    Ok(FirstReplayPage {
        rows,
        cursor_present,
    })
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

/// This DID's `commit` events, newest-first, capped at `limit`. Read-after-write walks these
/// from the top and stops as soon as a commit's rev is at or below the AppView's indexed rev,
/// so `limit` only bounds the pathological case (a burst of unindexed writes); a small value
/// (e.g. 200) is ample given AppView lag is seconds.
pub async fn recent_commits_for_did(
    db: &SqlitePool,
    did: &str,
    limit: u32,
) -> Result<Vec<StoredEventRow>, sqlx::Error> {
    sqlx::query_as::<_, StoredEventRow>(
        "SELECT seq, event_type, event FROM repo_seq \
         WHERE did = ? AND event_type = 'commit' ORDER BY seq DESC LIMIT ?",
    )
    .bind(did)
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
        insert_at(db, seq, ty, "2026-06-30T00:00:00.000Z").await;
    }

    async fn insert_at(db: &SqlitePool, seq: u64, ty: &str, sequenced_at: &str) {
        insert_event(db, seq, "did:plc:a", ty, &[0xCA, 0xFE], sequenced_at)
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
    async fn retained_boundary_is_min_retained_seq_when_some_rows_are_old() {
        let db = pool().await;
        // Rows 1-3 are old (2020), rows 4-5 are young (2026) — a contiguous age prefix.
        insert_at(&db, 1, "commit", "2020-01-01T00:00:00.000Z").await;
        insert_at(&db, 2, "commit", "2020-01-01T00:00:00.000Z").await;
        insert_at(&db, 3, "commit", "2020-01-01T00:00:00.000Z").await;
        insert_at(&db, 4, "commit", "2026-06-30T00:00:00.000Z").await;
        insert_at(&db, 5, "commit", "2026-06-30T00:00:00.000Z").await;

        // Cutoff between the two epochs: rows with sequenced_at >= cutoff are the 2026 ones,
        // so the retained boundary is the smallest of them (seq 4); the age watermark is 3.
        assert_eq!(
            retained_boundary_seq(&db, "2026-06-29T00:00:00.000Z")
                .await
                .unwrap(),
            Some(4)
        );
    }

    #[tokio::test]
    async fn retained_boundary_is_none_when_all_rows_are_old() {
        let db = pool().await;
        insert_at(&db, 1, "commit", "2020-01-01T00:00:00.000Z").await;
        insert_at(&db, 2, "commit", "2020-01-01T00:00:00.000Z").await;

        // A cutoff in 2026 retains nothing (every row is older) → the sweep prunes the whole log.
        assert_eq!(
            retained_boundary_seq(&db, "2026-06-30T00:00:00.000Z")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn retained_boundary_is_min_seq_when_nothing_is_old() {
        let db = pool().await;
        insert(&db, 1, "commit").await;
        insert(&db, 2, "commit").await;
        insert(&db, 3, "commit").await; // all at 2026-06-30

        // A cutoff in 2020 (far past) retains every row → boundary is the smallest seq, and the
        // age watermark (boundary - 1) is 0, meaning age prunes nothing this pass.
        assert_eq!(
            retained_boundary_seq(&db, "2020-01-01T00:00:00.000Z")
                .await
                .unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn retained_boundary_is_over_prune_safe_for_non_monotonic_timestamps() {
        let db = pool().await;
        // A high-seq row (seq 50) carries an OLD timestamp, while lower-seq rows are young.
        // The boundary must be the smallest *retained* seq (1), NOT skewed by the old high row:
        // the age watermark is boundary-1 = 0, so age prunes nothing — the odd row lingers rather
        // than lifting the watermark to delete the fresh young rows.
        insert_at(&db, 1, "commit", "2026-06-30T00:00:00.000Z").await;
        insert_at(&db, 2, "commit", "2026-06-30T00:00:00.000Z").await;
        insert_at(&db, 50, "commit", "2020-01-01T00:00:00.000Z").await;
        assert_eq!(
            retained_boundary_seq(&db, "2026-06-29T00:00:00.000Z")
                .await
                .unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn retained_boundary_rejects_negative_stored_seq() {
        let db = pool().await;
        sqlx::query(
            "INSERT INTO repo_seq (seq, did, event_type, event, sequenced_at) \
             VALUES (-1, 'did:plc:a', 'commit', x'CAFE', '2026-06-30T00:00:00.000Z')",
        )
        .execute(&db)
        .await
        .unwrap();

        let err = retained_boundary_seq(&db, "2026-06-29T00:00:00.000Z")
            .await
            .unwrap_err();
        assert!(matches!(err, sqlx::Error::Protocol(_)));
    }

    #[tokio::test]
    async fn first_page_reports_cursor_present_from_the_same_snapshot() {
        let db = pool().await;
        insert(&db, 1, "commit").await;
        insert(&db, 3, "commit").await;
        insert(&db, 5, "commit").await;

        // Any row at or below the cursor means the cursor is inside the retained range (a lower
        // row survives), so replay must be strict from the cursor. The flag is projected by the
        // same SELECT that reads the first replay page.
        let page = first_events_in_range_with_cursor_presence(&db, 2, 5, 100)
            .await
            .unwrap();
        assert_eq!(
            page.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert!(page.cursor_present, "seq 1 <= cursor 2");

        let page = first_events_in_range_with_cursor_presence(&db, 0, 5, 100)
            .await
            .unwrap();
        assert_eq!(
            page.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
        assert!(!page.cursor_present, "no row <= 0");
    }

    #[tokio::test]
    async fn first_page_reports_false_when_cursor_is_below_a_pruned_prefix() {
        let db = pool().await;
        // Pruned prefix: only the suffix {3, 5} survives, so cursors 0, 1, and 2 are all below the
        // oldest retained row (seq 3) and must read as "outside the retained range".
        insert(&db, 3, "commit").await;
        insert(&db, 5, "commit").await;
        let page = first_events_in_range_with_cursor_presence(&db, 2, 5, 100)
            .await
            .unwrap();
        assert_eq!(
            page.rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert!(!page.cursor_present);

        let page = first_events_in_range_with_cursor_presence(&db, 4, 5, 100)
            .await
            .unwrap();
        assert_eq!(page.rows.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![5]);
        assert!(page.cursor_present, "seq 3 <= cursor 4");
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

    #[tokio::test]
    async fn recent_commits_for_did_returns_did_commits_newest_first() {
        let db = pool().await;
        let did_a = "did:plc:a";
        let did_b = "did:plc:b";

        // Insert commits and an account event for did_a
        insert_event(
            &db,
            1,
            did_a,
            "commit",
            &[0xCA, 0xFE],
            "2026-06-30T00:00:00.000Z",
        )
        .await
        .unwrap();
        insert_event(
            &db,
            2,
            did_a,
            "account",
            &[0xDE, 0xAD],
            "2026-06-30T00:00:00.000Z",
        )
        .await
        .unwrap();
        insert_event(
            &db,
            3,
            did_a,
            "commit",
            &[0xBE, 0xEF],
            "2026-06-30T00:00:00.000Z",
        )
        .await
        .unwrap();

        // Insert commits for a different DID
        insert_event(
            &db,
            4,
            did_b,
            "commit",
            &[0xDA, 0x7A],
            "2026-06-30T00:00:00.000Z",
        )
        .await
        .unwrap();
        insert_event(
            &db,
            5,
            did_b,
            "commit",
            &[0xC0, 0xFF],
            "2026-06-30T00:00:00.000Z",
        )
        .await
        .unwrap();

        // Query recent commits for did_a: should get only commits (not the account event),
        // newest-first (3, 1)
        let rows = recent_commits_for_did(&db, did_a, 100).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].seq, 3);
        assert_eq!(rows[0].event_type, "commit");
        assert_eq!(rows[1].seq, 1);
        assert_eq!(rows[1].event_type, "commit");

        // Query for did_b: should get its commits newest-first (5, 4)
        let rows = recent_commits_for_did(&db, did_b, 100).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].seq, 5);
        assert_eq!(rows[1].seq, 4);
    }

    #[tokio::test]
    async fn recent_commits_for_did_respects_limit() {
        let db = pool().await;
        let did = "did:plc:a";

        // Insert 5 commits
        for seq in 1..=5 {
            insert_event(
                &db,
                seq,
                did,
                "commit",
                &[0xCA, 0xFE],
                "2026-06-30T00:00:00.000Z",
            )
            .await
            .unwrap();
        }

        // Query with limit 2: should get the 2 newest (5, 4)
        let rows = recent_commits_for_did(&db, did, 2).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].seq, 5);
        assert_eq!(rows[1].seq, 4);
    }

    #[tokio::test]
    async fn recent_commits_for_did_returns_empty_for_nonexistent_did() {
        let db = pool().await;
        insert_event(
            &db,
            1,
            "did:plc:a",
            "commit",
            &[0xCA, 0xFE],
            "2026-06-30T00:00:00.000Z",
        )
        .await
        .unwrap();

        let rows = recent_commits_for_did(&db, "did:plc:nonexistent", 100)
            .await
            .unwrap();
        assert_eq!(rows.len(), 0);
    }
}
