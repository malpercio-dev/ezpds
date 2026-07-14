// pattern: Mixed (unavoidable)

//! Cursor replay: paging the durable `repo_seq` log back out for a subscriber that reconnects
//! with a prior cursor, and the subscription handshake (`Subscription`/`SubscribeOutcome`) that
//! hands a caller a replay reader plus the live broadcast stream, disjoint and gap-free.

use tokio::sync::broadcast;

use super::events::{decode_stored_event, FirehoseError, FirehoseEvent};
use super::Firehose;

/// A new subscription: an optional durable replay reader first, then the live event stream.
///
/// `replay` pages the `(cursor, upper]` range back from the durable log (oldest first); the
/// consumer drains it before streaming live events from `rx`. Because `rx` was taken and the
/// frontier `upper` snapshotted together under the sequencer lock — before any later emit could
/// advance the counter — every live event has `seq > upper`, so replay and the live stream are
/// exactly disjoint: no event is dropped between them and none is delivered twice.
pub struct Subscription<'f> {
    /// The missed events with `cursor < seq <= upper`, oldest first, to send before live streaming.
    /// `None` for a live-only subscription (no cursor).
    pub replay: Option<ReplayReader<'f>>,
    /// Live event stream for everything emitted after this subscription was created
    /// (all with `seq > upper`).
    pub rx: broadcast::Receiver<FirehoseEvent>,
}

/// The outcome of [`Firehose::subscribe_from`].
pub enum SubscribeOutcome<'f> {
    /// The subscription was established; drain `replay`, then stream `rx`.
    Subscribed(Subscription<'f>),
    /// The requested cursor is ahead of the latest assigned sequence (`current`), so it cannot
    /// be honoured — the client is claiming to have seen events that do not exist.
    FutureCursor { current: u64 },
}

/// How many backlog rows to read per query during cursor replay from the durable log, so a
/// subscriber resuming from an old cursor never issues one unbounded query or buffers the whole
/// backlog.
const REPLAY_BATCH: u32 = 256;

/// Paged cursor replay over the durable firehose log.
///
/// Does **not** lock out the retention sweep: instead each [`next_batch`](Self::next_batch)
/// consults the firehose's [`prune_floor`](Firehose::prune_floor), so a sweep that prunes past this
/// reader's position mid-drain is classified as a prune (best-effort re-anchor) rather than a
/// durability hole. That keeps a slow reader from serialising against other readers or blocking the
/// sweep. Each call returns at most `REPLAY_BATCH` decoded events, keeping memory bounded and
/// allowing the socket loop to interleave replay with heartbeat/read-timeout work.
pub struct ReplayReader<'f> {
    firehose: &'f Firehose,
    cursor: u64,
    upper: u64,
    after: u64,
    anchored: bool,
    first_page: bool,
    cursor_present: bool,
    done: bool,
}

impl<'f> ReplayReader<'f> {
    pub(super) fn new(firehose: &'f Firehose, cursor: u64, upper: u64) -> Self {
        Self {
            firehose,
            cursor,
            upper,
            after: cursor,
            anchored: false,
            first_page: true,
            cursor_present: false,
            done: cursor >= upper,
        }
    }

    /// Read and decode the next replay page, oldest first.
    ///
    /// The range is a dense prefix (the sequencer advances `last_seq` only after a row is
    /// persisted), so this enforces density between **consecutive** rows — each `seq` must be
    /// exactly the previous plus one, and the last must reach `upper` — and returns
    /// [`FirehoseError`] on any gap rather than silently skipping a missing `seq`. A negative
    /// stored `seq` (which can't occur from our writer) or a row that won't decode is likewise a
    /// hard error: replay must be exact or fail closed.
    ///
    /// **Best-effort at the pruned prefix.** The retention sweep (`firehose_gc`) prunes a
    /// *contiguous* prefix `seq ≤ watermark`, so the first row above a cursor that falls inside
    /// the pruned window is the oldest retained row, not `cursor + 1`. The first-row density check
    /// is **relaxed only when the cursor sits below the oldest retained row** (no row at or below
    /// the cursor): that is a genuine pruned prefix, so replay degrades to best-effort (the
    /// subscriber receives the retained suffix) rather than failing closed. When a row *does* exist
    /// at or below the cursor, replay is dense from the cursor and any jump on the first row is a
    /// mid-range gap that fails closed. The first replay page projects that cursor-presence bit in
    /// the same SQL statement that reads the rows, so the pruned-prefix decision observes one
    /// SQLite snapshot (no TOCTOU between the batch and the cursor-presence check).
    ///
    /// **Best-effort mid-drain, too.** Replay does not lock out the sweep, so a *slow*
    /// reader can have rows pruned out from under it between pages. Each gap or short/empty tail is
    /// therefore also checked against the firehose's [`prune_floor`](Firehose::prune_floor): when
    /// the next expected `seq` is at or below the floor, the missing rows were pruned, so the reader
    /// re-anchors to the retained suffix (best-effort) instead of failing closed. A gap or missing
    /// tail *above* the floor is a genuine mid-range hole (a durability bug, not a prune) and still
    /// fails closed. The floor is published before the sweep's `DELETE` (see
    /// [`Firehose::note_pruned`]) and read here after the page query, so the classification never
    /// misreads a prune as a hole.
    pub async fn next_batch(&mut self) -> Result<Vec<FirehoseEvent>, FirehoseError> {
        if self.done {
            return Ok(Vec::new());
        }

        let batch = if self.first_page {
            let page = crate::db::firehose_seq::first_events_in_range_with_cursor_presence(
                &self.firehose.db,
                self.cursor,
                self.upper,
                REPLAY_BATCH,
            )
            .await?;
            self.first_page = false;
            self.cursor_present = page.cursor_present;
            page.rows
        } else {
            crate::db::firehose_seq::events_in_range(
                &self.firehose.db,
                self.after,
                self.upper,
                REPLAY_BATCH,
            )
            .await?
        };

        // Read the prune floor *after* the page query so it reflects any sweep whose deletions this
        // page could have observed (`note_pruned` is published before the `DELETE`). The floor only
        // grows, so a value read here is a safe lower bound for the whole page's decisions.
        let prune_floor = self.firehose.prune_floor();

        if batch.is_empty() {
            self.done = true;
            if self.after < self.upper {
                // The remaining `(after, upper]` range is empty. If a sweep pruned past our
                // position (its floor reaches our next expected seq), the tail we were still owed
                // was pruned — degrade to best-effort (deliver nothing more) rather than fail
                // closed. Otherwise the missing rows are a genuine durability hole.
                if prune_floor > self.after {
                    return Ok(Vec::new());
                }
                return Err(FirehoseError::Decode(format!(
                    "firehose replay backlog ended at seq {} before the frontier {}",
                    self.after, self.upper
                )));
            }
            return Ok(Vec::new());
        }

        let page_len = batch.len();
        let mut events = Vec::with_capacity(page_len);
        for row in batch {
            let seq = u64::try_from(row.seq).map_err(|_| {
                FirehoseError::Decode(format!("negative stored firehose seq {}", row.seq))
            })?;
            if seq != self.after + 1 {
                // A gap. Decide pruned run vs mid-range hole. If the next expected seq
                // (`after + 1`) is at or below the prune floor — i.e. `after < prune_floor` — a
                // sweep removed the run we were about to read, so re-anchor to this (retained) row
                // and continue best-effort. This covers both a first-row gap and one that opened up
                // mid-drain after we had already anchored.
                if self.after < prune_floor {
                    self.anchored = true;
                    self.after = seq;
                    events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
                    continue;
                }
                // Not explained by pruning, and we've already anchored: a mid-range hole — fail
                // closed.
                if self.anchored {
                    return Err(FirehoseError::Decode(format!(
                        "firehose replay gap: expected seq {}, found {seq}",
                        self.after + 1
                    )));
                }
                // First-row gap not below the floor: fall back to the same-snapshot cursor-presence
                // bit. If a row still exists at or below the cursor, the gap is a real mid-range
                // hole → fail closed; if the cursor row is gone, a sweep pruned the prefix →
                // best-effort. (The floor can lag a prefix prune performed before this reader was
                // constructed, so the SQL-snapshot check is the authority for the first row.)
                if self.cursor_present {
                    return Err(FirehoseError::Decode(format!(
                        "firehose replay gap: expected seq {}, found {seq}",
                        self.after + 1
                    )));
                }
                // Pruned prefix: best-effort. Anchor here and continue dense from this row.
                self.anchored = true;
                self.after = seq;
                events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
                continue;
            }
            self.anchored = true;
            self.after = seq;
            events.push(decode_stored_event(seq, &row.event_type, &row.event)?);
        }

        if self.after >= self.upper {
            self.done = true;
        } else if (page_len as u32) < REPLAY_BATCH {
            // A short page that didn't reach the frontier: the rows between `after` and `upper` are
            // missing. Prefix pruning removes *low* seqs, so within the retained suffix the range
            // stays dense — a short tail here is a genuine hole unless the sweep's floor has climbed
            // past our position (the retained tail we snapshotted was pruned out from under us).
            self.done = true;
            if prune_floor <= self.after {
                return Err(FirehoseError::Decode(format!(
                    "firehose replay backlog ended at seq {} before the frontier {}",
                    self.after, self.upper
                )));
            }
        }

        Ok(events)
    }

    /// Own this reader while fetching the next replay page.
    ///
    /// This lets route code keep a single in-flight page-read future pinned across `select!`
    /// iterations without borrowing the reader from an outer slot. When the future completes, the
    /// caller gets the reader back with its updated cursor state intact.
    pub async fn into_next_batch(mut self) -> (Self, Result<Vec<FirehoseEvent>, FirehoseError>) {
        let result = self.next_batch().await;
        (self, result)
    }
}

#[cfg(test)]
pub(crate) async fn collect_replay_seqs(
    mut replay: Option<ReplayReader<'_>>,
) -> Result<Vec<u64>, FirehoseError> {
    let mut seqs = Vec::new();
    let Some(reader) = replay.as_mut() else {
        return Ok(seqs);
    };
    loop {
        let batch = reader.next_batch().await?;
        if batch.is_empty() {
            break;
        }
        seqs.extend(batch.iter().map(FirehoseEvent::seq));
    }
    Ok(seqs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehose::test_support::*;

    #[tokio::test]
    async fn replay_survives_restart() {
        // Regression: after a redeploy, a relay reconnecting with a prior cursor must replay the
        // commits it missed from the durable log, not an in-memory buffer the restart cleared.
        let db = crate::db::open_pool("sqlite::memory:").await.unwrap();
        crate::db::run_migrations(&db).await.unwrap();

        // First "process": three commits, then the firehose (and its broadcast backlog) is gone.
        {
            let fh = Firehose::new(db.clone()).await.unwrap();
            for _ in 0..3 {
                fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
            }
        }

        // Second "process": a fresh firehose over the same DB. A relay reconnects with cursor 1.
        let fh2 = Firehose::new(db.clone()).await.unwrap();
        let SubscribeOutcome::Subscribed(sub) = fh2.subscribe_from(Some(1)).await.unwrap() else {
            panic!("expected a subscription");
        };

        // The missed commits (seq 2, 3) come back paged from the durable log.
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert_eq!(
            seqs,
            vec![2, 3],
            "missed commits replay from the durable log after a restart"
        );
    }

    #[tokio::test]
    async fn subscribe_from_pages_replay_backlog() {
        let fh = test_firehose().await;
        for _ in 0..5 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        }

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(2)).await.unwrap() else {
            panic!("expected a subscription");
        };
        // Replay carries (cursor, upper] = (2, 5] from the durable log, oldest first.
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert_eq!(seqs, vec![3, 4, 5]);
    }

    #[tokio::test]
    async fn replay_reader_returns_bounded_pages() {
        let fh = test_firehose().await;
        for _ in 0..(REPLAY_BATCH + 3) {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap();
        }

        let SubscribeOutcome::Subscribed(mut sub) = fh.subscribe_from(Some(0)).await.unwrap()
        else {
            panic!("expected a subscription");
        };
        let mut replay = sub.replay.take().expect("cursor creates replay reader");

        let first = replay.next_batch().await.unwrap();
        assert_eq!(first.len(), REPLAY_BATCH as usize);
        assert_eq!(first.first().map(FirehoseEvent::seq), Some(1));
        assert_eq!(
            first.last().map(FirehoseEvent::seq),
            Some(u64::from(REPLAY_BATCH))
        );

        let second = replay.next_batch().await.unwrap();
        assert_eq!(second.len(), 3);
        assert_eq!(
            second.iter().map(FirehoseEvent::seq).collect::<Vec<_>>(),
            vec![
                u64::from(REPLAY_BATCH) + 1,
                u64::from(REPLAY_BATCH) + 2,
                u64::from(REPLAY_BATCH) + 3
            ]
        );

        assert!(replay.next_batch().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn subscribe_from_without_cursor_has_empty_replay() {
        let fh = test_firehose().await;
        fh.emit_commit(commit_input("did:plc:a")).await.unwrap();

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(None).await.unwrap() else {
            panic!("expected a subscription");
        };
        assert!(sub.replay.is_none(), "no cursor means live-only, no replay");
    }

    #[tokio::test]
    async fn subscribe_from_rejects_future_cursor() {
        let fh = test_firehose().await;
        fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1

        match fh.subscribe_from(Some(2)).await.unwrap() {
            SubscribeOutcome::FutureCursor { current } => assert_eq!(current, 1),
            SubscribeOutcome::Subscribed(_) => panic!("cursor 2 is in the future of seq 1"),
        }

        // The current seq itself is not "in the future": it subscribes with an empty replay.
        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(1)).await.unwrap() else {
            panic!("expected a subscription");
        };
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert!(seqs.is_empty());
    }

    #[tokio::test]
    async fn subscribe_from_fails_closed_on_replay_gap() {
        let fh = test_firehose().await;
        for _ in 0..3 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1, 2, 3
        }

        // Punch a hole the sequencer would never produce: seq 2 is missing but 3 remains, so the
        // intermediate gap can only be caught by a per-row density check, not a frontier check.
        sqlx::query("DELETE FROM repo_seq WHERE seq = 2")
            .execute(&fh.db)
            .await
            .unwrap();

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(0)).await.unwrap() else {
            panic!("expected subscription setup to succeed before replay is drained");
        };
        assert!(
            matches!(collect_replay_seqs(sub.replay).await, Err(FirehoseError::Decode(_))),
            "a mid-range gap in the durable replay range must fail closed, not silently skip the missing seq"
        );
    }

    #[tokio::test]
    async fn subscribe_from_degrades_to_best_effort_after_pruned_prefix() {
        let fh = test_firehose().await;
        for _ in 0..5 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=5
        }

        // Simulate a retention sweep that pruned a contiguous prefix (seq 1 and 2) but kept the
        // dense suffix 3..=5 including the frontier.
        sqlx::query("DELETE FROM repo_seq WHERE seq <= 2")
            .execute(&fh.db)
            .await
            .unwrap();

        // A cursor inside the pruned window must NOT fail closed: it degrades to best-effort and
        // replays the retained suffix. seq 1..2 are gone (best-effort), 3..=5 are delivered.
        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(0)).await.unwrap() else {
            panic!("cursor 0 below the pruned window must degrade, not fail");
        };
        let seqs = collect_replay_seqs(sub.replay).await.unwrap();
        assert_eq!(
            seqs,
            vec![3, 4, 5],
            "best-effort replays the retained suffix"
        );

        // A cursor inside the retained window replays normally (dense from cursor+1).
        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(3)).await.unwrap() else {
            panic!("cursor 3 is inside the retained window");
        };
        assert_eq!(collect_replay_seqs(sub.replay).await.unwrap(), vec![4, 5]);
    }

    #[tokio::test]
    async fn replay_degrades_to_best_effort_when_pruned_mid_drain() {
        // Replay must not lock out the retention sweep, so a slow reader can
        // have rows pruned out from under it between pages. A gap that opens up mid-drain because of
        // that prune must degrade to best-effort (re-anchor to the retained suffix), not fail
        // closed as if it were a durability hole.
        let fh = test_firehose().await;
        for _ in 0..(REPLAY_BATCH + 5) {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=261
        }

        let SubscribeOutcome::Subscribed(mut sub) = fh.subscribe_from(Some(0)).await.unwrap()
        else {
            panic!("expected a subscription");
        };
        let mut replay = sub.replay.take().expect("cursor creates replay reader");

        // First page: the dense prefix 1..=REPLAY_BATCH (upper = REPLAY_BATCH + 5).
        let first = replay.next_batch().await.unwrap();
        assert_eq!(first.len(), REPLAY_BATCH as usize);
        assert_eq!(
            first.last().map(FirehoseEvent::seq),
            Some(u64::from(REPLAY_BATCH))
        );

        // Simulate a retention sweep pruning past the reader's position between pages: delete
        // through REPLAY_BATCH + 2 and publish the floor, exactly as `firehose_gc::sweep` does.
        let watermark = u64::from(REPLAY_BATCH) + 2;
        sqlx::query("DELETE FROM repo_seq WHERE seq <= ?")
            .bind(watermark as i64)
            .execute(&fh.db)
            .await
            .unwrap();
        fh.note_pruned(watermark);

        // Second page: the pruned run (REPLAY_BATCH+1, +2) is skipped best-effort and the retained
        // suffix (REPLAY_BATCH+3 ..= +5) is delivered dense — no error.
        let second = replay.next_batch().await.unwrap();
        assert_eq!(
            second.iter().map(FirehoseEvent::seq).collect::<Vec<_>>(),
            vec![
                u64::from(REPLAY_BATCH) + 3,
                u64::from(REPLAY_BATCH) + 4,
                u64::from(REPLAY_BATCH) + 5
            ],
            "the pruned run is skipped best-effort and the retained suffix is delivered"
        );
        assert!(replay.next_batch().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn replay_degrades_to_best_effort_when_whole_tail_pruned_mid_drain() {
        // The empty-page counterpart of the test above: when a sweep prunes the *entire* remaining
        // snapshot tail between pages, the next page is empty and never reaches `upper`. That is a
        // prune (the floor covers our position), not a durability hole, so it ends best-effort
        // rather than raising "backlog ended before the frontier".
        let fh = test_firehose().await;
        for _ in 0..(REPLAY_BATCH + 5) {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=261
        }

        let SubscribeOutcome::Subscribed(mut sub) = fh.subscribe_from(Some(0)).await.unwrap()
        else {
            panic!("expected a subscription");
        };
        let mut replay = sub.replay.take().expect("cursor creates replay reader");
        let first = replay.next_batch().await.unwrap();
        assert_eq!(first.len(), REPLAY_BATCH as usize); // after = REPLAY_BATCH, upper = +5

        // Prune the whole remaining snapshot tail (everything above REPLAY_BATCH) and publish it.
        let watermark = u64::from(REPLAY_BATCH) + 5;
        sqlx::query("DELETE FROM repo_seq WHERE seq > ?")
            .bind(u64::from(REPLAY_BATCH) as i64)
            .execute(&fh.db)
            .await
            .unwrap();
        fh.note_pruned(watermark);

        // The empty tail is a prune, not a hole: an empty best-effort page, no error.
        let second = replay.next_batch().await.unwrap();
        assert!(
            second.is_empty(),
            "a fully-pruned tail ends replay best-effort instead of failing closed"
        );
    }

    #[tokio::test]
    async fn subscribe_from_fails_closed_on_a_gap_at_the_cursor_when_a_row_exists_at_the_cursor() {
        // Regression: with rows {1, 3} (seq 2 missing) and cursor = 1, a row EXISTS at the cursor
        // (seq 1), so the gap above it is a mid-range hole — NOT a pruned prefix. The first-row
        // relaxation must not fire: replay must fail closed instead of silently returning [3].
        let fh = test_firehose().await;
        for _ in 0..3 {
            fh.emit_commit(commit_input("did:plc:a")).await.unwrap(); // seq 1..=3
        }
        sqlx::query("DELETE FROM repo_seq WHERE seq = 2")
            .execute(&fh.db)
            .await
            .unwrap(); // leaves {1, 3}

        let SubscribeOutcome::Subscribed(sub) = fh.subscribe_from(Some(1)).await.unwrap() else {
            panic!("expected subscription setup to succeed before replay is drained");
        };
        assert!(
            matches!(
                collect_replay_seqs(sub.replay).await,
                Err(FirehoseError::Decode(_))
            ),
            "a gap at the cursor when a row exists at the cursor is mid-range, not a pruned prefix"
        );
    }
}
