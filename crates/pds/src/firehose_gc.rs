// pattern: Imperative Shell
//
//! `repo_seq` firehose event-log retention.
//!
//! A periodic background task that prunes the durable firehose event log (`repo_seq`, added by
//! V028) so it does not grow without bound. Every `#commit` and `#account` frame — including each
//! commit's CARv1 `blocks` — is retained in `repo_seq` so `com.atproto.sync.subscribeRepos` cursor
//! replay survives restarts (see `firehose.rs`). Without a sweep the table is append-only and
//! would eventually dominate the production SQLite DB and the Litestream backup.
//!
//! ## Policy (union — the most aggressive enabled retention bounds growth)
//!
//! On each pass the sweep computes a **low-water mark** below which rows are prunable, from the
//! enabled retention knobs (see [`FirehoseConfig`](common::FirehoseConfig)):
//!
//! * **Age** (`log_retention_secs`): rows whose `sequenced_at` is older than `now − retention`
//!   are prunable. The age watermark is `first_retained_seq − 1`, where `first_retained_seq` is
//!   `MIN(seq)` among rows *at or after* the cutoff (see [`firehose_seq::retained_boundary_seq`]);
//!   if no row is retained by age, the whole log is prunable up to the frontier.
//! * **Count** (`log_retention_count`): keep at most the newest `N` rows, i.e. the watermark is
//!   `MAX(seq) − N`.
//!
//! The combined watermark is the **`max`** of the enabled policies' contributions: a row is
//! pruned when it falls below **any** enabled cutoff, so enabling both knobs bounds growth by
//! whichever policy fires (age prunes old rows even when count would keep them; count prunes a
//! huge young backlog even when age would keep it). A `0` knob disables that policy and
//! contributes nothing; both at `0` makes the sweep a no-op (the log stays append-only, exactly
//! the pre-retention behaviour).
//!
//! The age boundary is deliberately computed from the first *retained* seq rather than
//! `MAX(seq)` among old rows, so a row with a skewed-old timestamp can never lift the watermark
//! past fresh rows (an over-prune / data loss). The worst case under non-monotonic timestamps is
//! that an oddly-timestamped row lingers — an under-prune the next pass corrects.
//!
//! ## Invariants preserved
//!
//! * **The live frontier is never pruned.** The watermark is clamped to `MAX(seq) − 1`, so a
//!   reconnecting relay can always resume from at least the newest retained event and `read_replay`
//!   can always reach the frontier it snapshotted.
//! * **`seq` stays monotonic and is never reused.** `seq` is the explicit `INTEGER PRIMARY KEY`,
//!   so a pruned number is gone for good; the sequencer keeps advancing from its in-memory
//!   `last_seq` regardless of what was pruned below it.
//! * **The retained suffix stays dense.** Pruning removes a contiguous prefix `seq ≤ watermark`,
//!   so the remaining `watermark+1 .. MAX(seq)` range has no holes and `read_replay`'s per-row
//!   density check still holds within it. A cursor below the pruned window degrades to
//!   best-effort replay (the subscriber receives the retained suffix) rather than failing closed.
//!
//! Like the blob GC it is best-effort, runs for the life of the process, and is dropped on
//! shutdown rather than joined.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;
use crate::db::firehose_seq;

/// Tally of what one retention pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcStats {
    /// Rows deleted from `repo_seq`.
    pub pruned: u64,
    /// Passes skipped (all retention knobs disabled or the log empty).
    pub skipped: bool,
}

/// Spawn the periodic `repo_seq` retention sweep.
///
/// The first interval tick is consumed without running the sweep, so the server does not prune
/// during startup; the first pass runs one `interval` after boot. The task loops for the life of
/// the process and is dropped on shutdown.
pub fn spawn_firehose_gc(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // `interval`'s first tick fires immediately — skip it so the sweep doesn't run mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_firehose_gc(&state).await;
        }
    })
}

/// Run a single `repo_seq` retention pass.
///
/// Computes the low-water mark from the enabled retention knobs, clamps it below the live
/// frontier, and deletes the contiguous prefix beneath it. A no-op when the log is empty or every
/// retention knob is disabled.
pub async fn run_firehose_gc(state: &AppState) -> GcStats {
    let config = &state.config.firehose;

    // No policy enabled: the sweep is intentionally inert (append-only log, pre-retention
    // behaviour). Checked up front so an operator who disables retention doesn't pay a per-pass
    // MAX(seq) round-trip.
    if config.log_retention_secs == 0 && config.log_retention_count == 0 {
        return GcStats {
            pruned: 0,
            skipped: true,
        };
    }

    let max_seq = match firehose_seq::max_seq(&state.db).await {
        Ok(max) => max,
        Err(e) => {
            tracing::error!(error = %e, "firehose GC: failed to read MAX(seq); skipping pass");
            return GcStats {
                pruned: 0,
                skipped: true,
            };
        }
    };
    // An empty log (or a single-row log where nothing is prunable) needs no work.
    if max_seq == 0 {
        return GcStats {
            pruned: 0,
            skipped: true,
        };
    }

    // Each enabled policy contributes how far it wants to prune (0 = prune nothing). The
    // combined watermark is the `max`: prune when ANY enabled policy fires, so the most
    // aggressive enabled retention bounds growth (union, not intersection).
    let mut watermark = 0u64;

    // Age-based: prune every row older than the retention window. The contribution is the seq
    // just below the first *retained* row (over-prune-safe), or `max_seq` if nothing is retained.
    if config.log_retention_secs > 0 {
        // Checked conversion: `log_retention_secs` is `u64`, but `chrono::Duration::seconds` takes
        // an `i64`. A value bigger than `i64::MAX` would wrap to a negative duration on `as i64`,
        // producing a cutoff in the future and pruning the whole log; treat overflow as a config
        // error and skip the pass rather than risk that.
        let retention_secs = match i64::try_from(config.log_retention_secs) {
            Ok(v) => v,
            Err(_) => {
                tracing::error!(
                    value = config.log_retention_secs,
                    "firehose GC: log_retention_secs overflows i64; skipping pass"
                );
                return GcStats {
                    pruned: 0,
                    skipped: true,
                };
            }
        };
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(retention_secs);
        let cutoff_rfc3339 = cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        match firehose_seq::retained_boundary_seq(&state.db, &cutoff_rfc3339).await {
            // The boundary is the first retained seq; everything strictly older is prunable.
            Ok(Some(first_retained)) => {
                watermark = watermark.max(first_retained.saturating_sub(1));
            }
            // Nothing is retained by age → the whole log is older than the window → prune to the
            // frontier guard below.
            Ok(None) => watermark = watermark.max(max_seq),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    cutoff = %cutoff_rfc3339,
                    "firehose GC: failed to compute age boundary; skipping pass"
                );
                return GcStats {
                    pruned: 0,
                    skipped: true,
                };
            }
        }
    }

    // Count-based: keep at most the newest `log_retention_count` rows. A count larger than the
    // log saturates to 0 (prune nothing) — exactly the "keep more than we have" case.
    if config.log_retention_count > 0 {
        let count_watermark = max_seq.saturating_sub(config.log_retention_count);
        watermark = watermark.max(count_watermark);
    }

    // Neither knob produced a pruning watermark (both disabled, or every contribution was 0):
    // nothing to prune this pass.
    if watermark == 0 {
        return GcStats {
            pruned: 0,
            skipped: true,
        };
    }

    // Never prune the live frontier row: a reconnecting relay must be able to resume from at
    // least the newest retained event, and `read_replay` must be able to reach the `upper`
    // frontier it snapshotted. The watermark is the highest prunable seq, so this keeps `MAX(seq)`
    // and guarantees the retained suffix is non-empty. This also makes the sweep safe to run
    // *without* the firehose `emit_lock`: a row emitted during this pass has `seq` greater than
    // the `max_seq` we read, hence greater than the watermark, so the range delete can't touch it.
    let watermark = watermark.min(max_seq.saturating_sub(1));

    // A watermark of 0 prunes nothing (every `seq` is >= 1) — the log stays fully retained.
    if watermark == 0 {
        return GcStats {
            pruned: 0,
            skipped: true,
        };
    }

    let pruned = match firehose_seq::prune_below(&state.db, watermark).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(
                error = %e,
                watermark,
                "firehose GC: failed to prune repo_seq; skipping pass"
            );
            return GcStats {
                pruned: 0,
                skipped: true,
            };
        }
    };

    if pruned > 0 {
        tracing::info!(pruned, watermark, "firehose GC pass pruned repo_seq");
    } else {
        tracing::debug!("firehose GC pass pruned nothing (watermark {watermark} below all rows)");
    }

    GcStats {
        pruned,
        skipped: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use common::FirehoseConfig;
    use std::sync::Arc;

    /// Set `config.firehose` on a fresh test `AppState`, returning the modified state.
    async fn state_with(firehose: FirehoseConfig) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.firehose = firehose;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Emit `n` events via the live firehose so the durable log holds a dense 1..=n prefix with
    /// real `sequenced_at` timestamps.
    async fn emit_n(state: &AppState, n: u64) {
        for _ in 0..n {
            state
                .firehose
                .emit_commit(crate::firehose::CommitInput {
                    repo: "did:plc:gc".to_string(),
                    commit: VALID_CID.to_string(),
                    rev: "3krev".to_string(),
                    since: None,
                    ops: vec![],
                    blocks: vec![],
                })
                .await
                .unwrap();
        }
    }

    // Same known-parseable DAG-CBOR CID the firehose unit tests use, so `validate_commit_cids`
    // accepts these synthetic emits.
    const VALID_CID: &str = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";

    #[tokio::test]
    async fn gc_is_a_noop_when_both_knobs_disabled() {
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 0,
            log_retention_count: 0,
        })
        .await;
        emit_n(&state, 5).await;

        let stats = run_firehose_gc(&state).await;
        assert!(stats.skipped);
        assert_eq!(stats.pruned, 0);
        assert_eq!(
            crate::db::firehose_seq::max_seq(&state.db).await.unwrap(),
            5,
            "nothing pruned"
        );
    }

    #[tokio::test]
    async fn gc_count_keeps_only_the_newest_n() {
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 0,
            log_retention_count: 3,
        })
        .await;
        emit_n(&state, 10).await; // seq 1..=10

        let stats = run_firehose_gc(&state).await;
        // watermark = 10 - 3 = 7, clamped below the frontier (10-1=9) stays 7 → prune <=7 (7 rows).
        assert_eq!(stats.pruned, 7);
        assert!(!stats.skipped);

        // The retained suffix is exactly the newest 3 rows; the frontier (seq 10) is preserved.
        let rows = crate::db::firehose_seq::events_in_range(&state.db, 0, 10, 100)
            .await
            .unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![8, 9, 10]);
    }

    #[tokio::test]
    async fn gc_count_never_prunes_the_frontier() {
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 0,
            log_retention_count: 1,
        })
        .await;
        emit_n(&state, 5).await; // seq 1..=5

        let stats = run_firehose_gc(&state).await;
        // watermark = 5 - 1 = 4, clamped to min(4, 5-1=4) = 4 → prune <=4 (4 rows), keep {5}.
        assert_eq!(stats.pruned, 4);
        assert!(!stats.skipped);

        let rows = crate::db::firehose_seq::events_in_range(&state.db, 0, 5, 100)
            .await
            .unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5], "only the live frontier survives count=1");
    }

    #[tokio::test]
    async fn gc_count_larger_than_log_prunes_nothing() {
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 0,
            log_retention_count: 1000,
        })
        .await;
        emit_n(&state, 3).await; // seq 1..=3

        let stats = run_firehose_gc(&state).await;
        // watermark = 3.saturating_sub(1000) = 0 → no-op (nothing below seq 1).
        assert!(stats.skipped);
        assert_eq!(stats.pruned, 0);
        assert_eq!(
            crate::db::firehose_seq::events_in_range(&state.db, 0, 3, 100)
                .await
                .unwrap()
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn gc_age_prunes_rows_older_than_the_window() {
        // Use a wide (1-day) window so the just-emitted rows are deterministically inside it; a
        // tiny `1s` window would make the "nothing old enough yet" assertion flaky on a slow run.
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 86_400, // 1 day
            log_retention_count: 0,
        })
        .await;
        emit_n(&state, 5).await; // seq 1..=5, all at ~now

        // Everything was just emitted, so nothing is older than 1 day yet.
        let stats = run_firehose_gc(&state).await;
        assert!(stats.skipped, "nothing is old enough yet");
        assert_eq!(stats.pruned, 0);

        // Age the rows into the past so the 1s window excludes all of them, then sweep.
        sqlx::query("UPDATE repo_seq SET sequenced_at = '2020-01-01T00:00:00.000Z'")
            .execute(&state.db)
            .await
            .unwrap();
        let stats = run_firehose_gc(&state).await;
        // No row is retained by age (everything is 2020) → age contributes `max_seq` (5), clamped
        // to the frontier (5-1=4) → prune <=4. The frontier (seq 5) is kept; 1..=4 pruned.
        assert_eq!(stats.pruned, 4, "frontier (seq 5) is kept; 1..=4 pruned");
        let rows = crate::db::firehose_seq::events_in_range(&state.db, 0, 5, 100)
            .await
            .unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5]);
    }

    #[tokio::test]
    async fn gc_count_wins_when_age_finds_nothing_old_while_count_is_exceeded() {
        // Union semantics: a young backlog that exceeds the count limit must be pruned by count,
        // even though age retains every row (nothing is old enough to prune by age). With the
        // old intersection rule count would have been suppressed by age and the log stayed huge.
        // A wide (1-day) age window keeps these rows deterministically young so the count branch
        // is what fires; a `1s` window would make the test flaky if the run drifted past 1s.
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 86_400, // 1 day — nothing has aged past it
            log_retention_count: 3,
        })
        .await;
        emit_n(&state, 10).await; // seq 1..=10, all young

        let stats = run_firehose_gc(&state).await;
        // age: boundary = MIN(seq) = 1 → contribution 0; count = 10 - 3 = 7. max(0, 7) = 7 → prune
        // <=7, keep the newest 3 rows {8, 9, 10}.
        assert_eq!(stats.pruned, 7);
        assert!(!stats.skipped);
        let rows = crate::db::firehose_seq::events_in_range(&state.db, 0, 10, 100)
            .await
            .unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs,
            vec![8, 9, 10],
            "count prunes the young backlog age would keep"
        );
    }

    #[tokio::test]
    async fn gc_age_wins_up_to_the_frontier_when_all_rows_are_old() {
        // Union semantics: when every row is older than the age window, age prunes the whole log
        // up to the frontier guard, regardless of a count knob that would have kept more rows.
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 1,
            log_retention_count: 8, // would keep 8 rows on its own
        })
        .await;
        emit_n(&state, 10).await; // seq 1..=10

        // Age everything into the past.
        sqlx::query("UPDATE repo_seq SET sequenced_at = '2020-01-01T00:00:00.000Z'")
            .execute(&state.db)
            .await
            .unwrap();

        let stats = run_firehose_gc(&state).await;
        // age: no row retained by age → contribution `max_seq` (10); count = 10 - 8 = 2.
        // max(10, 2) = 10, clamped by the frontier guard to 9 → prune <=9, keep only {frontier}.
        assert_eq!(stats.pruned, 9);
        let rows = crate::db::firehose_seq::events_in_range(&state.db, 0, 10, 100)
            .await
            .unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs,
            vec![10],
            "age prunes old rows even when count would keep them"
        );
    }

    #[tokio::test]
    async fn gc_empty_log_is_a_noop() {
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 1,
            log_retention_count: 3,
        })
        .await;
        // No events emitted.
        let stats = run_firehose_gc(&state).await;
        assert!(stats.skipped);
        assert_eq!(stats.pruned, 0);
    }

    // Replay-degradation contract: a cursor below the pruned window degrades to best-effort
    // rather than failing closed. Asserted in `firehose.rs`'s `read_replay` tests; this module
    // owns only the pruning, so it just verifies the suffix stays dense and the frontier intact.
    #[tokio::test]
    async fn gc_retained_suffix_is_dense_and_reaches_the_frontier() {
        let state = state_with(FirehoseConfig {
            gc_interval_secs: 3600,
            log_retention_secs: 0,
            log_retention_count: 3,
        })
        .await;
        emit_n(&state, 10).await;
        run_firehose_gc(&state).await; // keep 8,9,10

        // The subscriber-facing contract: subscribe_from cannot replay a pruned prefix, but it
        // must replay the full retained suffix for a cursor inside it and reach the frontier.
        let crate::firehose::SubscribeOutcome::Subscribed(sub) =
            state.firehose.subscribe_from(Some(7)).await.unwrap()
        else {
            panic!("cursor 7 is inside the retained window");
        };
        let seqs: Vec<u64> = sub.replay.iter().map(|e| e.seq()).collect();
        assert_eq!(
            seqs,
            vec![8, 9, 10],
            "retained suffix is dense and reaches frontier"
        );
    }
}
