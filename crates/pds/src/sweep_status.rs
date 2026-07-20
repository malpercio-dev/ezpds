// pattern: Imperative Shell (process-level shared state; no DB, no HTTP)

//! Readable last-run state for the periodic background sweeps.
//!
//! The OTel gauges in `metrics.rs` are write-only from inside the process — only a
//! Prometheus scrape observes them. The operator health endpoint
//! (`GET /v1/admin/health`) reports the same "is the sweep alive" signal as JSON, so each
//! sweep records its completion here, in the same place it writes its gauges, and the
//! route reads it back. Unlike the gauges this works with `[telemetry] metrics_enabled`
//! off.
//!
//! The recording sites share the sweeps' failure posture: a failed pass records nothing,
//! so a stale (or absent) [`SweepRun`] is the operator's signal that passes are not
//! completing — never record unconditionally at loop top.

use std::sync::RwLock;

/// One completed sweep pass.
#[derive(Debug, Clone, Copy)]
pub struct SweepRun {
    /// Unix seconds when the pass completed.
    pub completed_at: i64,
    /// Rows/files acted on by the pass (deleted blobs, pruned seq rows, reaped accounts,
    /// expired claim attempts).
    pub swept: u64,
}

impl SweepRun {
    /// A pass completing now, having swept `swept` items.
    pub fn now(swept: u64) -> Self {
        Self {
            completed_at: chrono::Utc::now().timestamp(),
            swept,
        }
    }
}

/// Last completed pass per periodic sweep. Every field is `None` until that sweep's first
/// completed pass after boot (each first pass runs one full interval after startup).
#[derive(Debug, Default, Clone, Copy)]
pub struct SweepSnapshot {
    pub blob_gc: Option<SweepRun>,
    /// The blob mirror is a replicator rather than a reclaimer, but shares the sweep
    /// posture: `swept` counts bucket objects synced (uploads + deletes), and a stale
    /// pass is the alarm.
    pub blob_mirror: Option<SweepRun>,
    /// The blob scrub is a verifier rather than a reclaimer: `swept` counts integrity
    /// problems flagged this pass (missing files, hash/size mismatches, orphan files) that
    /// were not auto-healed — the operator alarm count. A stale pass is still the alarm.
    pub blob_scrub: Option<SweepRun>,
    pub firehose_gc: Option<SweepRun>,
    pub account_reaper: Option<SweepRun>,
    pub agent_claim_sweep: Option<SweepRun>,
    pub admin_nonce_sweep: Option<SweepRun>,
    /// The labeler watcher is a poller rather than a reclaimer, but shares the sweep
    /// posture: `swept` counts label rows changed, and a stale pass is the alarm.
    pub labeler_watch: Option<SweepRun>,
}

/// Shared readable sweep state; one lives in `AppState` for the process lifetime.
#[derive(Debug, Default)]
pub struct SweepStatus {
    inner: RwLock<SweepSnapshot>,
}

impl SweepStatus {
    pub fn record_blob_gc(&self, run: SweepRun) {
        self.write().blob_gc = Some(run);
    }

    pub fn record_blob_mirror(&self, run: SweepRun) {
        self.write().blob_mirror = Some(run);
    }

    pub fn record_blob_scrub(&self, run: SweepRun) {
        self.write().blob_scrub = Some(run);
    }

    pub fn record_firehose_gc(&self, run: SweepRun) {
        self.write().firehose_gc = Some(run);
    }

    pub fn record_account_reaper(&self, run: SweepRun) {
        self.write().account_reaper = Some(run);
    }

    pub fn record_agent_claim_sweep(&self, run: SweepRun) {
        self.write().agent_claim_sweep = Some(run);
    }

    pub fn record_admin_nonce_sweep(&self, run: SweepRun) {
        self.write().admin_nonce_sweep = Some(run);
    }

    pub fn record_labeler_watch(&self, run: SweepRun) {
        self.write().labeler_watch = Some(run);
    }

    pub fn snapshot(&self) -> SweepSnapshot {
        // A poisoned lock means a writer panicked mid-assignment of a Copy value — the
        // data cannot be torn, so read through the poison rather than propagating a panic
        // into the health endpoint.
        match self.inner.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, SweepSnapshot> {
        match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_starts_empty_and_reflects_recorded_runs() {
        let status = SweepStatus::default();
        let before = status.snapshot();
        assert!(before.blob_gc.is_none());
        assert!(before.firehose_gc.is_none());
        assert!(before.account_reaper.is_none());
        assert!(before.agent_claim_sweep.is_none());
        assert!(before.admin_nonce_sweep.is_none());

        status.record_blob_gc(SweepRun {
            completed_at: 1000,
            swept: 3,
        });
        status.record_firehose_gc(SweepRun {
            completed_at: 2000,
            swept: 0,
        });

        let after = status.snapshot();
        assert_eq!(after.blob_gc.unwrap().completed_at, 1000);
        assert_eq!(after.blob_gc.unwrap().swept, 3);
        assert_eq!(after.firehose_gc.unwrap().swept, 0);
        assert!(after.account_reaper.is_none());
    }

    #[test]
    fn repeat_records_overwrite() {
        let status = SweepStatus::default();
        status.record_account_reaper(SweepRun {
            completed_at: 10,
            swept: 1,
        });
        status.record_account_reaper(SweepRun {
            completed_at: 20,
            swept: 0,
        });
        let snap = status.snapshot();
        assert_eq!(snap.account_reaper.unwrap().completed_at, 20);
        assert_eq!(snap.account_reaper.unwrap().swept, 0);
    }
}
