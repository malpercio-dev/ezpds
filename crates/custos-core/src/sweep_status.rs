// pattern: Imperative Shell (process-level shared state; no DB, no HTTP)

//! Readable last-run state for the periodic background sweeps.
//!
//! The OTel gauges in `metrics.rs` are write-only from inside the process — only a
//! Prometheus scrape observes them. The operator health endpoint
//! (`GET /v1/admin/health`) reports the same "is the sweep alive" signal as JSON, so each
//! sweep pass records its completion here (the `sweep` scheduler does it for every `Sweep`),
//! and the route reads it back. Unlike the gauges this works with `[telemetry] metrics_enabled`
//! off.
//!
//! The recording sites share the sweeps' failure posture: a failed pass records nothing,
//! so a stale (or absent) [`SweepRun`] is the operator's signal that passes are not
//! completing — never record unconditionally at loop top.
//!
//! A pass that *completes* while skipping some of its subjects is a different fault, and
//! staleness cannot express it: it records normally, with [`SweepRun::errors`] carrying the
//! count it could not do. Blob GC is the motivating case — it excludes accounts whose
//! reconcile failed rather than deleting blobs it could not prove were unreferenced.

use std::collections::HashMap;
use std::sync::RwLock;

/// One completed sweep pass.
#[derive(Debug, Clone, Copy)]
pub struct SweepRun {
    /// Unix seconds when the pass completed.
    pub completed_at: i64,
    /// Rows/files acted on by the pass (deleted blobs, pruned seq rows, reaped accounts,
    /// expired claim attempts).
    pub swept: u64,
    /// Failures the pass hit. A completed pass with `errors > 0` did run, but did not do its
    /// whole job — the distinction a stale `completed_at` alone cannot draw between "one
    /// subject is broken" and "the sweep is dead". Sweeps that have no per-item error path
    /// leave this `0`.
    ///
    /// This counts failed *operations*, not the work they cost. For blob GC one failed
    /// account is 1, however many of its blobs go uncollected as a result.
    pub errors: u64,
}

impl SweepRun {
    /// A pass completing now, having swept `swept` items and skipped `errors` on failures.
    pub fn now_with_errors(swept: u64, errors: u64) -> Self {
        Self {
            completed_at: chrono::Utc::now().timestamp(),
            swept,
            errors,
        }
    }
}

/// Slot keys for [`SweepStatus`]; each is the `Sweep::NAME` of the sweep that records it and
/// the lookup `GET /v1/admin/health` makes.
pub mod names {
    pub const BLOB_GC: &str = "blob_gc";
    pub const BLOB_MIRROR: &str = "blob_mirror";
    pub const BLOB_SCRUB: &str = "blob_scrub";
    pub const FIREHOSE_GC: &str = "firehose_gc";
    pub const ACCOUNT_REAPER: &str = "account_reaper";
    pub const AGENT_CLAIM_SWEEP: &str = "agent_claim_sweep";
    pub const ADMIN_NONCE_SWEEP: &str = "admin_nonce_sweep";
    pub const SOVEREIGN_SESSION_NONCE_SWEEP: &str = "sovereign_session_nonce_sweep";
    pub const SPACE_JTI_SWEEP: &str = "space_jti_sweep";
    pub const SPACE_OPLOG_SWEEP: &str = "space_oplog_sweep";
    pub const LABELER_WATCH: &str = "labeler_watch";
}

/// Last completed pass per periodic sweep, by [`names`] key. A sweep has no entry until its
/// first completed pass after boot.
///
/// The blob mirror is a replicator and the labeler watcher a poller rather than reclaimers,
/// but they share the posture: `swept` counts what they acted on, and a stale pass is the
/// alarm. The blob scrub is a verifier: its `swept` counts integrity problems flagged and not
/// auto-healed.
#[derive(Debug, Default, Clone)]
pub struct SweepSnapshot(HashMap<&'static str, SweepRun>);

impl SweepSnapshot {
    pub fn get(&self, name: &str) -> Option<SweepRun> {
        self.0.get(name).copied()
    }
}

/// Shared readable sweep state; one lives in `AppState` for the process lifetime.
#[derive(Debug, Default)]
pub struct SweepStatus {
    inner: RwLock<HashMap<&'static str, SweepRun>>,
}

impl SweepStatus {
    pub fn record(&self, name: &'static str, run: SweepRun) {
        self.write().insert(name, run);
    }

    pub fn snapshot(&self) -> SweepSnapshot {
        // A poisoned lock means a writer panicked mid-insert of a Copy value — the data
        // cannot be torn, so read through the poison rather than propagating a panic into the
        // health endpoint.
        match self.inner.read() {
            Ok(guard) => SweepSnapshot(guard.clone()),
            Err(poisoned) => SweepSnapshot(poisoned.into_inner().clone()),
        }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<&'static str, SweepRun>> {
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
        assert!(before.get(names::BLOB_GC).is_none());
        assert!(before.get(names::FIREHOSE_GC).is_none());
        assert!(before.get(names::ACCOUNT_REAPER).is_none());
        assert!(before.get(names::AGENT_CLAIM_SWEEP).is_none());
        assert!(before.get(names::ADMIN_NONCE_SWEEP).is_none());

        status.record(
            names::BLOB_GC,
            SweepRun {
                completed_at: 1000,
                swept: 3,
                errors: 0,
            },
        );
        status.record(
            names::FIREHOSE_GC,
            SweepRun {
                completed_at: 2000,
                swept: 0,
                errors: 0,
            },
        );

        let after = status.snapshot();
        assert_eq!(after.get(names::BLOB_GC).unwrap().completed_at, 1000);
        assert_eq!(after.get(names::BLOB_GC).unwrap().swept, 3);
        assert_eq!(after.get(names::FIREHOSE_GC).unwrap().swept, 0);
        assert!(after.get(names::ACCOUNT_REAPER).is_none());
    }

    #[test]
    fn repeat_records_overwrite() {
        let status = SweepStatus::default();
        status.record(
            names::ACCOUNT_REAPER,
            SweepRun {
                completed_at: 10,
                swept: 1,
                errors: 0,
            },
        );
        status.record(
            names::ACCOUNT_REAPER,
            SweepRun {
                completed_at: 20,
                swept: 0,
                errors: 0,
            },
        );
        let snap = status.snapshot();
        assert_eq!(snap.get(names::ACCOUNT_REAPER).unwrap().completed_at, 20);
        assert_eq!(snap.get(names::ACCOUNT_REAPER).unwrap().swept, 0);
    }
}
