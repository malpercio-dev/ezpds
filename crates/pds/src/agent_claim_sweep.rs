// pattern: Imperative Shell
//
//! Periodic agent-claim-attempt expiry sweep.
//!
//! A claim ceremony's `user_code` has a short TTL, and the read paths already refuse a lapsed
//! attempt (`can_complete` requires pending *and* unexpired) — but without a sweep the row would
//! sit `pending` forever and the audit trail would never say the ceremony died. Each pass flips
//! every lapsed pending attempt to `expired` and records a `claim_expired` audit event against
//! the owning registration, in one transaction, so the wallet's per-agent history shows exactly
//! how each ceremony ended (confirmed or expired — never silence).
//!
//! Template: `account_reaper.rs` / `firehose_gc.rs` — the first interval tick is skipped, an
//! error skips the pass (retried next tick), and the task runs for the life of the process.

use std::time::Duration;

use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::app::AppState;
use crate::db::agent_audit::{insert_agent_audit_event, AgentAuditEventType};
use crate::db::agent_auth::{expire_pending_agent_claim_attempts, expired_pending_claim_attempts};

/// Tally of what one sweep pass did, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    /// Claim attempts flipped `pending → expired` this pass.
    pub expired: u64,
}

/// Spawn the periodic claim-attempt expiry sweep. The first tick is consumed without sweeping so
/// the server does not run it mid-boot; the first pass runs one `interval` after startup.
pub fn spawn_agent_claim_sweep(state: AppState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_agent_claim_sweep(&state).await;
        }
    })
}

/// Run a single sweep pass: expire every lapsed pending attempt and audit each expiry.
///
/// The listing, the bulk status flip, and the audit rows share one transaction, so the flipped
/// set and the audited set cannot disagree; any error rolls the whole pass back and the next
/// tick retries.
pub async fn run_agent_claim_sweep(state: &AppState) -> SweepStats {
    let mut stats = SweepStats::default();

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = %e, "agent claim sweep: failed to open transaction; skipping pass");
            return stats;
        }
    };

    let due = match expired_pending_claim_attempts(&mut *tx).await {
        Ok(due) => due,
        Err(e) => {
            tracing::error!(error = %e, "agent claim sweep: failed to list lapsed attempts; skipping pass");
            return stats;
        }
    };

    if !due.is_empty() {
        if let Err(e) = expire_pending_agent_claim_attempts(&mut *tx).await {
            tracing::error!(error = %e, "agent claim sweep: failed to expire attempts; skipping pass");
            return stats;
        }
        for attempt in &due {
            let detail = serde_json::json!({ "claim_attempt_id": attempt.attempt_id }).to_string();
            if let Err(e) = insert_agent_audit_event(
                &mut *tx,
                &Uuid::new_v4().to_string(),
                &attempt.identity_id,
                attempt.did.as_deref(),
                AgentAuditEventType::ClaimExpired,
                Some(&detail),
            )
            .await
            {
                tracing::error!(
                    error = %e,
                    registration_id = %attempt.identity_id,
                    "agent claim sweep: failed to record expiry audit event; skipping pass"
                );
                return stats;
            }
        }
        if let Err(e) = tx.commit().await {
            tracing::error!(error = %e, "agent claim sweep: failed to commit; skipping pass");
            return stats;
        }
        stats.expired = due.len() as u64;
        tracing::info!(expired = stats.expired, "agent claim sweep pass complete");
    }

    // The error early-returns above skip this on purpose: a stale
    // `agent_claim_sweep_last_run_timestamp` signals that passes are not completing.
    state
        .metrics
        .agent_claim_sweep_swept
        .add(stats.expired, &[]);
    state
        .metrics
        .agent_claim_sweep_last_run_timestamp
        .record(crate::metrics::unix_now(), &[]);
    state
        .sweeps
        .record_agent_claim_sweep(crate::sweep_status::SweepRun::now(stats.expired));

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;

    async fn seed_account(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(db)
        .await
        .unwrap();
    }

    async fn seed_identity(db: &sqlx::SqlitePool, id: &str, did: Option<&str>) {
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, status, created_at, updated_at) \
             VALUES (?, ?, 'anonymous', '[]', '2099-01-01 00:00:00', 'active', datetime('now'), datetime('now'))",
        )
        .bind(id)
        .bind(did)
        .execute(db)
        .await
        .unwrap();
    }

    async fn seed_attempt(db: &sqlx::SqlitePool, id: &str, identity_id: &str, expires_at: &str) {
        // `user_code` is UNIQUE — derive one per attempt id.
        sqlx::query(
            "INSERT INTO agent_claim_attempts \
             (id, identity_id, user_code, user_code_expires_at, status, created_at) \
             VALUES (?, ?, ?, ?, 'pending', datetime('now'))",
        )
        .bind(id)
        .bind(identity_id)
        .bind(format!("code-{id}"))
        .bind(expires_at)
        .execute(db)
        .await
        .unwrap();
    }

    async fn attempt_status(db: &sqlx::SqlitePool, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM agent_claim_attempts WHERE id = ?")
            .bind(id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn expires_lapsed_attempts_and_audits_each() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:sweepowner").await;
        seed_identity(&state.db, "reg_lapsed", Some("did:plc:sweepowner")).await;
        seed_identity(&state.db, "reg_anon", None).await;
        seed_attempt(&state.db, "cla_lapsed", "reg_lapsed", "2020-01-01 00:00:00").await;
        seed_attempt(&state.db, "cla_anon", "reg_anon", "2020-01-01 00:00:00").await;
        seed_attempt(&state.db, "cla_live", "reg_lapsed", "2099-01-01 00:00:00").await;

        let stats = run_agent_claim_sweep(&state).await;
        assert_eq!(stats.expired, 2);
        assert_eq!(attempt_status(&state.db, "cla_lapsed").await, "expired");
        assert_eq!(attempt_status(&state.db, "cla_anon").await, "expired");
        assert_eq!(
            attempt_status(&state.db, "cla_live").await,
            "pending",
            "an unexpired attempt is untouched"
        );

        // Each expiry landed one attributed audit event; the NULL-did anonymous registration is
        // audited too.
        let events =
            crate::db::agent_audit::list_agent_audit_events(&state.db, "reg_lapsed", None, 10)
                .await
                .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "claim_expired");
        assert_eq!(events[0].did.as_deref(), Some("did:plc:sweepowner"));
        let anon_events =
            crate::db::agent_audit::list_agent_audit_events(&state.db, "reg_anon", None, 10)
                .await
                .unwrap();
        assert_eq!(anon_events.len(), 1);
        assert_eq!(anon_events[0].did, None);
    }

    #[tokio::test]
    async fn nothing_due_is_a_noop_that_still_timestamps() {
        let state = test_state().await;
        let stats = run_agent_claim_sweep(&state).await;
        assert_eq!(stats, SweepStats::default());
        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("agent_claim_sweep_last_run_timestamp"),
            "missing agent_claim_sweep_last_run_timestamp in:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn a_swept_attempt_cannot_be_confirmed() {
        // Once swept, the attempt is terminal — `complete_agent_claim_attempt` guards on
        // `status = 'pending'`, so confirmation of the swept row affects no rows.
        let state = test_state().await;
        seed_identity(&state.db, "reg_gone", None).await;
        seed_attempt(&state.db, "cla_gone", "reg_gone", "2020-01-01 00:00:00").await;
        run_agent_claim_sweep(&state).await;

        let completed = crate::db::agent_auth::complete_agent_claim_attempt(&state.db, "cla_gone")
            .await
            .unwrap();
        assert!(!completed, "an expired attempt must not complete");
    }
}
