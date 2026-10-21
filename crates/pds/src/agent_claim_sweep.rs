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

use std::time::Duration;

use anyhow::Context;
use uuid::Uuid;

use crate::app::AppState;
use crate::db::agent_audit::{insert_agent_audit_event, AgentAuditEventType};
use crate::db::agent_auth::{expire_pending_agent_claim_attempts, expired_pending_claim_attempts};
use crate::sweep::{Pass, Sweep};
use crate::sweep_status::names;

/// Expire every lapsed pending attempt and audit each expiry once per `interval`.
///
/// The listing, the bulk status flip, and the audit rows share one transaction, so the flipped
/// set and the audited set cannot disagree; any error rolls the whole pass back and the next
/// tick retries.
pub struct AgentClaimSweep {
    pub interval: Duration,
}

impl Sweep<AppState> for AgentClaimSweep {
    const NAME: &'static str = names::AGENT_CLAIM_SWEEP;

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self, state: &AppState) -> anyhow::Result<Pass> {
        let mut tx = state.db.begin().await.context("open transaction")?;
        let due = expired_pending_claim_attempts(&mut *tx)
            .await
            .context("list lapsed attempts")?;

        if !due.is_empty() {
            expire_pending_agent_claim_attempts(&mut *tx)
                .await
                .context("expire attempts")?;
            for attempt in &due {
                let detail =
                    serde_json::json!({ "claim_attempt_id": attempt.attempt_id }).to_string();
                insert_agent_audit_event(
                    &mut *tx,
                    &Uuid::new_v4().to_string(),
                    &attempt.identity_id,
                    attempt.did.as_deref(),
                    AgentAuditEventType::ClaimExpired,
                    Some(&detail),
                )
                .await
                .with_context(|| {
                    format!("record expiry audit event for {}", attempt.identity_id)
                })?;
            }
            tx.commit().await.context("commit")?;
            tracing::info!(expired = due.len(), "agent claim sweep pass complete");
        }

        let expired = due.len() as u64;
        state.metrics.agent_claim_sweep_swept.add(expired, &[]);
        state
            .metrics
            .agent_claim_sweep_last_run_timestamp
            .record(crate::metrics::unix_now(), &[]);
        Ok(Pass::swept(expired))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::db::accounts::insert_bare_account as seed_account;
    use crate::sweep::run_once;

    fn sweep() -> AgentClaimSweep {
        AgentClaimSweep {
            interval: Duration::from_secs(1),
        }
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

        let pass = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(pass.swept, 2);
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
        let pass = run_once(&sweep(), &state).await.unwrap();
        assert_eq!(pass, Pass::default());
        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains("agent_claim_sweep_last_run_timestamp"),
            "missing agent_claim_sweep_last_run_timestamp in:\n{rendered}"
        );
        // The readable snapshot records the same completed pass (swept nothing ≠ never ran).
        let run = state
            .sweeps
            .snapshot()
            .get(names::AGENT_CLAIM_SWEEP)
            .unwrap();
        assert_eq!(run.swept, 0);
    }

    #[tokio::test]
    async fn a_swept_attempt_cannot_be_confirmed() {
        // Once swept, the attempt is terminal — `complete_agent_claim_attempt` guards on
        // `status = 'pending'`, so confirmation of the swept row affects no rows.
        let state = test_state().await;
        seed_identity(&state.db, "reg_gone", None).await;
        seed_attempt(&state.db, "cla_gone", "reg_gone", "2020-01-01 00:00:00").await;
        run_once(&sweep(), &state).await;

        let completed = crate::db::agent_auth::complete_agent_claim_attempt(&state.db, "cla_gone")
            .await
            .unwrap();
        assert!(!completed, "an expired attempt must not complete");
    }
}
