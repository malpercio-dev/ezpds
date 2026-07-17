// pattern: Imperative Shell
//
// Recovery-escrow audit log queries (V050). Append-only: this module exposes INSERT only —
// no UPDATE or DELETE exists here, and none may be added (the `agent_audit_events` V040
// doctrine; SELECT pagination on the rowid cursor arrives with the surface that reads the
// trail). Account deletion is the sole remover (`account_delete::purge_account`). Event
// vocabulary lives in `RecoveryAuditEventType`; the schema's CHECK constraint additionally
// reserves the release-flow strings (`release_requested`, `release_cancelled`, `released`)
// for the escrow release endpoints. `detail` carries mechanical facts only — never share
// material.

use common::{ApiError, ErrorCode};
use sqlx::Sqlite;

/// What happened to an account's escrowed share. The owner endpoints write the
/// deposit/rotate/delete events; the escrow release flow (`/v1/recovery/release*`) writes the
/// release events. Every string is also reserved in the table's CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryAuditEventType {
    /// The account's first Share 2 envelope was deposited.
    Deposited,
    /// An existing escrowed envelope was replaced (share-set rotation or re-key).
    Rotated,
    /// The owner opted out of escrow and the envelope was deleted.
    Deleted,
    /// A release was opened with a valid email OTP (the `pending` delay window began, or — with
    /// a zero delay — the share was handed back in the same call).
    ReleaseRequested,
    /// An in-flight pending release was cancelled by an authenticated session/device.
    ReleaseCancelled,
    /// The Share 2 envelope was actually handed back to the recovering wallet.
    Released,
}

impl RecoveryAuditEventType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RecoveryAuditEventType::Deposited => "deposited",
            RecoveryAuditEventType::Rotated => "rotated",
            RecoveryAuditEventType::Deleted => "deleted",
            RecoveryAuditEventType::ReleaseRequested => "release_requested",
            RecoveryAuditEventType::ReleaseCancelled => "release_cancelled",
            RecoveryAuditEventType::Released => "released",
        }
    }
}

/// Append one audit event. Generic over the executor so callers write it inside the same
/// transaction as the escrow state change it records.
pub(crate) async fn insert_recovery_audit_event<'e, E>(
    executor: E,
    id: &str,
    did: &str,
    event_type: RecoveryAuditEventType,
    detail: Option<&str>,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO recovery_audit_events (id, did, event_type, detail, created_at) \
         VALUES (?, ?, ?, ?, datetime('now'))",
    )
    .bind(id)
    .bind(did)
    .bind(event_type.as_str())
    .bind(detail)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(
            did = %did,
            event_type = %event_type.as_str(),
            error = %e,
            "DB error inserting recovery audit event"
        );
        ApiError::new(ErrorCode::InternalError, "failed to record audit event")
    })?;
    Ok(())
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
        .expect("seed account");
    }

    #[tokio::test]
    async fn insert_round_trips_every_variant() {
        let state = test_state().await;
        let did = "did:plc:recauditowner";
        seed_account(&state.db, did).await;

        for (i, event) in [
            RecoveryAuditEventType::Deposited,
            RecoveryAuditEventType::Rotated,
            RecoveryAuditEventType::Deleted,
        ]
        .into_iter()
        .enumerate()
        {
            insert_recovery_audit_event(
                &state.db,
                &format!("evt_{i}"),
                did,
                event,
                Some(r#"{"set_id":7}"#),
            )
            .await
            .expect("insert");
        }

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, event_type FROM recovery_audit_events WHERE did = ? ORDER BY rowid",
        )
        .bind(did)
        .fetch_all(&state.db)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![
                ("evt_0".into(), "deposited".into()),
                ("evt_1".into(), "rotated".into()),
                ("evt_2".into(), "deleted".into()),
            ]
        );
    }

    /// The schema's CHECK reserves the release-flow vocabulary: those strings insert, anything
    /// outside the vocabulary is refused.
    #[tokio::test]
    async fn check_constraint_reserves_the_release_vocabulary() {
        let state = test_state().await;
        let did = "did:plc:recauditvocab";
        seed_account(&state.db, did).await;

        for (i, reserved) in ["release_requested", "release_cancelled", "released"]
            .iter()
            .enumerate()
        {
            sqlx::query(
                "INSERT INTO recovery_audit_events (id, did, event_type, created_at) \
                 VALUES (?, ?, ?, datetime('now'))",
            )
            .bind(format!("evt_r{i}"))
            .bind(did)
            .bind(reserved)
            .execute(&state.db)
            .await
            .unwrap_or_else(|e| panic!("reserved event type {reserved} must insert: {e}"));
        }

        let unknown = sqlx::query(
            "INSERT INTO recovery_audit_events (id, did, event_type, created_at) \
             VALUES ('evt_bad', ?, 'exfiltrated', datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await;
        assert!(unknown.is_err(), "unknown event types must be refused");
    }

    #[tokio::test]
    async fn unknown_did_is_a_foreign_key_error() {
        let state = test_state().await;
        let result = insert_recovery_audit_event(
            &state.db,
            "evt_orphan",
            "did:plc:recauditghost",
            RecoveryAuditEventType::Deposited,
            None,
        )
        .await;
        assert!(
            result.is_err(),
            "FK to accounts must reject an orphan event"
        );
    }
}
