// pattern: Imperative Shell
//
// Agent-action audit log queries (V040). Append-only: this module exposes INSERT and SELECT
// only — no UPDATE or DELETE exists here, and none may be added. Account deletion is the sole
// remover (`account_delete::purge_account`, which drops an account's whole agent history in FK
// order). Event vocabulary lives in `AgentAuditEventType`; callers build the `detail` JSON and
// must never include request bodies or token material.

use common::{ApiError, ErrorCode};
use sqlx::Sqlite;

/// What an agent identity did, recorded at the points where activity is attributable via the
/// `registration_id` token claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentAuditEventType {
    /// The identity was registered (`POST /agent/identity`).
    Registered,
    /// A claim ceremony was opened and a `user_code` issued.
    ClaimInitiated,
    /// The account owner confirmed the `user_code`; the identity flipped to `claimed`.
    ClaimConfirmed,
    /// A pending claim attempt lapsed unconfirmed and was swept.
    ClaimExpired,
    /// An assertion or claim token was exchanged for an access token at the token endpoint.
    TokenExchanged,
    /// An agent-derived token committed a repo write.
    RepoWrite,
    /// An agent-derived token uploaded a blob.
    BlobUpload,
    /// The identity was revoked by the account owner.
    Revoked,
}

impl AgentAuditEventType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AgentAuditEventType::Registered => "registered",
            AgentAuditEventType::ClaimInitiated => "claim_initiated",
            AgentAuditEventType::ClaimConfirmed => "claim_confirmed",
            AgentAuditEventType::ClaimExpired => "claim_expired",
            AgentAuditEventType::TokenExchanged => "token_exchanged",
            AgentAuditEventType::RepoWrite => "repo_write",
            AgentAuditEventType::BlobUpload => "blob_upload",
            AgentAuditEventType::Revoked => "revoked",
        }
    }
}

/// One audit row, newest-first in list queries. The registration id is not carried back — list
/// queries are already scoped to one registration.
#[derive(Debug, Clone)]
pub(crate) struct AgentAuditEventRow {
    /// Insertion-order sequence (the table's rowid) — the pagination cursor. The table is
    /// append-only, so rowid order is exactly event order.
    pub(crate) seq: i64,
    pub(crate) id: String,
    pub(crate) did: Option<String>,
    pub(crate) event_type: String,
    pub(crate) detail: Option<String>,
    pub(crate) created_at: String,
}

/// Append one audit event. Generic over the executor so callers can write it inside the same
/// transaction as the state change it records (claim confirm, revocation).
pub(crate) async fn insert_agent_audit_event<'e, E>(
    executor: E,
    id: &str,
    registration_id: &str,
    did: Option<&str>,
    event_type: AgentAuditEventType,
    detail: Option<&str>,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO agent_audit_events \
         (id, registration_id, did, event_type, detail, created_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'))",
    )
    .bind(id)
    .bind(registration_id)
    .bind(did)
    .bind(event_type.as_str())
    .bind(detail)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(
            registration_id = %registration_id,
            event_type = %event_type.as_str(),
            error = %e,
            "DB error inserting agent audit event"
        );
        ApiError::new(ErrorCode::InternalError, "failed to record audit event")
    })?;
    Ok(())
}

/// Page an identity's audit events newest-first. `before_seq` is the previous page's last `seq`
/// (exclusive); `None` starts from the newest event.
pub(crate) async fn list_agent_audit_events(
    db: &sqlx::SqlitePool,
    registration_id: &str,
    before_seq: Option<i64>,
    limit: i64,
) -> Result<Vec<AgentAuditEventRow>, ApiError> {
    type AuditSqlRow = (i64, String, Option<String>, String, Option<String>, String);
    let rows: Vec<AuditSqlRow> =
        sqlx::query_as(
            "SELECT rowid, id, did, event_type, detail, created_at \
             FROM agent_audit_events \
             WHERE registration_id = ? AND (? IS NULL OR rowid < ?) \
             ORDER BY rowid DESC LIMIT ?",
        )
        .bind(registration_id)
        .bind(before_seq)
        .bind(before_seq)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(|e| {
            tracing::error!(registration_id = %registration_id, error = %e, "DB error listing agent audit events");
            ApiError::new(ErrorCode::InternalError, "failed to list audit events")
        })?;

    Ok(rows
        .into_iter()
        .map(
            |(seq, id, did, event_type, detail, created_at)| AgentAuditEventRow {
                seq,
                id,
                did,
                event_type,
                detail,
                created_at,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::db::agent_auth::{self, NewAgentIdentity, RegistrationType};

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

    async fn seed_identity(db: &sqlx::SqlitePool, id: &str) {
        agent_auth::insert_agent_identity(
            db,
            &NewAgentIdentity {
                id,
                did: None,
                registration_type: RegistrationType::Anonymous,
                issuer: None,
                subject: None,
                email: None,
                scopes: "[]",
                identity_assertion: None,
                assertion_expires_at: "2030-01-01 00:00:00",
                pre_claim_scopes: None,
                claim_token: None,
                claim_token_expires_at: None,
            },
        )
        .await
        .expect("seed identity");
    }

    #[tokio::test]
    async fn insert_and_list_pages_newest_first() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:other").await;
        seed_identity(&state.db, "reg_a").await;
        seed_identity(&state.db, "reg_b").await;

        for i in 0..3 {
            insert_agent_audit_event(
                &state.db,
                &format!("evt_{i}"),
                "reg_a",
                None,
                AgentAuditEventType::Registered,
                None,
            )
            .await
            .expect("insert");
        }
        insert_agent_audit_event(
            &state.db,
            "evt_other",
            "reg_b",
            Some("did:plc:other"),
            AgentAuditEventType::RepoWrite,
            Some(r#"{"collection":"app.bsky.feed.post"}"#),
        )
        .await
        .expect("insert");

        let page1 = list_agent_audit_events(&state.db, "reg_a", None, 2)
            .await
            .expect("page 1");
        assert_eq!(
            page1.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            vec!["evt_2", "evt_1"],
            "newest first, scoped to reg_a"
        );

        let page2 = list_agent_audit_events(&state.db, "reg_a", Some(page1[1].seq), 2)
            .await
            .expect("page 2");
        assert_eq!(
            page2.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            vec!["evt_0"],
            "cursor resumes below the previous page"
        );
    }

    #[tokio::test]
    async fn detail_and_did_round_trip() {
        let state = test_state().await;
        seed_account(&state.db, "did:plc:owner").await;
        seed_identity(&state.db, "reg_detail").await;
        insert_agent_audit_event(
            &state.db,
            "evt_d",
            "reg_detail",
            Some("did:plc:owner"),
            AgentAuditEventType::BlobUpload,
            Some(r#"{"size":42}"#),
        )
        .await
        .expect("insert");

        let events = list_agent_audit_events(&state.db, "reg_detail", None, 10)
            .await
            .expect("list");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "blob_upload");
        assert_eq!(events[0].did.as_deref(), Some("did:plc:owner"));
        assert_eq!(events[0].detail.as_deref(), Some(r#"{"size":42}"#));
    }

    #[tokio::test]
    async fn unknown_registration_id_is_a_foreign_key_error() {
        let state = test_state().await;
        let result = insert_agent_audit_event(
            &state.db,
            "evt_orphan",
            "reg_missing",
            None,
            AgentAuditEventType::Registered,
            None,
        )
        .await;
        assert!(
            result.is_err(),
            "FK to agent_identities must reject an orphan event"
        );
    }
}
