// pattern: Imperative Shell
//
// Server-wide admin-action audit log queries (V052). Append-only: this module exposes
// INSERT and SELECT only — no UPDATE or DELETE exists here, and none may be added. The
// table carries no foreign keys, so nothing removes its rows either (not even account
// deletion): the server's history deliberately outlives the accounts, devices, and codes
// it describes. Action vocabulary lives in `AdminAuditAction`; callers build the `detail`
// JSON and must never include request bodies, pairing codes, or token material.

use common::{ApiError, ErrorCode};
use sqlx::Sqlite;

/// What an admin did, recorded at every mutating admin route once the actor is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminAuditAction {
    /// An account takedown was applied (`com.atproto.admin.updateSubjectStatus`).
    AccountTakedown,
    /// An account takedown was cleared.
    AccountRestore,
    /// An account's credentials were swept (`/v1/admin/accounts/{id}/revoke-credentials`).
    CredentialsRevoked,
    /// Claim/invite codes were minted (native mint or `createInviteCode(s)`).
    ClaimCodesMinted,
    /// A claim code was revoked before redemption.
    ClaimCodeRevoked,
    /// A single-use admin-device pairing code was minted (master token only).
    PairingCodeMinted,
    /// A companion-app device registered by consuming a pairing code.
    DeviceRegistered,
    /// A companion-app device was revoked.
    DeviceRevoked,
    /// An in-flight planned device transfer was cancelled by the operator.
    TransferCancelled,
    /// The operator asked every configured relay to crawl this PDS now.
    RequestCrawl,
    /// An account's email address was corrected (`/v1/admin/accounts/{id}/email`).
    EmailUpdated,
    /// A password-reset token was minted for out-of-band delivery.
    ResetTokenIssued,
    /// An operator-level PDS signing key was created (`/v1/pds/keys`).
    SigningKeyCreated,
}

impl AdminAuditAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AdminAuditAction::AccountTakedown => "account_takedown",
            AdminAuditAction::AccountRestore => "account_restore",
            AdminAuditAction::CredentialsRevoked => "credentials_revoked",
            AdminAuditAction::ClaimCodesMinted => "claim_codes_minted",
            AdminAuditAction::ClaimCodeRevoked => "claim_code_revoked",
            AdminAuditAction::PairingCodeMinted => "pairing_code_minted",
            AdminAuditAction::DeviceRegistered => "device_registered",
            AdminAuditAction::DeviceRevoked => "device_revoked",
            AdminAuditAction::TransferCancelled => "transfer_cancelled",
            AdminAuditAction::RequestCrawl => "request_crawl",
            AdminAuditAction::EmailUpdated => "email_updated",
            AdminAuditAction::ResetTokenIssued => "reset_token_issued",
            AdminAuditAction::SigningKeyCreated => "signing_key_created",
        }
    }

    /// Parse a caller-supplied `action` filter. `None` for an unknown value — the list
    /// route rejects it with a 400 (like the account listing's `status` filter) instead
    /// of silently returning an empty page.
    pub(crate) fn from_filter(value: &str) -> Option<Self> {
        const ALL: [AdminAuditAction; 13] = [
            AdminAuditAction::AccountTakedown,
            AdminAuditAction::AccountRestore,
            AdminAuditAction::CredentialsRevoked,
            AdminAuditAction::ClaimCodesMinted,
            AdminAuditAction::ClaimCodeRevoked,
            AdminAuditAction::PairingCodeMinted,
            AdminAuditAction::DeviceRegistered,
            AdminAuditAction::DeviceRevoked,
            AdminAuditAction::TransferCancelled,
            AdminAuditAction::RequestCrawl,
            AdminAuditAction::EmailUpdated,
            AdminAuditAction::ResetTokenIssued,
            AdminAuditAction::SigningKeyCreated,
        ];
        ALL.into_iter().find(|action| action.as_str() == value)
    }
}

/// One audit row, newest-first in list queries.
#[derive(Debug, Clone)]
pub(crate) struct AdminAuditEventRow {
    /// Insertion-order sequence (the table's rowid) — the pagination cursor. The table is
    /// append-only, so rowid order is exactly event order.
    pub(crate) seq: i64,
    pub(crate) id: String,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) subject: Option<String>,
    pub(crate) outcome: String,
    pub(crate) detail: Option<String>,
    pub(crate) created_at: String,
}

/// Optional equality filters for the list query; every `None` matches all rows.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AdminAuditFilter<'a> {
    pub(crate) action: Option<&'a str>,
    pub(crate) actor: Option<&'a str>,
    pub(crate) subject: Option<&'a str>,
}

/// Append one audit event, surfacing the raw `sqlx::Error` for callers whose enclosing
/// transaction speaks sqlx (e.g. the claim-code mint). Generic over the executor so the
/// write joins the same transaction as the state change it records.
pub(crate) async fn insert_admin_audit_event<'e, E>(
    executor: E,
    actor: &str,
    action: AdminAuditAction,
    subject: Option<&str>,
    outcome: &str,
    detail: Option<&str>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO admin_audit_events \
         (id, actor, action, subject, outcome, detail, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(actor)
    .bind(action.as_str())
    .bind(subject)
    .bind(outcome)
    .bind(detail)
    .execute(executor)
    .await?;
    Ok(())
}

/// [`insert_admin_audit_event`] mapped to the route-facing `ApiError`. A failed write
/// fails the request — a privileged action must not land unattributed.
pub(crate) async fn record_admin_audit_event<'e, E>(
    executor: E,
    actor: &str,
    action: AdminAuditAction,
    subject: Option<&str>,
    outcome: &str,
    detail: Option<&str>,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    insert_admin_audit_event(executor, actor, action, subject, outcome, detail)
        .await
        .map_err(|e| {
            tracing::error!(
                actor = %actor,
                action = %action.as_str(),
                error = %e,
                "DB error inserting admin audit event"
            );
            ApiError::new(ErrorCode::InternalError, "failed to record audit event")
        })
}

/// Page the audit log newest-first. `before_seq` is the previous page's last `seq`
/// (exclusive); `None` starts from the newest event.
pub(crate) async fn list_admin_audit_events(
    db: &sqlx::SqlitePool,
    filter: AdminAuditFilter<'_>,
    before_seq: Option<i64>,
    limit: i64,
) -> Result<Vec<AdminAuditEventRow>, ApiError> {
    type AuditSqlRow = (
        i64,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
    );
    let rows: Vec<AuditSqlRow> = sqlx::query_as(
        "SELECT rowid, id, actor, action, subject, outcome, detail, created_at \
         FROM admin_audit_events \
         WHERE (? IS NULL OR action = ?) \
           AND (? IS NULL OR actor = ?) \
           AND (? IS NULL OR subject = ?) \
           AND (? IS NULL OR rowid < ?) \
         ORDER BY rowid DESC LIMIT ?",
    )
    .bind(filter.action)
    .bind(filter.action)
    .bind(filter.actor)
    .bind(filter.actor)
    .bind(filter.subject)
    .bind(filter.subject)
    .bind(before_seq)
    .bind(before_seq)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error listing admin audit events");
        ApiError::new(ErrorCode::InternalError, "failed to list audit events")
    })?;

    Ok(rows
        .into_iter()
        .map(
            |(seq, id, actor, action, subject, outcome, detail, created_at)| AdminAuditEventRow {
                seq,
                id,
                actor,
                action,
                subject,
                outcome,
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

    async fn record(
        db: &sqlx::SqlitePool,
        actor: &str,
        action: AdminAuditAction,
        subject: Option<&str>,
    ) {
        record_admin_audit_event(db, actor, action, subject, "ok", None)
            .await
            .expect("insert audit event");
    }

    #[tokio::test]
    async fn lists_newest_first_and_pages_on_seq() {
        let state = test_state().await;
        record(
            &state.db,
            "master-token",
            AdminAuditAction::AccountTakedown,
            Some("did:plc:a"),
        )
        .await;
        record(
            &state.db,
            "device:dev-1",
            AdminAuditAction::AccountRestore,
            Some("did:plc:a"),
        )
        .await;
        record(
            &state.db,
            "master-token",
            AdminAuditAction::RequestCrawl,
            None,
        )
        .await;

        let page1 = list_admin_audit_events(&state.db, AdminAuditFilter::default(), None, 2)
            .await
            .expect("page 1");
        assert_eq!(
            page1.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
            vec!["request_crawl", "account_restore"],
            "newest first"
        );

        let page2 = list_admin_audit_events(
            &state.db,
            AdminAuditFilter::default(),
            Some(page1[1].seq),
            2,
        )
        .await
        .expect("page 2");
        assert_eq!(
            page2.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
            vec!["account_takedown"],
            "cursor resumes below the previous page"
        );
    }

    #[tokio::test]
    async fn filters_are_conjunctive() {
        let state = test_state().await;
        record(
            &state.db,
            "master-token",
            AdminAuditAction::DeviceRevoked,
            Some("dev-1"),
        )
        .await;
        record(
            &state.db,
            "device:dev-2",
            AdminAuditAction::DeviceRevoked,
            Some("dev-1"),
        )
        .await;
        record(
            &state.db,
            "device:dev-2",
            AdminAuditAction::CredentialsRevoked,
            Some("did:plc:a"),
        )
        .await;

        let by_action = list_admin_audit_events(
            &state.db,
            AdminAuditFilter {
                action: Some("device_revoked"),
                ..Default::default()
            },
            None,
            10,
        )
        .await
        .expect("filter by action");
        assert_eq!(by_action.len(), 2);

        let combined = list_admin_audit_events(
            &state.db,
            AdminAuditFilter {
                action: Some("device_revoked"),
                actor: Some("device:dev-2"),
                subject: Some("dev-1"),
            },
            None,
            10,
        )
        .await
        .expect("combined filter");
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].actor, "device:dev-2");
    }

    #[tokio::test]
    async fn detail_and_outcome_round_trip() {
        let state = test_state().await;
        record_admin_audit_event(
            &state.db,
            "master-token",
            AdminAuditAction::ClaimCodeRevoked,
            Some("ABC123"),
            "revoked",
            Some(r#"{"reason":"leaked"}"#),
        )
        .await
        .expect("insert");

        let events = list_admin_audit_events(&state.db, AdminAuditFilter::default(), None, 10)
            .await
            .expect("list");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "revoked");
        assert_eq!(events[0].subject.as_deref(), Some("ABC123"));
        assert_eq!(events[0].detail.as_deref(), Some(r#"{"reason":"leaked"}"#));
    }

    #[test]
    fn every_action_filter_round_trips() {
        for action in [
            AdminAuditAction::AccountTakedown,
            AdminAuditAction::AccountRestore,
            AdminAuditAction::CredentialsRevoked,
            AdminAuditAction::ClaimCodesMinted,
            AdminAuditAction::ClaimCodeRevoked,
            AdminAuditAction::PairingCodeMinted,
            AdminAuditAction::DeviceRegistered,
            AdminAuditAction::DeviceRevoked,
            AdminAuditAction::TransferCancelled,
            AdminAuditAction::RequestCrawl,
            AdminAuditAction::EmailUpdated,
            AdminAuditAction::ResetTokenIssued,
            AdminAuditAction::SigningKeyCreated,
        ] {
            assert_eq!(AdminAuditAction::from_filter(action.as_str()), Some(action));
        }
        assert_eq!(AdminAuditAction::from_filter("nonsense"), None);
    }
}
