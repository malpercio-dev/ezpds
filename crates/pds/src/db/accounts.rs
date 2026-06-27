// pattern: Imperative Shell
//
// Account lookup queries. Gathers from the accounts + handles + did_documents tables;
// returns plain data structs. No business logic — callers decide what to do with the result.

use common::{ApiError, ErrorCode};

/// Flat account row returned by `resolve_identifier`.
pub(crate) struct AccountRow {
    pub(crate) did: String,
    pub(crate) email: String,
    /// Argon2id PHC string. `None` for mobile accounts (password auth not allowed).
    pub(crate) password_hash: Option<String>,
    /// One associated handle (if any). `None` means no row exists in the `handles` table.
    pub(crate) handle: Option<String>,
}

/// Flat account row used by `getSession` — includes confirmation status and DID document.
pub(crate) struct SessionAccountRow {
    pub(crate) did: String,
    pub(crate) email: String,
    /// `true` when `email_confirmed_at` is non-NULL in the DB.
    pub(crate) email_confirmed: bool,
    /// One associated handle (if any).
    pub(crate) handle: Option<String>,
    /// Raw JSON string from `did_documents.document`, if present.
    pub(crate) did_doc: Option<String>,
}

/// Fetch account info needed for `getSession` by DID.
///
/// Returns `None` when the DID is not found or the account is deactivated.
pub(crate) async fn get_session_account(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<SessionAccountRow>, ApiError> {
    // (email, email_confirmed_at, handle, did_document)
    type Row = (String, Option<String>, Option<String>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT a.email, a.email_confirmed_at, h.handle, d.document \
         FROM accounts a \
         LEFT JOIN handles h ON h.did = a.did \
         LEFT JOIN did_documents d ON d.did = a.did \
         WHERE a.did = ? AND a.deactivated_at IS NULL \
         LIMIT 1",
    )
    .bind(did)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error fetching session account");
        ApiError::new(ErrorCode::InternalError, "failed to load account")
    })?;

    Ok(row.map(
        |(email, email_confirmed_at, handle, did_doc)| SessionAccountRow {
            did: did.to_string(),
            email,
            email_confirmed: email_confirmed_at.is_some(),
            handle,
            did_doc,
        },
    ))
}

/// Return `true` when an active (non-deactivated) account exists for `did`.
///
/// Used by handlers that authenticate via JWT but still need to reject tokens whose
/// underlying account has since been deactivated or removed — e.g. `getPreferences`,
/// which otherwise has no reason to read the `accounts` table. Mirrors the
/// `deactivated_at IS NULL` guard that `get_session_account` applies.
pub(crate) async fn account_is_active(db: &sqlx::SqlitePool, did: &str) -> Result<bool, ApiError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM accounts WHERE did = ? AND deactivated_at IS NULL LIMIT 1")
            .bind(did)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "DB error checking account active state");
                ApiError::new(ErrorCode::InternalError, "failed to load account")
            })?;

    Ok(row.is_some())
}

/// Whether an `activate_account` / `deactivate_account` call actually changed the account status.
///
/// Lets the route handler emit a firehose `#account` event only on a real transition and skip the
/// redundant status-quo event when the account was already in the target state (an idempotent
/// no-op call), while still distinguishing a missing account for the not-found response.
pub(crate) enum AccountStateChange {
    /// No account row matched the DID.
    NotFound,
    /// The account was already in the target status; nothing meaningful changed.
    Unchanged,
    /// The account transitioned into the target status.
    Changed,
}

/// Mark an account deactivated, recording an optional requested deletion time.
///
/// Stores `delete_after` verbatim (the caller validates it is an RFC 3339 datetime). Re-deactivating
/// an already-deactivated account is allowed and refreshes `delete_after`, but preserves the
/// original `deactivated_at` instant (via `COALESCE`) and reports [`AccountStateChange::Unchanged`]
/// so the caller skips a redundant firehose event. Reports `NotFound` when no account row matches.
pub(crate) async fn deactivate_account(
    db: &sqlx::SqlitePool,
    did: &str,
    delete_after: Option<&str>,
) -> Result<AccountStateChange, ApiError> {
    // Read the current status first so we can report whether this call is a real transition.
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT deactivated_at FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "DB error reading account state");
                ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
            })?;
    let Some((deactivated_at,)) = row else {
        return Ok(AccountStateChange::NotFound);
    };
    let was_active = deactivated_at.is_none();

    // Run the UPDATE even when already deactivated so a revised `delete_after` is recorded.
    // `COALESCE` keeps the original deactivation instant rather than resetting it on re-calls.
    sqlx::query(
        "UPDATE accounts \
         SET deactivated_at = COALESCE(deactivated_at, datetime('now')), delete_after = ?, \
             updated_at = datetime('now') \
         WHERE did = ?",
    )
    .bind(delete_after)
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error deactivating account");
        ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
    })?;

    Ok(if was_active {
        AccountStateChange::Changed
    } else {
        AccountStateChange::Unchanged
    })
}

/// Clear an account's deactivation, returning it to active status.
///
/// Sets both `deactivated_at` and `delete_after` back to NULL. Reactivating an already-active
/// account is a no-op that reports [`AccountStateChange::Unchanged`] so the caller skips a
/// redundant firehose event; an actual reactivation reports `Changed`. Reports `NotFound` when no
/// account row matches.
pub(crate) async fn activate_account(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<AccountStateChange, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT deactivated_at FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "DB error reading account state");
                ApiError::new(ErrorCode::InternalError, "failed to activate account")
            })?;
    let Some((deactivated_at,)) = row else {
        return Ok(AccountStateChange::NotFound);
    };
    if deactivated_at.is_none() {
        return Ok(AccountStateChange::Unchanged);
    }

    sqlx::query(
        "UPDATE accounts \
         SET deactivated_at = NULL, delete_after = NULL, updated_at = datetime('now') \
         WHERE did = ?",
    )
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error activating account");
        ApiError::new(ErrorCode::InternalError, "failed to activate account")
    })?;

    Ok(AccountStateChange::Changed)
}

/// Classification of a `pending_accounts` UNIQUE constraint violation.
///
/// Produced by [`classify_pending_account_conflict`] so callers don't repeat the
/// SQLite error-string matching. `Email`/`Handle` name the conflicting column;
/// `Other` covers a UNIQUE violation on some different column of `pending_accounts`.
pub(crate) enum PendingAccountConflict<'a> {
    Email,
    Handle,
    Other(&'a str),
}

/// Classify a UNIQUE constraint violation against the `pending_accounts` table.
///
/// Returns `None` when the error is not a `pending_accounts` UNIQUE violation
/// (e.g. a different table's constraint, or a non-constraint error). Callers
/// decide how to surface each variant — this only inspects the error.
pub(crate) fn classify_pending_account_conflict(
    e: &sqlx::Error,
) -> Option<PendingAccountConflict<'_>> {
    match crate::db::unique_violation_column(e, "pending_accounts") {
        Some("email") => Some(PendingAccountConflict::Email),
        Some("handle") => Some(PendingAccountConflict::Handle),
        Some(col) => Some(PendingAccountConflict::Other(col)),
        None => None,
    }
}

/// Fetch the raw `repo_root_cid` for an account by DID.
///
/// Returns `Ok(None)` when no account row exists for the DID; `Ok(Some(cid))`
/// with the raw stored string otherwise. Callers own the None→404 mapping and
/// the CID parse — this function only runs the query.
pub(crate) async fn get_repo_root_cid(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
        .bind(did)
        .fetch_optional(db)
        .await
}

/// Repo write preconditions for an account: its repo root CID and active status, fetched in one
/// query. Backs the create/put/delete/applyWrites paths, which need both the CAS root and the
/// deactivation gate — reading them together avoids a second round-trip against `accounts` and
/// narrows the window between the active check and the commit CAS.
pub(crate) struct RepoWriteState {
    /// Stored repo root commit CID, or `None` when the account exists but has no repo yet.
    pub(crate) repo_root_cid: Option<String>,
    /// `true` when `deactivated_at` is NULL.
    pub(crate) active: bool,
}

/// Fetch the repo root CID and active status for `did` in a single query.
///
/// Returns `None` when no account row exists for `did` (the caller maps this to a 404, the same
/// as a `None` `repo_root_cid`). `active` is derived from `deactivated_at`.
pub(crate) async fn get_repo_write_state(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<RepoWriteState>, sqlx::Error> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT repo_root_cid, deactivated_at FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await?;

    Ok(row.map(|(repo_root_cid, deactivated_at)| RepoWriteState {
        repo_root_cid,
        active: deactivated_at.is_none(),
    }))
}

/// A single repo entry for `com.atproto.sync.listRepos`.
///
/// Only accounts that have created their repo (non-NULL `repo_root_cid`) produce a row —
/// the lexicon requires `head` and `rev`, so an account without a repo root has nothing
/// to list. `active` is derived from `deactivated_at`.
pub(crate) struct RepoListRow {
    pub(crate) did: String,
    /// Raw stored repo root commit CID string (the repo `head`).
    pub(crate) head: String,
    /// Stored commit revision (TID). `None` for pre-`repo_rev`-migration accounts; the
    /// caller falls back to reading the rev from the commit block in that case.
    pub(crate) rev: Option<String>,
    /// `true` when `deactivated_at` is NULL.
    pub(crate) active: bool,
}

/// List hosted repos in DID order for `listRepos`, starting strictly after `cursor`.
///
/// Pass `cursor = ""` (or any value sorting below all DIDs) for the first page. Returns up
/// to `limit` rows ordered by DID ascending; the caller derives the next cursor from the
/// last returned DID. Only accounts with a non-NULL `repo_root_cid` are included.
pub(crate) async fn list_repos(
    db: &sqlx::SqlitePool,
    cursor: &str,
    limit: i64,
) -> Result<Vec<RepoListRow>, sqlx::Error> {
    let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT did, repo_root_cid, repo_rev, deactivated_at FROM accounts \
         WHERE repo_root_cid IS NOT NULL AND did > ? \
         ORDER BY did ASC LIMIT ?",
    )
    .bind(cursor)
    .bind(limit)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(did, head, rev, deactivated_at)| RepoListRow {
            did,
            head,
            rev,
            active: deactivated_at.is_none(),
        })
        .collect())
}

/// Repo hosting status for a single account, backing `com.atproto.sync.getRepoStatus`.
///
/// Unlike most account lookups this row is produced even for a deactivated account —
/// reporting that state *is* the point of `getRepoStatus`. `active` is derived from
/// `deactivated_at`; `head`/`rev` are `None` for an account that has not created its repo.
pub(crate) struct RepoStatusRow {
    /// `true` when `deactivated_at` is NULL.
    pub(crate) active: bool,
    /// Stored repo root commit CID (the repo `head`), or `None` when the account has no repo.
    pub(crate) head: Option<String>,
    /// Stored commit revision (TID). `None` for an account with no repo or one created before
    /// the `repo_rev` migration; the caller falls back to reading the rev from the commit block.
    pub(crate) rev: Option<String>,
}

/// Fetch repo hosting status for a single DID for `getRepoStatus`.
///
/// Returns `None` only when no account row exists for `did` (the caller maps this to a 404).
/// This query intentionally does **not** filter on `deactivated_at`: a deactivated account
/// still has a reportable status.
pub(crate) async fn get_repo_status(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<RepoStatusRow>, sqlx::Error> {
    let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT deactivated_at, repo_root_cid, repo_rev FROM accounts WHERE did = ?",
    )
    .bind(did)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|(deactivated_at, head, rev)| RepoStatusRow {
        active: deactivated_at.is_none(),
        head,
        rev,
    }))
}

/// Resolve an email address to an active (non-deactivated) account.
///
/// Used by the provisioning session login endpoint (`POST /v1/accounts/sessions`).
/// Returns `None` when not found or deactivated; `Err` only on DB errors.
pub(crate) async fn resolve_by_email(
    db: &sqlx::SqlitePool,
    email: &str,
) -> Result<Option<AccountRow>, ApiError> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT a.did, a.password_hash, h.handle \
         FROM accounts a \
         LEFT JOIN handles h ON h.did = a.did \
         WHERE a.email = ? AND a.deactivated_at IS NULL \
         LIMIT 1",
    )
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        // Logging the email domain aids ops triage without exposing the full address in logs.
        let domain = email.split('@').nth(1).unwrap_or("<unknown>");
        tracing::error!(error = %e, email_domain = %domain, "DB error resolving email");
        ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
    })?;

    Ok(row.map(|(did, password_hash, handle)| AccountRow {
        did,
        email: email.to_string(),
        password_hash,
        handle,
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    /// Create an in-memory SQLite pool with all migrations applied.
    async fn test_pool() -> sqlx::SqlitePool {
        let db = open_pool("sqlite::memory:").await.expect("test pool");
        run_migrations(&db).await.expect("migrations");
        db
    }

    /// Insert a minimal active account row.
    async fn insert_account(db: &sqlx::SqlitePool, did: &str) {
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

    /// Insert an active account row that also has a `repo_root_cid`.
    async fn insert_account_with_repo(db: &sqlx::SqlitePool, did: &str, cid: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, repo_root_cid, created_at, updated_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .bind(cid)
        .execute(db)
        .await
        .unwrap();
    }

    // ── deactivate_account ────────────────────────────────────────────────────

    #[tokio::test]
    async fn deactivate_active_account_returns_changed() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:a").await;

        let result = deactivate_account(&db, "did:plc:a", None)
            .await
            .expect("no DB error");
        assert!(
            matches!(result, AccountStateChange::Changed),
            "first deactivation must return Changed"
        );
    }

    #[tokio::test]
    async fn deactivate_active_account_sets_deactivated_at() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:b").await;

        deactivate_account(&db, "did:plc:b", None)
            .await
            .unwrap();

        let deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind("did:plc:b")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            deactivated_at.is_some(),
            "deactivated_at must be set after deactivation"
        );
    }

    #[tokio::test]
    async fn deactivate_stores_delete_after() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:c").await;

        deactivate_account(&db, "did:plc:c", Some("2030-01-01T00:00:00Z"))
            .await
            .unwrap();

        let stored: Option<String> =
            sqlx::query_scalar("SELECT delete_after FROM accounts WHERE did = ?")
                .bind("did:plc:c")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("2030-01-01T00:00:00Z"),
            "delete_after must be stored verbatim"
        );
    }

    #[tokio::test]
    async fn deactivate_with_none_delete_after_stores_null() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:d").await;

        deactivate_account(&db, "did:plc:d", None).await.unwrap();

        let stored: Option<String> =
            sqlx::query_scalar("SELECT delete_after FROM accounts WHERE did = ?")
                .bind("did:plc:d")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(stored, None, "delete_after must be NULL when not provided");
    }

    #[tokio::test]
    async fn re_deactivating_returns_unchanged() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:e").await;

        deactivate_account(&db, "did:plc:e", None).await.unwrap();
        let result = deactivate_account(&db, "did:plc:e", None)
            .await
            .expect("no DB error");
        assert!(
            matches!(result, AccountStateChange::Unchanged),
            "re-deactivating an already-deactivated account must return Unchanged"
        );
    }

    #[tokio::test]
    async fn re_deactivating_preserves_original_deactivated_at() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:f").await;

        // First deactivation.
        deactivate_account(&db, "did:plc:f", None).await.unwrap();
        let first_deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind("did:plc:f")
                .fetch_one(&db)
                .await
                .unwrap();

        // Brief pause to ensure any clock-based timestamp would differ.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Second deactivation with a new delete_after.
        deactivate_account(&db, "did:plc:f", Some("2031-06-01T00:00:00Z"))
            .await
            .unwrap();
        let second_deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind("did:plc:f")
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(
            first_deactivated_at, second_deactivated_at,
            "COALESCE must preserve the original deactivated_at on re-calls"
        );
    }

    #[tokio::test]
    async fn re_deactivating_refreshes_delete_after() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:g").await;

        deactivate_account(&db, "did:plc:g", Some("2030-01-01T00:00:00Z"))
            .await
            .unwrap();
        deactivate_account(&db, "did:plc:g", Some("2031-06-15T12:00:00Z"))
            .await
            .unwrap();

        let stored: Option<String> =
            sqlx::query_scalar("SELECT delete_after FROM accounts WHERE did = ?")
                .bind("did:plc:g")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("2031-06-15T12:00:00Z"),
            "re-deactivation must update delete_after to the new value"
        );
    }

    #[tokio::test]
    async fn deactivate_missing_did_returns_not_found() {
        let db = test_pool().await;

        let result = deactivate_account(&db, "did:plc:ghost", None)
            .await
            .expect("no DB error");
        assert!(
            matches!(result, AccountStateChange::NotFound),
            "a DID with no account row must return NotFound"
        );
    }

    // ── activate_account ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn activate_deactivated_account_returns_changed() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:h").await;
        deactivate_account(&db, "did:plc:h", None).await.unwrap();

        let result = activate_account(&db, "did:plc:h").await.expect("no DB error");
        assert!(
            matches!(result, AccountStateChange::Changed),
            "activating a deactivated account must return Changed"
        );
    }

    #[tokio::test]
    async fn activate_clears_deactivated_at() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:i").await;
        deactivate_account(&db, "did:plc:i", None).await.unwrap();

        activate_account(&db, "did:plc:i").await.unwrap();

        let deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind("did:plc:i")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            deactivated_at, None,
            "deactivated_at must be NULL after activation"
        );
    }

    #[tokio::test]
    async fn activate_clears_delete_after() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:j").await;
        deactivate_account(&db, "did:plc:j", Some("2030-01-01T00:00:00Z"))
            .await
            .unwrap();

        activate_account(&db, "did:plc:j").await.unwrap();

        let delete_after: Option<String> =
            sqlx::query_scalar("SELECT delete_after FROM accounts WHERE did = ?")
                .bind("did:plc:j")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(
            delete_after, None,
            "delete_after must be cleared on activation"
        );
    }

    #[tokio::test]
    async fn activate_already_active_account_returns_unchanged() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:k").await;

        let result = activate_account(&db, "did:plc:k").await.expect("no DB error");
        assert!(
            matches!(result, AccountStateChange::Unchanged),
            "activating an already-active account must return Unchanged"
        );
    }

    #[tokio::test]
    async fn activate_missing_did_returns_not_found() {
        let db = test_pool().await;

        let result = activate_account(&db, "did:plc:ghost2")
            .await
            .expect("no DB error");
        assert!(
            matches!(result, AccountStateChange::NotFound),
            "a DID with no account row must return NotFound"
        );
    }

    #[tokio::test]
    async fn activate_makes_account_is_active_return_true() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:l").await;
        deactivate_account(&db, "did:plc:l", None).await.unwrap();
        assert!(
            !account_is_active(&db, "did:plc:l").await.unwrap(),
            "account_is_active must be false after deactivation"
        );

        activate_account(&db, "did:plc:l").await.unwrap();
        assert!(
            account_is_active(&db, "did:plc:l").await.unwrap(),
            "account_is_active must be true after activation"
        );
    }

    // ── get_repo_write_state ──────────────────────────────────────────────────

    #[tokio::test]
    async fn get_repo_write_state_missing_did_returns_none() {
        let db = test_pool().await;

        let result = get_repo_write_state(&db, "did:plc:missing")
            .await
            .expect("no DB error");
        assert!(result.is_none(), "a missing DID must return None");
    }

    #[tokio::test]
    async fn get_repo_write_state_active_account_is_active() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:m").await;

        let state = get_repo_write_state(&db, "did:plc:m")
            .await
            .unwrap()
            .expect("account exists");
        assert!(state.active, "active account must report active=true");
    }

    #[tokio::test]
    async fn get_repo_write_state_deactivated_account_is_not_active() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:n").await;
        deactivate_account(&db, "did:plc:n", None).await.unwrap();

        let state = get_repo_write_state(&db, "did:plc:n")
            .await
            .unwrap()
            .expect("account exists");
        assert!(
            !state.active,
            "deactivated account must report active=false"
        );
    }

    #[tokio::test]
    async fn get_repo_write_state_returns_correct_repo_root_cid() {
        let db = test_pool().await;
        let cid = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";
        insert_account_with_repo(&db, "did:plc:o", cid).await;

        let state = get_repo_write_state(&db, "did:plc:o")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(
            state.repo_root_cid.as_deref(),
            Some(cid),
            "must return the stored repo root CID"
        );
    }

    #[tokio::test]
    async fn get_repo_write_state_null_repo_root_cid() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:p").await;

        let state = get_repo_write_state(&db, "did:plc:p")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(
            state.repo_root_cid, None,
            "an account without a repo must have repo_root_cid=None"
        );
    }

    #[tokio::test]
    async fn get_repo_write_state_deactivated_preserves_repo_root_cid() {
        let db = test_pool().await;
        let cid = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";
        insert_account_with_repo(&db, "did:plc:q", cid).await;
        deactivate_account(&db, "did:plc:q", None).await.unwrap();

        let state = get_repo_write_state(&db, "did:plc:q")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(
            state.repo_root_cid.as_deref(),
            Some(cid),
            "deactivation must not clear repo_root_cid"
        );
        assert!(!state.active);
    }
}

/// Resolve a handle or DID to an active (non-deactivated) account.
///
/// Returns `None` when not found; `Err` only on DB errors.
pub(crate) async fn resolve_identifier(
    db: &sqlx::SqlitePool,
    identifier: &str,
) -> Result<Option<AccountRow>, ApiError> {
    if identifier.starts_with("did:") {
        let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT a.email, a.password_hash, h.handle \
             FROM accounts a \
             LEFT JOIN handles h ON h.did = a.did \
             WHERE a.did = ? AND a.deactivated_at IS NULL \
             LIMIT 1",
        )
        .bind(identifier)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(identifier = %identifier, error = %e, "DB error resolving DID");
            ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
        })?;

        Ok(row.map(|(email, password_hash, handle)| AccountRow {
            did: identifier.to_string(),
            email,
            password_hash,
            handle,
        }))
    } else {
        let row: Option<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT a.did, a.email, a.password_hash, h.handle \
             FROM handles h \
             JOIN accounts a ON a.did = h.did \
             WHERE h.handle = ? AND a.deactivated_at IS NULL \
             LIMIT 1",
        )
        .bind(identifier)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!(identifier = %identifier, error = %e, "DB error resolving handle");
            ApiError::new(ErrorCode::InternalError, "failed to resolve identifier")
        })?;

        Ok(row.map(|(did, email, password_hash, handle)| AccountRow {
            did,
            email,
            password_hash,
            handle: Some(handle),
        }))
    }
}
