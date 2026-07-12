// pattern: Imperative Shell
//
// Account lookup queries. Gathers from the accounts + handles + did_documents tables;
// returns plain data structs. No business logic — callers decide what to do with the result.

use common::{ApiError, ErrorCode};
use sqlx::Sqlite;

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

/// Whether a fully-provisioned account row exists for `did` (unfiltered by lifecycle). Used by the
/// account-creation paths to reject a DID that has already been promoted.
pub(crate) async fn account_exists(db: &sqlx::SqlitePool, did: &str) -> Result<bool, ApiError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE did = ?)")
        .bind(did)
        .fetch_one(db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to check accounts existence");
            ApiError::new(ErrorCode::InternalError, "database error")
        })?;

    Ok(exists)
}

/// Fetch account info needed for `getSession` by DID.
///
/// Returns `None` when the DID is not found or the account is not active (deactivated,
/// suspended, or taken down).
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
         WHERE a.did = ? AND a.deactivated_at IS NULL AND a.suspended_at IS NULL \
           AND a.taken_down_at IS NULL \
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

/// Mark an active account's email confirmed.
///
/// Sets `email_confirmed_at` to now for the account named by `did`, provided it is active (not
/// deactivated, suspended, or taken down — mirroring [`get_session_account`]'s guard). Returns
/// `true` when a row was updated, `false` when no active account matched. Re-confirming an
/// already-confirmed account simply refreshes the timestamp — harmless and idempotent.
pub(crate) async fn set_email_confirmed(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<bool, ApiError> {
    let result = sqlx::query(
        "UPDATE accounts \
         SET email_confirmed_at = datetime('now'), updated_at = datetime('now') \
         WHERE did = ? AND deactivated_at IS NULL AND suspended_at IS NULL \
           AND taken_down_at IS NULL",
    )
    .bind(did)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to set email_confirmed_at");
        ApiError::new(ErrorCode::InternalError, "failed to confirm email")
    })?;
    Ok(result.rows_affected() == 1)
}

/// Outcome of [`update_account_email`].
pub(crate) enum EmailUpdateOutcome {
    /// The email was changed and confirmation state reset.
    Updated,
    /// No active account row matched the DID.
    NotFound,
    /// The requested new email is already in use by another account
    /// (the `idx_accounts_email` UNIQUE index rejected the write).
    Taken,
}

/// Change an active account's email and reset its confirmation state.
///
/// Sets `email` to `new_email` and clears `email_confirmed_at` — a changed address is unconfirmed
/// until re-verified — for the account named by `did`, provided it is active. A collision with the
/// `idx_accounts_email` UNIQUE index is reported as [`EmailUpdateOutcome::Taken`] rather than a
/// 500, so the caller can return a clean client error.
pub(crate) async fn update_account_email(
    db: &sqlx::SqlitePool,
    did: &str,
    new_email: &str,
) -> Result<EmailUpdateOutcome, ApiError> {
    let result = sqlx::query(
        "UPDATE accounts \
         SET email = ?, email_confirmed_at = NULL, updated_at = datetime('now') \
         WHERE did = ? AND deactivated_at IS NULL AND suspended_at IS NULL \
           AND taken_down_at IS NULL",
    )
    .bind(new_email)
    .bind(did)
    .execute(db)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 1 => Ok(EmailUpdateOutcome::Updated),
        Ok(_) => Ok(EmailUpdateOutcome::NotFound),
        Err(e) if crate::db::is_unique_violation(&e) => Ok(EmailUpdateOutcome::Taken),
        Err(e) => {
            tracing::error!(did = %did, error = %e, "failed to update account email");
            Err(ApiError::new(
                ErrorCode::InternalError,
                "failed to update email",
            ))
        }
    }
}

/// Fetch the account's derived [`AccountLifecycle`], or `None` when no account row exists.
///
/// Used by handlers that authenticate via JWT but still need account-lifecycle context —
/// e.g. the preferences routes, which otherwise have no reason to read the `accounts`
/// table. Deliberately unfiltered (unlike `get_session_account`'s lifecycle guard) so a
/// route can keep serving a self-service-deactivated account — the migration window between
/// a deactivated `createAccount` and `activateAccount` — while still refusing moderation
/// states. The caller decides which lifecycle states it admits.
pub(crate) async fn account_lifecycle(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<AccountLifecycle>, ApiError> {
    let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT deactivated_at, suspended_at, taken_down_at FROM accounts WHERE did = ?",
    )
    .bind(did)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "DB error loading account lifecycle");
        ApiError::new(ErrorCode::InternalError, "failed to load account")
    })?;

    Ok(row.map(|(deactivated_at, suspended_at, taken_down_at)| {
        AccountLifecycle::from_timestamps(
            deactivated_at.as_deref(),
            suspended_at.as_deref(),
            taken_down_at.as_deref(),
        )
    }))
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
/// Stores `delete_after` verbatim (the caller validates it is an RFC 3339 datetime). The result is
/// derived from the writes themselves, not a pre-read: a conditional UPDATE flips an *active*
/// account and reports [`AccountStateChange::Changed`]; if nothing flipped, a second UPDATE
/// refreshes `delete_after` on an already-deactivated account (preserving the original
/// `deactivated_at`) and reports `Unchanged`, or matches nothing and reports `NotFound`.
///
/// Takes the caller's open transaction rather than opening its own: the route handler commits it
/// only after also deciding whether to stage a firehose `#account` event in the same transaction
/// (on `Changed`), so the status transition and the event either land together or not at all.
pub(crate) async fn deactivate_account(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    did: &str,
    delete_after: Option<&str>,
) -> Result<AccountStateChange, ApiError> {
    let map_err = |e: sqlx::Error| {
        tracing::error!(did = %did, error = %e, "DB error deactivating account");
        ApiError::new(ErrorCode::InternalError, "failed to deactivate account")
    };

    // Transition: only an active account (deactivated_at IS NULL) flips here, so rows_affected == 1
    // means this call performed the real active → deactivated transition.
    let transitioned = sqlx::query(
        "UPDATE accounts \
         SET deactivated_at = datetime('now'), delete_after = ?, updated_at = datetime('now') \
         WHERE did = ? AND deactivated_at IS NULL",
    )
    .bind(delete_after)
    .bind(did)
    .execute(&mut **tx)
    .await
    .map_err(&map_err)?;

    if transitioned.rows_affected() == 1 {
        return Ok(AccountStateChange::Changed);
    }

    // No transition: either already deactivated (refresh delete_after, leaving deactivated_at
    // untouched) or no such account. rows_affected distinguishes the two.
    let refreshed = sqlx::query(
        "UPDATE accounts SET delete_after = ?, updated_at = datetime('now') WHERE did = ?",
    )
    .bind(delete_after)
    .bind(did)
    .execute(&mut **tx)
    .await
    .map_err(&map_err)?;

    Ok(if refreshed.rows_affected() == 1 {
        AccountStateChange::Unchanged
    } else {
        AccountStateChange::NotFound
    })
}

/// Clear an account's deactivation, returning it to active status.
///
/// Sets both `deactivated_at` and `delete_after` back to NULL. The result is derived from the
/// write itself: a conditional UPDATE flips a *deactivated* account and reports
/// [`AccountStateChange::Changed`]; if nothing flipped, a single existence read distinguishes an
/// already-active account (`Unchanged`, no firehose event) from a missing one (`NotFound`). A
/// stale read there can only yield `Unchanged`/`NotFound` — both no-emit outcomes — so it cannot
/// cause a spurious `#account` event.
///
/// Takes the caller's open transaction (see [`deactivate_account`]) rather than the pool, so a
/// `Changed` outcome can stage a firehose `#account` event in the same transaction before commit.
pub(crate) async fn activate_account(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    did: &str,
) -> Result<AccountStateChange, ApiError> {
    let map_err = |e: sqlx::Error| {
        tracing::error!(did = %did, error = %e, "DB error activating account");
        ApiError::new(ErrorCode::InternalError, "failed to activate account")
    };

    // Transition: only a deactivated account flips here, so rows_affected == 1 means this call
    // performed the real deactivated → active transition.
    let transitioned = sqlx::query(
        "UPDATE accounts \
         SET deactivated_at = NULL, delete_after = NULL, updated_at = datetime('now') \
         WHERE did = ? AND deactivated_at IS NOT NULL",
    )
    .bind(did)
    .execute(&mut **tx)
    .await
    .map_err(&map_err)?;

    if transitioned.rows_affected() == 1 {
        return Ok(AccountStateChange::Changed);
    }

    let exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM accounts WHERE did = ? LIMIT 1")
        .bind(did)
        .fetch_optional(&mut **tx)
        .await
        .map_err(&map_err)?;

    Ok(if exists.is_some() {
        AccountStateChange::Unchanged
    } else {
        AccountStateChange::NotFound
    })
}

/// List the DIDs of accounts whose scheduled permanent-deletion time has arrived.
///
/// A `delete_after` is only ever set alongside `deactivated_at` (by `deactivateAccount`) and is
/// cleared on reactivation, so a non-NULL `delete_after` in the past uniquely identifies an
/// account that asked to be permanently deleted and whose grace window has elapsed. Backs the
/// deletion reaper (`account_reaper.rs`). Unfiltered by lifecycle otherwise — the whole point is
/// to act on deactivated accounts.
///
/// `delete_after` is stored verbatim as the client-supplied RFC 3339 string (with a `T`
/// separator and a `Z`/offset), while `datetime('now')` renders `YYYY-MM-DD HH:MM:SS`. A raw text
/// `<=` between those two formats is wrong — e.g. an instant earlier *today* sorts *after*
/// `datetime('now')` because `'T'` (0x54) > `' '` (0x20) — so both sides are normalised through
/// SQLite's `datetime()`, which parses the ISO-8601 form (converting any offset to UTC) into the
/// same canonical shape before comparison.
pub async fn accounts_due_for_deletion(db: &sqlx::SqlitePool) -> Result<Vec<String>, ApiError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT did FROM accounts \
         WHERE delete_after IS NOT NULL AND datetime(delete_after) <= datetime('now')",
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error listing accounts due for deletion");
        ApiError::new(ErrorCode::InternalError, "failed to list accounts")
    })?;
    Ok(rows.into_iter().map(|(did,)| did).collect())
}

/// Fetch an account's stored password hash by DID, **without** the lifecycle guard the login
/// lookups apply — a deactivated account must still be resolvable here so it can be deleted.
///
/// Returns `None` when no account row exists for `did`; `Some(None)` when the account exists but
/// has no main password (a mobile account); `Some(Some(hash))` otherwise. Backs
/// `deleteAccount`, which authenticates by DID + password + email token rather than a session.
pub async fn account_password_hash(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<Option<String>>, ApiError> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT password_hash FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "DB error fetching account password hash");
                ApiError::new(ErrorCode::InternalError, "failed to look up account")
            })?;
    Ok(row.map(|(hash,)| hash))
}

/// Outcome of [`set_account_takedown`], carrying the account's full derived lifecycle after the
/// write rather than just whether the takedown dimension itself changed.
///
/// Clearing a takedown does not necessarily return the account to `Active`: `suspended_at` or
/// `deactivated_at` may still be set, and the caller's firehose `#account` event must reflect
/// the account's true resulting state (per the takendown > suspended > deactivated precedence),
/// not just this call's own dimension.
pub(crate) enum TakedownStateChange {
    /// No account row matched the DID.
    NotFound,
    /// The takedown flag was already at the requested value; nothing meaningful changed. The
    /// carried lifecycle still reflects the account's current (unaffected) state.
    Unchanged(AccountLifecycle),
    /// `taken_down_at` transitioned (set or cleared). The carried lifecycle is the account's
    /// state immediately after this write.
    Changed(AccountLifecycle),
}

/// Apply or clear an account takedown, flipping `taken_down_at`.
///
/// Backs `com.atproto.admin.updateSubjectStatus`'s `takedown` field: `applied = true` sets
/// `taken_down_at` (only if not already set); `applied = false` clears it (only if currently
/// set). The transition result is derived from the write itself, mirroring
/// [`deactivate_account`]/[`activate_account`] — a conditional UPDATE flips the column and
/// reports [`TakedownStateChange::Changed`]; a redundant call (already at the target value)
/// reports [`TakedownStateChange::Unchanged`]. Either way the row is read back afterward to
/// derive the account's full [`AccountLifecycle`], since a lone `taken_down_at` flip does not
/// determine the resulting `active`/`status` when `suspended_at`/`deactivated_at` may also be
/// set.
///
/// Takes the caller's open transaction (see [`deactivate_account`]) so the status transition and
/// its firehose `#account` event commit atomically.
pub(crate) async fn set_account_takedown(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    did: &str,
    applied: bool,
) -> Result<TakedownStateChange, ApiError> {
    let map_err = |e: sqlx::Error| {
        tracing::error!(did = %did, error = %e, "DB error setting account takedown");
        ApiError::new(ErrorCode::InternalError, "failed to update account status")
    };

    let transitioned = if applied {
        sqlx::query(
            "UPDATE accounts \
             SET taken_down_at = datetime('now'), updated_at = datetime('now') \
             WHERE did = ? AND taken_down_at IS NULL",
        )
        .bind(did)
    } else {
        sqlx::query(
            "UPDATE accounts SET taken_down_at = NULL, updated_at = datetime('now') \
             WHERE did = ? AND taken_down_at IS NOT NULL",
        )
        .bind(did)
    }
    .execute(&mut **tx)
    .await
    .map_err(&map_err)?;

    let changed = transitioned.rows_affected() == 1;

    // (deactivated_at, suspended_at, taken_down_at) — read back regardless of whether this call
    // itself changed anything, so the caller always gets an accurate resulting lifecycle.
    type Row = (Option<String>, Option<String>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT deactivated_at, suspended_at, taken_down_at FROM accounts WHERE did = ?",
    )
    .bind(did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(&map_err)?;

    let Some((deactivated_at, suspended_at, taken_down_at)) = row else {
        return Ok(TakedownStateChange::NotFound);
    };
    let lifecycle = AccountLifecycle::from_timestamps(
        deactivated_at.as_deref(),
        suspended_at.as_deref(),
        taken_down_at.as_deref(),
    );

    Ok(if changed {
        TakedownStateChange::Changed(lifecycle)
    } else {
        TakedownStateChange::Unchanged(lifecycle)
    })
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

/// Operator-facing account overview, fetched without the `deactivated_at IS NULL` guard that
/// the user-facing lookups apply: the provisioning/usage endpoints report on an account
/// regardless of its activation state.
pub(crate) struct AccountOverview {
    /// When the account row was created (`accounts.created_at`).
    pub(crate) created_at: String,
    /// Stored repo root commit CID, or `None` when the account has no repo yet.
    pub(crate) repo_root_cid: Option<String>,
}

/// Fetch an [`AccountOverview`] by DID for the operator usage/storage endpoints.
///
/// Returns `None` only when no account row exists for `did` (the caller maps this to a 404).
/// Unlike `resolve_identifier`'s lifecycle gate, this does **not** filter deactivated
/// accounts — an operator still needs their usage figures.
pub(crate) async fn get_account_overview(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<AccountOverview>, sqlx::Error> {
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT created_at, repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await?;

    Ok(row.map(|(created_at, repo_root_cid)| AccountOverview {
        created_at,
        repo_root_cid,
    }))
}

/// The timestamp of an account's most recent repo-block write or blob upload, or `None` when
/// it has neither.
///
/// `block_owners.created_at` and `blob_owners.created_at` share the same
/// `strftime('%Y-%m-%dT%H:%M:%fZ')` format, so the cross-table `MAX` is a valid lexicographic
/// comparison. Blob activity reads the per-account ownership rows, not the physical `blobs`
/// table, whose `account_did` records only the first uploader. Callers fall back to the
/// account's `created_at` when this is `None` (a freshly provisioned account with no repo
/// and no blobs).
pub(crate) async fn account_last_active(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: (Option<String>,) = sqlx::query_as(
        "SELECT MAX(ts) FROM ( \
            SELECT created_at AS ts FROM block_owners WHERE account_did = ? \
            UNION ALL \
            SELECT created_at AS ts FROM blob_owners WHERE account_did = ? \
         )",
    )
    .bind(did)
    .bind(did)
    .fetch_one(db)
    .await?;

    Ok(row.0)
}

/// Repo write preconditions for an account: its repo root CID and active status, fetched in one
/// query. Backs the create/put/delete/applyWrites paths, which need both the CAS root and the
/// lifecycle gate — reading them together avoids a second round-trip against `accounts` and
/// narrows the window between the active check and the commit CAS.
pub(crate) struct RepoWriteState {
    /// Stored repo root commit CID, or `None` when the account exists but has no repo yet.
    pub(crate) repo_root_cid: Option<String>,
    /// `true` when the account is not deactivated, suspended, or taken down.
    pub(crate) active: bool,
}

/// Fetch the repo root CID and active status for `did` in a single query.
///
/// Returns `None` when no account row exists for `did` (the caller maps this to a 404, the same
/// as a `None` `repo_root_cid`). `active` is derived from `deactivated_at`/`suspended_at`/
/// `taken_down_at` via [`AccountLifecycle`] — a takedown or suspension closes the repo to writes
/// exactly like a self-service deactivation.
pub(crate) async fn get_repo_write_state(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<RepoWriteState>, sqlx::Error> {
    // (repo_root_cid, deactivated_at, suspended_at, taken_down_at)
    type Row = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT repo_root_cid, deactivated_at, suspended_at, taken_down_at \
         FROM accounts WHERE did = ?",
    )
    .bind(did)
    .fetch_optional(db)
    .await?;

    Ok(row.map(
        |(repo_root_cid, deactivated_at, suspended_at, taken_down_at)| RepoWriteState {
            repo_root_cid,
            active: AccountLifecycle::from_timestamps(
                deactivated_at.as_deref(),
                suspended_at.as_deref(),
                taken_down_at.as_deref(),
            )
            .is_active(),
        },
    ))
}

/// Fetch the account's persisted repo head, unfiltered by lifecycle status.
///
/// Backs `record_write::gc_repo_blocks`'s stale-root guard: GC must compare against whatever root
/// is actually persisted, so unlike [`get_repo_write_state`] this deliberately ignores
/// deactivation/suspension/takedown. Returns `None` when the account is missing or has no repo.
pub(crate) async fn current_repo_root(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<Option<String>> =
        sqlx::query_scalar("SELECT repo_root_cid FROM accounts WHERE did = ?")
            .bind(did)
            .fetch_optional(db)
            .await?;
    Ok(row.flatten())
}

/// Advance an account's repo root with optimistic concurrency, only while it is still active.
///
/// The commit compare-and-swap shared by every write path (`createRecord`/`putRecord` via
/// `record_write`, `deleteRecord`, `applyWrites`): set `repo_root_cid`/`repo_rev` to the new
/// values, but only if the persisted root still equals `expected_root` *and* the account is not
/// deactivated, suspended, or taken down. Returns `true` when the swap landed (exactly one row
/// updated) and `false` when it did not — a concurrent write moved the root, or the account lost
/// active status between the caller's active check and this commit. Callers map `false` to a 409
/// conflict. Single statement, so no transaction is opened here — generic over the executor so
/// the caller can run it inside a transaction that also stages the firehose `#commit` row (see
/// `record_write::commit_repo_write`), making the CAS and the event commit atomically.
pub(crate) async fn advance_repo_root_if_active<'e, E>(
    executor: E,
    did: &str,
    new_root: &str,
    new_rev: &str,
    expected_root: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let updated = sqlx::query(
        "UPDATE accounts SET repo_root_cid = ?, repo_rev = ? \
         WHERE did = ? AND repo_root_cid = ? AND deactivated_at IS NULL \
           AND suspended_at IS NULL AND taken_down_at IS NULL",
    )
    .bind(new_root)
    .bind(new_rev)
    .bind(did)
    .bind(expected_root)
    .execute(executor)
    .await?;

    Ok(updated.rows_affected() == 1)
}

/// Set the repo root/rev of a **deactivated, repo-less** account after an `importRepo`, atomically
/// with the caller's block-insert transaction.
///
/// Unlike [`advance_repo_root_if_active`], the account must be **deactivated** (importing over a
/// live repo is not supported) and must not already hold a repo — the `repo_root_cid IS NULL`
/// guard makes import strictly first-write-wins, so a retried or racing `importRepo` cannot
/// silently overwrite an already-imported repo (it gets `false` → the caller's 409). A failed
/// import rolls back its whole transaction, leaving `repo_root_cid` NULL, so this does not block
/// a legitimate retry after an error. The guard also rejects a suspended or taken-down account.
/// Returns `true` when exactly one row was updated, `false` otherwise. Single statement, so no
/// transaction is opened here — generic over the executor so the caller can run it inside the
/// transaction that persists the imported blocks.
pub(crate) async fn set_repo_root_for_deactivated<'e, E>(
    executor: E,
    did: &str,
    new_root: &str,
    new_rev: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let updated = sqlx::query(
        "UPDATE accounts SET repo_root_cid = ?, repo_rev = ? \
         WHERE did = ? AND repo_root_cid IS NULL AND deactivated_at IS NOT NULL \
           AND suspended_at IS NULL AND taken_down_at IS NULL",
    )
    .bind(new_root)
    .bind(new_rev)
    .bind(did)
    .execute(executor)
    .await?;

    Ok(updated.rows_affected() == 1)
}

/// The moderation/lifecycle state of an account, derived from its nullable timestamp columns.
///
/// Backs the `active` flag (and, for `getRepoStatus`, the `status` reason) of the public sync
/// endpoints. Precedence runs from most to least severe — taken down → suspended → deactivated →
/// active — so an account with several timestamps set reports only its strongest restriction (a
/// moderation takedown supersedes the user's own deactivation). Only `Active` means the repo is
/// actively hosted; every other state reports `active: false`. The lexicon `status` string is a
/// wire concern owned by the route handler, not this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountLifecycle {
    Active,
    Deactivated,
    Suspended,
    TakenDown,
}

impl AccountLifecycle {
    /// Derive the lifecycle from the three nullable lifecycle timestamps; any non-NULL value
    /// means that state is set. Applies the takendown > suspended > deactivated precedence.
    fn from_timestamps(
        deactivated_at: Option<&str>,
        suspended_at: Option<&str>,
        taken_down_at: Option<&str>,
    ) -> Self {
        if taken_down_at.is_some() {
            Self::TakenDown
        } else if suspended_at.is_some() {
            Self::Suspended
        } else if deactivated_at.is_some() {
            Self::Deactivated
        } else {
            Self::Active
        }
    }

    /// `true` only when the repo is actively hosted (no lifecycle restriction in force).
    pub(crate) fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// The lexicon `status` knownValue for this lifecycle state, or `None` when `Active`.
    ///
    /// Maps each non-active state to its AT Protocol wire string. `Active` returns `None`
    /// because the `status` field is omitted entirely for a live repo (it carries a *reason*
    /// for being inactive, and is meaningless otherwise). The route handler calls this instead
    /// of duplicating the match.
    pub(crate) fn as_status_str(self) -> Option<&'static str> {
        match self {
            Self::Active => None,
            Self::Deactivated => Some("deactivated"),
            Self::Suspended => Some("suspended"),
            Self::TakenDown => Some("takendown"),
        }
    }

    /// Parse an operator-supplied status filter string: the wire strings from
    /// [`Self::as_status_str`] plus `"active"` (which that method expresses as omission).
    /// Returns `None` for an unrecognized value — the caller decides how to reject it.
    pub(crate) fn from_status_filter(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "deactivated" => Some(Self::Deactivated),
            "suspended" => Some(Self::Suspended),
            "takendown" => Some(Self::TakenDown),
            _ => None,
        }
    }

    /// SQL predicate selecting exactly the accounts whose *derived* lifecycle is this state.
    ///
    /// Must mirror [`Self::from_timestamps`]'s precedence (takendown > suspended > deactivated):
    /// e.g. an account that is both suspended and taken down derives `TakenDown`, so the
    /// `Suspended` predicate has to exclude it or the same account would match two filters.
    /// Column references are prefixed with the `a.` alias used by [`list_accounts_admin`], the
    /// sole consumer.
    fn as_sql_predicate(self) -> &'static str {
        match self {
            Self::Active => {
                "a.deactivated_at IS NULL AND a.suspended_at IS NULL AND a.taken_down_at IS NULL"
            }
            Self::Deactivated => {
                "a.deactivated_at IS NOT NULL AND a.suspended_at IS NULL \
                 AND a.taken_down_at IS NULL"
            }
            Self::Suspended => "a.suspended_at IS NOT NULL AND a.taken_down_at IS NULL",
            Self::TakenDown => "a.taken_down_at IS NOT NULL",
        }
    }
}

/// A single repo entry for `com.atproto.sync.listRepos`.
///
/// Only accounts that have created their repo (non-NULL `repo_root_cid`) produce a row —
/// the lexicon requires `head` and `rev`, so an account without a repo root has nothing
/// to list. `active` is derived from the account lifecycle (deactivated/suspended/takendown).
pub(crate) struct RepoListRow {
    pub(crate) did: String,
    /// Raw stored repo root commit CID string (the repo `head`).
    pub(crate) head: String,
    /// Stored commit revision (TID). `None` for pre-`repo_rev`-migration accounts; the
    /// caller falls back to reading the rev from the commit block in that case.
    pub(crate) rev: Option<String>,
    /// `true` when the account is actively hosted (no deactivation, suspension, or takedown).
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
    // (did, repo_root_cid, repo_rev, deactivated_at, suspended_at, taken_down_at)
    type Row = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT did, repo_root_cid, repo_rev, deactivated_at, suspended_at, taken_down_at \
         FROM accounts \
         WHERE repo_root_cid IS NOT NULL AND did > ? \
         ORDER BY did ASC LIMIT ?",
    )
    .bind(cursor)
    .bind(limit)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(did, head, rev, deactivated_at, suspended_at, taken_down_at)| RepoListRow {
                did,
                head,
                rev,
                active: AccountLifecycle::from_timestamps(
                    deactivated_at.as_deref(),
                    suspended_at.as_deref(),
                    taken_down_at.as_deref(),
                )
                .is_active(),
            },
        )
        .collect())
}

/// One row of the operator account listing (`GET /v1/admin/accounts`).
pub(crate) struct AdminAccountRow {
    pub(crate) did: String,
    /// The account's first-created handle, or `None` when it has none. Accounts can hold
    /// several handles; the listing surfaces one deterministic choice.
    pub(crate) handle: Option<String>,
    pub(crate) created_at: String,
    /// Derived lifecycle state (takendown > suspended > deactivated > active).
    pub(crate) lifecycle: AccountLifecycle,
    /// Total bytes of the account's owned blobs (0 when it has none).
    pub(crate) blob_bytes: i64,
}

/// Escape SQL `LIKE` metacharacters (`%`, `_`, and the `\` escape itself) in a user-supplied
/// search term so it matches literally inside a `LIKE ... ESCAPE '\'` pattern.
fn escape_like(term: &str) -> String {
    term.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// List accounts for the operator console in DID order, starting strictly after `cursor`.
///
/// Pass `cursor = ""` for the first page; the caller derives the next cursor from the last
/// returned DID. `status` narrows to accounts whose *derived* lifecycle matches; `q` is a
/// literal substring match against the DID or any of the account's handles. Unlike
/// [`list_repos`] this includes accounts without a repo — the operator view must not hide
/// half-provisioned rows.
///
/// Handle and blob-byte lookups are correlated scalar subqueries rather than JOINs: a JOIN on
/// `handles` would duplicate a multi-handle account across rows (corrupting the DID cursor),
/// and both subqueries run only for the ≤`limit` emitted rows as indexed lookups — one query
/// per page instead of N+1 on the single-connection pool.
pub(crate) async fn list_accounts_admin(
    db: &sqlx::SqlitePool,
    cursor: &str,
    limit: i64,
    status: Option<AccountLifecycle>,
    q: Option<&str>,
) -> Result<Vec<AdminAccountRow>, sqlx::Error> {
    // (did, handle, created_at, deactivated_at, suspended_at, taken_down_at, blob_bytes)
    type Row = (
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    );

    // Assembled from fixed clause constants only — user input is always bound, never spliced.
    let mut sql = String::from(
        "SELECT a.did, \
                (SELECT h.handle FROM handles h WHERE h.did = a.did \
                 ORDER BY h.created_at ASC, h.handle ASC LIMIT 1), \
                a.created_at, a.deactivated_at, a.suspended_at, a.taken_down_at, \
                (SELECT COALESCE(SUM(b.size_bytes), 0) FROM blob_owners o \
                 JOIN blobs b ON b.cid = o.cid WHERE o.account_did = a.did) \
         FROM accounts a WHERE a.did > ?",
    );
    if let Some(status) = status {
        sql.push_str(" AND ");
        sql.push_str(status.as_sql_predicate());
    }
    if q.is_some() {
        sql.push_str(
            " AND (a.did LIKE ? ESCAPE '\\' OR EXISTS \
              (SELECT 1 FROM handles hq WHERE hq.did = a.did AND hq.handle LIKE ? ESCAPE '\\'))",
        );
    }
    sql.push_str(" ORDER BY a.did ASC LIMIT ?");

    let mut query = sqlx::query_as::<_, Row>(&sql).bind(cursor);
    if let Some(term) = q {
        let pattern = format!("%{}%", escape_like(term));
        query = query.bind(pattern.clone()).bind(pattern);
    }
    let rows = query.bind(limit).fetch_all(db).await?;

    Ok(rows
        .into_iter()
        .map(
            |(did, handle, created_at, deactivated_at, suspended_at, taken_down_at, blob_bytes)| {
                AdminAccountRow {
                    did,
                    handle,
                    created_at,
                    lifecycle: AccountLifecycle::from_timestamps(
                        deactivated_at.as_deref(),
                        suspended_at.as_deref(),
                        taken_down_at.as_deref(),
                    ),
                    blob_bytes,
                }
            },
        )
        .collect())
}

/// Repo hosting status for a single account, backing `com.atproto.sync.getRepoStatus`.
///
/// Unlike most account lookups this row is produced even for a non-active account — reporting
/// that state *is* the point of `getRepoStatus`. `lifecycle` carries the derived account state
/// (the handler maps it to the lexicon `active`/`status` fields); `head`/`rev` are `None` for an
/// account that has not created its repo.
pub(crate) struct RepoStatusRow {
    /// The account's lifecycle state, derived from its deactivation/suspension/takedown columns.
    pub(crate) lifecycle: AccountLifecycle,
    /// Stored repo root commit CID (the repo `head`), or `None` when the account has no repo.
    pub(crate) head: Option<String>,
    /// Stored commit revision (TID). `None` for an account with no repo or one created before
    /// the `repo_rev` migration; the caller falls back to reading the rev from the commit block.
    pub(crate) rev: Option<String>,
}

/// Fetch repo hosting status for a single DID for `getRepoStatus`.
///
/// Returns `None` only when no account row exists for `did` (the caller maps this to a 404).
/// This query intentionally does **not** filter on any lifecycle column: a deactivated,
/// suspended, or taken-down account still has a reportable status.
pub(crate) async fn get_repo_status(
    db: &sqlx::SqlitePool,
    did: &str,
) -> Result<Option<RepoStatusRow>, sqlx::Error> {
    // (deactivated_at, suspended_at, taken_down_at, repo_root_cid, repo_rev)
    type Row = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT deactivated_at, suspended_at, taken_down_at, repo_root_cid, repo_rev \
         FROM accounts WHERE did = ?",
    )
    .bind(did)
    .fetch_optional(db)
    .await?;

    Ok(row.map(
        |(deactivated_at, suspended_at, taken_down_at, head, rev)| RepoStatusRow {
            lifecycle: AccountLifecycle::from_timestamps(
                deactivated_at.as_deref(),
                suspended_at.as_deref(),
                taken_down_at.as_deref(),
            ),
            head,
            rev,
        },
    ))
}

/// Resolve an email address to an active account (not deactivated, suspended, or taken down).
///
/// Used by the provisioning session login endpoint (`POST /v1/accounts/sessions`).
/// Returns `None` when not found or not active; `Err` only on DB errors.
pub(crate) async fn resolve_by_email(
    db: &sqlx::SqlitePool,
    email: &str,
) -> Result<Option<AccountRow>, ApiError> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT a.did, a.password_hash, h.handle \
         FROM accounts a \
         LEFT JOIN handles h ON h.did = a.did \
         WHERE a.email = ? AND a.deactivated_at IS NULL AND a.suspended_at IS NULL \
           AND a.taken_down_at IS NULL \
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

/// Resolve a handle or DID to an active account (not deactivated, suspended, or taken down).
///
/// Returns `None` when not found or not active; `Err` only on DB errors.
pub(crate) async fn resolve_identifier(
    db: &sqlx::SqlitePool,
    identifier: &str,
) -> Result<Option<AccountRow>, ApiError> {
    if identifier.starts_with("did:") {
        let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT a.email, a.password_hash, h.handle \
             FROM accounts a \
             LEFT JOIN handles h ON h.did = a.did \
             WHERE a.did = ? AND a.deactivated_at IS NULL AND a.suspended_at IS NULL \
               AND a.taken_down_at IS NULL \
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
             WHERE h.handle = ? AND a.deactivated_at IS NULL AND a.suspended_at IS NULL \
               AND a.taken_down_at IS NULL \
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

    /// Run [`deactivate_account`] in its own committed transaction — production callers hold the
    /// transaction open to also stage a firehose event, but these tests only exercise the DB
    /// state transition, so wrapping and committing here keeps the individual test bodies calling
    /// it exactly as before the tx-taking signature change.
    async fn deactivate(
        db: &sqlx::SqlitePool,
        did: &str,
        delete_after: Option<&str>,
    ) -> AccountStateChange {
        let mut tx = db.begin().await.unwrap();
        let result = deactivate_account(&mut tx, did, delete_after)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        result
    }

    /// Run [`activate_account`] in its own committed transaction (see [`deactivate`]).
    async fn activate(db: &sqlx::SqlitePool, did: &str) -> AccountStateChange {
        let mut tx = db.begin().await.unwrap();
        let result = activate_account(&mut tx, did).await.unwrap();
        tx.commit().await.unwrap();
        result
    }

    // ── deactivate_account ────────────────────────────────────────────────────

    #[tokio::test]
    async fn deactivate_active_account_returns_changed() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:a").await;

        let result = deactivate(&db, "did:plc:a", None).await;
        assert!(
            matches!(result, AccountStateChange::Changed),
            "first deactivation must return Changed"
        );
    }

    #[tokio::test]
    async fn deactivate_active_account_sets_deactivated_at() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:b").await;

        deactivate(&db, "did:plc:b", None).await;

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

        deactivate(&db, "did:plc:c", Some("2030-01-01T00:00:00Z")).await;

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

        deactivate(&db, "did:plc:d", None).await;

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

        deactivate(&db, "did:plc:e", None).await;
        let result = deactivate(&db, "did:plc:e", None).await;
        assert!(
            matches!(result, AccountStateChange::Unchanged),
            "re-deactivating an already-deactivated account must return Unchanged"
        );
    }

    #[tokio::test]
    async fn re_deactivating_preserves_original_deactivated_at() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:f").await;

        deactivate(&db, "did:plc:f", None).await;

        // Pin the deactivation instant to a known sentinel so the assertion does not depend on
        // `datetime('now')`'s one-second granularity (which a short sleep could not outrun).
        const SENTINEL: &str = "2020-01-01 00:00:00";
        sqlx::query("UPDATE accounts SET deactivated_at = ? WHERE did = ?")
            .bind(SENTINEL)
            .bind("did:plc:f")
            .execute(&db)
            .await
            .unwrap();

        // Re-deactivate with a new delete_after: the transition path must not fire, so the
        // original deactivated_at sentinel must survive untouched.
        deactivate(&db, "did:plc:f", Some("2031-06-01T00:00:00Z")).await;
        let deactivated_at: Option<String> =
            sqlx::query_scalar("SELECT deactivated_at FROM accounts WHERE did = ?")
                .bind("did:plc:f")
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(
            deactivated_at.as_deref(),
            Some(SENTINEL),
            "re-deactivation must preserve the original deactivated_at"
        );
    }

    #[tokio::test]
    async fn re_deactivating_refreshes_delete_after() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:g").await;

        deactivate(&db, "did:plc:g", Some("2030-01-01T00:00:00Z")).await;
        deactivate(&db, "did:plc:g", Some("2031-06-15T12:00:00Z")).await;

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

        let result = deactivate(&db, "did:plc:ghost", None).await;
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
        deactivate(&db, "did:plc:h", None).await;

        let result = activate(&db, "did:plc:h").await;
        assert!(
            matches!(result, AccountStateChange::Changed),
            "activating a deactivated account must return Changed"
        );
    }

    #[tokio::test]
    async fn activate_clears_deactivated_at() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:i").await;
        deactivate(&db, "did:plc:i", None).await;

        activate(&db, "did:plc:i").await;

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
        deactivate(&db, "did:plc:j", Some("2030-01-01T00:00:00Z")).await;

        activate(&db, "did:plc:j").await;

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

        let result = activate(&db, "did:plc:k").await;
        assert!(
            matches!(result, AccountStateChange::Unchanged),
            "activating an already-active account must return Unchanged"
        );
    }

    #[tokio::test]
    async fn activate_missing_did_returns_not_found() {
        let db = test_pool().await;

        let result = activate(&db, "did:plc:ghost2").await;
        assert!(
            matches!(result, AccountStateChange::NotFound),
            "a DID with no account row must return NotFound"
        );
    }

    #[tokio::test]
    async fn activate_flips_account_lifecycle_back_to_active() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:l").await;
        deactivate(&db, "did:plc:l", None).await;
        assert_eq!(
            account_lifecycle(&db, "did:plc:l").await.unwrap(),
            Some(AccountLifecycle::Deactivated),
            "lifecycle must be Deactivated after deactivation"
        );

        activate(&db, "did:plc:l").await;
        assert_eq!(
            account_lifecycle(&db, "did:plc:l").await.unwrap(),
            Some(AccountLifecycle::Active),
            "lifecycle must be Active after activation"
        );
    }

    // ── get_account_overview / account_last_active ────────────────────────────

    #[tokio::test]
    async fn get_account_overview_missing_did_returns_none() {
        let db = test_pool().await;
        assert!(get_account_overview(&db, "did:plc:none")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn get_account_overview_returns_created_at_and_repo_root() {
        let db = test_pool().await;
        let cid = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";
        insert_account_with_repo(&db, "did:plc:ov", cid).await;

        let overview = get_account_overview(&db, "did:plc:ov")
            .await
            .unwrap()
            .expect("account exists");
        assert!(!overview.created_at.is_empty());
        assert_eq!(overview.repo_root_cid.as_deref(), Some(cid));
    }

    #[tokio::test]
    async fn get_account_overview_includes_deactivated_accounts() {
        // Unlike the user-facing lookups, the operator overview must still find a
        // deactivated account.
        let db = test_pool().await;
        insert_account(&db, "did:plc:ovde").await;
        deactivate(&db, "did:plc:ovde", None).await;

        assert!(get_account_overview(&db, "did:plc:ovde")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn account_last_active_none_without_blocks_or_blobs() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:la").await;
        assert!(account_last_active(&db, "did:plc:la")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn account_last_active_returns_latest_of_blocks_and_blobs() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:la2").await;

        // A block at an earlier instant, a blob at a later one. MAX must pick the blob.
        sqlx::query(
            "INSERT INTO blocks (cid, account_did, bytes, created_at) \
             VALUES ('bafblk', 'did:plc:la2', x'a100', '2026-01-01T00:00:00.000Z')",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO block_owners (cid, account_did, created_at) \
             VALUES ('bafblk', 'did:plc:la2', '2026-01-01T00:00:00.000Z')",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, created_at) \
             VALUES ('bafblb', 'did:plc:la2', 'image/png', 1, 'p', '2026-02-02T00:00:00.000Z')",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO blob_owners (cid, account_did, created_at) \
             VALUES ('bafblb', 'did:plc:la2', '2026-02-02T00:00:00.000Z')",
        )
        .execute(&db)
        .await
        .unwrap();

        let last = account_last_active(&db, "did:plc:la2").await.unwrap();
        assert_eq!(last.as_deref(), Some("2026-02-02T00:00:00.000Z"));
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
        deactivate(&db, "did:plc:n", None).await;

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

    // ── get_repo_status lifecycle derivation ──────────────────────────────────

    /// Set a single nullable lifecycle column on an account to `datetime('now')`. The column is
    /// matched to a fixed SQL statement (never interpolated) so the query stays static.
    async fn set_lifecycle_column(db: &sqlx::SqlitePool, did: &str, column: &str) {
        let sql = match column {
            "deactivated_at" => {
                "UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?"
            }
            "suspended_at" => "UPDATE accounts SET suspended_at = datetime('now') WHERE did = ?",
            "taken_down_at" => "UPDATE accounts SET taken_down_at = datetime('now') WHERE did = ?",
            other => panic!("unsupported lifecycle column: {other}"),
        };
        sqlx::query(sql).bind(did).execute(db).await.unwrap();
    }

    #[tokio::test]
    async fn get_repo_status_active_account_is_active() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:rs_active").await;

        let row = get_repo_status(&db, "did:plc:rs_active")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(row.lifecycle, AccountLifecycle::Active);
        assert!(row.lifecycle.is_active());
    }

    #[tokio::test]
    async fn get_repo_status_deactivated_account_reports_deactivated() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:rs_deact").await;
        set_lifecycle_column(&db, "did:plc:rs_deact", "deactivated_at").await;

        let row = get_repo_status(&db, "did:plc:rs_deact")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(row.lifecycle, AccountLifecycle::Deactivated);
        assert!(!row.lifecycle.is_active());
    }

    #[tokio::test]
    async fn get_repo_status_suspended_account_reports_suspended() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:rs_susp").await;
        set_lifecycle_column(&db, "did:plc:rs_susp", "suspended_at").await;

        let row = get_repo_status(&db, "did:plc:rs_susp")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(row.lifecycle, AccountLifecycle::Suspended);
    }

    #[tokio::test]
    async fn get_repo_status_takendown_account_reports_takendown() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:rs_td").await;
        set_lifecycle_column(&db, "did:plc:rs_td", "taken_down_at").await;

        let row = get_repo_status(&db, "did:plc:rs_td")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(row.lifecycle, AccountLifecycle::TakenDown);
    }

    #[tokio::test]
    async fn get_repo_status_takendown_supersedes_suspended_and_deactivated() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:rs_all").await;
        for column in ["deactivated_at", "suspended_at", "taken_down_at"] {
            set_lifecycle_column(&db, "did:plc:rs_all", column).await;
        }

        let row = get_repo_status(&db, "did:plc:rs_all")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(
            row.lifecycle,
            AccountLifecycle::TakenDown,
            "takedown must win the lifecycle precedence"
        );
    }

    #[tokio::test]
    async fn get_repo_status_suspended_supersedes_deactivated() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:rs_sd").await;
        set_lifecycle_column(&db, "did:plc:rs_sd", "deactivated_at").await;
        set_lifecycle_column(&db, "did:plc:rs_sd", "suspended_at").await;

        let row = get_repo_status(&db, "did:plc:rs_sd")
            .await
            .unwrap()
            .expect("account exists");
        assert_eq!(row.lifecycle, AccountLifecycle::Suspended);
    }

    #[tokio::test]
    async fn get_repo_status_missing_did_returns_none() {
        let db = test_pool().await;
        assert!(get_repo_status(&db, "did:plc:rs_ghost")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn get_repo_write_state_deactivated_preserves_repo_root_cid() {
        let db = test_pool().await;
        let cid = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";
        insert_account_with_repo(&db, "did:plc:q", cid).await;
        deactivate(&db, "did:plc:q", None).await;

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

    // ── get_repo_write_state / advance_repo_root_if_active lifecycle enforcement ──────────────

    #[tokio::test]
    async fn get_repo_write_state_suspended_account_is_not_active() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:gs_susp").await;
        set_lifecycle_column(&db, "did:plc:gs_susp", "suspended_at").await;

        let state = get_repo_write_state(&db, "did:plc:gs_susp")
            .await
            .unwrap()
            .expect("account exists");
        assert!(
            !state.active,
            "a suspended account must report active=false"
        );
    }

    #[tokio::test]
    async fn get_repo_write_state_takendown_account_is_not_active() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:gs_td").await;
        set_lifecycle_column(&db, "did:plc:gs_td", "taken_down_at").await;

        let state = get_repo_write_state(&db, "did:plc:gs_td")
            .await
            .unwrap()
            .expect("account exists");
        assert!(
            !state.active,
            "a taken-down account must report active=false"
        );
    }

    #[tokio::test]
    async fn advance_repo_root_if_active_rejects_suspended_account() {
        let db = test_pool().await;
        let cid = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";
        insert_account_with_repo(&db, "did:plc:cas_susp", cid).await;
        set_lifecycle_column(&db, "did:plc:cas_susp", "suspended_at").await;

        let swapped =
            advance_repo_root_if_active(&db, "did:plc:cas_susp", "new-root", "rev-1", cid)
                .await
                .unwrap();
        assert!(
            !swapped,
            "the commit CAS must not advance the root for a suspended account"
        );
    }

    #[tokio::test]
    async fn advance_repo_root_if_active_rejects_takendown_account() {
        let db = test_pool().await;
        let cid = "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uwrf3e2o6cw3djmprrm";
        insert_account_with_repo(&db, "did:plc:cas_td", cid).await;
        set_lifecycle_column(&db, "did:plc:cas_td", "taken_down_at").await;

        let swapped = advance_repo_root_if_active(&db, "did:plc:cas_td", "new-root", "rev-1", cid)
            .await
            .unwrap();
        assert!(
            !swapped,
            "the commit CAS must not advance the root for a taken-down account"
        );
    }

    // ── login/session lifecycle enforcement ────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_identifier_by_did_excludes_suspended_account() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:ri_susp").await;
        set_lifecycle_column(&db, "did:plc:ri_susp", "suspended_at").await;

        assert!(resolve_identifier(&db, "did:plc:ri_susp")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn resolve_identifier_by_did_excludes_takendown_account() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:ri_td").await;
        set_lifecycle_column(&db, "did:plc:ri_td", "taken_down_at").await;

        assert!(resolve_identifier(&db, "did:plc:ri_td")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn get_session_account_excludes_takendown_account() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:gsa_td").await;
        set_lifecycle_column(&db, "did:plc:gsa_td", "taken_down_at").await;

        assert!(get_session_account(&db, "did:plc:gsa_td")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn account_lifecycle_reports_suspended_takendown_and_missing() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:aia_susp").await;
        set_lifecycle_column(&db, "did:plc:aia_susp", "suspended_at").await;
        assert_eq!(
            account_lifecycle(&db, "did:plc:aia_susp").await.unwrap(),
            Some(AccountLifecycle::Suspended)
        );

        insert_account(&db, "did:plc:aia_td").await;
        set_lifecycle_column(&db, "did:plc:aia_td", "taken_down_at").await;
        assert_eq!(
            account_lifecycle(&db, "did:plc:aia_td").await.unwrap(),
            Some(AccountLifecycle::TakenDown)
        );

        assert_eq!(
            account_lifecycle(&db, "did:plc:aia_ghost").await.unwrap(),
            None,
            "a DID with no account row must report None"
        );
    }

    // ── set_account_takedown ───────────────────────────────────────────────────────────────────

    /// Run [`set_account_takedown`] in its own committed transaction (see [`deactivate`]).
    async fn set_takedown(db: &sqlx::SqlitePool, did: &str, applied: bool) -> TakedownStateChange {
        let mut tx = db.begin().await.unwrap();
        let result = set_account_takedown(&mut tx, did, applied).await.unwrap();
        tx.commit().await.unwrap();
        result
    }

    #[tokio::test]
    async fn set_account_takedown_applies_to_active_account() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:td_a").await;

        let result = set_takedown(&db, "did:plc:td_a", true).await;
        assert!(matches!(
            result,
            TakedownStateChange::Changed(AccountLifecycle::TakenDown)
        ));

        let taken_down_at: Option<String> =
            sqlx::query_scalar("SELECT taken_down_at FROM accounts WHERE did = ?")
                .bind("did:plc:td_a")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(taken_down_at.is_some());
    }

    #[tokio::test]
    async fn set_account_takedown_reapplying_is_unchanged() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:td_b").await;
        set_takedown(&db, "did:plc:td_b", true).await;

        let result = set_takedown(&db, "did:plc:td_b", true).await;
        assert!(matches!(
            result,
            TakedownStateChange::Unchanged(AccountLifecycle::TakenDown)
        ));
    }

    #[tokio::test]
    async fn set_account_takedown_clears_and_returns_active() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:td_c").await;
        set_takedown(&db, "did:plc:td_c", true).await;

        let result = set_takedown(&db, "did:plc:td_c", false).await;
        assert!(matches!(
            result,
            TakedownStateChange::Changed(AccountLifecycle::Active)
        ));

        let taken_down_at: Option<String> =
            sqlx::query_scalar("SELECT taken_down_at FROM accounts WHERE did = ?")
                .bind("did:plc:td_c")
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(taken_down_at.is_none());
    }

    #[tokio::test]
    async fn set_account_takedown_clearing_reveals_underlying_suspension() {
        // Clearing a takedown must not report Active if the account is still suspended — the
        // caller's #account event has to reflect the true resulting lifecycle, not just this
        // call's own dimension.
        let db = test_pool().await;
        insert_account(&db, "did:plc:td_d").await;
        set_lifecycle_column(&db, "did:plc:td_d", "suspended_at").await;
        set_takedown(&db, "did:plc:td_d", true).await;

        let result = set_takedown(&db, "did:plc:td_d", false).await;
        assert!(matches!(
            result,
            TakedownStateChange::Changed(AccountLifecycle::Suspended)
        ));
    }

    #[tokio::test]
    async fn set_account_takedown_clearing_when_not_applied_is_unchanged() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:td_e").await;

        let result = set_takedown(&db, "did:plc:td_e", false).await;
        assert!(matches!(
            result,
            TakedownStateChange::Unchanged(AccountLifecycle::Active)
        ));
    }

    #[tokio::test]
    async fn set_account_takedown_missing_did_returns_not_found() {
        let db = test_pool().await;

        let result = set_takedown(&db, "did:plc:td_ghost", true).await;
        assert!(matches!(result, TakedownStateChange::NotFound));
    }

    async fn list_admin(
        db: &sqlx::SqlitePool,
        status: Option<AccountLifecycle>,
        q: Option<&str>,
    ) -> Vec<AdminAccountRow> {
        list_accounts_admin(db, "", 100, status, q).await.unwrap()
    }

    #[tokio::test]
    async fn list_accounts_admin_status_filters_respect_precedence() {
        // An account that is both suspended and taken down derives TakenDown, so it must match
        // only the takendown filter — the suspended filter has to exclude it.
        let db = test_pool().await;
        insert_account(&db, "did:plc:laa_active").await;
        insert_account(&db, "did:plc:laa_suspended").await;
        set_lifecycle_column(&db, "did:plc:laa_suspended", "suspended_at").await;
        insert_account(&db, "did:plc:laa_both").await;
        set_lifecycle_column(&db, "did:plc:laa_both", "suspended_at").await;
        set_lifecycle_column(&db, "did:plc:laa_both", "taken_down_at").await;

        let dids = |rows: Vec<AdminAccountRow>| rows.into_iter().map(|r| r.did).collect::<Vec<_>>();

        assert_eq!(
            dids(list_admin(&db, Some(AccountLifecycle::Active), None).await),
            vec!["did:plc:laa_active"]
        );
        assert_eq!(
            dids(list_admin(&db, Some(AccountLifecycle::Suspended), None).await),
            vec!["did:plc:laa_suspended"]
        );
        assert_eq!(
            dids(list_admin(&db, Some(AccountLifecycle::TakenDown), None).await),
            vec!["did:plc:laa_both"]
        );
        assert!(list_admin(&db, Some(AccountLifecycle::Deactivated), None)
            .await
            .is_empty());
        // Unfiltered, all three appear (DID order: active < both < suspended) with their
        // derived lifecycles.
        let all = list_admin(&db, None, None).await;
        assert_eq!(all.len(), 3);
        assert_eq!(all[1].did, "did:plc:laa_both");
        assert_eq!(all[1].lifecycle, AccountLifecycle::TakenDown);
    }

    #[tokio::test]
    async fn list_accounts_admin_search_matches_did_and_handle_literally() {
        let db = test_pool().await;
        insert_account(&db, "did:plc:laa_q_alpha").await;
        insert_account(&db, "did:plc:laa_q_beta").await;
        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind("beta.example.com")
            .bind("did:plc:laa_q_beta")
            .execute(&db)
            .await
            .unwrap();

        // Matches by DID substring.
        let rows = list_admin(&db, None, Some("q_alpha")).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].did, "did:plc:laa_q_alpha");
        assert_eq!(rows[0].handle, None);

        // Matches by handle substring, and the handle is surfaced on the row.
        let rows = list_admin(&db, None, Some("beta.example")).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].did, "did:plc:laa_q_beta");
        assert_eq!(rows[0].handle.as_deref(), Some("beta.example.com"));

        // LIKE metacharacters in the term match literally, not as wildcards: "%alpha" would
        // match everything ending in "alpha" if unescaped, but no DID/handle contains a '%'.
        assert!(list_admin(&db, None, Some("%alpha")).await.is_empty());
        assert!(list_admin(&db, None, Some("q_al_ha")).await.is_empty());
    }

    #[tokio::test]
    async fn list_accounts_admin_paginates_and_reports_blob_bytes() {
        let db = test_pool().await;
        for did in ["did:plc:laa_pg_a", "did:plc:laa_pg_b", "did:plc:laa_pg_c"] {
            insert_account(&db, did).await;
        }
        crate::db::blobs::insert_blob(
            &db,
            "baflaapgblob",
            "did:plc:laa_pg_b",
            "image/jpeg",
            640,
            "blobs/xx/baflaapgblob",
            "2030-01-01 00:00:00",
        )
        .await
        .unwrap();

        let page1 = list_accounts_admin(&db, "", 2, None, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].did, "did:plc:laa_pg_a");
        assert_eq!(page1[0].blob_bytes, 0);
        assert_eq!(page1[1].did, "did:plc:laa_pg_b");
        assert_eq!(page1[1].blob_bytes, 640);

        let page2 = list_accounts_admin(&db, &page1[1].did, 2, None, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].did, "did:plc:laa_pg_c");
    }
}
