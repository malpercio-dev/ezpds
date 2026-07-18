// pattern: Imperative Shell
//
// Query layer for the wallet-confirmed OAuth consent primitive (V056). Owns the SQL for the
// `pending_oauth_authorizations` single-use request rows and the append-only
// `oauth_consent_audit_events` trail. No transactions are opened here — the executor-generic
// functions compose into the route handlers' transactions (route-owned atomicity, per the crate's
// hard rules). Terminal transitions are guarded single-statement UPDATEs whose `rows_affected`
// reports whether this caller won the race, so the request is single-use even under concurrency.

use common::{ApiError, ErrorCode};
use sqlx::Sqlite;

/// A pending consent request as read back for the status poll, wallet preview, and approval
/// reconstruction. Carries only the fields the read paths need — the completion path reads its own
/// [`CompletedAuthorization`] via the guarded `RETURNING`. `is_expired` is derived in SQL from
/// `expires_at`, not stored, so a lapsed `pending` row reads as expired immediately without a
/// background sweep.
#[derive(Debug, Clone)]
pub struct PendingOAuthAuthorization {
    pub request_id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uri: String,
    pub requested_scope: String,
    pub login_hint: Option<String>,
    pub origin: Option<String>,
    pub ip: Option<String>,
    pub status: String,
    pub is_expired: bool,
}

/// The fields a newly created pending request carries. Client metadata is snapshotted at creation
/// so the wallet preview and later completion do not re-resolve the client document.
#[derive(Debug, Clone)]
pub struct NewPendingOAuthAuthorization<'a> {
    pub request_id: &'a str,
    pub user_code: &'a str,
    pub client_id: &'a str,
    pub client_name: Option<&'a str>,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub state: &'a str,
    pub response_type: &'a str,
    pub requested_scope: &'a str,
    pub login_hint: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    /// Time-to-live in seconds (~300 for the 5-minute window).
    pub ttl_secs: i64,
}

/// The authorization context a completed request hands back for code issuance — returned atomically
/// by the guarded `approved → completed` transition so the browser can never mint two codes.
#[derive(Debug, Clone)]
pub struct CompletedAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub granted_scope: String,
    pub account_did: String,
}

const SELECT_COLUMNS: &str = "request_id, client_id, client_name, redirect_uri, requested_scope, \
     login_hint, origin, ip, status, datetime(expires_at) <= datetime('now') AS is_expired";

fn map_row(row: &sqlx::sqlite::SqliteRow) -> PendingOAuthAuthorization {
    use sqlx::Row;
    PendingOAuthAuthorization {
        request_id: row.get("request_id"),
        client_id: row.get("client_id"),
        client_name: row.get("client_name"),
        redirect_uri: row.get("redirect_uri"),
        requested_scope: row.get("requested_scope"),
        login_hint: row.get("login_hint"),
        origin: row.get("origin"),
        ip: row.get("ip"),
        status: row.get("status"),
        is_expired: row.get::<i64, _>("is_expired") != 0,
    }
}

/// Insert a fresh pending request. `expires_at` is computed as `now + ttl_secs`.
pub async fn insert_pending_authorization<'e, E>(
    executor: E,
    new: &NewPendingOAuthAuthorization<'_>,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO pending_oauth_authorizations \
         (request_id, user_code, client_id, client_name, redirect_uri, code_challenge, \
          code_challenge_method, state, response_type, requested_scope, login_hint, origin, ip, \
          user_agent, status, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'), \
                 datetime('now', ?))",
    )
    .bind(new.request_id)
    .bind(new.user_code)
    .bind(new.client_id)
    .bind(new.client_name)
    .bind(new.redirect_uri)
    .bind(new.code_challenge)
    .bind(new.code_challenge_method)
    .bind(new.state)
    .bind(new.response_type)
    .bind(new.requested_scope)
    .bind(new.login_hint)
    .bind(new.origin)
    .bind(new.ip)
    .bind(new.user_agent)
    // A signed modifier string ("+300 seconds" / "-10 seconds"); `{:+}` keeps a negative TTL valid
    // (a plain "+{ttl}" would render "+-10 seconds", which SQLite rejects → NULL expiry).
    .bind(format!("{:+} seconds", new.ttl_secs))
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error inserting pending OAuth authorization");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to create authorization request",
        )
    })?;
    Ok(())
}

/// Reclaim rows whose expiry lapsed more than `grace_secs` ago. Called opportunistically on each
/// creation (the `oauth_par_requests` / `transfers` precedent) instead of a background sweep; the
/// grace keeps a just-expired row around long enough for the poll to report `expired`.
pub async fn cleanup_expired_pending_authorizations<'e, E>(
    executor: E,
    grace_secs: i64,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "DELETE FROM pending_oauth_authorizations \
         WHERE datetime(expires_at) <= datetime('now', ? || ' seconds')",
    )
    .bind(format!("-{grace_secs}"))
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error cleaning up expired pending OAuth authorizations");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to clean up authorization requests",
        )
    })?;
    Ok(())
}

/// Look up a pending request by its high-entropy `request_id` (status poll, approval, completion).
pub async fn get_pending_by_request_id(
    pool: &sqlx::SqlitePool,
    request_id: &str,
) -> Result<Option<PendingOAuthAuthorization>, ApiError> {
    let row = sqlx::query(&format!(
        "SELECT {SELECT_COLUMNS} FROM pending_oauth_authorizations WHERE request_id = ?"
    ))
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error fetching pending OAuth authorization by request_id");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to look up authorization request",
        )
    })?;
    Ok(row.as_ref().map(map_row))
}

/// Look up a pending request by its human-typeable `user_code` (wallet preview / arrive-by-code).
pub async fn get_pending_by_user_code(
    pool: &sqlx::SqlitePool,
    user_code: &str,
) -> Result<Option<PendingOAuthAuthorization>, ApiError> {
    let row = sqlx::query(&format!(
        "SELECT {SELECT_COLUMNS} FROM pending_oauth_authorizations WHERE user_code = ?"
    ))
    .bind(user_code)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error fetching pending OAuth authorization by user_code");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to look up authorization request",
        )
    })?;
    Ok(row.as_ref().map(map_row))
}

/// Guarded single-use `pending → approved` transition, binding the approving account DID and the
/// granted scope set. Returns `true` only if this call won the transition (row still `pending` and
/// unexpired), so a replayed approval envelope affects zero rows.
pub async fn approve_pending_authorization<'e, E>(
    executor: E,
    request_id: &str,
    account_did: &str,
    granted_scope: &str,
) -> Result<bool, ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE pending_oauth_authorizations \
         SET status = 'approved', account_did = ?, granted_scope = ? \
         WHERE request_id = ? AND status = 'pending' \
           AND datetime(expires_at) > datetime('now')",
    )
    .bind(account_did)
    .bind(granted_scope)
    .bind(request_id)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error approving pending OAuth authorization");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to approve authorization request",
        )
    })?;
    Ok(result.rows_affected() == 1)
}

/// Guarded single-use `pending → denied` transition. Returns `true` only if this call terminated a
/// still-pending, unexpired request.
pub async fn deny_pending_authorization<'e, E>(
    executor: E,
    request_id: &str,
    account_did: &str,
) -> Result<bool, ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE pending_oauth_authorizations \
         SET status = 'denied', account_did = ? \
         WHERE request_id = ? AND status = 'pending' \
           AND datetime(expires_at) > datetime('now')",
    )
    .bind(account_did)
    .bind(request_id)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error denying pending OAuth authorization");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to deny authorization request",
        )
    })?;
    Ok(result.rows_affected() == 1)
}

/// Guarded single-use `approved → completed` transition, returning the authorization context for
/// code issuance in the same statement (`RETURNING`) so the browser can mint at most one code.
/// Deliberately carries no `expires_at` predicate: approval is the meaningful gate, and the issued
/// authorization code carries its own short expiry (matching the transfers-completion precedent).
pub async fn complete_pending_authorization(
    pool: &sqlx::SqlitePool,
    request_id: &str,
) -> Result<Option<CompletedAuthorization>, ApiError> {
    let row = sqlx::query(
        "UPDATE pending_oauth_authorizations SET status = 'completed' \
         WHERE request_id = ? AND status = 'approved' \
         RETURNING client_id, redirect_uri, code_challenge, code_challenge_method, state, \
                   granted_scope, account_did",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "DB error completing pending OAuth authorization");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to complete authorization request",
        )
    })?;
    use sqlx::Row;
    Ok(row.map(|r| CompletedAuthorization {
        client_id: r.get("client_id"),
        redirect_uri: r.get("redirect_uri"),
        code_challenge: r.get("code_challenge"),
        code_challenge_method: r.get("code_challenge_method"),
        state: r.get("state"),
        // NOT NULL in practice: only an approved row is selected, and approval always sets it.
        granted_scope: r.try_get("granted_scope").unwrap_or_default(),
        account_did: r.try_get("account_did").unwrap_or_default(),
    }))
}

/// The consent-ceremony audit vocabulary (append-only, V056). `detail` carries mechanical facts
/// only — never signatures, user codes, or token material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthConsentAuditEventType {
    /// The consent page created a pending request (wallet path rendered).
    RequestCreated,
    /// The wallet approved the request with a valid device-key signature.
    Approved,
    /// The wallet denied the request.
    Denied,
    /// The browser exchanged an approved request for an authorization code.
    Completed,
}

impl OAuthConsentAuditEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            OAuthConsentAuditEventType::RequestCreated => "request_created",
            OAuthConsentAuditEventType::Approved => "approved",
            OAuthConsentAuditEventType::Denied => "denied",
            OAuthConsentAuditEventType::Completed => "completed",
        }
    }
}

/// Append one consent audit event. Generic over the executor so a terminal-transition write and its
/// audit row share one transaction.
pub async fn insert_oauth_consent_audit_event<'e, E>(
    executor: E,
    id: &str,
    request_id: &str,
    account_did: Option<&str>,
    client_id: &str,
    event_type: OAuthConsentAuditEventType,
    detail: Option<&str>,
) -> Result<(), ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO oauth_consent_audit_events \
         (id, request_id, account_did, client_id, event_type, detail, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
    )
    .bind(id)
    .bind(request_id)
    .bind(account_did)
    .bind(client_id)
    .bind(event_type.as_str())
    .bind(detail)
    .execute(executor)
    .await
    .map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            event_type = %event_type.as_str(),
            error = %e,
            "DB error inserting OAuth consent audit event"
        );
        ApiError::new(ErrorCode::InternalError, "failed to record audit event")
    })?;
    Ok(())
}
