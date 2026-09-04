// pattern: Imperative Shell
//
// Query layer for the wallet-confirmed OAuth consent primitive (V056). Owns the SQL for the
// `pending_oauth_authorizations` single-use request rows and the append-only
// `oauth_consent_audit_events` trail. No transactions are opened here — the executor-generic
// functions compose into the route handlers' transactions (route-owned atomicity, per the crate's
// hard rules). Terminal transitions are guarded single-statement UPDATEs whose `rows_affected`
// reports whether this caller won the race, so the request is single-use even under concurrency.

use common::{ApiError, ApiResultExt, ErrorCode};
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
    /// The short number-match code (V060). `Some` iff a `login-approval` push was dispatched for
    /// this request, in which case an approval must present it (the anti-MFA-fatigue proof that
    /// the approver can see the login surface).
    pub match_code: Option<String>,
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
    /// `query` | `fragment` — how the completion redirect delivers its parameters (V059).
    pub response_mode: &'a str,
    pub requested_scope: &'a str,
    pub login_hint: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    /// The DPoP key thumbprint bound at PAR time (V062), carried into the authorization
    /// code this request eventually yields. `None` when the flow proved no key.
    pub dpop_jkt: Option<&'a str>,
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
    /// `query` | `fragment` — the completion redirect answers in this mode (V059).
    pub response_mode: String,
    pub granted_scope: String,
    pub account_did: String,
    /// The DPoP key bound at PAR time (V062), stamped onto the issued authorization code.
    pub dpop_jkt: Option<String>,
}

const SELECT_COLUMNS: &str = "request_id, client_id, client_name, redirect_uri, requested_scope, \
     login_hint, origin, ip, status, datetime(expires_at) <= datetime('now') AS is_expired, \
     match_code";

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
        match_code: row.get("match_code"),
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
          code_challenge_method, state, response_type, response_mode, requested_scope, \
          login_hint, origin, ip, user_agent, dpop_jkt, status, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'), \
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
    .bind(new.response_mode)
    .bind(new.requested_scope)
    .bind(new.login_hint)
    .bind(new.origin)
    .bind(new.ip)
    .bind(new.user_agent)
    .bind(new.dpop_jkt)
    // A signed modifier string ("+300 seconds" / "-10 seconds"); `{:+}` keeps a negative TTL valid
    // (a plain "+{ttl}" would render "+-10 seconds", which SQLite rejects → NULL expiry).
    .bind(format!("{:+} seconds", new.ttl_secs))
    .execute(executor)
    .await
    .or_internal_as(
        "DB error inserting pending OAuth authorization",
        "failed to create authorization request",
    )?;
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
    .or_internal_as(
        "DB error cleaning up expired pending OAuth authorizations",
        "failed to clean up authorization requests",
    )?;
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
    .or_internal_as(
        "DB error fetching pending OAuth authorization by request_id",
        "failed to look up authorization request",
    )?;
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
    .or_internal_as(
        "DB error fetching pending OAuth authorization by user_code",
        "failed to look up authorization request",
    )?;
    Ok(row.as_ref().map(map_row))
}

/// Record that a `login-approval` push was dispatched for this request, binding the number-match
/// code an approval must now present (V060). Guarded on the row still being pending and never
/// having dispatched before, so the code is written exactly once and a late dispatch can never
/// retrofit a requirement onto a resolved request. Returns whether this call set it.
pub async fn set_push_dispatched<'e, E>(
    executor: E,
    request_id: &str,
    match_code: &str,
) -> Result<bool, ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE pending_oauth_authorizations \
         SET match_code = ?, push_dispatched_at = datetime('now') \
         WHERE request_id = ? AND status = 'pending' AND match_code IS NULL",
    )
    .bind(match_code)
    .bind(request_id)
    .execute(executor)
    .await
    .or_internal_as(
        "DB error recording push dispatch for pending OAuth authorization",
        "failed to record push dispatch",
    )?;
    Ok(result.rows_affected() == 1)
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
    .or_internal_as(
        "DB error approving pending OAuth authorization",
        "failed to approve authorization request",
    )?;
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
    .or_internal_as(
        "DB error denying pending OAuth authorization",
        "failed to deny authorization request",
    )?;
    Ok(result.rows_affected() == 1)
}

/// Guarded single-use `approved → completed` transition, returning the authorization context for
/// code issuance in the same statement (`RETURNING`) so the browser can mint at most one code.
/// Deliberately carries no `expires_at` predicate: approval is the meaningful gate, and the issued
/// authorization code carries its own short expiry (matching the transfers-completion precedent).
///
/// Executor-generic so the caller can run this transition, the authorization-code insert, and the
/// completion audit in one transaction — a failed code insert then rolls the transition back,
/// leaving the request retryable rather than stranded as `completed` with no code.
pub async fn complete_pending_authorization<'e, E>(
    executor: E,
    request_id: &str,
) -> Result<Option<CompletedAuthorization>, ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let row = sqlx::query(
        "UPDATE pending_oauth_authorizations SET status = 'completed' \
         WHERE request_id = ? AND status = 'approved' \
         RETURNING client_id, redirect_uri, code_challenge, code_challenge_method, state, \
                   response_mode, granted_scope, account_did, dpop_jkt",
    )
    .bind(request_id)
    .fetch_optional(executor)
    .await
    .or_internal_as(
        "DB error completing pending OAuth authorization",
        "failed to complete authorization request",
    )?;
    use sqlx::Row;
    Ok(row.map(|r| CompletedAuthorization {
        client_id: r.get("client_id"),
        redirect_uri: r.get("redirect_uri"),
        code_challenge: r.get("code_challenge"),
        code_challenge_method: r.get("code_challenge_method"),
        state: r.get("state"),
        response_mode: r.get("response_mode"),
        dpop_jkt: r.get("dpop_jkt"),
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
    /// A `login-approval` push was sealed and enqueued toward the hinted account's devices,
    /// making number matching mandatory for this request (V060).
    PushDispatched,
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
            OAuthConsentAuditEventType::PushDispatched => "push_dispatched",
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
            error = %e, "DB error inserting OAuth consent audit event");
        ApiError::new(ErrorCode::InternalError, "failed to record audit event")
    })?;
    Ok(())
}
