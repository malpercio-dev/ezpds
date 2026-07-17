// pattern: Imperative Shell
//
// The escrow-assisted recovery *release gate* — the server half of recovery ceremony A
// (`docs/design-plans/2026-07-17-key-recovery-from-shares.md` §4):
//
//   POST /v1/recovery/initiate       — public; handle/DID → email an OTP. Always 200 (no oracle).
//   POST /v1/recovery/release        — OTP opens a cancellable release; polling collects the share.
//   POST /v1/recovery/release/cancel — any account session/device kills a pending release.
//
// Threat framing: releasing the PDS-held Share 2 converts an "iCloud + mailbox compromise" into
// an identity takeover, so every knob errs toward friction. The two backstops are the cancellable
// delay window enforced here and the device key's 72-hour rotation-priority supremacy at
// plc.directory (ordering `[device, recovery, PDS]`). One share is information-theoretically
// worthless without a second, which is why polling can be identified by the account handle once
// the release has been opened with a valid OTP.
//
// Uniform failure (no oracles): a wrong/expired/replayed OTP, an unknown handle at `release`, and
// an escrow-deleted account (owner opt-out) all return the same 401 — an attacker learns nothing
// about which accounts exist or hold escrow. `initiate` is always-200 (the `requestPasswordReset`
// posture). initiate + release share one per-IP rate limiter instance (`rate_limit.rs` family 2)
// so alternating them can't double the OTP-guess budget.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::guards::{authenticate_account_owner, OwnerAuthError};
use crate::auth::token::{generate_token, hash_bearer_token};
use crate::db::accounts::{account_email, resolve_identifier};
use crate::db::recovery_audit::{insert_recovery_audit_event, RecoveryAuditEventType};
use crate::db::recovery_escrow::{clear_release, get_release_state, open_release};
use crate::db::recovery_otps::{consume_recovery_otp, insert_recovery_otp};
use common::{ApiError, ErrorCode};

/// The single uniform failure for the release flow: wrong/expired/replayed OTP, unknown handle,
/// and escrow-deleted account all surface identically so nothing about account or escrow presence
/// leaks. 401, matching the `deleteAccount` credential-failure posture.
fn uniform_release_failure() -> ApiError {
    ApiError::new(
        ErrorCode::Unauthorized,
        "recovery release could not be authorized",
    )
}

// ── POST /v1/recovery/initiate ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct InitiateRequest {
    /// The account handle or DID to recover.
    pub identifier: String,
}

/// POST /v1/recovery/initiate
///
/// Public: emails a single-use, 1-hour OTP to the account address so the holder can open an escrow
/// release. Always returns 200 regardless of whether the identifier resolves or the account holds
/// escrow — the `requestPasswordReset` no-enumeration posture. A resolvable account with no escrow
/// still receives an OTP (opening a release against it fails uniformly at `release`), so `initiate`
/// is not an escrow-presence oracle either.
pub async fn recovery_initiate(
    State(state): State<AppState>,
    Json(payload): Json<InitiateRequest>,
) -> StatusCode {
    // Generate an OTP unconditionally so the work (and rough timing) is the same whether or not the
    // identifier resolves — the same equalization `requestPasswordReset` uses.
    let token = generate_token();

    let account = match resolve_identifier(&state.db, &payload.identifier).await {
        Ok(Some(account)) => account,
        Ok(None) => return StatusCode::OK,
        Err(e) => {
            tracing::error!(error = %e, "DB error resolving recovery identifier; returning 200");
            return StatusCode::OK;
        }
    };

    let email = match account_email(&state.db, &account.did).await {
        Ok(Some(email)) => email,
        // No stored email (or a lookup error): nowhere to deliver, but still 200 (no oracle).
        Ok(None) => return StatusCode::OK,
        Err(e) => {
            tracing::error!(error = %e, "DB error reading recovery account email; returning 200");
            return StatusCode::OK;
        }
    };

    if let Err(e) = insert_recovery_otp(&state.db, &account.did, &token.hash).await {
        tracing::error!(did = %account.did, error = %e, "failed to store recovery OTP; returning 200");
        return StatusCode::OK;
    }

    let host = state.config.public_host();
    let message = crate::email::EmailMessage {
        to: email,
        subject: format!("Recover your {host} identity"),
        body: format!(
            "A recovery-share release was requested for your {host} account.\n\n\
             Recovery code: {code}\n\n\
             Enter this code in your app to begin releasing your escrowed recovery share. \
             It expires in 1 hour.\n\n\
             If you didn't request this, you can safely ignore this email — no release begins \
             until this code is used.",
            code = token.plaintext,
        ),
    };
    if let Err(e) = state.email.send(message).await {
        tracing::error!(did = %account.did, error = %e, "failed to send recovery OTP email");
    }

    StatusCode::OK
}

// ── POST /v1/recovery/release ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ReleaseRequest {
    /// The account handle or DID being recovered.
    pub identifier: String,
    /// The emailed OTP. Present to **open** a release; absent to **poll** an already-opened one.
    #[serde(default)]
    pub otp: Option<String>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseResponse {
    /// `"pending"` while the delay window is open, `"released"` once the share is handed back.
    status: &'static str,
    /// When the pending release becomes collectable (present only while `pending`).
    #[serde(skip_serializing_if = "Option::is_none")]
    available_at: Option<String>,
    /// The base32 v2 Share 2 envelope (present only on `released`).
    #[serde(skip_serializing_if = "Option::is_none")]
    share: Option<String>,
}

/// POST /v1/recovery/release
///
/// Two modes on one endpoint, matching the design's single-track state machine:
///
/// * **open** (`otp` present) — consume the OTP, then start the cancellable delay window
///   (`release_pending_until = now + [recovery] release_delay_secs`). Audits `release_requested`
///   and notifies the account email. A zero delay collapses this to a single call that returns the
///   share directly (also auditing `released` + notifying).
/// * **poll** (`otp` absent) — an already-opened release is identified by handle: return `pending`
///   with `availableAt` until the window elapses, then the Share 2 envelope once (auditing
///   `released` + notifying), clearing the in-flight state.
pub async fn recovery_release(
    State(state): State<AppState>,
    Json(payload): Json<ReleaseRequest>,
) -> Result<Json<ReleaseResponse>, ApiError> {
    // The master key is required to unwrap the escrow ciphertext. Check it up front so a
    // misconfigured server never consumes an OTP or opens a release it could not fulfil. 503 is a
    // server-wide fact, not an account oracle.
    let master_key = require_master_key(&state)?;

    // Resolve the identifier to a DID. An unknown handle is the uniform failure — no existence
    // oracle. (Handles are public, so no dummy-work equalization is warranted here.)
    let did = match resolve_identifier(&state.db, &payload.identifier).await? {
        Some(account) => account.did,
        None => return Err(uniform_release_failure()),
    };

    match payload.otp.as_deref() {
        Some(otp) => open_release_flow(&state, &did, otp, &master_key).await,
        None => poll_release_flow(&state, &did, &master_key).await,
    }
}

/// The **open** path: validate + consume the OTP, confirm escrow exists, start the delay window,
/// and (with a zero delay) hand the share back immediately.
async fn open_release_flow(
    state: &AppState,
    did: &str,
    otp: &str,
    master_key: &[u8; 32],
) -> Result<Json<ReleaseResponse>, ApiError> {
    // Hash the presented OTP and consume it atomically, bound to this DID. Anything but a live,
    // unspent, matching OTP is the uniform failure — wrong, expired, and replayed all land here.
    let token_hash = hash_bearer_token(otp).map_err(|_| uniform_release_failure())?;
    let consumed = consume_recovery_otp(&state.db, did, &token_hash).await?;
    if !consumed {
        return Err(uniform_release_failure());
    }

    // An escrow-deleted account (owner opt-out) has no row: the same uniform failure, so escrow
    // presence is never an oracle even to a caller who proved email control.
    let state_row = get_release_state(&state.db, did)
        .await
        .map_err(map_db_err)?
        .ok_or_else(uniform_release_failure)?;

    let delay_secs = state.config.recovery.release_delay_secs;

    // Open (or reset) the release and audit the request, atomically.
    let map_err = map_db_err;
    let mut tx = state.db.begin().await.map_err(map_err)?;
    open_release(&mut *tx, did, delay_secs)
        .await
        .map_err(map_err)?;
    let detail = serde_json::json!({ "delay_secs": delay_secs });
    insert_recovery_audit_event(
        &mut *tx,
        &Uuid::new_v4().to_string(),
        did,
        RecoveryAuditEventType::ReleaseRequested,
        Some(&detail.to_string()),
    )
    .await?;
    tx.commit().await.map_err(map_err)?;

    notify(state, did, RELEASE_REQUESTED_NOTICE).await;

    if delay_secs == 0 {
        // Immediate release: the window is already elapsed. Deliver the share now.
        deliver_share(state, did, &state_row.share_encrypted, master_key).await
    } else {
        // Re-read to return the freshly stamped `release_pending_until` as `availableAt`.
        let opened = get_release_state(&state.db, did)
            .await
            .map_err(map_db_err)?
            .ok_or_else(uniform_release_failure)?;
        Ok(Json(ReleaseResponse {
            status: "pending",
            available_at: opened.release_pending_until,
            share: None,
        }))
    }
}

/// The **poll** path: an already-opened release, identified by handle. Return `pending` until the
/// window elapses, then the share once.
async fn poll_release_flow(
    state: &AppState,
    did: &str,
    master_key: &[u8; 32],
) -> Result<Json<ReleaseResponse>, ApiError> {
    // No in-flight release (never opened, cancelled, or already collected) is the uniform failure —
    // the client must re-`initiate`. Same 401 as an escrow-less account, so no oracle.
    let state_row = get_release_state(&state.db, did)
        .await
        .map_err(map_db_err)?
        .ok_or_else(uniform_release_failure)?;
    if !state_row.release_in_flight {
        return Err(uniform_release_failure());
    }

    if state_row.available {
        deliver_share(state, did, &state_row.share_encrypted, master_key).await
    } else {
        Ok(Json(ReleaseResponse {
            status: "pending",
            available_at: state_row.release_pending_until,
            share: None,
        }))
    }
}

/// Hand back the Share 2 envelope and close the release: unwrap the ciphertext, then atomically
/// clear the in-flight state and audit `released`. The clear is guarded on a still-in-flight
/// release, so concurrent collectors (single-connection pool serializes them) can't double-deliver
/// or double-audit — the loser sees the uniform failure and re-`initiate`s.
async fn deliver_share(
    state: &AppState,
    did: &str,
    share_encrypted: &str,
    master_key: &[u8; 32],
) -> Result<Json<ReleaseResponse>, ApiError> {
    // Unwrap first so a decrypt failure (500) leaves the release intact and retryable, rather than
    // clearing a release we then can't fulfil.
    let unwrapped = crypto::decrypt_secret_bytes(share_encrypted, master_key).map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to unwrap escrow share for release");
        ApiError::new(ErrorCode::InternalError, "failed to release escrow share")
    })?;
    let envelope = crypto::ShareEnvelope::from_bytes(&unwrapped).map_err(|e| {
        tracing::error!(did = %did, error = %e, "stored escrow envelope is malformed");
        ApiError::new(ErrorCode::InternalError, "failed to release escrow share")
    })?;
    let share = envelope.encode_share().to_string();

    let mut tx = state.db.begin().await.map_err(map_db_err)?;
    let cleared = clear_release(&mut *tx, did).await.map_err(map_db_err)?;
    if !cleared {
        // Raced: another request already collected and cleared it. Uniform failure — re-initiate.
        return Err(uniform_release_failure());
    }
    insert_recovery_audit_event(
        &mut *tx,
        &Uuid::new_v4().to_string(),
        did,
        RecoveryAuditEventType::Released,
        None,
    )
    .await?;
    tx.commit().await.map_err(map_db_err)?;

    notify(state, did, RELEASED_NOTICE).await;

    Ok(Json(ReleaseResponse {
        status: "released",
        available_at: None,
        share: Some(share),
    }))
}

// ── POST /v1/recovery/release/cancel ───────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct CancelResponse {
    /// Always `"cancelled"` — the terminal state holds whether or not a release was in flight.
    status: &'static str,
}

/// POST /v1/recovery/release/cancel
///
/// Kill a pending release. Authenticated as the account owner (wallet session token or full-access
/// OAuth/XRPC token) — the DID comes from the credential, so a cancel can only ever touch the
/// caller's own in-flight release. Composes with `POST /v1/admin/accounts/{id}/revoke-credentials`
/// for a compromised-mailbox response: revoke the attacker's sessions, then cancel. Idempotent: a
/// cancel with nothing pending is a 200 no-op with no `release_cancelled` audit event.
pub async fn recovery_release_cancel(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<CancelResponse>, ApiError> {
    let did = authenticate_account_owner(&headers, &method, &uri, &state)
        .await
        .map_err(|err| match err {
            OwnerAuthError::Unauthenticated(e) => e,
            OwnerAuthError::AgentDerived => ApiError::new(
                ErrorCode::InsufficientScope,
                "this operation is not available to agent-derived credentials",
            ),
            OwnerAuthError::NotFullAccess => ApiError::new(
                ErrorCode::InvalidToken,
                "a session or full-access token is required",
            ),
        })?;

    let mut tx = state.db.begin().await.map_err(map_db_err)?;
    let cancelled = clear_release(&mut *tx, &did).await.map_err(map_db_err)?;
    if cancelled {
        insert_recovery_audit_event(
            &mut *tx,
            &Uuid::new_v4().to_string(),
            &did,
            RecoveryAuditEventType::ReleaseCancelled,
            None,
        )
        .await?;
    }
    tx.commit().await.map_err(map_db_err)?;

    Ok(Json(CancelResponse {
        status: "cancelled",
    }))
}

// ── shared helpers ─────────────────────────────────────────────────────────────

const RELEASE_REQUESTED_NOTICE: &str = "requested";
const RELEASED_NOTICE: &str = "released";

/// Resolve the configured master key (needed to unwrap the escrow ciphertext) or 503.
fn require_master_key(state: &AppState) -> Result<[u8; 32], ApiError> {
    state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| *s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })
}

fn map_db_err(e: sqlx::Error) -> ApiError {
    tracing::error!(error = %e, "DB error in recovery release flow");
    ApiError::new(ErrorCode::InternalError, "recovery release failed")
}

/// Best-effort notification to the account email on release request / actual release. A delivery
/// failure is logged, never propagated — the security-relevant state change already committed.
async fn notify(state: &AppState, did: &str, kind: &str) {
    let email = match account_email(&state.db, did).await {
        Ok(Some(email)) => email,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(did = %did, error = %e, "failed to read email for recovery notice");
            return;
        }
    };
    let host = state.config.public_host();
    let (subject, body) = match kind {
        RELEASE_REQUESTED_NOTICE => (
            format!("A recovery-share release was requested on {host}"),
            format!(
                "A release of your escrowed recovery share was just requested for your {host} \
                 account.\n\n\
                 If this was you, no action is needed — the share becomes available after the \
                 delay window.\n\n\
                 If this was NOT you, cancel it now from any signed-in device, and revoke your \
                 credentials if your email may be compromised.",
            ),
        ),
        _ => (
            format!("Your recovery share was released on {host}"),
            format!(
                "Your escrowed recovery share has been released for your {host} account.\n\n\
                 If you did not perform a recovery, contact your operator immediately: your \
                 identity may be under attack. Your device key can still override a hostile \
                 recovery for 72 hours.",
            ),
        ),
    };
    let message = crate::email::EmailMessage {
        to: email,
        subject,
        body,
    };
    if let Err(e) = state.email.send(message).await {
        tracing::error!(did = %did, kind, error = %e, "failed to send recovery release notice");
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{app, test_state, AppState};
    use crate::email::{EmailError, EmailMessage, EmailSender};
    use crate::routes::test_utils::test_master_key;
    use axum::body::Body;
    use axum::http::{HeaderValue, Request, StatusCode};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    /// Email sink that keeps every message so tests can read the OTP and assert on notifications —
    /// the "LogEmailSender in tests" role, but inspectable.
    #[derive(Clone, Default)]
    struct CapturingEmail(Arc<Mutex<Vec<EmailMessage>>>);

    impl EmailSender for CapturingEmail {
        fn send<'a>(
            &'a self,
            message: EmailMessage,
        ) -> Pin<Box<dyn Future<Output = Result<(), EmailError>> + Send + 'a>> {
            let store = self.0.clone();
            Box::pin(async move {
                store.lock().unwrap().push(message);
                Ok(())
            })
        }
    }

    struct Harness {
        state: AppState,
        emails: Arc<Mutex<Vec<EmailMessage>>>,
    }

    async fn harness_with_delay(delay_secs: u64) -> Harness {
        let base = test_state().await; // rate limiting is disabled in the test harness
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
        config.recovery.release_delay_secs = delay_secs;
        let emails = Arc::new(Mutex::new(Vec::new()));
        let email: Arc<dyn EmailSender> = Arc::new(CapturingEmail(emails.clone()));
        let state = AppState {
            config: Arc::new(config),
            email,
            ..base
        };
        Harness { state, emails }
    }

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

    /// The Share 2 envelope (index 2) for a set, both wrapped (for storage) and as its base32
    /// encoding (what a successful release returns).
    fn share2(set_id: u32) -> (String, String) {
        let seed = [0x5a_u8; 32];
        let envelopes = crypto::split_secret_into_envelopes(&seed, set_id).unwrap();
        let share2 = &envelopes[1];
        assert_eq!(share2.index(), 2);
        let wrapped =
            crypto::encrypt_secret_bytes(share2.to_bytes().as_slice(), &test_master_key()).unwrap();
        (wrapped, share2.encode_share().to_string())
    }

    async fn deposit_escrow(db: &sqlx::SqlitePool, did: &str, set_id: u32) -> String {
        let (wrapped, encoded) = share2(set_id);
        crate::db::recovery_escrow::insert_escrow_share(db, did, &wrapped)
            .await
            .expect("deposit escrow");
        encoded
    }

    async fn initiate(state: &AppState, identifier: &str) -> StatusCode {
        recovery_initiate(
            State(state.clone()),
            Json(InitiateRequest {
                identifier: identifier.to_string(),
            }),
        )
        .await
    }

    async fn release(
        state: &AppState,
        identifier: &str,
        otp: Option<&str>,
    ) -> Result<ReleaseResponse, ApiError> {
        recovery_release(
            State(state.clone()),
            Json(ReleaseRequest {
                identifier: identifier.to_string(),
                otp: otp.map(str::to_string),
            }),
        )
        .await
        .map(|json| json.0)
    }

    /// Pull the emailed OTP out of the most recent captured message.
    fn latest_otp(emails: &Arc<Mutex<Vec<EmailMessage>>>) -> String {
        let guard = emails.lock().unwrap();
        let body = &guard.last().expect("an OTP email was sent").body;
        body.split("Recovery code: ")
            .nth(1)
            .expect("body carries a recovery code")
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    }

    async fn audit_events(db: &sqlx::SqlitePool, did: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT event_type FROM recovery_audit_events WHERE did = ? ORDER BY rowid",
        )
        .bind(did)
        .fetch_all(db)
        .await
        .unwrap()
    }

    /// Force a pending release's window into the past — the test's "clock advance".
    async fn expire_pending(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "UPDATE recovery_escrow SET release_pending_until = datetime('now', '-1 second') \
             WHERE did = ?",
        )
        .bind(did)
        .execute(db)
        .await
        .unwrap();
    }

    async fn session_headers(db: &sqlx::SqlitePool, did: &str) -> HeaderMap {
        let token = crate::auth::token::generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("seed session");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token.plaintext)).unwrap(),
        );
        headers
    }

    async fn cancel(state: &AppState, headers: &HeaderMap) -> Result<CancelResponse, ApiError> {
        recovery_release_cancel(
            State(state.clone()),
            Method::POST,
            Uri::from_static("/v1/recovery/release/cancel"),
            headers.clone(),
        )
        .await
        .map(|json| json.0)
    }

    // ── initiate ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn initiate_is_always_200_and_never_a_handle_oracle() {
        let h = harness_with_delay(0).await;
        let did = "did:plc:recinit";
        seed_account(&h.state.db, did).await;

        // Known account: 200 + an OTP row + an email.
        assert_eq!(initiate(&h.state, did).await, StatusCode::OK);
        let otp_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_otps WHERE did = ?")
            .bind(did)
            .fetch_one(&h.state.db)
            .await
            .unwrap();
        assert_eq!(otp_rows, 1);
        assert_eq!(h.emails.lock().unwrap().len(), 1);

        // Unknown identifier: still 200, no OTP minted anywhere, no email.
        assert_eq!(
            initiate(&h.state, "did:plc:doesnotexist").await,
            StatusCode::OK
        );
        let total_otps: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_otps")
            .fetch_one(&h.state.db)
            .await
            .unwrap();
        assert_eq!(total_otps, 1, "unknown identifier mints no OTP");
    }

    // ── full happy path (with delay) ──────────────────────────────────────────

    #[tokio::test]
    async fn full_happy_path_initiate_release_pending_then_share() {
        let h = harness_with_delay(24 * 60 * 60).await;
        let did = "did:plc:rechappy";
        seed_account(&h.state.db, did).await;
        let expected_share = deposit_escrow(&h.state.db, did, 1).await;

        // initiate → OTP email.
        assert_eq!(initiate(&h.state, did).await, StatusCode::OK);
        let otp = latest_otp(&h.emails);

        // release (open) → pending, with an availableAt in the future.
        let opened = release(&h.state, did, Some(&otp)).await.unwrap();
        assert_eq!(opened.status, "pending");
        assert!(opened.available_at.is_some());
        assert!(opened.share.is_none());

        // Polling before the window elapses stays pending (no OTP needed now).
        let polled = release(&h.state, did, None).await.unwrap();
        assert_eq!(polled.status, "pending");
        assert!(polled.share.is_none());

        // Clock advance → the share is returned, and it is exactly the deposited Share 2 envelope.
        expire_pending(&h.state.db, did).await;
        let released = release(&h.state, did, None).await.unwrap();
        assert_eq!(released.status, "released");
        assert_eq!(released.share.as_deref(), Some(expected_share.as_str()));

        // Once collected, the release state is cleared: a further poll is the uniform failure.
        assert_eq!(
            release(&h.state, did, None)
                .await
                .unwrap_err()
                .status_code(),
            401
        );

        // Audit trail: request then release; the pending polls add nothing.
        assert_eq!(
            audit_events(&h.state.db, did).await,
            vec!["release_requested", "released"]
        );
        // Notifications: OTP + request + released.
        assert_eq!(h.emails.lock().unwrap().len(), 3);
    }

    // ── zero-delay collapses to a single call ─────────────────────────────────

    #[tokio::test]
    async fn zero_delay_returns_share_immediately() {
        let h = harness_with_delay(0).await;
        let did = "did:plc:reczero";
        seed_account(&h.state.db, did).await;
        let expected_share = deposit_escrow(&h.state.db, did, 3).await;

        assert_eq!(initiate(&h.state, did).await, StatusCode::OK);
        let otp = latest_otp(&h.emails);

        let released = release(&h.state, did, Some(&otp)).await.unwrap();
        assert_eq!(released.status, "released");
        assert_eq!(released.share.as_deref(), Some(expected_share.as_str()));

        // Both request and release are audited in the one call.
        assert_eq!(
            audit_events(&h.state.db, did).await,
            vec!["release_requested", "released"]
        );
    }

    // ── cancel ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn cancel_blocks_release_and_requires_fresh_initiate() {
        let h = harness_with_delay(24 * 60 * 60).await;
        let did = "did:plc:reccancel";
        seed_account(&h.state.db, did).await;
        deposit_escrow(&h.state.db, did, 1).await;

        assert_eq!(initiate(&h.state, did).await, StatusCode::OK);
        let otp = latest_otp(&h.emails);
        assert_eq!(
            release(&h.state, did, Some(&otp)).await.unwrap().status,
            "pending"
        );

        // Owner cancels via a session token.
        let headers = session_headers(&h.state.db, did).await;
        assert_eq!(
            cancel(&h.state, &headers).await.unwrap().status,
            "cancelled"
        );

        // Even after the (would-be) window, polling now fails: the release is gone.
        expire_pending(&h.state.db, did).await; // no-op: pending_until is already NULL
        assert_eq!(
            release(&h.state, did, None)
                .await
                .unwrap_err()
                .status_code(),
            401
        );

        // A replay of the spent OTP is refused too — a fresh initiate is required to retry.
        assert_eq!(
            release(&h.state, did, Some(&otp))
                .await
                .unwrap_err()
                .status_code(),
            401
        );

        assert_eq!(
            audit_events(&h.state.db, did).await,
            vec!["release_requested", "release_cancelled"]
        );
    }

    #[tokio::test]
    async fn cancel_with_nothing_pending_is_idempotent_no_op() {
        let h = harness_with_delay(0).await;
        let did = "did:plc:recnocancel";
        seed_account(&h.state.db, did).await;
        deposit_escrow(&h.state.db, did, 1).await;
        let headers = session_headers(&h.state.db, did).await;

        assert_eq!(
            cancel(&h.state, &headers).await.unwrap().status,
            "cancelled"
        );
        assert!(
            audit_events(&h.state.db, did).await.is_empty(),
            "cancelling nothing writes no audit event"
        );
    }

    #[tokio::test]
    async fn cancel_requires_owner_auth() {
        let h = harness_with_delay(0).await;
        let err = cancel(&h.state, &HeaderMap::new()).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // ── uniform failure (no oracles) ──────────────────────────────────────────

    #[tokio::test]
    async fn wrong_expired_and_replayed_otp_are_uniform_401() {
        let h = harness_with_delay(0).await;
        let did = "did:plc:recwrong";
        seed_account(&h.state.db, did).await;
        deposit_escrow(&h.state.db, did, 1).await;

        // Wrong OTP.
        let wrong = crate::auth::token::generate_token().plaintext;
        assert_eq!(
            release(&h.state, did, Some(&wrong))
                .await
                .unwrap_err()
                .status_code(),
            401
        );

        // Replayed OTP: a real OTP, spent once, refused the second time.
        assert_eq!(initiate(&h.state, did).await, StatusCode::OK);
        let otp = latest_otp(&h.emails);
        assert_eq!(
            release(&h.state, did, Some(&otp)).await.unwrap().status,
            "released"
        );
        assert_eq!(
            release(&h.state, did, Some(&otp))
                .await
                .unwrap_err()
                .status_code(),
            401
        );

        // Expired OTP: another initiate, then age the row past expiry.
        assert_eq!(initiate(&h.state, did).await, StatusCode::OK);
        sqlx::query("UPDATE recovery_otps SET expires_at = datetime('now', '-1 hour') WHERE did = ? AND used_at IS NULL")
            .bind(did)
            .execute(&h.state.db)
            .await
            .unwrap();
        let expired = latest_otp(&h.emails);
        assert_eq!(
            release(&h.state, did, Some(&expired))
                .await
                .unwrap_err()
                .status_code(),
            401
        );
    }

    #[tokio::test]
    async fn unknown_handle_at_release_is_401() {
        let h = harness_with_delay(0).await;
        let otp = crate::auth::token::generate_token().plaintext;
        assert_eq!(
            release(&h.state, "did:plc:nobody", Some(&otp))
                .await
                .unwrap_err()
                .status_code(),
            401
        );
    }

    #[tokio::test]
    async fn escrow_deleted_account_is_same_uniform_failure_as_wrong_otp() {
        // An account with a valid OTP but NO escrow row (owner opted out) must fail exactly like a
        // wrong OTP — no oracle for escrow presence, even to a caller who proved email control.
        let h = harness_with_delay(0).await;
        let did = "did:plc:recnoescrow";
        seed_account(&h.state.db, did).await; // deliberately no deposit_escrow

        assert_eq!(initiate(&h.state, did).await, StatusCode::OK);
        let otp = latest_otp(&h.emails);
        let err = release(&h.state, did, Some(&otp)).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
        assert!(
            audit_events(&h.state.db, did).await.is_empty(),
            "no escrow => no release opened => no audit"
        );
    }

    #[tokio::test]
    async fn missing_master_key_is_service_unavailable() {
        let base = test_state().await; // no master key
        let did = "did:plc:recnokey";
        seed_account(&base.db, did).await;
        let err = release(&base, did, Some("whatever")).await.unwrap_err();
        assert_eq!(err.status_code(), 503);
    }

    // ── rate limiting (shared initiate+release instance) ──────────────────────

    #[tokio::test]
    async fn initiate_and_release_share_one_per_ip_budget() {
        // cap = 3, shared across both endpoints: 3 calls in any mix pass, the 4th is 429.
        let mut state = test_state().await;
        state.rate_limiter = Arc::new(crate::rate_limit::RateLimiterState::new(
            &common::RateLimitConfig {
                enabled: true,
                recovery_per_5min: 3,
                ..common::RateLimitConfig::default()
            },
        ));
        let router = app(state);

        let req = |path: &str, ip: &str| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header("x-forwarded-for", ip)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"identifier":"did:plc:x"}"#))
                .unwrap()
        };

        // Three requests across the two endpoints from one IP all pass the limiter (some 4xx from
        // the handler, but never 429).
        for path in [
            "/v1/recovery/initiate",
            "/v1/recovery/release",
            "/v1/recovery/initiate",
        ] {
            let resp = router
                .clone()
                .oneshot(req(path, "203.0.113.40"))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        // The 4th trips the shared cap: 429 with the standard RateLimit-* headers.
        let resp = router
            .clone()
            .oneshot(req("/v1/recovery/release", "203.0.113.40"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key("retry-after"));
        assert!(resp.headers().contains_key("ratelimit-limit"));
        assert!(resp.headers().contains_key("ratelimit-remaining"));
        assert!(resp.headers().contains_key("ratelimit-reset"));

        // A different IP has its own budget.
        let resp = router
            .oneshot(req("/v1/recovery/release", "203.0.113.41"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
