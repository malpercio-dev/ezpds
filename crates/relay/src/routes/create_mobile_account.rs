// pattern: Imperative Shell
//
// Gathers: JSON request body (email, handle, device_public_key, platform, claim_code), DB pool
// Processes: platform validation → public key validation → email non-empty check →
//            handle format validation → email uniqueness (accounts + pending_accounts) →
//            handle uniqueness (handles + pending_accounts) →
//            ID + token generation → atomic transaction:
//              UPDATE claim_codes (redeem guard; 0 rows → SELECT to classify 404 vs 409)
//              INSERT pending_accounts (email/handle uniqueness enforced by unique indexes)
//              INSERT devices
//              INSERT pending_sessions
// Returns: JSON { account_id, device_id, device_token, session_token, next_step } on success;
//          ApiError on all failure paths

use axum::{extract::State, http::StatusCode, response::Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::routes::create_account::validate_handle;
use crate::routes::register_device::{is_valid_platform, MAX_PUBLIC_KEY_LEN};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMobileAccountRequest {
    email: String,
    handle: String,
    device_public_key: String,
    platform: String,
    claim_code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMobileAccountResponse {
    account_id: String,
    device_id: String,
    device_token: String,
    session_token: String,
    next_step: String,
}

pub async fn create_mobile_account(
    State(state): State<AppState>,
    Json(payload): Json<CreateMobileAccountRequest>,
) -> Result<(StatusCode, Json<CreateMobileAccountResponse>), ApiError> {
    // --- Validate platform ---
    if !is_valid_platform(&payload.platform) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "platform must be one of: ios, android, macos, linux, windows",
        ));
    }

    // --- Validate device_public_key ---
    if payload.device_public_key.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "devicePublicKey must not be empty",
        ));
    }
    if payload.device_public_key.len() > MAX_PUBLIC_KEY_LEN {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            format!("devicePublicKey must be at most {MAX_PUBLIC_KEY_LEN} characters"),
        ));
    }

    // --- Validate email (basic non-empty check; format validation is deferred) ---
    if payload.email.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "email must not be empty",
        ));
    }

    // --- Validate handle format ---
    if let Err(msg) = validate_handle(&payload.handle) {
        return Err(ApiError::new(ErrorCode::InvalidHandle, msg));
    }

    // --- Email uniqueness: check accounts and pending_accounts in one query ---
    // Fast-path rejection before the INSERT to avoid consuming a claim code slot on a
    // predictable conflict. The unique indexes remain the authoritative enforcement.
    let email_taken: i64 = sqlx::query_scalar(
        "SELECT CAST(
             (EXISTS(SELECT 1 FROM accounts WHERE email = ?)
              OR EXISTS(SELECT 1 FROM pending_accounts WHERE email = ?))
         AS INTEGER)",
    )
    .bind(&payload.email)
    .bind(&payload.email)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to check email uniqueness");
        ApiError::new(ErrorCode::InternalError, "failed to create account")
    })?;

    if email_taken != 0 {
        return Err(ApiError::new(
            ErrorCode::AccountExists,
            "an account with this email already exists",
        ));
    }

    // --- Handle uniqueness: check handles and pending_accounts in one query ---
    let handle_taken: i64 = sqlx::query_scalar(
        "SELECT CAST(
             (EXISTS(SELECT 1 FROM handles WHERE handle = ?)
              OR EXISTS(SELECT 1 FROM pending_accounts WHERE handle = ?))
         AS INTEGER)",
    )
    .bind(&payload.handle)
    .bind(&payload.handle)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to check handle uniqueness");
        ApiError::new(ErrorCode::InternalError, "failed to create account")
    })?;

    if handle_taken != 0 {
        return Err(ApiError::new(
            ErrorCode::HandleTaken,
            "this handle is already claimed",
        ));
    }

    // --- Generate IDs and credentials ---
    // device_token / session_token: 32 random bytes → base64url (no padding) for the wire;
    // SHA-256 of the raw bytes → 64-char hex for the DB.
    // Plaintext tokens are returned once and never stored; future auth uses the hashes.
    let account_id = Uuid::new_v4().to_string();
    let device_id = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string();

    let mut device_token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut device_token_bytes);
    let device_token = URL_SAFE_NO_PAD.encode(device_token_bytes);
    let device_token_hash: String = Sha256::digest(device_token_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let mut session_token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut session_token_bytes);
    let session_token = URL_SAFE_NO_PAD.encode(session_token_bytes);
    let session_token_hash: String = Sha256::digest(session_token_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // --- Atomically provision: redeem claim code + create account + register device + issue session ---
    provision_mobile_account(
        &state.db,
        ProvisionParams {
            claim_code: &payload.claim_code,
            account_id: &account_id,
            email: &payload.email,
            handle: &payload.handle,
            device_id: &device_id,
            platform: &payload.platform,
            public_key: &payload.device_public_key,
            device_token_hash: &device_token_hash,
            session_id: &session_id,
            session_token_hash: &session_token_hash,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateMobileAccountResponse {
            account_id,
            device_id,
            device_token,
            session_token,
            next_step: "did_creation".to_string(),
        }),
    ))
}

/// Parameters for [`provision_mobile_account`]. Grouped into a struct to keep the
/// function signature under Clippy's `too_many_arguments` limit.
struct ProvisionParams<'a> {
    claim_code: &'a str,
    account_id: &'a str,
    email: &'a str,
    handle: &'a str,
    device_id: &'a str,
    platform: &'a str,
    public_key: &'a str,
    device_token_hash: &'a str,
    session_id: &'a str,
    session_token_hash: &'a str,
}

/// Atomically redeem a claim code and create the account, device, and pending session.
///
/// Steps inside the transaction:
///  1. UPDATE claim_codes with a WHERE guard to reject invalid/expired/redeemed codes.
///  2. If 0 rows_affected: SELECT to distinguish 404 (invalid/expired) from 409 (redeemed).
///  3. INSERT pending_accounts — email/handle uniqueness enforced by unique indexes.
///  4. INSERT devices — bound to the new pending account.
///  5. INSERT pending_sessions — issues a session token for the DID-creation step.
///
/// On any failure after begin(), the transaction is dropped and SQLite rolls back all
/// changes — the claim code remains unredeemed and no orphaned rows are created.
#[tracing::instrument(skip(db, p), err, fields(claim_code = %p.claim_code))]
async fn provision_mobile_account(
    db: &sqlx::SqlitePool,
    p: ProvisionParams<'_>,
) -> Result<(), ApiError> {
    let ProvisionParams {
        claim_code,
        account_id,
        email,
        handle,
        device_id,
        platform,
        public_key,
        device_token_hash,
        session_id,
        session_token_hash,
    } = p;
    let mut tx = db
        .begin()
        .await
        .inspect_err(|e| {
            tracing::error!(error = %e, "failed to begin mobile account transaction");
        })
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create account"))?;

    // Attempt to mark the claim code redeemed. The WHERE guard rejects invalid, expired,
    // and previously-redeemed codes in one atomic step — no separate SELECT needed for
    // the guard itself. A 0 rows_affected result is classified below.
    let result = sqlx::query(
        "UPDATE claim_codes \
         SET redeemed_at = datetime('now') \
         WHERE code = ? AND redeemed_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(claim_code)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| {
        tracing::error!(error = %e, "failed to execute claim code redemption UPDATE");
    })
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create account"))?;

    if result.rows_affected() == 0 {
        // Distinguish: already-redeemed (409) vs. invalid or expired (404).
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT redeemed_at FROM claim_codes WHERE code = ?")
                .bind(claim_code)
                .fetch_optional(&mut *tx)
                .await
                .inspect_err(|e| {
                    tracing::error!(error = %e, "failed to classify claim code status");
                })
                .map_err(|_| {
                    ApiError::new(ErrorCode::InternalError, "failed to create account")
                })?;

        return Err(match row {
            Some((Some(_),)) => ApiError::new(
                ErrorCode::ClaimCodeRedeemed,
                "claim code has already been redeemed",
            ),
            _ => ApiError::new(
                ErrorCode::NotFound,
                "claim code is invalid or has expired",
            ),
        });
    }

    // Insert the pending account. The claim_code FK references the just-updated claim_codes row.
    // tier is always 'free' for mobile self-registration; tier selection is reserved for
    // admin-provisioned accounts (POST /v1/accounts) where an operator picks the tier.
    sqlx::query(
        "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
         VALUES (?, ?, ?, 'free', ?, datetime('now'))",
    )
    .bind(account_id)
    .bind(email)
    .bind(handle)
    .bind(claim_code)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| {
        tracing::error!(error = %e, "failed to insert pending_accounts row");
    })
    .map_err(|e| classify_pending_account_error(&e))?;

    // Register the device bound to this pending account.
    sqlx::query(
        "INSERT INTO devices \
         (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(platform)
    .bind(public_key)
    .bind(device_token_hash)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| {
        tracing::error!(error = %e, "failed to insert device record");
    })
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create account"))?;

    // Issue a pending session token to authorize the DID-creation step.
    sqlx::query(
        "INSERT INTO pending_sessions \
         (id, account_id, device_id, token_hash, created_at, expires_at) \
         VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'))",
    )
    .bind(session_id)
    .bind(account_id)
    .bind(device_id)
    .bind(session_token_hash)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| {
        tracing::error!(error = %e, "failed to insert pending session");
    })
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create account"))?;

    tx.commit()
        .await
        .inspect_err(|e| {
            tracing::error!(error = %e, "failed to commit mobile account transaction");
        })
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create account"))?;

    Ok(())
}

/// Classify a unique constraint violation from the pending_accounts INSERT into the
/// appropriate ApiError. Returns InternalError for non-unique-violation errors.
///
/// Constraint name matching uses SQLite's stable "UNIQUE constraint failed: <table>.<column>"
/// format. The fallthrough branch (unknown constraint) logs the constraint name so any
/// unexpected violations surface in traces — matching the pattern in create_account.rs.
fn classify_pending_account_error(e: &sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(db_err) = e {
        if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation {
            let msg = db_err.message();
            if msg.contains("pending_accounts.email") {
                return ApiError::new(
                    ErrorCode::AccountExists,
                    "an account with this email already exists",
                );
            }
            if msg.contains("pending_accounts.handle") {
                return ApiError::new(
                    ErrorCode::HandleTaken,
                    "this handle is already claimed",
                );
            }
            // Unknown unique constraint — log the name so it surfaces in traces.
            tracing::error!(
                constraint = msg,
                "unique violation on unexpected constraint in pending_accounts insert"
            );
        }
    }
    ApiError::new(ErrorCode::InternalError, "failed to create account")
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn post_create_mobile_account(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/accounts/mobile")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// Seed a standalone (unlinked) claim code ready for mobile provisioning.
    /// Returns the claim code string.
    async fn seed_claim_code(db: &sqlx::SqlitePool) -> String {
        let code: String = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(8)
            .map(|c| c.to_ascii_uppercase())
            .collect();

        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+24 hours'), datetime('now'))",
        )
        .bind(&code)
        .execute(db)
        .await
        .unwrap();

        code
    }

    fn mobile_body(claim_code: &str) -> String {
        format!(
            r#"{{"email":"test@example.com","handle":"test.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{claim_code}"}}"#
        )
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn returns_201_with_correct_shape() {
        // MM-84.AC1: single POST completes account + device + session setup
        let state = test_state().await;
        let claim_code = seed_claim_code(&state.db).await;

        let response = app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["accountId"].as_str().is_some(), "accountId must be present");
        assert!(json["deviceId"].as_str().is_some(), "deviceId must be present");
        assert!(json["deviceToken"].as_str().is_some(), "deviceToken must be present");
        assert!(json["sessionToken"].as_str().is_some(), "sessionToken must be present");
        assert_eq!(json["nextStep"], "did_creation");
    }

    #[tokio::test]
    async fn all_ids_are_uuids() {
        let state = test_state().await;
        let claim_code = seed_claim_code(&state.db).await;

        let response = app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        uuid::Uuid::parse_str(json["accountId"].as_str().unwrap())
            .expect("accountId must be a valid UUID");
        uuid::Uuid::parse_str(json["deviceId"].as_str().unwrap())
            .expect("deviceId must be a valid UUID");
    }

    #[tokio::test]
    async fn tokens_are_base64url_43_chars() {
        let state = test_state().await;
        let claim_code = seed_claim_code(&state.db).await;

        let response = app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for field in ["deviceToken", "sessionToken"] {
            let token = json[field].as_str().unwrap();
            assert!(
                token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{field} must be base64url without padding; got: {token}"
            );
            assert_eq!(
                token.len(),
                43,
                "{field} must be 43 chars (base64url of 32 bytes)"
            );
        }
    }

    #[tokio::test]
    async fn all_rows_persisted_in_db() {
        // MM-84.AC1: transaction atomicity — all three rows must be written
        let state = test_state().await;
        let db = state.db.clone();
        let claim_code = seed_claim_code(&state.db).await;

        let response = app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let account_id = json["accountId"].as_str().unwrap();
        let device_id = json["deviceId"].as_str().unwrap();

        // pending_accounts row
        let (email, handle, tier, code): (String, String, String, String) = sqlx::query_as(
            "SELECT email, handle, tier, claim_code FROM pending_accounts WHERE id = ?",
        )
        .bind(account_id)
        .fetch_one(&db)
        .await
        .expect("pending_accounts row must exist");

        assert_eq!(email, "test@example.com");
        assert_eq!(handle, "test.example.com");
        assert_eq!(tier, "free");
        assert_eq!(code, claim_code);

        // devices row
        let (dev_account_id, platform, public_key): (String, String, String) = sqlx::query_as(
            "SELECT account_id, platform, public_key FROM devices WHERE id = ?",
        )
        .bind(device_id)
        .fetch_one(&db)
        .await
        .expect("devices row must exist");

        assert_eq!(dev_account_id, account_id);
        assert_eq!(platform, "ios");
        assert_eq!(public_key, "dGVzdC1rZXk=");

        // pending_sessions row
        let (sess_account_id, sess_device_id): (String, String) = sqlx::query_as(
            "SELECT account_id, device_id FROM pending_sessions WHERE account_id = ?",
        )
        .bind(account_id)
        .fetch_one(&db)
        .await
        .expect("pending_sessions row must exist");

        assert_eq!(sess_account_id, account_id);
        assert_eq!(sess_device_id, device_id);
    }

    #[tokio::test]
    async fn claim_code_marked_redeemed() {
        let state = test_state().await;
        let db = state.db.clone();
        let claim_code = seed_claim_code(&state.db).await;

        app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        let redeemed_at: Option<String> =
            sqlx::query_scalar("SELECT redeemed_at FROM claim_codes WHERE code = ?")
                .bind(&claim_code)
                .fetch_one(&db)
                .await
                .unwrap();

        assert!(redeemed_at.is_some(), "claim code must have redeemed_at set");
    }

    #[tokio::test]
    async fn token_hashes_are_sha256_of_tokens() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use sha2::{Digest, Sha256};

        let state = test_state().await;
        let db = state.db.clone();
        let claim_code = seed_claim_code(&state.db).await;

        let response = app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let device_id = json["deviceId"].as_str().unwrap();
        let account_id = json["accountId"].as_str().unwrap();

        // device token hash
        let device_token_bytes =
            URL_SAFE_NO_PAD.decode(json["deviceToken"].as_str().unwrap()).unwrap();
        let expected_device_hash: String = Sha256::digest(&device_token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let (stored_device_hash,): (String,) =
            sqlx::query_as("SELECT device_token_hash FROM devices WHERE id = ?")
                .bind(device_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(stored_device_hash, expected_device_hash, "device_token_hash mismatch");

        // session token hash
        let session_token_bytes =
            URL_SAFE_NO_PAD.decode(json["sessionToken"].as_str().unwrap()).unwrap();
        let expected_session_hash: String = Sha256::digest(&session_token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let (stored_session_hash,): (String,) = sqlx::query_as(
            "SELECT token_hash FROM pending_sessions WHERE account_id = ?",
        )
        .bind(account_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(stored_session_hash, expected_session_hash, "session token_hash mismatch");
    }

    // ── Claim code errors ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_claim_code_returns_404() {
        // MM-84.AC2: invalid claim code returns 404
        let response = app(test_state().await)
            .oneshot(post_create_mobile_account(
                r#"{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"INVALID"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn expired_claim_code_returns_404() {
        // MM-84.AC2: expired claim code returns 404
        let state = test_state().await;
        let code = "EXPRD001";

        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '-1 hour'), datetime('now', '-2 hours'))",
        )
        .bind(code)
        .execute(&state.db)
        .await
        .unwrap();

        let body = format!(
            r#"{{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{code}"}}"#
        );
        let response = app(state)
            .oneshot(post_create_mobile_account(&body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn already_redeemed_claim_code_returns_409() {
        // MM-84.AC3: already-redeemed claim code returns 409
        let state = test_state().await;
        let claim_code = seed_claim_code(&state.db).await;
        let application = app(state);

        // First call succeeds.
        let first = application
            .clone()
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        // Second call with same code must return 409.
        let second = application
            .oneshot(post_create_mobile_account(
                &format!(r#"{{"email":"other@example.com","handle":"other.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{claim_code}"}}"#)
            ))
            .await
            .unwrap();

        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(second.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "CLAIM_CODE_REDEEMED");
    }

    // ── Atomicity ─────────────────────────────────────────────────────────────
    //
    // These tests verify that a conflicting email or handle prevents claim code
    // consumption. The pre-flight uniqueness check fires before the transaction
    // begins, so the claim code UPDATE is never executed and no rollback is needed.
    // This is intentional: the pre-flight is an optimisation that avoids burning
    // a claim code slot on a predictable conflict.

    #[tokio::test]
    async fn duplicate_email_pre_flight_protects_claim_code() {
        // MM-84.AC4: email conflict caught pre-flight — claim code must not be consumed
        let state = test_state().await;
        let db = state.db.clone();
        let claim_code = seed_claim_code(&state.db).await;

        // Seed a pending account with the same email as the request will use.
        let existing_code = seed_claim_code(&db).await;
        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, 'test@example.com', 'existing.example.com', 'free', ?, datetime('now'))",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&existing_code)
        .execute(&db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let redeemed_at: Option<String> =
            sqlx::query_scalar("SELECT redeemed_at FROM claim_codes WHERE code = ?")
                .bind(&claim_code)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            redeemed_at.is_none(),
            "claim code must not be consumed when pre-flight rejects the request"
        );
    }

    #[tokio::test]
    async fn duplicate_handle_pre_flight_protects_claim_code() {
        // MM-84.AC4: handle conflict caught pre-flight — claim code must not be consumed
        let state = test_state().await;
        let db = state.db.clone();
        let claim_code = seed_claim_code(&db).await;

        // Seed a pending account with the same handle as the request will use.
        let existing_code = seed_claim_code(&db).await;
        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, 'other@example.com', 'test.example.com', 'free', ?, datetime('now'))",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&existing_code)
        .execute(&db)
        .await
        .unwrap();

        let response = app(state)
            .oneshot(post_create_mobile_account(&mobile_body(&claim_code)))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "HANDLE_TAKEN");

        let redeemed_at: Option<String> =
            sqlx::query_scalar("SELECT redeemed_at FROM claim_codes WHERE code = ?")
                .bind(&claim_code)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            redeemed_at.is_none(),
            "claim code must not be consumed when pre-flight rejects the request"
        );
    }

    // ── Duplicate email / handle ───────────────────────────────────────────────

    #[tokio::test]
    async fn duplicate_email_in_pending_returns_409() {
        let state = test_state().await;
        let db = state.db.clone();
        let code1 = seed_claim_code(&db).await;
        let code2 = seed_claim_code(&db).await;

        let resp1 = app(state.clone())
            .oneshot(post_create_mobile_account(&format!(
                r#"{{"email":"dup@example.com","handle":"dup1.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{code1}"}}"#
            )))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        let resp2 = app(state)
            .oneshot(post_create_mobile_account(&format!(
                r#"{{"email":"dup@example.com","handle":"dup2.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{code2}"}}"#
            )))
            .await
            .unwrap();

        assert_eq!(resp2.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "ACCOUNT_EXISTS");
    }

    #[tokio::test]
    async fn duplicate_email_in_accounts_returns_409() {
        // exercises the OR EXISTS(SELECT 1 FROM accounts WHERE email = ?) branch in the pre-flight
        let state = test_state().await;

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:existing', 'existing@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let code = seed_claim_code(&state.db).await;
        let response = app(state)
            .oneshot(post_create_mobile_account(&format!(
                r#"{{"email":"existing@example.com","handle":"new.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{code}"}}"#
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "ACCOUNT_EXISTS");
    }

    #[tokio::test]
    async fn duplicate_handle_in_pending_returns_409() {
        let state = test_state().await;
        let db = state.db.clone();
        let code1 = seed_claim_code(&db).await;
        let code2 = seed_claim_code(&db).await;

        let resp1 = app(state.clone())
            .oneshot(post_create_mobile_account(&format!(
                r#"{{"email":"h1@example.com","handle":"taken.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{code1}"}}"#
            )))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        let resp2 = app(state)
            .oneshot(post_create_mobile_account(&format!(
                r#"{{"email":"h2@example.com","handle":"taken.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{code2}"}}"#
            )))
            .await
            .unwrap();

        assert_eq!(resp2.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "HANDLE_TAKEN");
    }

    #[tokio::test]
    async fn duplicate_handle_in_handles_returns_409() {
        // exercises the OR EXISTS(SELECT 1 FROM handles WHERE handle = ?) branch in the pre-flight
        let state = test_state().await;

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:active', 'active@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO handles (handle, did, created_at) \
             VALUES ('active.example.com', 'did:plc:active', datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let code = seed_claim_code(&state.db).await;
        let response = app(state)
            .oneshot(post_create_mobile_account(&format!(
                r#"{{"email":"new@example.com","handle":"active.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"{code}"}}"#
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "HANDLE_TAKEN");
    }

    // ── Platform validation ───────────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_platform_returns_400() {
        let response = app(test_state().await)
            .oneshot(post_create_mobile_account(
                r#"{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"plan9","claimCode":"ABC123"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    // ── Public key validation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_public_key_returns_400() {
        let response = app(test_state().await)
            .oneshot(post_create_mobile_account(
                r#"{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"","platform":"ios","claimCode":"ABC123"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oversized_public_key_returns_400() {
        use crate::routes::register_device::MAX_PUBLIC_KEY_LEN;
        let big_key = "x".repeat(MAX_PUBLIC_KEY_LEN + 1);
        let body = format!(
            r#"{{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"{big_key}","platform":"ios","claimCode":"ABC123"}}"#
        );
        let response = app(test_state().await)
            .oneshot(post_create_mobile_account(&body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    // ── Email validation ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_email_returns_400() {
        // Present-but-empty email must be caught by application validation (400),
        // not the deserializer (422 — which fires only for a missing field).
        let response = app(test_state().await)
            .oneshot(post_create_mobile_account(
                r#"{"email":"","handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"ABC123"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    // ── Missing required fields ───────────────────────────────────────────────

    #[tokio::test]
    async fn missing_email_returns_422() {
        let response = app(test_state().await)
            .oneshot(post_create_mobile_account(
                r#"{"handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"ABC123"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn missing_claim_code_returns_422() {
        let response = app(test_state().await)
            .oneshot(post_create_mobile_account(
                r#"{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── DB failure ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn closed_db_pool_returns_500() {
        let state = test_state().await;
        state.db.close().await;

        let response = app(state)
            .oneshot(post_create_mobile_account(
                r#"{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"ABC123"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INTERNAL_ERROR");
    }
}
