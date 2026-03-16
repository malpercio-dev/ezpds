// pattern: Imperative Shell
//
// Gathers: JSON request body (claim_code, device_public_key, platform), DB pool
// Processes: platform validation → public key non-empty/length check → atomic claim-code
//            redemption + device registration (single transaction, rolls back on any step
//            failure):
//              UPDATE claim_codes WHERE code = ? AND unredeemed AND unexpired
//              SELECT pending_accounts.id WHERE claim_code = ?
//              INSERT INTO devices (...)
// Returns: JSON { device_id, device_token, account_id } on success; ApiError on all failure paths

use axum::{extract::State, http::StatusCode, response::Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Maximum allowed length for a device public key string.
/// A P-256 uncompressed public key in base64 is ~88 chars; 512 is generous
/// enough to accommodate any standard encoding without accepting unbounded input.
/// Shared by create_mobile_account, which also validates device_public_key.
pub(crate) const MAX_PUBLIC_KEY_LEN: usize = 512;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    claim_code: String,
    device_public_key: String,
    platform: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    device_id: String,
    device_token: String,
    account_id: String,
}

pub async fn register_device(
    State(state): State<AppState>,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), ApiError> {
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

    // --- Generate device credentials ---
    // 32 random bytes → base64url (no padding) for the wire; SHA-256 hex for the DB.
    // The plaintext token is returned once and never stored; future auth uses the hash.
    let device_id = Uuid::new_v4().to_string();
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let device_token = URL_SAFE_NO_PAD.encode(token_bytes);
    let device_token_hash: String = Sha256::digest(token_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // --- Atomically redeem claim code and register device ---
    let account_id = redeem_and_register(
        &state.db,
        &payload.claim_code,
        &device_id,
        &payload.platform,
        &payload.device_public_key,
        &device_token_hash,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            device_id,
            device_token,
            account_id,
        }),
    ))
}

pub(crate) fn is_valid_platform(platform: &str) -> bool {
    matches!(platform, "ios" | "android" | "macos" | "linux" | "windows")
}

/// Atomically redeem a claim code and register the device in a single transaction.
///
/// The UPDATE runs with a WHERE guard (`redeemed_at IS NULL AND expires_at > now`) so a
/// zero `rows_affected` unambiguously means the code is invalid, expired, or already
/// redeemed — no race window, and no second SELECT is needed for the guard.
///
/// Returns the `account_id` (pending_accounts.id) on success.
/// On any failure after the transaction has begun, the transaction is dropped and
/// SQLite rolls back all changes — the claim code remains unredeemed.
#[tracing::instrument(skip(db), err, fields(claim_code = %claim_code))]
async fn redeem_and_register(
    db: &sqlx::SqlitePool,
    claim_code: &str,
    device_id: &str,
    platform: &str,
    public_key: &str,
    device_token_hash: &str,
) -> Result<String, ApiError> {
    let mut tx = db
        .begin()
        .await
        .inspect_err(|e| {
            tracing::error!(error = %e, "failed to begin device registration transaction");
        })
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to register device"))?;

    // Attempt to mark the claim code redeemed. The WHERE guard rejects invalid, expired,
    // or previously-redeemed codes atomically — no separate SELECT needed.
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
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to register device"))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "claim code is invalid, expired, or already redeemed",
        ));
    }

    // Resolve the pending account bound to this claim code.
    let (account_id,): (String,) =
        sqlx::query_as("SELECT id FROM pending_accounts WHERE claim_code = ?")
            .bind(claim_code)
            .fetch_one(&mut *tx)
            .await
            .inspect_err(|e| {
                if matches!(e, sqlx::Error::RowNotFound) {
                    tracing::error!("no pending_account row found for claim code — orphaned code");
                } else {
                    tracing::error!(error = %e, "failed to fetch pending account for claim code");
                }
            })
            .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to register device"))?;

    sqlx::query(
        "INSERT INTO devices \
         (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(device_id)
    .bind(&account_id)
    .bind(platform)
    .bind(public_key)
    .bind(device_token_hash)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| {
        tracing::error!(error = %e, "failed to insert device record");
    })
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to register device"))?;

    tx.commit()
        .await
        .inspect_err(|e| {
            tracing::error!(error = %e, "failed to commit device registration transaction");
        })
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to register device"))?;

    Ok(account_id)
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

    fn post_register_device(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/devices")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// Seed a pending account with a valid (unredeemed, unexpired) claim code.
    /// Returns (account_id, claim_code).
    ///
    /// Each call generates a unique claim code and unique email/handle so the helper
    /// is safe to call multiple times on the same pool without UNIQUE constraint conflicts.
    async fn seed_pending_account(db: &sqlx::SqlitePool) -> (String, String) {
        let account_id = uuid::Uuid::new_v4().to_string();
        let claim_code: String = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(8)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let email = format!("test-{}@example.com", &account_id[..8]);
        let handle = format!("test-{}.example.com", &account_id[..8]);

        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+24 hours'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(db)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(&email)
        .bind(&handle)
        .bind(&claim_code)
        .execute(db)
        .await
        .unwrap();

        (account_id, claim_code)
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn returns_201_with_correct_shape() {
        let state = test_state().await;
        let (_, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["deviceId"].as_str().is_some(),
            "deviceId must be present"
        );
        assert!(
            json["deviceToken"].as_str().is_some(),
            "deviceToken must be present"
        );
        assert!(
            json["accountId"].as_str().is_some(),
            "accountId must be present"
        );
    }

    #[tokio::test]
    async fn device_id_is_uuid() {
        let state = test_state().await;
        let (_, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"android"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let device_id = json["deviceId"].as_str().unwrap();

        uuid::Uuid::parse_str(device_id).expect("deviceId must be a valid UUID");
    }

    #[tokio::test]
    async fn device_token_is_base64url() {
        let state = test_state().await;
        let (_, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"macos"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = json["deviceToken"].as_str().unwrap();

        // URL_SAFE_NO_PAD base64: only [A-Za-z0-9_-], no '=' padding
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "deviceToken must be base64url without padding; got: {token}"
        );
        // 32 bytes encoded as base64url (no pad) → 43 chars
        assert_eq!(
            token.len(),
            43,
            "deviceToken must be 43 chars (base64url of 32 bytes)"
        );
    }

    #[tokio::test]
    async fn account_id_matches_pending_account() {
        // returned account_id matches the pending account bound to the claim code
        let state = test_state().await;
        let (expected_account_id, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"linux"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["accountId"].as_str().unwrap(), expected_account_id);
    }

    #[tokio::test]
    async fn device_persisted_in_db() {
        let state = test_state().await;
        let db = state.db.clone();
        let (account_id, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"windows"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let device_id = json["deviceId"].as_str().unwrap();

        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT account_id, platform, public_key, device_token_hash FROM devices WHERE id = ?",
        )
        .bind(device_id)
        .fetch_one(&db)
        .await
        .expect("device row must exist in DB");

        assert_eq!(row.0, account_id, "account_id");
        assert_eq!(row.1, "windows", "platform");
        assert_eq!(row.2, "dGVzdC1rZXk=", "public_key");
        // token hash must be 64-char hex (SHA-256)
        assert_eq!(row.3.len(), 64, "device_token_hash must be 64-char hex");
        assert!(
            row.3.chars().all(|c| c.is_ascii_hexdigit()),
            "device_token_hash must be lowercase hex"
        );
    }

    #[tokio::test]
    async fn token_hash_is_sha256_of_token() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use sha2::{Digest, Sha256};

        let state = test_state().await;
        let db = state.db.clone();
        let (_, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let device_token = json["deviceToken"].as_str().unwrap();
        let device_id = json["deviceId"].as_str().unwrap();

        let token_bytes = URL_SAFE_NO_PAD.decode(device_token).unwrap();
        let expected_hash: String = Sha256::digest(&token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let stored_hash: (String,) =
            sqlx::query_as("SELECT device_token_hash FROM devices WHERE id = ?")
                .bind(device_id)
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(stored_hash.0, expected_hash);
    }

    #[tokio::test]
    async fn claim_code_marked_redeemed_after_registration() {
        // claim code is single-use; marked redeemed on success
        let state = test_state().await;
        let db = state.db.clone();
        let (_, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}}"#
        );
        app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        let redeemed_at: Option<String> =
            sqlx::query_scalar("SELECT redeemed_at FROM claim_codes WHERE code = ?")
                .bind(&claim_code)
                .fetch_one(&db)
                .await
                .unwrap();

        assert!(
            redeemed_at.is_some(),
            "claim code must have redeemed_at set"
        );
    }

    #[tokio::test]
    async fn orphaned_claim_code_returns_500_and_does_not_redeem_code() {
        // Atomicity: if the pending_accounts lookup fails (orphaned code — code exists in
        // claim_codes but no matching pending_accounts row), the transaction must roll back
        // so the claim code remains unredeemed. Verifies the UPDATE is not committed without
        // the subsequent INSERT also succeeding.
        let state = test_state().await;
        let db = state.db.clone();
        let claim_code = "ORPHAN1";

        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+24 hours'), datetime('now'))",
        )
        .bind(claim_code)
        .execute(&state.db)
        .await
        .unwrap();
        // Deliberately omit the matching pending_accounts insert.

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INTERNAL_ERROR");

        // Transaction must have rolled back: claim code must remain unredeemed.
        let redeemed_at: Option<String> =
            sqlx::query_scalar("SELECT redeemed_at FROM claim_codes WHERE code = ?")
                .bind(claim_code)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            redeemed_at.is_none(),
            "claim code must remain unredeemed after failed registration (transaction rollback)"
        );
    }

    // ── Invalid / expired / redeemed claim codes ──────────────────────────────

    #[tokio::test]
    async fn invalid_claim_code_returns_400() {
        let response = app(test_state().await)
            .oneshot(post_register_device(
                r#"{"claimCode":"ZZZZZZ","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    #[tokio::test]
    async fn expired_claim_code_returns_400() {
        let state = test_state().await;
        let account_id = uuid::Uuid::new_v4().to_string();
        let claim_code = "EXPIRD1";

        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '-1 hour'), datetime('now', '-2 hours'))",
        )
        .bind(claim_code)
        .execute(&state.db)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, 'expired@example.com', 'expired.example.com', 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(claim_code)
        .execute(&state.db)
        .await
        .unwrap();

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}}"#
        );
        let response = app(state)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    #[tokio::test]
    async fn already_redeemed_claim_code_returns_400() {
        // claim code is single-use; second use returns error
        let state = test_state().await;
        let (_, claim_code) = seed_pending_account(&state.db).await;

        let body = format!(
            r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}}"#
        );
        let application = app(state);

        // First registration succeeds.
        let first = application
            .clone()
            .oneshot(post_register_device(&body))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        // Second registration with the same code fails.
        let second = application
            .oneshot(post_register_device(&body))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(second.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    // ── Platform validation ───────────────────────────────────────────────────

    #[tokio::test]
    async fn all_valid_platforms_accepted() {
        // platform validation (ios, android, macos, linux, windows)
        for platform in ["ios", "android", "macos", "linux", "windows"] {
            let state = test_state().await;
            let (_, claim_code) = seed_pending_account(&state.db).await;

            let body = format!(
                r#"{{"claimCode":"{claim_code}","devicePublicKey":"dGVzdC1rZXk=","platform":"{platform}"}}"#
            );
            let response = app(state)
                .oneshot(post_register_device(&body))
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "platform {platform:?} must be accepted"
            );
        }
    }

    #[tokio::test]
    async fn invalid_platform_returns_400() {
        let response = app(test_state().await)
            .oneshot(post_register_device(
                r#"{"claimCode":"ABC123","devicePublicKey":"dGVzdC1rZXk=","platform":"plan9"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    #[tokio::test]
    async fn platform_is_case_sensitive() {
        let response = app(test_state().await)
            .oneshot(post_register_device(
                r#"{"claimCode":"ABC123","devicePublicKey":"dGVzdC1rZXk=","platform":"iOS"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    // ── Public key validation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_public_key_returns_400() {
        let response = app(test_state().await)
            .oneshot(post_register_device(
                r#"{"claimCode":"ABC123","devicePublicKey":"","platform":"ios"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    #[tokio::test]
    async fn oversized_public_key_returns_400() {
        let oversized_key = "A".repeat(super::MAX_PUBLIC_KEY_LEN + 1);
        let body = format!(
            r#"{{"claimCode":"ABC123","devicePublicKey":"{oversized_key}","platform":"ios"}}"#
        );
        let response = app(test_state().await)
            .oneshot(post_register_device(&body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    // ── Missing required fields ───────────────────────────────────────────────

    #[tokio::test]
    async fn missing_claim_code_returns_422() {
        let response = app(test_state().await)
            .oneshot(post_register_device(
                r#"{"devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn missing_device_public_key_returns_422() {
        let response = app(test_state().await)
            .oneshot(post_register_device(
                r#"{"claimCode":"ABC123","platform":"ios"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn missing_platform_returns_422() {
        let response = app(test_state().await)
            .oneshot(post_register_device(
                r#"{"claimCode":"ABC123","devicePublicKey":"dGVzdC1rZXk="}"#,
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
            .oneshot(post_register_device(
                r#"{"claimCode":"ABC123","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "INTERNAL_ERROR");
    }

    // ── Pure unit tests ───────────────────────────────────────────────────────

    #[test]
    fn is_valid_platform_accepts_known_platforms() {
        for p in ["ios", "android", "macos", "linux", "windows"] {
            assert!(super::is_valid_platform(p), "{p} must be valid");
        }
    }

    #[test]
    fn is_valid_platform_rejects_unknown() {
        assert!(!super::is_valid_platform("plan9"));
        assert!(!super::is_valid_platform(""));
        assert!(!super::is_valid_platform("iOS")); // case-sensitive
        assert!(!super::is_valid_platform("Windows")); // case-sensitive
    }
}
