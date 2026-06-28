// pattern: Imperative Shell
//
// Pairing bootstrap for the operator companion app's per-device signed-request auth.
//
// Two endpoints:
//   POST /v1/admin/pairing-codes — master-token authed; mints a single-use,
//        short-TTL pairing code the operator renders as a QR for a new phone.
//   POST /v1/admin/devices       — pairing code + self-signature; registers the
//        phone's P-256 public key and consumes the code atomically.
//
// Registration is authenticated by the pairing code (a bearer secret) plus a
// self-signature proving the caller holds the private key for the supplied public
// key — not the master token, so a paired phone cannot enroll accomplices.

use axum::{extract::State, http::HeaderMap, response::Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::admin_devices::{
    consume_pairing_code, get_pairing_code, insert_device, insert_pairing_code, NewAdminDevice,
};
use crate::db::is_unique_violation;
use crate::routes::auth;

/// Default pairing-code lifetime: long enough to scan a QR, short enough that an
/// unclaimed code's exposure window stays small. Mirrors the design's "~5 minutes".
const DEFAULT_PAIRING_TTL_MINUTES: i64 = 5;

/// Upper bound on a caller-chosen TTL — a pairing code is a bearer secret, so it
/// must not be mintable with an open-ended lifetime.
const MAX_PAIRING_TTL_MINUTES: i64 = 60;

// ── POST /v1/admin/pairing-codes ─────────────────────────────────────────────

fn default_ttl_minutes() -> i64 {
    DEFAULT_PAIRING_TTL_MINUTES
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCodeRequest {
    /// Optional override for the code's lifetime; clamped to `MAX_PAIRING_TTL_MINUTES`.
    #[serde(default = "default_ttl_minutes")]
    expires_in_minutes: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCodeResponse {
    /// The single-use bearer code; rendered as a QR for the operator's new phone.
    pairing_code: String,
    /// RFC 3339 / ISO-8601 UTC expiry the relay computed (e.g. `2026-06-28T03:34:00Z`).
    expires_at: String,
}

/// Mint a single-use pairing code. Master token only: pairing-code minting stays
/// the root-of-trust path so a compromised device cannot enroll accomplices.
pub async fn mint_pairing_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PairingCodeRequest>,
) -> Result<Json<PairingCodeResponse>, ApiError> {
    // Auth first, before validation, so unauthenticated callers learn nothing.
    auth::require_admin_token(&headers, &state)?;

    if payload.expires_in_minutes < 1 || payload.expires_in_minutes > MAX_PAIRING_TTL_MINUTES {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("expiresInMinutes must be between 1 and {MAX_PAIRING_TTL_MINUTES}"),
        ));
    }

    // Retry on the rare event of a uniqueness collision with an existing code.
    for attempt in 0..3_usize {
        let code = generate_pairing_code();
        match insert_pairing_code(&state.db, &code, payload.expires_in_minutes).await {
            Ok(expires_at) => {
                return Ok(Json(PairingCodeResponse {
                    pairing_code: code,
                    expires_at: to_rfc3339_utc(&expires_at),
                }))
            }
            Err(e) if is_unique_violation(&e) => {
                tracing::warn!(attempt, "pairing code collision; retrying");
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to insert pairing code");
                return Err(ApiError::new(
                    ErrorCode::InternalError,
                    "failed to store pairing code",
                ));
            }
        }
    }

    Err(ApiError::new(
        ErrorCode::InternalError,
        "failed to generate a unique pairing code after retries",
    ))
}

/// A 128-bit random pairing code, base64url-no-pad (22 chars). Strong enough to be
/// a bearer secret even though it lives only briefly in a QR on the operator's screen.
fn generate_pairing_code() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Render a SQLite `datetime('now', …)` value (`YYYY-MM-DD HH:MM:SS`, UTC, no zone)
/// as an unambiguous RFC 3339 / ISO-8601 UTC instant. Unlike most timestamps the API
/// returns informationally, `expiresAt` drives client-side validity math, so it must
/// carry an explicit zone designator rather than relying on an implied UTC convention.
fn to_rfc3339_utc(sqlite_datetime: &str) -> String {
    format!("{}Z", sqlite_datetime.replace(' ', "T"))
}

// ── POST /v1/admin/devices ───────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    /// The single-use code minted by `POST /v1/admin/pairing-codes`.
    pairing_code: String,
    /// Human-readable device label (e.g. "Operator iPhone").
    label: String,
    /// The device's P-256 public key as a `did:key:` URI.
    public_key: String,
    /// Platform tag (e.g. "ios").
    platform: String,
    /// Unix-seconds timestamp the device included in its self-signed message.
    timestamp: i64,
    /// base64url-no-pad raw 64-byte `r‖s` P-256 signature over the registration message.
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    /// The server-assigned device id the phone stores and sends as `X-Admin-Device`.
    device_id: String,
}

/// Register a device by claiming a pairing code.
///
/// The caller proves two things: possession of a valid pairing code (a bearer
/// secret), and control of the private key for `public_key` (a self-signature over
/// the canonical registration message). The relay verifies the signature *before*
/// consuming the code so a bad signature never burns a code, then consumes the code
/// and inserts the device atomically.
///
/// All rejection paths return a generic 401 so the response never reveals which of
/// {unknown, expired, consumed} code state or signature mismatch caused the failure.
pub async fn register_admin_device(
    State(state): State<AppState>,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, ApiError> {
    // --- Validate shape ---
    if payload.label.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "label is required",
        ));
    }
    if payload.platform.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "platform is required",
        ));
    }
    if payload.public_key.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "publicKey is required",
        ));
    }

    // --- Pairing code must be pending (unknown/expired/consumed all reject) ---
    // One generic 401 for every registration auth failure (bad signature, and
    // unknown/expired/consumed code alike) so the response never reveals which
    // check failed. Internal/DB errors keep their own distinct 500s below.
    let code_row = get_pairing_code(&state.db, &payload.pairing_code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to look up pairing code");
            ApiError::new(ErrorCode::InternalError, "pairing lookup failed")
        })?;
    if !code_row.as_ref().is_some_and(|c| c.is_pending()) {
        return Err(auth::invalid_registration_credentials());
    }

    // --- Self-signature must verify against the supplied public key ---
    // Proves the caller holds the private key, not just a copied public key.
    auth::verify_device_self_signature(
        &payload.pairing_code,
        &payload.public_key,
        payload.timestamp,
        &payload.signature,
    )?;

    // --- Consume the code and insert the device atomically ---
    // consume_pairing_code only touches a still-pending row, so it is the
    // authoritative single-use gate: a lost race (concurrent claim or just-expired)
    // returns false here and rejects.
    let device_id = uuid::Uuid::new_v4().to_string();
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin device registration transaction");
        ApiError::new(ErrorCode::InternalError, "registration failed")
    })?;

    let consumed = consume_pairing_code(&mut *tx, &payload.pairing_code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to consume pairing code");
            ApiError::new(ErrorCode::InternalError, "registration failed")
        })?;
    if !consumed {
        return Err(auth::invalid_registration_credentials());
    }

    insert_device(
        &mut *tx,
        &NewAdminDevice {
            id: &device_id,
            label: payload.label.trim(),
            public_key: &payload.public_key,
            platform: payload.platform.trim(),
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert admin device");
        ApiError::new(ErrorCode::InternalError, "registration failed")
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit device registration");
        ApiError::new(ErrorCode::InternalError, "registration failed")
    })?;

    Ok(Json(RegisterDeviceResponse { device_id }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::auth::device_registration_sign_string;
    use crate::routes::test_utils::{body_json, test_state_with_admin_token};

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn post(uri: &str, body: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    /// Assert a registration auth failure: 401 *and* the single generic body. The
    /// body check guards the non-enumeration contract — distinct per-step messages
    /// would still return 401 and pass a status-only assertion.
    async fn assert_generic_unauthorized(response: axum::response::Response) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(
            json["error"]["message"].as_str().unwrap(),
            auth::INVALID_REGISTRATION_CREDENTIALS,
        );
    }

    /// Mint a pairing code via the live endpoint and return it.
    async fn mint_code(state: &AppState) -> String {
        let response = app(state.clone())
            .oneshot(post(
                "/v1/admin/pairing-codes",
                r#"{"expiresInMinutes": 5}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        body_json(response).await["pairingCode"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// A fresh device keypair plus a self-signed registration body for `code`.
    /// `timestamp` defaults to a fixed value; the relay does not window-check it at
    /// registration (the code's short TTL is the freshness bound).
    fn signed_registration_body(code: &str, timestamp: i64) -> (crypto::DidKeyUri, String) {
        let keypair = crypto::generate_p256_keypair().expect("keypair");
        let message = device_registration_sign_string(code, &keypair.key_id.0, timestamp);
        let signature = sign_with(&keypair, message.as_bytes());
        let body = serde_json::json!({
            "pairingCode": code,
            "label": "Operator iPhone",
            "publicKey": keypair.key_id.0,
            "platform": "ios",
            "timestamp": timestamp,
            "signature": signature,
        })
        .to_string();
        (keypair.key_id, body)
    }

    /// Sign `message` with the keypair's private bytes, returning base64url r‖s.
    fn sign_with(keypair: &crypto::P256Keypair, message: &[u8]) -> String {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_bytes(keypair.private_key_bytes.as_slice().into())
            .expect("valid scalar");
        let sig: Signature = sk.sign(message);
        let normalized = sig.normalize_s().unwrap_or(sig);
        URL_SAFE_NO_PAD.encode(normalized.to_bytes())
    }

    // ── Pairing-code minting ────────────────────────────────────────────────

    #[tokio::test]
    async fn mint_returns_code_and_expiry() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post(
                "/v1/admin/pairing-codes",
                r#"{"expiresInMinutes": 5}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(!json["pairingCode"].as_str().unwrap().is_empty());
        // expiresAt is unambiguous RFC 3339 / ISO-8601 UTC, e.g. "2026-06-28T03:34:00Z".
        let expires_at = json["expiresAt"].as_str().unwrap();
        assert_eq!(expires_at.len(), 20);
        assert!(expires_at.ends_with('Z'));
        assert_eq!(expires_at.as_bytes()[10], b'T');
    }

    #[tokio::test]
    async fn mint_defaults_ttl_when_omitted() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post(
                "/v1/admin/pairing-codes",
                r#"{}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mint_without_master_token_returns_401() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post("/v1/admin/pairing-codes", r#"{}"#, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mint_with_wrong_token_returns_401() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post("/v1/admin/pairing-codes", r#"{}"#, Some("wrong")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mint_with_zero_ttl_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post(
                "/v1/admin/pairing-codes",
                r#"{"expiresInMinutes": 0}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn mint_with_excessive_ttl_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post(
                "/v1/admin/pairing-codes",
                r#"{"expiresInMinutes": 61}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── Device registration ─────────────────────────────────────────────────

    #[tokio::test]
    async fn register_with_valid_code_and_signature_succeeds() {
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();
        let code = mint_code(&state).await;
        let (_, body) = signed_registration_body(&code, 1_700_000_000);

        let response = app(state)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let device_id = body_json(response).await["deviceId"]
            .as_str()
            .unwrap()
            .to_string();

        // The device row exists and the code was consumed.
        let device = crate::db::admin_devices::get_device(&db, &device_id)
            .await
            .unwrap()
            .expect("device persisted");
        assert!(device.is_active);
        assert_eq!(device.label, "Operator iPhone");
        let code_row = get_pairing_code(&db, &code).await.unwrap().unwrap();
        assert!(
            code_row.consumed_at.is_some(),
            "code consumed on registration"
        );
    }

    #[tokio::test]
    async fn register_with_unknown_code_returns_401() {
        let state = test_state_with_admin_token().await;
        let (_, body) = signed_registration_body("NO-SUCH-CODE", 1_700_000_000);
        let response = app(state)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_generic_unauthorized(response).await;
    }

    #[tokio::test]
    async fn register_with_expired_code_returns_401() {
        let state = test_state_with_admin_token().await;
        // Insert an already-expired code directly.
        sqlx::query(
            "INSERT INTO admin_pairing_codes (code, expires_at, created_at) \
             VALUES ('EXPIRED', datetime('now', '-1 minute'), datetime('now', '-6 minutes'))",
        )
        .execute(&state.db)
        .await
        .unwrap();
        let (_, body) = signed_registration_body("EXPIRED", 1_700_000_000);

        let response = app(state)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_generic_unauthorized(response).await;
    }

    #[tokio::test]
    async fn register_with_bad_self_signature_returns_401() {
        // Signature does not verify against the supplied key.
        let state = test_state_with_admin_token().await;
        let code = mint_code(&state).await;
        let keypair = crypto::generate_p256_keypair().unwrap();
        // Sign a *different* message than the relay will reconstruct.
        let signature = sign_with(&keypair, b"not the registration message");
        let body = serde_json::json!({
            "pairingCode": code,
            "label": "Operator iPhone",
            "publicKey": keypair.key_id.0,
            "platform": "ios",
            "timestamp": 1_700_000_000,
            "signature": signature,
        })
        .to_string();

        let response = app(state)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_generic_unauthorized(response).await;
    }

    #[tokio::test]
    async fn register_with_signature_from_other_key_returns_401() {
        // Correct message, but signed by a different key than the supplied public key.
        let state = test_state_with_admin_token().await;
        let code = mint_code(&state).await;
        let advertised = crypto::generate_p256_keypair().unwrap();
        let attacker = crypto::generate_p256_keypair().unwrap();
        let message = device_registration_sign_string(&code, &advertised.key_id.0, 1_700_000_000);
        let signature = sign_with(&attacker, message.as_bytes());
        let body = serde_json::json!({
            "pairingCode": code,
            "label": "Operator iPhone",
            "publicKey": advertised.key_id.0,
            "platform": "ios",
            "timestamp": 1_700_000_000,
            "signature": signature,
        })
        .to_string();

        let response = app(state)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_generic_unauthorized(response).await;
    }

    #[tokio::test]
    async fn register_with_malformed_signature_returns_401() {
        let state = test_state_with_admin_token().await;
        let code = mint_code(&state).await;
        let keypair = crypto::generate_p256_keypair().unwrap();
        let body = serde_json::json!({
            "pairingCode": code,
            "label": "Operator iPhone",
            "publicKey": keypair.key_id.0,
            "platform": "ios",
            "timestamp": 1_700_000_000,
            "signature": "not-base64url!!!",
        })
        .to_string();

        let response = app(state)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_generic_unauthorized(response).await;
    }

    #[tokio::test]
    async fn second_claim_of_same_code_fails() {
        // Single-use.
        let state = test_state_with_admin_token().await;
        let code = mint_code(&state).await;

        let (_, body1) = signed_registration_body(&code, 1_700_000_000);
        let first = app(state.clone())
            .oneshot(post("/v1/admin/devices", &body1, None))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // A second registration (fresh key, same code) must be rejected.
        let (_, body2) = signed_registration_body(&code, 1_700_000_001);
        let second = app(state)
            .oneshot(post("/v1/admin/devices", &body2, None))
            .await
            .unwrap();
        assert_generic_unauthorized(second).await;
    }

    #[tokio::test]
    async fn register_with_empty_label_returns_400() {
        let state = test_state_with_admin_token().await;
        let code = mint_code(&state).await;
        let keypair = crypto::generate_p256_keypair().unwrap();
        let message = device_registration_sign_string(&code, &keypair.key_id.0, 1_700_000_000);
        let signature = sign_with(&keypair, message.as_bytes());
        let body = serde_json::json!({
            "pairingCode": code,
            "label": "   ",
            "publicKey": keypair.key_id.0,
            "platform": "ios",
            "timestamp": 1_700_000_000,
            "signature": signature,
        })
        .to_string();

        let response = app(state)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_missing_field_returns_422() {
        let state = test_state_with_admin_token().await;
        let response = app(state)
            .oneshot(post(
                "/v1/admin/devices",
                r#"{"pairingCode": "x", "label": "y"}"#,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn rfc3339_utc_adds_t_and_z() {
        // SQLite's space-separated, zoneless datetime becomes an unambiguous UTC instant.
        assert_eq!(
            to_rfc3339_utc("2026-06-28 03:34:00"),
            "2026-06-28T03:34:00Z"
        );
    }

    #[tokio::test]
    async fn mint_then_register_uses_no_master_token_on_register() {
        // The register endpoint is authed by code+signature, never the master token:
        // even a totally unconfigured admin state can register once a code exists.
        let state = test_state_with_admin_token().await;
        let code = mint_code(&state).await;
        let (_, body) = signed_registration_body(&code, 1_700_000_000);

        // Swap to a state with the SAME db but no admin token configured.
        let no_token = test_state().await;
        // Move the minted code into the tokenless db so we can prove auth independence.
        let expires_at: String =
            sqlx::query_scalar("SELECT expires_at FROM admin_pairing_codes WHERE code = ?")
                .bind(&code)
                .fetch_one(&state.db)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO admin_pairing_codes (code, expires_at, created_at) VALUES (?, ?, datetime('now'))",
        )
        .bind(&code)
        .bind(&expires_at)
        .execute(&no_token.db)
        .await
        .unwrap();

        let response = app(no_token)
            .oneshot(post("/v1/admin/devices", &body, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
