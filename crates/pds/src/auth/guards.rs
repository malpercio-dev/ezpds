// pattern: Imperative Shell
//
// Route-level auth middleware: token/session/signature checks that read request
// headers and query the database. Pure helpers it builds on live in `auth/`.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crypto::{verify_p256_signature, DidKeyUri};
use subtle::ConstantTimeEq;

use common::{ApiError, ErrorCode, ADMIN_TIMESTAMP_WINDOW_SECS};

use crate::app::AppState;

/// Information about an authenticated pending session.
#[derive(Debug)]
pub struct PendingSessionInfo {
    pub account_id: String,
    #[allow(dead_code)]
    pub device_id: String,
}

/// Information about an authenticated promoted-account session.
#[derive(Debug)]
pub struct SessionInfo {
    pub did: String,
}

/// Validate the admin Bearer token from request headers.
///
/// Returns `Ok(())` when the token is present, has the `"Bearer "` prefix, and the
/// final byte comparison passes. The presence check and `"Bearer "` prefix strip are
/// conventional short-circuits that do not expose the token value; only the final byte
/// comparison uses `subtle::ct_eq` to avoid timing side-channels on the token itself.
/// Returns `ApiError::Unauthorized` in all other cases, including when the server has
/// no token configured.
///
/// Call this at the top of any handler that requires admin access.
pub fn require_admin_token(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let expected_token = state
        .config
        .admin_token
        .as_ref()
        .map(|t| t.0.as_str())
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "admin token not configured"))?;

    let auth_value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::warn!(
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
        .unwrap_or("");

    let provided_token = auth_value.strip_prefix("Bearer ").ok_or_else(|| {
        ApiError::new(
            ErrorCode::Unauthorized,
            "missing or invalid Authorization header",
        )
    })?;

    if !bool::from(provided_token.as_bytes().ct_eq(expected_token.as_bytes())) {
        return Err(ApiError::new(
            ErrorCode::Unauthorized,
            "invalid admin token",
        ));
    }

    Ok(())
}

// ── Per-device signed-request admin auth (companion app) ─────────────────────

/// Headers a companion-app device attaches to every admin request. Names are
/// stored lowercase because `HeaderMap` normalises on lookup and `from_static`
/// rejects uppercase; the canonical display form is `X-Admin-*`.
pub const ADMIN_DEVICE_HEADER: &str = "x-admin-device";
pub const ADMIN_TIMESTAMP_HEADER: &str = "x-admin-timestamp";
pub const ADMIN_NONCE_HEADER: &str = "x-admin-nonce";
pub const ADMIN_SIGNATURE_HEADER: &str = "x-admin-signature";

/// The single generic 401 for every device signed-request auth failure — a missing
/// header, an unknown device, a stale timestamp, a bad signature, or a replayed
/// nonce all surface this identical message so the response never reveals which
/// check failed. A *revoked* device is the one deliberate exception: it returns 403
/// so an operator can confirm a device was cut off server-side.
pub const INVALID_ADMIN_SIGNATURE: &str = "invalid admin request signature";

fn invalid_admin_signature() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized, INVALID_ADMIN_SIGNATURE)
}

/// The canonical envelope a device signs for each admin request, and that
/// `require_admin` reconstructs to verify it.
///
/// Format: `method ‖ "\n" ‖ path ‖ "\n" ‖ timestamp ‖ "\n" ‖ nonce ‖ "\n" ‖ sha256_hex(body)`
/// — newline-separated to match the registration envelope convention. The body is
/// committed to as the lowercase hex SHA-256 digest of the exact request bytes (empty
/// string hashed for a bodiless request). This function is the single source of truth
/// for that format; the companion app's signing client must produce identical bytes.
pub fn admin_request_sign_string(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let body_hash = crate::token::sha256_hex(body);
    format!("{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}")
}

/// Read a header as a UTF-8 string, treating non-UTF-8 values as absent.
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Whether the request's `Content-Type` is JSON — `application/json` (optionally with
/// parameters like `; charset=utf-8`) or any `application/*+json` — matching what
/// axum's `Json` extractor accepts. The admin routes parse the body via
/// `Json::from_bytes` (after consuming it as `Bytes` for signature verification), which
/// skips the extractor's media-type guard; they call this to preserve the prior 415
/// rejection for non-JSON (or absent) content types.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = header_str(headers, axum::http::header::CONTENT_TYPE.as_str()) else {
        return false;
    };
    let essence = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence == "application/json"
        || (essence.starts_with("application/") && essence.ends_with("+json"))
}

/// Current Unix time in seconds. Clamps a pre-epoch clock to 0 rather than panicking;
/// such a request fails the timestamp-window check anyway.
fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Which credential authenticated an admin request — the master (break-glass) token, or a
/// specific companion-app device. Returned by [`require_admin`]/[`require_admin_json`] so a
/// caller that logs the action (e.g. `updateSubjectStatus`) can record *who* performed it, not
/// just *that* someone with valid admin credentials did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminActor {
    /// Authenticated via the shared master Bearer token (break-glass / CI path).
    MasterToken,
    /// Authenticated via a specific companion-app device's signed request; carries the
    /// device's server-assigned id.
    Device(String),
}

impl AdminActor {
    /// Render as a single string for structured log fields — `"master-token"` or
    /// `"device:<id>"`.
    pub fn as_log_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::MasterToken => std::borrow::Cow::Borrowed("master-token"),
            Self::Device(id) => std::borrow::Cow::Owned(format!("device:{id}")),
        }
    }
}

/// Gate an admin endpoint: accept the master Bearer token **or** a verified,
/// non-replayed device signature.
///
/// A request carrying the `X-Admin-Device` header is treated as a device signed
/// request and verified via [`verify_admin_device_request`]; any other request
/// falls back to the master token ([`require_admin_token`]), preserving the existing
/// break-glass / CI path unchanged. `method` and `path` are the request's HTTP method
/// and path (no query) — they are bound into the signature so a signature minted for
/// one route cannot authorize another. `body` is the exact request body bytes.
///
/// Returns which credential authenticated the request ([`AdminActor`]) so callers that log the
/// action can record the acting admin, not just that authentication succeeded.
pub async fn require_admin(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    state: &AppState,
) -> Result<AdminActor, ApiError> {
    // The master token is the root of trust / break-glass path: accept it whenever it
    // is valid, regardless of any (possibly malformed) device headers, so the
    // "master token OR device signature" contract holds even if both are present.
    let token_result = require_admin_token(headers, state);
    if token_result.is_ok() {
        return Ok(AdminActor::MasterToken);
    }

    // Otherwise a request carrying the device header is verified as a device signed
    // request; a request with neither credential surfaces the master-token error.
    if headers.contains_key(ADMIN_DEVICE_HEADER) {
        verify_admin_device_request(method, path, headers, body, &state.db).await
    } else {
        Err(token_result.unwrap_err())
    }
}

/// Gate an admin endpoint and enforce JSON content type in one step.
///
/// Combines [`require_admin`] with the 415 media-type guard that axum's `Json`
/// extractor would otherwise provide. Admin handlers that consume the body as raw
/// [`axum::body::Bytes`] for signature verification call this before parsing the
/// body with `Json::from_bytes`, so raw-body handlers keep the same rejection
/// statuses as `Json`-extracting ones.
///
/// Returns `Err(Response)` on auth failure (401/403) or a non-JSON content type (415);
/// `Ok(AdminActor)` (see [`require_admin`]) to proceed with body parsing.
pub async fn require_admin_json(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    state: &AppState,
) -> Result<AdminActor, Response> {
    // The media-type guard runs first: it is cheap and side-effect-free, whereas
    // `require_admin` may consume a nonce and bump `last_seen_at`. Checking it first
    // means a wrong `Content-Type` returns 415 without burning a nonce (which would
    // otherwise make the corrected retry fail as a replay) and matches the original
    // ordering where axum's `Json` extractor rejected the media type before the handler.
    if !is_json_content_type(headers) {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected application/json",
        )
            .into_response());
    }
    require_admin(method, path, headers, body, state)
        .await
        .map_err(IntoResponse::into_response)
}

/// Verify a device signed admin request against its stored public key.
///
/// Steps: parse the `X-Admin-*` headers; load the device (unknown ⇒ 401, revoked ⇒
/// 403); reject a timestamp outside the ±[`ADMIN_TIMESTAMP_WINDOW_SECS`] window;
/// verify the P-256 signature over the canonical [`admin_request_sign_string`];
/// record the nonce (a previously-seen nonce ⇒ replay ⇒ 401); then bump
/// `last_seen_at` (best effort). Every failure but the revoked case returns the
/// single generic [`INVALID_ADMIN_SIGNATURE`] 401 (non-enumeration).
async fn verify_admin_device_request(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    db: &sqlx::SqlitePool,
) -> Result<AdminActor, ApiError> {
    use crate::db::admin_devices::{get_device, insert_nonce_if_absent, touch_last_seen};

    let device_id = header_str(headers, ADMIN_DEVICE_HEADER).ok_or_else(invalid_admin_signature)?;
    let timestamp = header_str(headers, ADMIN_TIMESTAMP_HEADER)
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(invalid_admin_signature)?;
    let nonce = header_str(headers, ADMIN_NONCE_HEADER).ok_or_else(invalid_admin_signature)?;
    let signature = header_str(headers, ADMIN_SIGNATURE_HEADER)
        .and_then(decode_signature)
        .ok_or_else(invalid_admin_signature)?;

    // Device must be known and active. A revoked device is rejected with 403 so it can
    // be cut off server-side without the phone; all other failures are a generic 401.
    let device = get_device(db, device_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to look up admin device");
            ApiError::new(ErrorCode::InternalError, "admin auth failed")
        })?
        .ok_or_else(invalid_admin_signature)?;
    if !device.is_active {
        return Err(ApiError::new(ErrorCode::Forbidden, "admin device revoked"));
    }

    // Reject stale or future-dated requests (clock skew beyond the window). This bounds
    // how long a captured request stays replayable alongside the nonce check below.
    // Saturating bounds avoid i64 overflow on an extreme attacker-supplied timestamp
    // (a direct `now - timestamp` could panic in debug or wrap in release).
    let now = unix_now_secs();
    if timestamp < now.saturating_sub(ADMIN_TIMESTAMP_WINDOW_SECS)
        || timestamp > now.saturating_add(ADMIN_TIMESTAMP_WINDOW_SECS)
    {
        return Err(invalid_admin_signature());
    }

    // The signature must verify against the stored key over the canonical envelope —
    // binding method, path, timestamp, nonce, and a hash of the body.
    let sign_string = admin_request_sign_string(method, path, timestamp, nonce, body);
    verify_p256_signature(
        &DidKeyUri(device.public_key.clone()),
        sign_string.as_bytes(),
        &signature,
    )
    .map_err(|_| invalid_admin_signature())?;

    // Record the nonce; a value this device has already used is a replay. INSERT OR
    // IGNORE makes the seen-once check atomic, so concurrent replays cannot both win.
    let fresh = insert_nonce_if_absent(db, nonce, device_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to record admin nonce");
            ApiError::new(ErrorCode::InternalError, "admin auth failed")
        })?;
    if !fresh {
        return Err(invalid_admin_signature());
    }

    // Liveness bookkeeping only — a failure here must not deny an authenticated request.
    if let Err(e) = touch_last_seen(db, device_id).await {
        tracing::warn!(error = %e, device_id, "failed to bump admin device last_seen_at");
    }

    Ok(AdminActor::Device(device_id.to_string()))
}

/// The single generic 401 message for every admin-device registration auth failure.
///
/// A malformed signature, an unknown/expired/consumed pairing code, and a
/// signature that does not verify all surface this identical message so the
/// response never reveals which check failed (non-enumeration). The registration
/// handler reuses it for the pairing-code state checks it owns.
pub const INVALID_REGISTRATION_CREDENTIALS: &str = "invalid registration credentials";

pub(crate) fn invalid_registration_credentials() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized, INVALID_REGISTRATION_CREDENTIALS)
}

/// The canonical message a device self-signs during admin-device registration.
///
/// Format: `pairing_code ‖ "\n" ‖ public_key ‖ "\n" ‖ timestamp` — newline-separated
/// to match the per-request `sign_string` envelope convention. The companion app's
/// signing client must produce the identical bytes for verification to pass; this
/// function is the single source of truth for that format.
pub fn device_registration_sign_string(
    pairing_code: &str,
    public_key: &str,
    timestamp: i64,
) -> String {
    format!("{pairing_code}\n{public_key}\n{timestamp}")
}

/// Decode a base64url-no-pad signature into the raw 64-byte `r‖s` form, or `None`
/// if it is not valid base64url or not exactly 64 bytes.
fn decode_signature(encoded: &str) -> Option<[u8; 64]> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    bytes.try_into().ok()
}

/// Verify a device's self-signature during admin-device registration.
///
/// Decodes the base64url signature, reconstructs the canonical registration
/// message, and checks the P-256 signature against the supplied `did:key`. Proves
/// the caller holds the private key (not just a copied public key). Any failure —
/// malformed signature or a verification mismatch — returns the generic
/// [`INVALID_REGISTRATION_CREDENTIALS`] 401 so callers cannot enumerate the cause.
pub fn verify_device_self_signature(
    pairing_code: &str,
    public_key: &str,
    timestamp: i64,
    signature_b64: &str,
) -> Result<(), ApiError> {
    let signature = decode_signature(signature_b64).ok_or_else(invalid_registration_credentials)?;
    let message = device_registration_sign_string(pairing_code, public_key, timestamp);
    verify_p256_signature(
        &DidKeyUri(public_key.to_string()),
        message.as_bytes(),
        &signature,
    )
    .map_err(|_| invalid_registration_credentials())
}

/// Authenticate a `pending_session` Bearer token.
///
/// Extracts the Bearer token from the Authorization header, SHA-256 hashes the raw
/// decoded bytes (matching the storage format from `POST /v1/accounts/mobile`), and
/// queries `pending_sessions` for a matching, unexpired row.
///
/// # Errors
/// Returns `ApiError::Unauthorized` if:
/// - The Authorization header is missing
/// - The token is not valid base64url
/// - No unexpired session matches the token hash
pub async fn require_pending_session(
    headers: &HeaderMap,
    db: &sqlx::SqlitePool,
) -> Result<PendingSessionInfo, ApiError> {
    use crate::token::hash_bearer_token;

    // Extract Bearer token from Authorization header.
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::warn!(
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unauthorized,
                "missing or invalid Authorization header",
            )
        })?;

    // Decode base64url → raw bytes, then SHA-256 hash → hex string.
    // Matches the storage format written by POST /v1/accounts/mobile.
    let token_hash = hash_bearer_token(token)?;

    // Look up the session by hash, rejecting expired sessions.
    //
    // Unlike `require_admin_token`'s constant-time compare, the session/pending/device paths
    // do a plain `WHERE token_hash = ?` lookup that is *not* constant-time. That asymmetry is
    // intentional and safe: the compared value is the SHA-256 of a 256-bit random secret, so a
    // timing oracle on the hash reveals nothing exploitable — recovering the token from a leaked
    // digest would require a SHA-256 preimage. (The admin token is compared in constant time
    // because it is a human-configured secret, not a hash of one.)
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT account_id, device_id FROM pending_sessions \
         WHERE token_hash = ? AND expires_at > datetime('now')",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query pending session");
        ApiError::new(ErrorCode::InternalError, "session lookup failed")
    })?;

    let (account_id, device_id) = row.ok_or_else(|| {
        ApiError::new(ErrorCode::Unauthorized, "invalid or expired session token")
    })?;

    Ok(PendingSessionInfo {
        account_id,
        device_id,
    })
}

/// Authenticate a device Bearer token for a specific device ID.
///
/// Extracts the Bearer token from the Authorization header, SHA-256 hashes it, and
/// queries `devices WHERE id = ? AND device_token_hash = ?`. The `device_id` scope
/// ensures that a token belonging to device A cannot authenticate requests for device B.
///
/// # Errors
/// Returns `ApiError::Unauthorized` if:
/// - The Authorization header is missing or malformed
/// - The token is not valid base64url
/// - No device matches both the `device_id` and the token hash
pub async fn require_device_token(
    headers: &HeaderMap,
    device_id: &str,
    db: &sqlx::SqlitePool,
) -> Result<(), ApiError> {
    use crate::token::hash_bearer_token;

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::warn!(
                        device_id = %device_id,
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unauthorized,
                "missing or invalid Authorization header",
            )
        })?;

    let token_hash = hash_bearer_token(token)?;

    let found: Option<(String,)> =
        sqlx::query_as("SELECT id FROM devices WHERE id = ? AND device_token_hash = ?")
            .bind(device_id)
            .bind(&token_hash)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to query device token");
                ApiError::new(ErrorCode::InternalError, "device lookup failed")
            })?;

    if found.is_some() {
        return Ok(());
    }

    let transfer_device_found =
        crate::db::transfers::transfer_device_token_exists(db, device_id, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to query transfer device token");
                ApiError::new(ErrorCode::InternalError, "device lookup failed")
            })?;

    if !transfer_device_found {
        tracing::debug!(device_id = %device_id, "no device matched id+token_hash");
    }

    transfer_device_found
        .then_some(())
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "invalid device token"))
}

/// Authenticate a promoted-account Bearer token.
///
/// Extracts the Bearer token from the Authorization header, SHA-256 hashes the raw
/// decoded bytes (matching the storage format written by `POST /v1/dids`), and
/// queries `sessions` for a matching, unexpired row.
///
/// # Errors
/// Returns `ApiError::Unauthorized` if:
/// - The Authorization header is missing
/// - The token is not valid base64url
/// - No unexpired session matches the token hash
pub async fn require_session(
    headers: &HeaderMap,
    db: &sqlx::SqlitePool,
) -> Result<SessionInfo, ApiError> {
    use crate::token::hash_bearer_token;

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::warn!(
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unauthorized,
                "missing or invalid Authorization header",
            )
        })?;

    let token_hash = hash_bearer_token(token)?;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT did FROM sessions WHERE token_hash = ? AND expires_at > datetime('now')",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query session");
        ApiError::new(ErrorCode::InternalError, "session lookup failed")
    })?;

    let (did,) = row.ok_or_else(|| {
        tracing::debug!("no unexpired session row found for token hash");
        ApiError::new(ErrorCode::Unauthorized, "invalid or expired session token")
    })?;

    Ok(SessionInfo { did })
}

/// Why account-owner authentication failed. Vocab-neutral (the `issuer_trust::TrustedJwtError`
/// pattern): the `/v1/agents` surface maps it to XRPC `ApiError`s and the claim ceremony's
/// confirm gate maps it to auth.md-style `{error, error_description}` responses.
#[derive(Debug)]
pub enum OwnerAuthError {
    /// No usable credential: the bearer token is neither a live wallet session nor a verifiable
    /// access token. Carries the underlying rejection for callers that speak XRPC.
    Unauthenticated(ApiError),
    /// A verified access token that is agent-derived (`registration_id` claim). An agent must
    /// never act as the account owner — least of all to confirm its own claim ceremony.
    AgentDerived,
    /// A verified access token below full access (e.g. an app password).
    NotFullAccess,
}

/// Authenticate the account owner behind the account-holder agent surfaces: a wallet session
/// token first (`sessions` table — what Obsign holds after the create flow), then a full-access
/// OAuth/XRPC access token. The same dual-credential posture as `transfer/complete`. Returns the
/// caller's DID.
pub async fn authenticate_account_owner(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<String, OwnerAuthError> {
    if let Ok(session) = require_session(headers, &state.db).await {
        return Ok(session.did);
    }

    let token =
        crate::auth::extract_bearer_token(headers).map_err(OwnerAuthError::Unauthenticated)?;
    let claims = crate::auth::jwt::verify_access_token(token, state)
        .map_err(OwnerAuthError::Unauthenticated)?;
    if claims.registration_id.is_some() {
        return Err(OwnerAuthError::AgentDerived);
    }
    let scope =
        crate::auth::jwt::parse_scope(&claims.scope).map_err(OwnerAuthError::Unauthenticated)?;
    if scope != crate::auth::jwt::AuthScope::Access {
        return Err(OwnerAuthError::NotFullAccess);
    }
    Ok(claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::sync::Arc;

    use crate::app::test_state;

    async fn state_with_token(token: &str) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.admin_token = Some(common::Sensitive(token.to_string()));
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn no_token_configured_returns_401() {
        let state = test_state().await; // admin_token = None
        let headers = headers_with_bearer("anything");
        let err = require_admin_token(&headers, &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn missing_authorization_header_returns_401() {
        let state = state_with_token("secret").await;
        let err = require_admin_token(&HeaderMap::new(), &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn bare_token_without_bearer_prefix_returns_401() {
        let state = state_with_token("secret").await;
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, "secret".parse().unwrap());
        let err = require_admin_token(&headers, &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn wrong_token_returns_401() {
        let state = state_with_token("correct").await;
        let err = require_admin_token(&headers_with_bearer("wrong"), &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn correct_token_returns_ok() {
        let state = state_with_token("secret").await;
        assert!(require_admin_token(&headers_with_bearer("secret"), &state).is_ok());
    }

    #[tokio::test]
    async fn non_utf8_authorization_header_returns_401() {
        // Exercises the inspect_err / treat-as-absent path.
        // HeaderValue::from_bytes accepts arbitrary bytes; to_str() will fail on \xff.
        let state = state_with_token("secret").await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
        );
        let err = require_admin_token(&headers, &state).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // ── require_pending_session tests ────────────────────────────────────────

    #[tokio::test]
    async fn pending_session_missing_authorization_header_returns_401() {
        let state = test_state().await;
        let err = require_pending_session(&HeaderMap::new(), &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn pending_session_non_base64url_token_returns_401() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer not-valid-base64url!!!".parse().unwrap(),
        );
        let state = test_state().await;
        let err = require_pending_session(&headers, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn pending_session_valid_unexpired_session_returns_ok() {
        use crate::token::generate_token;
        use uuid::Uuid;

        let state = test_state().await;

        // Set up a claim code, pending account, device, and pending session.
        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert claim_code");

        let account_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(format!("test{}@example.com", &account_id[..8]))
        .bind(format!("test{}.example.com", &account_id[..8]))
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert pending_account");

        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'test_pubkey', 'test_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .execute(&state.db)
        .await
        .expect("insert device");

        // Generate a valid session token.
        let token = generate_token();

        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert pending_session");

        // Call require_pending_session with valid token.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
        );

        let result = require_pending_session(&headers, &state.db)
            .await
            .expect("valid session should succeed");
        assert_eq!(result.account_id, account_id);
        assert_eq!(result.device_id, device_id);
    }

    #[tokio::test]
    async fn pending_session_expired_session_returns_401() {
        use crate::token::generate_token;
        use uuid::Uuid;

        let state = test_state().await;

        // Set up claim code, pending account, device, and expired pending session.
        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert claim_code");

        let account_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(format!("test{}@example.com", &account_id[..8]))
        .bind(format!("test{}.example.com", &account_id[..8]))
        .bind(&claim_code)
        .execute(&state.db)
        .await
        .expect("insert pending_account");

        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'test_pubkey', 'test_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .execute(&state.db)
        .await
        .expect("insert device");

        // Generate a token but set it as expired.
        let token = generate_token();

        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '-1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert pending_session");

        // Call require_pending_session with expired token.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
        );

        let err = require_pending_session(&headers, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn pending_session_non_utf8_authorization_header_returns_401() {
        // Exercises the inspect_err / treat-as-absent path.
        // HeaderValue::from_bytes accepts arbitrary bytes; to_str() will fail on \xff.
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
        );
        let err = require_pending_session(&headers, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // ── require_session tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn session_missing_authorization_header_returns_401() {
        let state = test_state().await;
        let err = require_session(&HeaderMap::new(), &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn session_non_base64url_token_returns_401() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer not-valid-base64url!!!".parse().unwrap(),
        );
        let state = test_state().await;
        let err = require_session(&headers, &state.db).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn session_valid_unexpired_session_returns_ok() {
        use crate::token::generate_token;
        use uuid::Uuid;

        let state = test_state().await;

        // Insert an account (required by sessions FK constraint).
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("test{}@example.com", &did[8..16]))
        .execute(&state.db)
        .await
        .expect("insert account");

        let token = generate_token();

        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert session");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
        );

        let result = require_session(&headers, &state.db)
            .await
            .expect("valid session should succeed");
        assert_eq!(result.did, did);
    }

    #[tokio::test]
    async fn session_expired_session_returns_401() {
        use crate::token::generate_token;
        use uuid::Uuid;

        let state = test_state().await;

        // Insert an account (required by sessions FK constraint).
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("test{}@example.com", &did[8..16]))
        .execute(&state.db)
        .await
        .expect("insert account");

        let token = generate_token();

        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '-1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(&state.db)
        .await
        .expect("insert expired session");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token.plaintext).parse().unwrap(),
        );

        let err = require_session(&headers, &state.db).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // ── require_device_token tests ────────────────────────────────────────────

    use crate::routes::test_utils::seed_device;

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn device_token_missing_authorization_header_returns_401() {
        let state = test_state().await;
        let (device_id, _) = seed_device(&state.db).await;
        let err = require_device_token(&HeaderMap::new(), &device_id, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn device_token_wrong_token_returns_401() {
        let state = test_state().await;
        let (device_id, _) = seed_device(&state.db).await;
        // Generate a fresh token that was never stored in DB
        let wrong_token = crate::token::generate_token().plaintext;
        let err = require_device_token(&bearer(&wrong_token), &device_id, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn device_token_valid_token_wrong_device_id_returns_401() {
        let state = test_state().await;
        let (_, token) = seed_device(&state.db).await;
        let err = require_device_token(&bearer(&token), "non-existent-device-id", &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn device_token_valid_token_and_device_id_returns_ok() {
        let state = test_state().await;
        let (device_id, token) = seed_device(&state.db).await;
        require_device_token(&bearer(&token), &device_id, &state.db)
            .await
            .expect("valid device token must succeed");
    }

    #[tokio::test]
    async fn device_token_malformed_base64_returns_401() {
        // "!!!" is not valid base64url — hash_bearer_token must reject it before any DB query.
        let state = test_state().await;
        let (device_id, _) = seed_device(&state.db).await;
        let err = require_device_token(&bearer("!!!not-base64url!!!"), &device_id, &state.db)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }
}

#[cfg(test)]
mod device_registration_tests {
    use super::*;
    use crate::routes::test_utils::sign_p256;

    #[test]
    fn sign_string_is_newline_separated() {
        // Pins the wire format so the signing client stays in lockstep.
        assert_eq!(
            device_registration_sign_string("CODE", "did:key:zABC", 1700),
            "CODE\ndid:key:zABC\n1700"
        );
    }

    #[test]
    fn verify_accepts_matching_self_signature() {
        let keypair = crypto::generate_p256_keypair().unwrap();
        let message = device_registration_sign_string("PAIR", &keypair.key_id.0, 1700);
        let signature = sign_p256(&keypair, message.as_bytes());
        assert!(verify_device_self_signature("PAIR", &keypair.key_id.0, 1700, &signature).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_signing_key_with_generic_401() {
        let advertised = crypto::generate_p256_keypair().unwrap();
        let attacker = crypto::generate_p256_keypair().unwrap();
        let message = device_registration_sign_string("PAIR", &advertised.key_id.0, 1700);
        let signature = sign_p256(&attacker, message.as_bytes());
        let err = verify_device_self_signature("PAIR", &advertised.key_id.0, 1700, &signature)
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
        assert_eq!(
            err.to_string(),
            format!("Unauthorized: {INVALID_REGISTRATION_CREDENTIALS}")
        );
    }

    #[test]
    fn verify_rejects_tampered_field_with_generic_401() {
        // Signature covers timestamp 1700; verifying against 1701 must fail.
        let keypair = crypto::generate_p256_keypair().unwrap();
        let message = device_registration_sign_string("PAIR", &keypair.key_id.0, 1700);
        let signature = sign_p256(&keypair, message.as_bytes());
        let err =
            verify_device_self_signature("PAIR", &keypair.key_id.0, 1701, &signature).unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[test]
    fn verify_rejects_malformed_signature_with_generic_401() {
        let keypair = crypto::generate_p256_keypair().unwrap();
        let err = verify_device_self_signature("PAIR", &keypair.key_id.0, 1700, "not-base64url!!!")
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
        assert_eq!(
            err.to_string(),
            format!("Unauthorized: {INVALID_REGISTRATION_CREDENTIALS}")
        );
    }
}

#[cfg(test)]
mod require_admin_tests {
    use super::*;

    use crate::app::{test_state, AppState};
    use crate::db::admin_devices::{insert_device, revoke_device, NewAdminDevice};
    use crate::routes::test_utils::sign_p256;

    const METHOD: &str = "POST";
    const PATH: &str = "/v1/accounts/claim-codes";
    const BODY: &[u8] = br#"{"count":1}"#;

    /// Seed an active admin device, returning its id and the keypair that signs for it.
    async fn seed_admin_device(state: &AppState) -> (String, crypto::P256Keypair) {
        let keypair = crypto::generate_p256_keypair().expect("keypair");
        let device_id = uuid::Uuid::new_v4().to_string();
        insert_device(
            &state.db,
            &NewAdminDevice {
                id: &device_id,
                label: "Operator iPhone",
                public_key: &keypair.key_id.0,
                platform: "ios",
            },
        )
        .await
        .expect("insert device");
        (device_id, keypair)
    }

    /// Build a fully-signed set of `X-Admin-*` headers for the given envelope inputs.
    fn signed_headers(
        device_id: &str,
        keypair: &crypto::P256Keypair,
        method: &str,
        path: &str,
        timestamp: i64,
        nonce: &str,
        body: &[u8],
    ) -> HeaderMap {
        let sign_string = admin_request_sign_string(method, path, timestamp, nonce, body);
        let signature = sign_p256(keypair, sign_string.as_bytes());
        let mut h = HeaderMap::new();
        h.insert(ADMIN_DEVICE_HEADER, device_id.parse().unwrap());
        h.insert(
            ADMIN_TIMESTAMP_HEADER,
            timestamp.to_string().parse().unwrap(),
        );
        h.insert(ADMIN_NONCE_HEADER, nonce.parse().unwrap());
        h.insert(ADMIN_SIGNATURE_HEADER, signature.parse().unwrap());
        h
    }

    #[test]
    fn sign_string_is_newline_separated_with_body_hash() {
        // Pins the wire format so the signing client stays in lockstep. The final
        // field is the lowercase hex SHA-256 of the body (empty body shown here).
        let empty_hash = crate::token::sha256_hex(b"");
        assert_eq!(
            admin_request_sign_string("POST", "/x", 1700, "abc", b""),
            format!("POST\n/x\n1700\nabc\n{empty_hash}")
        );
    }

    #[tokio::test]
    async fn master_token_still_authorizes() {
        // No X-Admin-* headers → master-token path is taken, unchanged.
        let mut state = test_state().await;
        let config = std::sync::Arc::make_mut(&mut state.config);
        config.admin_token = Some(common::Sensitive("secret".to_string()));

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer secret".parse().unwrap(),
        );
        let actor = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .expect("master token must authorize");
        assert_eq!(actor, AdminActor::MasterToken);
        assert_eq!(actor.as_log_str(), "master-token");
    }

    #[tokio::test]
    async fn master_token_accepted_even_with_device_header_present() {
        // A valid master token authorizes regardless of a (here malformed) device
        // header — preserving the "master token OR device signature" contract.
        let mut state = test_state().await;
        let config = std::sync::Arc::make_mut(&mut state.config);
        config.admin_token = Some(common::Sensitive("secret".to_string()));

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer secret".parse().unwrap(),
        );
        headers.insert(ADMIN_DEVICE_HEADER, "garbage-device".parse().unwrap());

        require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .expect("master token must authorize even with a device header present");
    }

    #[tokio::test]
    async fn extreme_timestamp_is_rejected_without_panicking() {
        // An i64::MIN timestamp would overflow a naive `now - timestamp`; the saturating
        // bounds must reject it cleanly with a 401 rather than panic.
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        let headers = signed_headers(
            &device_id,
            &keypair,
            METHOD,
            PATH,
            i64::MIN,
            "nonce-extreme",
            BODY,
        );
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn correctly_signed_device_request_authorizes() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        let headers = signed_headers(
            &device_id,
            &keypair,
            METHOD,
            PATH,
            unix_now_secs(),
            "nonce-ok",
            BODY,
        );
        let actor = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .expect("a valid device signature must authorize");
        assert_eq!(actor, AdminActor::Device(device_id.clone()));
        assert_eq!(actor.as_log_str(), format!("device:{device_id}"));
    }

    #[tokio::test]
    async fn signature_over_different_method_is_rejected() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        // Sign for GET, present as POST.
        let headers = signed_headers(
            &device_id,
            &keypair,
            "GET",
            PATH,
            unix_now_secs(),
            "nonce-m",
            BODY,
        );
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn signature_over_different_path_is_rejected() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        let headers = signed_headers(
            &device_id,
            &keypair,
            METHOD,
            "/v1/pds/keys",
            unix_now_secs(),
            "nonce-p",
            BODY,
        );
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn signature_over_different_body_is_rejected() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        // Sign over a different body than the one presented for verification.
        let headers = signed_headers(
            &device_id,
            &keypair,
            METHOD,
            PATH,
            unix_now_secs(),
            "nonce-b",
            br#"{"count":10}"#,
        );
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn timestamp_outside_window_is_rejected() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        // 120s in the past — beyond the ±60s window. Signature is otherwise valid.
        let stale = unix_now_secs() - 120;
        let headers = signed_headers(&device_id, &keypair, METHOD, PATH, stale, "nonce-t", BODY);
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn reused_nonce_is_rejected_second_time() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        let ts = unix_now_secs();
        let headers = signed_headers(&device_id, &keypair, METHOD, PATH, ts, "nonce-dup", BODY);

        // First use within the window is accepted exactly once...
        require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .expect("first use of a fresh nonce is accepted");
        // ...a second presentation of the same nonce is a replay.
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn distinct_nonces_within_window_each_accepted() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        let ts = unix_now_secs();
        for nonce in ["n-1", "n-2"] {
            let headers = signed_headers(&device_id, &keypair, METHOD, PATH, ts, nonce, BODY);
            require_admin(METHOD, PATH, &headers, BODY, &state)
                .await
                .unwrap_or_else(|_| panic!("distinct nonce {nonce} must be accepted"));
        }
    }

    #[tokio::test]
    async fn revoked_device_is_rejected_with_403() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        revoke_device(&state.db, &device_id).await.unwrap();

        let headers = signed_headers(
            &device_id,
            &keypair,
            METHOD,
            PATH,
            unix_now_secs(),
            "nonce-rev",
            BODY,
        );
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(
            err.status_code(),
            403,
            "a revoked device is denied with 403, not the generic 401"
        );
    }

    #[tokio::test]
    async fn unknown_device_is_rejected_with_401() {
        let state = test_state().await;
        let keypair = crypto::generate_p256_keypair().unwrap();
        let headers = signed_headers(
            "no-such-device",
            &keypair,
            METHOD,
            PATH,
            unix_now_secs(),
            "nonce-u",
            BODY,
        );
        let err = require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn last_seen_at_is_bumped_after_auth() {
        let state = test_state().await;
        let (device_id, keypair) = seed_admin_device(&state).await;
        assert!(crate::db::admin_devices::get_device(&state.db, &device_id)
            .await
            .unwrap()
            .unwrap()
            .last_seen_at
            .is_none());

        let headers = signed_headers(
            &device_id,
            &keypair,
            METHOD,
            PATH,
            unix_now_secs(),
            "nonce-seen",
            BODY,
        );
        require_admin(METHOD, PATH, &headers, BODY, &state)
            .await
            .unwrap();

        assert!(
            crate::db::admin_devices::get_device(&state.db, &device_id)
                .await
                .unwrap()
                .unwrap()
                .last_seen_at
                .is_some(),
            "authenticating bumps last_seen_at"
        );
    }
}
