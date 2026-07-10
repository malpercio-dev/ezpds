// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), JSON body / query, DB pool
// Processes: auth check → input validation → claim-code mint / inventory list / revoke
// Returns: JSON on success; ApiError on all failure paths

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::{require_admin, require_admin_json};
use crate::code_gen::generate_code;
use crate::db::claim_codes::{list_claim_codes, revoke_claim_code, RevokeClaimCodeOutcome};
use crate::db::is_unique_violation;

const MAX_COUNT: u32 = 10;
const MAX_LIST_LIMIT: u32 = 200;

fn default_list_limit() -> u32 {
    50
}

fn default_expires_in_hours() -> u32 {
    24
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimCodesRequest {
    count: u32,
    #[serde(default = "default_expires_in_hours")]
    expires_in_hours: u32,
}

#[derive(Serialize)]
pub struct ClaimCodesResponse {
    /// 6-character uppercase alphanumeric strings, unique within this batch.
    codes: Vec<String>,
}

/// `POST /v1/accounts/claim-codes` — admin-only claim-code minting.
///
/// Auth runs first, over the raw body, so the canonical signature envelope can bind
/// the exact request bytes (and so unauthenticated callers learn nothing about the
/// body schema). Only after auth passes is the body parsed as JSON — using
/// `Json::from_bytes` so malformed/invalid bodies return the same 400/422 statuses
/// the `Json` extractor produced before this route accepted device signatures.
pub async fn claim_codes(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ClaimCodesResponse>, Response> {
    require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let Json(payload) =
        Json::<ClaimCodesRequest>::from_bytes(&body).map_err(IntoResponse::into_response)?;

    claim_codes_inner(&state, payload)
        .await
        .map_err(IntoResponse::into_response)
}

async fn claim_codes_inner(
    state: &AppState,
    payload: ClaimCodesRequest,
) -> Result<Json<ClaimCodesResponse>, ApiError> {
    // --- Validate input ---
    if payload.count == 0 || payload.count > MAX_COUNT {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            format!("count must be between 1 and {MAX_COUNT}"),
        ));
    }
    if payload.expires_in_hours == 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "expiresInHours must be greater than 0",
        ));
    }

    // --- Generate unique codes and insert in a single transaction ---
    // Attempt up to 3 times total (2 retries) on the rare event of a uniqueness
    // conflict with an existing DB row (probability ≈ existing_codes / 36^6 per code).
    for attempt in 0..3_usize {
        let codes = generate_unique_codes(payload.count as usize);
        match insert_claim_codes(&state.db, &codes, payload.expires_in_hours).await {
            Ok(()) => return Ok(Json(ClaimCodesResponse { codes })),
            Err(e) if is_unique_violation(&e) => {
                tracing::warn!(attempt, "claim code uniqueness conflict; retrying");
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to insert claim codes");
                return Err(ApiError::new(
                    ErrorCode::InternalError,
                    "failed to store claim codes",
                ));
            }
        }
    }

    Err(ApiError::new(
        ErrorCode::InternalError,
        "failed to generate unique claim codes after retries",
    ))
}

// ── Inventory: list + revoke ──────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListClaimCodesParams {
    #[serde(default = "default_list_limit")]
    limit: u32,
    /// `id` of the last row of the previous page (exclusive), from the prior response's
    /// `cursor`; absent for the first page.
    cursor: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimCodeView {
    code: String,
    /// Derived lifecycle: `pending` | `redeemed` | `expired` | `revoked`.
    status: &'static str,
    created_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    redeemed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListClaimCodesResponse {
    codes: Vec<ClaimCodeView>,
    /// Present when another page may exist; pass back as the `cursor` query param.
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// Collapse a row's lifecycle timestamps into the one status word the operator sees.
///
/// The states can overlap on a real row (a code redeemed before its expiry passed is now
/// both "redeemed" and past `expires_at`; a revoked code keeps aging toward expiry), so
/// this function owns the precedence order.
/// Precedence: the terminal events win over the clock. A redeemed or revoked code reports
/// that event forever — never "expired", even once `expires_at` passes — because the event
/// is the fact the operator acts on (a signup happened / a kill was ordered). `expired`
/// and `pending` apply only to codes nothing ever happened to. (`redeemed_at` and
/// `revoked_at` are never both set: the revoke UPDATE refuses a redeemed code and every
/// redemption UPDATE refuses a revoked one.)
fn derive_status(row: &crate::db::claim_codes::ClaimCodeRow) -> &'static str {
    if row.redeemed_at.is_some() {
        "redeemed"
    } else if row.revoked_at.is_some() {
        "revoked"
    } else if row.is_expired {
        "expired"
    } else {
        "pending"
    }
}

/// `GET /v1/accounts/claim-codes` — admin-only claim-code inventory.
///
/// Pages the full mint history newest-first (`id` cursor — a stable INTEGER PRIMARY KEY,
/// V041), each row carrying its derived
/// lifecycle status. A minted-but-unredeemed code is a live signup credential — this is the
/// operator's view of what is outstanding. Admin-authed: the master token **or** an active
/// companion-app device's signed request ([`require_admin`]); a GET signs the empty body.
pub async fn list_claim_code_inventory(
    State(state): State<AppState>,
    Query(params): Query<ListClaimCodesParams>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ListClaimCodesResponse>, ApiError> {
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    if params.limit == 0 || params.limit > MAX_LIST_LIMIT {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("limit must be between 1 and {MAX_LIST_LIMIT}"),
        ));
    }

    let rows = list_claim_codes(&state.db, params.cursor, params.limit)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to list claim codes");
            ApiError::new(ErrorCode::InternalError, "failed to list claim codes")
        })?;

    // A short page means the history is exhausted; a full page may have more.
    let cursor = (rows.len() == params.limit as usize)
        .then(|| rows.last().map(|r| r.id.to_string()))
        .flatten();
    let codes = rows
        .iter()
        .map(|row| ClaimCodeView {
            code: row.code.clone(),
            status: derive_status(row),
            created_at: row.created_at.clone(),
            expires_at: row.expires_at.clone(),
            redeemed_at: row.redeemed_at.clone(),
            revoked_at: row.revoked_at.clone(),
        })
        .collect();

    Ok(Json(ListClaimCodesResponse { codes, cursor }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeClaimCodeRequest {
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeClaimCodeResponse {
    code: String,
    status: &'static str,
}

/// `POST /v1/accounts/claim-codes/revoke` — admin-only claim-code revocation.
///
/// The code travels in the JSON body, not the path: it is a live credential, and request
/// paths leak into places bodies don't (access logs, tracing spans). Idempotent for an
/// already-revoked code (200, like the device revoke route); a **redeemed** code is 409 —
/// there is nothing live to kill, and pretending otherwise would hide a signup that already
/// happened. Unknown codes are 404.
pub async fn revoke_claim_code_route(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RevokeClaimCodeResponse>, Response> {
    require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await?;
    let Json(payload) =
        Json::<RevokeClaimCodeRequest>::from_bytes(&body).map_err(IntoResponse::into_response)?;

    revoke_inner(&state, payload)
        .await
        .map_err(IntoResponse::into_response)
}

async fn revoke_inner(
    state: &AppState,
    payload: RevokeClaimCodeRequest,
) -> Result<Json<RevokeClaimCodeResponse>, ApiError> {
    let outcome = revoke_claim_code(&state.db, &payload.code)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to revoke claim code");
            ApiError::new(ErrorCode::InternalError, "failed to revoke claim code")
        })?;

    match outcome {
        RevokeClaimCodeOutcome::Revoked | RevokeClaimCodeOutcome::AlreadyRevoked => {
            Ok(Json(RevokeClaimCodeResponse {
                code: payload.code,
                status: "revoked",
            }))
        }
        RevokeClaimCodeOutcome::Redeemed => Err(ApiError::new(
            ErrorCode::Conflict,
            "code has already been redeemed",
        )),
        RevokeClaimCodeOutcome::NotFound => {
            Err(ApiError::new(ErrorCode::NotFound, "unknown claim code"))
        }
    }
}

/// Generate `count` unique codes, ensuring no duplicates within the batch.
fn generate_unique_codes(count: usize) -> Vec<String> {
    let mut codes = std::collections::HashSet::with_capacity(count);
    while codes.len() < count {
        codes.insert(generate_code());
    }
    codes.into_iter().collect()
}

/// Insert all codes in a single transaction; returns Err if any INSERT fails.
async fn insert_claim_codes(
    db: &sqlx::SqlitePool,
    codes: &[String],
    expires_in_hours: u32,
) -> Result<(), sqlx::Error> {
    let offset = format!("+{expires_in_hours} hours");
    let mut tx = db.begin().await.inspect_err(|e| {
        tracing::error!(error = %e, "failed to begin claim_codes transaction");
    })?;
    for code in codes {
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', ?), datetime('now'))",
        )
        .bind(code)
        .bind(&offset)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await.inspect_err(|e| {
        tracing::error!(error = %e, "failed to commit claim_codes transaction");
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::test_state_with_admin_token;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn post_claim_codes(body: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/accounts/claim-codes")
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn returns_200_with_one_code() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"count": 1, "expiresInHours": 24}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let codes = json["codes"].as_array().unwrap();
        assert_eq!(codes.len(), 1);
    }

    #[tokio::test]
    async fn returns_ten_codes_for_batch() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"count": 10, "expiresInHours": 24}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["codes"].as_array().unwrap().len(), 10);
    }

    #[tokio::test]
    async fn defaults_expires_in_hours_to_24() {
        // expiresInHours is optional; default = 24h
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post_claim_codes(
                r#"{"count": 1}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let code = json["codes"][0].as_str().unwrap();

        let expires_at: String =
            sqlx::query_scalar("SELECT expires_at FROM claim_codes WHERE code = ?")
                .bind(code)
                .fetch_one(&db)
                .await
                .unwrap();

        // Verify expires_at is within 5 seconds of 24h from now.
        let within_window: bool = sqlx::query_scalar(
            "SELECT ABS(strftime('%s', ?) - strftime('%s', datetime('now', '+24 hours'))) < 5",
        )
        .bind(&expires_at)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            within_window,
            "expires_at must be approximately 24h from now"
        );
    }

    // ── Code format ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn codes_are_6_char_uppercase_alphanumeric() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"count": 5, "expiresInHours": 1}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for code in json["codes"].as_array().unwrap() {
            let s = code.as_str().unwrap();
            assert_eq!(s.len(), 6, "code must be 6 chars, got: {s}");
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "code must be uppercase alphanumeric, got: {s}"
            );
        }
    }

    #[tokio::test]
    async fn codes_in_batch_are_unique() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"count": 10, "expiresInHours": 1}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let codes: Vec<&str> = json["codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let unique: std::collections::HashSet<&&str> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "codes within a batch must be unique"
        );
    }

    // ── DB persistence ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn codes_persisted_in_db_with_pending_status() {
        // stored with redeemed_at NULL (pending) and correct expiry
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post_claim_codes(
                r#"{"count": 2, "expiresInHours": 48}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for code in json["codes"].as_array().unwrap() {
            let code_str = code.as_str().unwrap();
            let row: (String, Option<String>) =
                sqlx::query_as("SELECT expires_at, redeemed_at FROM claim_codes WHERE code = ?")
                    .bind(code_str)
                    .fetch_one(&db)
                    .await
                    .expect("code must exist in DB");

            assert!(
                row.1.is_none(),
                "redeemed_at must be NULL for a freshly generated code"
            );

            // expires_at must be approximately 48h from now (within 5 seconds).
            let within_window: bool = sqlx::query_scalar(
                "SELECT ABS(strftime('%s', ?) - strftime('%s', datetime('now', '+48 hours'))) < 5",
            )
            .bind(&row.0)
            .fetch_one(&db)
            .await
            .unwrap();
            assert!(
                within_window,
                "expires_at must be approximately 48h from now"
            );
        }
    }

    // ── Retry / DB error paths ────────────────────────────────────────────────

    #[tokio::test]
    async fn non_unique_db_error_returns_500_without_retry() {
        // Closing the pool before the request causes db.begin() to fail with a
        // non-unique-violation error. The handler must return 500 immediately
        // (no retry) and must not panic.
        let state = test_state_with_admin_token().await;
        state.db.close().await;

        let response = app(state)
            .oneshot(post_claim_codes(
                r#"{"count": 1, "expiresInHours": 24}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── Input validation ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn count_zero_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"count": 0, "expiresInHours": 24}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn count_eleven_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"count": 11, "expiresInHours": 24}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn expires_in_hours_zero_returns_400() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"count": 1, "expiresInHours": 0}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_count_returns_422() {
        // serde rejects missing required field
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(
                r#"{"expiresInHours": 24}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_authorization_header_returns_401() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(r#"{"count": 1}"#, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_bearer_token_returns_401() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_claim_codes(r#"{"count": 1}"#, Some("wrong-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bare_token_without_bearer_prefix_returns_401() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/accounts/claim-codes")
            .header("Content-Type", "application/json")
            .header("Authorization", "test-admin-token") // no "Bearer " prefix
            .body(Body::from(r#"{"count": 1}"#))
            .unwrap();

        let response = app(test_state_with_admin_token().await)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_json_content_type_returns_415() {
        // Valid JSON body + valid token, but a non-JSON media type: matches the former
        // `Json` extractor's 415 rejection.
        let request = Request::builder()
            .method("POST")
            .uri("/v1/accounts/claim-codes")
            .header("Content-Type", "text/plain")
            .header("Authorization", "Bearer test-admin-token")
            .body(Body::from(r#"{"count": 1}"#))
            .unwrap();
        let response = app(test_state_with_admin_token().await)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn admin_token_not_configured_returns_401() {
        // test_state() leaves admin_token as None
        let response = app(test_state().await)
            .oneshot(post_claim_codes(
                r#"{"count": 1}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Device signed-request auth (end-to-end) ────────────────────────────────

    #[tokio::test]
    async fn signed_device_request_mints_a_code() {
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        // A state with NO master token: proves the device path is independent of it.
        let state = test_state().await;
        let keypair = crypto::generate_p256_keypair().unwrap();
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
        .unwrap();

        let body = r#"{"count":2,"expiresInHours":24}"#;
        let path = "/v1/accounts/claim-codes";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = "e2e-nonce-1";
        let sign_string = admin_request_sign_string("POST", path, ts, nonce, body.as_bytes());
        let signature = crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes());

        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .header(ADMIN_DEVICE_HEADER, &device_id)
            .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
            .header(ADMIN_NONCE_HEADER, nonce)
            .header(ADMIN_SIGNATURE_HEADER, signature)
            .body(Body::from(body))
            .unwrap();

        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .map(|b| serde_json::from_slice::<serde_json::Value>(&b).unwrap())
            .unwrap();
        assert_eq!(json["codes"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn signed_device_request_with_tampered_body_is_rejected() {
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = test_state().await;
        let keypair = crypto::generate_p256_keypair().unwrap();
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
        .unwrap();

        let path = "/v1/accounts/claim-codes";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = "e2e-nonce-2";
        // Sign over count:1 but send count:9 — the body hash will not match.
        let sign_string = admin_request_sign_string("POST", path, ts, nonce, br#"{"count":1}"#);
        let signature = crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes());

        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .header(ADMIN_DEVICE_HEADER, &device_id)
            .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
            .header(ADMIN_NONCE_HEADER, nonce)
            .header(ADMIN_SIGNATURE_HEADER, signature)
            .body(Body::from(r#"{"count":9}"#))
            .unwrap();

        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Inventory: list ───────────────────────────────────────────────────────

    /// Insert one code directly with explicit lifecycle timestamps.
    async fn seed_code(
        db: &sqlx::SqlitePool,
        code: &str,
        expires_offset: &str,
        redeemed: bool,
        revoked: bool,
    ) {
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at, redeemed_at, revoked_at) \
             VALUES (?, datetime('now', ?), datetime('now'), \
                     CASE WHEN ? THEN datetime('now') END, \
                     CASE WHEN ? THEN datetime('now') END)",
        )
        .bind(code)
        .bind(expires_offset)
        .bind(redeemed)
        .bind(revoked)
        .execute(db)
        .await
        .expect("seed claim code");
    }

    fn get_inventory(query: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri(format!("/v1/accounts/claim-codes{query}"));
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn list_reports_derived_status_newest_first() {
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();
        seed_code(&db, "WAITIN", "+24 hours", false, false).await;
        seed_code(&db, "LAPSED", "-1 hours", false, false).await;
        // Terminal events beat the clock: both of these are past expiry, but they must
        // report the event, never "expired".
        seed_code(&db, "SPENT1", "-1 hours", true, false).await;
        seed_code(&db, "KILLED", "-1 hours", false, true).await;

        let response = app(state)
            .oneshot(get_inventory("", Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        let codes = json["codes"].as_array().unwrap();
        let by_code: std::collections::HashMap<&str, &str> = codes
            .iter()
            .map(|c| (c["code"].as_str().unwrap(), c["status"].as_str().unwrap()))
            .collect();
        assert_eq!(by_code["WAITIN"], "pending");
        assert_eq!(by_code["LAPSED"], "expired");
        assert_eq!(by_code["SPENT1"], "redeemed");
        assert_eq!(by_code["KILLED"], "revoked");

        // Newest-first: last seeded comes back first.
        assert_eq!(codes[0]["code"], "KILLED");
        assert_eq!(codes[3]["code"], "WAITIN");
        // A short page carries no cursor.
        assert!(json.get("cursor").is_none());
    }

    #[tokio::test]
    async fn list_pages_with_cursor() {
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();
        for code in ["CODE01", "CODE02", "CODE03"] {
            seed_code(&db, code, "+24 hours", false, false).await;
        }

        let first = app(state.clone())
            .oneshot(get_inventory("?limit=2", Some("test-admin-token")))
            .await
            .unwrap();
        let first_json = body_json(first).await;
        assert_eq!(first_json["codes"].as_array().unwrap().len(), 2);
        assert_eq!(first_json["codes"][0]["code"], "CODE03");
        let cursor = first_json["cursor"].as_str().unwrap().to_string();

        let second = app(state)
            .oneshot(get_inventory(
                &format!("?limit=2&cursor={cursor}"),
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        let second_json = body_json(second).await;
        assert_eq!(second_json["codes"].as_array().unwrap().len(), 1);
        assert_eq!(second_json["codes"][0]["code"], "CODE01");
        assert!(second_json.get("cursor").is_none());
    }

    #[tokio::test]
    async fn list_rejects_invalid_limit() {
        let state = test_state_with_admin_token().await;
        for query in ["?limit=0", "?limit=201"] {
            let response = app(state.clone())
                .oneshot(get_inventory(query, Some("test-admin-token")))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query {query}");
        }
    }

    #[tokio::test]
    async fn list_requires_admin() {
        let state = test_state_with_admin_token().await;
        let missing = app(state.clone())
            .oneshot(get_inventory("", None))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let wrong = app(state)
            .oneshot(get_inventory("", Some("wrong-token")))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_accepts_signed_device_request() {
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = test_state().await;
        seed_code(&state.db, "WAITIN", "+24 hours", false, false).await;
        let keypair = crypto::generate_p256_keypair().unwrap();
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
        .unwrap();

        // A GET signs the empty body; the query string is not part of the signed path.
        let path = "/v1/accounts/claim-codes";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = "inventory-nonce-1";
        let sign_string = admin_request_sign_string("GET", path, ts, nonce, b"");
        let signature = crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes());

        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header(ADMIN_DEVICE_HEADER, &device_id)
            .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
            .header(ADMIN_NONCE_HEADER, nonce)
            .header(ADMIN_SIGNATURE_HEADER, signature)
            .body(Body::empty())
            .unwrap();

        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["codes"][0]["code"], "WAITIN");
    }

    // ── Inventory: revoke ─────────────────────────────────────────────────────

    fn post_revoke(body: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/accounts/claim-codes/revoke")
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn revoke_pending_code_returns_revoked_and_closes_redemption() {
        let state = test_state_with_admin_token().await;
        let db = state.db.clone();
        seed_code(&db, "LIVE01", "+24 hours", false, false).await;

        let response = app(state)
            .oneshot(post_revoke(
                r#"{"code": "LIVE01"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["code"], "LIVE01");
        assert_eq!(json["status"], "revoked");

        assert!(
            !crate::db::claim_codes::claim_code_valid(&db, "LIVE01")
                .await
                .unwrap(),
            "a revoked code must no longer pass the redemption preflight"
        );
    }

    #[tokio::test]
    async fn revoke_is_idempotent() {
        let state = test_state_with_admin_token().await;
        seed_code(&state.db, "LIVE01", "+24 hours", false, false).await;

        for _ in 0..2 {
            let response = app(state.clone())
                .oneshot(post_revoke(
                    r#"{"code": "LIVE01"}"#,
                    Some("test-admin-token"),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn revoke_redeemed_code_returns_409() {
        let state = test_state_with_admin_token().await;
        seed_code(&state.db, "SPENT1", "+24 hours", true, false).await;

        let response = app(state)
            .oneshot(post_revoke(
                r#"{"code": "SPENT1"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn revoke_unknown_code_returns_404() {
        let response = app(test_state_with_admin_token().await)
            .oneshot(post_revoke(
                r#"{"code": "GHOST1"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn revoke_requires_admin() {
        let state = test_state_with_admin_token().await;
        seed_code(&state.db, "LIVE01", "+24 hours", false, false).await;

        let missing = app(state.clone())
            .oneshot(post_revoke(r#"{"code": "LIVE01"}"#, None))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let wrong = app(state)
            .oneshot(post_revoke(r#"{"code": "LIVE01"}"#, Some("wrong-token")))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_accepts_signed_device_request() {
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = test_state().await;
        seed_code(&state.db, "LIVE01", "+24 hours", false, false).await;
        let keypair = crypto::generate_p256_keypair().unwrap();
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
        .unwrap();

        let body = r#"{"code":"LIVE01"}"#;
        let path = "/v1/accounts/claim-codes/revoke";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = "revoke-nonce-1";
        let sign_string = admin_request_sign_string("POST", path, ts, nonce, body.as_bytes());
        let signature = crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes());

        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .header(ADMIN_DEVICE_HEADER, &device_id)
            .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
            .header(ADMIN_NONCE_HEADER, nonce)
            .header(ADMIN_SIGNATURE_HEADER, signature)
            .body(Body::from(body))
            .unwrap();

        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["status"], "revoked");
    }

    #[tokio::test]
    async fn wrong_content_type_does_not_consume_signed_request_nonce() {
        // The media-type guard runs before signature verification, so a wrong
        // Content-Type returns 415 without burning the nonce — the corrected retry
        // with the same signed request (same nonce) must still succeed.
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = test_state().await;
        let keypair = crypto::generate_p256_keypair().unwrap();
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
        .unwrap();

        let body = r#"{"count":1}"#;
        let path = "/v1/accounts/claim-codes";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = "ct-order-nonce";
        let sign_string = admin_request_sign_string("POST", path, ts, nonce, body.as_bytes());
        let signature = crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes());

        let build = |content_type: &str| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Content-Type", content_type)
                .header(ADMIN_DEVICE_HEADER, device_id.as_str())
                .header(ADMIN_TIMESTAMP_HEADER, ts.to_string())
                .header(ADMIN_NONCE_HEADER, nonce)
                .header(ADMIN_SIGNATURE_HEADER, signature.as_str())
                .body(Body::from(body))
                .unwrap()
        };

        // Wrong media type → 415, and the nonce must not be consumed.
        let r1 = app(state.clone())
            .oneshot(build("text/plain"))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // The corrected retry reusing the same nonce succeeds (nonce was not burned).
        let r2 = app(state).oneshot(build("application/json")).await.unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }
}
