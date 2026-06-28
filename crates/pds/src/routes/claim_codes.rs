// pattern: Imperative Shell
//
// Gathers: admin Bearer token (Authorization header), JSON request body, DB pool
// Processes: auth check → input validation → code generation → DB batch insert (transaction)
// Returns: JSON { codes: [...] } on success; ApiError on all failure paths

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::is_unique_violation;
use crate::routes::auth::require_admin_json;
use crate::routes::code_gen::generate_code;

const MAX_COUNT: u32 = 10;

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
    require_admin_json(method.as_str(), uri.path(), &headers, &body, &state)
        .await?;

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
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use crate::routes::auth::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
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
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use crate::routes::auth::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
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
}
