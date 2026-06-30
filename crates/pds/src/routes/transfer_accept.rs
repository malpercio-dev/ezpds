// pattern: Imperative Shell
//
// Gathers: JSON request body (transfer code, new device public key, platform), DB pool
// Processes: key/platform validation → generate new device credentials → atomic transfer
//            accept + promoted-device credential insert
// Returns: JSON { transferId, status, deviceId, deviceToken } on success; ApiError on
//          invalid/expired code, already-accepted transfer, or storage failure
//
// Implements: POST /v1/transfer/accept

use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::transfers::{accept_transfer as accept_transfer_row, AcceptOutcome};
use crate::routes::token::generate_token;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptTransferRequest {
    #[serde(alias = "transfer_code", alias = "code")]
    transfer_code: String,
    #[serde(alias = "device_public_key")]
    device_public_key: String,
    platform: Platform,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptTransferResponse {
    transfer_id: String,
    status: String,
    device_id: String,
    device_token: String,
}

/// Supported device platforms for the new transfer target device.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Platform {
    Ios,
    Android,
    Macos,
    Linux,
    Windows,
}

impl Platform {
    fn as_str(&self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
            Platform::Macos => "macos",
            Platform::Linux => "linux",
            Platform::Windows => "windows",
        }
    }
}

/// POST /v1/transfer/accept
///
/// The transfer code is the only authorization credential: a new device that knows a
/// still-pending, unexpired code can join the planned device swap. Acceptance registers
/// fresh device credentials and advances the transfer state in one transaction so a
/// code cannot mint more than one device token.
pub async fn transfer_accept(
    State(state): State<AppState>,
    Json(payload): Json<AcceptTransferRequest>,
) -> Result<(StatusCode, Json<AcceptTransferResponse>), ApiError> {
    crate::auth::validation::validate_device_public_key(&payload.device_public_key)
        .map_err(|msg| ApiError::new(ErrorCode::InvalidClaim, msg))?;

    let device_id = Uuid::new_v4().to_string();
    let device_token = generate_token();

    let outcome = accept_transfer_row(
        &state.db,
        &payload.transfer_code,
        &device_id,
        payload.platform.as_str(),
        &payload.device_public_key,
        &device_token.hash,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to accept transfer");
        ApiError::new(ErrorCode::InternalError, "failed to accept transfer")
    })?;

    match outcome {
        AcceptOutcome::Accepted { transfer_id } => Ok((
            StatusCode::OK,
            Json(AcceptTransferResponse {
                transfer_id,
                status: "accepted".to_string(),
                device_id,
                device_token: device_token.plaintext,
            }),
        )),
        AcceptOutcome::InvalidOrExpired => Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "transfer code is invalid or expired",
        )),
        AcceptOutcome::NotPending => Err(ApiError::new(
            ErrorCode::Conflict,
            "transfer is no longer pending",
        )),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::app::{app, test_state, AppState};
    use crate::routes::test_utils::body_json;

    async fn seed_account(db: &sqlx::SqlitePool) -> String {
        let did = format!(
            "did:plc:{}",
            &Uuid::new_v4().to_string().replace('-', "")[..24]
        );
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(&did)
        .bind(format!("{}@example.com", &did[8..16]))
        .execute(db)
        .await
        .expect("insert account");
        did
    }

    async fn seed_transfer(db: &sqlx::SqlitePool, code: &str, status: &str) -> (String, String) {
        let did = seed_account(db).await;
        let transfer_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO transfers (id, did, code, status, expires_at, created_at) \
             VALUES (?, ?, ?, ?, datetime('now', '+15 minutes'), datetime('now'))",
        )
        .bind(&transfer_id)
        .bind(&did)
        .bind(code)
        .bind(status)
        .execute(db)
        .await
        .expect("insert transfer");
        (transfer_id, did)
    }

    async fn seed_expired_transfer(db: &sqlx::SqlitePool, code: &str) -> String {
        let did = seed_account(db).await;
        let transfer_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO transfers (id, did, code, status, expires_at, created_at) \
             VALUES (?, ?, ?, 'pending', datetime('now', '-1 minute'), datetime('now', '-16 minutes'))",
        )
        .bind(&transfer_id)
        .bind(&did)
        .bind(code)
        .execute(db)
        .await
        .expect("insert expired transfer");
        transfer_id
    }

    fn post_accept(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/transfer/accept")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn accept_body(code: &str) -> String {
        format!(r#"{{"transferCode":"{code}","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}}"#)
    }

    async fn accept(state: AppState, code: &str) -> axum::response::Response {
        app(state)
            .oneshot(post_accept(&accept_body(code)))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn valid_code_returns_device_credentials_and_marks_accepted() {
        let state = test_state().await;
        let db = state.db.clone();
        let (transfer_id, did) = seed_transfer(&state.db, "ABC123", "pending").await;

        let response = accept(state, "ABC123").await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["transferId"], transfer_id);
        assert_eq!(json["status"], "accepted");
        let device_id = json["deviceId"].as_str().expect("deviceId required");
        let token = json["deviceToken"].as_str().expect("deviceToken required");
        assert_eq!(token.len(), 43, "device token is base64url of 32 bytes");

        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT t.status, t.accepted_device_id, d.did, d.platform \
             FROM transfers t \
             JOIN transfer_devices d ON d.id = t.accepted_device_id \
             WHERE t.id = ?",
        )
        .bind(&transfer_id)
        .fetch_one(&db)
        .await
        .expect("accepted transfer row");
        assert_eq!(row.0, "accepted");
        assert_eq!(row.1, device_id);
        assert_eq!(row.2, did);
        assert_eq!(row.3, "ios");
    }

    #[tokio::test]
    async fn returned_device_credentials_authenticate_device_pds_lookup() {
        let state = test_state().await;
        seed_transfer(&state.db, "PDS123", "pending").await;

        let response = accept(state.clone(), "PDS123").await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let device_id = json["deviceId"].as_str().unwrap();
        let token = json["deviceToken"].as_str().unwrap();

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/devices/{device_id}/pds"))
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn snake_case_request_fields_are_accepted() {
        let state = test_state().await;
        seed_transfer(&state.db, "SNAKE1", "pending").await;

        let response = app(state)
            .oneshot(post_accept(
                r#"{"transfer_code":"SNAKE1","device_public_key":"dGVzdC1rZXk=","platform":"android"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_code_returns_400() {
        let response = accept(test_state().await, "NOPE00").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_CLAIM");
    }

    #[tokio::test]
    async fn expired_code_returns_400_and_is_swept() {
        let state = test_state().await;
        let db = state.db.clone();
        let transfer_id = seed_expired_transfer(&state.db, "OLD123").await;

        let response = accept(state, "OLD123").await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let status: String = sqlx::query_scalar("SELECT status FROM transfers WHERE id = ?")
            .bind(&transfer_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "expired");
    }

    #[tokio::test]
    async fn already_accepted_code_returns_409_and_mints_no_new_device() {
        let state = test_state().await;
        let db = state.db.clone();
        seed_transfer(&state.db, "DONE12", "pending").await;

        let first = accept(state.clone(), "DONE12").await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = accept(state, "DONE12").await;
        assert_eq!(second.status(), StatusCode::CONFLICT);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transfer_devices")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 1, "second accept must not mint another device");
    }

    #[tokio::test]
    async fn empty_public_key_returns_400() {
        let state = test_state().await;
        seed_transfer(&state.db, "KEY123", "pending").await;

        let response = app(state)
            .oneshot(post_accept(
                r#"{"transferCode":"KEY123","devicePublicKey":"","platform":"ios"}"#,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
