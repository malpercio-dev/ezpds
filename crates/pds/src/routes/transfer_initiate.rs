// pattern: Imperative Shell
//
// Gathers: Authorization header (source-device session bearer token), DB pool
// Processes: require_session → DID, generate transfer id + 6-char code, insert a
//            pending transfer session enforcing one active transfer per account
// Returns: JSON { transferId, transferCode, expiresAt, status } on success;
//          ApiError on failure (401 no session, 409 duplicate active transfer)
//
// Implements: POST /v1/transfer/initiate

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::Serialize;
use uuid::Uuid;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::transfers::{insert_transfer, InitiateOutcome};
use crate::routes::auth::require_session;
use crate::routes::code_gen::generate_code;

/// Lifetime of a transfer code, in minutes.
///
/// The canonical provisioning spec (`docs/provisioning-api-spec.md` §13) specifies 15
/// minutes; the older MM-129 summary said 10. We follow the spec.
const TRANSFER_TTL_MINUTES: i64 = 15;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiateTransferResponse {
    transfer_id: String,
    transfer_code: String,
    expires_at: String,
    status: String,
}

/// POST /v1/transfer/initiate
///
/// Begins a planned device swap. The source device authenticates with its session
/// bearer token; the authenticated DID *is* the account being transferred (no body is
/// needed — the new device does not exist yet and registers itself at `/accept`). Mints
/// a short-lived 6-character code and a `pending` transfer session. Only one active
/// transfer per account is allowed; a second concurrent attempt returns 409.
pub async fn transfer_initiate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<InitiateTransferResponse>), ApiError> {
    let session = require_session(&headers, &state.db).await?;

    let transfer_id = Uuid::new_v4().to_string();
    let code = generate_code();

    let outcome = insert_transfer(
        &state.db,
        &transfer_id,
        &session.did,
        &code,
        TRANSFER_TTL_MINUTES,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to insert transfer session");
        ApiError::new(ErrorCode::InternalError, "failed to initiate transfer")
    })?;

    match outcome {
        InitiateOutcome::Created { expires_at } => Ok((
            StatusCode::OK,
            Json(InitiateTransferResponse {
                transfer_id,
                transfer_code: code,
                expires_at,
                status: "pending".to_string(),
            }),
        )),
        InitiateOutcome::DuplicateActive => Err(ApiError::new(
            ErrorCode::Conflict,
            "an active transfer already exists for this account",
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
    use crate::routes::token::generate_token;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Seed a promoted account and a valid (1-year) session for it.
    /// Returns `(did, session_token_plaintext)`.
    async fn seed_session(db: &sqlx::SqlitePool) -> (String, String) {
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

        let token = generate_token();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");

        (did, token.plaintext)
    }

    fn post_initiate(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/transfer/initiate")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    /// Run a single initiate request against a fresh app over `state`.
    async fn initiate(state: AppState, token: &str) -> axum::response::Response {
        app(state).oneshot(post_initiate(token)).await.unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_session_returns_200_with_correct_shape() {
        let state = test_state().await;
        let (_, token) = seed_session(&state.db).await;

        let response = initiate(state, &token).await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(json["transferId"].as_str().is_some(), "transferId required");
        let code = json["transferCode"]
            .as_str()
            .expect("transferCode required");
        assert_eq!(code.len(), 6, "transfer code is 6 chars");
        assert!(
            code.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "transfer code is uppercase alphanumeric: {code}"
        );
        assert!(json["expiresAt"].as_str().is_some(), "expiresAt required");
        assert_eq!(json["status"], "pending");
    }

    #[tokio::test]
    async fn transfer_is_persisted_as_pending() {
        let state = test_state().await;
        let db = state.db.clone();
        let (did, token) = seed_session(&state.db).await;

        let response = initiate(state, &token).await;
        let json = body_json(response).await;
        let transfer_id = json["transferId"].as_str().unwrap().to_string();

        let row: (String, String) =
            sqlx::query_as("SELECT did, status FROM transfers WHERE id = ?")
                .bind(&transfer_id)
                .fetch_one(&db)
                .await
                .expect("transfer row must exist");
        assert_eq!(row.0, did, "transfer bound to the session DID");
        assert_eq!(row.1, "pending");
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_session_returns_401() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/transfer/initiate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_session_token_returns_401() {
        let state = test_state().await;
        let bogus = generate_token().plaintext; // never stored
        let response = initiate(state, &bogus).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── One active transfer per account ───────────────────────────────────────

    #[tokio::test]
    async fn second_active_transfer_returns_409() {
        let state = test_state().await;
        let (_, token) = seed_session(&state.db).await;

        let first = initiate(state.clone(), &token).await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = initiate(state, &token).await;
        assert_eq!(
            second.status(),
            StatusCode::CONFLICT,
            "a second active transfer for the same account must 409"
        );
        let json = body_json(second).await;
        assert_eq!(json["error"]["code"], "CONFLICT");
    }
}
