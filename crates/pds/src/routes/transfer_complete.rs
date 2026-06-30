// pattern: Imperative Shell
//
// Gathers: Authorization bearer token (source session or accepted target device token),
//          JSON request body (transfer id), DB pool
// Processes: bearer-token hashing → atomic transfer completion + credential revocation
// Returns: JSON { transferId, status: "complete" } on success; ApiError on invalid,
//          unaccepted, or unauthorized transfers
//
// Implements: POST /v1/transfer/complete

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extract_bearer_token;
use crate::token::hash_bearer_token;
use crate::transfer::{complete_transfer as complete_transfer_row, CompleteOutcome};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteTransferRequest {
    #[serde(alias = "transfer_id")]
    transfer_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteTransferResponse {
    transfer_id: String,
    status: String,
}

/// POST /v1/transfer/complete
///
/// Finalizes a planned device swap. The caller may present either a source account
/// session bearer token (before completion) or the accepted target device token. The
/// transaction moves the transfer to the terminal `complete` state, revokes the account's
/// old promoted sessions and prior transfer-device credentials, preserves the accepted
/// target device credential, and records an audit event.
pub async fn transfer_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CompleteTransferRequest>,
) -> Result<(StatusCode, Json<CompleteTransferResponse>), ApiError> {
    let bearer = extract_bearer_token(&headers)?;
    let token_hash = hash_bearer_token(bearer)?;

    let outcome = complete_transfer_row(&state.db, &payload.transfer_id, &token_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to complete transfer");
            ApiError::new(ErrorCode::InternalError, "failed to complete transfer")
        })?;

    match outcome {
        CompleteOutcome::Completed { transfer_id } => Ok((
            StatusCode::OK,
            Json(CompleteTransferResponse {
                transfer_id,
                status: "complete".to_string(),
            }),
        )),
        CompleteOutcome::Invalid => Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "transfer is invalid or expired",
        )),
        CompleteOutcome::NotAccepted => Err(ApiError::new(
            ErrorCode::Conflict,
            "transfer has not been accepted",
        )),
        CompleteOutcome::Unauthorized => Err(ApiError::new(
            ErrorCode::Unauthorized,
            "invalid transfer completion token",
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
    use crate::token::{generate_token, hash_bearer_token};

    struct AcceptedTransferFixture {
        did: String,
        transfer_id: String,
        source_token: String,
        target_device_id: String,
        target_token: String,
        old_device_id: String,
        old_token: String,
    }

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

    async fn seed_source_session(db: &sqlx::SqlitePool, did: &str) -> String {
        let token = generate_token();
        let session_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(&session_id)
        .bind(did)
        .bind(&token.hash)
        .execute(db)
        .await
        .expect("insert session");

        sqlx::query(
            "INSERT INTO refresh_tokens \
             (jti, did, session_id, next_jti, expires_at, app_password_name, created_at) \
             VALUES (?, ?, ?, NULL, datetime('now', '+1 year'), NULL, datetime('now'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(&session_id)
        .execute(db)
        .await
        .expect("insert refresh token");

        token.plaintext
    }

    async fn insert_transfer_device(
        db: &sqlx::SqlitePool,
        did: &str,
        device_id: &str,
        token_hash: &str,
    ) {
        sqlx::query(
            "INSERT INTO transfer_devices \
             (id, did, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'dGVzdC1rZXk=', ?, datetime('now'), datetime('now'))",
        )
        .bind(device_id)
        .bind(did)
        .bind(token_hash)
        .execute(db)
        .await
        .expect("insert transfer device");
    }

    async fn seed_accepted_transfer(db: &sqlx::SqlitePool) -> AcceptedTransferFixture {
        let did = seed_account(db).await;
        let source_token = seed_source_session(db, &did).await;
        let target = generate_token();
        let old = generate_token();
        let target_device_id = Uuid::new_v4().to_string();
        let old_device_id = Uuid::new_v4().to_string();
        insert_transfer_device(db, &did, &target_device_id, &target.hash).await;
        insert_transfer_device(db, &did, &old_device_id, &old.hash).await;

        let transfer_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO transfers \
             (id, did, code, status, expires_at, created_at, accepted_device_id, accepted_at) \
             VALUES (?, ?, 'DONE12', 'accepted', datetime('now', '+15 minutes'), \
                     datetime('now'), ?, datetime('now'))",
        )
        .bind(&transfer_id)
        .bind(&did)
        .bind(&target_device_id)
        .execute(db)
        .await
        .expect("insert accepted transfer");

        AcceptedTransferFixture {
            did,
            transfer_id,
            source_token,
            target_device_id,
            target_token: target.plaintext,
            old_device_id,
            old_token: old.plaintext,
        }
    }

    fn post_complete(transfer_id: &str, bearer: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/transfer/complete")
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"transferId":"{transfer_id}"}}"#)))
            .unwrap()
    }

    async fn complete(
        state: AppState,
        transfer_id: &str,
        bearer: &str,
    ) -> axum::response::Response {
        app(state)
            .oneshot(post_complete(transfer_id, bearer))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn source_session_completes_transfer_and_revokes_old_credentials() {
        let state = test_state().await;
        let db = state.db.clone();
        let fixture = seed_accepted_transfer(&db).await;

        let response = complete(state.clone(), &fixture.transfer_id, &fixture.source_token).await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["transferId"], fixture.transfer_id);
        assert_eq!(json["status"], "complete");

        let (status, completed_at): (String, Option<String>) =
            sqlx::query_as("SELECT status, completed_at FROM transfers WHERE id = ?")
                .bind(&fixture.transfer_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(status, "complete");
        assert!(completed_at.is_some(), "completion timestamp recorded");

        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE did = ?")
            .bind(&fixture.did)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(sessions, 0, "old promoted sessions revoked");
        let refresh_tokens: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE did = ?")
                .bind(&fixture.did)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(refresh_tokens, 0, "refresh tokens revoked before sessions");

        let old_revoked_at: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM transfer_devices WHERE id = ?")
                .bind(&fixture.old_device_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            old_revoked_at.is_some(),
            "prior transfer device token revoked"
        );
        let target_revoked_at: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM transfer_devices WHERE id = ?")
                .bind(&fixture.target_device_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            target_revoked_at.is_none(),
            "accepted target credential survives"
        );

        let audit_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM transfer_audit_events WHERE transfer_id = ?")
                .bind(&fixture.transfer_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(audit_events, 1, "completion audit event recorded");

        let pds_lookup = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/devices/{}/pds", fixture.target_device_id))
                    .header("Authorization", format!("Bearer {}", fixture.target_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pds_lookup.status(), StatusCode::OK);

        let old_device_reuse = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/devices/{}/pds", fixture.old_device_id))
                    .header("Authorization", format!("Bearer {}", fixture.old_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_device_reuse.status(), StatusCode::UNAUTHORIZED);

        let old_session_reuse = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/transfer/initiate")
                    .header("Authorization", format!("Bearer {}", fixture.source_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_session_reuse.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accepted_target_device_token_can_complete_transfer() {
        let state = test_state().await;
        let db = state.db.clone();
        let fixture = seed_accepted_transfer(&db).await;

        let response = complete(state, &fixture.transfer_id, &fixture.target_token).await;

        assert_eq!(response.status(), StatusCode::OK);
        let status: String = sqlx::query_scalar("SELECT status FROM transfers WHERE id = ?")
            .bind(&fixture.transfer_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "complete");
    }

    #[tokio::test]
    async fn already_complete_target_call_is_idempotent_without_duplicate_audit() {
        let state = test_state().await;
        let db = state.db.clone();
        let fixture = seed_accepted_transfer(&db).await;

        let first = complete(state.clone(), &fixture.transfer_id, &fixture.target_token).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = complete(state, &fixture.transfer_id, &fixture.target_token).await;
        assert_eq!(second.status(), StatusCode::OK);

        let audit_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM transfer_audit_events WHERE transfer_id = ?")
                .bind(&fixture.transfer_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(audit_events, 1);
    }

    #[tokio::test]
    async fn stale_source_session_cannot_reenter_complete_terminal_path() {
        // Source sessions are deleted on first completion, so a repeat call with the
        // original source token is unauthorized. Simulate a stale session row surviving
        // completion to prove the terminal path only honors the target credential.
        let state = test_state().await;
        let db = state.db.clone();
        let fixture = seed_accepted_transfer(&db).await;

        let first = complete(state.clone(), &fixture.transfer_id, &fixture.target_token).await;
        assert_eq!(first.status(), StatusCode::OK);

        // Re-insert a session row matching the (now-revoked) source token hash.
        let stale_hash = hash_bearer_token(&fixture.source_token).unwrap();
        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, NULL, ?, datetime('now'), datetime('now', '+1 year'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&fixture.did)
        .bind(&stale_hash)
        .execute(&db)
        .await
        .unwrap();

        let response = complete(state, &fixture.transfer_id, &fixture.source_token).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "stale source session must not re-enter the terminal success path"
        );
    }

    #[tokio::test]
    async fn pending_transfer_returns_409() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = seed_account(&db).await;
        let source_token = seed_source_session(&db, &did).await;
        let transfer_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO transfers (id, did, code, status, expires_at, created_at) \
             VALUES (?, ?, 'PEND12', 'pending', datetime('now', '+15 minutes'), datetime('now'))",
        )
        .bind(&transfer_id)
        .bind(&did)
        .execute(&db)
        .await
        .unwrap();

        let response = complete(state, &transfer_id, &source_token).await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn unrelated_token_returns_401_without_completing() {
        let state = test_state().await;
        let db = state.db.clone();
        let fixture = seed_accepted_transfer(&db).await;
        let unrelated = generate_token().plaintext;

        let response = complete(state, &fixture.transfer_id, &unrelated).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let status: String = sqlx::query_scalar("SELECT status FROM transfers WHERE id = ?")
            .bind(&fixture.transfer_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(status, "accepted");
    }

    #[tokio::test]
    async fn unrelated_token_cannot_probe_pending_transfer_state() {
        let state = test_state().await;
        let db = state.db.clone();
        let did = seed_account(&db).await;
        let transfer_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO transfers (id, did, code, status, expires_at, created_at) \
             VALUES (?, ?, 'WAIT12', 'pending', datetime('now', '+15 minutes'), datetime('now'))",
        )
        .bind(&transfer_id)
        .bind(&did)
        .execute(&db)
        .await
        .unwrap();
        let unrelated = generate_token().plaintext;

        let response = complete(state, &transfer_id, &unrelated).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn snake_case_transfer_id_is_accepted() {
        let state = test_state().await;
        let fixture = seed_accepted_transfer(&state.db).await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/transfer/complete")
                    .header("Authorization", format!("Bearer {}", fixture.target_token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"transfer_id":"{}"}}"#,
                        fixture.transfer_id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
