// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (full access required), DB pool, JSON body {name}
// Processes: scope gate → delete the named app password AND its sessions/refresh tokens, atomically
// Returns: 200 OK (empty); ApiError on failure
//
// Implements: POST /xrpc/com.atproto.server.revokeAppPassword

use axum::{extract::State, http::StatusCode, response::Json};
use serde::Deserialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;

#[derive(Deserialize)]
pub struct RevokeAppPasswordRequest {
    name: String,
}

/// POST /xrpc/com.atproto.server.revokeAppPassword
///
/// Revokes the named app password for the authenticated account. New logins with it fail
/// immediately (the hash is gone), and any existing app-password sessions it created can no
/// longer be refreshed (their refresh tokens are deleted; short-lived access tokens expire on
/// their own). Idempotent: revoking an unknown name is a 200 no-op. Requires a full
/// access-scope token.
pub async fn revoke_app_password(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Json(payload): Json<RevokeAppPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }

    if payload.name.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "app password name must not be empty",
        ));
    }

    let map_err = |e: sqlx::Error| {
        tracing::error!(error = %e, "DB error revoking app password");
        ApiError::new(ErrorCode::InternalError, "failed to revoke app password")
    };

    // Delete the app password and every session it opened, atomically. The refresh tokens must
    // be deleted before their session rows (refresh_tokens.session_id → sessions.id FK), so
    // capture the session ids first.
    let mut tx = state.db.begin().await.map_err(map_err)?;

    let session_ids: Vec<(String,)> = sqlx::query_as(
        "SELECT session_id FROM refresh_tokens WHERE did = ? AND app_password_name = ?",
    )
    .bind(&user.did)
    .bind(&payload.name)
    .fetch_all(&mut *tx)
    .await
    .map_err(map_err)?;

    sqlx::query("DELETE FROM app_passwords WHERE did = ? AND name = ?")
        .bind(&user.did)
        .bind(&payload.name)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

    sqlx::query("DELETE FROM refresh_tokens WHERE did = ? AND app_password_name = ?")
        .bind(&user.did)
        .bind(&payload.name)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

    for (session_id,) in &session_ids {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
    }

    tx.commit().await.map_err(map_err)?;

    Ok(StatusCode::OK)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state, AppState};
    use crate::routes::test_utils::{
        access_jwt, body_json, insert_account_with_password, seed_app_password,
    };

    fn post_revoke(token: Option<&str>, json: serde_json::Value) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.revokeAppPassword")
            .header("Content-Type", "application/json");
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::from(json.to_string())).unwrap()
    }

    fn post_create_session(identifier: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"identifier":"{identifier}","password":"{password}"}}"#
            )))
            .unwrap()
    }

    async fn setup(state: &AppState) {
        insert_account_with_password(
            &state.db,
            "did:plc:alice",
            "alice.test.example.com",
            "alice@example.com",
            "hunter2",
        )
        .await;
    }

    #[tokio::test]
    async fn revoked_app_password_can_no_longer_create_session() {
        let state = test_state().await;
        setup(&state).await;
        seed_app_password(
            &state.db,
            "did:plc:alice",
            "cli",
            "wxyz-wxyz-wxyz-wxyz",
            false,
        )
        .await;

        // Sanity: the app password authenticates before revocation.
        let before = app(state.clone())
            .oneshot(post_create_session("did:plc:alice", "wxyz-wxyz-wxyz-wxyz"))
            .await
            .unwrap();
        assert_eq!(before.status(), StatusCode::OK);

        let token = access_jwt(&state.jwt_secret, "did:plc:alice");
        let revoke = app(state.clone())
            .oneshot(post_revoke(
                Some(&token),
                serde_json::json!({"name": "cli"}),
            ))
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);

        // After revocation the same secret must be rejected.
        let after = app(state)
            .oneshot(post_create_session("did:plc:alice", "wxyz-wxyz-wxyz-wxyz"))
            .await
            .unwrap();
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_deletes_existing_refresh_tokens() {
        let state = test_state().await;
        setup(&state).await;
        seed_app_password(
            &state.db,
            "did:plc:alice",
            "cli",
            "wxyz-wxyz-wxyz-wxyz",
            false,
        )
        .await;

        // Open an app-password session, then revoke the app password.
        let session = app(state.clone())
            .oneshot(post_create_session("did:plc:alice", "wxyz-wxyz-wxyz-wxyz"))
            .await
            .unwrap();
        let session_json = body_json(session).await;
        let refresh_jwt = session_json["refreshJwt"].as_str().unwrap().to_string();

        let token = access_jwt(&state.jwt_secret, "did:plc:alice");
        app(state.clone())
            .oneshot(post_revoke(
                Some(&token),
                serde_json::json!({"name": "cli"}),
            ))
            .await
            .unwrap();

        // The app-password session's refresh token is gone.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM refresh_tokens WHERE app_password_name = 'cli'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(
            count, 0,
            "refresh tokens for the app password must be deleted"
        );

        // And refreshing with it fails.
        let refresh = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.refreshSession")
                    .header("Authorization", format!("Bearer {refresh_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refresh.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_unknown_name_is_idempotent_200() {
        let state = test_state().await;
        setup(&state).await;
        let token = access_jwt(&state.jwt_secret, "did:plc:alice");

        let response = app(state)
            .oneshot(post_revoke(
                Some(&token),
                serde_json::json!({"name": "does-not-exist"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revoke_only_affects_the_named_app_password() {
        let state = test_state().await;
        setup(&state).await;
        seed_app_password(
            &state.db,
            "did:plc:alice",
            "keep",
            "keep-keep-keep-keep",
            false,
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:alice",
            "drop",
            "drop-drop-drop-drop",
            false,
        )
        .await;

        let token = access_jwt(&state.jwt_secret, "did:plc:alice");
        app(state.clone())
            .oneshot(post_revoke(
                Some(&token),
                serde_json::json!({"name": "drop"}),
            ))
            .await
            .unwrap();

        // "keep" still authenticates; "drop" does not.
        let keep = app(state.clone())
            .oneshot(post_create_session("did:plc:alice", "keep-keep-keep-keep"))
            .await
            .unwrap();
        assert_eq!(keep.status(), StatusCode::OK);
        let drop = app(state)
            .oneshot(post_create_session("did:plc:alice", "drop-drop-drop-drop"))
            .await
            .unwrap();
        assert_eq!(drop.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(post_revoke(None, serde_json::json!({"name": "x"})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
