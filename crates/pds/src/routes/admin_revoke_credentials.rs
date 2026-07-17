// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), account DID (path), DB pool
// Processes: admin auth → account lookup (404 if absent) → atomic account-wide credential sweep
// Returns: JSON per-family revocation counts on success; ApiError on all failure paths

//! POST /v1/admin/accounts/:id/revoke-credentials - Operator credential revocation for an account.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::db::admin_audit::{record_admin_audit_event, AdminAuditAction};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCredentialsResponse {
    /// Session rows deleted (each session's refresh tokens go with it).
    sessions_revoked: i64,
    /// App-password credentials deleted; new logins with them fail immediately.
    app_passwords_revoked: i64,
    /// OAuth refresh-token grants deleted.
    oauth_tokens_revoked: i64,
    /// Pending (unexchanged) OAuth authorization codes deleted.
    oauth_codes_revoked: i64,
    /// Promoted transfer-device tokens tombstoned (`revoked_at` stamped).
    transfer_device_tokens_revoked: i64,
}

/// POST /v1/admin/accounts/:id/revoke-credentials
///
/// Operator kill-switch for a compromised account: atomically revokes every credential the
/// account's holders could keep authenticating with — sessions (and their refresh tokens),
/// app passwords, OAuth refresh tokens and pending authorization codes, and promoted
/// transfer-device tokens. Already-minted access JWTs are stateless and expire on their own
/// (minutes); this closes every path to minting new ones. `:id` is the account DID; works
/// regardless of lifecycle state, so takedown-then-sweep composes. The account's main
/// password is deliberately untouched (it is the owner's recovery path — reset is a
/// separate, user-driven flow), as are operator admin devices (`/v1/admin/devices`).
/// Idempotent: a repeat sweep is a 200 reporting zero counts. Admin-authed: the master
/// token **or** an active companion-app device's signed request ([`require_admin`]).
pub async fn revoke_account_credentials(
    State(state): State<AppState>,
    Path(did): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RevokeCredentialsResponse>, ApiError> {
    // Auth first so an unauthenticated caller cannot probe which DIDs exist.
    let actor = require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    if !crate::db::accounts::account_exists(&state.db, &did).await? {
        return Err(ApiError::new(ErrorCode::NotFound, "account not found"));
    }

    let map_err = |e: sqlx::Error| {
        tracing::error!(error = %e, "DB error revoking account credentials");
        ApiError::new(ErrorCode::InternalError, "failed to revoke credentials")
    };

    // One transaction so a partially-swept account can never be observed. Delete order
    // follows the FK graph (refresh_tokens.session_id → sessions.id); transfer-device
    // tokens are tombstoned rather than deleted so the row survives as the audit record
    // (V030 doctrine) — the auth guard already filters on `revoked_at IS NULL`.
    let mut tx = state.db.begin().await.map_err(map_err)?;

    sqlx::query("DELETE FROM refresh_tokens WHERE did = ?")
        .bind(&did)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

    let sessions = sqlx::query("DELETE FROM sessions WHERE did = ?")
        .bind(&did)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?
        .rows_affected();

    let oauth_tokens = sqlx::query("DELETE FROM oauth_tokens WHERE did = ?")
        .bind(&did)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?
        .rows_affected();

    let oauth_codes = sqlx::query("DELETE FROM oauth_authorization_codes WHERE did = ?")
        .bind(&did)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?
        .rows_affected();

    let app_passwords = sqlx::query("DELETE FROM app_passwords WHERE did = ?")
        .bind(&did)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?
        .rows_affected();

    let transfer_devices = sqlx::query(
        "UPDATE transfer_devices SET revoked_at = datetime('now') \
         WHERE did = ? AND revoked_at IS NULL",
    )
    .bind(&did)
    .execute(&mut *tx)
    .await
    .map_err(map_err)?
    .rows_affected();

    // Audit the sweep atomically with it: which admin credential swept whom, and the
    // literal per-family counts the response reports.
    let audit_detail = serde_json::json!({
        "sessionsRevoked": sessions,
        "appPasswordsRevoked": app_passwords,
        "oauthTokensRevoked": oauth_tokens,
        "oauthCodesRevoked": oauth_codes,
        "transferDeviceTokensRevoked": transfer_devices,
    })
    .to_string();
    record_admin_audit_event(
        &mut *tx,
        actor.as_log_str().as_ref(),
        AdminAuditAction::CredentialsRevoked,
        Some(&did),
        "ok",
        Some(&audit_detail),
    )
    .await?;

    tx.commit().await.map_err(map_err)?;

    tracing::info!(
        did = %did,
        sessions,
        app_passwords,
        oauth_tokens,
        oauth_codes,
        transfer_devices,
        "account credentials revoked by operator"
    );

    Ok(Json(RevokeCredentialsResponse {
        sessions_revoked: sessions as i64,
        app_passwords_revoked: app_passwords as i64,
        oauth_tokens_revoked: oauth_tokens as i64,
        oauth_codes_revoked: oauth_codes as i64,
        transfer_device_tokens_revoked: transfer_devices as i64,
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use crate::app::app;
    use crate::routes::test_utils::{
        body_json, insert_account_with_password, seed_app_password, test_state_with_admin_token,
    };

    const ADMIN: &str = "test-admin-token";

    /// The fake app-password fixture, assembled at runtime so secret scanners never
    /// see a password-shaped literal in source (the sibling `revoke_app_password`
    /// tests interpolate through `format!` for the same reason).
    fn fixture_app_password() -> String {
        ["wxyz"; 4].join("-")
    }

    fn session_request(identifier: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"identifier":"{identifier}","password":"{password}"}}"#
            )))
            .unwrap()
    }

    fn post_revoke(did: &str, token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method(http::Method::POST)
            .uri(format!("/v1/admin/accounts/{did}/revoke-credentials"));
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    async fn create_session(state: &crate::app::AppState, did: &str, password: &str) {
        let response = app(state.clone())
            .oneshot(session_request(did, password))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "createSession must succeed"
        );
    }

    async fn seed_oauth_grants(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_metadata, created_at) \
             VALUES ('test-client', '{}', datetime('now'))",
        )
        .execute(db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO oauth_tokens (id, client_id, did, scope, expires_at, created_at) \
             VALUES ('tok1', 'test-client', ?, 'atproto', datetime('now', '+1 day'), datetime('now'))",
        )
        .bind(did)
        .execute(db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO oauth_authorization_codes (code, client_id, did, code_challenge, \
             code_challenge_method, redirect_uri, scope, expires_at, created_at) \
             VALUES ('code1', 'test-client', ?, 'ch', 'S256', 'app:/cb', 'atproto', \
             datetime('now', '+10 minutes'), datetime('now'))",
        )
        .bind(did)
        .execute(db)
        .await
        .unwrap();
    }

    async fn seed_transfer_device(db: &sqlx::SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO transfer_devices (id, did, platform, public_key, device_token_hash, \
             created_at, last_seen_at) \
             VALUES ('tdev1', ?, 'ios', 'pk', 'hash1', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn revokes_every_credential_family_and_reports_counts() {
        let state = test_state_with_admin_token().await;
        insert_account_with_password(
            &state.db,
            "did:plc:arc1",
            "arc1.test.example.com",
            "arc1@example.com",
            "hunter2",
        )
        .await;
        create_session(&state, "did:plc:arc1", "hunter2").await;
        seed_app_password(
            &state.db,
            "did:plc:arc1",
            "cli",
            &fixture_app_password(),
            false,
        )
        .await;
        seed_oauth_grants(&state.db, "did:plc:arc1").await;
        seed_transfer_device(&state.db, "did:plc:arc1").await;

        let response = app(state.clone())
            .oneshot(post_revoke("did:plc:arc1", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["sessionsRevoked"], 1);
        assert_eq!(json["appPasswordsRevoked"], 1);
        assert_eq!(json["oauthTokensRevoked"], 1);
        assert_eq!(json["oauthCodesRevoked"], 1);
        assert_eq!(json["transferDeviceTokensRevoked"], 1);

        for (table, expected) in [
            ("sessions", 0i64),
            ("refresh_tokens", 0),
            ("app_passwords", 0),
            ("oauth_tokens", 0),
            ("oauth_authorization_codes", 0),
        ] {
            let count: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE did = ?"))
                    .bind("did:plc:arc1")
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(count, expected, "{table} must be swept");
        }
        let revoked: Option<String> =
            sqlx::query_scalar("SELECT revoked_at FROM transfer_devices WHERE id = 'tdev1'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(
            revoked.is_some(),
            "transfer-device token must be tombstoned, not deleted"
        );
    }

    #[tokio::test]
    async fn revoked_credentials_no_longer_authenticate() {
        let state = test_state_with_admin_token().await;
        insert_account_with_password(
            &state.db,
            "did:plc:arc2",
            "arc2.test.example.com",
            "arc2@example.com",
            "hunter2",
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:arc2",
            "cli",
            &fixture_app_password(),
            false,
        )
        .await;

        // Open a real session and keep its refresh token.
        let session = app(state.clone())
            .oneshot(session_request("did:plc:arc2", "hunter2"))
            .await
            .unwrap();
        let refresh_jwt = body_json(session).await["refreshJwt"]
            .as_str()
            .unwrap()
            .to_string();

        let revoke = app(state.clone())
            .oneshot(post_revoke("did:plc:arc2", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);

        // The session's refresh token is dead.
        let refresh = app(state.clone())
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

        // The app password no longer opens sessions.
        let login = app(state)
            .oneshot(session_request("did:plc:arc2", &fixture_app_password()))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn repeat_sweep_is_idempotent_200_with_zero_counts() {
        let state = test_state_with_admin_token().await;
        insert_account_with_password(
            &state.db,
            "did:plc:arc3",
            "arc3.test.example.com",
            "arc3@example.com",
            "hunter2",
        )
        .await;
        create_session(&state, "did:plc:arc3", "hunter2").await;

        let first = app(state.clone())
            .oneshot(post_revoke("did:plc:arc3", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(body_json(first).await["sessionsRevoked"], 1);

        let second = app(state)
            .oneshot(post_revoke("did:plc:arc3", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let json = body_json(second).await;
        assert_eq!(json["sessionsRevoked"], 0);
        assert_eq!(json["appPasswordsRevoked"], 0);
        assert_eq!(json["oauthTokensRevoked"], 0);
        assert_eq!(json["oauthCodesRevoked"], 0);
        assert_eq!(json["transferDeviceTokensRevoked"], 0);
    }

    #[tokio::test]
    async fn only_sweeps_the_named_account() {
        let state = test_state_with_admin_token().await;
        for did in ["did:plc:arc4", "did:plc:arc5"] {
            insert_account_with_password(
                &state.db,
                did,
                &format!("{}.test.example.com", did.replace(':', "-")),
                &format!("{did}@example.com"),
                "hunter2",
            )
            .await;
            create_session(&state, did, "hunter2").await;
        }

        let response = app(state.clone())
            .oneshot(post_revoke("did:plc:arc4", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let survivor: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE did = 'did:plc:arc5'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(survivor, 1, "other accounts' sessions must survive");
    }

    #[tokio::test]
    async fn unknown_account_returns_404() {
        let state = test_state_with_admin_token().await;
        let response = app(state)
            .oneshot(post_revoke("did:plc:missing", Some(ADMIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_auth_returns_401_even_for_unknown_account() {
        let state = test_state_with_admin_token().await;
        let response = app(state)
            .oneshot(post_revoke("did:plc:missing", None))
            .await
            .unwrap();
        // Auth is checked before existence, so there is no DID-presence oracle.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn signed_device_request_revokes_credentials() {
        use crate::auth::guards::{
            admin_request_sign_string, ADMIN_DEVICE_HEADER, ADMIN_NONCE_HEADER,
            ADMIN_SIGNATURE_HEADER, ADMIN_TIMESTAMP_HEADER,
        };
        use crate::db::admin_devices::{insert_device, NewAdminDevice};
        use std::time::{SystemTime, UNIX_EPOCH};

        // A state with NO master token: proves the device path is independent of it.
        let state = crate::app::test_state().await;
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
        insert_account_with_password(
            &state.db,
            "did:plc:arc6",
            "arc6.test.example.com",
            "arc6@example.com",
            "hunter2",
        )
        .await;
        create_session(&state, "did:plc:arc6", "hunter2").await;

        let path = "/v1/admin/accounts/did:plc:arc6/revoke-credentials";
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = "revoke-credentials-nonce-1";
        let sign_string = admin_request_sign_string("POST", path, ts, nonce, b"");
        let signature = crate::routes::test_utils::sign_p256(&keypair, sign_string.as_bytes());

        let request = Request::builder()
            .method(http::Method::POST)
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
        assert_eq!(json["sessionsRevoked"], 1);
    }
}
