// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool via AppState
// Processes: scope validation → account + DID doc lookup
// Returns: JSON {did, handle, email, emailConfirmed, didDoc} on success; ApiError on failure
//
// Implements: GET /xrpc/com.atproto.server.getSession

use axum::{extract::State, response::Json};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::accounts::get_session_account;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionResponse {
    pub did: String,
    pub handle: String,
    pub email: String,
    pub email_confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_doc: Option<serde_json::Value>,
}

/// GET /xrpc/com.atproto.server.getSession
///
/// Returns session info for the authenticated account. Accepts both legacy HS256
/// tokens (from `createSession`) and ES256 OAuth access tokens.
pub async fn get_session(
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<GetSessionResponse>, ApiError> {
    // Only access-scope tokens are valid; refresh tokens must not be accepted.
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    let account = get_session_account(&state.db, &user.did)
        .await?
        .ok_or_else(|| {
            tracing::warn!(did = %user.did, "getSession: account not found or deactivated");
            ApiError::new(ErrorCode::InvalidToken, "account not found")
        })?;

    let did_doc = account.did_doc.as_deref().and_then(|s| {
        serde_json::from_str(s)
            .inspect_err(|e| {
                tracing::error!(did = %account.did, error = %e, "malformed DID doc JSON in did_documents table")
            })
            .ok()
    });

    // ATProto spec: "handle.invalid" is the sentinel for accounts without a resolvable handle.
    let handle = account
        .handle
        .unwrap_or_else(|| "handle.invalid".to_string());

    Ok(Json(GetSessionResponse {
        did: account.did,
        handle,
        email: account.email,
        email_confirmed: account.email_confirmed,
        did_doc,
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Issue a valid HS256 access JWT for a DID using the test state's fixed secret.
    fn access_jwt(secret: &[u8; 32], sub: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.access",
                "sub": sub,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    /// Issue an expired HS256 access JWT (exp in the past).
    fn expired_access_jwt(secret: &[u8; 32], sub: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.access",
                "sub": sub,
                "iat": 1_000_000_u64,
                "exp": 1_000_001_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    /// Issue a refresh-scope JWT (should be rejected by getSession).
    fn refresh_jwt(secret: &[u8; 32], sub: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.refresh",
                "sub": sub,
                "iat": now,
                "exp": now + 7_776_000_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn get_session_request(token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/xrpc/com.atproto.server.getSession")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn insert_account(db: &sqlx::SqlitePool, did: &str, handle: &str, email: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(email)
        .execute(db)
        .await
        .unwrap();

        sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
            .bind(handle)
            .bind(did)
            .execute(db)
            .await
            .unwrap();
    }

    async fn insert_did_doc(db: &sqlx::SqlitePool, did: &str, doc: serde_json::Value) {
        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) \
             VALUES (?, ?, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(doc.to_string())
        .execute(db)
        .await
        .unwrap();
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn valid_token_returns_session_info() {
        let state = test_state().await;
        insert_account(
            &state.db,
            "did:plc:alice",
            "alice.test.example.com",
            "alice@example.com",
        )
        .await;
        let token = access_jwt(&state.jwt_secret, "did:plc:alice");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["did"], "did:plc:alice");
        assert_eq!(json["handle"], "alice.test.example.com");
        assert_eq!(json["email"], "alice@example.com");
        assert_eq!(json["emailConfirmed"], false);
        assert!(
            json.get("didDoc").is_none(),
            "didDoc absent when no document stored"
        );
    }

    #[tokio::test]
    async fn confirmed_email_returns_true() {
        let state = test_state().await;
        insert_account(
            &state.db,
            "did:plc:confirmed",
            "conf.test.example.com",
            "conf@example.com",
        )
        .await;
        sqlx::query("UPDATE accounts SET email_confirmed_at = datetime('now') WHERE did = ?")
            .bind("did:plc:confirmed")
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, "did:plc:confirmed");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["emailConfirmed"], true);
    }

    #[tokio::test]
    async fn did_doc_included_when_present() {
        let state = test_state().await;
        insert_account(
            &state.db,
            "did:plc:withdoc",
            "doc.test.example.com",
            "doc@example.com",
        )
        .await;
        let doc = serde_json::json!({"id": "did:plc:withdoc", "@context": ["https://www.w3.org/ns/did/v1"]});
        insert_did_doc(&state.db, "did:plc:withdoc", doc.clone()).await;
        let token = access_jwt(&state.jwt_secret, "did:plc:withdoc");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["didDoc"]["id"], "did:plc:withdoc");
    }

    // ── Auth failures ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/xrpc/com.atproto.server.getSession")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let response = app(test_state().await)
            .oneshot(get_session_request("not.a.valid.jwt"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn expired_token_returns_401() {
        let state = test_state().await;
        let token = expired_access_jwt(&state.jwt_secret, "did:plc:alice");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "TOKEN_EXPIRED");
    }

    #[tokio::test]
    async fn refresh_token_returns_401() {
        let state = test_state().await;
        insert_account(
            &state.db,
            "did:plc:refresh",
            "refresh.test.example.com",
            "r@example.com",
        )
        .await;
        let token = refresh_jwt(&state.jwt_secret, "did:plc:refresh");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn deactivated_account_returns_401_with_invalid_token_code() {
        let state = test_state().await;
        insert_account(
            &state.db,
            "did:plc:deact",
            "deact.test.example.com",
            "deact@example.com",
        )
        .await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind("did:plc:deact")
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, "did:plc:deact");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn app_pass_token_returns_401() {
        let state = test_state().await;
        insert_account(
            &state.db,
            "did:plc:apppass",
            "apppass.test.example.com",
            "apppass@example.com",
        )
        .await;

        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.appPass",
                "sub": "did:plc:apppass",
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(&state.jwt_secret),
        )
        .unwrap();

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn account_without_handle_returns_handle_invalid() {
        let state = test_state().await;
        // Insert account without a corresponding handles row.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind("did:plc:nohandle")
        .bind("nohandle@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        let token = access_jwt(&state.jwt_secret, "did:plc:nohandle");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["handle"], "handle.invalid");
    }

    #[tokio::test]
    async fn malformed_did_doc_json_returns_200_without_did_doc() {
        let state = test_state().await;
        insert_account(
            &state.db,
            "did:plc:baddoc",
            "baddoc.test.example.com",
            "baddoc@example.com",
        )
        .await;
        sqlx::query(
            "INSERT INTO did_documents (did, document, created_at, updated_at) \
             VALUES (?, ?, datetime('now'), datetime('now'))",
        )
        .bind("did:plc:baddoc")
        .bind("this is not valid json {{{")
        .execute(&state.db)
        .await
        .unwrap();
        let token = access_jwt(&state.jwt_secret, "did:plc:baddoc");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(
            json.get("didDoc").is_none(),
            "malformed didDoc must be omitted"
        );
    }

    #[tokio::test]
    async fn token_for_nonexistent_did_returns_401() {
        let state = test_state().await;
        // No account inserted — DID exists only in the JWT.
        let token = access_jwt(&state.jwt_secret, "did:plc:ghost");

        let response = app(state)
            .oneshot(get_session_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    // ── DPoP binding tests ─────────────────────────────────────────────────────
    // Note: Complete DPoP test coverage requires:
    // - ES256 token minting with cnf.jkt binding
    // - DPoP proof creation with ath claim matching the token
    // - Validation of ath (access token hash) claim in the DPoP proof
    // - Validation of cnf.jkt (key binding) match between token and proof
    //
    // These tests are deferred to a dedicated DPoP test module that can leverage
    // the test helpers in auth/mod.rs. Current coverage: DPoP extraction and
    // validation is exercised indirectly through oauth_token tests.
}
