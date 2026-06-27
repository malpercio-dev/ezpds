// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool via AppState, raw JSON body
// Processes: scope validation → account-active check → parse + validate the preferences
//            array → overwrite the account's locally-stored blob
// Returns: 200 (empty body) on success; 400 for a malformed request; 401 for a bad token
//
// Implements: POST /xrpc/app.bsky.actor.putPreferences

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::accounts::account_is_active;
use crate::db::preferences::put_preferences;

#[derive(Deserialize)]
struct PutPreferencesRequest {
    preferences: Vec<Value>,
}

/// POST /xrpc/app.bsky.actor.putPreferences
///
/// Overwrites the account's locally-stored `app.bsky` preferences in their entirety — the
/// write companion to `getPreferences`. Preferences live on the PDS for user data
/// sovereignty rather than being proxied to the AppView, so this route is registered ahead
/// of the `app.bsky.*` catch-all. Like `getPreferences`, only full access-scope tokens are
/// accepted (app passwords cannot write preferences), and a token whose account has since
/// been deactivated or removed is rejected even though the JWT is still cryptographically
/// valid. The body must be `{ "preferences": [ {…}, … ] }`; a malformed body — not an
/// object, missing the field, or a non-object entry — returns 400.
pub async fn put_preferences_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    // A valid JWT is not enough: reject tokens whose account has been deactivated or removed,
    // mirroring `getPreferences`. Without this an unexpired token would keep writing
    // preferences after the account is gone.
    if !account_is_active(&state.db, &user.did).await? {
        tracing::warn!(did = %user.did, "putPreferences: account not found or deactivated");
        return Err(ApiError::new(ErrorCode::InvalidToken, "account not found"));
    }

    // Parse the body ourselves rather than via the `Json` extractor so a malformed request
    // returns our 400 ApiError shape (the extractor's rejection is a 422 with a plain body).
    let request: PutPreferencesRequest = serde_json::from_slice(&body).map_err(|e| {
        tracing::debug!(did = %user.did, error = %e, "putPreferences: malformed request body");
        ApiError::new(ErrorCode::InvalidRequest, "invalid preferences format")
    })?;

    // Each preference is a typed union member in the lexicon, so every entry must be a JSON
    // object. Rejecting scalars/arrays here keeps a malformed write from corrupting later
    // reads (an empty array is valid and clears the stored preferences).
    if !request.preferences.iter().all(Value::is_object) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "each preference must be an object",
        ));
    }

    let blob = serde_json::to_string(&request.preferences).map_err(|e| {
        tracing::error!(did = %user.did, error = %e, "failed to serialize preferences");
        ApiError::new(ErrorCode::InternalError, "failed to store preferences")
    })?;

    put_preferences(&state.db, &user.did, &blob).await?;

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

    use crate::app::{app, test_state};

    /// Issue a valid HS256 access JWT for a DID using the test state's fixed secret.
    fn access_jwt(secret: &[u8; 32], sub: &str) -> String {
        scoped_jwt(secret, sub, "com.atproto.access")
    }

    /// Issue a scoped HS256 JWT (used to exercise wrong-scope rejection paths).
    fn scoped_jwt(secret: &[u8; 32], sub: &str, scope: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": scope,
                "sub": sub,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn put_request(token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/app.bsky.actor.putPreferences")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn get_request(token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/xrpc/app.bsky.actor.getPreferences")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn insert_account(db: &sqlx::SqlitePool, did: &str, email: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(email)
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

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:alice", "alice@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:alice");
        let prefs = serde_json::json!([
            { "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true },
            { "$type": "app.bsky.actor.defs#savedFeedsPrefV2", "items": [] }
        ]);

        let router = app(state);
        let response = router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": prefs }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The stored value must be retrievable verbatim via getPreferences.
        let response = router.oneshot(get_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["preferences"], prefs);
    }

    #[tokio::test]
    async fn put_overwrites_previous_preferences_entirely() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:bob", "bob@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:bob");
        let router = app(state);

        let first = serde_json::json!([{ "$type": "a", "v": 1 }, { "$type": "b" }]);
        let second = serde_json::json!([{ "$type": "c", "v": 2 }]);

        for prefs in [&first, &second] {
            let response = router
                .clone()
                .oneshot(put_request(
                    &token,
                    serde_json::json!({ "preferences": prefs }),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let response = router.oneshot(get_request(&token)).await.unwrap();
        let json = body_json(response).await;
        assert_eq!(
            json["preferences"], second,
            "the second write must replace the first entirely, not merge"
        );
    }

    #[tokio::test]
    async fn empty_array_clears_preferences() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:clear", "clear@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:clear");
        let router = app(state);

        // Store something, then overwrite with an empty array.
        router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": "x" }] }),
            ))
            .await
            .unwrap();
        let response = router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router.oneshot(get_request(&token)).await.unwrap();
        let json = body_json(response).await;
        assert_eq!(json["preferences"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn missing_preferences_field_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:nofield", "nofield@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:nofield");

        let response = app(state)
            .oneshot(put_request(&token, serde_json::json!({ "wrong": [] })))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn non_object_preference_entry_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:scalar", "scalar@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:scalar");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": "ok" }, "not-an-object"] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn malformed_json_body_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:malformed", "malformed@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:malformed");

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/app.bsky.actor.putPreferences")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from("not json {{{"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn preferences_are_not_proxied_to_appview() {
        // putPreferences must be served locally. Point the AppView at an unroutable address:
        // if the request escaped to the proxy it would fail, so a clean 200 proves the local
        // handler matched ahead of the `app.bsky.*` catch-all.
        use std::sync::Arc;
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = "http://127.0.0.1:1".to_string();
        let state = crate::app::AppState {
            config: Arc::new(config),
            ..base
        };
        insert_account(&state.db, "did:plc:carol", "carol@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:carol");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/app.bsky.actor.putPreferences")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "preferences": [] }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn app_pass_token_returns_401() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:apppass", "apppass@example.com").await;
        let token = scoped_jwt(&state.jwt_secret, "did:plc:apppass", "com.atproto.appPass");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn deactivated_account_returns_401() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact", "deact@example.com").await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind("did:plc:deact")
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, "did:plc:deact");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn token_for_nonexistent_account_returns_401() {
        let state = test_state().await;
        // No account inserted — the DID exists only inside the JWT.
        let token = access_jwt(&state.jwt_secret, "did:plc:ghost");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }
}
