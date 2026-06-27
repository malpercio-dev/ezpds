// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool via AppState
// Processes: scope validation → load the account's locally-stored preferences blob
// Returns: JSON { preferences: [...] }; an empty array for accounts with none stored
//
// Implements: GET /xrpc/app.bsky.actor.getPreferences

use axum::{extract::State, response::Json};
use serde::Serialize;
use serde_json::Value;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::preferences::get_preferences;

#[derive(Serialize)]
pub struct GetPreferencesResponse {
    pub preferences: Vec<Value>,
}

/// GET /xrpc/app.bsky.actor.getPreferences
///
/// Preferences are stored locally on the PDS for user data sovereignty rather than proxied
/// to the AppView (unlike most `app.bsky.*` methods, which the catch-all forwards). A new
/// account with nothing stored returns an empty array. Like `getSession`, only full
/// access-scope tokens are accepted — app passwords cannot read preferences.
pub async fn get_preferences_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<GetPreferencesResponse>, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    let preferences: Vec<Value> = match get_preferences(&state.db, &user.did).await? {
        Some(blob) => serde_json::from_str(&blob).map_err(|e| {
            tracing::error!(did = %user.did, error = %e, "stored preferences blob is not valid JSON");
            ApiError::new(ErrorCode::InternalError, "stored preferences are corrupt")
        })?,
        None => Vec::new(),
    };

    Ok(Json(GetPreferencesResponse { preferences }))
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

    /// Issue an app-password-scope JWT (must be rejected by getPreferences).
    fn app_pass_jwt(secret: &[u8; 32], sub: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": "com.atproto.appPass",
                "sub": sub,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn get_preferences_request(token: &str) -> Request<Body> {
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

    async fn insert_preferences(db: &sqlx::SqlitePool, did: &str, blob: &str) {
        sqlx::query(
            "INSERT INTO account_preferences (did, preferences, updated_at) \
             VALUES (?, ?, datetime('now'))",
        )
        .bind(did)
        .bind(blob)
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
    async fn new_account_returns_empty_preferences() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:alice", "alice@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:alice");

        let response = app(state)
            .oneshot(get_preferences_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(
            json["preferences"],
            serde_json::json!([]),
            "an account with nothing stored must return an empty array"
        );
    }

    #[tokio::test]
    async fn returns_stored_preferences() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:bob", "bob@example.com").await;
        let stored = serde_json::json!([
            { "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true },
            { "$type": "app.bsky.actor.defs#savedFeedsPrefV2", "items": [] }
        ]);
        insert_preferences(&state.db, "did:plc:bob", &stored.to_string()).await;
        let token = access_jwt(&state.jwt_secret, "did:plc:bob");

        let response = app(state)
            .oneshot(get_preferences_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["preferences"], stored);
    }

    #[tokio::test]
    async fn preferences_are_not_proxied_to_appview() {
        // getPreferences must be served locally. Point the AppView at an unroutable address:
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
            .oneshot(get_preferences_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["preferences"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/xrpc/app.bsky.actor.getPreferences")
                    .body(Body::empty())
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
        let token = app_pass_jwt(&state.jwt_secret, "did:plc:apppass");

        let response = app(state)
            .oneshot(get_preferences_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn corrupt_stored_blob_returns_500() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:corrupt", "corrupt@example.com").await;
        insert_preferences(&state.db, "did:plc:corrupt", "this is not json {{{").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:corrupt");

        let response = app(state)
            .oneshot(get_preferences_request(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
