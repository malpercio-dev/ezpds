// pattern: Imperative Shell
//
// Gathers: DB pool (via AppState)
// Processes: SELECT most recently created signing key
// Returns: JSON { keyId, publicKey, algorithm } on success; 503 if no key provisioned

use axum::{extract::State, response::Json};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

// Response uses camelCase per JSON API convention (keyId, publicKey).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRelaySigningKeyResponse {
    key_id: String,
    public_key: String,
    algorithm: String,
}

pub async fn get_relay_signing_key(
    State(state): State<AppState>,
) -> Result<Json<GetRelaySigningKeyResponse>, ApiError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key, algorithm \
         FROM relay_signing_keys \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query relay signing key");
        ApiError::new(ErrorCode::InternalError, "failed to query signing key")
    })?;

    let (id, public_key, algorithm) = row.ok_or_else(|| {
        ApiError::new(ErrorCode::ServiceUnavailable, "no signing key provisioned")
    })?;

    Ok(Json(GetRelaySigningKeyResponse {
        key_id: id,
        public_key,
        algorithm,
    }))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    /// Insert a signing key row directly into the test DB.
    /// `created_at` is an ISO 8601 UTC string, e.g. `"2026-01-01T00:00:00"`.
    ///
    /// `private_key_encrypted` is a NOT NULL column, but the GET handler never reads it,
    /// so any valid base64 value satisfies the constraint. The real format is
    /// base64(nonce(12) || ciphertext(32) || tag(16)) = 80 base64 chars. The 84-char
    /// placeholder below (60 zero-bytes base64-encoded + padding) is intentionally a
    /// dummy — replace with a correct 80-char value if a test ever needs to read
    /// private_key_encrypted back.
    async fn insert_test_key(db: &sqlx::SqlitePool, key_id: &str, created_at: &str) {
        sqlx::query(
            "INSERT INTO relay_signing_keys \
             (id, algorithm, public_key, private_key_encrypted, created_at) \
             VALUES (?, 'p256', 'zTestPublicKey123', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==', ?)",
        )
        .bind(key_id)
        .bind(created_at)
        .execute(db)
        .await
        .unwrap();
    }

    /// Build a GET /v1/relay/keys request with no Authorization header (public endpoint).
    fn get_keys() -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/v1/relay/keys")
            .body(Body::empty())
            .unwrap()
    }

    // MM-146.AC1.3: Returns 503 when no signing key is provisioned.
    #[tokio::test]
    async fn get_relay_keys_returns_503_when_no_key_provisioned() {
        let response = app(test_state().await).oneshot(get_keys()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // MM-146.AC1.1: Returns 200 with { keyId, publicKey, algorithm } when a key is provisioned.
    #[tokio::test]
    async fn get_relay_keys_returns_200_with_active_key() {
        let state = test_state().await;
        insert_test_key(&state.db, "did:key:zTestKey1", "2026-01-01T00:00:00").await;

        let response = app(state).oneshot(get_keys()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["keyId"], "did:key:zTestKey1");
        assert_eq!(json["algorithm"], "p256");
        assert!(json["publicKey"].is_string(), "publicKey must be present");
    }

    // MM-146.AC1.2: Returns the most recently created key when multiple keys exist.
    #[tokio::test]
    async fn get_relay_keys_returns_most_recently_created_key() {
        let state = test_state().await;
        insert_test_key(&state.db, "did:key:zOlderKey", "2026-01-01T00:00:00").await;
        insert_test_key(&state.db, "did:key:zNewerKey", "2026-01-02T00:00:00").await;

        let response = app(state).oneshot(get_keys()).await.unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["keyId"], "did:key:zNewerKey",
            "must return the key with the most recent created_at"
        );
    }

    // MM-146.AC1.4: Endpoint requires no authentication.
    #[tokio::test]
    async fn get_relay_keys_requires_no_authentication() {
        // test_state() has no admin_token configured.
        // get_keys() sends no Authorization header.
        // If the endpoint incorrectly required auth, this would return 401 instead of 200.
        let state = test_state().await;
        insert_test_key(&state.db, "did:key:zPublicKey", "2026-01-01T00:00:00").await;

        let response = app(state).oneshot(get_keys()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
