// pattern: Imperative Shell
//
// Gathers: DB pool (via AppState)
// Processes: SELECT most recently created signing key
// Returns: JSON { keyId, publicKey, algorithm } on success; 503 if no key provisioned

use axum::{extract::State, response::Json};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::relay_signing_keys::{latest_signing_key, RelaySigningKey};

// Response uses camelCase per JSON API convention (keyId, publicKey).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPdsSigningKeyResponse {
    key_id: String,
    public_key: String,
    algorithm: String,
}

pub async fn get_pds_signing_key(
    State(state): State<AppState>,
) -> Result<Json<GetPdsSigningKeyResponse>, ApiError> {
    let RelaySigningKey {
        id,
        public_key,
        algorithm,
    } = latest_signing_key(&state.db).await?.ok_or_else(|| {
        ApiError::new(ErrorCode::ServiceUnavailable, "no signing key provisioned")
    })?;

    Ok(Json(GetPdsSigningKeyResponse {
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
    /// placeholder below encodes 63 bytes (with padding characters) — replace with a valid 80-char value
    /// (60 bytes, no padding) if a test ever needs to read private_key_encrypted back.
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

    /// Build a GET /v1/pds/keys request with no Authorization header (public endpoint).
    fn get_keys() -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/v1/pds/keys")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn get_pds_keys_returns_503_when_no_key_provisioned() {
        let response = app(test_state().await).oneshot(get_keys()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn get_pds_keys_returns_200_with_active_key() {
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
        assert_eq!(json["publicKey"], "zTestPublicKey123");
    }

    #[tokio::test]
    async fn get_pds_keys_returns_most_recently_created_key() {
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

    #[tokio::test]
    async fn get_pds_keys_requires_no_authentication() {
        // test_state() has no admin_token configured.
        // get_keys() sends no Authorization header.
        // If the endpoint incorrectly required auth, this would return 401 instead of 200.
        let state = test_state().await;
        insert_test_key(&state.db, "did:key:zPublicKey", "2026-01-01T00:00:00").await;

        let response = app(state).oneshot(get_keys()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
