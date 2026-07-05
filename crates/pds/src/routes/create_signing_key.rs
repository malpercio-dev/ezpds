// pattern: Imperative Shell
//
// Gathers: admin Bearer token (Authorization header), JSON request body, config, DB pool
// Processes: auth check → algorithm check → master key check → key generation → encryption → DB insert
// Returns: JSON { key_id, public_key, algorithm } on success; ApiError on all failure paths

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin_json;

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Algorithm {
    P256,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSigningKeyRequest {
    #[allow(dead_code)]
    algorithm: Algorithm,
}

// Response uses camelCase per JSON API convention (keyId, publicKey).
// The design document shows snake_case field names; this is a deliberate
// deviation — camelCase is standard for JSON responses and matches ATProto conventions.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSigningKeyResponse {
    key_id: String,
    public_key: String,
    algorithm: String,
}

/// `POST /v1/pds/keys` — admin-only operator signing-key creation.
///
/// Auth runs first, over the raw body, so a device signature can bind the exact
/// request bytes; the body is then parsed via `Json::from_bytes` to preserve the
/// same 400/422 statuses the `Json` extractor produced before this route accepted
/// device signatures.
pub async fn create_signing_key(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreateSigningKeyResponse>, Response> {
    require_admin_json(method.as_str(), uri.path(), &headers, &body, &state).await?;

    // Validate the body shape (algorithm enum) using the same rejection semantics as
    // the former `Json` extractor: unknown variant / missing field → 422, null → 400.
    let _ =
        Json::<CreateSigningKeyRequest>::from_bytes(&body).map_err(IntoResponse::into_response)?;

    create_signing_key_inner(&state)
        .await
        .map_err(IntoResponse::into_response)
}

async fn create_signing_key_inner(
    state: &AppState,
) -> Result<Json<CreateSigningKeyResponse>, ApiError> {
    // --- Master key: return 503 if not configured ---
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;

    // --- Generate P-256 keypair ---
    let keypair = crypto::generate_p256_keypair().map_err(|e| {
        tracing::error!(error = %e, "failed to generate P-256 keypair");
        ApiError::new(ErrorCode::InternalError, "key generation failed")
    })?;

    // --- Encrypt private key with AES-256-GCM ---
    // private_key_bytes is Zeroizing<[u8; 32]>; deref coercion to &[u8; 32] applies.
    let private_key_encrypted = crypto::encrypt_private_key(&keypair.private_key_bytes, master_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to encrypt private key");
            ApiError::new(ErrorCode::InternalError, "key encryption failed")
        })?;

    // --- Persist to relay_signing_keys ---
    // created_at uses SQLite's datetime('now') to produce ISO 8601 UTC without a chrono dep.
    crate::db::relay_signing_keys::insert_signing_key(
        &state.db,
        &keypair.key_id.to_string(),
        "p256",
        &keypair.public_key,
        &private_key_encrypted,
    )
    .await?;

    Ok(Json(CreateSigningKeyResponse {
        key_id: keypair.key_id.to_string(),
        public_key: keypair.public_key,
        algorithm: "p256".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    use crate::app::{app, test_state, AppState};
    use common::Sensitive;

    /// Build an AppState with both admin_token and signing_key_master_key configured.
    async fn test_state_with_keys() -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.admin_token = Some("test-admin-token".to_string());
        config.signing_key_master_key = Some(Sensitive(Zeroizing::new([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])));
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Build a POST /v1/pds/keys request with JSON body and optional Bearer token.
    fn post_keys(body: &str, bearer: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/pds/keys")
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    // --- Happy path ---

    #[tokio::test]
    async fn create_signing_key_returns_200_with_key_fields() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(
                r#"{"algorithm": "p256"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["keyId"].is_string(), "keyId must be present");
        assert!(json["publicKey"].is_string(), "publicKey must be present");
        assert_eq!(json["algorithm"], "p256");
    }

    #[tokio::test]
    async fn key_id_is_did_key_uri() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(
                r#"{"algorithm": "p256"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let key_id = json["keyId"].as_str().unwrap();
        assert!(
            key_id.starts_with("did:key:z"),
            "keyId must start with did:key:z, got: {key_id}"
        );
    }

    #[tokio::test]
    async fn public_key_is_multibase_base58btc() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(
                r#"{"algorithm": "p256"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let public_key = json["publicKey"].as_str().unwrap();
        assert!(
            public_key.starts_with('z'),
            "publicKey must start with 'z' (multibase base58btc prefix), got: {public_key}"
        );
        assert!(
            !public_key.starts_with("did:key:"),
            "publicKey must not include did:key: prefix"
        );
    }

    #[tokio::test]
    async fn response_has_no_private_key_field() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(
                r#"{"algorithm": "p256"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("privateKey").is_none(),
            "privateKey must not appear in response"
        );
        assert!(
            json.get("private_key").is_none(),
            "private_key must not appear in response"
        );
    }

    #[tokio::test]
    async fn row_persisted_in_db_with_encrypted_private_key() {
        let state = test_state_with_keys().await;
        let db = state.db.clone();

        let response = app(state)
            .oneshot(post_keys(
                r#"{"algorithm": "p256"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let key_id = json["keyId"].as_str().unwrap();

        // Verify the row exists and has the expected fields.
        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT id, algorithm, public_key, private_key_encrypted \
             FROM relay_signing_keys WHERE id = ?",
        )
        .bind(key_id)
        .fetch_one(&db)
        .await
        .expect("row must exist in relay_signing_keys after successful creation");

        assert_eq!(row.0, key_id, "db id must match response keyId");
        assert_eq!(row.1, "p256", "db algorithm must be p256");
        assert_eq!(
            row.2,
            json["publicKey"].as_str().unwrap(),
            "db public_key must match response publicKey"
        );
        // base64(12-byte nonce || 32-byte ciphertext || 16-byte tag) = base64(60 bytes) = 80 chars
        assert_eq!(
            row.3.len(),
            80,
            "private_key_encrypted must be 80 base64 chars (nonce 12 + ciphertext 32 + tag 16)"
        );
    }

    // --- Auth tests ---

    #[tokio::test]
    async fn missing_authorization_header_returns_401() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(r#"{"algorithm": "p256"}"#, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_bearer_token_returns_401() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(r#"{"algorithm": "p256"}"#, Some("wrong-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bare_token_without_bearer_prefix_returns_401() {
        // Authorization header present but "Bearer " prefix missing
        let request = Request::builder()
            .method("POST")
            .uri("/v1/pds/keys")
            .header("Content-Type", "application/json")
            .header("Authorization", "test-admin-token") // no "Bearer " prefix
            .body(Body::from(r#"{"algorithm": "p256"}"#))
            .unwrap();

        let response = app(test_state_with_keys().await)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Algorithm tests ---

    #[tokio::test]
    async fn unsupported_algorithm_returns_422() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(
                r#"{"algorithm": "k256"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn empty_algorithm_returns_422() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(r#"{"algorithm": ""}"#, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn missing_algorithm_field_returns_422() {
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(r#"{}"#, Some("test-admin-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn null_algorithm_returns_400() {
        // null is a distinct JSON token that some API clients send for unset fields.
        // Unlike missing/invalid enum variants (422), Axum's default JSON rejection treats
        // null deserialization as a general Bad Request (400).
        let response = app(test_state_with_keys().await)
            .oneshot(post_keys(
                r#"{"algorithm": null}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // --- Master key test ---

    #[tokio::test]
    async fn missing_master_key_returns_503() {
        // signing_key_master_key not configured → 503
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.admin_token = Some("test-admin-token".to_string());
        // signing_key_master_key intentionally left as None
        let state = AppState {
            config: Arc::new(config),
            ..base
        };

        let response = app(state)
            .oneshot(post_keys(
                r#"{"algorithm": "p256"}"#,
                Some("test-admin-token"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn non_json_content_type_returns_415() {
        // Valid JSON body + valid token, but a non-JSON media type: matches the former
        // `Json` extractor's 415 rejection.
        let request = Request::builder()
            .method("POST")
            .uri("/v1/pds/keys")
            .header("Content-Type", "text/plain")
            .header("Authorization", "Bearer test-admin-token")
            .body(Body::from(r#"{"algorithm": "p256"}"#))
            .unwrap();
        let response = app(test_state_with_keys().await)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn admin_token_not_configured_returns_401() {
        // Operator has not set EZPDS_ADMIN_TOKEN; any request to the endpoint returns 401.
        // test_state() leaves admin_token as None by default.
        let response = app(test_state().await)
            .oneshot(post_keys(r#"{"algorithm": "p256"}"#, Some("any-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
