// pattern: Imperative Shell
//
// Gathers: optional migrating DID, master key (config), DB pool
// Processes: reuse-or-generate reserved P-256 repo signing key → encrypt → store reservation
// Returns: JSON { signingKey }; 503 if no master key

// Implements: POST /xrpc/com.atproto.server.reserveSigningKey

use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::db::repo_keys::{
    get_reserved_repo_key_by_did, insert_reserved_repo_key, RepoSigningKey,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveSigningKeyRequest {
    did: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveSigningKeyResponse {
    signing_key: String,
}

pub async fn reserve_signing_key(
    State(state): State<AppState>,
    Json(request): Json<ReserveSigningKeyRequest>,
) -> Result<Json<ReserveSigningKeyResponse>, ApiError> {
    let did = request
        .did
        .as_deref()
        .map(str::trim)
        .filter(|did| !did.is_empty());
    if let Some(did) = did {
        validate_did(did)?;
        if let Some(existing) = get_reserved_repo_key_by_did(&state.db, did)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to read reserved signing key");
                ApiError::new(ErrorCode::InternalError, "failed to read signing key")
            })?
        {
            return Ok(Json(ReserveSigningKeyResponse {
                signing_key: existing.key_id,
            }));
        }
    }

    let key = generate_reserved_key(&state)?;
    let inserted = insert_reserved_repo_key(&state.db, did, &key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = ?did, "failed to store reserved signing key");
            ApiError::new(ErrorCode::InternalError, "failed to store signing key")
        })?;

    if !inserted {
        let did = did.expect("only DID-keyed reservations can conflict");
        let existing = get_reserved_repo_key_by_did(&state.db, did)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, did = %did, "failed to read conflicted reserved signing key");
                ApiError::new(ErrorCode::InternalError, "failed to read signing key")
            })?
            .ok_or_else(|| {
                tracing::error!(did = %did, "reserved signing-key conflict row disappeared");
                ApiError::new(ErrorCode::InternalError, "failed to reserve signing key")
            })?;
        return Ok(Json(ReserveSigningKeyResponse {
            signing_key: existing.key_id,
        }));
    }

    Ok(Json(ReserveSigningKeyResponse {
        signing_key: key.key_id,
    }))
}

fn validate_did(did: &str) -> Result<(), ApiError> {
    if did.starts_with("did:") && !did.chars().any(char::is_whitespace) {
        return Ok(());
    }

    Err(ApiError::new(
        ErrorCode::InvalidRequest,
        "did must be a valid DID string",
    ))
}

fn generate_reserved_key(state: &AppState) -> Result<RepoSigningKey, ApiError> {
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

    let keypair = crypto::generate_p256_keypair().map_err(|e| {
        tracing::error!(error = %e, "failed to generate reserved signing key");
        ApiError::new(ErrorCode::InternalError, "key generation failed")
    })?;
    let private_key_encrypted = crypto::encrypt_private_key(&keypair.private_key_bytes, master_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to encrypt reserved signing key");
            ApiError::new(ErrorCode::InternalError, "key encryption failed")
        })?;

    Ok(RepoSigningKey {
        key_id: keypair.key_id.to_string(),
        public_key: keypair.public_key,
        private_key_encrypted,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    use common::Sensitive;

    use crate::app::{app, test_state, AppState};

    async fn state_with_master_key() -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.signing_key_master_key = Some(Sensitive(Zeroizing::new([7u8; 32])));
        AppState {
            config: Arc::new(config),
            db: base.db,
            http_client: base.http_client,
            dns_provider: base.dns_provider,
            txt_resolver: base.txt_resolver,
            well_known_resolver: base.well_known_resolver,
            jwt_secret: base.jwt_secret,
            oauth_signing_keypair: base.oauth_signing_keypair,
            dpop_nonces: base.dpop_nonces,
            failed_login_attempts: base.failed_login_attempts,
            firehose: base.firehose,
            crawlers: base.crawlers,
            iroh: base.iroh,
        }
    }

    fn post_req(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.reserveSigningKey")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn reserves_key_without_auth() {
        let state = state_with_master_key().await;
        let app = app(state);

        let resp = app
            .oneshot(post_req(serde_json::json!({"did":"did:plc:migrating"})))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let signing_key = json["signingKey"].as_str().unwrap();
        assert!(signing_key.starts_with("did:key:z"));
    }

    #[tokio::test]
    async fn reservation_is_idempotent_by_did() {
        let state = state_with_master_key().await;
        let app = app(state);
        let body = serde_json::json!({"did":"did:plc:sameacct"});

        let resp1 = app.clone().oneshot(post_req(body.clone())).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        let key1 = body_json(resp1).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();

        let resp2 = app.oneshot(post_req(body)).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let key2 = body_json(resp2).await["signingKey"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(key2, key1);
    }

    #[tokio::test]
    async fn missing_did_is_allowed_for_lexicon_compatibility() {
        let state = state_with_master_key().await;
        let app = app(state);

        let resp = app.oneshot(post_req(serde_json::json!({}))).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["signingKey"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z"));
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = state_with_master_key().await;
        let app = app(state);

        let resp = app
            .oneshot(post_req(serde_json::json!({"did":"not a did"})))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn no_master_key_returns_503() {
        let state = test_state().await;
        let app = app(state);

        let resp = app
            .oneshot(post_req(serde_json::json!({"did":"did:plc:migrating"})))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
