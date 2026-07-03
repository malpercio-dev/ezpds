// pattern: Imperative Shell
//
// Gathers: pending-session Bearer token, master key (config), DB pool
// Processes: auth → reuse-or-generate per-account P-256 key → encrypt → store on pending account
// Returns: JSON { keyId, publicKey, algorithm }; 401 without a pending session; 503 if no master key

//! GET /v1/repo-signing-key — issue (idempotently) the authenticated pending
//! account's ATProto repo signing key. The wallet publishes the returned
//! did:key as the new DID's `#atproto` verification method, and the PDS later
//! signs every repo commit with the matching private key. Replaces the shared
//! operator key (`relay_signing_keys`) for repo signing with a per-account key.

use axum::{extract::State, http::HeaderMap, response::Json};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_pending_session;
use crate::db::repo_keys::{get_pending_repo_key, set_pending_repo_key, RepoSigningKey};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoSigningKeyResponse {
    key_id: String,
    public_key: String,
    algorithm: String,
}

pub async fn get_repo_signing_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RepoSigningKeyResponse>, ApiError> {
    let session = require_pending_session(&headers, &state.db).await?;

    // Idempotent: a retried ceremony must receive the same key it already
    // published, or op verification at /v1/dids would reject the mismatch.
    if let Some(existing) = get_pending_repo_key(&state.db, &session.account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to read pending repo signing key");
            ApiError::new(ErrorCode::InternalError, "failed to read signing key")
        })?
    {
        return Ok(Json(RepoSigningKeyResponse {
            key_id: existing.key_id,
            public_key: existing.public_key,
            algorithm: "p256".to_string(),
        }));
    }

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
        tracing::error!(error = %e, "failed to generate repo signing key");
        ApiError::new(ErrorCode::InternalError, "key generation failed")
    })?;
    let private_key_encrypted = crypto::encrypt_private_key(&keypair.private_key_bytes, master_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to encrypt repo signing key");
            ApiError::new(ErrorCode::InternalError, "key encryption failed")
        })?;

    let key = RepoSigningKey {
        key_id: keypair.key_id.to_string(),
        public_key: keypair.public_key,
        private_key_encrypted,
    };
    set_pending_repo_key(&state.db, &session.account_id, &key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to store repo signing key");
            ApiError::new(ErrorCode::InternalError, "failed to store signing key")
        })?;

    Ok(Json(RepoSigningKeyResponse {
        key_id: key.key_id,
        public_key: key.public_key,
        algorithm: "p256".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sqlx::SqlitePool;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    use crate::app::{app, test_state, AppState};
    use common::Sensitive;

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
            rate_limiter: base.rate_limiter,
            allow_loopback_proxy_targets: base.allow_loopback_proxy_targets,
        }
    }

    /// Seed a claim code, pending account, device, and pending session.
    /// Returns (account_id, session_token_plaintext).
    async fn seed_pending_session(pool: &SqlitePool) -> (String, String) {
        use crate::token::generate_token;
        use uuid::Uuid;

        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(pool)
        .await
        .unwrap();

        let account_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(format!("t{}@example.com", &account_id[..8]))
        .bind(format!("t{}.example.com", &account_id[..8]))
        .bind(&claim_code)
        .execute(pool)
        .await
        .unwrap();

        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'pk', 'th', datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .execute(pool)
        .await
        .unwrap();

        let token = generate_token();
        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token.hash)
        .execute(pool)
        .await
        .unwrap();

        (account_id, token.plaintext)
    }

    fn get_req(token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method("GET").uri("/v1/repo-signing-key");
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn requires_pending_session() {
        let state = state_with_master_key().await;
        let app = app(state);
        let resp = app.oneshot(get_req(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn generates_and_is_idempotent() {
        let state = state_with_master_key().await;
        let (_account_id, token) = seed_pending_session(&state.db).await;
        let app = app(state);

        let resp1 = app.clone().oneshot(get_req(Some(&token))).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        let j1 = body_json(resp1).await;
        let key_id1 = j1["keyId"].as_str().unwrap().to_string();
        assert!(key_id1.starts_with("did:key:z"));
        assert_eq!(j1["algorithm"], "p256");

        // Second call with the same pending session must return the SAME key.
        let resp2 = app.oneshot(get_req(Some(&token))).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let j2 = body_json(resp2).await;
        assert_eq!(j2["keyId"].as_str().unwrap(), key_id1);
    }

    #[tokio::test]
    async fn no_master_key_returns_503() {
        let state = test_state().await; // master key is None
        let (_account_id, token) = seed_pending_session(&state.db).await;
        let app = app(state);
        let resp = app.oneshot(get_req(Some(&token))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn load_repo_signer_reconstructs_the_stored_key() {
        use crate::db::repo_keys::{insert_did_signing_key, RepoSigningKey};
        use repo_engine::CommitSigner;

        let state = test_state().await;
        let master = [9u8; 32];
        let did = "did:plc:signerload";
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'sl@example.com', 'h', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let kp = crypto::generate_p256_keypair().unwrap();
        let enc = crypto::encrypt_private_key(&kp.private_key_bytes, &master).unwrap();
        insert_did_signing_key(
            &state.db,
            did,
            &RepoSigningKey {
                key_id: kp.key_id.to_string(),
                public_key: kp.public_key.clone(),
                private_key_encrypted: enc,
            },
        )
        .await
        .unwrap();

        // The loaded signer must be the SAME key — deterministic RFC6979 sigs match.
        let loaded = crate::auth::signing_key::load_repo_signer(&state.db, did, &master)
            .await
            .unwrap();
        let direct = CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
        assert_eq!(loaded.sign(b"commit bytes"), direct.sign(b"commit bytes"));

        // A wrong master key must fail (auth-tag mismatch), not return a bogus signer.
        let wrong = crate::auth::signing_key::load_repo_signer(&state.db, did, &[0u8; 32]).await;
        assert!(wrong.is_err());
    }
}
