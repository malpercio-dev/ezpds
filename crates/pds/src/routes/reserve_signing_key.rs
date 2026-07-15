// pattern: Imperative Shell
//
// Gathers: optional migrating DID, master key (config), DB pool
// Processes: reuse-or-generate reserved P-256 repo signing key → encrypt → store reservation
// Returns: JSON { signingKey }; 503 if no master key

// Implements: POST /xrpc/com.atproto.server.reserveSigningKey

use axum::{
    extract::{connect_info::ConnectInfo, rejection::ExtensionRejection, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::rate_limit::{is_rate_limited, record_failure};
use crate::auth::validation::lock_failed_login_attempts;
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

const ANONYMOUS_RESERVE_SIGNING_KEY_LIMIT: &str = "reserveSigningKey:<anonymous>";

pub async fn reserve_signing_key(
    State(state): State<AppState>,
    remote_addr: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    Json(request): Json<ReserveSigningKeyRequest>,
) -> Result<Json<ReserveSigningKeyResponse>, ApiError> {
    // axum 0.8 dropped the blanket `Option<T>` extractor; `Result` keeps the same
    // "absent under `oneshot` test harnesses" tolerance ConnectInfo needs here.
    let remote_addr = remote_addr.ok();
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

    check_anonymous_reservation_limit(&state, remote_addr.as_ref())?;

    let key = generate_reserved_key(&state)?;
    let inserted = insert_reserved_repo_key(&state.db, did, &key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = ?did, "failed to store reserved signing key");
            ApiError::new(ErrorCode::InternalError, "failed to store signing key")
        })?;

    if !inserted {
        let did = did.ok_or_else(|| {
            tracing::error!("reserved signing-key insert conflicted without a DID");
            ApiError::new(ErrorCode::InternalError, "failed to reserve signing key")
        })?;
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
    if crate::auth::validation::is_valid_did(did) {
        return Ok(());
    }

    Err(ApiError::new(
        ErrorCode::InvalidRequest,
        "did must be a valid DID string",
    ))
}

fn check_anonymous_reservation_limit(
    state: &AppState,
    remote_addr: Option<&ConnectInfo<SocketAddr>>,
) -> Result<(), ApiError> {
    let limiter_key = anonymous_reservation_limiter_key(remote_addr);
    let mut attempts = lock_failed_login_attempts(
        &state.failed_login_attempts,
        Some("reserve_signing_key_anonymous"),
    )?;
    if is_rate_limited(&mut attempts, &limiter_key) {
        return Err(ApiError::new(
            ErrorCode::RateLimited,
            "too many anonymous signing key reservations",
        ));
    }
    record_failure(&mut attempts, &limiter_key);
    Ok(())
}

fn anonymous_reservation_limiter_key(remote_addr: Option<&ConnectInfo<SocketAddr>>) -> String {
    let caller = remote_addr
        .map(|ConnectInfo(addr)| format!("peer:{}", addr.ip()))
        .unwrap_or_else(|| "peer:unknown".to_string());
    format!("{ANONYMOUS_RESERVE_SIGNING_KEY_LIMIT}:{caller}")
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
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use std::net::{IpAddr, SocketAddr};
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::auth::rate_limit::RATE_LIMIT_MAX_FAILURES;
    use crate::routes::test_utils::state_with_master_key;

    fn post_req(body: serde_json::Value) -> Request<Body> {
        post_req_from(body, None)
    }

    fn post_req_from(body: serde_json::Value, caller_ip: Option<&str>) -> Request<Body> {
        let mut req = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.reserveSigningKey")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(caller_ip) = caller_ip {
            let addr = SocketAddr::new(caller_ip.parse::<IpAddr>().unwrap(), 49152);
            req.extensions_mut().insert(ConnectInfo(addr));
        }
        req
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
    async fn anonymous_reservations_are_rate_limited_per_caller() {
        let state = state_with_master_key().await;
        let app = app(state);

        for _ in 0..RATE_LIMIT_MAX_FAILURES {
            let resp = app
                .clone()
                .oneshot(post_req_from(serde_json::json!({}), Some("203.0.113.1")))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let limited = app
            .clone()
            .oneshot(post_req_from(serde_json::json!({}), Some("203.0.113.1")))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let other_caller = app
            .oneshot(post_req_from(serde_json::json!({}), Some("203.0.113.2")))
            .await
            .unwrap();
        assert_eq!(other_caller.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn fresh_did_reservations_are_rate_limited_per_caller() {
        let state = state_with_master_key().await;
        let app = app(state);

        for n in 0..RATE_LIMIT_MAX_FAILURES {
            let resp = app
                .clone()
                .oneshot(post_req_from(
                    serde_json::json!({"did": format!("did:plc:fresh{n}")}),
                    Some("203.0.113.1"),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let limited = app
            .clone()
            .oneshot(post_req_from(
                serde_json::json!({"did":"did:plc:freshlimited"}),
                Some("203.0.113.1"),
            ))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let other_caller = app
            .oneshot(post_req_from(
                serde_json::json!({"did":"did:plc:freshother"}),
                Some("203.0.113.2"),
            ))
            .await
            .unwrap();
        assert_eq!(other_caller.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_did_returns_400() {
        let state = state_with_master_key().await;
        let app = app(state);

        for did in [
            "not a did",
            "did:",
            "did::",
            "did:plc:",
            "did:plc:abc:",
            "did:PLC:abc",
        ] {
            let resp = app
                .clone()
                .oneshot(post_req(serde_json::json!({"did": did})))
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "did={did}");
        }
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
