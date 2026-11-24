// pattern: Imperative Shell
//
// Gathers: optional migrating DID, master key (config), DB pool
// Processes: reuse-or-generate reserved P-256 key → encrypt → store reservation
// Returns: JSON { signingKey } / { kemKey }; 503 if no master key

// Implements: POST /xrpc/com.atproto.server.reserveSigningKey
//             POST /xrpc/com.atproto.server.reserveKemKey

//! The two key reservations an account needs before it exists: its repo signing key and its
//! Spaces KEM key (ADR-0043). A client that builds a did:plc op before the account is created
//! (an inbound migration, or a wallet minting an agent child) reserves both, so the op can name
//! keys this server already holds. The two are identical apart from the table they are filed
//! in, so one handler body serves both.

use axum::{
    extract::{connect_info::ConnectInfo, rejection::ExtensionRejection, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use custos_core::auth::rate_limit::{is_rate_limited, record_failure};
use custos_core::auth::validation::lock_failed_login_attempts;
use custos_core::lexicon::LexiconInput;
use custos_db::repo_keys::RepoSigningKey;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveKeyRequest {
    did: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveSigningKeyResponse {
    signing_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveKemKeyResponse {
    kem_key: String,
}

/// Which reservation a request makes.
#[derive(Debug, Clone, Copy)]
enum Reservation {
    Signing,
    Kem,
}

impl Reservation {
    /// Per-family anonymous limiter key prefix, so minting an agent child (which reserves one of
    /// each) does not spend twice from one budget.
    fn limiter_prefix(self) -> &'static str {
        match self {
            Reservation::Signing => "reserveSigningKey:<anonymous>",
            Reservation::Kem => "reserveKemKey:<anonymous>",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Reservation::Signing => "signing key",
            Reservation::Kem => "KEM key",
        }
    }

    async fn get_by_did(
        self,
        state: &AppState,
        did: &common::Did,
    ) -> Result<Option<RepoSigningKey>, sqlx::Error> {
        match self {
            Reservation::Signing => {
                custos_db::repo_keys::get_reserved_repo_key_by_did(&state.db, did).await
            }
            Reservation::Kem => {
                custos_db::kem_keys::get_reserved_kem_key_by_did(&state.db, did).await
            }
        }
    }

    async fn insert(
        self,
        state: &AppState,
        did: Option<&common::Did>,
        key: &RepoSigningKey,
    ) -> Result<bool, sqlx::Error> {
        let did = did.map(common::Did::as_str);
        match self {
            Reservation::Signing => {
                custos_db::repo_keys::insert_reserved_repo_key(&state.db, did, key).await
            }
            Reservation::Kem => {
                custos_db::kem_keys::insert_reserved_kem_key(&state.db, did, key).await
            }
        }
    }
}

pub async fn reserve_signing_key(
    State(state): State<AppState>,
    remote_addr: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    LexiconInput(request): LexiconInput<ReserveKeyRequest>,
) -> Result<Json<ReserveSigningKeyResponse>, ApiError> {
    let signing_key = reserve(&state, remote_addr, request, Reservation::Signing).await?;
    Ok(Json(ReserveSigningKeyResponse { signing_key }))
}

/// Reserve the KEM key a not-yet-created account will publish as `#atproto_kem`. Filed under the
/// DID when one is given (an inbound migration), otherwise under its own did:key (an agent child,
/// whose DID is the hash of an op that must already name the key).
pub async fn reserve_kem_key(
    State(state): State<AppState>,
    remote_addr: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    LexiconInput(request): LexiconInput<ReserveKeyRequest>,
) -> Result<Json<ReserveKemKeyResponse>, ApiError> {
    let kem_key = reserve(&state, remote_addr, request, Reservation::Kem).await?;
    Ok(Json(ReserveKemKeyResponse { kem_key }))
}

/// Return the reservation already filed under the DID, or mint and file a fresh one. Returns the
/// reserved key's did:key.
async fn reserve(
    state: &AppState,
    remote_addr: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    request: ReserveKeyRequest,
    family: Reservation,
) -> Result<String, ApiError> {
    let label = family.label();
    let read_error = |e: sqlx::Error| {
        tracing::error!(error = %e, "failed to read reserved {label}");
        ApiError::new(ErrorCode::InternalError, format!("failed to read {label}"))
    };
    // axum 0.8 dropped the blanket `Option<T>` extractor; `Result` keeps the same
    // "absent under `oneshot` test harnesses" tolerance ConnectInfo needs here.
    let remote_addr = remote_addr.ok();
    let did = request
        .did
        .as_deref()
        .map(str::trim)
        .filter(|did| !did.is_empty())
        .map(validate_did)
        .transpose()?;
    if let Some(did) = &did {
        if let Some(existing) = family.get_by_did(state, did).await.map_err(read_error)? {
            return Ok(existing.key_id);
        }
    }

    check_anonymous_reservation_limit(state, remote_addr.as_ref(), family)?;

    let key = custos_core::kem::generate_wrapped_key(state)?;
    let inserted = family
        .insert(state, did.as_ref(), &key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = ?did, "failed to store reserved {label}");
            ApiError::new(ErrorCode::InternalError, format!("failed to store {label}"))
        })?;

    if !inserted {
        // A concurrent request filed a reservation under the same DID first; return that one.
        let did = did.as_ref().ok_or_else(|| {
            tracing::error!("reserved {label} insert conflicted without a DID");
            ApiError::new(
                ErrorCode::InternalError,
                format!("failed to reserve {label}"),
            )
        })?;
        let existing = family
            .get_by_did(state, did)
            .await
            .map_err(read_error)?
            .ok_or_else(|| {
                tracing::error!(did = %did, "reserved {label} conflict row disappeared");
                ApiError::new(
                    ErrorCode::InternalError,
                    format!("failed to reserve {label}"),
                )
            })?;
        return Ok(existing.key_id);
    }

    Ok(key.key_id)
}

fn validate_did(did: &str) -> Result<common::Did, ApiError> {
    common::Did::parse(did)
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "did must be a valid DID string"))
}

fn check_anonymous_reservation_limit(
    state: &AppState,
    remote_addr: Option<&ConnectInfo<SocketAddr>>,
    family: Reservation,
) -> Result<(), ApiError> {
    let caller = remote_addr
        .map(|ConnectInfo(addr)| format!("peer:{}", addr.ip()))
        .unwrap_or_else(|| "peer:unknown".to_string());
    let limiter_key = format!("{}:{caller}", family.limiter_prefix());
    let mut attempts =
        lock_failed_login_attempts(&state.failed_login_attempts, Some("reserve_key_anonymous"))?;
    if is_rate_limited(&mut attempts, &limiter_key) {
        return Err(ApiError::new(
            ErrorCode::RateLimited,
            format!("too many anonymous {} reservations", family.label()),
        ));
    }
    record_failure(&mut attempts, &limiter_key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use std::net::{IpAddr, SocketAddr};
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::{body_json, state_with_master_key};
    use custos_core::auth::rate_limit::RATE_LIMIT_MAX_FAILURES;

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
    async fn kem_key_reservations_are_filed_apart_from_signing_keys() {
        let state = state_with_master_key().await;
        let db = state.db.clone();
        let app = app(state);
        let kem_req = |body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.server.reserveKemKey")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let body = serde_json::json!({"did":"did:plc:kemmigrant"});

        let first = body_json(app.clone().oneshot(kem_req(body.clone())).await.unwrap()).await;
        let second = body_json(app.clone().oneshot(kem_req(body.clone())).await.unwrap()).await;
        let signing = body_json(app.oneshot(post_req(body)).await.unwrap()).await;

        let kem_key = first["kemKey"].as_str().unwrap();
        assert!(kem_key.starts_with("did:key:z"));
        assert_eq!(second["kemKey"], first["kemKey"]);
        assert_ne!(signing["signingKey"].as_str().unwrap(), kem_key);
        let filed = custos_db::kem_keys::get_reserved_kem_key_by_did(&db, "did:plc:kemmigrant")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(filed.key_id, kem_key);
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
