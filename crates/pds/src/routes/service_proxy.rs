// pattern: Imperative Shell
//
// Gathers: an incoming XRPC request (method, query, headers, body) bound for an upstream
//          atproto service — the AppView for `app.bsky.*`, the chat service for `chat.bsky.*`
// Processes: mints a fresh ES256 service-auth JWT (signed by the account's repo key) and
//            forwards the request to the given upstream under that token
// Returns: the upstream's status, content-type, and streamed response body

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Maximum buffered request body when proxying to an upstream service. `app.bsky.*` and
/// `chat.bsky.*` procedures carry small JSON payloads (preferences, mutes, message sends);
/// anything larger is almost certainly a mistake, so it is rejected rather than buffered.
const MAX_PROXY_BODY: usize = 1024 * 1024; // 1 MiB

/// Returns true when an [`axum::body::to_bytes`] error was caused by the body exceeding the
/// length limit (rather than the body stream failing). `to_bytes` wraps the over-limit case as
/// an [`http_body_util::LengthLimitError`] in the error's source chain.
fn is_length_limit_error(err: &axum::Error) -> bool {
    std::error::Error::source(err)
        .map(|src| src.is::<http_body_util::LengthLimitError>())
        .unwrap_or(false)
}

/// Forward an XRPC request to an upstream atproto service (the AppView or the chat service).
///
/// `upstream_url` is the service base URL (no trailing slash) and `proxy_did` is its service
/// DID, sent as the `atproto-proxy` header so the upstream knows the request arrives on the
/// user's behalf via their PDS. `did` is the authenticated account DID. A fresh ES256
/// service-auth JWT (signed by the account's `#atproto` repo key, `iss`=account DID,
/// `aud`=service DID, `lxm`=method, 60s TTL) is minted and attached as the `Authorization`; the
/// caller's own PDS session token is **not** forwarded (the AppView can't verify it). The
/// upstream status, content type, and body are streamed straight back; a failure to reach the
/// upstream maps to `503`, while upstream error *responses* (4xx/5xx) are passed through verbatim.
pub async fn proxy_xrpc(
    state: &AppState,
    upstream_url: &str,
    proxy_did: &str,
    nsid: &str,
    did: &str,
    req: Request,
) -> Response {
    // Preserve the original query string verbatim so upstream query params survive the hop.
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target = format!("{upstream_url}/xrpc/{nsid}{query}");

    let (parts, body) = req.into_parts();

    let body_bytes = match axum::body::to_bytes(body, MAX_PROXY_BODY).await {
        Ok(bytes) => bytes,
        Err(err) => {
            // `to_bytes` fails for two distinct reasons: the body exceeded `MAX_PROXY_BODY`, or
            // the body stream itself errored (client disconnect, read timeout, framing error).
            // Only the former is a genuine 413; a broken stream is a 400 so the client isn't
            // misled into thinking its payload was too large.
            if is_length_limit_error(&err) {
                return ApiError::new(
                    ErrorCode::PayloadTooLarge,
                    "request body exceeds the proxy limit",
                )
                .into_response();
            }
            tracing::warn!(error = %err, nsid, "failed to read request body while proxying XRPC");
            return ApiError::new(ErrorCode::InvalidRequest, "failed to read request body")
                .into_response();
        }
    };

    // Mint a fresh ES256 service-auth JWT signed by the account's `#atproto` repo key. The
    // upstream verifies it against the user's DID; forwarding the user's PDS session token
    // instead is rejected with "poorly formatted jwt" (HS256, no `iss`, signed by a secret no
    // third party holds).
    let service_jwt = match mint_service_auth(state, did, proxy_did, nsid).await {
        Ok(jwt) => jwt,
        Err(resp) => return resp,
    };

    // reqwest 0.12 and axum 0.7 share the same `http` crate, so `Method` and `HeaderValue` are
    // identical types and move across the boundary without conversion.
    let mut outbound = state.http_client.request(parts.method, &target);

    // Pass content-type and the client's content-negotiation preference through; the inbound
    // Authorization is intentionally DROPPED and replaced with the minted service-auth JWT. Host,
    // content-length, and connection are hop-by-hop or recomputed by reqwest.
    for name in [header::CONTENT_TYPE, header::ACCEPT] {
        if let Some(val) = parts.headers.get(&name) {
            outbound = outbound.header(name, val);
        }
    }
    outbound = outbound
        .header(header::AUTHORIZATION, format!("Bearer {service_jwt}"))
        .header("atproto-proxy", proxy_did);

    if !body_bytes.is_empty() {
        outbound = outbound.body(body_bytes);
    }

    let upstream = match outbound.send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(error = %err, nsid, "upstream proxy request failed");
            return ApiError::new(
                ErrorCode::ServiceUnavailable,
                "failed to reach the upstream service",
            )
            .into_response();
        }
    };

    // Map status and content-type, then stream the body through without buffering it.
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }

    match builder.body(Body::from_stream(upstream.bytes_stream())) {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, nsid, "failed to build proxy response");
            ApiError::new(ErrorCode::InternalError, "proxy response build failed").into_response()
        }
    }
}

/// Mint a fresh ES256 service-auth JWT for proxying `nsid` to `proxy_did` on behalf of `did`.
///
/// Loads the account's `#atproto` repo signing key (decrypting it with the configured master
/// key) and signs a short-lived token: `iss` = the account DID, `aud` = the service DID with any
/// `#fragment` stripped (the AppView keys verification on the bare DID), `lxm` = the proxied
/// method, 60s TTL. Returns the built error response on the unhappy paths (master key missing →
/// 503, key load/decrypt failure → 500) so the caller can early-return it.
async fn mint_service_auth(
    state: &AppState,
    did: &str,
    proxy_did: &str,
    nsid: &str,
) -> Result<String, Response> {
    use std::time::{SystemTime, UNIX_EPOCH};

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
            .into_response()
        })?;

    let signer = crate::auth::signing_key::load_repo_signer(&state.db, did, master_key)
        .await
        .map_err(IntoResponse::into_response)?;

    // The audience is the bare service DID — a `#fragment` (e.g. `#bsky_chat`) belongs in the
    // `atproto-proxy` header, not the JWT `aud`, which the AppView matches against its own DID.
    let aud = proxy_did.split('#').next().unwrap_or(proxy_did);

    // A failure to read the wall clock is unrecoverable here; fall back to 0 so the token is
    // simply already-expired (rejected upstream) rather than panicking the request.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(crate::auth::jwt::mint_service_auth_jwt(
        |bytes| signer.sign(bytes),
        did,
        aud,
        Some(nsid),
        now,
        now + 60,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::app::{app, test_state, AppState};
    use crate::routes::test_utils::test_master_key;

    /// The account DID baked into every proxied request's bearer token (see [`bearer`]). The
    /// proxy mints the service-auth JWT for whichever DID the inbound session authenticates as,
    /// so this is the DID we must seed a repo signing key for.
    const TEST_DID: &str = "did:plc:tester";

    /// Seed `TEST_DID` with an account row and a per-account repo signing key, encrypted under
    /// [`test_master_key`]. The proxy needs only the *decryptable signing key* to mint the
    /// service-auth JWT — not a full repo — so this is leaner than `seed_account_with_repo`.
    async fn seed_repo_key(db: &sqlx::SqlitePool) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(TEST_DID)
        .bind(format!("{TEST_DID}@example.com"))
        .execute(db)
        .await
        .unwrap();

        let kp = crypto::generate_p256_keypair().unwrap();
        let private_key_encrypted =
            crypto::encrypt_private_key(&kp.private_key_bytes, &test_master_key()).unwrap();
        crate::db::repo_keys::insert_did_signing_key(
            db,
            TEST_DID,
            &crate::db::repo_keys::RepoSigningKey {
                key_id: kp.key_id.to_string(),
                public_key: kp.public_key.clone(),
                private_key_encrypted,
            },
        )
        .await
        .unwrap();
    }

    /// Configure `config` so the proxy can mint a service-auth JWT: install the master key the
    /// seeded repo key was encrypted under.
    fn with_master_key(config: &mut common::Config) {
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
            test_master_key(),
        )));
    }

    /// Build router state whose AppView points at the given mock server URI, with `TEST_DID`'s
    /// repo signing key seeded so proxied requests can mint a service-auth JWT.
    async fn state_with_appview(uri: &str) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = uri.to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Build router state whose chat service points at the given mock server URI, with
    /// `TEST_DID`'s repo signing key seeded so proxied requests can mint a service-auth JWT.
    async fn state_with_chat(uri: &str) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.chat.url = uri.to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Mint a short-lived HS256 access JWT (`com.atproto.access` scope) for `sub`, signed with
    /// `secret`. Defined locally so this route module stays free of cross-route imports.
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

    /// A valid `Bearer` access token (`com.atproto.access` scope) for the given state's signing
    /// secret. The proxy sits behind the `AuthenticatedUser` gate, so every proxied request must
    /// present one of these or be rejected with `401` before reaching the upstream.
    fn bearer(state: &AppState) -> String {
        format!("Bearer {}", access_jwt(&state.jwt_secret, "did:plc:tester"))
    }

    #[tokio::test]
    async fn proxies_get_query_to_appview() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getTimeline"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "feed": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getTimeline")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["feed"].is_array());
    }

    #[tokio::test]
    async fn mints_service_auth_jwt_instead_of_forwarding_session_token() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let server = MockServer::start().await;
        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        // The AppView keys verification on its *bare* DID; `mint_service_auth` strips the
        // `#fragment` that lives on the configured service DID.
        let expected_aud = state
            .config
            .appview
            .did
            .split('#')
            .next()
            .unwrap()
            .to_string();

        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.notification.listNotifications"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "notifications": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.notification.listNotifications")
                    .header("authorization", &auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Inspect what actually reached the AppView: it must be a freshly-minted ES256
        // service-auth JWT, NOT the inbound HS256 PDS session token (which the AppView rejects
        // as "poorly formatted jwt").
        let requests = server.received_requests().await.unwrap();
        let forwarded = requests
            .iter()
            .find(|r| r.url.path() == "/xrpc/app.bsky.notification.listNotifications")
            .expect("AppView received the proxied request");
        let forwarded_auth = forwarded
            .headers
            .get("authorization")
            .expect("proxied request carries an Authorization header")
            .to_str()
            .unwrap();

        assert_ne!(
            forwarded_auth, auth,
            "the inbound PDS session token must not be forwarded verbatim"
        );

        let token = forwarded_auth
            .strip_prefix("Bearer ")
            .expect("Bearer scheme");
        let mut parts = token.split('.');
        let decode = |seg: &str| -> serde_json::Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(seg).unwrap()).unwrap()
        };
        let jwt_header = decode(parts.next().unwrap());
        let claims = decode(parts.next().unwrap());
        assert!(parts.next().is_some(), "JWT carries a signature segment");

        assert_eq!(jwt_header["alg"], "ES256");
        assert_eq!(claims["iss"], TEST_DID);
        assert_eq!(claims["aud"], expected_aud);
        assert_eq!(claims["lxm"], "app.bsky.notification.listNotifications");
    }

    #[tokio::test]
    async fn passes_through_appview_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getTimeline"))
            .respond_with(ResponseTemplate::new(400).set_body_json(
                serde_json::json!({ "error": "InvalidRequest", "message": "bad cursor" }),
            ))
            .mount(&server)
            .await;

        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getTimeline")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "InvalidRequest");
    }

    #[tokio::test]
    async fn proxies_post_body_to_appview() {
        // Use a procedure with no local handler so it reaches the proxy. `app.bsky.actor.*`
        // preferences are served locally and would never proxy; `graph.muteActor` proxies.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.graph.muteActor"))
            .and(body_json(serde_json::json!({ "actor": "did:plc:abc123" })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/app.bsky.graph.muteActor")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"actor":"did:plc:abc123"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn transport_failure_maps_to_503() {
        // Point the AppView at a port nothing is listening on so the outbound request fails at
        // the transport layer rather than returning an HTTP status. The proxy still mints a
        // service-auth JWT first, so the master key + seeded repo key must be present.
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = "http://127.0.0.1:1".to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getTimeline")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "SERVICE_UNAVAILABLE");
    }

    #[tokio::test]
    async fn oversized_body_maps_to_413() {
        // A body larger than MAX_PROXY_BODY must be rejected as 413 before any AppView call.
        // No mock is mounted: if the request escaped to the AppView the connection would fail,
        // so a clean 413 also proves the body cap short-circuits the proxy.
        let server = MockServer::start().await;
        let oversized = "x".repeat(super::MAX_PROXY_BODY + 1);

        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/app.bsky.graph.muteActor")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .body(Body::from(oversized))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "PAYLOAD_TOO_LARGE");
    }

    #[tokio::test]
    async fn preserves_query_string() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getAuthorFeed"))
            .and(query_param("actor", "did:plc:abc123"))
            .and(query_param("limit", "10"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "feed": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getAuthorFeed?actor=did:plc:abc123&limit=10")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- auth gate (both proxied namespaces) ---

    // The proxy forwards on behalf of an authenticated user, so an unauthenticated `app.bsky.*`
    // request is rejected locally with `401` and never reaches the upstream. No mock is mounted:
    // a clean `401` proves nothing escaped the PDS.
    #[tokio::test]
    async fn appview_request_without_auth_is_rejected() {
        let server = MockServer::start().await;
        let response = app(state_with_appview(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getTimeline")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn chat_request_without_auth_is_rejected() {
        let server = MockServer::start().await;
        let response = app(state_with_chat(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/chat.bsky.convo.listConvos")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // An arbitrary, unverifiable bearer token must be rejected at the gate just like a missing
    // one — the proxy must not become an open relay for forged credentials.
    #[tokio::test]
    async fn chat_request_with_invalid_token_is_rejected() {
        let server = MockServer::start().await;
        let response = app(state_with_chat(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/chat.bsky.convo.listConvos")
                    .header("authorization", "Bearer not-a-real-jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // --- chat.bsky.* proxy (direct messages) ---

    #[tokio::test]
    async fn proxies_chat_list_convos_to_chat_service() {
        let server = MockServer::start().await;
        let state = state_with_chat(&server.uri()).await;
        let auth = bearer(&state);

        // The forwarded Authorization is now a minted service-auth JWT, not the inbound token,
        // so we no longer match on its value; the `atproto-proxy` header still carries the full
        // service DID (fragment included) so the chat service routes the request.
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .and(query_param("limit", "50"))
            .and(header("atproto-proxy", "did:web:api.bsky.chat#bsky_chat"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "convos": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/chat.bsky.convo.listConvos?limit=50")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["convos"].is_array());
    }

    #[tokio::test]
    async fn proxies_chat_get_log_with_cursor_to_chat_service() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .and(query_param("cursor", "abc123"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "logs": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let state = state_with_chat(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/chat.bsky.convo.getLog?cursor=abc123")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn passes_through_chat_service_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getLog"))
            .respond_with(ResponseTemplate::new(400).set_body_json(
                serde_json::json!({ "error": "InvalidRequest", "message": "bad cursor" }),
            ))
            .mount(&server)
            .await;

        let state = state_with_chat(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/chat.bsky.convo.getLog")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "InvalidRequest");
    }

    // The chat service is a distinct upstream from the AppView: a `chat.bsky.*` request must
    // reach the configured chat URL, never the AppView. Pointing the AppView at a dead port and
    // the chat service at a live mock proves the router keys on the NSID prefix, not a shared
    // proxy target.
    #[tokio::test]
    async fn chat_request_does_not_hit_appview() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "convos": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.chat.url = server.uri();
        config.appview.url = "http://127.0.0.1:1".to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/chat.bsky.convo.listConvos")
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
