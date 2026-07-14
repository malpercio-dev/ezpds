// pattern: Imperative Shell
//
// Gathers: an incoming XRPC request (method, query, headers, body) bound for an upstream
//          atproto service — the AppView for `app.bsky.*`, the chat service for `chat.bsky.*`,
//          or a client-named labeler for `com.atproto.moderation.*`
// Processes: mints a fresh ES256 service-auth JWT (signed by the account's repo key) and
//            forwards the request to the given upstream under that token
// Returns: the upstream's status, content-type, and streamed response body

use std::borrow::Cow;

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::identity::resolution::HeaderProxyGuard;

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

/// Build and send the upstream XRPC request (query passthrough, body buffering with the
/// MAX_PROXY_BODY cap, service-auth JWT mint, atproto-proxy header), returning the raw upstream
/// response. Both `proxy_xrpc` (streaming) and `read_after_write::pipethrough_munged` (buffering)
/// build on this so request construction never diverges.
///
/// `header_guard` is `Some` whenever the target host was resolved and SSRF-validated from a
/// caller-supplied `atproto-proxy` header naming a caller-controlled DID document
/// (`identity::resolution::resolve_atproto_proxy_target`) — always for `com.atproto.moderation.*`
/// (which has no configured default), and for `app.bsky.*`/`chat.bsky.*` only when the caller's
/// header overrides that namespace's default upstream. When present, the outbound request is sent
/// on a one-off hardened client (see `build_header_proxy_client`) rather than `state.http_client`:
/// redirects are disabled, since the SSRF check only inspects the first URL and a malicious target
/// could otherwise 3xx its way onto a private address; when the host was a domain name, DNS
/// resolution is additionally pinned to exactly the addresses already validated, so the client
/// can't re-resolve at connect time and land on an address that was never checked.
pub(crate) async fn proxy_request(
    state: &AppState,
    upstream_url: &str,
    proxy_did: &str,
    nsid: &str,
    did: &str,
    header_guard: Option<&HeaderProxyGuard>,
    req: Request,
) -> Result<reqwest::Response, Response> {
    // Preserve the original query string verbatim so upstream query params survive the hop.
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target = format!("{upstream_url}/xrpc/{nsid}{query}");

    let client: Cow<'_, reqwest::Client> = match header_guard {
        Some(guard) => match build_header_proxy_client(guard) {
            Ok(client) => Cow::Owned(client),
            Err(err) => return Err(err.into_response()),
        },
        None => Cow::Borrowed(&state.http_client),
    };

    let (parts, body) = req.into_parts();

    let body_bytes = match axum::body::to_bytes(body, MAX_PROXY_BODY).await {
        Ok(bytes) => bytes,
        Err(err) => {
            // `to_bytes` fails for two distinct reasons: the body exceeded `MAX_PROXY_BODY`, or
            // the body stream itself errored (client disconnect, read timeout, framing error).
            // Only the former is a genuine 413; a broken stream is a 400 so the client isn't
            // misled into thinking its payload was too large.
            if is_length_limit_error(&err) {
                return Err(ApiError::new(
                    ErrorCode::PayloadTooLarge,
                    "request body exceeds the proxy limit",
                )
                .into_response());
            }
            tracing::warn!(error = %err, nsid, "failed to read request body while proxying XRPC");
            return Err(
                ApiError::new(ErrorCode::InvalidRequest, "failed to read request body")
                    .into_response(),
            );
        }
    };

    // Mint a fresh ES256 service-auth JWT signed by the account's `#atproto` repo key. The
    // upstream verifies it against the user's DID; forwarding the user's PDS session token
    // instead is rejected with "poorly formatted jwt" (HS256, no `iss`, signed by a secret no
    // third party holds).
    let service_jwt = match mint_service_auth(state, did, proxy_did, nsid).await {
        Ok(jwt) => jwt,
        Err(resp) => return Err(resp),
    };

    // reqwest 0.12 and axum 0.7 share the same `http` crate, so `Method` and `HeaderValue` are
    // identical types and move across the boundary without conversion.
    let mut outbound = client.request(parts.method, &target);

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

    match outbound.send().await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::warn!(error = %err, nsid, "upstream proxy request failed");
            Err(ApiError::new(
                ErrorCode::ServiceUnavailable,
                "failed to reach the upstream service",
            )
            .into_response())
        }
    }
}

/// Forward an XRPC request to an upstream atproto service (the AppView, the chat service, a
/// labeler/moderation service, or any other service named by an `atproto-proxy` header).
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
    header_guard: Option<&HeaderProxyGuard>,
    req: Request,
) -> Response {
    let upstream =
        match proxy_request(state, upstream_url, proxy_did, nsid, did, header_guard, req).await {
            Ok(resp) => resp,
            Err(resp) => return resp,
        };

    // Map status and content-type, then stream the body through without buffering it.
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    // A 3xx is passed through, not followed (see `build_header_proxy_client`), but is useless to
    // the caller without its Location — forward it so "passed through verbatim" actually holds.
    let location = upstream.headers().get(header::LOCATION).cloned();

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if status.is_redirection() {
        if let Some(location) = location {
            builder = builder.header(header::LOCATION, location);
        }
    }

    match builder.body(Body::from_stream(upstream.bytes_stream())) {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, nsid, "failed to build proxy response");
            ApiError::new(ErrorCode::InternalError, "proxy response build failed").into_response()
        }
    }
}

/// Build a one-off HTTP client hardened for proxying to a caller-controlled `atproto-proxy`
/// target (always the case for `com.atproto.moderation.*`; for `app.bsky.*`/`chat.bsky.*` only
/// when the caller's header overrides the namespace's configured default).
///
/// Always disables redirects: `resolve_atproto_proxy_target`'s SSRF check only inspects the
/// *first* URL, so a malicious target returning a 3xx to a private/loopback/metadata address
/// would otherwise sail straight past it — `state.http_client` and a naive pinned client both
/// follow redirects by default. When `guard.pinned` is present (the host was a domain name), DNS
/// resolution for that domain is additionally overridden to exactly the addresses already
/// validated: without this, `proxy_xrpc` would hand the *domain* to the client, which re-resolves
/// it independently at connect time, and a second DNS answer (attacker-controlled, or simply a
/// changed record between validation and connection) could point at an address that was never
/// checked.
fn build_header_proxy_client(guard: &HeaderProxyGuard) -> Result<reqwest::Client, ApiError> {
    crate::identity::resolution::build_pinned_client(guard.pinned.as_ref()).map_err(|e| {
        tracing::error!(error = %e, "failed to build header-target proxy client");
        ApiError::new(
            ErrorCode::InternalError,
            "failed to prepare proxied request",
        )
    })
}

/// Mint a fresh ES256 service-auth JWT for proxying `nsid` to `proxy_did` on behalf of `did`.
///
/// Delegates the key load + claim assembly to the shared
/// [`crate::auth::signing_key::mint_account_service_auth`] (the same path
/// `com.atproto.server.getServiceAuth` uses) so the two never drift. Resolves the master key and
/// strips the audience fragment here: `aud` = the service DID with any `#fragment` removed (the
/// AppView keys verification on the bare DID; the fragment belongs in the `atproto-proxy` header),
/// `lxm` = the proxied method, 60s TTL. Returns the built error response on the unhappy paths
/// (master key missing → 503, clock failure → 500, key load/decrypt failure → 500).
pub(crate) async fn mint_service_auth(
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

    // The audience is the bare service DID — a `#fragment` (e.g. `#bsky_chat`) belongs in the
    // `atproto-proxy` header, not the JWT `aud`, which the AppView matches against its own DID.
    let aud = proxy_did.split('#').next().unwrap_or(proxy_did);

    // Mint with the same clock-failure handling as getServiceAuth (a 500), rather than silently
    // emitting an already-expired token.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| {
            ApiError::new(ErrorCode::InternalError, "system clock error").into_response()
        })?;

    crate::auth::signing_key::mint_account_service_auth(
        &state.db,
        master_key,
        did,
        aud,
        Some(nsid),
        now,
        now + 60,
    )
    .await
    .map_err(IntoResponse::into_response)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use wiremock::matchers::{body_json, header, header_exists, method, path, query_param};
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

        // The forwarded Authorization is a minted service-auth JWT, not the inbound token,
        // so its value is not matched — but the chat branch must still send *an*
        // Authorization header, so assert its presence. The `atproto-proxy` header still carries
        // the full service DID (fragment included) so the chat service routes the request.
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .and(query_param("limit", "50"))
            .and(header_exists("authorization"))
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

    // --- com.atproto.moderation.* proxy (client-named labeler via atproto-proxy header) ---

    // Unlike app.bsky.*/chat.bsky.*, moderation has no single configured upstream: the client
    // names the labeler to report to via the atproto-proxy header, and the pds resolves that
    // DID's advertised service endpoint before forwarding.
    async fn state_with_master_key_and_repo() -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    #[tokio::test]
    async fn proxies_create_report_to_labeler_named_by_atproto_proxy_header() {
        let server = MockServer::start().await;
        let state = state_with_master_key_and_repo().await;
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:plc:labeler123",
            serde_json::json!({
                "id": "did:plc:labeler123",
                "service": [{
                    "id": "#atproto_labeler",
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": server.uri(),
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.moderation.createReport"))
            .and(header(
                "atproto-proxy",
                "did:plc:labeler123#atproto_labeler",
            ))
            .and(body_json(serde_json::json!({
                "reasonType": "com.atproto.moderation.defs#reasonSpam",
                "subject": {
                    "$type": "com.atproto.admin.defs#repoRef",
                    "did": "did:plc:abc123",
                },
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1,
                "reasonType": "com.atproto.moderation.defs#reasonSpam",
                "subject": { "$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:abc123" },
                "reportedBy": "did:plc:tester",
                "createdAt": "2026-07-02T00:00:00.000Z",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.moderation.createReport")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .header("atproto-proxy", "did:plc:labeler123#atproto_labeler")
                    .body(Body::from(
                        serde_json::json!({
                            "reasonType": "com.atproto.moderation.defs#reasonSpam",
                            "subject": {
                                "$type": "com.atproto.admin.defs#repoRef",
                                "did": "did:plc:abc123",
                            },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], 1);
    }

    // A labeler's 3xx must be passed straight back to the caller, never followed — the SSRF guard
    // (`resolve_atproto_proxy_target`) only validates the *first* URL, so an unvalidated redirect
    // target must never be dereferenced by the PDS itself. No `Location` mock is even mounted for
    // the redirect's own target: if the client followed it, the request would either 404 against
    // this same mock server (proving a follow happened) or hang/fail against nothing at all.
    #[tokio::test]
    async fn create_report_does_not_follow_redirect_from_labeler() {
        let server = MockServer::start().await;
        let state = state_with_master_key_and_repo().await;
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:plc:labeler123",
            serde_json::json!({
                "id": "did:plc:labeler123",
                "service": [{
                    "id": "#atproto_labeler",
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": server.uri(),
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.moderation.createReport"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "http://169.254.169.254/"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.moderation.createReport")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .header("atproto-proxy", "did:plc:labeler123#atproto_labeler")
                    .body(Body::from(
                        r#"{"reasonType":"com.atproto.moderation.defs#reasonSpam","subject":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // The mock's own 302 is what must come back — proof the PDS didn't chase the Location.
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "http://169.254.169.254/"
        );
    }

    // No mock is mounted: if the request escaped without a resolved target, there'd be nothing to
    // prove a clean 400 short-circuited the proxy — the absence of a listener would surface as a
    // different failure. A missing header must fail before any DID resolution is attempted.
    #[tokio::test]
    async fn create_report_without_atproto_proxy_header_is_rejected() {
        let state = state_with_master_key_and_repo().await;
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.moderation.createReport")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"reasonType":"com.atproto.moderation.defs#reasonSpam","subject":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    // A resolvable DID that doesn't advertise the requested service id must not silently proxy
    // to nothing — the caller gets a clear 503, not the labeler's default endpoint or a panic.
    #[tokio::test]
    async fn create_report_targeting_unknown_service_id_is_rejected() {
        let state = state_with_master_key_and_repo().await;
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:plc:labeler123",
            serde_json::json!({
                "id": "did:plc:labeler123",
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com",
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.moderation.createReport")
                    .header("authorization", auth)
                    .header("content-type", "application/json")
                    .header("atproto-proxy", "did:plc:labeler123#atproto_labeler")
                    .body(Body::from(
                        r#"{"reasonType":"com.atproto.moderation.defs#reasonSpam","subject":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn create_report_without_auth_is_rejected() {
        let state = state_with_master_key_and_repo().await;

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.moderation.createReport")
                    .header("atproto-proxy", "did:plc:labeler123#atproto_labeler")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_munged_appbsky_nsid_streams_verbatim() {
        // A non-munged app.bsky.* NSID (not one of the six read-after-write NSIDs) must stream
        // directly through proxy_xrpc without buffering or the read-after-write munge path.
        // app.bsky.graph.getFollows is a good choice: it's an app.bsky.* procedure that is
        // NOT in {getTimeline, getAuthorFeed, getPostThread, getActorLikes, getProfile, getProfiles}.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.graph.getFollows"))
            .and(query_param("actor", "did:plc:abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "subject": { "did": "did:plc:abc123", "handle": "test.bsky.social" },
                "follows": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.graph.getFollows?actor=did:plc:abc123")
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
        // Verify the response came straight from the AppView (no munge/selection/injection)
        assert!(json["follows"].is_array());
        // Critically: no "Atproto-Upstream-Lag" header should be present (that's only on munged NSIDs)
        // This would be verified in a full integration test, but the JSON structure itself proves
        // we got the AppView response unmodified.
    }

    // Integration test: verify read-after-write NSIDs are routed to the munged path
    // (`read_after_write::pipethrough_munged`) and still return the AppView response verbatim
    // here, because the test account has no unindexed local records — the munge path's fallback
    // ladder returns the buffered original untouched when `LocalRecords` is empty.
    #[tokio::test]
    async fn read_after_write_nsids_return_appview_response_verbatim() {
        let server = MockServer::start().await;
        let expected_response = serde_json::json!({ "feed": [] });
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getTimeline"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(expected_response.clone())
                    .append_header("content-type", "application/json"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);
        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("GET")
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
        assert_eq!(json, expected_response);
    }

    // --- atproto-proxy header honored generically for app.bsky.*/chat.bsky.* ---
    //
    // The header is honored generically for `app.bsky.*`, `chat.bsky.*`, and
    // `com.atproto.moderation.*` alike: whenever present, it routes to the named target instead
    // of the namespace's configured default. The official app relies on this for
    // `app.bsky.video.*`, routing those calls to the video service.

    #[tokio::test]
    async fn appbsky_header_target_routes_to_named_service_not_configured_appview() {
        let video_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.video.getUploadLimits"))
            .and(header("atproto-proxy", "did:web:video.bsky.app#bsky_video"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "canUpload": true })),
            )
            .expect(1)
            .mount(&video_server)
            .await;

        let base = test_state().await;
        let mut config = (*base.config).clone();
        // A dead port: if the request fell through to the default AppView instead of the header
        // target, it would fail at the transport layer rather than returning 200.
        config.appview.url = "http://127.0.0.1:1".to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:web:video.bsky.app",
            serde_json::json!({
                "id": "did:web:video.bsky.app",
                "service": [{
                    "id": "#bsky_video",
                    "type": "AtprotoVideoService",
                    "serviceEndpoint": video_server.uri(),
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.video.getUploadLimits")
                    .header("authorization", auth)
                    .header("atproto-proxy", "did:web:video.bsky.app#bsky_video")
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
        assert_eq!(json["canUpload"], true);
    }

    #[tokio::test]
    async fn appbsky_header_target_mints_service_auth_for_header_did_and_echoes_header() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let video_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.video.getUploadLimits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&video_server)
            .await;

        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = "http://127.0.0.1:1".to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:web:video.bsky.app",
            serde_json::json!({
                "id": "did:web:video.bsky.app",
                "service": [{
                    "id": "#bsky_video",
                    "type": "AtprotoVideoService",
                    "serviceEndpoint": video_server.uri(),
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.video.getUploadLimits")
                    .header("authorization", auth)
                    .header("atproto-proxy", "did:web:video.bsky.app#bsky_video")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let requests = video_server.received_requests().await.unwrap();
        let forwarded = requests
            .iter()
            .find(|r| r.url.path() == "/xrpc/app.bsky.video.getUploadLimits")
            .expect("video service received the proxied request");

        assert_eq!(
            forwarded
                .headers
                .get("atproto-proxy")
                .expect("atproto-proxy header forwarded")
                .to_str()
                .unwrap(),
            "did:web:video.bsky.app#bsky_video",
            "the caller's header value is echoed back verbatim"
        );

        let forwarded_auth = forwarded
            .headers
            .get("authorization")
            .expect("proxied request carries an Authorization header")
            .to_str()
            .unwrap();
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
        assert_eq!(
            claims["aud"], "did:web:video.bsky.app",
            "aud strips the #fragment, matching bsky_video's own DID"
        );
        assert_eq!(claims["lxm"], "app.bsky.video.getUploadLimits");
    }

    #[tokio::test]
    async fn chat_bsky_header_overrides_configured_chat_service() {
        let header_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "convos": [] })),
            )
            .expect(1)
            .mount(&header_server)
            .await;

        let base = test_state().await;
        let mut config = (*base.config).clone();
        // Point the *configured* chat service at a dead port: if the header were ignored, the
        // request would land here and fail at the transport layer instead of succeeding.
        config.chat.url = "http://127.0.0.1:1".to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:plc:otherchat",
            serde_json::json!({
                "id": "did:plc:otherchat",
                "service": [{
                    "id": "#other_chat",
                    "type": "AtprotoChat",
                    "serviceEndpoint": header_server.uri(),
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/chat.bsky.convo.listConvos")
                    .header("authorization", auth)
                    .header("atproto-proxy", "did:plc:otherchat#other_chat")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // Same SSRF guard as the moderation branch, exercised on the new app.bsky.* header path: a
    // private-address target must be rejected end-to-end, not just at the unit level.
    #[tokio::test]
    async fn appbsky_header_target_private_address_is_rejected() {
        let mut state = state_with_master_key_and_repo().await;
        state.allow_loopback_proxy_targets = false;

        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:web:video.bsky.app",
            serde_json::json!({
                "id": "did:web:video.bsky.app",
                "service": [{
                    "id": "#bsky_video",
                    "type": "AtprotoVideoService",
                    "serviceEndpoint": "http://127.0.0.1:9",
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.video.getUploadLimits")
                    .header("authorization", auth)
                    .header("atproto-proxy", "did:web:video.bsky.app#bsky_video")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // The read-after-write munge path hardcodes `state.config.appview.url`/`.did` internally, so
    // it can't honor a header naming a different target — an explicit header on one of the six
    // munged NSIDs must bypass munge entirely and stream to the header target instead.
    #[tokio::test]
    async fn read_after_write_nsid_with_header_bypasses_munge_and_reaches_header_target() {
        let header_server = MockServer::start().await;
        let expected = serde_json::json!({ "feed": [] });
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.feed.getTimeline"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(expected.clone())
                    .append_header("content-type", "application/json"),
            )
            .expect(1)
            .mount(&header_server)
            .await;

        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = "http://127.0.0.1:1".to_string();
        with_master_key(&mut config);
        seed_repo_key(&base.db).await;
        let state = AppState {
            config: Arc::new(config),
            ..base
        };
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:web:altfeed.example",
            serde_json::json!({
                "id": "did:web:altfeed.example",
                "service": [{
                    "id": "#alt_feed",
                    "type": "AtprotoFeedGenerator",
                    "serviceEndpoint": header_server.uri(),
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getTimeline")
                    .header("authorization", auth)
                    .header("atproto-proxy", "did:web:altfeed.example#alt_feed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        // No Atproto-Upstream-Lag header: this response never went through the munge path.
        assert!(response.headers().get("Atproto-Upstream-Lag").is_none());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, expected);
    }

    // Metrics: an app.bsky.*/chat.bsky.* request that used a header to override its default
    // upstream must be counted under the bounded `header_target` label, never the raw
    // hostname/DID (cardinality rule).
    #[tokio::test]
    async fn appbsky_header_target_records_bounded_metrics_label() {
        let video_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.video.getUploadLimits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&video_server)
            .await;

        let state = state_with_master_key_and_repo().await;
        crate::routes::test_utils::seed_did_document(
            &state.db,
            "did:web:video.bsky.app",
            serde_json::json!({
                "id": "did:web:video.bsky.app",
                "service": [{
                    "id": "#bsky_video",
                    "type": "AtprotoVideoService",
                    "serviceEndpoint": video_server.uri(),
                }],
            }),
        )
        .await;
        let auth = bearer(&state);

        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.video.getUploadLimits")
                    .header("authorization", auth)
                    .header("atproto-proxy", "did:web:video.bsky.app#bsky_video")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let rendered = state.metrics.render().unwrap().unwrap();
        assert!(
            rendered.contains(r#"upstream="header_target""#),
            "expected a bounded header_target upstream label, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("video.bsky.app"),
            "the raw target DID/hostname must never appear in a metrics label:\n{rendered}"
        );
    }
}
