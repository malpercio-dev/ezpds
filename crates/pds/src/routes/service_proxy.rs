// pattern: Imperative Shell
//
// Gathers: an incoming XRPC request (method, query, headers, body) bound for an upstream
//          atproto service — the AppView for `app.bsky.*`, the chat service for `chat.bsky.*`
// Processes: forwards it to the given upstream, passing the caller's auth through
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
/// user's behalf via their PDS. The caller's `Authorization` header is passed through unchanged
/// — the upstream trusts the user's PDS to have authenticated them. The upstream status, content
/// type, and body are streamed straight back to the client; a failure to reach the upstream maps
/// to `503`, while upstream error *responses* (4xx/5xx) are passed through verbatim.
pub async fn proxy_xrpc(
    state: &AppState,
    upstream_url: &str,
    proxy_did: &str,
    nsid: &str,
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

    // reqwest 0.12 and axum 0.7 share the same `http` crate, so `Method` and `HeaderValue` are
    // identical types and move across the boundary without conversion.
    let mut outbound = state.http_client.request(parts.method, &target);

    // Pass auth, content-type, and the client's content-negotiation preference through; host,
    // content-length, and connection are hop-by-hop or recomputed by reqwest, so they are
    // intentionally dropped.
    for name in [header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT] {
        if let Some(val) = parts.headers.get(&name) {
            outbound = outbound.header(name, val);
        }
    }
    outbound = outbound.header("atproto-proxy", proxy_did);

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

    /// Build router state whose AppView points at the given mock server URI.
    async fn state_with_appview(uri: &str) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = uri.to_string();
        AppState {
            config: Arc::new(config),
            ..base
        }
    }

    /// Build router state whose chat service points at the given mock server URI.
    async fn state_with_chat(uri: &str) -> AppState {
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.chat.url = uri.to_string();
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
    async fn forwards_authorization_header() {
        let server = MockServer::start().await;
        let state = state_with_appview(&server.uri()).await;
        let auth = bearer(&state);

        // The exact bearer that passed the local auth gate must reach the AppView unchanged.
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.notification.listNotifications"))
            .and(header("authorization", auth.as_str()))
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
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // `expect(1)` plus the header matcher verify the auth header reached the AppView.
        assert_eq!(response.status(), StatusCode::OK);
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
        // the transport layer rather than returning an HTTP status.
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = "http://127.0.0.1:1".to_string();
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

        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.listConvos"))
            .and(query_param("limit", "50"))
            .and(header("authorization", auth.as_str()))
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
