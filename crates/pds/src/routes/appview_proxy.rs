// pattern: Imperative Shell
//
// Gathers: an incoming `app.bsky.*` XRPC request (method, query, headers, body)
// Processes: forwards it to the configured AppView, passing the caller's auth through
// Returns: the AppView's status, content-type, and streamed response body

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use common::{ApiError, ErrorCode};

use crate::app::AppState;

/// Maximum buffered request body when proxying to the AppView. `app.bsky.*` procedures carry
/// small JSON payloads (preferences, mutes, follows); anything larger is almost certainly a
/// mistake, so it is rejected rather than buffered.
const MAX_PROXY_BODY: usize = 1024 * 1024; // 1 MiB

/// Forward an `app.bsky.*` XRPC request to the configured AppView.
///
/// The caller's `Authorization` header is passed through unchanged — the AppView trusts the
/// user's PDS to have authenticated them. The `atproto-proxy` header carries the AppView's
/// service DID so it knows the request arrives on the user's behalf via their PDS. The upstream
/// status, content type, and body are streamed straight back to the client; a failure to reach
/// the AppView maps to `503`, while AppView error *responses* (4xx/5xx) are passed through
/// verbatim.
pub async fn proxy_to_appview(state: &AppState, nsid: &str, req: Request) -> Response {
    let appview = &state.config.appview;

    // Preserve the original query string verbatim so AppView query params survive the hop.
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target = format!("{}/xrpc/{nsid}{query}", appview.url);

    let (parts, body) = req.into_parts();

    let body_bytes = match axum::body::to_bytes(body, MAX_PROXY_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError::new(
                ErrorCode::PayloadTooLarge,
                "request body exceeds the AppView proxy limit",
            )
            .into_response();
        }
    };

    // reqwest 0.12 and axum 0.7 share the same `http` crate, so `Method` and `HeaderValue` are
    // identical types and move across the boundary without conversion.
    let mut outbound = state.http_client.request(parts.method, &target);

    // Pass auth and content-type through; host, content-length, and connection are hop-by-hop
    // or recomputed by reqwest, so they are intentionally dropped.
    if let Some(authz) = parts.headers.get(header::AUTHORIZATION) {
        outbound = outbound.header(header::AUTHORIZATION, authz);
    }
    if let Some(content_type) = parts.headers.get(header::CONTENT_TYPE) {
        outbound = outbound.header(header::CONTENT_TYPE, content_type);
    }
    outbound = outbound.header("atproto-proxy", appview.did.as_str());

    if !body_bytes.is_empty() {
        outbound = outbound.body(body_bytes);
    }

    let upstream = match outbound.send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(error = %err, nsid, "AppView proxy request failed");
            return ApiError::new(ErrorCode::ServiceUnavailable, "failed to reach the AppView")
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
            tracing::error!(error = %err, nsid, "failed to build AppView proxy response");
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

        let response = app(state_with_appview(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getTimeline")
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
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.notification.listNotifications"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "notifications": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = app(state_with_appview(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.notification.listNotifications")
                    .header("authorization", "Bearer test-token")
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

        let response = app(state_with_appview(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getTimeline")
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
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/xrpc/app.bsky.actor.putPreferences"))
            .and(body_json(serde_json::json!({ "preferences": [] })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let response = app(state_with_appview(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/app.bsky.actor.putPreferences")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"preferences":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
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

        let response = app(state_with_appview(&server.uri()).await)
            .oneshot(
                Request::builder()
                    .uri("/xrpc/app.bsky.feed.getAuthorFeed?actor=did:plc:abc123&limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
