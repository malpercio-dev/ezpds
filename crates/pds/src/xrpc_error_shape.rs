// pattern: Imperative Shell

//! Boundary layer that re-encodes error responses on the `/xrpc/*` surface into the flat
//! AT Protocol XRPC error shape: `{"error": "<Name>", "message": "..."}`.
//!
//! Every handler in this crate returns [`common::ApiError`], which serializes as the
//! provisioning API's nested envelope (`{"error": {"code": ..., "message": ...}}`). That
//! envelope is this deployment's own dialect; atproto clients dispatch on the *flat* shape —
//! `@atproto/api` and indigo trigger session refresh only when a 401 body carries
//! `"error": "ExpiredToken"` — so a nested body on an XRPC route reads as an unknown error
//! and the client never refreshes ("logs in fine, actions fail five minutes later"; see
//! docs/2026-08-03-oauth-interop-audit.md).
//!
//! Rather than teach every XRPC handler a second error type, `ApiError`'s `IntoResponse`
//! attaches its semantic parts ([`common::ApiErrorParts`]) to the response extensions, and
//! this layer rebuilds the body in the XRPC dialect for `/xrpc/*` paths only. The name
//! mapping itself lives with the [`common::ErrorCode`] enum (`xrpc_name`), where adding a
//! variant forces choosing its XRPC name. The provisioning surface (`/v1/*`, `/agent/*`)
//! never matches the path filter and keeps its documented nested envelope.

use axum::{
    body::Body,
    extract::Request,
    http::header::{CONTENT_LENGTH, CONTENT_TYPE},
    middleware::Next,
    response::Response,
};
use common::ApiErrorParts;

/// Rebuild `ApiError` responses to `/xrpc/*` requests in the flat XRPC error shape.
///
/// Applied outside the shared middleware stack so errors produced by those layers (e.g. the
/// rate limiter's 429) are re-shaped too, not just handler errors.
pub async fn flatten_xrpc_errors(req: Request, next: Next) -> Response {
    let is_xrpc = req.uri().path().starts_with("/xrpc/");
    let response = next.run(req).await;
    if !is_xrpc {
        return response;
    }
    let Some(parts) = response.extensions().get::<ApiErrorParts>().cloned() else {
        return response;
    };

    let mut body = serde_json::json!({
        "error": parts.code.xrpc_name(),
        "message": parts.message,
    });
    // The flat shape has no envelope to nest details in; carry them as a top-level field
    // (unknown fields are ignored by XRPC clients) rather than silently dropping them.
    if let Some(details) = parts.details {
        body["details"] = details;
    }
    let bytes = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(err) => {
            // Serializing a Value cannot realistically fail; keep the original response
            // rather than manufacturing a second error on the error path.
            tracing::error!(error = %err, "failed to serialize flat XRPC error body");
            return response;
        }
    };

    let (mut head, _nested_body) = response.into_parts();
    // The rebuilt body has a different length; drop the stale header and let hyper set it.
    head.headers.remove(CONTENT_LENGTH);
    head.headers
        .insert(CONTENT_TYPE, "application/json".parse().expect("static"));
    Response::from_parts(head, Body::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, routing::get, Router};
    use common::{ApiError, ErrorCode};
    use tower::ServiceExt;

    async fn handler() -> Result<&'static str, ApiError> {
        Err(ApiError::new(ErrorCode::TokenExpired, "token has expired")
            .with_details(serde_json::json!({ "hint": "refresh" })))
    }

    fn test_router() -> Router {
        Router::new()
            .route("/xrpc/com.example.method", get(handler))
            .route("/v1/example", get(handler))
            .layer(middleware::from_fn(flatten_xrpc_errors))
    }

    async fn get_json(router: Router, path: &str) -> (u16, serde_json::Value) {
        let response = router
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status().as_u16();
        let content_length = response.headers().get(CONTENT_LENGTH).cloned();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        if let Some(len) = content_length {
            assert_eq!(
                len.to_str()
                    .expect("ascii")
                    .parse::<usize>()
                    .expect("number"),
                body.len(),
                "content-length must match the (possibly rebuilt) body"
            );
        }
        (status, serde_json::from_slice(&body).expect("json body"))
    }

    /// An XRPC-path error is re-encoded flat, with the canonical atproto name — the exact
    /// string clients key refresh-on-401 off — and details preserved at the top level.
    #[tokio::test]
    async fn xrpc_path_gets_flat_shape_with_canonical_name() {
        let (status, json) = get_json(test_router(), "/xrpc/com.example.method").await;
        assert_eq!(status, 401);
        assert_eq!(json["error"], "ExpiredToken");
        assert_eq!(json["message"], "token has expired");
        assert_eq!(json["details"]["hint"], "refresh");
        assert!(json["error"].is_string(), "flat shape, not an envelope");
    }

    /// Non-XRPC paths keep the provisioning API's documented nested envelope untouched.
    #[tokio::test]
    async fn non_xrpc_path_keeps_nested_envelope() {
        let (status, json) = get_json(test_router(), "/v1/example").await;
        assert_eq!(status, 401);
        assert_eq!(json["error"]["code"], "TOKEN_EXPIRED");
        assert_eq!(json["error"]["message"], "token has expired");
    }

    /// Success responses pass through unchanged.
    #[tokio::test]
    async fn success_responses_pass_through() {
        let router = Router::new()
            .route("/xrpc/com.example.ok", get(|| async { "ok" }))
            .layer(middleware::from_fn(flatten_xrpc_errors));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.ok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), 200);
    }
}
