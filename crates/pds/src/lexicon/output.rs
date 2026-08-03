// pattern: Imperative Shell

//! Test-build response-output validation: the drift detector for what Custos *serves*.
//!
//! Every natively-handled query/procedure that returns a JSON body has its `output` schema
//! parsed (the shared `schema::parse_xrpc_body`, the same parse an `input` gets) and registered
//! by NSID; `Registry::validate_output` (rooted at `Output`, `assertValidXrpcOutput` parity)
//! asserts a serialized body against it. At registry-build time `check_refs` walks the output
//! closure too — which is what pulls the output-only `defs` documents
//! (`com.atproto.repo.defs#commitMeta`, `com.atproto.identity.defs#identityInfo`) into the
//! vendored set, so a document whose output refs something un-vendored fails `registry_builds`
//! rather than 500ing at serve time.
//!
//! This module is the serve-path half, compiled into test builds only: `validate_xrpc_output`
//! wraps the real Axum router and buffers every successful natively-handled response with a
//! registered JSON schema after the handler has serialized its DTO. A missing or renamed field
//! panics the route test; production builds and non-JSON streams (the `sync.*` CAR streams,
//! `getBlob`) are untouched. The malformed-output registry fixtures remain as focused
//! invalid-case coverage.

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::Next,
    response::Response,
};

/// Validate the bytes emitted by real native XRPC handlers in test builds.
///
/// Only successful endpoints with a registered JSON output are inspected. Error envelopes and
/// streaming endpoints have different contracts and remain covered by their route tests.
pub(crate) async fn validate_xrpc_output(request: Request, next: Next) -> Response {
    let nsid = request
        .uri()
        .path()
        .strip_prefix("/xrpc/")
        .map(str::to_owned);
    let response = next.run(request).await;

    let Some(nsid) = nsid else {
        return response;
    };
    if !response.status().is_success() || super::registry().output(&nsid).is_none() {
        return response;
    }

    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, usize::MAX)
        .await
        .unwrap_or_else(|error| panic!("failed to collect {nsid} response body: {error}"));
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("{nsid} returned a non-JSON success body: {error}"));
    if let Err(error) = super::registry().validate_output(&nsid, &value) {
        let message = match error {
            super::ValidationError::Invalid(message) | super::ValidationError::Lexicon(message) => {
                message
            }
        };
        panic!("{nsid} handler output violates its lexicon: {message}");
    }

    Response::from_parts(parts, Body::from(bytes))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, extract::Request, middleware, routing::get, Json, Router};
    use tower::ServiceExt;

    #[tokio::test]
    #[should_panic(expected = "Output must have the property \"accessJwt\"")]
    async fn required_handler_field_removal_fails_the_request_test() {
        let app = Router::new()
            .route(
                "/xrpc/com.atproto.server.createSession",
                get(|| async {
                    Json(serde_json::json!({
                        "refreshJwt": "refresh",
                        "handle": "alice.example.com",
                        "did": "did:plc:abc123abc123abc123abc123",
                    }))
                }),
            )
            .layer(middleware::from_fn(super::validate_xrpc_output));

        let request = Request::builder()
            .uri("/xrpc/com.atproto.server.createSession")
            .body(Body::empty())
            .unwrap();
        let _ = app.oneshot(request).await;
    }
}
