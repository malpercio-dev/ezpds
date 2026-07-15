// pattern: Imperative Shell
//
// `NoInputBody`: a shared axum extractor guarding XRPC procedures whose lexicon defines no
// `input`. The reference PDS (via `@atproto/xrpc-server`'s `validateInput`) rejects any request
// carrying a body on a no-input procedure with a 400 `InvalidRequest` — "A request body was
// provided when none was expected". Custos historically accepted spurious bodies on most of these
// routes, and that leniency concealed a wallet interop bug (MM-291): the wallet sent empty `{}`
// payloads to no-input procedures that bsky.social rejected but Custos silently accepted. Because
// the wallet develops against Custos, Custos's leniency is the wallet's blind spot — matching the
// reference's strictness turns Custos into test coverage for the wallet.
//
// This lives outside `routes/` (like `request_host.rs`) so every no-input handler can share it
// without a route-to-route import. Extract it *last* in a handler's argument list — it consumes
// the request body, so it must be the sole `FromRequest` extractor:
//
// ```rust,ignore
// async fn handler(
//     user: AuthenticatedUser,
//     State(state): State<AppState>,
//     _: NoInputBody,
// ) -> Result<StatusCode, ApiError> { ... }
// ```

use axum::{body::Bytes, extract::FromRequest};

use common::{ApiError, ErrorCode};

/// The `InvalidRequest` message the reference PDS returns when a no-input procedure receives a
/// body. Kept byte-identical so a client (the wallet especially) sees the same error shape from
/// Custos and from bsky.social.
pub const NO_INPUT_BODY_MESSAGE: &str = "A request body was provided when none was expected";

/// Marker extractor that succeeds only when the request body is empty. A non-empty body is
/// rejected with a 400 `InvalidRequest` mirroring the reference PDS's message shape; an empty body
/// (no payload, `Content-Length: 0`) passes through.
#[derive(Debug)]
pub struct NoInputBody;

impl<S> FromRequest<S> for NoInputBody
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "failed to read request body"))?;
        if !body.is_empty() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                NO_INPUT_BODY_MESSAGE,
            ));
        }
        Ok(NoInputBody)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::FromRequest,
        http::{Request, StatusCode},
    };

    async fn extract(body: Body) -> Result<NoInputBody, ApiError> {
        let req = Request::builder()
            .method("POST")
            .uri("/xrpc/com.example.noInput")
            .body(body)
            .unwrap();
        NoInputBody::from_request(req, &()).await
    }

    #[tokio::test]
    async fn empty_body_is_accepted() {
        assert!(extract(Body::empty()).await.is_ok());
    }

    #[tokio::test]
    async fn non_empty_body_is_rejected_with_invalid_request() {
        let err = extract(Body::from(r#"{"unexpected":"payload"}"#))
            .await
            .expect_err("a non-empty body must be rejected");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
        // `ApiError`'s Display renders `{code:?}: {message}`, so the parity message is the tail.
        assert!(
            err.to_string().ends_with(NO_INPUT_BODY_MESSAGE),
            "unexpected error message: {err}"
        );
    }

    #[tokio::test]
    async fn whitespace_only_body_is_rejected() {
        // The reference PDS keys off the presence of a body (Content-Length > 0), not its contents,
        // so even a whitespace-only payload is a body it would not expect.
        let err = extract(Body::from("   \n"))
            .await
            .expect_err("a whitespace-only body must be rejected");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
    }

    #[tokio::test]
    async fn empty_json_object_is_rejected() {
        // The exact MM-291 shape: the wallet's spurious empty `{}`.
        let err = extract(Body::from("{}"))
            .await
            .expect_err("an empty JSON object is still a body");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
    }
}
