// pattern: Imperative Shell
//
// `LexiconInput<T>`: the axum extractor that runs a JSON XRPC procedure's request body through
// the lexicon registry before handing the handler its serde-typed payload. It replaces the bare
// `axum::Json<T>` extractor on natively-handled procedures, whose default rejections (422 with
// a plain-text body for a missing field, 415 for a missing content-type) diverge from the
// reference PDS's uniform 400 `InvalidRequest` envelope — the divergence three routes had
// already hand-patched around (`put_preferences`, `oauth_token`, `create_signing_key`).
//
// The presence/encoding checks mirror `@atproto/xrpc-server`'s `validateInput`, byte-matching
// its messages. Like `NoInputBody`, extract this *last* — it consumes the request body — and it
// keys presence off the received bytes (plus the `Content-Length` header to distinguish an
// explicitly empty body from an absent one), where the reference reads only the headers.
//
// Handlers that also need the raw body bytes (admin-signed requests verify a signature over
// them) skip the extractor and call `validate_procedure_body` directly after their auth step.

use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::http::{header, HeaderMap};
use serde::de::DeserializeOwned;

use common::{ApiError, ErrorCode};

use super::{registry, ValidationError};

/// Reference-parity message for a procedure that declares an input but received no body.
pub const BODY_EXPECTED_MESSAGE: &str = "A request body is expected but none was provided";

/// Reference-parity message for a body sent without a `Content-Type` header.
pub const ENCODING_REQUIRED_MESSAGE: &str =
    "Request encoding (Content-Type) required but not provided";

/// Validate `body` as `nsid`'s lexicon input (presence → encoding → JSON parse → schema) and
/// return the parsed JSON on success. Errors are 400 `InvalidRequest` with the reference PDS's
/// message shapes, except a broken vendored lexicon (unreachable; registry-build-checked),
/// which is a 500.
pub fn validate_procedure_body(
    nsid: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<serde_json::Value, ApiError> {
    let Some(input) = registry().input(nsid) else {
        // A handler asked for validation of a procedure whose lexicon isn't vendored — a wiring
        // defect, not a client error.
        tracing::error!(nsid, "no vendored lexicon input for procedure");
        return Err(ApiError::new(
            ErrorCode::InternalError,
            "server lexicon configuration error",
        ));
    };

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(normalize_mime)
        .filter(|mime| !mime.is_empty());

    if body.is_empty() {
        if content_type.is_none() {
            // The reference distinguishes an explicitly empty body (`Content-Length: 0`, which
            // reaches its encoding check) from an absent one (no length header at all).
            let declared_empty = headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                == Some("0");
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                if declared_empty {
                    ENCODING_REQUIRED_MESSAGE
                } else {
                    BODY_EXPECTED_MESSAGE
                },
            ));
        }
        check_encoding(input.encoding(), content_type.as_deref())?;
        // An empty body with a valid JSON content-type parses to `{}`, as in the reference's
        // body-parser — schemas with required properties still reject it below.
        let value = serde_json::Value::Object(serde_json::Map::new());
        validate_value(nsid, &value)?;
        return Ok(value);
    }

    check_encoding(input.encoding(), content_type.as_deref())?;
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            format!("invalid request body: {e}"),
        )
    })?;
    validate_value(nsid, &value)?;
    Ok(value)
}

fn validate_value(nsid: &str, value: &serde_json::Value) -> Result<(), ApiError> {
    registry().validate_input(nsid, value).map_err(|e| match e {
        ValidationError::Invalid(message) => ApiError::new(ErrorCode::InvalidRequest, message),
        ValidationError::Lexicon(message) => {
            tracing::error!(nsid, error = %message, "vendored lexicon set is inconsistent");
            ApiError::new(
                ErrorCode::InternalError,
                "server lexicon configuration error",
            )
        }
    })
}

fn check_encoding(expected: &str, content_type: Option<&str>) -> Result<(), ApiError> {
    match content_type {
        None => Err(ApiError::new(
            ErrorCode::InvalidRequest,
            ENCODING_REQUIRED_MESSAGE,
        )),
        Some(mime) if mime != expected => Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("Wrong request encoding (Content-Type): {mime}"),
        )),
        Some(_) => Ok(()),
    }
}

/// Lowercased media type with any parameters (`; charset=…`) stripped, the reference's
/// `normalizeMime`.
fn normalize_mime(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Extractor wrapper: lexicon-validate the request body for the procedure named by the request
/// path (`/xrpc/<nsid>`), then deserialize it into `T`. Must be a handler's final extractor.
#[derive(Debug)]
pub struct LexiconInput<T>(pub T);

impl<S, T> FromRequest<S> for LexiconInput<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let path = req.uri().path();
        let nsid = path.strip_prefix("/xrpc/").unwrap_or(path).to_owned();
        let headers = req.headers().clone();
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "failed to read request body"))?;
        let value = validate_procedure_body(&nsid, &headers, &body)?;
        // The lexicon schema has already vouched for required fields and types, so this serde
        // pass is shape bookkeeping; a residual mismatch (a handler struct stricter than the
        // lexicon) still surfaces as the envelope-shaped 400.
        let parsed: T = serde_json::from_value(value).map_err(|e| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                format!("invalid request body: {e}"),
            )
        })?;
        Ok(LexiconInput(parsed))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct CreateSessionShape {
        identifier: String,
        password: String,
    }

    async fn extract(request: Request<Body>) -> Result<LexiconInput<CreateSessionShape>, ApiError> {
        LexiconInput::<CreateSessionShape>::from_request(request, &()).await
    }

    fn request(content_type: Option<&str>, body: Body) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession");
        if let Some(ct) = content_type {
            builder = builder.header("Content-Type", ct);
        }
        builder.body(body).unwrap()
    }

    #[tokio::test]
    async fn valid_body_deserializes() {
        let extracted = extract(request(
            Some("application/json"),
            Body::from(r#"{"identifier":"alice.example.com","password":"hunter2"}"#),
        ))
        .await
        .expect("valid body");
        assert_eq!(extracted.0.identifier, "alice.example.com");
        assert_eq!(extracted.0.password, "hunter2");
    }

    #[tokio::test]
    async fn content_type_parameters_are_ignored() {
        assert!(extract(request(
            Some("application/json; charset=utf-8"),
            Body::from(r#"{"identifier":"alice.example.com","password":"hunter2"}"#),
        ))
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn missing_body_is_body_expected() {
        let err = extract(request(None, Body::empty())).await.unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
        assert!(err.to_string().ends_with(BODY_EXPECTED_MESSAGE), "{err}");
    }

    #[tokio::test]
    async fn body_without_content_type_is_encoding_required() {
        let err = extract(request(
            None,
            Body::from(r#"{"identifier":"alice.example.com","password":"hunter2"}"#),
        ))
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
        assert!(
            err.to_string().ends_with(ENCODING_REQUIRED_MESSAGE),
            "{err}"
        );
    }

    #[tokio::test]
    async fn wrong_content_type_is_wrong_encoding() {
        let err = extract(request(
            Some("text/plain"),
            Body::from(r#"{"identifier":"alice.example.com","password":"hunter2"}"#),
        ))
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
        assert!(
            err.to_string()
                .ends_with("Wrong request encoding (Content-Type): text/plain"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn schema_violation_is_invalid_request_envelope() {
        let err = extract(request(
            Some("application/json"),
            Body::from(r#"{"identifier":"alice.example.com"}"#),
        ))
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
        assert!(
            err.to_string()
                .ends_with("Input must have the property \"password\""),
            "{err}"
        );
    }

    #[tokio::test]
    async fn malformed_json_is_400() {
        let err = extract(request(Some("application/json"), Body::from("{not json")))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
    }

    #[tokio::test]
    async fn empty_body_with_json_content_type_validates_as_empty_object() {
        // createSession requires fields, so an explicitly-empty JSON body still fails — but
        // through the schema, matching a reference body-parser that yields `{}`.
        let err = extract(request(Some("application/json"), Body::empty()))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .ends_with("Input must have the property \"identifier\""),
            "{err}"
        );
    }
}
