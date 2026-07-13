use serde::Serialize;
use serde_json::Value;

/// Error codes for the provisioning API.
///
/// Most variants serialize as SCREAMING_SNAKE_CASE. Exceptions use `#[serde(rename)]`
/// when a specific wire format is required (e.g. `MethodNotImplemented` uses PascalCase
/// to match the AT Protocol XRPC error format).
///
/// `#[non_exhaustive]` prevents external crates from writing exhaustive match
/// arms — new variants can be added in future waves without breaking callers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidClaim,
    Unauthorized,
    TokenExpired,
    Forbidden,
    NotFound,
    WeakPassword,
    RateLimited,
    ExportInProgress,
    ServiceUnavailable,
    InternalError,
    /// Returned for any XRPC NSID that has no registered handler.
    ///
    /// Serialized as `"MethodNotImplemented"` (PascalCase) to match the AT Protocol XRPC
    /// error format, which uses PascalCase error names rather than SCREAMING_SNAKE_CASE.
    #[serde(rename = "MethodNotImplemented")]
    MethodNotImplemented,
    /// An account with the given email already exists (pending or active).
    AccountExists,
    /// The requested handle is already claimed by an active or pending account.
    HandleTaken,
    /// The handle string failed basic format validation.
    InvalidHandle,
    /// A claim code that has already been redeemed is presented again.
    /// Clients should inform the user to obtain a different code.
    ClaimCodeRedeemed,
    /// The DID has already been fully promoted to an active account.
    DidAlreadyExists,
    /// A DID resolution process confirmed that there is no current DID.
    #[serde(rename = "DidNotFound")]
    DidNotFound,
    /// A DID previously existed but has been deactivated.
    #[serde(rename = "DidDeactivated")]
    DidDeactivated,
    /// The external PLC directory returned a non-success response.
    PlcDirectoryError,
    /// A configured DNS provider returned an error when creating a subdomain record.
    DnsError,
    /// The requested handle does not resolve to a known DID locally or via DNS.
    HandleNotFound,
    /// Missing or absent Authorization header on a protected endpoint.
    AuthenticationRequired,
    /// Token is structurally invalid, has wrong signature, wrong audience, or DPoP mismatch.
    InvalidToken,
    /// The token is valid but its granted OAuth scope set does not authorize this operation.
    #[serde(rename = "InsufficientScope")]
    InsufficientScope,
    /// A password-reset token has expired or has already been used.
    ///
    /// Serialized as `"ExpiredToken"` (PascalCase) to match the AT Protocol XRPC error format
    /// for `com.atproto.server.resetPassword`.
    #[serde(rename = "ExpiredToken")]
    ExpiredToken,
    /// Request body exceeds the maximum allowed size.
    PayloadTooLarge,
    /// A write conflicted with a concurrent modification (e.g. the repo root advanced
    /// since it was read). Clients should retry against the new state.
    Conflict,
    /// A `swapCommit` or `swapRecord` optimistic-concurrency precondition did not match the
    /// current repo state. Distinct from the generic concurrent-write [`Conflict`] so clients
    /// can tell a failed compare-and-swap from a lost race.
    ///
    /// Serialized as `"InvalidSwap"` (PascalCase) to match the AT Protocol XRPC error format
    /// for `com.atproto.repo.{put,delete}Record`.
    #[serde(rename = "InvalidSwap")]
    InvalidSwap,
    /// A request was malformed in a way no more specific code covers — e.g. a request body that
    /// could not be read (client disconnect, read timeout, framing error).
    ///
    /// Serialized as `"InvalidRequest"` (PascalCase) to match the AT Protocol XRPC error format.
    #[serde(rename = "InvalidRequest")]
    InvalidRequest,
    /// The new handle does not resolve to the authenticated user's DID.
    /// Returned by `com.atproto.identity.updateHandle` when the proposed handle
    /// cannot be validated against the caller's identity.
    HandleResolutionFailed,
    /// A requested block CID was not found in the repo, or did not belong to it. Backs
    /// `com.atproto.sync.getBlocks`. Serialized as `"BlockNotFound"` (PascalCase) to match the
    /// lexicon's error name and the AT Protocol XRPC error format.
    #[serde(rename = "BlockNotFound")]
    BlockNotFound,
    // Codes for endpoints/designs not yet shipped (tiers, did:web self-service, device
    // leases, Shamir recovery, etc.) are catalogued in docs/provisioning-api-spec.md's
    // status-code appendix; add them here as those designs actually land.
}

impl ErrorCode {
    /// Returns the canonical HTTP status code for this error as a `u16`.
    pub fn status_code(&self) -> u16 {
        match self {
            ErrorCode::InvalidClaim => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::TokenExpired => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::WeakPassword => 422,
            ErrorCode::RateLimited => 429,
            ErrorCode::ExportInProgress => 503,
            ErrorCode::ServiceUnavailable => 503,
            ErrorCode::InternalError => 500,
            ErrorCode::MethodNotImplemented => 501,
            ErrorCode::AccountExists => 409,
            ErrorCode::HandleTaken => 409,
            ErrorCode::InvalidHandle => 400,
            ErrorCode::ClaimCodeRedeemed => 409,
            ErrorCode::DidAlreadyExists => 409,
            ErrorCode::DidNotFound => 404,
            ErrorCode::DidDeactivated => 410,
            ErrorCode::PlcDirectoryError => 502,
            ErrorCode::DnsError => 502,
            ErrorCode::HandleNotFound => 404,
            ErrorCode::AuthenticationRequired => 401,
            ErrorCode::InvalidToken => 401,
            ErrorCode::InsufficientScope => 403,
            ErrorCode::ExpiredToken => 400,
            ErrorCode::PayloadTooLarge => 413,
            ErrorCode::Conflict => 409,
            ErrorCode::InvalidSwap => 409,
            ErrorCode::InvalidRequest => 400,
            ErrorCode::HandleResolutionFailed => 400,
            ErrorCode::BlockNotFound => 400,
        }
    }
}

/// Provisioning API error, serialized as the standard error envelope.
///
/// Without details:
/// ```json
/// { "error": { "code": "NOT_FOUND", "message": "..." } }
/// ```
///
/// With details:
/// ```json
/// { "error": { "code": "INVALID_CLAIM", "message": "...", "details": { "field": "email" } } }
/// ```
///
/// Implements `IntoResponse` for Axum when the `axum` feature is enabled.
#[derive(Debug, Serialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    code: ErrorCode,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
    /// Extra HTTP response headers to emit alongside the error body (e.g. `Retry-After` and the
    /// `RateLimit-*` family on a 429). Never serialized into the JSON envelope; applied by the
    /// axum `IntoResponse` impl. Header names must be valid lowercase HTTP field names.
    #[serde(skip)]
    headers: Vec<(&'static str, String)>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            headers: Vec::new(),
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Attach an extra HTTP response header to this error (applied by `IntoResponse`). `name` must
    /// be a valid lowercase HTTP header name; an invalid name or value is silently dropped when the
    /// response is built rather than panicking.
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// Returns the HTTP status code for this error as a `u16`.
    pub fn status_code(&self) -> u16 {
        self.code.status_code()
    }
}

/// Wraps `ApiError` in the `{ "error": ... }` envelope for serialization.
#[cfg(any(feature = "axum", test))]
#[derive(Serialize)]
struct ApiErrorEnvelope {
    error: ApiError,
}

#[cfg(feature = "axum")]
mod axum_integration {
    use super::*;
    use axum::{
        http::{header, HeaderName, HeaderValue, StatusCode},
        response::{IntoResponse, Response},
        Json,
    };

    impl IntoResponse for ApiError {
        fn into_response(mut self) -> Response {
            let status = StatusCode::from_u16(self.code.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            // Take the extra headers out before `self` is moved into the JSON envelope.
            let extra_headers = std::mem::take(&mut self.headers);

            match serde_json::to_vec(&ApiErrorEnvelope { error: self }) {
                Ok(body) => {
                    let mut response = (status, [(header::CONTENT_TYPE, "application/json")], body)
                        .into_response();
                    for (name, value) in extra_headers {
                        if let (Ok(name), Ok(value)) = (
                            HeaderName::from_bytes(name.as_bytes()),
                            HeaderValue::from_str(&value),
                        ) {
                            response.headers_mut().insert(name, value);
                        }
                    }
                    response
                }
                Err(err) => {
                    tracing::error!(error = %err, "failed to serialize ApiError");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": {
                                "code": "INTERNAL_SERVER_ERROR",
                                "message": "internal error"
                            }
                        })),
                    )
                        .into_response()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_to_error_envelope() {
        let err = ApiError::new(ErrorCode::NotFound, "resource not found");
        let actual = serde_json::to_value(ApiErrorEnvelope { error: err }).unwrap();
        assert_eq!(
            actual,
            json!({
                "error": {
                    "code": "NOT_FOUND",
                    "message": "resource not found"
                }
            })
        );
    }

    #[test]
    fn serializes_with_details() {
        let err = ApiError::new(ErrorCode::InvalidClaim, "validation failed")
            .with_details(json!({ "field": "email" }));
        let actual = serde_json::to_value(ApiErrorEnvelope { error: err }).unwrap();
        assert_eq!(
            actual,
            json!({
                "error": {
                    "code": "INVALID_CLAIM",
                    "message": "validation failed",
                    "details": { "field": "email" }
                }
            })
        );
    }

    #[test]
    fn expired_token_serializes_as_pascal_case() {
        let err = ApiError::new(ErrorCode::ExpiredToken, "token has expired");
        let actual = serde_json::to_value(ApiErrorEnvelope { error: err }).unwrap();
        assert_eq!(actual["error"]["code"], "ExpiredToken");
    }

    #[test]
    fn invalid_swap_serializes_as_pascal_case() {
        let err = ApiError::new(ErrorCode::InvalidSwap, "swap precondition failed");
        let actual = serde_json::to_value(ApiErrorEnvelope { error: err }).unwrap();
        assert_eq!(actual["error"]["code"], "InvalidSwap");
        assert_eq!(ErrorCode::InvalidSwap.status_code(), 409);
    }

    #[test]
    fn did_resolution_errors_serialize_as_pascal_case() {
        let err = ApiError::new(ErrorCode::DidNotFound, "DID not found");
        let actual = serde_json::to_value(ApiErrorEnvelope { error: err }).unwrap();
        assert_eq!(actual["error"]["code"], "DidNotFound");

        let err = ApiError::new(ErrorCode::DidDeactivated, "DID deactivated");
        let actual = serde_json::to_value(ApiErrorEnvelope { error: err }).unwrap();
        assert_eq!(actual["error"]["code"], "DidDeactivated");
    }

    #[test]
    fn omits_details_when_absent() {
        let err = ApiError::new(ErrorCode::Forbidden, "access denied");
        let actual = serde_json::to_value(ApiErrorEnvelope { error: err }).unwrap();
        assert!(!actual["error"].as_object().unwrap().contains_key("details"));
    }

    #[test]
    fn status_code_mapping() {
        let cases = [
            (ErrorCode::InvalidClaim, 400u16),
            (ErrorCode::Unauthorized, 401),
            (ErrorCode::TokenExpired, 401),
            (ErrorCode::Forbidden, 403),
            (ErrorCode::NotFound, 404),
            (ErrorCode::WeakPassword, 422),
            (ErrorCode::RateLimited, 429),
            (ErrorCode::ExportInProgress, 503),
            (ErrorCode::ServiceUnavailable, 503),
            (ErrorCode::InternalError, 500),
            (ErrorCode::MethodNotImplemented, 501),
            (ErrorCode::AccountExists, 409),
            (ErrorCode::HandleTaken, 409),
            (ErrorCode::InvalidHandle, 400),
            (ErrorCode::ClaimCodeRedeemed, 409),
            (ErrorCode::DidAlreadyExists, 409),
            (ErrorCode::DidNotFound, 404),
            (ErrorCode::DidDeactivated, 410),
            (ErrorCode::PlcDirectoryError, 502),
            (ErrorCode::DnsError, 502),
            (ErrorCode::HandleNotFound, 404),
            (ErrorCode::AuthenticationRequired, 401),
            (ErrorCode::InvalidToken, 401),
            (ErrorCode::InsufficientScope, 403),
            (ErrorCode::ExpiredToken, 400),
            (ErrorCode::PayloadTooLarge, 413),
            (ErrorCode::InvalidRequest, 400),
            (ErrorCode::HandleResolutionFailed, 400),
            (ErrorCode::BlockNotFound, 400),
        ];
        for (code, expected) in cases {
            assert_eq!(code.status_code(), expected, "wrong status for {code:?}");
        }
    }

    #[cfg(feature = "axum")]
    mod axum_tests {
        use super::*;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        #[tokio::test]
        async fn into_response_correct_status_and_body() {
            let err = ApiError::new(ErrorCode::NotFound, "not found");
            let response = err.into_response();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"]["code"], "NOT_FOUND");
            assert_eq!(json["error"]["message"], "not found");
        }

        #[tokio::test]
        async fn into_response_emits_extra_headers() {
            let err = ApiError::new(ErrorCode::RateLimited, "slow down")
                .with_header("retry-after", "42")
                .with_header("ratelimit-remaining", "0");
            let response = err.into_response();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(response.headers().get("retry-after").unwrap(), "42");
            assert_eq!(response.headers().get("ratelimit-remaining").unwrap(), "0");
            // The extra headers are not leaked into the JSON body.
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(json["error"].get("headers").is_none());
        }
    }
}
