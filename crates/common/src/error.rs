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
    /// The external PLC directory returned a non-success response.
    PlcDirectoryError,
    /// A configured DNS provider returned an error when creating a subdomain record.
    DnsError,
    /// The requested handle does not resolve to a known DID locally or via DNS.
    HandleNotFound,
    // TODO: add remaining codes from Appendix A as endpoints are implemented:
    // 400: INVALID_DOCUMENT, INVALID_PROOF, INVALID_ENDPOINT, INVALID_CONFIRMATION
    // 401: INVALID_CREDENTIALS
    // 403: TIER_RESTRICTED, DIDWEB_REQUIRES_DOMAIN, SINGLE_DEVICE_TIER
    // 404: DEVICE_NOT_FOUND, DID_NOT_FOUND, NOT_IN_GRACE_PERIOD
    // 409: ACCOUNT_NOT_FOUND, DEVICE_LIMIT, DID_EXISTS,
    //      ROTATION_IN_PROGRESS, LEASE_HELD, MIGRATION_IN_PROGRESS, ACTIVE_MIGRATION
    // 410: ALREADY_DELETED
    // 422: INVALID_KEY, KEY_MISMATCH, DIDWEB_SELF_SERVICE
    // 423: ACCOUNT_LOCKED
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
            ErrorCode::PlcDirectoryError => 502,
            ErrorCode::DnsError => 502,
            ErrorCode::HandleNotFound => 404,
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
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
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
        http::{header, StatusCode},
        response::{IntoResponse, Response},
        Json,
    };

    impl IntoResponse for ApiError {
        fn into_response(self) -> Response {
            let status = StatusCode::from_u16(self.code.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            match serde_json::to_vec(&ApiErrorEnvelope { error: self }) {
                Ok(body) => {
                    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
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
            (ErrorCode::PlcDirectoryError, 502),
            (ErrorCode::DnsError, 502),
            (ErrorCode::HandleNotFound, 404),
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
    }
}
