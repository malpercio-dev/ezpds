// pattern: Functional Core

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Error codes for the provisioning API.
///
/// Serialized as SCREAMING_SNAKE_CASE strings in the JSON envelope.
/// `#[non_exhaustive]` prevents external crates from writing exhaustive match
/// arms — new variants can be added in future waves without breaking callers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // Wave 0–2 initial set
    InvalidClaim,
    Unauthorized,
    TokenExpired,
    Forbidden,
    NotFound,
    WeakPassword,
    RateLimited,
    ExportInProgress,
}

impl ErrorCode {
    /// Maps each error code to its canonical HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ErrorCode::InvalidClaim => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::TokenExpired => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::WeakPassword => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::ExportInProgress => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Provisioning API error, serialized as the standard error envelope:
///
/// ```json
/// { "error": { "code": "NOT_FOUND", "message": "...", "details": {} } }
/// ```
///
/// Implements `IntoResponse` so it can be returned directly from Axum handlers.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
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
}

/// Wraps `ApiError` in the `{ "error": ... }` envelope for serialization.
#[derive(Serialize)]
struct ApiErrorEnvelope {
    error: ApiError,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.code.status_code();
        (status, Json(ApiErrorEnvelope { error: self })).into_response()
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
        // `details` key must not appear at all
        assert!(!actual["error"].as_object().unwrap().contains_key("details"));
    }

    #[test]
    fn status_code_mapping() {
        let cases = [
            (ErrorCode::InvalidClaim, StatusCode::BAD_REQUEST),
            (ErrorCode::Unauthorized, StatusCode::UNAUTHORIZED),
            (ErrorCode::TokenExpired, StatusCode::UNAUTHORIZED),
            (ErrorCode::Forbidden, StatusCode::FORBIDDEN),
            (ErrorCode::NotFound, StatusCode::NOT_FOUND),
            (ErrorCode::WeakPassword, StatusCode::UNPROCESSABLE_ENTITY),
            (ErrorCode::RateLimited, StatusCode::TOO_MANY_REQUESTS),
            (ErrorCode::ExportInProgress, StatusCode::SERVICE_UNAVAILABLE),
        ];
        for (code, expected) in cases {
            assert_eq!(code.status_code(), expected, "wrong status for {code:?}");
        }
    }
}
