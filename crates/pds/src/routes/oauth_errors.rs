// pattern: Functional Core
//
// The shared OAuth 2.0 error response type for the token-issuing and token-revocation
// endpoints. Pure: given an error code, description, and optional DPoP nonce it builds an
// Axum response; no I/O, no database, no AppState. Lives here (rather than in either
// handler) so `oauth_token.rs` and `oauth_revoke.rs` share one responder without a
// route→route import — the same pattern as `oauth_templates.rs`.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};

/// OAuth 2.0 error response body (RFC 6749 §5.2).
///
/// All token-endpoint and revocation-endpoint errors use this format, distinct from the
/// codebase's `ApiError` envelope (`{ "error": { "code": "...", "message": "..." } }`).
pub(super) struct OAuthTokenError {
    pub error: &'static str,
    pub error_description: &'static str,
    /// Optional DPoP-Nonce value to include in the response header.
    /// Required for `use_dpop_nonce` errors so the client can retry.
    pub dpop_nonce: Option<String>,
}

impl OAuthTokenError {
    pub(super) fn new(error: &'static str, error_description: &'static str) -> Self {
        Self {
            error,
            error_description,
            dpop_nonce: None,
        }
    }

    pub(super) fn with_nonce(
        error: &'static str,
        error_description: &'static str,
        nonce: String,
    ) -> Self {
        Self {
            error,
            error_description,
            dpop_nonce: Some(nonce),
        }
    }
}

impl IntoResponse for OAuthTokenError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.error,
            "error_description": self.error_description,
        });
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        if let Some(nonce) = self.dpop_nonce {
            match axum::http::HeaderValue::from_str(&nonce) {
                Ok(hval) => {
                    headers.insert("DPoP-Nonce", hval);
                }
                Err(e) => {
                    // This should never happen: nonces are base64url ASCII, always valid
                    // header values. If it does happen, returning use_dpop_nonce without
                    // the nonce header leaves the client with no retry path (RFC 9449 §7.1).
                    // Return server_error instead.
                    tracing::error!(nonce = ?nonce, error = %e, "nonce string cannot be encoded as HTTP header value; this is a server bug");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(
                            axum::http::header::CONTENT_TYPE,
                            axum::http::HeaderValue::from_static("application/json"),
                        )],
                        Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "internal server error",
                        })),
                    )
                        .into_response();
                }
            }
        }

        // RFC 6749 §5.2: most errors are 400, but server_error is 500.
        let status = if self.error == "server_error" {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::BAD_REQUEST
        };
        (status, headers, Json(body)).into_response()
    }
}
