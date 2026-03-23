// pattern: Functional Core

use common::{ApiError, ErrorCode};

/// Extract `Authorization: Bearer <token>` from headers.
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, ApiError> {
    let auth_value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| {
            v.to_str()
                .inspect_err(|_| {
                    tracing::warn!(
                        "Authorization header contains non-UTF-8 bytes; treating as absent"
                    );
                })
                .ok()
        })
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::AuthenticationRequired,
                "missing Authorization header",
            )
        })?;

    // RFC 7235 §2.1: auth scheme names are case-insensitive ("bearer", "BEARER", etc.).
    const BEARER_LEN: usize = 7; // "Bearer ".len() — scheme name + single SP
    if !auth_value
        .get(..BEARER_LEN)
        .is_some_and(|s| s.eq_ignore_ascii_case("Bearer "))
    {
        return Err(ApiError::new(
            ErrorCode::AuthenticationRequired,
            "Authorization header must use Bearer scheme",
        ));
    }
    Ok(&auth_value[BEARER_LEN..])
}
