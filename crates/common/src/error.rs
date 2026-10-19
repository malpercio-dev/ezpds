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
    /// The named space is unknown to this host, or has been deleted. Declared by every
    /// `com.atproto.space.*` and `com.atproto.simplespace.*` method.
    #[serde(rename = "SpaceNotFound")]
    SpaceNotFound,
    /// The named account holds no permissioned repo in the space.
    ///
    /// Deliberately also the answer when the caller may not read the named repo at all: whether
    /// some other account holds a repo in a space is not a fact a caller without read access to
    /// that space is entitled to learn, so "not yours" and "not there" are one reply.
    #[serde(rename = "RepoNotFound")]
    RepoNotFound,
    /// No record exists at the requested path in a permissioned repo — either read
    /// (`com.atproto.space.getRecord`) or as an `applyWrites` update/delete precondition.
    #[serde(rename = "RecordNotFound")]
    RecordNotFound,
    /// `com.atproto.space.getBlob` named a blob no record in the space references, or one this
    /// host does not hold. One reply for both, so an unreferenced blob's existence is never
    /// disclosed (the reference's `isBlobInSpace` check does the same).
    #[serde(rename = "BlobNotFound")]
    BlobNotFound,
    /// A create targeted a path that already holds a record. Distinct from the generic
    /// [`Conflict`](ErrorCode::Conflict), which reports a lost race rather than a stated
    /// precondition the caller can fix by choosing another key.
    #[serde(rename = "RecordAlreadyExists")]
    RecordAlreadyExists,
    /// The space has been deleted by its authority — the durable deletion signal a syncer sees
    /// when it tries to renew a space credential (Spaces proposal, "Space deletion").
    #[serde(rename = "SpaceDeleted")]
    SpaceDeleted,
    /// The space authority refused a credential on the basis of the requesting user.
    #[serde(rename = "UserNotAuthorized")]
    UserNotAuthorized,
    /// The space authority refused a credential on the basis of the requesting app.
    #[serde(rename = "AppNotAuthorized")]
    AppNotAuthorized,
    /// The delegation token presented to `getSpaceCredential` failed verification.
    #[serde(rename = "InvalidDelegationToken")]
    InvalidDelegationToken,
    /// The client attestation presented to `getSpaceCredential` failed verification — malformed,
    /// unresolvable client, wrong signature, wrong audience, expired, or replayed.
    #[serde(rename = "InvalidClientAttestation")]
    InvalidClientAttestation,
    /// A simplespace management call by an account that is not the space's authority.
    #[serde(rename = "NotSpaceOwner")]
    NotSpaceOwner,
    /// `createSpace` named a space that already exists (and is not deleted).
    #[serde(rename = "SpaceAlreadyExists")]
    SpaceAlreadyExists,
    /// The requested simplespace `policy` is not one this host implements (an open union).
    #[serde(rename = "UnsupportedPolicy")]
    UnsupportedPolicy,
    /// The requested simplespace `appAccess` is not one this host implements (an open union).
    #[serde(rename = "UnsupportedAppAccess")]
    UnsupportedAppAccess,
    /// `registerNotify`'s subscriber identifier did not resolve to a DID document with a
    /// matching service endpoint, so a registration for it could never deliver.
    #[serde(rename = "ServiceNotResolvable")]
    ServiceNotResolvable,
    // Codes for endpoints/designs not yet shipped (tiers, did:web self-service, device
    // leases, Shamir recovery, etc.) are catalogued in docs/provisioning-api-spec.md's
    // status-code appendix; add them here as those designs actually land.
}

impl ErrorCode {
    /// The error's name in the flat AT Protocol XRPC error shape
    /// (`{"error": "<name>", "message": "..."}`), used by the PDS's `/xrpc/*` boundary.
    ///
    /// Where the AT Protocol defines a canonical name for the condition, that name is used —
    /// atproto clients dispatch on these strings (`@atproto/api` and indigo both trigger
    /// session refresh only on `error == "ExpiredToken"`, and the reference PDS answers a
    /// missing Authorization header with `AuthMissing`). Codes with no canonical XRPC name
    /// keep this API's own name, PascalCased to match the XRPC convention.
    ///
    /// This is deliberately separate from the serde serialization (the provisioning API's
    /// nested envelope): the two surfaces speak different dialects, and this method is the
    /// single place the XRPC dialect is defined.
    pub fn xrpc_name(&self) -> &'static str {
        match self {
            ErrorCode::InvalidClaim => "InvalidClaim",
            // Presented credentials were wrong (as opposed to absent): the reference PDS
            // answers with the generic non-refreshable auth failure name.
            ErrorCode::Unauthorized => "AuthenticationRequired",
            // An expired *access token*. The canonical XRPC name — clients key their
            // refresh-on-401 logic on exactly this string.
            ErrorCode::TokenExpired => "ExpiredToken",
            ErrorCode::Forbidden => "Forbidden",
            ErrorCode::NotFound => "NotFound",
            // com.atproto.server.createAccount's lexicon error for a rejected password.
            ErrorCode::WeakPassword => "InvalidPassword",
            ErrorCode::RateLimited => "RateLimitExceeded",
            ErrorCode::ExportInProgress => "ExportInProgress",
            ErrorCode::ServiceUnavailable => "ServiceUnavailable",
            ErrorCode::InternalError => "InternalServerError",
            ErrorCode::MethodNotImplemented => "MethodNotImplemented",
            ErrorCode::AccountExists => "AccountExists",
            // com.atproto.server.createAccount's lexicon error for a taken handle.
            ErrorCode::HandleTaken => "HandleNotAvailable",
            ErrorCode::InvalidHandle => "InvalidHandle",
            ErrorCode::ClaimCodeRedeemed => "ClaimCodeRedeemed",
            ErrorCode::DidAlreadyExists => "DidAlreadyExists",
            ErrorCode::DidNotFound => "DidNotFound",
            ErrorCode::DidDeactivated => "DidDeactivated",
            ErrorCode::PlcDirectoryError => "PlcDirectoryError",
            ErrorCode::DnsError => "DnsError",
            ErrorCode::HandleNotFound => "HandleNotFound",
            // Authorization header absent entirely — the reference PDS's exact wire name.
            ErrorCode::AuthenticationRequired => "AuthMissing",
            ErrorCode::InvalidToken => "InvalidToken",
            ErrorCode::InsufficientScope => "InsufficientScope",
            ErrorCode::ExpiredToken => "ExpiredToken",
            ErrorCode::PayloadTooLarge => "PayloadTooLarge",
            ErrorCode::Conflict => "Conflict",
            ErrorCode::InvalidSwap => "InvalidSwap",
            ErrorCode::InvalidRequest => "InvalidRequest",
            ErrorCode::HandleResolutionFailed => "HandleResolutionFailed",
            ErrorCode::BlockNotFound => "BlockNotFound",
            ErrorCode::SpaceNotFound => "SpaceNotFound",
            ErrorCode::RepoNotFound => "RepoNotFound",
            ErrorCode::RecordNotFound => "RecordNotFound",
            ErrorCode::BlobNotFound => "BlobNotFound",
            ErrorCode::RecordAlreadyExists => "RecordAlreadyExists",
            ErrorCode::SpaceDeleted => "SpaceDeleted",
            ErrorCode::UserNotAuthorized => "UserNotAuthorized",
            ErrorCode::AppNotAuthorized => "AppNotAuthorized",
            ErrorCode::InvalidDelegationToken => "InvalidDelegationToken",
            ErrorCode::InvalidClientAttestation => "InvalidClientAttestation",
            ErrorCode::NotSpaceOwner => "NotSpaceOwner",
            ErrorCode::SpaceAlreadyExists => "SpaceAlreadyExists",
            ErrorCode::UnsupportedPolicy => "UnsupportedPolicy",
            ErrorCode::UnsupportedAppAccess => "UnsupportedAppAccess",
            ErrorCode::ServiceNotResolvable => "ServiceNotResolvable",
        }
    }

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
            // The reference raises all four as `InvalidRequestError` with a named `error`, which
            // is HTTP 400 — clients dispatch on the name, not the status.
            ErrorCode::SpaceNotFound => 400,
            ErrorCode::RepoNotFound => 400,
            ErrorCode::RecordNotFound => 400,
            ErrorCode::BlobNotFound => 400,
            ErrorCode::RecordAlreadyExists => 400,
            ErrorCode::SpaceDeleted => 400,
            ErrorCode::UserNotAuthorized => 403,
            ErrorCode::AppNotAuthorized => 403,
            // The delegation token is the request's authorization credential, so a bad one is an
            // authentication failure, like InvalidToken.
            ErrorCode::InvalidDelegationToken => 401,
            // 400, not 401: the delegation token is the request's authorization and its failure is
            // a 401, but the attestation is a body parameter naming the app, and the reference
            // answers a bad one as an invalid request.
            ErrorCode::InvalidClientAttestation => 400,
            // The reference raises the simplespace management errors as `InvalidRequestError`
            // too — including NotSpaceOwner, which is an ownership precondition, not an auth
            // failure (the caller is authenticated; the space is just not theirs).
            ErrorCode::NotSpaceOwner => 400,
            ErrorCode::SpaceAlreadyExists => 400,
            ErrorCode::UnsupportedPolicy => 400,
            ErrorCode::UnsupportedAppAccess => 400,
            ErrorCode::ServiceNotResolvable => 400,
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

    /// Re-code an error while keeping its message — for a seam whose caller speaks a more
    /// specific error vocabulary than the shared verifier that produced the failure.
    pub fn with_code(mut self, code: ErrorCode) -> Self {
        self.code = code;
        self
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

    /// The error's code. Callers that distinguish two conditions sharing one status — the space
    /// surface's named `RecordNotFound`/`RecordAlreadyExists` errors are both 400 — assert on
    /// this rather than on [`Self::status_code`].
    pub fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The error's caller-facing message. For a seam that re-encodes this error in another wire
    /// dialect and wants to carry the explanation across rather than flatten it to a status.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Wraps `ApiError` in the `{ "error": ... }` envelope for serialization.
#[cfg(any(feature = "axum", test))]
#[derive(Serialize)]
struct ApiErrorEnvelope {
    error: ApiError,
}

/// The semantic parts of an [`ApiError`] response, attached to the response's `Extensions`
/// by the `IntoResponse` impl.
///
/// This exists so a boundary layer can re-encode the same error in a different wire dialect
/// without parsing the JSON body back out — the PDS's `/xrpc/*` surface uses it to answer in
/// the flat AT Protocol XRPC error shape while the provisioning surface keeps the nested
/// envelope this crate serializes.
#[derive(Debug, Clone)]
pub struct ApiErrorParts {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<Value>,
}

#[cfg(feature = "axum")]
impl ApiError {
    /// Log `err` at ERROR level under `context`, then build the matching
    /// `ErrorCode::InternalError`, using `context` as the public-facing message too. Covers
    /// the common "log the DB/IO failure, answer 500 with the same wording" call site.
    pub fn internal(err: impl std::fmt::Display, context: &'static str) -> Self {
        Self::internal_as(err, context, context)
    }

    /// Like [`Self::internal`], but the log context and the caller-facing `message` differ.
    pub fn internal_as(
        err: impl std::fmt::Display,
        context: &'static str,
        message: impl Into<String>,
    ) -> Self {
        tracing::error!(error = %err, "{}", context);
        Self::new(ErrorCode::InternalError, message)
    }
}

/// Extends `Result<T, E>` with a `.map_err` shorthand for the "log the failure, answer 500"
/// call site, so it reads as one line at the `?` instead of a `.map_err(|e| { .. })` closure.
#[cfg(feature = "axum")]
pub trait ApiResultExt<T> {
    /// `.map_err(|e| ApiError::internal(e, context))`.
    fn or_internal(self, context: &'static str) -> Result<T, ApiError>;
    /// `.map_err(|e| ApiError::internal_as(e, context, message))`.
    fn or_internal_as(
        self,
        context: &'static str,
        message: impl Into<String>,
    ) -> Result<T, ApiError>;
}

#[cfg(feature = "axum")]
impl<T, E: std::fmt::Display> ApiResultExt<T> for Result<T, E> {
    fn or_internal(self, context: &'static str) -> Result<T, ApiError> {
        self.map_err(|e| ApiError::internal(e, context))
    }

    fn or_internal_as(
        self,
        context: &'static str,
        message: impl Into<String>,
    ) -> Result<T, ApiError> {
        self.map_err(|e| ApiError::internal_as(e, context, message))
    }
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

            // Attach the semantic parts so a boundary layer (the PDS's `/xrpc/*` surface) can
            // re-encode this error in the flat XRPC dialect without re-parsing the body.
            let parts = ApiErrorParts {
                code: self.code.clone(),
                message: self.message.clone(),
                details: self.details.clone(),
            };

            match serde_json::to_vec(&ApiErrorEnvelope { error: self }) {
                Ok(body) => {
                    let mut response = (status, [(header::CONTENT_TYPE, "application/json")], body)
                        .into_response();
                    response.extensions_mut().insert(parts);
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

        /// The response carries [`ApiErrorParts`] in its extensions so a boundary layer can
        /// re-encode the error in the XRPC dialect without re-parsing the body.
        #[tokio::test]
        async fn into_response_attaches_api_error_parts_extension() {
            let err = ApiError::new(ErrorCode::TokenExpired, "token has expired")
                .with_details(json!({ "hint": "refresh" }));
            let response = err.into_response();
            let parts = response
                .extensions()
                .get::<ApiErrorParts>()
                .expect("ApiErrorParts extension must be attached");
            assert_eq!(parts.code, ErrorCode::TokenExpired);
            assert_eq!(parts.message, "token has expired");
            assert_eq!(parts.details, Some(json!({ "hint": "refresh" })));
        }
    }

    /// The XRPC dialect names atproto clients actually dispatch on. `ExpiredToken` is the
    /// string `@atproto/api` and indigo key session refresh off; `AuthMissing` is the
    /// reference PDS's answer to a missing Authorization header (verified against
    /// bsky.social 2026-08-03).
    #[test]
    fn xrpc_names_use_canonical_atproto_strings() {
        assert_eq!(ErrorCode::TokenExpired.xrpc_name(), "ExpiredToken");
        assert_eq!(ErrorCode::ExpiredToken.xrpc_name(), "ExpiredToken");
        assert_eq!(ErrorCode::InvalidToken.xrpc_name(), "InvalidToken");
        assert_eq!(ErrorCode::AuthenticationRequired.xrpc_name(), "AuthMissing");
        assert_eq!(
            ErrorCode::Unauthorized.xrpc_name(),
            "AuthenticationRequired"
        );
        assert_eq!(ErrorCode::RateLimited.xrpc_name(), "RateLimitExceeded");
        assert_eq!(ErrorCode::InternalError.xrpc_name(), "InternalServerError");
        assert_eq!(ErrorCode::HandleTaken.xrpc_name(), "HandleNotAvailable");
        assert_eq!(ErrorCode::WeakPassword.xrpc_name(), "InvalidPassword");
    }
}
