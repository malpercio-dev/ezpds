// pattern: Mixed (unavoidable)

//! [`PdsClientError`]: the typed XRPC failure shape both apps' request helpers classify a
//! non-2xx response into, plus the shared classification tail (`xrpc_ok`/`xrpc_json`) every
//! XRPC call in the wallet routes through.
//!
//! **Status classification.** [`classify_xrpc_response`] (→ the pure [`classify_xrpc_error`]):
//! `429` → `RateLimited { retry_after }`, `401` → `Unauthorized`, anything else →
//! `XrpcError { status, error, message }` carrying the atproto error envelope.
//! [`PdsClientError::NetworkError`] is transport-only — a server that answered is never
//! reported as a connectivity failure.
//!
//! **Breadcrumbs are injected, not hardcoded.** The wallet records every transport/server
//! failure into an exportable diagnostics log (`crate::diagnostics`); that is app-specific UI
//! plumbing this Tauri-free crate cannot depend on directly. Callers pass a
//! [`TransportObserver`] (the wallet's `diagnostics` module implements it); [`NoopObserver`]
//! is available for callers with nothing to record.

/// Observes transport and server-verdict failures for diagnostics/breadcrumb purposes.
/// A no-op default is provided ([`NoopObserver`]) for callers with nothing to record.
pub trait TransportObserver: Send + Sync {
    /// A `reqwest::Error` that never reached a server response (DNS/connect/TLS/timeout).
    fn record_transport(&self, op: &str, url: Option<&str>, error: &reqwest::Error);

    /// A server verdict: a non-2xx XRPC response was fully read and classified.
    fn record_server(&self, op: &str, host: Option<&str>, status: u16, error_code: Option<&str>);

    /// A transport failure that isn't a `reqwest::Error` (e.g. a DNS resolver error) — the
    /// caller has already reduced it to a fixed category string (never the raw error, which
    /// may embed caller-supplied data like a handle). Defaults to recording nothing — it
    /// cannot forward into [`Self::record_transport`], which requires a real `reqwest::Error`
    /// this category string isn't. An observer that doesn't override this drops this whole
    /// breadcrumb class (this crate's own DNS-failure path, currently); override it for a real
    /// breadcrumb. `host` follows the same redaction rule as `record_transport`: omit it when
    /// the category string itself could embed sensitive data.
    fn record_transport_category(&self, _op: &str, _host: Option<&str>, _category: &str) {}
}

/// A [`TransportObserver`] that records nothing.
pub struct NoopObserver;

impl TransportObserver for NoopObserver {
    fn record_transport(&self, _op: &str, _url: Option<&str>, _error: &reqwest::Error) {}
    fn record_server(
        &self,
        _op: &str,
        _host: Option<&str>,
        _status: u16,
        _error_code: Option<&str>,
    ) {
    }
}

/// Error type for PDS client operations.
///
/// Serializes to frontend with `#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]`,
/// matching the `DpopError` / `IdentityStoreError` pattern.
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PdsClientError {
    /// Neither DNS nor HTTP resolution succeeded for the handle.
    #[error("handle not found")]
    HandleNotFound,

    /// plc.directory returned 404 for the DID.
    #[error("did not found")]
    DidNotFound,

    /// PDS endpoint is down or unreachable.
    #[error("pds unreachable: {reason}")]
    PdsUnreachable {
        /// Reason for unreachability (transport error, connection refused, etc.).
        /// Not serialized to frontend (serde skip).
        #[serde(skip)]
        reason: String,
    },

    /// Transport-level failure (DNS timeout, connection refused, TLS error, body read error) —
    /// the request never got a well-formed HTTP response back. A non-2xx *response* is NOT a
    /// `NetworkError`: it is classified into one of the status-specific variants below. Keeping
    /// this variant transport-only is what lets screens tell "check your connection" apart from
    /// "the server said no".
    #[error("network error: {message}")]
    NetworkError { message: String },

    /// The server answered `429 Too Many Requests`. `retry_after` is the raw `Retry-After` header
    /// (seconds or an HTTP date) when the server sent one, so the UI can say how long to wait
    /// instead of blaming the connection. `message` is the server's own error text.
    #[error("rate limited: {message}")]
    RateLimited {
        retry_after: Option<String>,
        message: String,
    },

    /// The server answered `401 Unauthorized` — the session/token was rejected (expired, wrong
    /// audience, a scope refusal presented as 401). Distinct from a transport failure so the UI
    /// can prompt a re-login rather than a retry. `error` is the atproto error code from the
    /// envelope when present (e.g. `ExpiredToken`, `InvalidToken`) — preserved so a token failure
    /// reported under 401 is still recognizable by code rather than only by message text; `message`
    /// is the server's own error text.
    #[error("unauthorized: {message}")]
    Unauthorized {
        error: Option<String>,
        message: String,
    },

    /// Any other non-2xx XRPC response, carrying the atproto error envelope so the real reason
    /// reaches the UI instead of connectivity boilerplate. `error` is the envelope's `error` code
    /// (e.g. `InvalidRequest`, `InsufficientScope`) when the body was a recognizable envelope;
    /// `message` is the envelope's human-readable `message` (falling back to the error code, then
    /// the raw body). `status` is the HTTP status code.
    #[error("server error {status}: {message}")]
    XrpcError {
        status: u16,
        error: Option<String>,
        message: String,
    },

    /// Response body couldn't be parsed or was missing expected fields.
    #[error("invalid response: {message}")]
    InvalidResponse { message: String },

    /// PAR or token exchange failed.
    #[error("oauth failed: {message}")]
    OauthFailed { message: String },

    /// DID already exists (HTTP 409 from createAccount migration).
    #[error("did already exists")]
    DidAlreadyExists,

    /// `createSession` rejected the identifier/password (HTTP 401). Distinct from a transport
    /// failure so the claim flow can tell the user "wrong password" rather than "network error".
    #[error("invalid credentials: {message}")]
    InvalidCredentials { message: String },

    /// `createSession` needs an email 2FA one-time code (`AuthFactorTokenRequired`, HTTP 401).
    /// The account has email two-factor enabled and the server has emailed a code; retry
    /// `create_session` with that code as `auth_factor_token`.
    #[error("auth factor token required")]
    AuthFactorTokenRequired,

    /// Refused to send the account password to a non-HTTPS PDS URL (loopback excepted). The
    /// `pds_url` is derived from the DID document, so a plaintext `http://` endpoint must never
    /// receive the password.
    #[error("insecure pds url: {url}")]
    InsecurePdsUrl { url: String },
}

/// Whether an atproto XRPC error body (`{"error":"...","message":"..."}`) carries `error == code`.
pub fn error_code_is(body: &str, code: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(|s| s == code))
        .unwrap_or(false)
}

/// Parse an atproto XRPC error envelope (`{"error":"Code","message":"human text"}`) out of a
/// response body. Returns `(error_code, human_message)`:
/// - `error_code` is the envelope's `error` field when the body was a recognizable JSON envelope,
///   else `None` (e.g. an HTML gateway page or an empty body);
/// - `human_message` is the envelope's `message`, falling back to the `error` code, then to the
///   raw (trimmed) body when it wasn't an envelope at all.
///
/// The atproto error envelope is designed to be shown to users, so preserving both fields is what
/// turns an opaque non-2xx into a diagnosable one.
pub fn parse_xrpc_error_envelope(body: &str) -> (Option<String>, String) {
    let envelope = serde_json::from_str::<serde_json::Value>(body).ok();
    let error = envelope
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|e| e.as_str())
        .map(str::to_string);
    let message = envelope
        .as_ref()
        .and_then(|v| v.get("message"))
        .and_then(|m| m.as_str())
        .map(str::to_string)
        .or_else(|| error.clone())
        .unwrap_or_else(|| body.trim().to_string());
    (error, message)
}

/// Classify a non-2xx XRPC response into the typed `PdsClientError` variant that preserves the
/// server's own words. A pure function of the HTTP status, the raw `Retry-After` header, and the
/// parsed error envelope, so it is unit-testable without a live response.
///
/// Contract:
/// - `429` → [`PdsClientError::RateLimited`], carrying `retry_after` when the server sent it.
/// - `401` → [`PdsClientError::Unauthorized`], carrying the atproto `error` code when present so a
///   token failure reported under 401 stays recognizable by code.
/// - anything else → [`PdsClientError::XrpcError`] with the atproto `error` code and human message.
///
/// It must NEVER return [`PdsClientError::NetworkError`]: by the time we are here the server *did*
/// answer, so this is never a transport failure.
pub fn classify_xrpc_error(status: u16, retry_after: Option<String>, body: &str) -> PdsClientError {
    let (error, message) = parse_xrpc_error_envelope(body);
    match status {
        429 => PdsClientError::RateLimited {
            retry_after,
            message,
        },
        401 => PdsClientError::Unauthorized { error, message },
        // Everything else — including 403 — keeps its atproto error code and human message. Domain
        // callers (e.g. `claim::classify_plc_op_error`) recognize codes like `InsufficientScope`
        // here; this layer only speaks HTTP-status semantics. `retry_after` is meaningful only for
        // 429, so it is intentionally dropped for these statuses.
        _ => PdsClientError::XrpcError {
            status,
            error,
            message,
        },
    }
}

/// Upper bound on how much of an error response body we buffer, keep, and log. An atproto error
/// envelope is a short JSON object; anything larger is a broken or hostile server, and reading it
/// in full would let an untrusted endpoint spike memory or flood the logs.
const MAX_XRPC_ERROR_BODY: usize = 8 * 1024;

/// Read at most `cap` bytes of a response body, streaming so an oversized (untrusted) payload is
/// never fully buffered. Returns the decoded (lossy-UTF-8) prefix. A transport error mid-read
/// propagates as `Err` so the caller can treat it as a `NetworkError` rather than a server verdict.
async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<String, reqwest::Error> {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < cap {
        match resp.chunk().await? {
            Some(chunk) => {
                let take = (cap - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
            }
            None => break,
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read the status, `Retry-After` header, and body off a non-success XRPC response and classify it,
/// recording transport/server breadcrumbs into `observer` along the way.
///
/// The imperative wrapper around [`classify_xrpc_error`]. The `Retry-After` header is captured
/// before the body (reading the body consumes the response). The body is bounded to
/// [`MAX_XRPC_ERROR_BODY`] so an oversized untrusted payload can't spike memory or flood logs, and
/// a mid-read transport failure surfaces as `NetworkError` rather than a fabricated server verdict.
/// `context` names the call site (e.g. `"requestPlcOperationSignature"`) for the log line and the
/// breadcrumb only — the returned error carries the server's own message, not the context, so
/// screens show it verbatim.
pub async fn classify_xrpc_response(
    context: &str,
    resp: reqwest::Response,
    observer: &dyn TransportObserver,
) -> PdsClientError {
    let status = resp.status();
    // Capture both before the body read consumes the response. `url` is the full request
    // URL — `record_transport`'s contract, and what the wallet's `record_reqwest_transport`
    // adapter `Url::parse`s; a bare host fails that parse and silently drops the breadcrumb's
    // host. `host` (bare hostname, never the path or query) is what `record_server` wants.
    let url = resp.url().to_string();
    let host = resp.url().host_str().map(str::to_string);
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = match read_body_capped(resp, MAX_XRPC_ERROR_BODY).await {
        Ok(body) => body,
        Err(e) => {
            observer.record_transport(context, Some(url.as_str()), &e);
            tracing::warn!(context, status = %status, error = %e, "failed to read XRPC error body");
            return PdsClientError::NetworkError {
                message: format!("failed to read {status} response body: {e}"),
            };
        }
    };
    tracing::warn!(context, status = %status, body = %body, "XRPC call returned non-success");
    // Redacted breadcrumb for the user-exportable diagnostics log: the atproto `error`
    // code is a short, safe token (e.g. `RateLimited`), never the free-form message/body.
    let (error_code, _message) = parse_xrpc_error_envelope(&body);
    observer.record_server(
        context,
        host.as_deref(),
        status.as_u16(),
        error_code.as_deref(),
    );
    classify_xrpc_error(status.as_u16(), retry_after, &body)
}

/// The shared tail of an XRPC call once a response has been received: classify a non-2xx
/// status into the matching [`PdsClientError`] variant via [`classify_xrpc_response`], or hand
/// back the still-unread response on success. `op` is the same call-site name passed through to
/// `classify_xrpc_response` (used only for the log line and breadcrumb, not the returned error).
///
/// This is the one piece truly common to every XRPC call — callers that also need the JSON body
/// should prefer [`xrpc_json`]; callers with something extra around this branch (a special-cased
/// status code, a raw-bytes/text body, a custom timeout) call this directly.
pub async fn xrpc_ok(
    op: &str,
    resp: reqwest::Response,
    observer: &dyn TransportObserver,
) -> Result<reqwest::Response, PdsClientError> {
    if resp.status().is_success() {
        Ok(resp)
    } else {
        Err(classify_xrpc_response(op, resp, observer).await)
    }
}

/// [`xrpc_ok`], then decode a JSON success body. A malformed body maps to
/// [`PdsClientError::InvalidResponse`] — the variant most JSON-returning call sites use; a
/// handful of callers that report [`PdsClientError::NetworkError`] on a parse failure instead
/// call [`xrpc_ok`] directly and parse inline, to keep that pre-existing distinction intact.
pub async fn xrpc_json<T: serde::de::DeserializeOwned>(
    op: &str,
    resp: reqwest::Response,
    observer: &dyn TransportObserver,
) -> Result<T, PdsClientError> {
    let resp = xrpc_ok(op, resp, observer).await?;
    resp.json::<T>()
        .await
        .map_err(|e| PdsClientError::InvalidResponse {
            message: format!("failed to parse {op} response: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_429_carries_retry_after() {
        let err = classify_xrpc_error(
            429,
            Some("30".to_string()),
            r#"{"error":"RateLimitExceeded","message":"slow down"}"#,
        );
        assert!(matches!(
            err,
            PdsClientError::RateLimited { retry_after: Some(r), message }
                if r == "30" && message == "slow down"
        ));
    }

    #[test]
    fn classify_401_carries_error_code() {
        let err = classify_xrpc_error(401, None, r#"{"error":"ExpiredToken","message":"expired"}"#);
        assert!(matches!(
            err,
            PdsClientError::Unauthorized { error: Some(e), message }
                if e == "ExpiredToken" && message == "expired"
        ));
    }

    #[test]
    fn classify_other_status_is_xrpc_error() {
        let err = classify_xrpc_error(
            400,
            None,
            r#"{"error":"InvalidRequest","message":"bad request"}"#,
        );
        assert!(matches!(
            err,
            PdsClientError::XrpcError { status: 400, error: Some(e), message }
                if e == "InvalidRequest" && message == "bad request"
        ));
    }

    /// A 5xx with a non-envelope body still surfaces the raw body as the message (never a
    /// `NetworkError` — the server did answer).
    #[test]
    fn classify_xrpc_error_5xx_non_envelope_falls_back_to_body() {
        let err = classify_xrpc_error(503, None, "service unavailable");
        match err {
            PdsClientError::XrpcError {
                status,
                error,
                message,
            } => {
                assert_eq!(status, 503);
                assert_eq!(error, None);
                assert_eq!(message, "service unavailable");
            }
            other => panic!("expected XrpcError, got {other:?}"),
        }
    }

    #[test]
    fn envelope_falls_back_to_raw_body_when_not_json() {
        let (error, message) = parse_xrpc_error_envelope("not json at all");
        assert_eq!(error, None);
        assert_eq!(message, "not json at all");
    }

    #[test]
    fn envelope_falls_back_to_error_code_when_no_message() {
        let (error, message) = parse_xrpc_error_envelope(r#"{"error":"InsufficientScope"}"#);
        assert_eq!(error.as_deref(), Some("InsufficientScope"));
        assert_eq!(message, "InsufficientScope");
    }

    #[test]
    fn error_code_is_matches_exact_code() {
        assert!(error_code_is(
            r#"{"error":"InsufficientScope","message":"nope"}"#,
            "InsufficientScope"
        ));
        assert!(!error_code_is(
            r#"{"error":"InvalidRequest","message":"nope"}"#,
            "InsufficientScope"
        ));
    }

    /// `xrpc_json` is the shared tail every XRPC call site routes through: a non-2xx response
    /// classifies through `classify_xrpc_response` (here, `RateLimited` with the pacing hint),
    /// and a malformed body on an otherwise-successful response maps to `InvalidResponse`
    /// rather than panicking or silently defaulting. The only test anywhere driving a real
    /// `reqwest::Response` through `xrpc_json` — it pins capturing `Retry-After` before the
    /// body is consumed and the parse-failure branch.
    #[tokio::test]
    async fn xrpc_json_classifies_non_2xx_and_flags_malformed_body() {
        use httpmock::MockServer;

        let mock_server = MockServer::start();
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/rate-limited");
            then.status(429).header("Retry-After", "5").body("{}");
        });
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/garbage");
            then.status(200).body("not json");
        });

        let client = reqwest::Client::new();

        let resp = client
            .get(format!("{}/rate-limited", mock_server.base_url()))
            .send()
            .await
            .unwrap();
        match xrpc_json::<serde_json::Value>("test", resp, &NoopObserver)
            .await
            .unwrap_err()
        {
            PdsClientError::RateLimited { retry_after, .. } => {
                assert_eq!(retry_after.as_deref(), Some("5"));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }

        let resp = client
            .get(format!("{}/garbage", mock_server.base_url()))
            .send()
            .await
            .unwrap();
        match xrpc_json::<serde_json::Value>("test", resp, &NoopObserver)
            .await
            .unwrap_err()
        {
            PdsClientError::InvalidResponse { message } => {
                assert!(
                    message.contains("failed to parse test response"),
                    "got: {message}"
                );
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }
}
