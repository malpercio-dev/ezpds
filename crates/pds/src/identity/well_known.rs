// pattern: Imperative Shell
//
// HTTP well-known abstraction for handle resolution.
//
// WellKnownResolver — resolves handles via GET https://<handle>/.well-known/atproto-did.
//   Used as the third fallback in resolveHandle (after local DB and DNS TXT).
//   HttpWellKnownResolver is the production implementation; tests inject mocks.

use std::future::Future;
use std::pin::Pin;

/// Error returned by a [`WellKnownResolver`] operation.
#[derive(Debug, thiserror::Error)]
#[error("HTTP well-known error: {0}")]
pub struct WellKnownError(pub String);

/// Upper bound on the `.well-known/atproto-did` response body. A valid DID is well under this;
/// the endpoint host is caller-controlled (the handle being resolved), so its response is not
/// trusted to be bounded — without this, a malicious host could stream an unbounded body to
/// exhaust memory.
const MAX_WELL_KNOWN_BODY_BYTES: usize = 2048;

/// Abstraction over HTTP well-known handle resolution.
///
/// Used by `resolveHandle` as the third fallback after local DB and DNS TXT.
/// Calls `GET https://<handle>/.well-known/atproto-did` and returns the DID
/// from the response body, or `None` if the endpoint doesn't exist / returns non-2xx.
///
/// Object-safe: uses `Pin<Box<dyn Future>>` so `dyn WellKnownResolver` works with `Arc`.
pub trait WellKnownResolver: Send + Sync {
    /// Attempt to resolve a handle via its `/.well-known/atproto-did` endpoint.
    ///
    /// Returns `Ok(Some(did))` on success, `Ok(None)` if the endpoint is absent
    /// or returns non-2xx, and `Err` only on transport-level failures.
    fn resolve<'a>(
        &'a self,
        handle: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, WellKnownError>> + Send + 'a>>;
}

/// Production [`WellKnownResolver`] that calls `https://<handle>/.well-known/atproto-did`.
pub struct HttpWellKnownResolver {
    client: reqwest::Client,
}

impl HttpWellKnownResolver {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl WellKnownResolver for HttpWellKnownResolver {
    fn resolve<'a>(
        &'a self,
        handle: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, WellKnownError>> + Send + 'a>> {
        let url = format!("https://{}/.well-known/atproto-did", handle);
        Box::pin(async move {
            let mut resp = self
                .client
                .get(&url)
                .send()
                .await
                .map_err(|e| WellKnownError(e.to_string()))?;
            if !resp.status().is_success() {
                return Ok(None);
            }
            let mut body = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| WellKnownError(e.to_string()))?
            {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_WELL_KNOWN_BODY_BYTES {
                    return Err(WellKnownError(
                        "well-known response exceeds maximum size".to_string(),
                    ));
                }
            }
            let text = String::from_utf8(body).map_err(|e| WellKnownError(e.to_string()))?;
            Ok(Some(text.trim().to_string()))
        })
    }
}
