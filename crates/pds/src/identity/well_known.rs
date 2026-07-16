// pattern: Imperative Shell
//
// HTTP well-known abstraction for handle resolution.
//
// WellKnownResolver — resolves handles via GET https://<handle>/.well-known/atproto-did.
//   Used as the third fallback in resolveHandle (after local DB and DNS TXT).
//   HttpWellKnownResolver is the production implementation; tests inject mocks.

use std::future::Future;
use std::pin::Pin;

use super::did::is_valid_did;

/// Error returned by a [`WellKnownResolver`] operation.
#[derive(Debug, thiserror::Error)]
#[error("HTTP well-known error: {0}")]
pub struct WellKnownError(pub String);

impl WellKnownError {
    fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        let mut message = error.to_string();
        let mut source = error.source();
        while let Some(error) = source {
            message.push_str(": ");
            message.push_str(&error.to_string());
            source = error.source();
        }
        Self(message)
    }
}

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
                .map_err(|e| WellKnownError::from_error(&e))?;
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
            Ok(Some(parse_well_known_body(body)?))
        })
    }
}

fn parse_well_known_body(body: Vec<u8>) -> Result<String, WellKnownError> {
    let text = String::from_utf8(body).map_err(|e| WellKnownError(e.to_string()))?;
    let did = text.trim();
    if !is_valid_did(did) {
        return Err(WellKnownError(
            "well-known response is not a syntactically valid DID".to_string(),
        ));
    }
    Ok(did.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_body_that_is_not_a_valid_did() {
        let error = parse_well_known_body(b"internal service response".to_vec()).unwrap_err();
        assert!(error.to_string().contains("not a syntactically valid DID"));
    }

    #[test]
    fn accepts_trimmed_valid_did() {
        assert_eq!(
            parse_well_known_body(b"\n did:plc:abc123 \r\n".to_vec()).unwrap(),
            "did:plc:abc123"
        );
    }

    #[tokio::test]
    async fn hardened_client_rejects_private_hostname_target() {
        let client = crate::identity::proxy::build_hardened_client(false).unwrap();
        let resolver = HttpWellKnownResolver::new(client);

        let error = resolver.resolve("localhost").await.unwrap_err();
        assert!(error
            .to_string()
            .contains("refusing to connect to \"localhost\": it resolves to a non-public address"));
    }
}
