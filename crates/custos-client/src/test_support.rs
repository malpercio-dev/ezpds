// pattern: Imperative Shell

//! Fixtures shared by this crate's unit tests.

use httpmock::MockServer;

use crate::base64url::b64url_encode;
use crate::oauth_client::OAuthClient;

/// A Bearer test JWT carrying only an `exp` claim. The signature is a placeholder:
/// `OAuthClient` reads `exp` and never verifies the token.
pub(crate) fn bearer_jwt(exp: u64) -> String {
    let header = b64url_encode(r#"{"alg":"ES256"}"#);
    let payload = b64url_encode(format!(r#"{{"exp":{exp}}}"#));
    format!("{header}.{payload}.sig")
}

/// A Bearer client pointed at `server`, with a far-future access token so no lazy refresh
/// fires before the request under test.
#[allow(
    clippy::expect_used,
    reason = "the mock server URL is loopback, which new_bearer accepts"
)]
pub(crate) fn bearer_client(server: &MockServer) -> OAuthClient {
    OAuthClient::new_bearer(
        bearer_jwt(9_999_999_999),
        "refresh".to_string(),
        server.base_url(),
    )
    .expect("loopback base URL")
}
