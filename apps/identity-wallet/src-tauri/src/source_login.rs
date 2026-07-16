// pattern: Functional Core (one shared network core + a neutral error, no Tauri state)
//
// Both wallet source-login paths — the claim flow (`claim::authenticate_source_pds`) and the
// outbound migration (`migration_orchestrator::authenticate_migration_source`) — open a full
// session against the account's *current* PDS with a password `createSession` and wrap it in a
// Bearer `OAuthClient` (ADR-0021). A spec-strict PDS (bsky.social) gates the
// operations that follow — PLC/identity ops for the claim, minting the source's
// `com.atproto.server.createAccount` service-auth token for the migration — behind a full session;
// the atproto OAuth ceiling for a third-party client is `transition:generic`, which those
// operations refuse.
//
// The body is identical apart from which frontend-facing error enum it feeds. This module owns
// that body once and returns a neutral `SourceLoginError`; each caller keeps its own public enum
// and maps `SourceLoginError` in via `From`. Two distinct enums are a deliberate design
// choice — the goal is to share the *behavior + tests*, not collapse the contracts.

use crate::oauth_client::OAuthClient;

/// Neutral result of a source-PDS password login, mapped into each caller's frontend-facing error
/// enum (`ClaimError` / `MigrationError`) via `From`. The variants mirror exactly the ones both
/// callers used to produce inline, so the mapping is total and lossless.
#[derive(Debug)]
pub(crate) enum SourceLoginError {
    /// The account has email two-factor enabled: `createSession` returned `AuthFactorTokenRequired`
    /// and the PDS emailed a one-time code. The UI prompts for the code and re-invokes with it.
    TwoFactorRequired,
    /// The source PDS rejected the password (`createSession` 401). `message` is a fixed,
    /// user-safe string — never the server's raw text — so the UI can say "wrong password".
    SourceAuthFailed { message: String },
    /// The session the PDS returned is for a different account than the one being claimed/migrated.
    AccountMismatch,
    /// Refused to send the password to a non-HTTPS, non-loopback source PDS (endpoint from the DID
    /// document).
    InsecureSourceUrl,
    /// The source PDS rate-limited the login (HTTP 429). `retry_after` carries `Retry-After`.
    RateLimited { retry_after: Option<String> },
    /// A non-2xx the wallet doesn't model specially. `message` is the server's own error text.
    ServerError { message: String },
    /// Transport failure, or the returned session couldn't be turned into a Bearer client.
    NetworkError { message: String },
}

/// Shared core: run `createSession` against the source PDS and build a full-session Bearer
/// `OAuthClient`, enforcing the account-match guard. Extracted so both source-login paths share one
/// implementation and one behavioral test suite.
///
/// `expected_did` is the DID being claimed/migrated: the session the PDS returns MUST be for that
/// account, or the caller signed in to the wrong one and we refuse to bind those credentials rather
/// than act against the wrong identity. The password is used for one request and never stored.
pub(crate) async fn authenticate_source_password(
    pds_client: &crate::pds_client::PdsClient,
    pds_url: &str,
    expected_did: &str,
    identifier: &str,
    password: &str,
    auth_factor_token: Option<&str>,
) -> Result<OAuthClient, SourceLoginError> {
    let session = pds_client
        .create_session(pds_url, identifier, password, auth_factor_token)
        .await
        .map_err(|e| match e {
            crate::pds_client::PdsClientError::AuthFactorTokenRequired => {
                tracing::info!("source account has email 2FA; a code was sent");
                SourceLoginError::TwoFactorRequired
            }
            crate::pds_client::PdsClientError::InvalidCredentials { message } => {
                tracing::warn!(detail = %message, "source createSession rejected the password");
                SourceLoginError::SourceAuthFailed {
                    message: "The PDS did not accept that password.".to_string(),
                }
            }
            crate::pds_client::PdsClientError::InsecurePdsUrl { url } => {
                tracing::error!(pds_url = %url, "refusing password login to a non-HTTPS PDS");
                SourceLoginError::InsecureSourceUrl
            }
            // A rate limit or other server rejection during the password login must keep its real
            // reason too — a 429 here is not a connectivity problem.
            crate::pds_client::PdsClientError::RateLimited { retry_after, .. } => {
                SourceLoginError::RateLimited { retry_after }
            }
            crate::pds_client::PdsClientError::XrpcError { message, .. } => {
                SourceLoginError::ServerError { message }
            }
            other => SourceLoginError::NetworkError {
                message: format!("createSession failed: {}", other),
            },
        })?;

    // The session must be for the account being claimed/migrated. A mismatch means the user signed
    // in to a different account (or a hostile PDS returned someone else's session) — refuse to bind
    // those credentials rather than act against the wrong identity.
    if session.did != expected_did {
        tracing::warn!(
            expected = %expected_did,
            got = %session.did,
            "source session DID does not match the expected identity"
        );
        return Err(SourceLoginError::AccountMismatch);
    }

    OAuthClient::new_bearer(session.access_jwt, session.refresh_jwt, pds_url.to_string()).map_err(
        |e| {
            tracing::error!(error = %e, "failed to build Bearer client from source session");
            SourceLoginError::NetworkError {
                message: "failed to build source session client".to_string(),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Bearer-session JWT with a future `exp` so `new_bearer` derives a live expiry.
    fn future_exp_jwt() -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 3600).as_bytes());
        format!("{}.{}.sig", header, payload)
    }

    /// Happy path: a 200 `createSession` yields a full-session Bearer client bound to the PDS URL.
    #[tokio::test]
    async fn test_authenticate_source_password_success() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;

        let server = MockServer::start();
        let access_jwt = future_exp_jwt();
        let access_for_body = access_jwt.clone();
        server.mock(move |when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createSession");
            then.status(200).json_body(serde_json::json!({
                "accessJwt": access_for_body,
                "refreshJwt": "refresh_jwt",
                "did": "did:plc:test",
                "handle": "alice.example.com",
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let result = authenticate_source_password(
            &pds_client,
            &server.base_url(),
            "did:plc:test",
            "alice.example.com",
            "hunter2",
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "createSession 200 must build a Bearer client"
        );
    }

    /// A 200 whose `did` differs from the expected DID must be refused (wrong-account guard).
    #[tokio::test]
    async fn test_authenticate_source_password_did_mismatch() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;

        let server = MockServer::start();
        let access_jwt = future_exp_jwt();
        let access_for_body = access_jwt.clone();
        server.mock(move |when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createSession");
            then.status(200).json_body(serde_json::json!({
                "accessJwt": access_for_body,
                "refreshJwt": "refresh_jwt",
                "did": "did:plc:someone-else",
                "handle": "mallory.example.com",
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let result = authenticate_source_password(
            &pds_client,
            &server.base_url(),
            "did:plc:test",
            "alice.example.com",
            "hunter2",
            None,
        )
        .await;
        assert!(
            matches!(result, Err(SourceLoginError::AccountMismatch)),
            "a session for a different DID must be refused, got: {:?}",
            result.err()
        );
    }

    /// The password must never be sent to a non-HTTPS, non-loopback PDS — refused before any
    /// network call, so no mock server is needed.
    #[tokio::test]
    async fn test_authenticate_source_password_rejects_insecure_url() {
        crate::keychain::clear_for_test();
        let pds_client = crate::pds_client::PdsClient::new();
        let result = authenticate_source_password(
            &pds_client,
            "http://pds.example.com",
            "did:plc:test",
            "alice.example.com",
            "hunter2",
            None,
        )
        .await;
        assert!(
            matches!(result, Err(SourceLoginError::InsecureSourceUrl)),
            "a non-HTTPS PDS URL must be refused, got: {:?}",
            result.err()
        );
    }

    /// A 401 `createSession` (wrong password) surfaces as SourceAuthFailed, never NetworkError.
    #[tokio::test]
    async fn test_authenticate_source_password_wrong_password() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createSession");
            then.status(401).json_body(serde_json::json!({
                "error": "AuthenticationRequired",
                "message": "Invalid identifier or password"
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let result = authenticate_source_password(
            &pds_client,
            &server.base_url(),
            "did:plc:test",
            "alice.example.com",
            "wrong",
            None,
        )
        .await;
        assert!(
            matches!(result, Err(SourceLoginError::SourceAuthFailed { .. })),
            "a 401 must surface as SourceAuthFailed, got: {:?}",
            result.err()
        );
    }

    /// An email-2FA account answers a token-less attempt with `AuthFactorTokenRequired`, which must
    /// surface as `TwoFactorRequired` (prompt for a code), NOT `SourceAuthFailed` (wrong password).
    #[tokio::test]
    async fn test_authenticate_source_password_two_factor_required() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createSession");
            then.status(401).json_body(serde_json::json!({
                "error": "AuthFactorTokenRequired",
                "message": "A sign in code has been sent to your email address"
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let result = authenticate_source_password(
            &pds_client,
            &server.base_url(),
            "did:plc:test",
            "alice.example.com",
            "correct-password",
            None,
        )
        .await;
        assert!(
            matches!(result, Err(SourceLoginError::TwoFactorRequired)),
            "AuthFactorTokenRequired must surface as TwoFactorRequired, got: {:?}",
            result.err()
        );
    }
}
