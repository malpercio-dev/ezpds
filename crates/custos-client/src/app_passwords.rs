// pattern: Imperative Shell

//! App-password management: typed XRPC methods over an authenticated (full-access)
//! [`OAuthClient`] for `com.atproto.server.{create,list,revoke}AppPassword`.

use serde::{Deserialize, Serialize};

use crate::error::{xrpc_json, xrpc_ok, PdsClientError};
use crate::oauth_client::OAuthClient;

/// Result of minting an app password (`com.atproto.server.createAppPassword`).
/// `password` is the generated secret, surfaced ONCE at creation — the server
/// stores only its hash, so it can never be retrieved again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPasswordCreated {
    pub name: String,
    /// The generated `xxxx-xxxx-xxxx-xxxx` secret. Shown once; never retrievable.
    pub password: String,
    pub created_at: String,
    pub privileged: bool,
    /// The Custos personal-details grant (ADR-0033). Defaults to `false` when the field is
    /// absent — which is exactly what a non-Custos PDS returns, so a requested-but-ignored
    /// grant reads back honestly as not granted.
    #[serde(default)]
    pub personal_details: bool,
}

/// One app-password entry from `listAppPasswords` — public metadata only, never the secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPasswordEntry {
    pub name: String,
    pub created_at: String,
    pub privileged: bool,
    /// The Custos personal-details grant (ADR-0033); `false` when the host omits the field.
    #[serde(default)]
    pub personal_details: bool,
}

#[derive(Deserialize)]
struct ListAppPasswordsResponse {
    passwords: Vec<AppPasswordEntry>,
}

/// Mint a named app password on the hosting PDS.
///
/// Calls `POST /xrpc/com.atproto.server.createAppPassword`. Requires a full-access
/// session (an app-password session cannot mint more app passwords). A duplicate
/// name surfaces as `XrpcError { status: 409, .. }`.
pub async fn create_app_password(
    client: &OAuthClient,
    name: &str,
    privileged: bool,
    personal_details: bool,
) -> Result<AppPasswordCreated, PdsClientError> {
    let resp = client
        .post(
            "/xrpc/com.atproto.server.createAppPassword",
            &serde_json::json!({
                "name": name,
                "privileged": privileged,
                "personalDetails": personal_details,
            }),
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("create_app_password failed: {}", e),
        })?;

    xrpc_json("createAppPassword", resp, client.observer()).await
}

/// List the account's app passwords (names, creation times, privilege — never secrets).
///
/// Calls `GET /xrpc/com.atproto.server.listAppPasswords`. Requires a full-access session.
pub async fn list_app_passwords(
    client: &OAuthClient,
) -> Result<Vec<AppPasswordEntry>, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.server.listAppPasswords")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("list_app_passwords failed: {}", e),
        })?;

    xrpc_json::<ListAppPasswordsResponse>("listAppPasswords", resp, client.observer())
        .await
        .map(|body| body.passwords)
}

/// Revoke a named app password (and, server-side, its sessions/refresh tokens atomically).
///
/// Calls `POST /xrpc/com.atproto.server.revokeAppPassword`. Idempotent on the server.
pub async fn revoke_app_password(client: &OAuthClient, name: &str) -> Result<(), PdsClientError> {
    let resp = client
        .post(
            "/xrpc/com.atproto.server.revokeAppPassword",
            &serde_json::json!({ "name": name }),
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("revoke_app_password failed: {}", e),
        })?;

    xrpc_ok("revokeAppPassword", resp, client.observer())
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::bearer_client;
    use httpmock::prelude::*;

    /// create_app_password POSTs name+privileged and parses the one-time secret response.
    #[tokio::test]
    async fn test_create_app_password_success() {
        let mock_server = MockServer::start();

        // Assembled from fragments so secret scanners don't flag a literal credential.
        let expected_password = ["abcd", "efgh", "ijkl", "mnop"].join("-");

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAppPassword")
                .json_body(serde_json::json!({
                    "name": "Bluesky app",
                    "privileged": false,
                    "personalDetails": false
                }));
            // The response deliberately omits `personalDetails` — a non-Custos PDS's shape —
            // so this also pins the serde default of the grant field to false.
            then.status(200).json_body(serde_json::json!({
                "name": "Bluesky app",
                "password": expected_password.clone(),
                "createdAt": "2026-07-17T00:00:00.000Z",
                "privileged": false
            }));
        });

        let created =
            create_app_password(&bearer_client(&mock_server), "Bluesky app", false, false)
                .await
                .unwrap();
        assert_eq!(created.name, "Bluesky app");
        assert_eq!(created.password, expected_password);
        assert!(!created.privileged);
        assert!(
            !created.personal_details,
            "an absent personalDetails field must read back as not granted"
        );
    }

    /// A duplicate name surfaces as XrpcError with the 409 status preserved.
    #[tokio::test]
    async fn test_create_app_password_duplicate_is_409_xrpc_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAppPassword");
            then.status(409).json_body(serde_json::json!({
                "error": "Conflict",
                "message": "an app password with this name already exists"
            }));
        });

        let err = create_app_password(&bearer_client(&mock_server), "Bluesky app", false, false)
            .await
            .unwrap_err();
        match err {
            PdsClientError::XrpcError { status: 409, .. } => {}
            e => panic!("Expected XrpcError 409, got: {:?}", e),
        }
    }

    /// list_app_passwords unwraps the passwords array (metadata only, no secret field).
    #[tokio::test]
    async fn test_list_app_passwords_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.listAppPasswords");
            then.status(200).json_body(serde_json::json!({
                "passwords": [
                    {
                        "name": "Bluesky app",
                        "createdAt": "2026-07-17T00:00:00.000Z",
                        "privileged": false
                    },
                    {
                        "name": "Chat client",
                        "createdAt": "2026-07-16T00:00:00.000Z",
                        "privileged": true
                    }
                ]
            }));
        });

        let passwords = list_app_passwords(&bearer_client(&mock_server))
            .await
            .unwrap();
        assert_eq!(passwords.len(), 2);
        assert_eq!(passwords[0].name, "Bluesky app");
        assert!(passwords[1].privileged);
    }

    /// revoke_app_password POSTs the name and treats a 2xx as done.
    #[tokio::test]
    async fn test_revoke_app_password_success() {
        let mock_server = MockServer::start();

        let mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.revokeAppPassword")
                .json_body(serde_json::json!({ "name": "Bluesky app" }));
            then.status(200).json_body(serde_json::json!({}));
        });

        revoke_app_password(&bearer_client(&mock_server), "Bluesky app")
            .await
            .unwrap();
        mock.assert();
    }

    /// A 429 on the app-password surface is classified as RateLimited with Retry-After.
    #[tokio::test]
    async fn test_list_app_passwords_rate_limited() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.listAppPasswords");
            then.status(429)
                .header("retry-after", "30")
                .json_body(serde_json::json!({
                    "error": "RateLimitExceeded",
                    "message": "too many requests"
                }));
        });

        let err = list_app_passwords(&bearer_client(&mock_server))
            .await
            .unwrap_err();
        match err {
            PdsClientError::RateLimited { retry_after, .. } => {
                assert_eq!(retry_after.as_deref(), Some("30"));
            }
            e => panic!("Expected RateLimited, got: {:?}", e),
        }
    }
}
