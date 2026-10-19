// pattern: Imperative Shell

//! App-password management: typed XRPC methods over an authenticated (full-access)
//! [`OAuthClient`] for `com.atproto.server.{create,list,revoke}AppPassword`.

use serde::{Deserialize, Serialize};

use crate::error::{xrpc_json, xrpc_ok, PdsClientError, TransportObserver};
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
    observer: &dyn TransportObserver,
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

    xrpc_json("createAppPassword", resp, observer).await
}

/// List the account's app passwords (names, creation times, privilege — never secrets).
///
/// Calls `GET /xrpc/com.atproto.server.listAppPasswords`. Requires a full-access session.
pub async fn list_app_passwords(
    client: &OAuthClient,
    observer: &dyn TransportObserver,
) -> Result<Vec<AppPasswordEntry>, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.server.listAppPasswords")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("list_app_passwords failed: {}", e),
        })?;

    xrpc_json::<ListAppPasswordsResponse>("listAppPasswords", resp, observer)
        .await
        .map(|body| body.passwords)
}

/// Revoke a named app password (and, server-side, its sessions/refresh tokens atomically).
///
/// Calls `POST /xrpc/com.atproto.server.revokeAppPassword`. Idempotent on the server.
pub async fn revoke_app_password(
    client: &OAuthClient,
    name: &str,
    observer: &dyn TransportObserver,
) -> Result<(), PdsClientError> {
    let resp = client
        .post(
            "/xrpc/com.atproto.server.revokeAppPassword",
            &serde_json::json!({ "name": name }),
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("revoke_app_password failed: {}", e),
        })?;

    xrpc_ok("revokeAppPassword", resp, observer)
        .await
        .map(|_| ())
}
