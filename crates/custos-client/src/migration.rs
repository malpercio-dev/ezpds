// pattern: Functional Core

//! Migration XRPC helpers: typed methods over an authenticated [`OAuthClient`] for the
//! outbound-migration set (service auth, destination account creation, repo/blob import,
//! preferences, account-status/lifecycle). No orchestration here — sequencing multi-step
//! migration lives in the caller (e.g. identity-wallet's `migration_orchestrator.rs`).

use serde::{Deserialize, Serialize};

use crate::error::{xrpc_json, xrpc_ok, PdsClientError, TransportObserver};
use crate::oauth_client::OAuthClient;

/// Service auth token from getServiceAuth.
///
/// Returned from `GET /xrpc/com.atproto.server.getServiceAuth`.
#[derive(Debug, Deserialize)]
pub struct ServiceAuthToken {
    pub token: String,
}

/// Request body for createAccount migration.
///
/// Serializes to frontend with `#[serde(rename_all = "camelCase")]`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountMigrationRequest {
    pub handle: String,
    pub email: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_code: Option<String>,
}

/// Response from createAccount migration.
///
/// Returned from `POST /xrpc/com.atproto.server.createAccount`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
    #[serde(default)]
    pub did_doc: Option<serde_json::Value>,
}

/// Missing blob entry from listMissingBlobs.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingBlob {
    pub cid: String,
    pub record_uri: String,
}

/// Response from listMissingBlobs.
///
/// Returned from `GET /xrpc/com.atproto.repo.listMissingBlobs`.
#[derive(Debug, Deserialize)]
pub struct MissingBlobs {
    pub blobs: Vec<MissingBlob>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Account status from checkAccountStatus.
///
/// Returned from `GET /xrpc/com.atproto.server.checkAccountStatus`.
/// Also returned to the frontend via `verify_import` command, so it must derive Serialize.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    pub activated: bool,
    pub valid_did: bool,
    #[serde(default)]
    pub repo_commit: Option<String>,
    #[serde(default)]
    pub repo_rev: Option<String>,
    pub stored_blocks: i64,
    pub indexed_records: u64,
    pub private_state_values: u64,
    pub expected_blobs: u64,
    pub imported_blobs: u64,
}

/// Response from uploadBlob.
///
/// Returned from `POST /xrpc/com.atproto.repo.uploadBlob`.
#[derive(Debug, Deserialize)]
pub struct UploadBlobResponse {
    pub blob: serde_json::Value,
}

/// Get service auth token for migration from the SOURCE PDS.
///
/// Calls `GET /xrpc/com.atproto.server.getServiceAuth?aud={dest_did}&lxm={lxm}`.
/// For migration, `aud` is the destination server DID and `lxm` is typically
/// "com.atproto.server.createAccount".
pub async fn get_service_auth(
    client: &OAuthClient,
    aud: &str,
    lxm: &str,
    observer: &dyn TransportObserver,
) -> Result<ServiceAuthToken, PdsClientError> {
    let path = format!(
        "/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}",
        urlencoding::encode(aud),
        urlencoding::encode(lxm),
    );

    let resp = client
        .get(&path)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_service_auth failed: {}", e),
        })?;

    xrpc_json("getServiceAuth", resp, observer).await
}

/// Create account in migration mode on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.createAccount` with the request body.
/// The `client` should be a Bearer client carrying a service-auth JWT from the source PDS.
/// A 409 response maps to `PdsClientError::DidAlreadyExists`.
pub async fn create_account_migration(
    client: &OAuthClient,
    req: &CreateAccountMigrationRequest,
    observer: &dyn TransportObserver,
) -> Result<CreateAccountResponse, PdsClientError> {
    let resp = client
        .post("/xrpc/com.atproto.server.createAccount", req)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("create_account_migration failed: {}", e),
        })?;

    if resp.status().as_u16() == 409 {
        return Err(PdsClientError::DidAlreadyExists);
    }

    xrpc_json("createAccount", resp, observer).await
}

/// Import a CAR into the destination PDS repository.
///
/// Calls `POST /xrpc/com.atproto.repo.importRepo` with raw CAR bytes.
/// Content-Type is `application/vnd.ipld.car`.
pub async fn import_repo(
    client: &OAuthClient,
    car: Vec<u8>,
    observer: &dyn TransportObserver,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_bytes(
            "/xrpc/com.atproto.repo.importRepo",
            "application/vnd.ipld.car",
            car,
        )
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("import_repo failed: {}", e),
        })?;

    xrpc_ok("importRepo", resp, observer).await.map(|_| ())
}

/// Upload a blob to the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.repo.uploadBlob` with raw blob bytes.
/// Content-Type is set to the provided MIME type.
pub async fn upload_blob(
    client: &OAuthClient,
    mime: &str,
    bytes: Vec<u8>,
    observer: &dyn TransportObserver,
) -> Result<UploadBlobResponse, PdsClientError> {
    let resp = client
        .post_bytes("/xrpc/com.atproto.repo.uploadBlob", mime, bytes)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("upload_blob failed: {}", e),
        })?;

    xrpc_json("uploadBlob", resp, observer).await
}

/// List missing blobs on the destination PDS (one page).
///
/// Calls `GET /xrpc/com.atproto.repo.listMissingBlobs?cursor=...` (cursor is optional).
pub async fn list_missing_blobs(
    client: &OAuthClient,
    cursor: Option<&str>,
    observer: &dyn TransportObserver,
) -> Result<MissingBlobs, PdsClientError> {
    let path = if let Some(cur) = cursor {
        format!(
            "/xrpc/com.atproto.repo.listMissingBlobs?cursor={}",
            urlencoding::encode(cur)
        )
    } else {
        "/xrpc/com.atproto.repo.listMissingBlobs".to_string()
    };

    let resp = client
        .get(&path)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("list_missing_blobs failed: {}", e),
        })?;

    xrpc_json("listMissingBlobs", resp, observer).await
}

/// Get the user's preferences.
///
/// Calls `GET /xrpc/app.bsky.actor.getPreferences`.
/// Returns the full response object (with `preferences` key).
pub async fn get_preferences(
    client: &OAuthClient,
    observer: &dyn TransportObserver,
) -> Result<serde_json::Value, PdsClientError> {
    let resp = client
        .get("/xrpc/app.bsky.actor.getPreferences")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_preferences failed: {}", e),
        })?;

    xrpc_json("getPreferences", resp, observer).await
}

/// Put the user's preferences.
///
/// Calls `POST /xrpc/app.bsky.actor.putPreferences` with the preferences object
/// (the same object returned by `get_preferences`).
pub async fn put_preferences(
    client: &OAuthClient,
    prefs: &serde_json::Value,
    observer: &dyn TransportObserver,
) -> Result<(), PdsClientError> {
    let resp = client
        .post("/xrpc/app.bsky.actor.putPreferences", prefs)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("put_preferences failed: {}", e),
        })?;

    xrpc_ok("putPreferences", resp, observer).await.map(|_| ())
}

/// Check the account status on the destination PDS.
///
/// Calls `GET /xrpc/com.atproto.server.checkAccountStatus`.
pub async fn check_account_status(
    client: &OAuthClient,
    observer: &dyn TransportObserver,
) -> Result<AccountStatus, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.server.checkAccountStatus")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("check_account_status failed: {}", e),
        })?;

    xrpc_json("checkAccountStatus", resp, observer).await
}

/// Activate the account on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.activateAccount` with NO body and no
/// `Content-Type` — it is a no-input procedure. A spec-strict PDS rejects any body at all;
/// `post_no_body` satisfies that.
pub async fn activate_account(
    client: &OAuthClient,
    observer: &dyn TransportObserver,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.server.activateAccount")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("activate_account failed: {}", e),
        })?;

    xrpc_ok("activateAccount", resp, observer).await.map(|_| ())
}

/// Deactivate the account on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.deactivateAccount` with optional deleteAfter (RFC 3339).
pub async fn deactivate_account(
    client: &OAuthClient,
    delete_after: Option<&str>,
    observer: &dyn TransportObserver,
) -> Result<(), PdsClientError> {
    let body = match delete_after {
        Some(t) => serde_json::json!({ "deleteAfter": t }),
        None => serde_json::json!({}),
    };

    let resp = client
        .post("/xrpc/com.atproto.server.deactivateAccount", &body)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("deactivate_account failed: {}", e),
        })?;

    xrpc_ok("deactivateAccount", resp, observer)
        .await
        .map(|_| ())
}

/// Request permanent deletion of the authenticated account: mints and emails a single-use code.
///
/// Calls `POST /xrpc/com.atproto.server.requestAccountDelete` with NO body (a no-input procedure,
/// like `activateAccount`). Full-access session authed. The PDS emails a 1-hour confirmation code
/// to the account address; the code + the account password are then supplied to complete the
/// deletion.
pub async fn request_account_delete(
    client: &OAuthClient,
    observer: &dyn TransportObserver,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.server.requestAccountDelete")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("request_account_delete failed: {}", e),
        })?;

    xrpc_ok("requestAccountDelete", resp, observer)
        .await
        .map(|_| ())
}
