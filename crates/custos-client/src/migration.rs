// pattern: Imperative Shell

//! Migration XRPC helpers: typed methods over an authenticated [`OAuthClient`] for the
//! outbound-migration set (service auth, destination account creation, repo/blob import,
//! preferences, account-status/lifecycle). No orchestration here — sequencing multi-step
//! migration lives in the caller (e.g. obsign-core's `migration_orchestrator`).

use serde::{Deserialize, Serialize};

use crate::error::{xrpc_json, xrpc_ok, PdsClientError};
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

    xrpc_json("getServiceAuth", resp, client.observer()).await
}

/// Create account in migration mode on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.createAccount` with the request body.
/// The `client` should be a Bearer client carrying a service-auth JWT from the source PDS.
/// A 409 response maps to `PdsClientError::DidAlreadyExists`.
pub async fn create_account_migration(
    client: &OAuthClient,
    req: &CreateAccountMigrationRequest,
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

    xrpc_json("createAccount", resp, client.observer()).await
}

/// Import a CAR into the destination PDS repository.
///
/// Calls `POST /xrpc/com.atproto.repo.importRepo` with raw CAR bytes.
/// Content-Type is `application/vnd.ipld.car`.
pub async fn import_repo(client: &OAuthClient, car: Vec<u8>) -> Result<(), PdsClientError> {
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

    xrpc_ok("importRepo", resp, client.observer())
        .await
        .map(|_| ())
}

/// Upload a blob to the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.repo.uploadBlob` with raw blob bytes.
/// Content-Type is set to the provided MIME type.
pub async fn upload_blob(
    client: &OAuthClient,
    mime: &str,
    bytes: Vec<u8>,
) -> Result<UploadBlobResponse, PdsClientError> {
    let resp = client
        .post_bytes("/xrpc/com.atproto.repo.uploadBlob", mime, bytes)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("upload_blob failed: {}", e),
        })?;

    xrpc_json("uploadBlob", resp, client.observer()).await
}

/// List missing blobs on the destination PDS (one page).
///
/// Calls `GET /xrpc/com.atproto.repo.listMissingBlobs?cursor=...` (cursor is optional).
pub async fn list_missing_blobs(
    client: &OAuthClient,
    cursor: Option<&str>,
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

    xrpc_json("listMissingBlobs", resp, client.observer()).await
}

/// Get the user's preferences.
///
/// Calls `GET /xrpc/app.bsky.actor.getPreferences`.
/// Returns the full response object (with `preferences` key).
pub async fn get_preferences(client: &OAuthClient) -> Result<serde_json::Value, PdsClientError> {
    let resp = client
        .get("/xrpc/app.bsky.actor.getPreferences")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("get_preferences failed: {}", e),
        })?;

    xrpc_json("getPreferences", resp, client.observer()).await
}

/// Put the user's preferences.
///
/// Calls `POST /xrpc/app.bsky.actor.putPreferences` with the preferences object
/// (the same object returned by `get_preferences`).
pub async fn put_preferences(
    client: &OAuthClient,
    prefs: &serde_json::Value,
) -> Result<(), PdsClientError> {
    let resp = client
        .post("/xrpc/app.bsky.actor.putPreferences", prefs)
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("put_preferences failed: {}", e),
        })?;

    xrpc_ok("putPreferences", resp, client.observer())
        .await
        .map(|_| ())
}

/// Check the account status on the destination PDS.
///
/// Calls `GET /xrpc/com.atproto.server.checkAccountStatus`.
pub async fn check_account_status(client: &OAuthClient) -> Result<AccountStatus, PdsClientError> {
    let resp = client
        .get("/xrpc/com.atproto.server.checkAccountStatus")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("check_account_status failed: {}", e),
        })?;

    xrpc_json("checkAccountStatus", resp, client.observer()).await
}

/// Activate the account on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.activateAccount` with NO body and no
/// `Content-Type` — it is a no-input procedure. A spec-strict PDS rejects any body at all
/// (Custos itself now enforces this via its `NoInputBody` guard, having historically been
/// laxer here too); `post_no_body` satisfies that.
pub async fn activate_account(client: &OAuthClient) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.server.activateAccount")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("activate_account failed: {}", e),
        })?;

    xrpc_ok("activateAccount", resp, client.observer())
        .await
        .map(|_| ())
}

/// Deactivate the account on the destination PDS.
///
/// Calls `POST /xrpc/com.atproto.server.deactivateAccount` with optional deleteAfter (RFC 3339).
pub async fn deactivate_account(
    client: &OAuthClient,
    delete_after: Option<&str>,
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

    xrpc_ok("deactivateAccount", resp, client.observer())
        .await
        .map(|_| ())
}

/// Request permanent deletion of the authenticated account: mints and emails a single-use code.
///
/// Calls `POST /xrpc/com.atproto.server.requestAccountDelete` with NO body (a no-input procedure,
/// like `activateAccount`). Full-access session authed. The PDS emails a 1-hour confirmation code
/// to the account address; the code + the account password are then supplied to complete the
/// deletion.
pub async fn request_account_delete(client: &OAuthClient) -> Result<(), PdsClientError> {
    let resp = client
        .post_no_body("/xrpc/com.atproto.server.requestAccountDelete")
        .await
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("request_account_delete failed: {}", e),
        })?;

    xrpc_ok("requestAccountDelete", resp, client.observer())
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bearer_client, bearer_jwt};
    use httpmock::prelude::*;

    /// `createAccount`'s 409 short-circuit is the one branch here that isn't a plain
    /// pass-through to the shared XRPC classification tail — a destination account that
    /// already exists must surface as `DidAlreadyExists`, not the generic `XrpcError` the
    /// atproto envelope would otherwise classify a 409 into.
    #[tokio::test]
    async fn create_account_migration_409_is_did_already_exists() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/xrpc/com.atproto.server.createAccount");
            then.status(409)
                .json_body(serde_json::json!({ "error": "AlreadyExists" }));
        });

        let req = CreateAccountMigrationRequest {
            handle: "alice.example.com".to_string(),
            email: "alice@example.com".to_string(),
            did: "did:plc:abcdefghijklmnopqrstuvwx".to_string(),
            invite_code: None,
        };
        let err = create_account_migration(&bearer_client(&server), &req)
            .await
            .unwrap_err();
        assert!(matches!(err, PdsClientError::DidAlreadyExists));
    }

    /// get_service_auth issues GET with aud and lxm query params and parses token
    #[tokio::test]
    async fn test_get_service_auth_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth")
                .query_param("aud", "did:web:dest.example.com")
                .query_param("lxm", "com.atproto.server.createAccount");
            then.status(200).json_body(serde_json::json!({
                "token": "eyJhbGc..."
            }));
        });

        let jwt = bearer_jwt(9999999999); // Far future expiry
        let test_client = OAuthClient::new_bearer(
            jwt,
            "test_refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_service_auth(
            &test_client,
            "did:web:dest.example.com",
            "com.atproto.server.createAccount",
        )
        .await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.token, "eyJhbGc...");
    }

    /// get_service_auth returns NetworkError on non-2xx status
    #[tokio::test]
    async fn test_get_service_auth_error() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth");
            then.status(401).body("unauthorized");
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_service_auth(
            &test_client,
            "did:web:dest",
            "com.atproto.server.createAccount",
        )
        .await;

        assert!(result.is_err());
        // A 401 is classified as Unauthorized, not a generic NetworkError.
        match result.unwrap_err() {
            PdsClientError::Unauthorized { .. } => {
                // Expected
            }
            e => panic!("Expected Unauthorized, got: {:?}", e),
        }
    }

    /// create_account_migration POSTs camelCase body and parses response
    #[tokio::test]
    async fn test_create_account_migration_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount")
                // The body must be the camelCase {handle,email,did}; a serde-rename regression
                // (e.g. snake_case, or a dropped field) must fail this test.
                .body_includes("\"handle\":\"user.example.com\"")
                .body_includes("\"email\":\"user@example.com\"")
                .body_includes("\"did\":\"did:plc:abc123\"")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "accessJwt": "access...",
                "refreshJwt": "refresh...",
                "handle": "user.example.com",
                "did": "did:plc:abc123"
            }));
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_jwt".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let req = CreateAccountMigrationRequest {
            handle: "user.example.com".to_string(),
            email: "user@example.com".to_string(),
            did: "did:plc:abc123".to_string(),
            invite_code: None,
        };
        let result = create_account_migration(&test_client, &req).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.access_jwt, "access...");
        assert_eq!(resp.refresh_jwt, "refresh...");
        assert_eq!(resp.handle, "user.example.com");
        assert_eq!(resp.did, "did:plc:abc123");
    }

    /// import_repo sends CAR bytes with correct Content-Type and returns Ok on 200
    #[tokio::test]
    async fn test_import_repo_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo")
                .header("content-type", "application/vnd.ipld.car")
                // The exact CAR bytes must reach the server unchanged.
                .body("CAR bytes content")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let car_bytes = b"CAR bytes content".to_vec();
        let result = import_repo(&test_client, car_bytes).await;

        assert!(result.is_ok());
    }

    /// upload_blob sends raw bytes with provided MIME type and parses blob response
    #[tokio::test]
    async fn test_upload_blob_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.uploadBlob")
                .header("content-type", "image/jpeg")
                // The exact blob bytes must reach the server unchanged.
                .body("JPEG data")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blob": {
                    "$type": "com.atproto.sync.blob",
                    "mimeType": "image/jpeg",
                    "size": 1234,
                    "ref": { "$link": "bafy123" }
                }
            }));
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let blob_bytes = b"JPEG data".to_vec();
        let result = upload_blob(&test_client, "image/jpeg", blob_bytes).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        // Assert the fields the migration flow actually consumes from the blob ref, not just $type.
        assert_eq!(resp.blob["ref"]["$link"], "bafy123");
        assert_eq!(resp.blob["mimeType"], "image/jpeg");
        assert_eq!(resp.blob["size"], 1234);
    }

    /// list_missing_blobs without cursor issues base path; with cursor includes ?cursor=
    #[tokio::test]
    async fn test_list_missing_blobs_no_cursor() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "bafy1", "recordUri": "at://did/record1" },
                    { "cid": "bafy2", "recordUri": "at://did/record2" }
                ]
            }));
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = list_missing_blobs(&test_client, None).await;

        assert!(result.is_ok());
        let blobs = result.unwrap();
        assert_eq!(blobs.blobs.len(), 2);
        assert_eq!(blobs.blobs[0].cid, "bafy1");
    }

    /// list_missing_blobs with cursor includes it in query params
    #[tokio::test]
    async fn test_list_missing_blobs_with_cursor() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "next_page_token")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "bafy3", "recordUri": "at://did/record3" }
                ],
                "cursor": "another_token"
            }));
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = list_missing_blobs(&test_client, Some("next_page_token")).await;

        assert!(result.is_ok());
        let blobs = result.unwrap();
        assert_eq!(blobs.blobs.len(), 1);
        assert_eq!(blobs.cursor, Some("another_token".to_string()));
    }

    /// get_preferences parses full preferences object
    #[tokio::test]
    async fn test_get_preferences_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "preferences": [
                    { "feed": "pinned", "value": "at://feed1" }
                ]
            }));
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = get_preferences(&test_client).await;

        assert!(result.is_ok());
        let prefs = result.unwrap();
        assert!(prefs["preferences"].is_array());
    }

    /// put_preferences POSTs the preferences object back and treats 200 as success
    #[tokio::test]
    async fn test_put_preferences_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/app.bsky.actor.putPreferences")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let prefs = serde_json::json!({
            "preferences": [
                { "feed": "pinned", "value": "at://feed1" }
            ]
        });
        let result = put_preferences(&test_client, &prefs).await;

        assert!(result.is_ok());
    }

    /// check_account_status parses all fields including storedBlocks
    #[tokio::test]
    async fn test_check_account_status_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200).json_body(serde_json::json!({
                "activated": true,
                "validDid": true,
                "storedBlocks": 12345,
                "indexedRecords": 100,
                "privateStateValues": 5,
                "expectedBlobs": 50,
                "importedBlobs": 48
            }));
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = check_account_status(&test_client).await;

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(status.activated);
        assert!(status.valid_did);
        assert_eq!(status.stored_blocks, 12345);
        assert_eq!(status.indexed_records, 100);
        assert_eq!(status.expected_blobs, 50);
        assert_eq!(status.imported_blobs, 48);
    }

    /// activate_account POSTs a genuinely empty body and treats 200 as success.
    /// The real handler rejects any non-whitespace body with 400, so the empty-body
    /// assertion below is the actual server contract (a `{}` body would be a bug).
    #[tokio::test]
    async fn test_activate_account_success() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount")
                .is_true(|req| req.body_ref().is_empty())
                // No-input procedure: no Content-Type either (the old post_bytes
                // workaround still sent one with zero bytes).
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                })
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = activate_account(&test_client).await;

        assert!(result.is_ok());
    }

    /// deactivate_account without deleteAfter sends {} body
    #[tokio::test]
    async fn test_deactivate_account_no_delete_after() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = deactivate_account(&test_client, None).await;

        assert!(result.is_ok());
    }

    /// deactivate_account with deleteAfter includes it in request body
    #[tokio::test]
    async fn test_deactivate_account_with_delete_after() {
        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount")
                .body_includes("deleteAfter")
                .body_includes("2026-07-08")
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k == "authorization" && v.contains("Bearer"))
                });
            then.status(200);
        });

        let test_client = OAuthClient::new_bearer(
            bearer_jwt(9999999999),
            "refresh_token".to_string(),
            mock_server.base_url(),
        )
        .expect("new_bearer must succeed");
        let result = deactivate_account(&test_client, Some("2026-07-08T00:00:00.000Z")).await;

        assert!(result.is_ok());
    }

    /// Records `record_server` ops, to prove which observer a typed method reports into.
    #[derive(Default)]
    struct RecordingObserver(std::sync::Mutex<Vec<String>>);

    impl crate::error::TransportObserver for RecordingObserver {
        fn record_transport(&self, _op: &str, _url: Option<&str>, _error: &reqwest::Error) {}
        fn record_server(&self, op: &str, _h: Option<&str>, _s: u16, _c: Option<&str>) {
            self.0.lock().unwrap().push(op.to_string());
        }
    }

    /// The typed methods take no observer parameter: a classified failure must land in the
    /// observer the `OAuthClient` was built with.
    #[tokio::test]
    async fn typed_method_records_into_the_clients_own_observer() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus");
            then.status(500)
                .json_body(serde_json::json!({ "error": "InternalServerError" }));
        });
        let observer = std::sync::Arc::new(RecordingObserver::default());
        let client = OAuthClient::new_bearer_with_observer(
            bearer_jwt(9_999_999_999),
            "refresh".to_string(),
            server.base_url(),
            observer.clone(),
        )
        .unwrap();

        check_account_status(&client).await.unwrap_err();

        assert_eq!(*observer.0.lock().unwrap(), vec!["checkAccountStatus"]);
    }
}
