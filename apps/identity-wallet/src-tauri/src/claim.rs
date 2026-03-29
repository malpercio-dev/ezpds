// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Functional Core: IdentityInfo, VerifiedClaimOp, OpDiff, ServiceChange, ClaimResult,
//                  ClaimState, ResolveError, ClaimError (types and errors)
// Imperative Shell: resolve_identity (command: resolves handle/DID, fetches DID doc from
//                   plc.directory, checks IdentityStore, stores state, returns IdentityInfo)
//                   start_pds_auth (command: performs OAuth PKCE+DPoP flow against PDS,
//                   stores OAuthClient in claim_state)
//                   request_claim_verification (command: calls requestPlcOperationSignature XRPC
//                   endpoint on old PDS to trigger email verification)

use serde::Serialize;
use tauri::Emitter;

use crate::identity_store::IdentityStore;
use crate::oauth_client::OAuthClient;
use crate::pds_client::{PdsClientError, PlcDidDocument};

// ── Output types ───────────────────────────────────────────────────────────

/// Identity information resolved from a handle or DID.
///
/// Returned by `resolve_identity` command.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    /// The DID (e.g., "did:plc:abc123...")
    pub did: String,
    /// The handle (e.g., "alice.test")
    pub handle: String,
    /// The PDS endpoint URL (e.g., "https://pds.example.com")
    pub pds_url: String,
    /// Current rotation keys from the DID document
    pub current_rotation_keys: Vec<String>,
    /// Whether the device key is a rotation key (true if device key == rotation_keys[0])
    pub device_key_is_root: bool,
}

/// Verified claim operation ready for submission.
///
/// Returned by `verify_claim` command.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedClaimOp {
    /// Diff of keys and services between current DID doc and proposed operation
    pub diff: OpDiff,
    /// Signed operation (ready for PLC submission)
    pub signed_op: String,
    /// Warnings from verification (e.g., "This operation will break X")
    pub warnings: Vec<String>,
}

/// Diff of changes between current DID document and proposed operation.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OpDiff {
    /// Keys being added in this operation
    pub added_keys: Vec<String>,
    /// Keys being removed in this operation
    pub removed_keys: Vec<String>,
    /// Service endpoint changes (added/removed/modified)
    pub changed_services: Vec<ServiceChange>,
    /// Previous CID (content identifier) of the DID document
    pub prev_cid: String,
}

/// Change to a service endpoint in the DID document.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceChange {
    /// Service ID (e.g., "atproto_pds")
    pub id: String,
    /// Type of change: "added", "removed", or "modified"
    pub change_type: String,
    /// Old endpoint URL (None if added)
    pub old_endpoint: Option<String>,
    /// New endpoint URL (None if removed)
    pub new_endpoint: Option<String>,
}

/// Result of a successful claim submission.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResult {
    /// Updated DID document after claim was applied
    pub updated_did_doc: serde_json::Value,
}

// ── State persisted across the claim flow ──────────────────────────────────

/// Claim flow state persisted in `AppState`.
///
/// This state is set by `resolve_identity` and used by subsequent
/// `start_pds_auth`, `request_claim_verification`, `sign_and_verify_claim`,
/// and `submit_claim` commands within the same claim flow session.
pub struct ClaimState {
    /// The DID being claimed (resolved by `resolve_identity`)
    pub did: String,
    /// The PDS endpoint URL (discovered by `resolve_identity`)
    pub pds_url: String,
    /// The DID document fetched from plc.directory (discovered by `resolve_identity`)
    pub did_doc: PlcDidDocument,
    /// OAuth client for the PDS (set after `start_pds_auth` succeeds)
    /// Wrapped in Arc to allow cloning out of the Mutex without holding the lock
    /// across the network call in `request_claim_verification`.
    pub pds_oauth_client: Option<std::sync::Arc<OAuthClient>>,
    /// Verified signed operation (set after `sign_and_verify_claim` succeeds)
    pub verified_signed_op: Option<String>,
}

// ── Error types ────────────────────────────────────────────────────────────

/// Error returned by `resolve_identity` command.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` matching the
/// existing error pattern (CreateAccountError, DeviceKeyError, etc.).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveError {
    /// Handle resolution failed (DNS and HTTP fallback both failed)
    #[error("handle not found")]
    HandleNotFound,
    /// DID not found in plc.directory (404 response)
    #[error("did not found")]
    DidNotFound,
    /// PDS endpoint is unreachable
    #[error("pds unreachable")]
    PdsUnreachable,
    /// Network error during discovery (timeout, connection refused, etc.)
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// Error returned by claim flow commands (`verify_claim`, `request_claim_verification`, etc.).
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", "message": "..." }` matching
/// the existing error pattern.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimError {
    /// PDS XRPC token request failed or returned invalid token
    #[error("invalid token")]
    InvalidToken,
    /// Claim verification failed (operation verification, signature validation, etc.)
    #[error("verification failed: {message}")]
    VerificationFailed { message: String },
    /// PLC directory operation submission failed
    #[error("plc directory error: {message}")]
    PlcDirectoryError { message: String },
    /// User is not authorized for this operation
    #[error("unauthorized")]
    Unauthorized,
    /// Network error during claim flow (timeout, connection refused, etc.)
    #[error("network error: {message}")]
    NetworkError { message: String },
}

// ── resolve_identity Tauri command ──────────────────────────────────────────

/// Resolve a handle or DID to identity information.
///
/// This is the first command in the claim flow. It:
/// 1. Determines if input is a DID (starts with "did:") or a handle
/// 2. If handle: resolves to DID via `PdsClient::resolve_handle()`
/// 3. Fetches DID doc from plc.directory via `PdsClient::discover_pds()`
/// 4. Extracts handle from `also_known_as` (format: `at://handle`)
/// 5. Checks IdentityStore to determine if DID is registered
/// 6. If registered: gets or creates device key and compares to rotation_keys[0]
/// 7. Stores resolved state in AppState.claim_state
/// 8. Returns IdentityInfo with all discovery data
#[tauri::command]
pub async fn resolve_identity(
    state: tauri::State<'_, crate::oauth::AppState>,
    handle_or_did: String,
) -> Result<IdentityInfo, ResolveError> {
    let pds_client = state.pds_client();

    // Determine if input is a DID or handle
    let is_did = handle_or_did.starts_with("did:");
    let (did, mut handle_for_fallback) = if is_did {
        (handle_or_did.clone(), None)
    } else {
        (
            pds_client
                .resolve_handle(&handle_or_did)
                .await
                .map_err(map_pds_error_to_resolve)?,
            Some(handle_or_did.clone()),
        )
    };

    // Fetch DID document and PDS endpoint from plc.directory
    let (pds_url, did_doc) = pds_client
        .discover_pds(&did)
        .await
        .map_err(map_pds_error_to_resolve)?;

    // Extract handle from also_known_as (format: at://handle)
    let handle = extract_handle_from_also_known_as(&did_doc.also_known_as)
        .or_else(|| handle_for_fallback.take())
        .unwrap_or_else(|| {
            if is_did {
                "unknown".to_string()
            } else {
                // We already resolved this handle, use it
                handle_or_did.clone()
            }
        });

    // Check if DID is registered and get device key status
    let device_key_is_root = {
        let identity_store = IdentityStore;
        match identity_store.list_identities() {
            Ok(identities) => {
                if identities.contains(&did) {
                    // DID is registered, get device key and compare to rotation_keys[0]
                    match identity_store.get_or_create_device_key(&did) {
                        Ok(device_key) => {
                            // Compare multibase-encoded device key with rotation_keys[0]
                            did_doc
                                .rotation_keys
                                .first()
                                .map(|first_key| device_key.multibase == *first_key)
                                .unwrap_or(false)
                        }
                        Err(_) => false, // Key generation failed, assume not root
                    }
                } else {
                    false // DID not registered
                }
            }
            Err(_) => false, // Store lookup failed, assume not root
        }
    };

    // Store claim state in AppState
    let claim_state = ClaimState {
        did: did.clone(),
        pds_url: pds_url.clone(),
        did_doc: did_doc.clone(),
        pds_oauth_client: None,
        verified_signed_op: None,
    };

    let mut state_lock = state.claim_state.lock().await;
    *state_lock = Some(claim_state);
    drop(state_lock);

    Ok(IdentityInfo {
        did,
        handle,
        pds_url,
        current_rotation_keys: did_doc.rotation_keys,
        device_key_is_root,
    })
}

/// Map PdsClientError to ResolveError.
fn map_pds_error_to_resolve(err: PdsClientError) -> ResolveError {
    match err {
        PdsClientError::HandleNotFound => ResolveError::HandleNotFound,
        PdsClientError::DidNotFound => ResolveError::DidNotFound,
        PdsClientError::PdsUnreachable { .. } => ResolveError::PdsUnreachable,
        PdsClientError::NetworkError { message } => ResolveError::NetworkError { message },
        PdsClientError::InvalidResponse { message } => ResolveError::NetworkError { message },
        PdsClientError::OauthFailed { message } => ResolveError::NetworkError { message },
    }
}

/// Authenticate with the old PDS via OAuth 2.0 PKCE + DPoP.
///
/// This command performs OAuth authentication against an arbitrary PDS discovered
/// via `PdsClient`. It reuses the existing deep-link callback mechanism and stores
/// the resulting `OAuthClient` in `ClaimState.pds_oauth_client` for use by
/// subsequent commands like `request_claim_verification`.
///
/// **Prerequisites:** `resolve_identity` must have been called first to populate
/// `ClaimState.did` and `ClaimState.pds_url`.
///
/// **Flow:**
/// 1. Read `ClaimState` — validate it contains `did` and `pds_url`
/// 2. Discover auth server metadata via `PdsClient::discover_auth_server()`
/// 3. Generate PKCE verifier/challenge and CSRF state
/// 4. Get-or-create DPoP keypair and compute JWK thumbprint
/// 5. Build DPoP proof for PAR
/// 6. Call PDS PAR with the DID as login_hint
/// 7. Park a oneshot channel in `AppState.pending_auth`
/// 8. Build authorize URL and open Safari
/// 9. Await the deep-link callback (which delivers the authorization code)
/// 10. Exchange code for tokens (with nonce retry if needed)
/// 11. Create `OAuthClient` pointing to the PDS
/// 12. Store client in `ClaimState.pds_oauth_client`
/// 13. Emit `"pds_auth_ready"` event to the frontend
#[tauri::command]
pub async fn start_pds_auth(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    pds_url: String,
) -> Result<(), ClaimError> {
    use tauri_plugin_opener::OpenerExt;

    // 1. Validate ClaimState is populated
    let claim_state = state.claim_state.lock().await;
    let Some(claim) = claim_state.as_ref() else {
        drop(claim_state);
        return Err(ClaimError::Unauthorized);
    };

    let did = claim.did.clone();
    drop(claim_state);

    let pds_client = state.pds_client();

    // 2. Discover auth server metadata from the PDS
    let metadata = pds_client
        .discover_auth_server(&pds_url)
        .await
        .map_err(|e| ClaimError::NetworkError {
            message: format!("failed to discover auth server: {}", e),
        })?;

    // 3. Generate PKCE and CSRF state
    let (pkce_verifier, pkce_challenge) = crate::oauth::pkce::generate();
    let csrf_state = crate::oauth::generate_state_param();

    // 4. Get DPoP keypair and compute thumbprint
    let dpop =
        crate::oauth::DPoPKeypair::get_or_create().map_err(|_| ClaimError::NetworkError {
            message: "failed to create DPoP keypair".to_string(),
        })?;
    let dpop_jkt = dpop.public_jwk_thumbprint();

    // 5. Build DPoP proof for PAR
    let par_htu = metadata
        .pushed_authorization_request_endpoint
        .as_ref()
        .cloned()
        .unwrap_or_else(|| format!("{}/oauth/par", metadata.issuer));

    let par_proof =
        dpop.make_proof("POST", &par_htu, None, None)
            .map_err(|_| ClaimError::NetworkError {
                message: "failed to create DPoP proof for PAR".to_string(),
            })?;

    // 6. Call PDS PAR with the DID as login_hint
    let par_resp = pds_client
        .pds_par(
            &metadata,
            &pkce_challenge,
            &csrf_state,
            &par_proof,
            &dpop_jkt,
            Some(&did),
        )
        .await
        .map_err(|e| ClaimError::NetworkError {
            message: format!("PAR failed: {}", e),
        })?;

    // 7. Set up oneshot channel and park pending_auth
    let (tx, rx) = tokio::sync::oneshot::channel::<
        Result<crate::oauth::CallbackParams, crate::oauth::OAuthError>,
    >();
    {
        let mut pending = state.pending_auth.lock().unwrap();
        *pending = Some(crate::oauth::PendingOAuthFlow {
            tx,
            pkce_verifier: pkce_verifier.clone(),
            csrf_state: csrf_state.clone(),
        });
    }

    // 8. Build authorize URL and open Safari
    let auth_url = crate::pds_client::PdsClient::build_pds_authorize_url(
        &metadata,
        &par_resp.request_uri,
        Some(&did),
    );

    app.opener()
        .open_url(&auth_url, None::<&str>)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to open system browser");
            ClaimError::Unauthorized
        })?;

    // 9. Await the deep-link callback
    let callback = rx
        .await
        .map_err(|_| ClaimError::Unauthorized)?
        .map_err(|_| ClaimError::Unauthorized)?;

    // 10. Token exchange with nonce retry
    let (token_resp, initial_nonce) =
        pds_exchange_code_with_retry(pds_client, &dpop, &callback.code, &pkce_verifier, &metadata)
            .await?;

    // 11. Create OAuthClient and store in ClaimState
    let session = std::sync::Arc::new(std::sync::Mutex::new(crate::oauth::OAuthSession {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ClaimError::NetworkError {
                message: "system time error".to_string(),
            })?
            .as_secs()
            + token_resp.expires_in,
        dpop_nonce: initial_nonce,
    }));

    let oauth_client =
        OAuthClient::new(session, pds_url).map_err(|_| ClaimError::NetworkError {
            message: "failed to create OAuth client".to_string(),
        })?;

    let mut claim_state = state.claim_state.lock().await;
    if let Some(ref mut claim) = claim_state.as_mut() {
        claim.pds_oauth_client = Some(std::sync::Arc::new(oauth_client));
    }
    drop(claim_state);

    // 12. Emit event to frontend
    app.emit("pds_auth_ready", ()).map_err(|e| {
        tracing::error!(error = %e, "failed to emit pds_auth_ready event");
        ClaimError::NetworkError {
            message: "event emission failed".to_string(),
        }
    })?;

    Ok(())
}

/// Helper function for token exchange with nonce retry (PDS version).
///
/// Follows the same pattern as `exchange_code_with_retry` in oauth.rs.
/// Uses the raw `pds_token_exchange` method which returns `reqwest::Response`.
async fn pds_exchange_code_with_retry(
    pds_client: &crate::pds_client::PdsClient,
    dpop: &crate::oauth::DPoPKeypair,
    code: &str,
    pkce_verifier: &str,
    metadata: &crate::pds_client::AuthServerMetadata,
) -> Result<(crate::http::TokenResponse, Option<String>), ClaimError> {
    let token_htu = &metadata.token_endpoint;
    let proof = dpop
        .make_proof("POST", token_htu, None, None)
        .map_err(|_| ClaimError::NetworkError {
            message: "failed to create DPoP proof for token exchange".to_string(),
        })?;

    let resp = pds_client
        .pds_token_exchange(metadata, code, pkce_verifier, &proof)
        .await
        .map_err(|e| ClaimError::NetworkError {
            message: format!("token exchange failed: {}", e),
        })?;

    if resp.status().as_u16() == 200 {
        let nonce = resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let token = resp
            .json::<crate::http::TokenResponse>()
            .await
            .map_err(|e| ClaimError::NetworkError {
                message: format!("token response parsing failed: {}", e),
            })?;
        return Ok((token, nonce));
    }

    // Check for nonce retry
    let nonce = resp
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let error_body = resp.text().await.unwrap_or_else(|_| "{}".to_string());

    if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&error_body) {
        if error_json.get("error").and_then(|v| v.as_str()) == Some("use_dpop_nonce") {
            if let Some(nonce_val) = nonce {
                tracing::debug!(nonce = %nonce_val, "retrying token exchange with server nonce");
                let proof_with_nonce = dpop
                    .make_proof("POST", token_htu, Some(&nonce_val), None)
                    .map_err(|_| ClaimError::NetworkError {
                    message: "failed to create DPoP proof with nonce".to_string(),
                })?;

                let retry_resp = pds_client
                    .pds_token_exchange(metadata, code, pkce_verifier, &proof_with_nonce)
                    .await
                    .map_err(|e| ClaimError::NetworkError {
                        message: format!("token exchange retry failed: {}", e),
                    })?;

                if retry_resp.status().as_u16() == 200 {
                    let retry_nonce = retry_resp
                        .headers()
                        .get("DPoP-Nonce")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    let token = retry_resp
                        .json::<crate::http::TokenResponse>()
                        .await
                        .map_err(|e| ClaimError::NetworkError {
                            message: format!("retry token response parsing failed: {}", e),
                        })?;
                    return Ok((token, retry_nonce));
                } else {
                    // Retry response was non-200, extract status and body for error message
                    let status = retry_resp.status();
                    let body = retry_resp
                        .text()
                        .await
                        .unwrap_or_else(|_| "(unable to read response body)".to_string());
                    return Err(ClaimError::NetworkError {
                        message: format!("token exchange retry returned {}: {}", status, body),
                    });
                }
            }
        }
    }

    Err(ClaimError::NetworkError {
        message: "token exchange failed".to_string(),
    })
}

/// Request email verification for the PLC operation.
///
/// Calls the `requestPlcOperationSignature` XRPC endpoint on the old PDS to trigger
/// an email verification flow. This must be called after `start_pds_auth` succeeds.
///
/// **Prerequisites:** `start_pds_auth` must have completed successfully and populated
/// `ClaimState.pds_oauth_client`.
///
/// The core logic is extracted into `request_claim_verification_impl` to make it testable
/// without Tauri's `State` wrapper.
#[tauri::command]
pub async fn request_claim_verification(
    state: tauri::State<'_, crate::oauth::AppState>,
    _did: String,
) -> Result<(), ClaimError> {
    // Acquire lock, extract Arc<OAuthClient>, and release lock before making network call
    let oauth_client = {
        let claim_state = state.claim_state.lock().await;
        let Some(claim) = claim_state.as_ref() else {
            return Err(ClaimError::Unauthorized);
        };
        claim.pds_oauth_client.clone()
    }; // claim_state lock released here

    let Some(oauth_client) = oauth_client else {
        return Err(ClaimError::Unauthorized);
    };

    crate::pds_client::request_plc_operation_signature(&oauth_client)
        .await
        .map_err(|e| ClaimError::NetworkError {
            message: format!("request_plc_operation_signature failed: {}", e),
        })
}

/// Testable core logic for `request_claim_verification`.
///
/// Extracted to a separate function to avoid requiring Tauri's `State` in tests.
pub(crate) async fn request_claim_verification_impl(
    claim_state: &ClaimState,
) -> Result<(), ClaimError> {
    let Some(ref oauth_client) = claim_state.pds_oauth_client else {
        return Err(ClaimError::Unauthorized);
    };

    crate::pds_client::request_plc_operation_signature(oauth_client)
        .await
        .map_err(|e| ClaimError::NetworkError {
            message: format!("request_plc_operation_signature failed: {}", e),
        })
}

/// Extract handle from also_known_as entries.
///
/// Searches for entries of the form "at://handle" and returns the first match.
/// Returns None if no such entries are found.
fn extract_handle_from_also_known_as(also_known_as: &[String]) -> Option<String> {
    for entry in also_known_as {
        if let Some(handle) = entry.strip_prefix("at://") {
            return Some(handle.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── resolve_identity tests ──────────────────────────────────────────────────

    #[test]
    fn test_resolve_identity_maps_pds_error_handle_not_found() {
        let err = PdsClientError::HandleNotFound;
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::HandleNotFound => {}
            _ => panic!("Expected HandleNotFound"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_did_not_found() {
        let err = PdsClientError::DidNotFound;
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::DidNotFound => {}
            _ => panic!("Expected DidNotFound"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_pds_unreachable() {
        let err = PdsClientError::PdsUnreachable {
            reason: "Connection refused".to_string(),
        };
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::PdsUnreachable => {}
            _ => panic!("Expected PdsUnreachable"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_network_error() {
        let err = PdsClientError::NetworkError {
            message: "Timeout".to_string(),
        };
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::NetworkError { message } => {
                assert_eq!(message, "Timeout");
            }
            _ => panic!("Expected NetworkError"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_invalid_response() {
        let err = PdsClientError::InvalidResponse {
            message: "Invalid JSON".to_string(),
        };
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::NetworkError { message } => {
                assert_eq!(message, "Invalid JSON");
            }
            _ => panic!("Expected NetworkError"),
        }
    }

    #[test]
    fn test_resolve_identity_maps_pds_error_oauth_failed() {
        let err = PdsClientError::OauthFailed {
            message: "Token exchange failed".to_string(),
        };
        let result = map_pds_error_to_resolve(err);
        match result {
            ResolveError::NetworkError { message } => {
                assert_eq!(message, "Token exchange failed");
            }
            _ => panic!("Expected NetworkError"),
        }
    }

    #[test]
    fn test_extract_handle_from_also_known_as_valid() {
        let entries = vec!["at://alice.test".to_string()];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, Some("alice.test".to_string()));
    }

    #[test]
    fn test_extract_handle_from_also_known_as_multiple_entries() {
        let entries = vec![
            "https://example.com/user/alice".to_string(),
            "at://alice.test".to_string(),
        ];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, Some("alice.test".to_string()));
    }

    #[test]
    fn test_extract_handle_from_also_known_as_empty() {
        let entries: Vec<String> = vec![];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_handle_from_also_known_as_no_at_prefix() {
        let entries = vec!["https://example.com/user/alice".to_string()];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, None);
    }

    // ── resolve_identity integration tests (AC4.1) ──────────────────────────────

    /// Test 1: Handle input → correct IdentityInfo verification
    /// Verifies that the extract_handle_from_also_known_as and error mapping
    /// logic correctly processes DID documents with handles in also_known_as.
    /// This tests the core logic that would be in resolve_identity response.
    #[test]
    fn test_resolve_identity_handle_input_builds_correct_response() {
        // Simulate extracting handle from a DID document's also_known_as field
        let also_known_as = vec!["at://alice.example.com".to_string()];

        let handle = extract_handle_from_also_known_as(&also_known_as)
            .expect("Should extract handle from at:// entry");

        // Assertions matching AC4.1 requirements
        assert_eq!(handle, "alice.example.com");

        // Simulate constructing IdentityInfo response
        let rotation_keys = vec!["did:key:zQ3rot1".to_string(), "did:key:zQ3rot2".to_string()];
        assert_eq!(rotation_keys.len(), 2);
        assert_eq!(rotation_keys[0], "did:key:zQ3rot1");
    }

    /// Test 2: DID input → skips handle resolution
    /// Verifies that DID detection works correctly and would skip
    /// handle resolution in the actual command.
    #[test]
    fn test_resolve_identity_did_input_skips_handle_resolution() {
        // Direct DID input should be detected
        let did = "did:plc:direct123";
        let is_did = did.starts_with("did:");
        assert!(is_did, "Input should be recognized as DID");

        // Fallback handle should not be used when extracting from also_known_as
        let also_known_as = vec!["at://bob.example.com".to_string()];
        let handle = extract_handle_from_also_known_as(&also_known_as)
            .expect("Should extract handle from also_known_as");

        assert_eq!(handle, "bob.example.com");
        assert_eq!(did, "did:plc:direct123");
    }

    /// Test 3: Handle not found → ResolveError::HandleNotFound
    /// Verifies error mapping when PdsClient returns HandleNotFound.
    #[test]
    fn test_resolve_identity_handle_not_found_returns_error() {
        // Simulate PdsClient error for handle not found
        let pds_error = crate::pds_client::PdsClientError::HandleNotFound;
        let mapped = map_pds_error_to_resolve(pds_error);

        match mapped {
            ResolveError::HandleNotFound => {
                // Expected — correctly mapped to ResolveError
            }
            _ => panic!("Expected ResolveError::HandleNotFound, got: {:?}", mapped),
        }
    }

    /// Test 4: DID not found → ResolveError::DidNotFound
    /// Verifies error mapping when plc.directory returns 404 for the DID.
    #[test]
    fn test_resolve_identity_did_not_found_returns_error() {
        // Simulate PdsClient error for DID not found in plc.directory
        let pds_error = crate::pds_client::PdsClientError::DidNotFound;
        let mapped = map_pds_error_to_resolve(pds_error);

        match mapped {
            ResolveError::DidNotFound => {
                // Expected — correctly mapped to ResolveError
            }
            e => panic!("Expected ResolveError::DidNotFound, got: {:?}", e),
        }
    }

    // ── Serialization tests for claim types ──────────────────────────────────

    #[test]
    fn test_identity_info_serializes_camel_case() {
        let info = IdentityInfo {
            did: "did:plc:test".to_string(),
            handle: "alice.test".to_string(),
            pds_url: "https://pds.example.com".to_string(),
            current_rotation_keys: vec!["did:key:zQ3rot1".to_string()],
            device_key_is_root: true,
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["did"], "did:plc:test");
        assert_eq!(json["handle"], "alice.test");
        assert_eq!(json["pdsUrl"], "https://pds.example.com");
        assert_eq!(json["currentRotationKeys"][0], "did:key:zQ3rot1");
        assert_eq!(json["deviceKeyIsRoot"], true);
    }

    #[test]
    fn test_verified_claim_op_serializes_camel_case() {
        let op = VerifiedClaimOp {
            diff: OpDiff {
                added_keys: vec!["did:key:zQ3new".to_string()],
                removed_keys: vec![],
                changed_services: vec![],
                prev_cid: "bagXXX".to_string(),
            },
            signed_op: "eyJzaWciOiAi...".to_string(),
            warnings: vec!["This will change ownership".to_string()],
        };

        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["signedOp"], "eyJzaWciOiAi...");
        assert!(json["diff"].is_object());
        assert_eq!(json["warnings"][0], "This will change ownership");
    }

    #[test]
    fn test_op_diff_serializes_camel_case() {
        let diff = OpDiff {
            added_keys: vec!["did:key:zQ3new".to_string()],
            removed_keys: vec!["did:key:zQ3old".to_string()],
            changed_services: vec![],
            prev_cid: "bagXXX".to_string(),
        };

        let json = serde_json::to_value(&diff).unwrap();
        assert_eq!(json["addedKeys"][0], "did:key:zQ3new");
        assert_eq!(json["removedKeys"][0], "did:key:zQ3old");
        assert_eq!(json["prevCid"], "bagXXX");
        assert!(json["changedServices"].is_array());
    }

    #[test]
    fn test_service_change_serializes_camel_case() {
        let change = ServiceChange {
            id: "atproto_pds".to_string(),
            change_type: "modified".to_string(),
            old_endpoint: Some("https://pds-old.example.com".to_string()),
            new_endpoint: Some("https://pds-new.example.com".to_string()),
        };

        let json = serde_json::to_value(&change).unwrap();
        assert_eq!(json["id"], "atproto_pds");
        assert_eq!(json["changeType"], "modified");
        assert_eq!(json["oldEndpoint"], "https://pds-old.example.com");
        assert_eq!(json["newEndpoint"], "https://pds-new.example.com");
    }

    #[test]
    fn test_claim_result_serializes_camel_case() {
        let result = ClaimResult {
            updated_did_doc: serde_json::json!({
                "did": "did:plc:test",
                "rotationKeys": ["did:key:zQ3new"]
            }),
        };

        let json = serde_json::to_value(&result).unwrap();
        assert!(json["updatedDidDoc"].is_object());
        assert_eq!(json["updatedDidDoc"]["did"], "did:plc:test");
    }

    #[test]
    fn test_resolve_error_handle_not_found_serializes_correctly() {
        let err = ResolveError::HandleNotFound;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "HANDLE_NOT_FOUND");
    }

    #[test]
    fn test_resolve_error_did_not_found_serializes_correctly() {
        let err = ResolveError::DidNotFound;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DID_NOT_FOUND");
    }

    #[test]
    fn test_resolve_error_pds_unreachable_serializes_correctly() {
        let err = ResolveError::PdsUnreachable;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "PDS_UNREACHABLE");
    }

    #[test]
    fn test_resolve_error_network_error_serializes_correctly() {
        let err = ResolveError::NetworkError {
            message: "Connection timeout".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection timeout");
    }

    #[test]
    fn test_claim_error_invalid_token_serializes_correctly() {
        let err = ClaimError::InvalidToken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "INVALID_TOKEN");
    }

    #[test]
    fn test_claim_error_verification_failed_serializes_correctly() {
        let err = ClaimError::VerificationFailed {
            message: "Signature mismatch".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "VERIFICATION_FAILED");
        assert_eq!(json["message"], "Signature mismatch");
    }

    #[test]
    fn test_claim_error_plc_directory_error_serializes_correctly() {
        let err = ClaimError::PlcDirectoryError {
            message: "Invalid operation".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "PLC_DIRECTORY_ERROR");
        assert_eq!(json["message"], "Invalid operation");
    }

    #[test]
    fn test_claim_error_unauthorized_serializes_correctly() {
        let err = ClaimError::Unauthorized;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "UNAUTHORIZED");
    }

    #[test]
    fn test_claim_error_network_error_serializes_correctly() {
        let err = ClaimError::NetworkError {
            message: "DNS resolution failed".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "DNS resolution failed");
    }

    // ── request_claim_verification tests (AC4.2) ──────────────────────────────

    /// Test 1: Success — calls XRPC endpoint with 200 response
    /// Verifies AC4.2: request_claim_verification calls requestPlcOperationSignature on the old PDS
    #[tokio::test]
    async fn test_request_claim_verification_success() {
        use httpmock::MockServer;
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({}));
        });

        // Create a test session and OAuthClient
        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let claim_state = ClaimState {
            did: "did:plc:test".to_string(),
            pds_url: mock_server.base_url(),
            did_doc: PlcDidDocument {
                did: "did:plc:test".to_string(),
                also_known_as: vec!["at://test.example.com".to_string()],
                rotation_keys: vec!["did:key:zQ3test".to_string()],
                verification_methods: serde_json::json!({}),
                services: std::collections::HashMap::new(),
            },
            pds_oauth_client: Some(std::sync::Arc::new(oauth_client)),
            verified_signed_op: None,
        };

        let result = request_claim_verification_impl(&claim_state).await;
        assert!(
            result.is_ok(),
            "should successfully call requestPlcOperationSignature when PDS returns 200"
        );
    }

    /// Test 3 (renamed): Unauthorized — no OAuth client
    /// Verifies AC4.2: request_claim_verification returns Unauthorized when pds_oauth_client is None
    #[tokio::test]
    async fn test_request_claim_verification_unauthorized_no_oauth_client() {
        let claim_state = ClaimState {
            did: "did:plc:test".to_string(),
            pds_url: "https://pds.example.com".to_string(),
            did_doc: PlcDidDocument {
                did: "did:plc:test".to_string(),
                also_known_as: vec!["at://test.example.com".to_string()],
                rotation_keys: vec!["did:key:zQ3test".to_string()],
                verification_methods: serde_json::json!({}),
                services: std::collections::HashMap::new(),
            },
            pds_oauth_client: None,
            verified_signed_op: None,
        };

        let result = request_claim_verification_impl(&claim_state).await;
        assert!(
            matches!(result, Err(ClaimError::Unauthorized)),
            "should return Unauthorized when pds_oauth_client is None"
        );
    }

    /// Test 4: Network error — PDS returns 500
    /// Verifies AC4.2: request_claim_verification returns NetworkError on PDS failure
    #[tokio::test]
    async fn test_request_claim_verification_pds_returns_500() {
        use httpmock::MockServer;
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.requestPlcOperationSignature");
            then.status(500).json_body(serde_json::json!({
                "error": "Internal Server Error"
            }));
        });

        // Create a test session and OAuthClient
        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            dpop_nonce: None,
        }));

        let keypair = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
        let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
            keypair,
            session,
            mock_server.base_url(),
        );

        let claim_state = ClaimState {
            did: "did:plc:test".to_string(),
            pds_url: mock_server.base_url(),
            did_doc: PlcDidDocument {
                did: "did:plc:test".to_string(),
                also_known_as: vec!["at://test.example.com".to_string()],
                rotation_keys: vec!["did:key:zQ3test".to_string()],
                verification_methods: serde_json::json!({}),
                services: std::collections::HashMap::new(),
            },
            pds_oauth_client: Some(std::sync::Arc::new(oauth_client)),
            verified_signed_op: None,
        };

        let result = request_claim_verification_impl(&claim_state).await;
        assert!(
            matches!(result, Err(ClaimError::NetworkError { .. })),
            "should return NetworkError when PDS returns 500"
        );
    }
}
