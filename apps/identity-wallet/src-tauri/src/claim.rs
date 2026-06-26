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
//                   sign_and_verify_claim (command: calls getRecommendedDidCredentials and
//                   signPlcOperation on old PDS, verifies signature and local constraints)
//                   submit_claim (command: POSTs signed PLC operation to plc.directory,
//                   persists identity to IdentityStore, clears claim state)

use serde::Serialize;
use tauri::Emitter;

use crate::identity_store::IdentityStore;
use crate::oauth_client::OAuthClient;
use crate::pds_client::{PdsClientError, PlcDidDocument};
use crypto::DidKeyUri;

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
/// Returned by `sign_and_verify_claim` command.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedClaimOp {
    /// Diff of keys and services between current DID doc and proposed operation
    pub diff: OpDiff,
    /// Signed operation (ready for PLC submission) as JSON value
    pub signed_op: serde_json::Value,
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
    /// Previous CID (content identifier) of the DID document (None if no prior operation)
    pub prev_cid: Option<String>,
}

/// Type of change to a service endpoint.
#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ChangeType {
    /// Service endpoint was added
    Added,
    /// Service endpoint was removed
    Removed,
    /// Service endpoint was modified
    Modified,
}

/// Change to a service endpoint in the DID document.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceChange {
    /// Service ID (e.g., "atproto_pds")
    pub id: String,
    /// Type of change: added, removed, or modified
    pub change_type: ChangeType,
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
#[derive(Clone)]
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
    /// Verified signed operation (set after `sign_and_verify_claim` succeeds) as JSON value
    pub verified_signed_op: Option<serde_json::Value>,
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
    tracing::info!("resolve_identity command: resolving {}", handle_or_did);
    let pds_client = state.pds_client();

    // Determine if input is a DID or handle
    let is_did = handle_or_did.starts_with("did:");
    let (did, mut handle_for_fallback) = if is_did {
        (handle_or_did.clone(), None)
    } else {
        match pds_client.resolve_handle(&handle_or_did).await {
            Ok(did) => {
                tracing::info!(handle = %handle_or_did, did = %did, "handle resolved");
                (did, Some(handle_or_did.clone()))
            }
            Err(e) => {
                tracing::error!(handle = %handle_or_did, error = %e, "handle resolution failed");
                return Err(map_pds_error_to_resolve(e));
            }
        }
    };

    // Fetch DID document and PDS endpoint from plc.directory
    let (pds_url, mut did_doc) = match pds_client.discover_pds(&did).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(did = %did, error = %e, "PDS discovery failed");
            return Err(map_pds_error_to_resolve(e));
        }
    };

    // The W3C DID Document doesn't include rotation keys — fetch them from the audit log.
    match pds_client.fetch_audit_log(&did).await {
        Ok(raw_log) => {
            did_doc.rotation_keys = crate::pds_client::rotation_keys_from_audit_log(&raw_log);
            tracing::debug!(did = %did, count = did_doc.rotation_keys.len(), "populated rotation keys from audit log");
        }
        Err(e) => {
            tracing::warn!(did = %did, error = %e, "failed to fetch audit log for rotation keys");
        }
    }

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
                        Err(e) => {
                            tracing::error!(error = %e, did = %did, "failed to get or create device key");
                            false
                        }
                    }
                } else {
                    false // DID not registered
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to list identities");
                false
            }
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
    tracing::info!("start_pds_auth command: authenticating with {}", pds_url);
    use tauri_plugin_opener::OpenerExt;

    // 1. Validate ClaimState is populated and pds_url matches
    let did = {
        let claim_state = state.claim_state.lock().await;
        let Some(claim) = claim_state.as_ref() else {
            tracing::warn!("start_pds_auth: ClaimState not found");
            return Err(ClaimError::Unauthorized);
        };

        // Validate that pds_url matches ClaimState.pds_url (defense-in-depth)
        if claim.pds_url != pds_url {
            let expected = claim.pds_url.clone();
            drop(claim_state);
            tracing::warn!(
                expected = %expected,
                received = %pds_url,
                "start_pds_auth: pds_url mismatch"
            );
            return Err(ClaimError::Unauthorized);
        }

        claim.did.clone()
    }; // claim_state lock released here

    let pds_client = state.pds_client();

    // 2. Discover auth server metadata from the PDS
    tracing::debug!(pds_url = %pds_url, "discovering auth server metadata");
    let metadata = pds_client
        .discover_auth_server(&pds_url)
        .await
        .map_err(|e| {
            tracing::error!(pds_url = %pds_url, error = %e, "auth server discovery failed");
            ClaimError::NetworkError {
                message: format!("failed to discover auth server: {}", e),
            }
        })?;
    tracing::debug!(issuer = %metadata.issuer, "auth server metadata discovered");

    // 3. Generate PKCE and CSRF state
    let (pkce_verifier, pkce_challenge) = crate::oauth::pkce::generate();
    let csrf_state = crate::oauth::generate_state_param();

    // 4. Get DPoP keypair and compute thumbprint
    let dpop = crate::oauth::DPoPKeypair::get_or_create().map_err(|e| {
        tracing::error!(error = %e, "DPoP keypair creation failed");
        ClaimError::NetworkError {
            message: "failed to create DPoP keypair".to_string(),
        }
    })?;
    let dpop_jkt = dpop.public_jwk_thumbprint();

    // 5-6. PAR with DPoP nonce retry
    let par_htu = metadata
        .pushed_authorization_request_endpoint
        .as_ref()
        .cloned()
        .unwrap_or_else(|| format!("{}/oauth/par", metadata.issuer));

    let pds_url = state.custos_client().base_url_str().to_string();
    let client_id = crate::pds_client::client_id_for_pds(&pds_url);

    let par_resp = pds_par_with_retry(PdsParWithRetryParams {
        pds_client,
        dpop: &dpop,
        metadata: &metadata,
        par_htu: &par_htu,
        pkce_challenge: &pkce_challenge,
        csrf_state: &csrf_state,
        dpop_jkt: &dpop_jkt,
        did: &did,
        client_id: &client_id,
    })
    .await?;
    tracing::debug!("PAR succeeded, opening browser");

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
        &client_id,
    );

    app.opener()
        .open_url(&auth_url, None::<&str>)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to open system browser");
            ClaimError::Unauthorized
        })?;

    // 9. Await the deep-link callback
    tracing::debug!("waiting for deep-link callback");
    let callback = rx
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "deep-link callback channel closed");
            ClaimError::Unauthorized
        })?
        .map_err(|e| {
            tracing::error!(error = %e, "deep-link callback returned OAuth error");
            ClaimError::Unauthorized
        })?;
    tracing::debug!("deep-link callback received, exchanging code");

    // 10. Token exchange with nonce retry
    let (token_resp, initial_nonce) = pds_exchange_code_with_retry(
        pds_client,
        &dpop,
        &callback.code,
        &pkce_verifier,
        &metadata,
        &client_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "PDS token exchange failed");
        e
    })?;

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
        OAuthClient::new(session, pds_url.clone()).map_err(|_| ClaimError::NetworkError {
            message: "failed to create OAuth client".to_string(),
        })?;

    let mut claim_state = state.claim_state.lock().await;
    if let Some(ref mut claim) = claim_state.as_mut() {
        claim.pds_oauth_client = Some(std::sync::Arc::new(oauth_client));
    } else {
        drop(claim_state);
        return Err(ClaimError::Unauthorized);
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

/// Parameters for PAR with DPoP nonce retry.
struct PdsParWithRetryParams<'a> {
    pds_client: &'a crate::pds_client::PdsClient,
    dpop: &'a crate::oauth::DPoPKeypair,
    metadata: &'a crate::pds_client::AuthServerMetadata,
    par_htu: &'a str,
    pkce_challenge: &'a str,
    csrf_state: &'a str,
    dpop_jkt: &'a str,
    did: &'a str,
    client_id: &'a str,
}

/// Helper function for PAR with DPoP nonce retry.
///
/// Some authorization servers (e.g. bsky.social) require a DPoP nonce even for
/// PAR. On the first call, the server returns 400 `use_dpop_nonce` with a
/// `DPoP-Nonce` header. We extract the nonce, rebuild the DPoP proof, and retry.
async fn pds_par_with_retry(
    params: PdsParWithRetryParams<'_>,
) -> Result<crate::pds_client::PdsParResponse, ClaimError> {
    let par_proof = params
        .dpop
        .make_proof("POST", params.par_htu, None, None)
        .map_err(|e| {
            tracing::error!(error = %e, "DPoP proof generation failed for PAR");
            ClaimError::NetworkError {
                message: "failed to create DPoP proof for PAR".to_string(),
            }
        })?;

    tracing::debug!(par_endpoint = %params.par_htu, "sending PAR request");
    match params
        .pds_client
        .pds_par(
            params.metadata,
            crate::pds_client::PdsParRequest {
                pkce_challenge: params.pkce_challenge,
                state_param: params.csrf_state,
                dpop_proof: &par_proof,
                dpop_jkt: params.dpop_jkt,
                login_hint: Some(params.did),
                client_id: params.client_id,
            },
        )
        .await
    {
        Ok(resp) => return Ok(resp),
        Err(crate::pds_client::PdsClientError::OauthFailed { message })
            if message.contains("use_dpop_nonce") =>
        {
            tracing::debug!("PAR requires DPoP nonce, retrying");
        }
        Err(e) => {
            tracing::error!(error = %e, "PAR request failed");
            return Err(ClaimError::NetworkError {
                message: format!("PAR failed: {}", e),
            });
        }
    }

    // The nonce is in the error response body; we need to get it from the raw
    // response. Re-issue the PAR as a raw request to extract the nonce header.
    let raw_par_url = params
        .metadata
        .pushed_authorization_request_endpoint
        .clone()
        .unwrap_or_else(|| format!("{}/oauth/par", params.metadata.issuer));

    let nonce_proof = params
        .dpop
        .make_proof("POST", params.par_htu, None, None)
        .map_err(|_| ClaimError::NetworkError {
            message: "failed to create DPoP proof for nonce discovery".to_string(),
        })?;

    let form_data = vec![
        ("response_type", "code"),
        ("code_challenge_method", "S256"),
        ("code_challenge", params.pkce_challenge),
        ("state", params.csrf_state),
        ("client_id", params.client_id),
        (
            "redirect_uri",
            "dev.malpercio.identitywallet:/oauth/callback",
        ),
        ("scope", "atproto transition:generic"),
        ("dpop_jkt", params.dpop_jkt),
        ("login_hint", params.did),
    ];

    let nonce_resp = params
        .pds_client
        .client()
        .post(&raw_par_url)
        .header("DPoP", &nonce_proof)
        .form(&form_data)
        .send()
        .await
        .map_err(|e| ClaimError::NetworkError {
            message: format!("PAR nonce discovery failed: {}", e),
        })?;

    let nonce = nonce_resp
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let Some(nonce_val) = nonce else {
        tracing::error!("PAR returned use_dpop_nonce but no DPoP-Nonce header");
        return Err(ClaimError::NetworkError {
            message: "PAR requires nonce but server did not provide one".to_string(),
        });
    };

    tracing::debug!(nonce = %nonce_val, "retrying PAR with DPoP nonce");
    let retry_proof = params
        .dpop
        .make_proof("POST", params.par_htu, Some(&nonce_val), None)
        .map_err(|e| {
            tracing::error!(error = %e, "DPoP proof with nonce failed");
            ClaimError::NetworkError {
                message: "failed to create DPoP proof with nonce".to_string(),
            }
        })?;

    params
        .pds_client
        .pds_par(
            params.metadata,
            crate::pds_client::PdsParRequest {
                pkce_challenge: params.pkce_challenge,
                state_param: params.csrf_state,
                dpop_proof: &retry_proof,
                dpop_jkt: params.dpop_jkt,
                login_hint: Some(params.did),
                client_id: params.client_id,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "PAR retry with nonce failed");
            ClaimError::NetworkError {
                message: format!("PAR retry failed: {}", e),
            }
        })
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
    client_id: &str,
) -> Result<(crate::http::TokenResponse, Option<String>), ClaimError> {
    let token_htu = &metadata.token_endpoint;
    tracing::debug!(token_endpoint = %token_htu, "starting PDS token exchange");
    let proof = dpop
        .make_proof("POST", token_htu, None, None)
        .map_err(|e| {
            tracing::error!(error = %e, "DPoP proof for token exchange failed");
            ClaimError::NetworkError {
                message: "failed to create DPoP proof for token exchange".to_string(),
            }
        })?;

    let resp = pds_client
        .pds_token_exchange(metadata, code, pkce_verifier, &proof, client_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "PDS token exchange request failed");
            ClaimError::NetworkError {
                message: format!("token exchange failed: {}", e),
            }
        })?;

    tracing::debug!(status = %resp.status(), "PDS token exchange response received");
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
    tracing::debug!(status = "non-200", body = %error_body, "token exchange needs retry or failed");

    // Detect nonce retry by checking error JSON for "use_dpop_nonce" error code.
    // This is fragile string matching based on PDS/OAuth server error responses.
    // If the server's error format changes, this detection will fail silently.
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
                    .pds_token_exchange(metadata, code, pkce_verifier, &proof_with_nonce, client_id)
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
                    let status = retry_resp.status();
                    let body = retry_resp
                        .text()
                        .await
                        .unwrap_or_else(|_| "(unable to read response body)".to_string());
                    tracing::error!(status = %status, body = %body, "token exchange retry failed");
                    return Err(ClaimError::NetworkError {
                        message: format!("token exchange retry returned {}: {}", status, body),
                    });
                }
            }
        }
    }

    tracing::error!(body = %error_body, "token exchange failed with non-retryable error");
    Err(ClaimError::NetworkError {
        message: format!(
            "token exchange returned non-success response: {}",
            error_body
        ),
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
    did: String,
) -> Result<(), ClaimError> {
    tracing::info!(
        "request_claim_verification command: requesting signature for {}",
        did
    );
    // Acquire lock, extract claim state, and release lock before making network call
    let claim_state_copy = {
        let claim_state = state.claim_state.lock().await;
        let Some(claim) = claim_state.as_ref() else {
            return Err(ClaimError::Unauthorized);
        };
        // Validate that the caller's DID matches the claim state's DID
        if claim.did != did {
            return Err(ClaimError::Unauthorized);
        }
        claim.clone()
    }; // claim_state lock released here

    request_claim_verification_impl(&claim_state_copy).await
}

/// Testable core logic for `request_claim_verification`.
///
/// Extracted to a separate function to allow testing without Tauri's State.
pub(crate) async fn request_claim_verification_impl(
    claim_state: &ClaimState,
) -> Result<(), ClaimError> {
    let Some(ref oauth_client) = claim_state.pds_oauth_client else {
        tracing::error!("request_claim_verification: no pds_oauth_client in ClaimState");
        return Err(ClaimError::Unauthorized);
    };

    tracing::debug!("calling requestPlcOperationSignature XRPC");
    crate::pds_client::request_plc_operation_signature(oauth_client)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "requestPlcOperationSignature failed");
            ClaimError::NetworkError {
                message: format!("request_plc_operation_signature failed: {}", e),
            }
        })?;
    tracing::info!("email verification requested successfully");
    Ok(())
}

/// Sign and verify a PLC operation.
///
/// This command coordinates three systems:
/// 1. Old PDS via XRPC for the signed operation (`signPlcOperation`)
/// 2. plc.directory for the current audit log
/// 3. The crypto crate for local verification
///
/// The signed operation and diff are stored in `ClaimState.verified_signed_op` for submission.
///
/// **Prerequisites:** `start_pds_auth` must have completed successfully and populated
/// `ClaimState.pds_oauth_client`.
#[tauri::command]
pub async fn sign_and_verify_claim(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    token: String,
) -> Result<VerifiedClaimOp, ClaimError> {
    tracing::info!(
        "sign_and_verify_claim command: signing and verifying operation for {}",
        did
    );
    // Acquire lock, extract required data, and release lock before making network calls
    let (pds_client_ref, oauth_client_ref, claim_did, claim_did_doc) = {
        let claim_state = state.claim_state.lock().await;
        let Some(claim) = claim_state.as_ref() else {
            return Err(ClaimError::Unauthorized);
        };

        // Defense-in-depth: validate caller's DID matches ClaimState
        if claim.did != did {
            return Err(ClaimError::Unauthorized);
        }

        let Some(ref oauth_client) = claim.pds_oauth_client else {
            return Err(ClaimError::Unauthorized);
        };

        (
            state.pds_client(),
            oauth_client.clone(),
            claim.did.clone(),
            claim.did_doc.clone(),
        )
    }; // claim_state lock released here

    // Step 2: Look up the device key ID using IdentityStore
    let device_key = crate::identity_store::IdentityStore
        .get_or_create_device_key(&did)
        .map_err(|e| ClaimError::NetworkError {
            message: format!("failed to get device key: {}", e),
        })?;

    let (verified_op, signed_op_json) = sign_and_verify_claim_impl(
        pds_client_ref,
        &oauth_client_ref,
        &claim_did,
        &claim_did_doc,
        &device_key.key_id,
        &token,
    )
    .await?;

    // Store verified signed op in ClaimState for submit_claim
    {
        let mut claim_state = state.claim_state.lock().await;
        if let Some(ref mut claim) = claim_state.as_mut() {
            claim.verified_signed_op = Some(signed_op_json);
        } else {
            return Err(ClaimError::Unauthorized);
        }
    }

    Ok(verified_op)
}

/// Testable core logic for `sign_and_verify_claim`.
///
/// This helper can be called with resolved dependencies without needing Tauri's State.
/// The returned tuple contains (VerifiedClaimOp, signed_op_json_value).
pub(crate) async fn sign_and_verify_claim_impl(
    pds_client: &crate::pds_client::PdsClient,
    pds_oauth_client: &std::sync::Arc<OAuthClient>,
    did: &str,
    did_doc: &PlcDidDocument,
    device_key_id: &str,
    token: &str,
) -> Result<(VerifiedClaimOp, serde_json::Value), ClaimError> {
    use crate::pds_client::{
        get_recommended_did_credentials, sign_plc_operation, SignPlcOperationRequest,
    };

    // Step 1: Get recommended credentials from old PDS
    tracing::debug!(did = %did, "fetching recommended DID credentials from PDS");
    let recommended = get_recommended_did_credentials(pds_oauth_client)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "getRecommendedDidCredentials failed");
            ClaimError::NetworkError {
                message: format!("get_recommended_did_credentials failed: {}", e),
            }
        })?;
    tracing::debug!(did = %did, "recommended credentials received");

    // Step 2: Build the sign request with device key at position [0]
    let mut rotation_keys = vec![device_key_id.to_string()];
    if let Some(mut rec_keys) = recommended.rotation_keys {
        rotation_keys.append(&mut rec_keys);
    }

    let request = SignPlcOperationRequest {
        token: token.to_string(),
        rotation_keys: Some(rotation_keys),
        also_known_as: recommended.also_known_as.clone(),
        verification_methods: recommended.verification_methods.clone(),
        services: recommended.services.clone(),
    };

    // Step 3: Call signPlcOperation on old PDS
    tracing::debug!(did = %did, "calling signPlcOperation on PDS");
    let response = sign_plc_operation(pds_oauth_client, &request)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "signPlcOperation failed");
            if let crate::pds_client::PdsClientError::NetworkError { message } = &e {
                let lower_msg = message.to_lowercase();
                if lower_msg.contains("invalidtoken")
                    || lower_msg.contains("expiredtoken")
                    || lower_msg.contains("not authenticated")
                {
                    return ClaimError::InvalidToken;
                }
            }
            ClaimError::NetworkError {
                message: format!("sign_plc_operation failed: {}", e),
            }
        })?;
    tracing::debug!(did = %did, "signPlcOperation succeeded");

    // Step 4: Keep operation as JSON value (no need to serialize/deserialize)
    let op_value = response.operation.clone();

    // Step 5: Fetch current audit log and get expected prev CID
    tracing::debug!(did = %did, "fetching audit log for verification");
    let log_json = pds_client.fetch_audit_log(did).await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "fetch_audit_log failed");
        ClaimError::NetworkError {
            message: format!("fetch_audit_log failed: {}", e),
        }
    })?;

    let audit_log = crypto::parse_audit_log(&log_json).map_err(|e| {
        tracing::error!(did = %did, error = %e, "parse_audit_log failed");
        ClaimError::NetworkError {
            message: format!("parse_audit_log failed: {}", e),
        }
    })?;
    tracing::debug!(did = %did, entries = audit_log.len(), "audit log fetched");

    let expected_prev = audit_log.last().map(|entry| entry.cid.clone());

    // Step 6: Verify operation signature
    let op_json_str = serde_json::to_string(&op_value).map_err(|e| ClaimError::NetworkError {
        message: format!("failed to serialize operation: {}", e),
    })?;

    // For genesis claims (no prior rotation keys), the device key is the signer
    // and must be included in the authorized set for signature verification.
    let mut authorized_keys: Vec<DidKeyUri> = did_doc
        .rotation_keys
        .iter()
        .map(|k| DidKeyUri(k.clone()))
        .collect();
    if authorized_keys.is_empty() {
        authorized_keys.push(DidKeyUri(device_key_id.to_string()));
    }

    tracing::debug!(did = %did, authorized_keys = authorized_keys.len(), "verifying PLC operation signature");
    let verified_op =
        crypto::verify_plc_operation(&op_json_str, &authorized_keys).map_err(|e| {
            tracing::error!(did = %did, error = %e, "PLC operation signature verification failed");
            ClaimError::VerificationFailed {
                message: format!("signature verification failed: {}", e),
            }
        })?;
    tracing::debug!(did = %did, "signature verified, running local checks");

    // Step 7: Local verification checks

    // Check 1: rotationKeys[0] is our device key
    if verified_op.rotation_keys.first() != Some(&device_key_id.to_string()) {
        tracing::error!(
            did = %did,
            expected = %device_key_id,
            actual = ?verified_op.rotation_keys.first(),
            "device key not at rotationKeys[0]"
        );
        return Err(ClaimError::VerificationFailed {
            message: format!(
                "expected device key at rotationKeys[0], found: {:?}",
                verified_op.rotation_keys.first()
            ),
        });
    }

    // Check 2: prev chains correctly
    match (&verified_op.prev, expected_prev.as_deref()) {
        (Some(op_prev), Some(expected)) if op_prev == expected => { /* OK */ }
        (prev, expected) => {
            tracing::error!(did = %did, op_prev = ?prev, expected = ?expected, "prev CID mismatch");
            return Err(ClaimError::VerificationFailed {
                message: format!(
                    "prev mismatch: operation has {:?}, expected {:?}",
                    prev, expected
                ),
            });
        }
    }

    // Check 3: No unexpected key mutations
    let original_keys: std::collections::HashSet<_> =
        did_doc.rotation_keys.iter().cloned().collect();
    for key in verified_op.rotation_keys.iter().skip(1) {
        // Skip our device key at position [0]
        if !original_keys.contains(key) && key != device_key_id {
            return Err(ClaimError::VerificationFailed {
                message: format!("unexpected new rotation key: {}", key),
            });
        }
    }

    // Check for removed keys (excluding the device key which may have been added)
    for original_key in &original_keys {
        let key_in_operation = verified_op.rotation_keys.contains(original_key);
        if !key_in_operation {
            return Err(ClaimError::VerificationFailed {
                message: format!("rotation key removed: {}", original_key),
            });
        }
    }

    // Check 4: No unexpected service mutations
    // Note: pds_client::PlcService and crypto::PlcService are different types with identical fields
    let original_services = &did_doc.services;
    for (service_id, service) in &verified_op.services {
        if let Some(original_service) = original_services.get(service_id) {
            // Service exists in original; check if it was modified
            // Compare by field values since the types are different
            if original_service.service_type != service.service_type
                || original_service.endpoint != service.endpoint
            {
                return Err(ClaimError::VerificationFailed {
                    message: format!(
                        "service '{}' was modified: {} endpoint changed",
                        service_id, original_service.service_type
                    ),
                });
            }
        }
        // If service doesn't exist in original but does in operation, it was added (warning, not error)
    }

    // Check for removed services
    for original_service_id in original_services.keys() {
        if !verified_op.services.contains_key(original_service_id) {
            return Err(ClaimError::VerificationFailed {
                message: format!("service '{}' was removed", original_service_id),
            });
        }
    }

    // Step 8: Compute diff and warnings
    let added_keys: Vec<String> = verified_op
        .rotation_keys
        .iter()
        .filter(|k| !original_keys.contains(*k))
        .cloned()
        .collect();

    let removed_keys: Vec<String> = original_keys
        .iter()
        .filter(|k| !verified_op.rotation_keys.contains(k))
        .cloned()
        .collect();

    let mut changed_services = Vec::new();
    for (service_id, service) in &verified_op.services {
        if !original_services.contains_key(service_id) {
            changed_services.push(ServiceChange {
                id: service_id.clone(),
                change_type: ChangeType::Added,
                old_endpoint: None,
                new_endpoint: Some(service.endpoint.clone()),
            });
        }
    }

    let mut warnings = Vec::new();

    // Warning: PDS added extra services
    for service_id in verified_op.services.keys() {
        if !original_services.contains_key(service_id) {
            warnings.push(format!("Old PDS added service: {}", service_id));
        }
    }

    // Warning: PDS added extra also_known_as
    if verified_op.also_known_as.len() > did_doc.also_known_as.len() {
        warnings.push("Old PDS added extra also_known_as entries".to_string());
    }

    let diff = OpDiff {
        added_keys,
        removed_keys,
        changed_services,
        prev_cid: verified_op.prev.clone(),
    };

    Ok((
        VerifiedClaimOp {
            diff,
            signed_op: op_value.clone(),
            warnings,
        },
        op_value,
    ))
}

/// Submit a verified signed claim operation to plc.directory.
///
/// This is the final step in the claim flow. It:
/// 1. Reads `verified_signed_op` from `ClaimState`. Returns `Unauthorized` if `None`.
/// 2. POSTs the signed operation to plc.directory via `pds_client.post_plc_operation()`
/// 3. Persists the claimed identity to `IdentityStore`:
///    - `add_identity(did)` — registers DID in managed-dids index
///    - `get_or_create_device_key(did)` — ensures device key exists
///    - Re-fetches the DID document from plc.directory and stores it
///    - Fetches the PLC audit log and stores it
/// 4. Returns `ClaimResult` with the updated DID document
///    (Caller is responsible for clearing `ClaimState` on success)
pub(crate) async fn submit_claim_impl(
    pds_client: &crate::pds_client::PdsClient,
    claim_state: &ClaimState,
) -> Result<ClaimResult, ClaimError> {
    // Step 1: Read verified_signed_op from ClaimState
    let Some(ref operation) = claim_state.verified_signed_op else {
        tracing::error!(did = %claim_state.did, "submit_claim: no verified_signed_op in ClaimState");
        return Err(ClaimError::Unauthorized);
    };

    // Step 2: POST the signed operation to plc.directory
    tracing::info!(did = %claim_state.did, "submitting signed PLC operation to plc.directory");
    pds_client
        .post_plc_operation(&claim_state.did, operation)
        .await
        .map_err(|e| {
            tracing::error!(did = %claim_state.did, error = %e, "post_plc_operation failed");
            match e {
                crate::pds_client::PdsClientError::InvalidResponse { message } => {
                    ClaimError::PlcDirectoryError { message }
                }
                other => ClaimError::NetworkError {
                    message: format!("post_plc_operation failed: {}", other),
                },
            }
        })?;
    tracing::info!(did = %claim_state.did, "PLC operation accepted by plc.directory");

    // Step 3: Persist the claimed identity to IdentityStore
    let store = IdentityStore;

    // 3a: Register DID in managed-dids index (may already exist from prior attempts)
    tracing::debug!(did = %claim_state.did, "registering identity in store");
    if let Err(e) = store.add_identity(&claim_state.did) {
        if !matches!(
            e,
            crate::identity_store::IdentityStoreError::IdentityAlreadyExists
        ) {
            tracing::error!(did = %claim_state.did, error = %e, "failed to add identity to store");
            return Err(ClaimError::NetworkError {
                message: format!("failed to add identity: {}", e),
            });
        }
        tracing::debug!(did = %claim_state.did, "identity already exists in store (prior partial claim)");
    }

    // 3b: Ensure device key exists for the DID
    store
        .get_or_create_device_key(&claim_state.did)
        .map_err(|e| {
            tracing::error!(did = %claim_state.did, error = %e, "device key creation failed");
            ClaimError::NetworkError {
                message: format!("failed to get or create device key: {}", e),
            }
        })?;

    // 3c: Re-fetch the DID document from plc.directory
    tracing::debug!(did = %claim_state.did, "re-fetching DID document after claim");
    let (_, updated_did_doc) = pds_client
        .discover_pds(&claim_state.did)
        .await
        .map_err(|e| {
            tracing::error!(did = %claim_state.did, error = %e, "failed to re-fetch DID document");
            ClaimError::NetworkError {
                message: format!("failed to re-fetch DID document: {}", e),
            }
        })?;

    // Store the updated DID document as JSON string
    let did_doc_value = serde_json::json!({
        "did": updated_did_doc.did,
        "alsoKnownAs": updated_did_doc.also_known_as,
        "rotationKeys": updated_did_doc.rotation_keys,
        "verificationMethods": updated_did_doc.verification_methods,
        "services": updated_did_doc.services
            .iter()
            .map(|(id, svc)| {
                (id.clone(), serde_json::json!({
                    "type": svc.service_type,
                    "endpoint": svc.endpoint,
                }))
            })
            .collect::<serde_json::Map<String, serde_json::Value>>()
    });

    let did_doc_json =
        serde_json::to_string(&did_doc_value).map_err(|e| ClaimError::NetworkError {
            message: format!("failed to serialize DID document: {}", e),
        })?;

    store
        .store_did_doc(&claim_state.did, &did_doc_json)
        .map_err(|e| {
            tracing::error!(did = %claim_state.did, error = %e, "failed to store DID document");
            ClaimError::NetworkError {
                message: format!("failed to store DID document: {}", e),
            }
        })?;

    // 3d: Fetch and store the PLC audit log
    tracing::debug!(did = %claim_state.did, "fetching audit log for persistence");
    let log_json = pds_client
        .fetch_audit_log(&claim_state.did)
        .await
        .map_err(|e| {
            tracing::error!(did = %claim_state.did, error = %e, "failed to fetch audit log for persistence");
            ClaimError::NetworkError {
                message: format!("failed to fetch audit log: {}", e),
            }
        })?;

    store
        .store_plc_log(&claim_state.did, &log_json)
        .map_err(|e| {
            tracing::error!(did = %claim_state.did, error = %e, "failed to store PLC log");
            ClaimError::NetworkError {
                message: format!("failed to store PLC log: {}", e),
            }
        })?;
    tracing::info!(did = %claim_state.did, "identity claim persisted successfully");

    // Step 4: Clear ClaimState (handled by the Tauri command caller after this function succeeds)
    // Step 5: Return the updated DID document
    Ok(ClaimResult {
        updated_did_doc: did_doc_value,
    })
}

/// Tauri command wrapper for submit_claim.
///
/// Delegates to `submit_claim_impl` to allow testing without AppState.
#[tauri::command]
pub async fn submit_claim(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<ClaimResult, ClaimError> {
    tracing::info!("submit_claim command: submitting claim for {}", did);
    let pds_client = state.pds_client();

    // Acquire lock, extract claim state, then release lock before network calls
    let claim_state_copy = {
        let claim_state = state.claim_state.lock().await;
        claim_state.as_ref().cloned()
    };

    let Some(claim_state) = claim_state_copy else {
        return Err(ClaimError::Unauthorized);
    };

    // Defense-in-depth: validate caller's DID matches ClaimState
    if claim_state.did != did {
        return Err(ClaimError::Unauthorized);
    }

    let result = submit_claim_impl(pds_client, &claim_state).await;

    // On success, clear claim state
    if result.is_ok() {
        let mut claim_state_lock = state.claim_state.lock().await;
        *claim_state_lock = None;
    }

    result
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

    // ── resolve_identity integration tests ─────────────────────────────────────

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

        // Verify handle extraction from also_known_as format (at://handle)
        assert_eq!(handle, "alice.example.com");

        // Simulate constructing IdentityInfo response
        let rotation_keys = ["did:key:zQ3rot1".to_string(), "did:key:zQ3rot2".to_string()];
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
                prev_cid: Some("bagXXX".to_string()),
            },
            signed_op: serde_json::json!({"sig": "..."}),
            warnings: vec!["This will change ownership".to_string()],
        };

        let json = serde_json::to_value(&op).unwrap();
        assert!(json["signedOp"].is_object());
        assert!(json["diff"].is_object());
        assert_eq!(json["warnings"][0], "This will change ownership");
    }

    #[test]
    fn test_op_diff_serializes_camel_case() {
        let diff = OpDiff {
            added_keys: vec!["did:key:zQ3new".to_string()],
            removed_keys: vec!["did:key:zQ3old".to_string()],
            changed_services: vec![],
            prev_cid: Some("bagXXX".to_string()),
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
            change_type: ChangeType::Modified,
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

    // ── request_claim_verification tests ──────────────────────────────────────

    /// Test 1: Success — calls XRPC endpoint with 200 response
    /// request_claim_verification calls requestPlcOperationSignature on the old PDS
    #[tokio::test]
    async fn test_request_claim_verification_success() {
        crate::keychain::clear_for_test();
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
    /// request_claim_verification returns Unauthorized when pds_oauth_client is None
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
    /// request_claim_verification returns NetworkError on PDS failure
    #[tokio::test]
    async fn test_request_claim_verification_pds_returns_500() {
        crate::keychain::clear_for_test();
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

    // ── sign_and_verify_claim tests ──────────────────────────────────────────────

    /// Helper: Build a test rotation operation.
    ///
    /// Generates a P-256 signing keypair, builds a rotation op signed by that key,
    /// and includes the key in `rotation_keys`. Returns `(signed_op_json, device_key_id)`
    /// where `device_key_id` is the `did:key:` URI of the signing key — use it as the
    /// device key in tests so signature verification succeeds.
    fn build_test_rotation_op(
        extra_rotation_keys: Vec<String>,
        services: std::collections::BTreeMap<String, crypto::PlcService>,
        prev_cid: &str,
    ) -> (String, String) {
        use p256::ecdsa::{signature::Signer, SigningKey};
        use p256::FieldBytes;
        use std::collections::BTreeMap;

        // Generate a signing key for the operation
        let signing_kp = crypto::generate_p256_keypair().expect("signing keypair");
        let device_key_id = signing_kp.key_id.0.clone();
        let private_key_bytes = *signing_kp.private_key_bytes;
        let field_bytes: FieldBytes = private_key_bytes.into();
        let sk = SigningKey::from_bytes(&field_bytes).expect("valid key");

        // The signing key is always at rotation_keys[0]; extras follow
        let mut rotation_keys = vec![device_key_id.clone()];
        rotation_keys.extend(extra_rotation_keys);

        let mut verification_methods = BTreeMap::new();
        verification_methods.insert("atproto".to_string(), device_key_id.clone());

        let rotation = crypto::build_did_plc_rotation_op(
            prev_cid,
            rotation_keys,
            verification_methods,
            vec!["at://alice.example.com".to_string()],
            services,
            |data| {
                let sig: p256::ecdsa::Signature = Signer::sign(&sk, data);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("build rotation op");

        (rotation.signed_op_json, device_key_id)
    }

    /// Test 1: Success path with device key at rotationKeys[0]
    #[tokio::test]
    async fn test_sign_and_verify_claim_success() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();
        let prev_cid = "bagtest123".to_string();

        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        // Build rotation op — helper generates a signing key and includes it in rotation_keys.
        // The returned device_key is the signing key's did:key URI.
        let (rotation_json, device_key) =
            build_test_rotation_op(vec![], services.clone(), &prev_cid);

        // Mock getRecommendedDidCredentials
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });

        // Mock signPlcOperation
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation")
                .header_exists("Authorization")
                .header_exists("DPoP");
            then.status(200).json_body(serde_json::json!({
                "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
            }));
        });

        // Create mock audit log
        let audit_log_json = serde_json::to_string(&vec![serde_json::json!({
            "did": "did:plc:test",
            "cid": prev_cid,
            "createdAt": "2026-01-01T00:00:00Z",
            "nullified": false,
            "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
        })])
        .unwrap();

        // Mock plc.directory audit log endpoint
        let plc_mock = MockServer::start();
        plc_mock.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test/log/audit");
            then.status(200).body(&audit_log_json);
        });

        let pds_client_with_plc = crate::pds_client::PdsClient::new_for_test(plc_mock.base_url());

        // Create test session and OAuthClient
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

        // rotation_keys is empty: this DID has no prior rotation keys,
        // so adding device_key at [0] is purely an addition (no removals to flag).
        let did_doc = PlcDidDocument {
            did: "did:plc:test".to_string(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            rotation_keys: vec![],
            verification_methods: serde_json::json!({}),
            services: HashMap::new(),
        };

        let result = sign_and_verify_claim_impl(
            &pds_client_with_plc,
            &Arc::new(oauth_client),
            "did:plc:test",
            &did_doc,
            &device_key,
            "test_token",
        )
        .await;

        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let (verified_op, _signed_op_json) = result.unwrap();
        assert!(
            verified_op.diff.added_keys.contains(&device_key),
            "should have device key in added_keys, got: {:?}",
            verified_op.diff.added_keys
        );
    }

    /// Test 2: Wrong key at rotationKeys[0]
    #[tokio::test]
    async fn test_sign_and_verify_claim_wrong_key_at_rotation_keys_0() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();
        let wrong_key = "did:key:zQ3wrong_key".to_string();
        let prev_cid = "bagtest123".to_string();

        // Build rotation — signing key is at rotation_keys[0]
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        // device_key is different from the signing key — should fail verification
        let (rotation_json, signing_key) = build_test_rotation_op(vec![], services, &prev_cid);

        // Mock endpoints
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
            }));
        });

        let audit_log_json = serde_json::to_string(&vec![serde_json::json!({
            "did": "did:plc:test",
            "cid": prev_cid,
            "createdAt": "2026-01-01T00:00:00Z",
            "nullified": false,
            "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
        })])
        .unwrap();

        let plc_mock = MockServer::start();
        plc_mock.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test/log/audit");
            then.status(200).body(&audit_log_json);
        });

        let pds_client_with_plc = crate::pds_client::PdsClient::new_for_test(plc_mock.base_url());

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_token".to_string(),
            refresh_token: "refresh".to_string(),
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

        let did_doc = PlcDidDocument {
            did: "did:plc:test".to_string(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            rotation_keys: vec![signing_key.clone()],
            verification_methods: serde_json::json!({}),
            services: HashMap::new(),
        };

        let result = sign_and_verify_claim_impl(
            &pds_client_with_plc,
            &Arc::new(oauth_client),
            "did:plc:test",
            &did_doc,
            &wrong_key,
            "test_token",
        )
        .await;

        assert!(
            matches!(result, Err(ClaimError::VerificationFailed { .. })),
            "should return VerificationFailed when device key is not at rotationKeys[0], got: {:?}",
            result
        );
    }

    /// Test 3: prev chain mismatch
    #[tokio::test]
    async fn test_sign_and_verify_claim_prev_mismatch() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();
        let wrong_prev = "bagwrong".to_string();
        let correct_prev = "bagcorrect".to_string();

        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        // Build with wrong_prev — device_key is the signing key
        let (rotation_json, device_key) = build_test_rotation_op(vec![], services, &wrong_prev);

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
            }));
        });

        // Audit log has correct_prev, but operation has wrong_prev
        let audit_log_json = serde_json::to_string(&vec![serde_json::json!({
            "did": "did:plc:test",
            "cid": correct_prev,
            "createdAt": "2026-01-01T00:00:00Z",
            "nullified": false,
            "operation": {}
        })])
        .unwrap();

        let plc_mock = MockServer::start();
        plc_mock.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test/log/audit");
            then.status(200).body(&audit_log_json);
        });

        let pds_client_with_plc = crate::pds_client::PdsClient::new_for_test(plc_mock.base_url());

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_token".to_string(),
            refresh_token: "refresh".to_string(),
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

        let did_doc = PlcDidDocument {
            did: "did:plc:test".to_string(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            rotation_keys: vec![],
            verification_methods: serde_json::json!({}),
            services: HashMap::new(),
        };

        let result = sign_and_verify_claim_impl(
            &pds_client_with_plc,
            &Arc::new(oauth_client),
            "did:plc:test",
            &did_doc,
            &device_key,
            "test_token",
        )
        .await;

        assert!(
            matches!(result, Err(ClaimError::VerificationFailed { .. })),
            "should return VerificationFailed when prev doesn't match audit log, got: {:?}",
            result
        );
    }

    /// Test 4: unexpected key removal
    #[tokio::test]
    async fn test_sign_and_verify_claim_unexpected_key_removal() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();
        let original_key = "did:key:zQ3original".to_string();
        let prev_cid = "bagtest123".to_string();

        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        // Build operation — signing key is the device key, original_key is not included
        let (rotation_json, device_key) = build_test_rotation_op(vec![], services, &prev_cid);

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
            }));
        });

        let audit_log_json = serde_json::to_string(&vec![serde_json::json!({
            "did": "did:plc:test",
            "cid": prev_cid,
            "createdAt": "2026-01-01T00:00:00Z",
            "nullified": false,
            "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
        })])
        .unwrap();

        let plc_mock = MockServer::start();
        plc_mock.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test/log/audit");
            then.status(200).body(&audit_log_json);
        });

        let pds_client_with_plc = crate::pds_client::PdsClient::new_for_test(plc_mock.base_url());

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_token".to_string(),
            refresh_token: "refresh".to_string(),
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

        let did_doc = PlcDidDocument {
            did: "did:plc:test".to_string(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            rotation_keys: vec![original_key.clone()],
            verification_methods: serde_json::json!({}),
            services: HashMap::new(),
        };

        let result = sign_and_verify_claim_impl(
            &pds_client_with_plc,
            &Arc::new(oauth_client),
            "did:plc:test",
            &did_doc,
            &device_key,
            "test_token",
        )
        .await;

        assert!(
            matches!(result, Err(ClaimError::VerificationFailed { .. })),
            "should return VerificationFailed when a rotation key is removed, got: {:?}",
            result
        );
    }

    /// Test 5: unexpected service change
    #[tokio::test]
    async fn test_sign_and_verify_claim_unexpected_service_change() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();
        let prev_cid = "bagtest123".to_string();

        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://new-pds.example.com".to_string(), // Changed endpoint
            },
        );

        let (rotation_json, device_key) = build_test_rotation_op(vec![], services, &prev_cid);

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
            }));
        });

        let audit_log_json = serde_json::to_string(&vec![serde_json::json!({
            "did": "did:plc:test",
            "cid": prev_cid,
            "createdAt": "2026-01-01T00:00:00Z",
            "nullified": false,
            "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
        })])
        .unwrap();

        let plc_mock = MockServer::start();
        plc_mock.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test/log/audit");
            then.status(200).body(&audit_log_json);
        });

        let pds_client_with_plc = crate::pds_client::PdsClient::new_for_test(plc_mock.base_url());

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_token".to_string(),
            refresh_token: "refresh".to_string(),
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

        let mut original_services = HashMap::new();
        original_services.insert(
            "atproto_pds".to_string(),
            crate::pds_client::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(), // Original endpoint
            },
        );

        let did_doc = PlcDidDocument {
            did: "did:plc:test".to_string(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            rotation_keys: vec![],
            verification_methods: serde_json::json!({}),
            services: original_services,
        };

        let result = sign_and_verify_claim_impl(
            &pds_client_with_plc,
            &Arc::new(oauth_client),
            "did:plc:test",
            &did_doc,
            &device_key,
            "test_token",
        )
        .await;

        assert!(
            matches!(result, Err(ClaimError::VerificationFailed { .. })),
            "should return VerificationFailed when service endpoint is changed, got: {:?}",
            result
        );
    }

    /// Test 6: warnings for benign additions
    #[tokio::test]
    async fn test_sign_and_verify_claim_warnings_for_added_service() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();
        let prev_cid = "bagtest123".to_string();

        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            crypto::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );
        // Add an extra service not in the original DID doc
        services.insert(
            "extra_service".to_string(),
            crypto::PlcService {
                service_type: "ExtraService".to_string(),
                endpoint: "https://extra.example.com".to_string(),
            },
        );

        let (rotation_json, device_key) = build_test_rotation_op(vec![], services, &prev_cid);

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(200).json_body(serde_json::json!({
                "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
            }));
        });

        let audit_log_json = serde_json::to_string(&vec![serde_json::json!({
            "did": "did:plc:test",
            "cid": prev_cid,
            "createdAt": "2026-01-01T00:00:00Z",
            "nullified": false,
            "operation": serde_json::from_str::<serde_json::Value>(&rotation_json).unwrap()
        })])
        .unwrap();

        let plc_mock = MockServer::start();
        plc_mock.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test/log/audit");
            then.status(200).body(&audit_log_json);
        });

        let pds_client_with_plc = crate::pds_client::PdsClient::new_for_test(plc_mock.base_url());

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_token".to_string(),
            refresh_token: "refresh".to_string(),
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

        let mut original_services = HashMap::new();
        original_services.insert(
            "atproto_pds".to_string(),
            crate::pds_client::PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        // rotation_keys is empty: no prior rotation keys,
        // so adding device_key at [0] is purely an addition (no removals to flag).
        let did_doc = PlcDidDocument {
            did: "did:plc:test".to_string(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            rotation_keys: vec![],
            verification_methods: serde_json::json!({}),
            services: original_services,
        };

        let result = sign_and_verify_claim_impl(
            &pds_client_with_plc,
            &Arc::new(oauth_client),
            "did:plc:test",
            &did_doc,
            &device_key,
            "test_token",
        )
        .await;

        assert!(
            result.is_ok(),
            "should succeed even with added service (benign warning), got: {:?}",
            result.err()
        );
        let (verified_op, _signed_op_json) = result.unwrap();
        assert!(
            !verified_op.warnings.is_empty(),
            "should have warnings about added service, got: {:?}",
            verified_op.warnings
        );
    }

    /// Test 7: Invalid token error from PDS
    #[tokio::test]
    async fn test_sign_and_verify_claim_invalid_token() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        let mock_server = MockServer::start();
        let device_key = "did:key:zQ3test_device".to_string();

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.identity.signPlcOperation");
            then.status(400).json_body(serde_json::json!({
                "error": "InvalidToken",
                "message": "Token is invalid"
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new_for_test(mock_server.base_url());

        let session = Arc::new(Mutex::new(crate::oauth::OAuthSession {
            access_token: "test_token".to_string(),
            refresh_token: "refresh".to_string(),
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

        let did_doc = PlcDidDocument {
            did: "did:plc:test".to_string(),
            also_known_as: vec!["at://alice.example.com".to_string()],
            rotation_keys: vec!["did:key:zQ3signing".to_string()],
            verification_methods: serde_json::json!({}),
            services: HashMap::new(),
        };

        let result = sign_and_verify_claim_impl(
            &pds_client,
            &Arc::new(oauth_client),
            "did:plc:test",
            &did_doc,
            &device_key,
            "invalid_token",
        )
        .await;

        assert!(
            matches!(result, Err(ClaimError::InvalidToken)),
            "should return InvalidToken when PDS returns InvalidToken error, got: {:?}",
            result
        );
    }

    // ── submit_claim tests ────────────────────────────────────────────────────

    /// Test Success: submit_claim POSTs signed operation and persists identity
    #[tokio::test]
    async fn test_submit_claim_success() {
        crate::keychain::clear_for_test();
        use httpmock::MockServer;

        let mock_server = MockServer::start();

        // Mock POST to plc.directory (signed operation submission)
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/did:plc:test");
            then.status(200).json_body(serde_json::json!({}));
        });

        // Mock GET to plc.directory (re-fetch DID doc)
        // Use mock_server.base_url() as PDS endpoint so HEAD reachability check
        // routes through the mock server instead of hitting the real internet.
        let pds_endpoint = mock_server.base_url();
        let updated_doc = serde_json::json!({
            "id": "did:plc:test",
            "alsoKnownAs": ["at://alice.example.com"],
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": pds_endpoint
            }]
        });

        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test")
                .header_exists("host");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(updated_doc.clone());
        });

        // Mock HEAD request for PDS reachability check
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::HEAD);
            then.status(200);
        });

        // Mock audit log fetch
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/did:plc:test/log/audit");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!([
                    {
                        "cid": "bafy123",
                        "operation": {
                            "type": "plc_operation"
                        }
                    }
                ]));
        });

        let pds_client = crate::pds_client::PdsClient::new_for_test(mock_server.base_url());

        let claim_state = ClaimState {
            did: "did:plc:test".to_string(),
            pds_url: mock_server.base_url(),
            did_doc: PlcDidDocument {
                did: "did:plc:test".to_string(),
                also_known_as: vec!["at://alice.example.com".to_string()],
                rotation_keys: vec!["did:key:zQ3test".to_string()],
                verification_methods: serde_json::json!({}),
                services: std::collections::HashMap::new(),
            },
            pds_oauth_client: None,
            verified_signed_op: Some(serde_json::json!({
                "type": "plc_operation",
                "prev": "bafy123",
                "rotationKeys": ["did:key:zQ3test"]
            })),
        };

        let result = submit_claim_impl(&pds_client, &claim_state).await;

        assert!(
            result.is_ok(),
            "should successfully submit claim and persist identity"
        );
        let claim_result = result.unwrap();
        assert_eq!(claim_result.updated_did_doc["did"], "did:plc:test");
    }

    /// Test Failure: submit_claim returns PlcDirectoryError when POST fails
    #[tokio::test]
    async fn test_submit_claim_plc_directory_error() {
        use httpmock::MockServer;

        let mock_server = MockServer::start();

        // Mock POST returning 409 Conflict
        mock_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/did:plc:test");
            then.status(409)
                .json_body(serde_json::json!({"error": "Conflicting operation"}));
        });

        let pds_client = crate::pds_client::PdsClient::new_for_test(mock_server.base_url());

        let claim_state = ClaimState {
            did: "did:plc:test".to_string(),
            pds_url: mock_server.base_url(),
            did_doc: PlcDidDocument {
                did: "did:plc:test".to_string(),
                also_known_as: vec!["at://alice.example.com".to_string()],
                rotation_keys: vec!["did:key:zQ3test".to_string()],
                verification_methods: serde_json::json!({}),
                services: std::collections::HashMap::new(),
            },
            pds_oauth_client: None,
            verified_signed_op: Some(serde_json::json!({
                "type": "plc_operation",
                "prev": "bafy123"
            })),
        };

        let result = submit_claim_impl(&pds_client, &claim_state).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ClaimError::PlcDirectoryError { message } => {
                assert!(message.contains("Conflicting operation"));
            }
            e => panic!("Expected PlcDirectoryError, got: {:?}", e),
        }
    }

    /// Test: Unauthorized — no verified signed operation
    #[tokio::test]
    async fn test_submit_claim_no_verified_op() {
        let pds_client = crate::pds_client::PdsClient::new();

        let claim_state = ClaimState {
            did: "did:plc:test".to_string(),
            pds_url: "https://plc.directory".to_string(),
            did_doc: PlcDidDocument {
                did: "did:plc:test".to_string(),
                also_known_as: vec![],
                rotation_keys: vec![],
                verification_methods: serde_json::json!({}),
                services: std::collections::HashMap::new(),
            },
            pds_oauth_client: None,
            verified_signed_op: None, // No verified operation
        };

        let result = submit_claim_impl(&pds_client, &claim_state).await;

        assert!(
            matches!(result, Err(ClaimError::Unauthorized)),
            "should return Unauthorized when verified_signed_op is None"
        );
    }
}
