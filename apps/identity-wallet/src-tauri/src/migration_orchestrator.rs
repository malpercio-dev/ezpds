// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Functional Core: MigrationPhase, OutboundMigrationState, MigrationError, PendingSourceLogin,
//                  ensure_phase_did (pure gate function, no network, no side effects)
// Imperative Shell: prepare_migration, prepare_source_auth, complete_source_auth,
//                   create_destination_account (Tauri commands; Tasks 4-6 in Phase 3)

use serde::Serialize;
use std::sync::Arc;
use tauri::Emitter;
use crate::oauth_client::OAuthClient;

// ── Phase enum ─────────────────────────────────────────────────────────────

/// Migration phase tracking the outbound migration flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum MigrationPhase {
    Resolved,
    SourceAuthed,
    DestCreated,
    RepoTransferred,
    BlobsTransferred,
    PreferencesTransferred,
    Verified,
    IdentityArmed,
    Finalized,
}

// ── State types ────────────────────────────────────────────────────────────

/// Outbound migration state persisted in `AppState`.
///
/// Resolved by `prepare_migration` and used by subsequent migration commands
/// within the same migration session. In-memory only; an app kill restarts from
/// `prepare_migration`.
#[derive(Clone)]
pub struct OutboundMigrationState {
    /// The DID being migrated
    pub did: String,
    /// Source PDS URL (resolved by `prepare_migration` via `discover_pds`)
    pub source_pds_url: String,
    /// Destination PDS URL (provided by caller to `prepare_migration`)
    pub dest_pds_url: String,
    /// Destination server DID (from `describeServer`, used as `aud` for `getServiceAuth`)
    pub dest_did: String,
    /// Handle (preserved from source; extracted from `plc_doc.also_known_as`)
    pub handle: String,
    /// OAuth client for source PDS (set after `prepare_source_auth`/`complete_source_auth`)
    /// Wrapped in Arc to allow cloning out of the Mutex without holding the lock
    /// across network calls.
    pub source_client: Option<Arc<OAuthClient>>,
    /// OAuth client for destination PDS (set after `create_destination_account`)
    /// Wrapped in Arc to allow cloning out of the Mutex without holding the lock
    /// across network calls.
    pub dest_client: Option<Arc<OAuthClient>>,
    /// Current phase in the migration flow
    pub phase: MigrationPhase,
}

/// State parked in `AppState.pending_source_login` between `prepare_source_auth` and
/// `complete_source_auth` while the ASWebAuthenticationSession runs. Holds the discovered
/// auth-server metadata plus the secrets the token exchange needs — none of it is serialized to
/// the webview (twin of `claim::PendingPdsLogin`).
pub struct PendingSourceLogin {
    /// The DID this auth was prepared for — re-checked against `OutboundMigrationState` in
    /// `complete_source_auth` so a concurrent `prepare_migration` can't attach this client
    /// to a different migration.
    pub did: String,
    /// Source PDS URL this auth was prepared for (re-checked alongside `did`).
    pub source_pds_url: String,
    /// PKCE code_verifier for the token exchange.
    pub pkce_verifier: String,
    /// CSRF state — validated against the callback URL's `state` param.
    pub csrf_state: String,
    /// Auth-server metadata discovered from the source PDS (needed for the token exchange).
    pub metadata: crate::pds_client::AuthServerMetadata,
    /// OAuth `client_id` for the source PDS.
    pub client_id: String,
    /// Source PDS base URL the resulting `OAuthClient` targets.
    pub oauth_client_pds_url: String,
}

// ── Error types ────────────────────────────────────────────────────────────

/// Error returned by outbound migration commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` matching the wallet's
/// established error contract (same pattern as `ClaimError`, `CreateAccountError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationError {
    /// Migration not ready: state absent, DID mismatch, or phase too low
    #[error("migration not ready: {message}")]
    MigrationNotReady { message: String },
    /// Destination PDS is unreachable
    #[error("destination unreachable: {message}")]
    DestinationUnreachable { message: String },
    /// Source PDS OAuth authentication failed
    #[error("source auth failed: {message}")]
    SourceAuthFailed { message: String },
    /// Service authentication (getServiceAuth) failed
    #[error("service auth failed: {message}")]
    ServiceAuthFailed { message: String },
    /// Account creation (createAccount) failed
    #[error("account creation failed: {message}")]
    AccountCreationFailed { message: String },
    /// Destination account exists but session was lost (app kill; restart migration)
    #[error("destination conflict: {message}")]
    DestinationConflict { message: String },
    /// Repository transfer failed
    #[error("repo transfer failed: {message}")]
    RepoTransferFailed { message: String },
    /// Blob transfer failed
    #[error("blob transfer failed: {message}")]
    BlobTransferFailed { message: String },
    /// Preferences transfer failed
    #[error("preferences transfer failed: {message}")]
    PreferencesTransferFailed { message: String },
    /// Verification incomplete: imported entries do not match expected count
    #[error("verification incomplete")]
    VerificationIncomplete { imported: u64, expected: u64 },
    /// Identity activation failed
    #[error("activation failed: {message}")]
    ActivationFailed { message: String },
    /// Account deactivation failed
    #[error("deactivation failed: {message}")]
    DeactivationFailed { message: String },
    /// Network error during migration
    #[error("network error: {message}")]
    NetworkError { message: String },
}

// ── Pure prerequisite gate ─────────────────────────────────────────────────

/// Pure prerequisite gate: state present, DID matches, and phase is at least `required`.
/// No network, no side effects — this is what makes AC1.3/AC1.4 side-effect-free and
/// unit-testable.
pub(crate) fn ensure_phase_did<'a>(
    state: &'a Option<OutboundMigrationState>,
    did: &str,
    required: MigrationPhase,
) -> Result<&'a OutboundMigrationState, MigrationError> {
    let Some(s) = state.as_ref() else {
        return Err(MigrationError::MigrationNotReady {
            message: "no migration in progress".into(),
        });
    };
    if s.did != did {
        return Err(MigrationError::MigrationNotReady {
            message: "did does not match active migration".into(),
        });
    }
    if s.phase < required {
        return Err(MigrationError::MigrationNotReady {
            message: format!("expected phase >= {:?}, found {:?}", required, s.phase),
        });
    }
    Ok(s)
}

// ── Task 4: prepare_migration ──────────────────────────────────────────────

/// Resolve destination + source PDS and store migration state at phase Resolved.
///
/// 1. discover_pds(did) → source_pds_url + handle (from also_known_as, strip "at://")
/// 2. describe_server(dest_pds_url) → dest_did (map PdsUnreachable → DESTINATION_UNREACHABLE)
/// 3. store fresh OutboundMigrationState at phase Resolved (in-memory only; app kill restarts)
#[tauri::command]
pub async fn prepare_migration(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    dest_pds_url: String,
) -> Result<(), MigrationError> {
    let result = prepare_migration_impl(
        state.pds_client(),
        &did,
        &dest_pds_url,
    )
    .await?;

    // Store fresh state at phase Resolved (in-memory only; app kill restarts from prepare_migration)
    *state.orchestration_state.lock().await = Some(result);
    Ok(())
}

/// Pure core: discover source + dest, return fresh OutboundMigrationState at Resolved.
async fn prepare_migration_impl(
    pds_client: &crate::pds_client::PdsClient,
    did: &str,
    dest_pds_url: &str,
) -> Result<OutboundMigrationState, MigrationError> {
    tracing::info!(did = %did, dest_url = %dest_pds_url, "prepare_migration: discovering source + destination");

    // 1. Discover source PDS
    let (source_pds_url, plc_doc) = pds_client
        .discover_pds(did)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "failed to discover source PDS");
            // Preserve the unreachable distinction in the message (there is no SourceUnreachable
            // variant; AC1.5 only names the destination, but a bare NetworkError is less actionable).
            match e {
                crate::pds_client::PdsClientError::PdsUnreachable { .. } => {
                    MigrationError::NetworkError {
                        message: format!("source PDS unreachable: {}", e),
                    }
                }
                other => MigrationError::NetworkError {
                    message: format!("source discovery failed: {}", other),
                },
            }
        })?;

    // Extract handle from also_known_as (format: at://handle). A DID document with no at:// entry
    // is a data problem (unusable identity), not a network error — surface it as such.
    let handle = extract_handle_from_also_known_as(&plc_doc.also_known_as)
        .ok_or_else(|| {
            tracing::error!(did = %did, "no at:// handle in also_known_as");
            MigrationError::AccountCreationFailed {
                message: "source DID document has no at:// handle in alsoKnownAs".into(),
            }
        })?;

    // 2. Describe destination server
    let dest_describe = pds_client
        .describe_server(dest_pds_url)
        .await
        .map_err(|e| {
            tracing::error!(dest_url = %dest_pds_url, error = %e, "describe_server failed");
            match e {
                crate::pds_client::PdsClientError::PdsUnreachable { .. } => {
                    MigrationError::DestinationUnreachable {
                        message: format!("destination unreachable: {}", e),
                    }
                }
                other => MigrationError::NetworkError {
                    message: format!("describe_server failed: {}", other),
                },
            }
        })?;

    tracing::info!(
        source_url = %source_pds_url,
        dest_url = %dest_pds_url,
        dest_did = %dest_describe.did,
        handle = %handle,
        "migration resolved"
    );

    // 3. Build fresh state at Resolved phase
    Ok(OutboundMigrationState {
        did: did.to_string(),
        source_pds_url,
        dest_pds_url: dest_pds_url.to_string(),
        dest_did: dest_describe.did,
        handle,
        source_client: None,
        dest_client: None,
        phase: MigrationPhase::Resolved,
    })
}

// ── Task 5: Source-PDS OAuth ───────────────────────────────────────────────

/// Phase 1 of source-PDS login: discover auth server + PKCE + PAR → authorize URL.
/// Mirrors claim::prepare_pds_auth (see claim.rs 346–451 for details).
///
/// Gate: ensure_phase_did(..., Resolved) → read source_pds_url, drop lock
/// Then: discover_auth_server, generate PKCE+CSRF, DPoP keypair, PAR, park PendingSourceLogin
#[tauri::command]
pub async fn prepare_source_auth(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<crate::oauth::OAuthPrepared, MigrationError> {
    tracing::info!(did = %did, "prepare_source_auth: authenticating with source PDS");

    // Gate: ensure phase + DID, extract source_pds_url
    let source_pds_url = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::Resolved).map_err(|e| {
            tracing::warn!("prepare_source_auth: phase gate failed: {}", e);
            e
        })?;
        mig.source_pds_url.clone()
    }; // lock released

    let pds_client = state.pds_client();

    // Discover auth server metadata from the source PDS
    tracing::debug!(source_url = %source_pds_url, "discovering source auth server");
    let metadata = pds_client
        .discover_auth_server(&source_pds_url)
        .await
        .map_err(|e| {
            tracing::error!(source_url = %source_pds_url, error = %e, "auth server discovery failed");
            MigrationError::SourceAuthFailed {
                message: format!("failed to discover auth server: {}", e),
            }
        })?;
    tracing::debug!(issuer = %metadata.issuer, "auth server metadata discovered");

    // PKCE + CSRF state
    let (pkce_verifier, pkce_challenge) = crate::oauth::pkce::generate();
    let csrf_state = crate::oauth::generate_state_param();

    // DPoP keypair + thumbprint
    let dpop = crate::oauth::DPoPKeypair::get_or_create().map_err(|e| {
        tracing::error!(error = %e, "DPoP keypair creation failed");
        MigrationError::SourceAuthFailed {
            message: "failed to create DPoP keypair".to_string(),
        }
    })?;
    let dpop_jkt = dpop.public_jwk_thumbprint();

    // PAR with nonce retry (reuse claim.rs helper pattern)
    let par_htu = metadata
        .pushed_authorization_request_endpoint
        .as_ref()
        .cloned()
        .unwrap_or_else(|| format!("{}/oauth/par", metadata.issuer));

    let client_metadata_base_url = state.custos_client().base_url_str().to_string();
    let client_id = crate::pds_client::client_id_for_pds(&client_metadata_base_url);
    let oauth_client_pds_url = source_pds_url.clone();

    let par_resp = source_par_with_retry(SourceParWithRetryParams {
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

    // Build the authorize URL
    let auth_url = crate::pds_client::PdsClient::build_pds_authorize_url(
        &metadata,
        &par_resp.request_uri,
        Some(&did),
        &client_id,
    );

    // Park the secrets in pending_source_login
    *state.pending_source_login.lock().unwrap() = Some(PendingSourceLogin {
        did: did.clone(),
        source_pds_url: source_pds_url.clone(),
        pkce_verifier,
        csrf_state,
        metadata,
        client_id,
        oauth_client_pds_url,
    });

    Ok(crate::oauth::OAuthPrepared {
        auth_url,
        callback_scheme: "dev.malpercio.identitywallet".to_string(),
    })
}

/// Helper for PAR with DPoP nonce retry (mirrors claim.rs pattern).
struct SourceParWithRetryParams<'a> {
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

async fn source_par_with_retry(
    params: SourceParWithRetryParams<'_>,
) -> Result<crate::pds_client::PdsParResponse, MigrationError> {
    let par_proof = params
        .dpop
        .make_proof("POST", params.par_htu, None, None)
        .map_err(|e| {
            tracing::error!(error = %e, "DPoP proof generation failed for PAR");
            MigrationError::SourceAuthFailed {
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
            return Err(MigrationError::SourceAuthFailed {
                message: format!("PAR failed: {}", e),
            });
        }
    }

    // Nonce retry: extract nonce from DPoP-Nonce header
    let raw_par_url = params
        .metadata
        .pushed_authorization_request_endpoint
        .clone()
        .unwrap_or_else(|| format!("{}/oauth/par", params.metadata.issuer));

    let nonce_proof = params
        .dpop
        .make_proof("POST", params.par_htu, None, None)
        .map_err(|_| MigrationError::SourceAuthFailed {
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
        .map_err(|e| MigrationError::SourceAuthFailed {
            message: format!("PAR nonce discovery failed: {}", e),
        })?;

    let nonce = nonce_resp
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let Some(nonce_val) = nonce else {
        tracing::error!("PAR returned use_dpop_nonce but no DPoP-Nonce header");
        return Err(MigrationError::SourceAuthFailed {
            message: "PAR requires nonce but server did not provide one".to_string(),
        });
    };

    tracing::debug!(nonce = %nonce_val, "retrying PAR with DPoP nonce");
    let retry_proof = params
        .dpop
        .make_proof("POST", params.par_htu, Some(&nonce_val), None)
        .map_err(|e| {
            tracing::error!(error = %e, "DPoP proof with nonce failed");
            MigrationError::SourceAuthFailed {
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
            MigrationError::SourceAuthFailed {
                message: format!("PAR retry failed: {}", e),
            }
        })
}

/// Phase 2 of source-PDS login: exchange code + store OAuthClient, advance to SourceAuthed.
/// Mirrors claim::complete_pds_auth (claim.rs 458–549).
#[tauri::command]
pub async fn complete_source_auth(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    callback_url: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "complete_source_auth: exchanging code");

    // Take the parked flow
    let pending = state
        .pending_source_login
        .lock()
        .unwrap()
        .take()
        .ok_or(MigrationError::SourceAuthFailed {
            message: "no pending source login".into(),
        })?;

    // Validate DID matches parked state
    if pending.did != did {
        tracing::warn!("complete_source_auth: did mismatch with parked state");
        return Err(MigrationError::SourceAuthFailed {
            message: "did mismatch with pending auth".into(),
        });
    }

    // Parse + CSRF-validate callback URL
    let (code, callback_state) = crate::oauth::parse_callback_url(&callback_url).map_err(|_| {
        MigrationError::SourceAuthFailed {
            message: "invalid callback URL".into(),
        }
    })?;
    if callback_state != pending.csrf_state {
        tracing::error!("complete_source_auth: CSRF state mismatch");
        return Err(MigrationError::SourceAuthFailed {
            message: "csrf state mismatch".into(),
        });
    }

    // DPoP keypair for token exchange
    let pds_client = state.pds_client();
    let dpop = crate::oauth::DPoPKeypair::get_or_create().map_err(|e| {
        tracing::error!(error = %e, "DPoP keypair creation failed");
        MigrationError::SourceAuthFailed {
            message: "failed to create DPoP keypair".to_string(),
        }
    })?;

    // Token exchange with nonce retry
    let (token_resp, _initial_nonce) = source_exchange_code_with_retry(
        pds_client,
        &dpop,
        &code,
        &pending.pkce_verifier,
        &pending.metadata,
        &pending.client_id,
    )
    .await?;

    // Build OAuthClient and store in orchestration_state
    let session = std::sync::Arc::new(std::sync::Mutex::new(crate::oauth::OAuthSession {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MigrationError::SourceAuthFailed {
                message: "system time error".to_string(),
            })?
            .as_secs()
            + token_resp.expires_in,
        dpop_nonce: _initial_nonce,
    }));

    let oauth_client = OAuthClient::new(session, pending.oauth_client_pds_url.clone()).map_err(|_| {
        MigrationError::SourceAuthFailed {
            message: "failed to create OAuth client".to_string(),
        }
    })?;

    // Update orchestration state: store source_client, advance phase
    let mut orchestration = state.orchestration_state.lock().await;
    if let Some(ref mut mig) = orchestration.as_mut() {
        // Double-check DID matches (defense-in-depth)
        if mig.did != did {
            drop(orchestration);
            tracing::warn!("complete_source_auth: orchestration state did mismatch");
            return Err(MigrationError::SourceAuthFailed {
                message: "did mismatch with orchestration state".into(),
            });
        }
        mig.source_client = Some(std::sync::Arc::new(oauth_client));
        mig.phase = MigrationPhase::SourceAuthed;
    } else {
        drop(orchestration);
        return Err(MigrationError::SourceAuthFailed {
            message: "no orchestration state to update".into(),
        });
    }
    drop(orchestration);

    // Emit event (vestigial but preserved)
    app.emit("source_auth_ready", ()).map_err(|e| {
        tracing::error!(error = %e, "failed to emit source_auth_ready event");
        MigrationError::NetworkError {
            message: "event emission failed".to_string(),
        }
    })?;

    Ok(())
}

/// Helper for token exchange with nonce retry.
async fn source_exchange_code_with_retry(
    pds_client: &crate::pds_client::PdsClient,
    dpop: &crate::oauth::DPoPKeypair,
    code: &str,
    pkce_verifier: &str,
    metadata: &crate::pds_client::AuthServerMetadata,
    client_id: &str,
) -> Result<(crate::http::TokenResponse, Option<String>), MigrationError> {
    let token_htu = &metadata.token_endpoint;
    tracing::debug!(token_endpoint = %token_htu, "starting source token exchange");
    let proof = dpop
        .make_proof("POST", token_htu, None, None)
        .map_err(|e| {
            tracing::error!(error = %e, "DPoP proof for token exchange failed");
            MigrationError::SourceAuthFailed {
                message: "failed to create DPoP proof for token exchange".to_string(),
            }
        })?;

    let resp = pds_client
        .pds_token_exchange(metadata, code, pkce_verifier, &proof, client_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "source token exchange request failed");
            MigrationError::SourceAuthFailed {
                message: format!("token exchange failed: {}", e),
            }
        })?;

    tracing::debug!(status = %resp.status(), "source token exchange response received");
    if resp.status().as_u16() == 200 {
        let nonce = resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let token = resp
            .json::<crate::http::TokenResponse>()
            .await
            .map_err(|e| MigrationError::SourceAuthFailed {
                message: format!("token response parsing failed: {}", e),
            })?;
        return Ok((token, nonce));
    }

    // Nonce retry logic (mirrors claim.rs)
    let nonce = resp
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let error_body = resp.text().await.unwrap_or_else(|_| "{}".to_string());
    tracing::debug!(status = "non-200", body = %error_body, "token exchange needs retry or failed");

    if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&error_body) {
        if error_json.get("error").and_then(|v| v.as_str()) == Some("use_dpop_nonce") {
            if let Some(nonce_val) = nonce {
                tracing::debug!(nonce = %nonce_val, "retrying token exchange with server nonce");
                let proof_with_nonce = dpop
                    .make_proof("POST", token_htu, Some(&nonce_val), None)
                    .map_err(|_| MigrationError::SourceAuthFailed {
                        message: "failed to create DPoP proof with nonce".to_string(),
                    })?;

                let retry_resp = pds_client
                    .pds_token_exchange(metadata, code, pkce_verifier, &proof_with_nonce, client_id)
                    .await
                    .map_err(|e| MigrationError::SourceAuthFailed {
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
                        .map_err(|e| MigrationError::SourceAuthFailed {
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
                    return Err(MigrationError::SourceAuthFailed {
                        message: format!("token exchange retry returned {}: {}", status, body),
                    });
                }
            }
        }
    }

    tracing::error!(body = %error_body, "token exchange failed with non-retryable error");
    Err(MigrationError::SourceAuthFailed {
        message: format!(
            "token exchange returned non-success response: {}",
            error_body
        ),
    })
}

// ── Task 6: create_destination_account ──────────────────────────────────────

/// Pure core: reserve key, mint service-auth, create account, return Bearer client.
/// Extracted for unit testability with mocked servers.
async fn create_destination_account_impl(
    pds_client: &crate::pds_client::PdsClient,
    source_client: &Arc<OAuthClient>,
    dest_pds_url: &str,
    dest_did: &str,
    did: &str,
    handle: &str,
    email: &str,
    invite_code: Option<String>,
    existing_dest_client: Option<Arc<OAuthClient>>,
) -> Result<Arc<OAuthClient>, MigrationError> {
    // 0. Idempotent fast path: if dest_client already exists, return it.
    //    Borrow (don't move) so `existing_dest_client` survives to the DidAlreadyExists arm below.
    if let Some(client) = &existing_dest_client {
        tracing::info!(did = %did, "create_destination_account: dest_client exists, returning cached");
        return Ok(client.clone());
    }

    // 1. Reserve signing key at destination
    tracing::debug!(did = %did, dest_url = %dest_pds_url, "reserving signing key at destination");
    let _reserved_key = pds_client
        .reserve_signing_key(dest_pds_url, did)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "reserveSigningKey failed");
            MigrationError::AccountCreationFailed {
                message: format!("failed to reserve signing key: {}", e),
            }
        })?;

    // 2. Get service auth token from source PDS
    tracing::debug!(did = %did, "getting service auth from source");
    let service_auth_token = crate::pds_client::get_service_auth(
        source_client,
        dest_did,
        "com.atproto.server.createAccount",
    )
    .await
    .map_err(|e| {
        tracing::error!(did = %did, error = %e, "getServiceAuth failed");
        MigrationError::ServiceAuthFailed {
            message: format!("failed to get service auth: {}", e),
        }
    })?;

    // 3. One-shot Bearer client carrying the service-auth token
    let sa_client = OAuthClient::new_bearer(
        service_auth_token.token.clone(),
        String::new(),
        dest_pds_url.into(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create service-auth Bearer client");
        MigrationError::AccountCreationFailed {
            message: "failed to create Bearer client".to_string(),
        }
    })?;

    // 4. Create account migration (deactivated account)
    tracing::info!(
        did = %did,
        handle = %handle,
        "creating destination account (deactivated)"
    );

    let req = crate::pds_client::CreateAccountMigrationRequest {
        handle: handle.into(),
        email: email.into(),
        did: did.into(),
        invite_code,
    };

    match crate::pds_client::create_account_migration(&sa_client, &req).await {
        Ok(resp) => {
            // 5. Build destination Bearer client from the returned session tokens.
            let dest_client =
                OAuthClient::new_bearer(resp.access_jwt, resp.refresh_jwt, dest_pds_url.into())
                    .map_err(|e| {
                        tracing::error!(error = %e, "failed to create destination Bearer client from response");
                        MigrationError::AccountCreationFailed {
                            message: "failed to create destination client".to_string(),
                        }
                    })?;
            tracing::info!(did = %did, "destination account created successfully");
            Ok(Arc::new(dest_client))
        }
        // The account already exists at the destination. If we still hold an in-memory dest_client
        // we tolerate it (AC5.1, idempotent re-establish — the fast path above usually covers this).
        // If not, the destination session was lost (only possible after an app kill wiped in-memory
        // state), so the flow must restart from prepare_migration (AC10.3 / DESTINATION_CONFLICT).
        Err(crate::pds_client::PdsClientError::DidAlreadyExists) => match existing_dest_client {
            Some(client) => {
                tracing::info!(did = %did, "createAccount 409 but dest_client held; tolerating (AC5.1)");
                Ok(client)
            }
            None => {
                tracing::error!(did = %did, "createAccount 409 with no dest_client; destination conflict");
                Err(MigrationError::DestinationConflict {
                    message: "account exists but session was lost (app kill); restart migration".into(),
                })
            }
        },
        Err(other) => {
            tracing::error!(did = %did, error = %other, "createAccount failed");
            Err(MigrationError::AccountCreationFailed {
                message: format!("account creation failed: {}", other),
            })
        }
    }
}

/// Tauri command: create destination account or re-establish cached session.
///
/// Gate: ensure_phase_did(..., SourceAuthed) → extract source_client, dest_pds_url,
/// dest_did, handle, existing dest_client; drop lock; call _impl; re-lock to update.
#[tauri::command]
pub async fn create_destination_account(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    email: String,
    invite_code: Option<String>,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "create_destination_account command");

    // Gate + extract dependencies
    let (source_client, dest_pds_url, dest_did, handle, existing_dest_client) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::SourceAuthed).map_err(|e| {
            tracing::warn!("create_destination_account: phase gate failed: {}", e);
            e
        })?;

        (
            mig.source_client.clone(),
            mig.dest_pds_url.clone(),
            mig.dest_did.clone(),
            mig.handle.clone(),
            mig.dest_client.clone(),
        )
    }; // lock released

    let Some(source_client) = source_client else {
        tracing::error!(did = %did, "create_destination_account: source_client not found");
        return Err(MigrationError::SourceAuthFailed {
            message: "source client not authenticated".into(),
        });
    };

    let pds_client = state.pds_client();

    // Call impl (pure, testable)
    let dest_client = create_destination_account_impl(
        pds_client,
        &source_client,
        &dest_pds_url,
        &dest_did,
        &did,
        &handle,
        &email,
        invite_code,
        existing_dest_client,
    )
    .await?;

    // Update orchestration state
    let mut orchestration = state.orchestration_state.lock().await;
    if let Some(ref mut mig) = orchestration.as_mut() {
        // Defense-in-depth DID check
        if mig.did != did {
            drop(orchestration);
            tracing::warn!("create_destination_account: orchestration state did mismatch");
            return Err(MigrationError::MigrationNotReady {
                message: "did mismatch with orchestration state".into(),
            });
        }
        mig.dest_client = Some(dest_client);
        mig.phase = MigrationPhase::DestCreated;
    } else {
        drop(orchestration);
        return Err(MigrationError::MigrationNotReady {
            message: "orchestration state lost".into(),
        });
    }

    tracing::info!(did = %did, "destination account created and stored");
    Ok(())
}

// ── Task 1: transfer_repo ──────────────────────────────────────────────────

/// Pure core: fetch the source repo CAR (auth:none) and import it into the destination
/// (Bearer). Extracted for unit testability with mocked servers.
async fn transfer_repo_impl(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: &str,
    did: &str,
) -> Result<(), MigrationError> {
    // 1. Fetch repository CAR from source
    tracing::debug!(did = %did, source_url = %source_pds_url, "fetching repository from source");
    let car = pds_client
        .fetch_repo_car(source_pds_url, did)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "failed to fetch repository CAR");
            MigrationError::RepoTransferFailed {
                message: format!("failed to fetch repository: {}", e),
            }
        })?;

    // 2. Import repository into destination
    tracing::debug!(did = %did, car_len = %car.len(), "importing repository to destination");
    crate::pds_client::import_repo(dest_client, car)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "failed to import repository");
            MigrationError::RepoTransferFailed {
                message: format!("failed to import repository: {}", e),
            }
        })?;

    Ok(())
}

/// Tauri command: fetch repository from source PDS and import into destination.
///
/// Gate: ensure_phase_did(..., DestCreated) → clone dest_client, read source_pds_url; drop lock
/// Then: fetch_repo_car(source) → import_repo(dest); re-lock + advance to RepoTransferred
#[tauri::command]
pub async fn transfer_repo(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "transfer_repo: fetching and importing repository");

    // Gate + extract dependencies
    let (dest_client, source_pds_url) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::DestCreated).map_err(|e| {
            tracing::warn!("transfer_repo: phase gate failed: {}", e);
            e
        })?;

        (mig.dest_client.clone(), mig.source_pds_url.clone())
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "transfer_repo: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    let pds_client = state.pds_client();

    // Fetch source CAR + import into destination (pure core, unit-tested).
    transfer_repo_impl(pds_client, &dest_client, &source_pds_url, &did).await?;

    // 3. Update orchestration state: advance phase to RepoTransferred
    let mut orchestration = state.orchestration_state.lock().await;
    if let Some(ref mut mig) = orchestration.as_mut() {
        // Defense-in-depth DID check
        if mig.did != did {
            drop(orchestration);
            tracing::warn!("transfer_repo: orchestration state did mismatch");
            return Err(MigrationError::MigrationNotReady {
                message: "did mismatch with orchestration state".into(),
            });
        }
        mig.phase = MigrationPhase::RepoTransferred;
    } else {
        drop(orchestration);
        return Err(MigrationError::MigrationNotReady {
            message: "orchestration state lost".into(),
        });
    }

    tracing::info!(did = %did, "repository transferred successfully");
    Ok(())
}

// ── Task 2: transfer_blobs ─────────────────────────────────────────────────

/// Pure core: drain the destination's missing-blob set via cursor pagination.
///
/// Loops: list_missing_blobs(cursor) → if empty, done; for each blob, fetch from source
/// and upload to dest; advance cursor and repeat. Any leg failing aborts with
/// BlobTransferFailed WITHOUT advancing the phase, so the whole step is retry-safe (AC2.6).
async fn drain_missing_blobs(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: &str,
    did: &str,
) -> Result<(), MigrationError> {
    let mut cursor: Option<String> = None;
    loop {
        let page = crate::pds_client::list_missing_blobs(dest_client, cursor.as_deref())
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "list_missing_blobs failed");
                MigrationError::BlobTransferFailed {
                    message: format!("failed to list missing blobs: {}", e),
                }
            })?;

        // AC2.3 / AC2.5: terminate when page is empty
        if page.blobs.is_empty() {
            tracing::debug!(did = %did, "blob drain complete: missing set is empty");
            return Ok(());
        }

        // Upload each blob on this page
        for blob in &page.blobs {
            tracing::debug!(did = %did, cid = %blob.cid, "fetching blob from source");
            let bytes = pds_client
                .fetch_blob(source_pds_url, did, &blob.cid)
                .await
                .map_err(|e| {
                    tracing::error!(did = %did, cid = %blob.cid, error = %e, "fetch_blob failed");
                    MigrationError::BlobTransferFailed {
                        message: format!("failed to fetch blob {}: {}", blob.cid, e),
                    }
                })?;

            tracing::debug!(did = %did, cid = %blob.cid, bytes_len = %bytes.len(), "uploading blob to destination");
            crate::pds_client::upload_blob(dest_client, "application/octet-stream", bytes)
                .await
                .map_err(|e| {
                    tracing::error!(did = %did, cid = %blob.cid, error = %e, "upload_blob failed");
                    MigrationError::BlobTransferFailed {
                        message: format!("failed to upload blob {}: {}", blob.cid, e),
                    }
                })?;
        }

        // Walk pages: advance cursor or loop with None (will re-list and see empty on success)
        cursor = page.cursor;
    }
}

/// Tauri command: drain missing blobs from destination via cursor-paginated loop.
///
/// Gate: ensure_phase_did(..., RepoTransferred) → clone dest_client, read source_pds_url; drop lock
/// Then: drain_missing_blobs; re-lock + advance to BlobsTransferred
#[tauri::command]
pub async fn transfer_blobs(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "transfer_blobs: draining missing blobs");

    // Gate + extract dependencies
    let (dest_client, source_pds_url) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::RepoTransferred).map_err(|e| {
            tracing::warn!("transfer_blobs: phase gate failed: {}", e);
            e
        })?;

        (mig.dest_client.clone(), mig.source_pds_url.clone())
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "transfer_blobs: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    let pds_client = state.pds_client();

    // Drain the missing-blob set
    drain_missing_blobs(pds_client, &dest_client, &source_pds_url, &did).await?;

    // Update orchestration state: advance phase to BlobsTransferred
    let mut orchestration = state.orchestration_state.lock().await;
    if let Some(ref mut mig) = orchestration.as_mut() {
        // Defense-in-depth DID check
        if mig.did != did {
            drop(orchestration);
            tracing::warn!("transfer_blobs: orchestration state did mismatch");
            return Err(MigrationError::MigrationNotReady {
                message: "did mismatch with orchestration state".into(),
            });
        }
        mig.phase = MigrationPhase::BlobsTransferred;
    } else {
        drop(orchestration);
        return Err(MigrationError::MigrationNotReady {
            message: "orchestration state lost".into(),
        });
    }

    tracing::info!(did = %did, "blobs transferred successfully");
    Ok(())
}

// ── Helper: extract handle from also_known_as ───────────────────────────────

fn extract_handle_from_also_known_as(also_known_as: &[String]) -> Option<String> {
    for entry in also_known_as {
        if let Some(handle) = entry.strip_prefix("at://") {
            return Some(handle.to_string());
        }
    }
    None
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;

    // AC1.3: Phase too low returns MigrationNotReady
    #[test]
    fn test_ensure_phase_did_phase_too_low() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::SourceAuthed,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::RepoTransferred);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // AC1.4: DID mismatch returns MigrationNotReady
    #[test]
    fn test_ensure_phase_did_did_mismatch() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::Resolved,
        });

        let result = ensure_phase_did(&state, "did:plc:different", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // None state returns MigrationNotReady
    #[test]
    fn test_ensure_phase_did_no_state() {
        let result = ensure_phase_did(&None, "did:plc:abc123", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // AC1.3/AC1.4: Happy path — state present, DID matches, phase sufficient
    #[test]
    fn test_ensure_phase_did_success() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::RepoTransferred,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::SourceAuthed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().phase, MigrationPhase::RepoTransferred);
    }

    // AC10.1: MigrationError serialization — MigrationNotReady
    #[test]
    fn test_migration_error_serialization_not_ready() {
        let err = MigrationError::MigrationNotReady {
            message: "test message".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "MIGRATION_NOT_READY");
        assert_eq!(json["message"], "test message");
    }

    // AC10.1: MigrationError serialization — VerificationIncomplete
    #[test]
    fn test_migration_error_serialization_verification_incomplete() {
        let err = MigrationError::VerificationIncomplete {
            imported: 5,
            expected: 10,
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "VERIFICATION_INCOMPLETE");
        assert_eq!(json["imported"], 5);
        assert_eq!(json["expected"], 10);
    }

    // AC10.1: MigrationError serialization — DestinationUnreachable
    #[test]
    fn test_migration_error_serialization_destination_unreachable() {
        let err = MigrationError::DestinationUnreachable {
            message: "connection refused".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DESTINATION_UNREACHABLE");
        assert_eq!(json["message"], "connection refused");
    }

    // AC10.1: MigrationError serialization — SourceAuthFailed
    #[test]
    fn test_migration_error_serialization_source_auth_failed() {
        let err = MigrationError::SourceAuthFailed {
            message: "invalid grant".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "SOURCE_AUTH_FAILED");
        assert_eq!(json["message"], "invalid grant");
    }

    // AC10.1: MigrationError serialization — DestinationConflict
    #[test]
    fn test_migration_error_serialization_destination_conflict() {
        let err = MigrationError::DestinationConflict {
            message: "account exists but session was lost".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DESTINATION_CONFLICT");
        assert_eq!(json["message"], "account exists but session was lost");
    }

    // ── Task 5 tests: OAuth gating ─────────────────────────────────────────

    // AC1.4: prepare_source_auth with wrong DID returns MIGRATION_NOT_READY (pure gate)
    #[test]
    fn test_prepare_source_auth_did_mismatch_gate() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::Resolved,
        });

        let result = ensure_phase_did(&state, "did:plc:different", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // prepare_source_auth gates at phase >= Resolved. Resolved is the first phase, so a
    // "phase too low" case is impossible; the only gate failures are no-state and did-mismatch.
    #[test]
    fn test_prepare_source_auth_no_state_gate() {
        // No state → gate fails
        let result = ensure_phase_did(&None, "did:plc:abc123", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // ── Task 6 tests: Account creation idempotence + gating ───────────────

    /// A JWT whose `exp` is `exp`. Bearer test clients need a future-exp token, else `new_bearer`
    /// sets expires_at=0 and a proactive refresh fires before the request under test.
    fn make_bearer_jwt(exp: u64) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, exp));
        format!("{}.{}.sig", header, payload)
    }

    // AC5.1: create_destination_account_impl with an existing dest_client returns it (idempotent
    // re-establish) WITHOUT any network — the fast path short-circuits before reserve/serviceAuth/
    // createAccount, so this also covers "409-with-existing is tolerated" (createAccount is never
    // reached when a client is held). No #[ignore] needed: no socket is bound.
    #[tokio::test]
    async fn test_create_destination_account_impl_idempotent_with_existing_client() {
        let existing = Arc::new(
            OAuthClient::new_bearer(make_bearer_jwt(9999999999), String::new(), "https://dest.pds".into())
                .unwrap(),
        );
        // Dummy deps that must never be touched (unreachable URLs prove the fast path took over).
        let pds_client = crate::pds_client::PdsClient::new();
        let source_client = Arc::new(
            OAuthClient::new_bearer(make_bearer_jwt(9999999999), String::new(), "http://127.0.0.1:1".into())
                .unwrap(),
        );

        let result = create_destination_account_impl(
            &pds_client,
            &source_client,
            "http://127.0.0.1:1",
            "did:web:dest",
            "did:plc:abc123",
            "alice.test",
            "alice@example.com",
            None,
            Some(existing.clone()),
        )
        .await;

        assert!(result.is_ok());
        assert!(
            Arc::ptr_eq(&result.unwrap(), &existing),
            "must return the exact cached client without hitting the network"
        );
    }

    // AC5.1: createAccount 409 with NO existing dest_client → DESTINATION_CONFLICT (session lost).
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_create_destination_account_impl_409_no_existing_is_conflict() {
        let source = MockServer::start();
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth");
            then.status(200)
                .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
        });
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.reserveSigningKey");
            then.status(200)
                .json_body(serde_json::json!({ "signingKey": "did:key:zDest" }));
        });
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount");
            then.status(409).body("account already exists");
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let source_client = Arc::new(
            OAuthClient::new_bearer(make_bearer_jwt(9999999999), String::new(), source.base_url())
                .unwrap(),
        );

        let result = create_destination_account_impl(
            &pds_client,
            &source_client,
            &dest.base_url(),
            "did:web:dest",
            "did:plc:abc123",
            "alice.test",
            "alice@example.com",
            None,
            None, // no existing client → conflict
        )
        .await;

        assert!(matches!(
            result,
            Err(MigrationError::DestinationConflict { .. })
        ));
    }

    // Happy path: reserveSigningKey → getServiceAuth → createAccount(200) → dest Bearer client.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_create_destination_account_impl_happy_path() {
        let source = MockServer::start();
        let sa_mock = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth");
            then.status(200)
                .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
        });
        let dest = MockServer::start();
        let reserve_mock = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.reserveSigningKey");
            then.status(200)
                .json_body(serde_json::json!({ "signingKey": "did:key:zDest" }));
        });
        let create_mock = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount");
            then.status(200).json_body(serde_json::json!({
                "accessJwt": make_bearer_jwt(9999999999),
                "refreshJwt": "refresh_jwt",
                "handle": "alice.test",
                "did": "did:plc:abc123"
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let source_client = Arc::new(
            OAuthClient::new_bearer(make_bearer_jwt(9999999999), String::new(), source.base_url())
                .unwrap(),
        );

        let result = create_destination_account_impl(
            &pds_client,
            &source_client,
            &dest.base_url(),
            "did:web:dest",
            "did:plc:abc123",
            "alice.test",
            "alice@example.com",
            None,
            None,
        )
        .await;

        assert!(result.is_ok(), "happy path must return a dest client");
        // Each leg was exercised exactly once, in order.
        assert_eq!(reserve_mock.calls(), 1);
        assert_eq!(sa_mock.calls(), 1);
        assert_eq!(create_mock.calls(), 1);
    }

    // AC1.3: create_destination_account before SourceAuthed phase returns MIGRATION_NOT_READY
    #[test]
    fn test_create_destination_account_phase_gate() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::Resolved, // Too early!
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::SourceAuthed);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // Helper test: extract_handle_from_also_known_as
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

    // Only non-at:// entries present → None (prepare_migration maps this to AccountCreationFailed).
    #[test]
    fn test_extract_handle_from_also_known_as_no_at_uri() {
        let entries = vec![
            "https://example.com/user/alice".to_string(),
            "mailto:alice@example.com".to_string(),
        ];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, None);
    }

    // ── Task 1 tests: transfer_repo ────────────────────────────────────────

    // AC2.1: transfer_repo fetches source CAR and imports to dest, advances phase.
    // (Pure gate test: phase < RepoTransferred returns MIGRATION_NOT_READY)
    #[test]
    fn test_transfer_repo_phase_gate() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::SourceAuthed, // Too early!
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::DestCreated);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // AC2.1: transfer_repo phase gate (pure test, no network)
    #[test]
    fn test_transfer_repo_phase_too_low() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::SourceAuthed, // Too early!
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::DestCreated);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // ── Task 2 tests: transfer_blobs ───────────────────────────────────────

    // AC2.5: transfer_blobs phase gate (pure test, no network)
    #[test]
    fn test_transfer_blobs_phase_too_low() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::DestCreated, // Too early for transfer_blobs!
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::RepoTransferred);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // Build a Bearer dest client (future-exp so no proactive refresh fires) at `base_url`.
    fn bearer_client_at(base_url: String) -> OAuthClient {
        OAuthClient::new_bearer(make_bearer_jwt(9999999999), String::new(), base_url).unwrap()
    }

    // ── Task 1 mock tests: transfer_repo_impl ──────────────────────────────

    // AC2.1: fetch the source CAR and POST the exact bytes to the destination importRepo.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_transfer_repo_impl_success() {
        let source = MockServer::start();
        let get_repo = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo")
                .query_param("did", "did:plc:abc123");
            then.status(200).body("CAR-DATA-BYTES");
        });
        let dest = MockServer::start();
        let import = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo")
                .header("content-type", "application/vnd.ipld.car")
                .body("CAR-DATA-BYTES"); // the exact source bytes must round-trip
            then.status(200);
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result =
            transfer_repo_impl(&pds_client, &dest_client, &source.base_url(), "did:plc:abc123").await;

        assert!(result.is_ok());
        assert_eq!(get_repo.calls(), 1);
        assert_eq!(import.calls(), 1);
    }

    // AC2.1 failure: a dest importRepo 500 → RepoTransferFailed (command leaves phase un-advanced).
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_transfer_repo_impl_import_failure() {
        let source = MockServer::start();
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo");
            then.status(200).body("CAR");
        });
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo");
            then.status(500).body("server error");
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result =
            transfer_repo_impl(&pds_client, &dest_client, &source.base_url(), "did:plc:abc123").await;

        assert!(matches!(result, Err(MigrationError::RepoTransferFailed { .. })));
    }

    // ── Task 2 mock tests: drain_missing_blobs ─────────────────────────────

    // AC2.5: an empty first page completes immediately with no getBlob/uploadBlob calls.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_missing_blobs_empty_first_page() {
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param_missing("cursor");
            then.status(200)
                .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        // Source URL is unreachable; if the drain tried to fetch a blob it would error, proving
        // the empty-page short-circuit did not touch the source.
        let result =
            drain_missing_blobs(&pds_client, &dest_client, "http://127.0.0.1:1", "did:plc:abc123").await;

        assert!(result.is_ok());
    }

    // AC2.2/AC2.3: walk two cursor pages, fetch every missing CID from source and upload to dest
    // once each, terminating on the empty page.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_missing_blobs_multi_page() {
        let source = MockServer::start();
        let get_a = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob")
                .query_param("cid", "cid_a");
            then.status(200).body("blob-a");
        });
        let get_b = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob")
                .query_param("cid", "cid_b");
            then.status(200).body("blob-b");
        });
        let get_c = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob")
                .query_param("cid", "cid_c");
            then.status(200).body("blob-c");
        });

        let dest = MockServer::start();
        // Page 1 (no cursor): two blobs, cursor c1.
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param_missing("cursor");
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "cid_a", "recordUri": "at://did:plc:abc123/app.bsky.feed.post/1" },
                    { "cid": "cid_b", "recordUri": "at://did:plc:abc123/app.bsky.feed.post/2" }
                ],
                "cursor": "c1"
            }));
        });
        // Page 2 (cursor=c1): one blob, cursor c2.
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "c1");
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "cid_c", "recordUri": "at://did:plc:abc123/app.bsky.feed.post/3" }
                ],
                "cursor": "c2"
            }));
        });
        // Page 3 (cursor=c2): drained → empty, terminates the loop.
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "c2");
            then.status(200)
                .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
        });
        let upload = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.uploadBlob");
            then.status(200)
                .json_body(serde_json::json!({ "blob": { "$type": "blob" } }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result =
            drain_missing_blobs(&pds_client, &dest_client, &source.base_url(), "did:plc:abc123").await;

        assert!(result.is_ok());
        assert_eq!(get_a.calls(), 1, "cid_a fetched once");
        assert_eq!(get_b.calls(), 1, "cid_b fetched once");
        assert_eq!(get_c.calls(), 1, "cid_c fetched once");
        assert_eq!(upload.calls(), 3, "each of the 3 blobs uploaded once");
    }

    // AC2.6: a failing source getBlob mid-drain aborts with BlobTransferFailed (retry-safe).
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_missing_blobs_mid_failure_is_blob_transfer_failed() {
        let source = MockServer::start();
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob");
            then.status(500).body("blob fetch error");
        });
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param_missing("cursor");
            then.status(200).json_body(serde_json::json!({
                "blobs": [ { "cid": "cid_a", "recordUri": "at://did:plc:abc123/x/1" } ],
                "cursor": null
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result =
            drain_missing_blobs(&pds_client, &dest_client, &source.base_url(), "did:plc:abc123").await;

        assert!(matches!(result, Err(MigrationError::BlobTransferFailed { .. })));
    }
}
