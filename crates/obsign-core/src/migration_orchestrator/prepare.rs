// pattern: Mixed (pure cores + Imperative Shell commands — see the parent module doc)

//! Setup steps: `prepare_migration`, source-PDS login, and destination account creation.

use super::*;

// ── prepare_migration ──────────────────────────────────────────────

/// Resolve destination + source PDS and store migration state at phase Resolved.
///
/// 1. discover_pds(did) → source_pds_url + preferred login identifier (handle, then DID)
/// 2. describe_server(dest_pds_url) → dest_did (map PdsUnreachable → DESTINATION_UNREACHABLE)
/// 3. store fresh OutboundMigrationState at phase Resolved (in-memory only; app kill restarts)
pub async fn prepare_migration(
    state: &crate::oauth::Core,
    did: String,
    dest_pds_url: String,
) -> Result<PreparedMigration, MigrationError> {
    let result = prepare_migration_impl(state.pds_client(), &did, &dest_pds_url).await?;

    // Surface the resolved source identity so the source-auth screen can prefill the login
    // identifier and show which PDS it is signing into (the authoritative copy stays in state).
    let prepared = PreparedMigration {
        handle: result.handle.clone(),
        source_pds_url: result.source_pds_url.clone(),
    };

    // Store fresh state at phase Resolved (in-memory only; app kill restarts from prepare_migration)
    *state.orchestration_state.lock().await = Some(result);
    Ok(prepared)
}

/// Pure core: discover source + dest, return fresh OutboundMigrationState at Resolved.
pub(super) async fn prepare_migration_impl(
    pds_client: &crate::pds_client::PdsClient,
    did: &str,
    dest_pds_url: &str,
) -> Result<OutboundMigrationState, MigrationError> {
    tracing::info!(did = %did, dest_url = %dest_pds_url, "prepare_migration: discovering source + destination");

    // 1. Discover source PDS
    let (source_pds_url, plc_doc) = pds_client.discover_pds(did).await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to discover source PDS");
        // Preserve the unreachable distinction in the message (there is no SourceUnreachable
        // variant; only the destination is named, but a bare NetworkError is less actionable).
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

    // Prefer the human-readable handle for the source login. An at:// URI may legally use a DID
    // as its authority, so do not mistake `at://did:...` for a handle. createSession accepts the
    // DID directly, which is the safe fallback when the document has no usable handle.
    let handle = preferred_login_identifier(&plc_doc.also_known_as, did);

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
        accepted_blob_loss: Vec::new(),
        recovery: false,
    })
}

// ── Source-PDS password login ──────────────────────────────────────

/// Authenticate with the source PDS using the account **password** (`createSession`), yielding a
/// full-session Bearer client that the migration then uses for its source-side calls.
///
/// Why a password and not the wallet's OAuth token: creating the destination account
/// (`create_destination_account`) mints a `com.atproto.server.createAccount` service-auth token
/// **from the source PDS**, and a spec-strict PDS such as bsky.social gates that mint behind a full
/// session — an OAuth `transition:generic` grant is refused (`insufficient access`). A
/// password `createSession` mints a full `com.atproto.access` session, the only credential class
/// that can. This mirrors the claim flow's `authenticate_source_pds` (ADR-0021) — one password
/// path for every source login.
///
/// The password is used for exactly one `createSession` request and is never stored — the wallet
/// keeps only the resulting Bearer session, in memory, in `OutboundMigrationState.source_client`.
/// An app password is a lesser scope and is rejected the same way a wrong real password is.
///
/// `auth_factor_token` is the email 2FA one-time code. Pass `None` first; if the account has email
/// two-factor enabled the call returns `TwoFactorRequired` (and the PDS emails a code), and the UI
/// re-invokes with that code as `Some`.
///
/// Gate: `ensure_phase_did(..., Resolved)` — `prepare_migration` must have resolved the source PDS.
pub async fn authenticate_migration_source(
    state: &crate::oauth::Core,
    did: String,
    identifier: String,
    password: String,
    auth_factor_token: Option<String>,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "authenticate_migration_source: password login for source PDS");

    // Snapshot the source PDS URL under the lock; the phase/DID gate is defense-in-depth.
    let source_pds_url = {
        let orchestration = state.orchestration_state.lock().await;
        let mig =
            ensure_phase_did(&orchestration, &did, MigrationPhase::Resolved).map_err(|e| {
                tracing::warn!("authenticate_migration_source: phase gate failed: {}", e);
                e
            })?;
        mig.source_pds_url.clone()
    }; // lock released — createSession is a network call

    let oauth_client = authenticate_migration_source_impl(
        state.pds_client(),
        &source_pds_url,
        &did,
        &identifier,
        &password,
        auth_factor_token.as_deref(),
    )
    .await?;

    // Re-acquire the lock and store the Bearer client, rejecting the write if a concurrent
    // `prepare_migration` swapped the active migration while we were on the network.
    let mut orchestration = state.orchestration_state.lock().await;
    match orchestration.as_mut() {
        Some(mig) if mig.did == did && mig.source_pds_url == source_pds_url => {
            mig.source_client = Some(std::sync::Arc::new(oauth_client));
            mig.phase = MigrationPhase::SourceAuthed;
            Ok(())
        }
        _ => {
            drop(orchestration);
            tracing::warn!("authenticate_migration_source: active migration changed during login");
            Err(MigrationError::MigrationNotReady {
                message: "migration state changed during source login".into(),
            })
        }
    }
}

/// Testable core: run `createSession` against the source PDS and build a full-session Bearer
/// `OAuthClient`. Split out so the command can release the orchestration lock around the network
/// call (twin of `claim::authenticate_source_pds_impl`).
///
/// The `createSession` body + account-match guard are shared with the claim flow in
/// `source_login::authenticate_source_password`; this wrapper only maps the neutral
/// `SourceLoginError` into the migration's `MigrationError` contract.
///
/// `expected_did` is the DID being migrated: the session the PDS returns MUST be for that account,
/// or the caller signed in to the wrong one and we refuse to bind those credentials to this
/// migration.
pub async fn authenticate_migration_source_impl(
    pds_client: &crate::pds_client::PdsClient,
    source_pds_url: &str,
    expected_did: &str,
    identifier: &str,
    password: &str,
    auth_factor_token: Option<&str>,
) -> Result<OAuthClient, MigrationError> {
    crate::source_login::authenticate_source_password(
        pds_client,
        source_pds_url,
        expected_did,
        identifier,
        password,
        auth_factor_token,
    )
    .await
    .map_err(MigrationError::from)
}

/// Map the neutral source-login error into the migration's frontend-facing enum. The variants line
/// up one-to-one with what `authenticate_migration_source_impl` used to produce inline.
impl From<crate::source_login::SourceLoginError> for MigrationError {
    fn from(e: crate::source_login::SourceLoginError) -> Self {
        use crate::source_login::SourceLoginError as S;
        match e {
            S::TwoFactorRequired => MigrationError::TwoFactorRequired,
            S::SourceAuthFailed { message } => MigrationError::SourceAuthFailed { message },
            S::AccountMismatch => MigrationError::AccountMismatch,
            S::InsecureSourceUrl => MigrationError::InsecureSourceUrl,
            S::RateLimited { retry_after } => MigrationError::RateLimited { retry_after },
            S::ServerError { message } => MigrationError::ServerRejected { message },
            S::NetworkError { message } => MigrationError::NetworkError { message },
        }
    }
}

// ── create_destination_account ──────────────────────────────────────

/// Pure core: reserve key, mint service-auth, create account, return Bearer client.
/// Extracted for unit testability with mocked servers.
// The explicit-dependency signature (source/dest clients, urls, dids, handle, email, invite,
// existing client) is deliberate for testability; a struct would only move the arity around.
#[allow(clippy::too_many_arguments)]
pub(super) async fn create_destination_account_impl(
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
        .reserve_signing_key(dest_pds_url, Some(did))
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

    // 3-5. Shared with the disaster-recovery flow, which mints the token offline
    // instead of asking the source PDS for one.
    create_destination_account_with_token(
        &service_auth_token.token,
        dest_pds_url,
        did,
        handle,
        email,
        invite_code,
        existing_dest_client,
    )
    .await
}

/// The token-agnostic half of destination-account creation: wrap a service-auth JWT
/// (source-minted or offline-minted) in a one-shot Bearer client, run the migration
/// `createAccount`, and return the destination Bearer session. Shared by
/// `create_destination_account_impl` and `disaster_recovery.rs`.
pub async fn create_destination_account_with_token(
    service_auth_token: &str,
    dest_pds_url: &str,
    did: &str,
    handle: &str,
    email: &str,
    invite_code: Option<String>,
    existing_dest_client: Option<Arc<OAuthClient>>,
) -> Result<Arc<OAuthClient>, MigrationError> {
    // Idempotent fast path shared by both callers: a session already established by a
    // prior attempt means there is nothing to create — return it without any network.
    if let Some(client) = &existing_dest_client {
        tracing::info!(
            "create_destination_account_with_token: dest_client exists, returning cached"
        );
        return Ok(client.clone());
    }

    // One-shot Bearer client carrying the service-auth token.
    let sa_client = OAuthClient::new_bearer_with_observer(
        service_auth_token.to_string(),
        String::new(),
        dest_pds_url.into(),
        crate::oauth_client::diagnostics_observer(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create service-auth Bearer client");
        MigrationError::AccountCreationFailed {
            message: "failed to create Bearer client".to_string(),
        }
    })?;

    // Create account migration (deactivated account).
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
            let dest_client = OAuthClient::new_bearer_with_observer(
                resp.access_jwt,
                resp.refresh_jwt,
                dest_pds_url.into(),
                crate::oauth_client::diagnostics_observer(),
            )
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
        // we tolerate it (idempotent re-establish — the fast path above usually covers this).
        // If not, the destination session was lost (only possible after an app kill wiped in-memory
        // state), so the flow must restart from prepare_migration (DESTINATION_CONFLICT).
        Err(crate::pds_client::PdsClientError::DidAlreadyExists) => match existing_dest_client {
            Some(client) => {
                tracing::info!(did = %did, "createAccount 409 but dest_client held; tolerating");
                Ok(client)
            }
            None => {
                tracing::error!(did = %did, "createAccount 409 with no dest_client; destination conflict");
                Err(MigrationError::DestinationConflict {
                    message: "account exists but session was lost (app kill); restart migration"
                        .into(),
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
pub async fn create_destination_account(
    state: &crate::oauth::Core,
    did: String,
    email: String,
    invite_code: Option<String>,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "create_destination_account command");

    // Gate + extract dependencies
    let (source_client, dest_pds_url, dest_did, handle, existing_dest_client) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig =
            ensure_phase_did(&orchestration, &did, MigrationPhase::SourceAuthed).map_err(|e| {
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

    MigrationJournal::new(&state.orchestration_state, &did)
        .commit(MigrationPhase::DestCreated, |mig| {
            mig.dest_client = Some(dest_client)
        })
        .await?;

    tracing::info!(did = %did, "destination account created and stored");
    Ok(())
}

// ── Helper: extract handle from also_known_as ───────────────────────────────

pub fn extract_handle_from_also_known_as(also_known_as: &[String]) -> Option<String> {
    for entry in also_known_as {
        if let Some(handle) = entry.strip_prefix("at://") {
            if !handle.starts_with("did:") {
                return Some(handle.to_string());
            }
        }
    }
    None
}

pub fn preferred_login_identifier(also_known_as: &[String], did: &str) -> String {
    extract_handle_from_also_known_as(also_known_as).unwrap_or_else(|| did.to_string())
}
