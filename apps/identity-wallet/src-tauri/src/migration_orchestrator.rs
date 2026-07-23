// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Functional Core: MigrationPhase, OutboundMigrationState, MigrationError, PreparedMigration,
//                  ensure_phase_did, import_reconciles, extract_handle_from_also_known_as
//                  (pure functions — no network, no side effects)
// Imperative Shell: prepare_migration, authenticate_migration_source,
//                   create_destination_account; transfer_repo, transfer_blobs,
//                   transfer_preferences, verify_import; arm_identity_leg,
//                   finalize_migration — Tauri commands, plus their
//                   *_impl / authenticate_migration_source_impl / drain_missing_blobs network cores.
//
// The source-PDS login is a password `createSession` → full-session Bearer client (ADR-0021),
// NOT an OAuth `transition:generic` grant: minting the `com.atproto.server.createAccount`
// service-auth token from the source PDS (see `create_destination_account_impl`) requires a full
// session on a spec-strict PDS such as bsky.social. Mirrors `claim::authenticate_source_pds`.

use crate::oauth_client::OAuthClient;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

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
    /// Preferred source login identifier (handle when known, otherwise the DID)
    pub handle: String,
    /// Full-session Bearer client for the source PDS (set after `authenticate_migration_source`).
    /// Wrapped in Arc to allow cloning out of the Mutex without holding the lock
    /// across network calls.
    pub source_client: Option<Arc<OAuthClient>>,
    /// OAuth client for destination PDS (set after `create_destination_account`)
    /// Wrapped in Arc to allow cloning out of the Mutex without holding the lock
    /// across network calls.
    pub dest_client: Option<Arc<OAuthClient>>,
    /// Current phase in the migration flow
    pub phase: MigrationPhase,
    /// Blobs the user explicitly accepted as lost via the drain's loss manifest. Empty on a
    /// clean drain; populated only when `transfer_blobs` is re-invoked with `accept_loss = true`.
    /// `verify_import` subtracts this count from `expected_blobs` so a degraded-but-accepted
    /// migration still reconciles.
    pub accepted_blob_loss: Vec<BlobLoss>,
    /// True when this session is a sovereign disaster recovery (`disaster_recovery.rs`):
    /// the source PDS is presumed dead, so there is no source client, the blob drain
    /// goes straight to the iCloud mirror, the preferences leg is skipped (nothing to
    /// read them from), and the finalize activates the destination without deactivating
    /// a source. False for every normal outbound migration.
    pub recovery: bool,
}

/// Resolved source identity returned by `prepare_migration`, so the source-auth screen can prefill
/// the login identifier and show which PDS it is signing into (mirrors the claim flow's
/// `IdentityInfo`). The authoritative `source_pds_url` used for the actual `createSession` lives in
/// `OutboundMigrationState` — this copy is display/prefill only.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedMigration {
    /// Preferred source login identifier (handle from `alsoKnownAs`, otherwise the DID).
    pub handle: String,
    /// Source PDS base URL (the account's current PDS, resolved via `discover_pds`).
    pub source_pds_url: String,
}

// ── Blob loss manifest ─────────────────────────────────────────────────────

/// Which half of a single blob's transfer failed. `Source` = the source PDS couldn't serve
/// `getBlob` (the observed source-PDS fault); `Destination` = the destination PDS refused `uploadBlob`.
/// Serializes lowercase (`"source"` / `"destination"`) — the wallet UI maps it to the same
/// fetch-vs-upload language `describeBlobTransferDetail` already uses.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlobTransferDirection {
    Source,
    Destination,
}

/// One blob the drain gave up on after per-blob retries. Collected into a loss manifest so the
/// user can make an informed skip — which blob, which record references it, and why it failed —
/// instead of the whole migration parking on a single dead blob. Serializes camelCase to
/// match the wallet's `BlobLoss` type.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlobLoss {
    /// The blob's CID (content hash), as listed by `listMissingBlobs`.
    pub cid: String,
    /// The `at://` URI of a record that references this blob (from `listMissingBlobs`), so the UI
    /// can tell the user which content loses its media.
    pub record_uri: String,
    /// Which side of the transfer failed after retries.
    pub direction: BlobTransferDirection,
    /// The last error text (server-supplied when available), shown as subordinate detail.
    pub reason: String,
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
    /// The source PDS rejected the password login (`createSession` 401). Distinct from a network
    /// failure so the UI can say "wrong password" instead of blaming the connection. An app
    /// password is a lesser scope and is refused the same way.
    #[error("source auth failed: {message}")]
    SourceAuthFailed { message: String },
    /// The source account has email two-factor enabled: `createSession` returned
    /// `AuthFactorTokenRequired` and the PDS emailed a one-time code. The UI prompts for the code
    /// and re-invokes `authenticate_migration_source` with it — distinct from a wrong password.
    #[error("two-factor code required")]
    TwoFactorRequired,
    /// The source PDS session is for a different account than the one being migrated (the entered
    /// credentials signed in to the wrong account). Refused before any migration step proceeds.
    #[error("account mismatch")]
    AccountMismatch,
    /// Refused to send the account password to a non-HTTPS source PDS (loopback excepted). The PDS
    /// endpoint comes from the DID document, so a plaintext `http://` endpoint is rejected.
    #[error("insecure source url")]
    InsecureSourceUrl,
    /// The source PDS rate-limited the login (HTTP 429). `retry_after` carries the server's
    /// `Retry-After` value when present, so the UI can say how long to wait rather than blaming the
    /// connection.
    #[error("rate limited")]
    RateLimited {
        #[serde(rename = "retryAfter")]
        retry_after: Option<String>,
    },
    /// The source PDS rejected the login with a non-2xx the wallet doesn't model specially.
    /// `message` is the server's own error text, shown verbatim so a third-party PDS's real reason
    /// reaches the user instead of connectivity boilerplate.
    #[error("server error: {message}")]
    ServerError { message: String },
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
    /// The drain completed a full pass, but some blobs permanently failed after per-blob retries.
    /// Not a hard abort: the transferable blobs are already on the destination and the phase is NOT
    /// advanced. The carried manifest lets the UI offer an informed "continue without these blobs"
    /// (re-invoke `transfer_blobs` with `accept_loss = true`) instead of abandoning the run.
    #[error("blob drain incomplete: {} blob(s) could not be transferred", losses.len())]
    BlobDrainIncomplete { losses: Vec<BlobLoss> },
    /// Preferences transfer failed
    #[error("preferences transfer failed: {message}")]
    PreferencesTransferFailed { message: String },
    /// Verification incomplete: imported entries do not match expected count
    #[error("verification incomplete")]
    VerificationIncomplete { imported: u64, expected: u64 },
    /// Identity activation failed
    #[error("activation failed: {message}")]
    ActivationFailed { message: String },
    /// Minting the destination sovereign session failed (device-key proof rejected, rate limited,
    /// server error, or transport failure). A retryable *pre-cutover* failure: the source account
    /// is still active and the migration can be retried. Never advances to `Finalized`.
    #[error("sovereign login failed: {message}")]
    SovereignLoginFailed { message: String },
    /// Persisting the destination sovereign session to the Keychain failed. Retryable pre-cutover
    /// failure — the source stays active and the migration can be retried. The prior valid token
    /// record (if any) is left intact because the write is atomic (replace-or-fail).
    #[error("session persist failed: {message}")]
    SessionPersistFailed { message: String },
    /// Account deactivation failed
    #[error("deactivation failed: {message}")]
    DeactivationFailed { message: String },
    /// Network error during migration
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The iCloud/local backup needed by a disaster recovery is unavailable or invalid
    /// (no backup location, or no snapshot that passes validation).
    #[error("backup unavailable: {message}")]
    BackupUnavailable { message: String },
}

// ── Pure prerequisite gate ─────────────────────────────────────────────────

/// Pure prerequisite gate: state present, DID matches, and phase is at least `required`.
/// No network, no side effects — this is what makes the gate side-effect-free and
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
/// 1. discover_pds(did) → source_pds_url + preferred login identifier (handle, then DID)
/// 2. describe_server(dest_pds_url) → dest_did (map PdsUnreachable → DESTINATION_UNREACHABLE)
/// 3. store fresh OutboundMigrationState at phase Resolved (in-memory only; app kill restarts)
#[tauri::command]
pub async fn prepare_migration(
    state: tauri::State<'_, crate::oauth::AppState>,
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
async fn prepare_migration_impl(
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

// ── Task 5: Source-PDS password login ──────────────────────────────────────

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
#[tauri::command]
pub async fn authenticate_migration_source(
    state: tauri::State<'_, crate::oauth::AppState>,
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
/// `OAuthClient`. Extracted so it can be exercised without Tauri's `State` wrapper (twin of
/// `claim::authenticate_source_pds_impl`).
///
/// The `createSession` body + account-match guard are shared with the claim flow in
/// `source_login::authenticate_source_password`; this wrapper only maps the neutral
/// `SourceLoginError` into the migration's `MigrationError` contract.
///
/// `expected_did` is the DID being migrated: the session the PDS returns MUST be for that account,
/// or the caller signed in to the wrong one and we refuse to bind those credentials to this
/// migration.
pub(crate) async fn authenticate_migration_source_impl(
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
            S::ServerError { message } => MigrationError::ServerError { message },
            S::NetworkError { message } => MigrationError::NetworkError { message },
        }
    }
}

// ── Task 6: create_destination_account ──────────────────────────────────────

/// Pure core: reserve key, mint service-auth, create account, return Bearer client.
/// Extracted for unit testability with mocked servers.
// The explicit-dependency signature (source/dest clients, urls, dids, handle, email, invite,
// existing client) is deliberate for testability; a struct would only move the arity around.
#[allow(clippy::too_many_arguments)]
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
pub(crate) async fn create_destination_account_with_token(
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
    let sa_client = OAuthClient::new_bearer(
        service_auth_token.to_string(),
        String::new(),
        dest_pds_url.into(),
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
///
/// `mirror_root`, when present, is the wallet's local iCloud repo mirror. If the source PDS can't
/// serve `getRepo` (the repo twin of the observed blob-drain fault), the transfer falls back to the
/// mirror's snapshot before giving up — content addressing makes that substitution trustless
/// (`repo_backup::mirror_repo_car` re-validates the CAR against the DID and returns `None` on any
/// doubt), so a backed-up user's dead source repo becomes a non-event. When the mirror can't supply
/// a valid snapshot the original source failure is surfaced unchanged, exactly as before the mirror
/// existed. The fallback is consulted only for the source `getRepo` half; a destination `importRepo`
/// refusal is a genuinely different failure the mirror can't fix.
async fn transfer_repo_impl(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: &str,
    did: &str,
    mirror_root: Option<&Path>,
) -> Result<(), MigrationError> {
    // 1. Fetch repository CAR from source; on a source getRepo failure, fall back to the local
    //    iCloud mirror before giving up.
    tracing::debug!(did = %did, source_url = %source_pds_url, "fetching repository from source");
    let car = match pds_client.fetch_repo_car(source_pds_url, did).await {
        Ok(car) => car,
        Err(source_err) => {
            tracing::error!(did = %did, error = %source_err, "failed to fetch repository CAR from source");
            // The source PDS can't serve getRepo. Try the local mirror: a CID/commit-valid backup
            // copy stands in for the bytes the source can't serve. `mirror_repo_car` is fail-closed
            // (revalidates, returns None on a missing/undownloaded/rotten snapshot), so the original
            // source failure is preserved unchanged whenever no trustworthy snapshot exists.
            match mirror_root {
                Some(root) => match crate::repo_backup::mirror_repo_car(root, did).await {
                    Some(car) => {
                        tracing::info!(did = %did, "transfer_repo: recovered the repo snapshot from the local mirror after a source getRepo failure");
                        car
                    }
                    None => {
                        return Err(MigrationError::RepoTransferFailed {
                            message: format!("failed to fetch repository: {}", source_err),
                        });
                    }
                },
                None => {
                    return Err(MigrationError::RepoTransferFailed {
                        message: format!("failed to fetch repository: {}", source_err),
                    });
                }
            }
        }
    };

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
/// Then: fetch_repo_car(source) → import_repo(dest); re-lock + advance to RepoTransferred.
/// A source `getRepo` failure falls back to the local iCloud repo mirror when this device has a
/// CID/commit-valid snapshot for the DID (`repo_backup::mirror_repo_car`), turning a dead source
/// repo into a non-event for backed-up users; when no valid snapshot exists the original source
/// failure is surfaced unchanged.
#[tauri::command]
pub async fn transfer_repo(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "transfer_repo: fetching and importing repository");

    // Gate + extract dependencies
    let (dest_client, source_pds_url) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig =
            ensure_phase_did(&orchestration, &did, MigrationPhase::DestCreated).map_err(|e| {
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

    // Resolve the local repo mirror, if this device has one. When present the transfer falls back to
    // it for a source PDS that can't serve getRepo (the repo twin of the blob drain's fallback);
    // when absent the transfer behaves as before.
    let mirror_root = crate::blob_backup::resolve_backup_root(&app).map(|(root, _location)| root);

    // Fetch source CAR + import into destination (pure core, unit-tested).
    transfer_repo_impl(
        pds_client,
        &dest_client,
        &source_pds_url,
        &did,
        mirror_root.as_deref(),
    )
    .await?;

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

/// Per-blob transfer attempts before the drain gives up on a blob and records it in the loss
/// manifest. A source PDS that permanently 500s every `getBlob` (the observed source-PDS fault) is
/// declared lost after this many tries; transient blips get absorbed by the retry.
const BLOB_TRANSFER_ATTEMPTS: u32 = 3;

/// Short exponential backoff between per-blob retries: 250ms after the 1st failure, 500ms after the
/// 2nd. Keeps a doomed drain from hammering the source while still spacing out transient retries.
fn blob_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(250u64 * 2u64.pow(attempt.saturating_sub(1)))
}

/// Where a successfully-transferred blob's bytes came from. Tracked so a drain that leaned on the
/// local mirror to route around a source-PDS `getBlob` fault is visible in the logs (and countable),
/// never a silent substitution — the observability the resilience design asks of any degraded path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlobOrigin {
    /// Fetched from the source PDS, the normal path.
    SourcePds,
    /// Recovered from the wallet's local blob mirror after the source PDS failed `getBlob`.
    LocalMirror,
}

/// Transfer one blob: fetch it from the source, then upload it to the destination, retrying each
/// half up to `BLOB_TRANSFER_ATTEMPTS` times with a short backoff. On success `Ok(BlobOrigin)`
/// naming where the bytes came from; once retries are exhausted, `Err(BlobLoss)` naming which half
/// failed (and the last server error) so the caller can fold it into the loss manifest instead of
/// aborting the whole drain.
///
/// `mirror_root`, when present, is the local blob-backup mirror. If the source PDS can't serve the
/// blob (the observed real-migration fault: metadata present, `getBlob` 500s), the drain falls back
/// to the mirror before recording a loss — content addressing makes that substitution trustless, so
/// a backed-up user's dead source blob becomes a non-event. The mirror is consulted only for the
/// fetch half; a destination `uploadBlob` refusal is a genuinely different failure it can't fix.
async fn transfer_one_blob(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: Option<&str>,
    did: &str,
    blob: &crate::pds_client::MissingBlob,
    mirror_root: Option<&Path>,
) -> Result<BlobOrigin, BlobLoss> {
    // No source at all (disaster recovery): the mirror IS the source. Skip the doomed
    // fetch retries and read the CID-verified backup copy directly.
    let Some(source_pds_url) = source_pds_url else {
        return match mirror_root {
            Some(root) => {
                match crate::blob_backup::mirror_fallback_blob(root, did, &blob.cid).await {
                    Some(bytes) => {
                        upload_blob_with_retries(
                            dest_client,
                            did,
                            blob,
                            bytes,
                            BlobOrigin::LocalMirror,
                        )
                        .await
                    }
                    None => Err(BlobLoss {
                        cid: blob.cid.clone(),
                        record_uri: blob.record_uri.clone(),
                        direction: BlobTransferDirection::Source,
                        reason: "source PDS unavailable and the backup mirror has no usable copy"
                            .to_string(),
                    }),
                }
            }
            None => Err(BlobLoss {
                cid: blob.cid.clone(),
                record_uri: blob.record_uri.clone(),
                direction: BlobTransferDirection::Source,
                reason: "source PDS unavailable and no backup mirror on this device".to_string(),
            }),
        };
    };

    // Fetch-from-source half.
    let mut attempt = 0;
    let (bytes, origin) = loop {
        attempt += 1;
        match pds_client.fetch_blob(source_pds_url, did, &blob.cid).await {
            Ok(bytes) => break (bytes, BlobOrigin::SourcePds),
            Err(e) if attempt >= BLOB_TRANSFER_ATTEMPTS => {
                // Source PDS is out of retries. Before declaring the blob lost, try the local
                // mirror: content addressing lets a verified backup copy stand in for the bytes the
                // source can't serve.
                match mirror_root {
                    Some(root) => {
                        match crate::blob_backup::mirror_fallback_blob(root, did, &blob.cid).await {
                            Some(bytes) => break (bytes, BlobOrigin::LocalMirror),
                            None => {
                                tracing::error!(did = %did, cid = %blob.cid, attempts = attempt, error = %e, "fetch_blob exhausted retries and the local mirror has no usable copy; recording blob loss");
                                return Err(BlobLoss {
                                    cid: blob.cid.clone(),
                                    record_uri: blob.record_uri.clone(),
                                    direction: BlobTransferDirection::Source,
                                    reason: e.to_string(),
                                });
                            }
                        }
                    }
                    None => {
                        tracing::error!(did = %did, cid = %blob.cid, attempts = attempt, error = %e, "fetch_blob exhausted retries; recording blob loss");
                        return Err(BlobLoss {
                            cid: blob.cid.clone(),
                            record_uri: blob.record_uri.clone(),
                            direction: BlobTransferDirection::Source,
                            reason: e.to_string(),
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!(did = %did, cid = %blob.cid, attempt, error = %e, "fetch_blob failed; retrying");
                tokio::time::sleep(blob_backoff(attempt)).await;
            }
        }
    };

    // Upload-to-destination half.
    upload_blob_with_retries(dest_client, did, blob, bytes, origin).await
}

/// Upload one blob's bytes to the destination with per-blob retries — the shared
/// upload half of `transfer_one_blob` for both the source-fetched and mirror-read
/// paths. Returns the given `origin` on success.
async fn upload_blob_with_retries(
    dest_client: &OAuthClient,
    did: &str,
    blob: &crate::pds_client::MissingBlob,
    bytes: Vec<u8>,
    origin: BlobOrigin,
) -> Result<BlobOrigin, BlobLoss> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match crate::pds_client::upload_blob(dest_client, "application/octet-stream", bytes.clone())
            .await
        {
            Ok(_) => return Ok(origin),
            Err(e) if attempt >= BLOB_TRANSFER_ATTEMPTS => {
                tracing::error!(did = %did, cid = %blob.cid, attempts = attempt, error = %e, "upload_blob exhausted retries; recording blob loss");
                return Err(BlobLoss {
                    cid: blob.cid.clone(),
                    record_uri: blob.record_uri.clone(),
                    direction: BlobTransferDirection::Destination,
                    reason: e.to_string(),
                });
            }
            Err(e) => {
                tracing::warn!(did = %did, cid = %blob.cid, attempt, error = %e, "upload_blob failed; retrying");
                tokio::time::sleep(blob_backoff(attempt)).await;
            }
        }
    }
}

/// Pure core: drain the destination's missing-blob set via cursor pagination, degrading per-blob.
///
/// Loops `list_missing_blobs(cursor)`; each blob is transferred via `transfer_one_blob` (which
/// retries per-blob). A blob that still fails is added to a give-up set and recorded in the returned
/// loss manifest — one dead blob no longer parks the whole migration. The give-up set also
/// drives termination: `listMissingBlobs` keeps re-reporting a skipped blob, so the loop stops once
/// a full pass (cursor exhausted) surfaces no *new* transferable blob. A clean drain returns an
/// empty `Vec`. Only `list_missing_blobs` itself failing — we can't even enumerate, so no manifest
/// is possible — aborts hard with `BlobTransferFailed`, still WITHOUT advancing the phase.
///
/// `mirror_root`, when present, is the wallet's local blob mirror: a blob the source PDS can't serve
/// is recovered from it before being recorded as lost (see `transfer_one_blob`), shrinking the loss
/// manifest — ideally to empty — for backed-up users.
async fn drain_missing_blobs(
    pds_client: &crate::pds_client::PdsClient,
    dest_client: &OAuthClient,
    source_pds_url: Option<&str>,
    did: &str,
    mirror_root: Option<&Path>,
) -> Result<Vec<BlobLoss>, MigrationError> {
    let mut cursor: Option<String> = None;
    let mut losses: Vec<BlobLoss> = Vec::new();
    let mut recovered_from_mirror: u64 = 0;
    let mut given_up: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    loop {
        let page = crate::pds_client::list_missing_blobs(dest_client, cursor.as_deref())
            .await
            .map_err(|e| {
                tracing::error!(did = %did, error = %e, "list_missing_blobs failed");
                MigrationError::BlobTransferFailed {
                    message: format!("failed to list missing blobs: {}", e),
                }
            })?;

        // Blobs on this page we haven't already given up on.
        let pending: Vec<&crate::pds_client::MissingBlob> = page
            .blobs
            .iter()
            .filter(|b| !given_up.contains(&b.cid))
            .collect();

        if pending.is_empty() {
            // Nothing transferable on this page: either the set is fully drained (empty page → a
            // clean drain) or only already-given-up blobs remain. Keep scanning while pages remain;
            // once a full pass (cursor exhausted) yields no transferable blob, return the manifest.
            match page.cursor {
                Some(next) => {
                    cursor = Some(next);
                    continue;
                }
                None => {
                    if recovered_from_mirror > 0 {
                        tracing::info!(did = %did, recovered = recovered_from_mirror, "blob drain: recovered blob(s) from the local mirror after source getBlob failures");
                    }
                    if losses.is_empty() {
                        tracing::debug!(did = %did, "blob drain complete: missing set is empty");
                    } else {
                        tracing::warn!(did = %did, lost = losses.len(), "blob drain incomplete: some blobs could not be transferred");
                    }
                    return Ok(losses);
                }
            }
        }

        for blob in pending {
            tracing::debug!(did = %did, cid = %blob.cid, "transferring blob");
            match transfer_one_blob(
                pds_client,
                dest_client,
                source_pds_url,
                did,
                blob,
                mirror_root,
            )
            .await
            {
                Ok(BlobOrigin::LocalMirror) => recovered_from_mirror += 1,
                Ok(BlobOrigin::SourcePds) => {}
                Err(loss) => {
                    given_up.insert(blob.cid.clone());
                    losses.push(loss);
                }
            }
        }

        // Advance: Some → next page; None → re-list from the start. On the re-list the transferred
        // blobs are gone from the missing set, so only given-up blobs remain and the `pending`
        // filter above converges the loop.
        cursor = page.cursor;
    }
}

/// Tauri command: drain missing blobs from destination via cursor-paginated loop.
///
/// Gate: ensure_phase_did(..., RepoTransferred) → clone dest_client, read source_pds_url; drop lock.
/// Then `drain_missing_blobs` degrades per-blob:
/// - clean drain → advance to BlobsTransferred.
/// - some blobs lost and `accept_loss = false` → return `BlobDrainIncomplete { losses }` WITHOUT
///   advancing, so the UI can show the manifest and let the user decide.
/// - `accept_loss = true` → record the (re-drained) losses on the state, advance anyway, and
///   `verify_import` later subtracts them so the migration still reconciles.
#[tauri::command]
pub async fn transfer_blobs(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    accept_loss: bool,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, accept_loss, "transfer_blobs: draining missing blobs");

    // Gate + extract dependencies. A recovery session has no usable source: the drain
    // reads the iCloud mirror directly instead of burning retries on a dead host.
    let (dest_client, source_pds_url) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::RepoTransferred).map_err(
            |e| {
                tracing::warn!("transfer_blobs: phase gate failed: {}", e);
                e
            },
        )?;

        let source = if mig.recovery {
            None
        } else {
            Some(mig.source_pds_url.clone())
        };
        (mig.dest_client.clone(), source)
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "transfer_blobs: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    let pds_client = state.pds_client();

    // Resolve the local blob mirror, if this device has one. When present the drain falls back to it
    // for any blob the source PDS can't serve (the observed real-migration fault), turning a dead
    // source blob into a non-event for backed-up users; when absent the drain behaves as before.
    let mirror_root = crate::blob_backup::resolve_backup_root(&app).map(|(root, _location)| root);

    // Drain the missing-blob set. A hard enumerate failure propagates as BlobTransferFailed.
    let losses = drain_missing_blobs(
        pds_client,
        &dest_client,
        source_pds_url.as_deref(),
        &did,
        mirror_root.as_deref(),
    )
    .await?;

    // Some blobs couldn't be transferred. Unless the user has already accepted the loss, surface the
    // manifest and DON'T advance — the step stays retry-safe (the transferable blobs are already on
    // the destination; a Retry re-drains and may recover blobs that failed transiently).
    if !losses.is_empty() && !accept_loss {
        tracing::warn!(did = %did, lost = losses.len(), "transfer_blobs: drain incomplete; awaiting user decision");
        return Err(MigrationError::BlobDrainIncomplete { losses });
    }

    // Update orchestration state: record any accepted losses and advance to BlobsTransferred.
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
        if !losses.is_empty() {
            tracing::warn!(did = %did, accepted = losses.len(), "transfer_blobs: proceeding with an accepted blob-loss manifest");
        }
        mig.accepted_blob_loss = losses;
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

// ── Task 3: transfer_preferences ───────────────────────────────────────────

/// Pure core: get preferences from source and put them to destination.
/// Extracted for unit testability with mocked servers.
async fn transfer_preferences_impl(
    source_client: &OAuthClient,
    dest_client: &OAuthClient,
) -> Result<(), MigrationError> {
    // 1. Get preferences from source (old PDS, DPoP-authenticated)
    tracing::debug!("fetching preferences from source");
    let prefs = crate::pds_client::get_preferences(source_client)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to get preferences from source");
            MigrationError::PreferencesTransferFailed {
                message: format!("failed to get preferences: {}", e),
            }
        })?;

    // 2. Put preferences to destination (new PDS, Bearer-authenticated)
    tracing::debug!("uploading preferences to destination");
    crate::pds_client::put_preferences(dest_client, &prefs)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to put preferences to destination");
            MigrationError::PreferencesTransferFailed {
                message: format!("failed to put preferences: {}", e),
            }
        })?;

    Ok(())
}

/// Tauri command: get preferences from source PDS and put to destination.
///
/// Gate: ensure_phase_did(..., BlobsTransferred) → clone source_client AND dest_client; drop lock
/// Then: transfer_preferences_impl; re-lock + advance to PreferencesTransferred
#[tauri::command]
pub async fn transfer_preferences(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "transfer_preferences: getting and putting preferences");

    // Gate + extract dependencies
    let (source_client, dest_client, recovery) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::BlobsTransferred)
            .map_err(|e| {
                tracing::warn!("transfer_preferences: phase gate failed: {}", e);
                e
            })?;

        (
            mig.source_client.clone(),
            mig.dest_client.clone(),
            mig.recovery,
        )
    }; // lock released

    // Disaster recovery: there is no source to read preferences from and no
    // preferences backup exists — skip honestly and advance the phase so the rest of
    // the flow proceeds.
    if recovery {
        tracing::info!(did = %did, "transfer_preferences: recovery session has no preferences source; skipping");
        let mut orchestration = state.orchestration_state.lock().await;
        match orchestration.as_mut() {
            Some(mig) if mig.did == did => {
                mig.phase = MigrationPhase::PreferencesTransferred;
                return Ok(());
            }
            _ => {
                return Err(MigrationError::MigrationNotReady {
                    message: "orchestration state lost".into(),
                })
            }
        }
    }

    let Some(source_client) = source_client else {
        tracing::error!(did = %did, "transfer_preferences: source_client not found");
        return Err(MigrationError::SourceAuthFailed {
            message: "source client not authenticated".into(),
        });
    };

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "transfer_preferences: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // Transfer preferences (pure core, unit-tested).
    transfer_preferences_impl(&source_client, &dest_client).await?;

    // Update orchestration state: advance phase to PreferencesTransferred
    let mut orchestration = state.orchestration_state.lock().await;
    if let Some(ref mut mig) = orchestration.as_mut() {
        // Defense-in-depth DID check
        if mig.did != did {
            drop(orchestration);
            tracing::warn!("transfer_preferences: orchestration state did mismatch");
            return Err(MigrationError::MigrationNotReady {
                message: "did mismatch with orchestration state".into(),
            });
        }
        mig.phase = MigrationPhase::PreferencesTransferred;
    } else {
        drop(orchestration);
        return Err(MigrationError::MigrationNotReady {
            message: "orchestration state lost".into(),
        });
    }

    tracing::info!(did = %did, "preferences transferred successfully");
    Ok(())
}

// ── Task 4: verify_import ──────────────────────────────────────────────────

/// Pure completeness check: the import reconciles when every expected blob is accounted
/// for — either imported or on the user-accepted loss manifest — AND the repo is present. Does NOT
/// require valid_did (the DID doc still points at the old PDS pre-identity-op). `accepted_loss` is
/// the count of blobs the user explicitly chose to skip via the drain's manifest; on a clean
/// migration it is 0 and this reduces to the exact `imported == expected` check.
pub(crate) fn import_reconciles_with_loss(
    status: &crate::pds_client::AccountStatus,
    accepted_loss: u64,
) -> bool {
    status.imported_blobs.saturating_add(accepted_loss) == status.expected_blobs
        && status.repo_commit.is_some()
}

/// Tauri command: check destination account completeness, advance to Verified if reconciled.
///
/// Gate: ensure_phase_did(..., PreferencesTransferred) → clone dest_client; drop lock
/// Then: check_account_status(dest_client); if import_reconciles → advance to Verified & return status;
///       else → VerificationIncomplete with counts, phase unchanged
#[tauri::command]
pub async fn verify_import(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<crate::pds_client::AccountStatus, MigrationError> {
    tracing::info!(did = %did, "verify_import: checking account completeness");

    // Gate + extract dependencies. Capture the accepted blob-loss count so the reconcile check can
    // tolerate blobs the user explicitly chose to skip via the drain's manifest.
    let (dest_client, accepted_loss) = {
        let orchestration = state.orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, &did, MigrationPhase::PreferencesTransferred)
            .map_err(|e| {
                tracing::warn!("verify_import: phase gate failed: {}", e);
                e
            })?;

        (mig.dest_client.clone(), mig.accepted_blob_loss.len() as u64)
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "verify_import: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // Check account status on destination
    let status = crate::pds_client::check_account_status(&dest_client)
        .await
        .map_err(|e| {
            tracing::error!(did = %did, error = %e, "check_account_status failed");
            MigrationError::NetworkError {
                message: format!("failed to check account status: {}", e),
            }
        })?;

    // Gate: verify import is complete (blobs — imported or accepted-as-lost — plus repo)
    if import_reconciles_with_loss(&status, accepted_loss) {
        // Advance phase and return the status
        let mut orchestration = state.orchestration_state.lock().await;
        if let Some(ref mut mig) = orchestration.as_mut() {
            // Defense-in-depth DID check
            if mig.did != did {
                drop(orchestration);
                tracing::warn!("verify_import: orchestration state did mismatch");
                return Err(MigrationError::MigrationNotReady {
                    message: "did mismatch with orchestration state".into(),
                });
            }
            mig.phase = MigrationPhase::Verified;
        } else {
            drop(orchestration);
            return Err(MigrationError::MigrationNotReady {
                message: "orchestration state lost".into(),
            });
        }

        tracing::info!(did = %did, "import verified successfully");
        Ok(status)
    } else {
        // Import incomplete — return counts, phase unchanged
        tracing::warn!(
            did = %did,
            imported_blobs = status.imported_blobs,
            expected_blobs = status.expected_blobs,
            repo_commit = ?status.repo_commit,
            "import incomplete"
        );
        Err(MigrationError::VerificationIncomplete {
            imported: status.imported_blobs,
            expected: status.expected_blobs,
        })
    }
}

// ── Task 1: arm_identity_leg ───────────────────────────────────────────────

/// Tauri command: populate the migration identity-leg state with the destination Bearer client,
/// then advance to IdentityArmed.
///
/// Gate: ensure_phase_did(..., Verified) → clone dest_client; drop lock
/// Build fresh MigrationState { did, dest_oauth_client, signed_op: None, op_cid: None }; store in AppState
/// Advance phase → IdentityArmed
#[tauri::command]
pub async fn arm_identity_leg(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "arm_identity_leg: populating migration identity-leg state");
    arm_identity_leg_core(&state.orchestration_state, &state.migration_state, &did).await
}

/// Core of `arm_identity_leg`, parameterized over the two mutexes so it is unit-testable without a
/// Tauri `State`. Gate at Verified → build `migrate::MigrationState` with the dest Bearer client →
/// park it in `migration_state` → advance the orchestration phase to `IdentityArmed`. No network.
async fn arm_identity_leg_core(
    orchestration_state: &tokio::sync::Mutex<Option<OutboundMigrationState>>,
    migration_state: &tokio::sync::Mutex<Option<crate::migrate::MigrationState>>,
    did: &str,
) -> Result<(), MigrationError> {
    // Gate: ensure phase + DID, extract dest_client
    let dest_client = {
        let orchestration = orchestration_state.lock().await;
        let mig = ensure_phase_did(&orchestration, did, MigrationPhase::Verified).map_err(|e| {
            tracing::warn!("arm_identity_leg: phase gate failed: {}", e);
            e
        })?;
        mig.dest_client.clone()
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "arm_identity_leg: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // Build + park the identity-leg state (dest_oauth_client is Arc<OAuthClient>, NOT Option).
    *migration_state.lock().await = Some(crate::migrate::MigrationState {
        did: did.to_string(),
        dest_oauth_client: dest_client,
        signed_op: None,
        op_cid: None,
    });

    // Advance orchestration phase to IdentityArmed (defense-in-depth DID re-check under the lock).
    let mut orchestration = orchestration_state.lock().await;
    let Some(mig) = orchestration.as_mut() else {
        return Err(MigrationError::MigrationNotReady {
            message: "orchestration state lost".into(),
        });
    };
    if mig.did != did {
        return Err(MigrationError::MigrationNotReady {
            message: "did mismatch with orchestration state".into(),
        });
    }
    mig.phase = MigrationPhase::IdentityArmed;

    tracing::info!(did = %did, "identity leg armed successfully");
    Ok(())
}

// ── Task 2: finalize_migration ─────────────────────────────────────────────

/// Activate the destination account. First cutover step — retry-tolerant and
/// server-idempotent, so a resumed finalize can safely call it again.
async fn activate_destination_account(dest_client: &OAuthClient) -> Result<(), MigrationError> {
    tracing::debug!("finalizing migration: activating destination account");
    crate::pds_client::activate_account(dest_client)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "activate_account failed");
            MigrationError::ActivationFailed {
                message: format!("failed to activate destination account: {}", e),
            }
        })
}

/// Deactivate the source account (no `deleteAfter`). Last cutover step — runs only
/// after the destination is active AND its sovereign session is durably persisted,
/// so a wallet crash can never strand the account credential-less.
async fn deactivate_source_account(source_client: &OAuthClient) -> Result<(), MigrationError> {
    tracing::debug!("finalizing migration: deactivating source account");
    crate::pds_client::deactivate_account(source_client, None)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "deactivate_account failed");
            MigrationError::DeactivationFailed {
                message: format!("failed to deactivate source account: {}", e),
            }
        })
}

/// Map a sovereign-login failure onto the retryable pre-cutover migration errors.
/// A Keychain write failure is a *persistence* failure (the mint succeeded but could
/// not be saved); everything else is a *login* failure. Both keep the source active.
fn map_sovereign_error(error: crate::sovereign_session::SovereignLoginError) -> MigrationError {
    use crate::sovereign_session::SovereignLoginError as E;
    match error {
        E::KeychainFailure { message } => MigrationError::SessionPersistFailed { message },
        other => MigrationError::SovereignLoginFailed {
            message: other.to_string(),
        },
    }
}

/// Ensure the migrated DID has a durably persisted destination sovereign session,
/// minting one with the DID's current rotation key if needed.
///
/// Idempotency (the resume seam): if a persisted record whose *refresh* token is
/// still unexpired already exists, this returns `Ok` without signing anything — a
/// resumed finalize must not re-mint (and thus must not require a fresh device-key
/// signature) when a durable credential already exists. Only a missing or
/// refresh-expired record triggers a new device-signed mint via
/// `sovereign_login_impl`, which discovers plc.directory's current rotation set and
/// the hosted account, proves control, and atomically replaces the token record.
async fn ensure_sovereign_session_persisted(
    pds_client: &crate::pds_client::PdsClient,
    store: &crate::identity_store::IdentityStore,
    did: &str,
    now: i64,
    nonce: &str,
) -> Result<(), MigrationError> {
    if let Some(record) =
        store
            .load_oauth_tokens(did)
            .map_err(|e| MigrationError::SessionPersistFailed {
                message: e.to_string(),
            })?
    {
        if record
            .refresh_expires_at
            .is_some_and(|exp| (exp as i64) > now)
        {
            tracing::info!(did = %did, "sovereign session already persisted; skipping re-mint");
            return Ok(());
        }
    }

    crate::sovereign_session::sovereign_login_impl(pds_client, store, did, now, nonce)
        .await
        .map(|_| ())
        .map_err(map_sovereign_error)
}

/// Tauri command: run the safe cutover — activate the destination, mint + persist its
/// sovereign session, deactivate the source, then advance to Finalized.
///
/// Gate: ensure_phase_did(..., IdentityArmed) → defense-in-depth: migration_state
/// must be cleared (None) to prove the identity op was submitted; if Some → MIGRATION_NOT_READY.
/// The sovereign-session mint runs against the DID's *current* PLC rotation set (the identity op
/// has already landed) using a fresh device-key proof; the frontend re-gates biometric before
/// every finalize invocation, so a resumed attempt obtains fresh authorization before that
/// signature (and the idempotent skip means an already-persisted session signs nothing at all).
#[tauri::command]
pub async fn finalize_migration(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), MigrationError> {
    tracing::info!(did = %did, "finalize_migration: activate → sovereign session → deactivate");

    // Proof material for the sovereign-session mint (imperative shell: clock + RNG).
    let now = crate::sovereign_session::unix_timestamp().map_err(map_sovereign_error)?;
    let nonce = crate::sovereign_session::fresh_nonce();
    let pds_client = state.pds_client();
    let session_did = did.clone();

    finalize_migration_core(
        &state.orchestration_state,
        &state.migration_state,
        &did,
        || async move {
            ensure_sovereign_session_persisted(
                pds_client,
                &crate::identity_store::IdentityStore,
                &session_did,
                now,
                &nonce,
            )
            .await
        },
    )
    .await
}

/// Core of `finalize_migration`, parameterized over the two mutexes and an injected
/// `ensure_session` step so its gating, ordering, and phase advance are unit-testable without a
/// Tauri `State`, a Keychain, or a live PDS. Gate at IdentityArmed; require the migrate
/// `migration_state` cleared (== None, proving `submit_migration_op_cmd` ran); then run the cutover
/// in strict order — **activate destination → ensure sovereign session persisted → deactivate
/// source** — and advance to `Finalized`.
///
/// The ordering is the whole point: `ensure_session` (mint + Keychain persist) runs *after*
/// activation and *before* deactivation, so a sovereign-login or persistence failure aborts the
/// cutover with the source still active and no phase advance — retryable, never `Finalized`.
async fn finalize_migration_core<Fut>(
    orchestration_state: &tokio::sync::Mutex<Option<OutboundMigrationState>>,
    migration_state: &tokio::sync::Mutex<Option<crate::migrate::MigrationState>>,
    did: &str,
    ensure_session: impl FnOnce() -> Fut,
) -> Result<(), MigrationError>
where
    Fut: std::future::Future<Output = Result<(), MigrationError>>,
{
    // Gate: ensure phase + DID, extract clients
    let (dest_client, source_client, recovery) = {
        let orchestration = orchestration_state.lock().await;
        let mig =
            ensure_phase_did(&orchestration, did, MigrationPhase::IdentityArmed).map_err(|e| {
                tracing::warn!("finalize_migration: phase gate failed: {}", e);
                e
            })?;
        (
            mig.dest_client.clone(),
            mig.source_client.clone(),
            mig.recovery,
        )
    }; // lock released

    let Some(dest_client) = dest_client else {
        tracing::error!(did = %did, "finalize_migration: dest_client not found");
        return Err(MigrationError::AccountCreationFailed {
            message: "destination client not authenticated".into(),
        });
    };

    // A disaster recovery has no source to deactivate — the source PDS is presumed
    // dead. A normal migration requires the authenticated source client for step 3.
    let source_client = if recovery {
        None
    } else {
        match source_client {
            Some(client) => Some(client),
            None => {
                tracing::error!(did = %did, "finalize_migration: source_client not found");
                return Err(MigrationError::SourceAuthFailed {
                    message: "source client not authenticated".into(),
                });
            }
        }
    };

    // Defense-in-depth: the identity op must have been submitted (migration_state cleared).
    if migration_state.lock().await.is_some() {
        tracing::error!(did = %did, "finalize_migration: migration identity op not yet submitted");
        return Err(MigrationError::MigrationNotReady {
            message: "identity op not yet submitted".into(),
        });
    }

    // 1. Activate destination (idempotent, server-side).
    activate_destination_account(&dest_client).await?;

    // 2. Mint + persist the destination sovereign session BEFORE touching the source. A failure
    //    here (login rejected/rate-limited/5xx/transport, or Keychain write) leaves the source
    //    active and is retryable; the migration never reaches `Finalized`.
    ensure_session().await?;

    // 3. Deactivate source (no deleteAfter) — the destination credential is now durable.
    //    Skipped entirely in a disaster recovery: the source is gone, and there is
    //    nothing to deactivate.
    if let Some(source_client) = &source_client {
        deactivate_source_account(source_client).await?;
    }

    // Advance orchestration phase to Finalized (defense-in-depth DID re-check under the lock).
    let mut orchestration = orchestration_state.lock().await;
    let Some(mig) = orchestration.as_mut() else {
        return Err(MigrationError::MigrationNotReady {
            message: "orchestration state lost".into(),
        });
    };
    if mig.did != did {
        return Err(MigrationError::MigrationNotReady {
            message: "did mismatch with orchestration state".into(),
        });
    }
    mig.phase = MigrationPhase::Finalized;

    tracing::info!(did = %did, "migration finalized successfully");
    Ok(())
}

// ── Helper: extract handle from also_known_as ───────────────────────────────

pub(crate) fn extract_handle_from_also_known_as(also_known_as: &[String]) -> Option<String> {
    for entry in also_known_as {
        if let Some(handle) = entry.strip_prefix("at://") {
            if !handle.starts_with("did:") {
                return Some(handle.to_string());
            }
        }
    }
    None
}

pub(crate) fn preferred_login_identifier(also_known_as: &[String], did: &str) -> String {
    extract_handle_from_also_known_as(also_known_as).unwrap_or_else(|| did.to_string())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;

    // Phase too low returns MigrationNotReady
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
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::RepoTransferred);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // DID mismatch returns MigrationNotReady
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
            accepted_blob_loss: Vec::new(),
            recovery: false,
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

    // Happy path — state present, DID matches, phase sufficient
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
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::SourceAuthed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().phase, MigrationPhase::RepoTransferred);
    }

    // MigrationError serialization — MigrationNotReady
    #[test]
    fn test_migration_error_serialization_not_ready() {
        let err = MigrationError::MigrationNotReady {
            message: "test message".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "MIGRATION_NOT_READY");
        assert_eq!(json["message"], "test message");
    }

    // MigrationError serialization — VerificationIncomplete
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

    // MigrationError serialization — BlobDrainIncomplete carries the loss manifest with camelCase
    // fields and a lowercase direction, the exact shape the wallet's `BlobLoss` type consumes.
    #[test]
    fn test_migration_error_serialization_blob_drain_incomplete() {
        let err = MigrationError::BlobDrainIncomplete {
            losses: vec![
                BlobLoss {
                    cid: "bafyfetch".into(),
                    record_uri: "at://did:plc:abc/app.bsky.feed.post/1".into(),
                    direction: BlobTransferDirection::Source,
                    reason: "server error (500)".into(),
                },
                BlobLoss {
                    cid: "bafyupload".into(),
                    record_uri: "at://did:plc:abc/app.bsky.feed.post/2".into(),
                    direction: BlobTransferDirection::Destination,
                    reason: "rejected".into(),
                },
            ],
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "BLOB_DRAIN_INCOMPLETE");
        assert_eq!(json["losses"][0]["cid"], "bafyfetch");
        assert_eq!(
            json["losses"][0]["recordUri"],
            "at://did:plc:abc/app.bsky.feed.post/1"
        );
        assert_eq!(json["losses"][0]["direction"], "source");
        assert_eq!(json["losses"][0]["reason"], "server error (500)");
        assert_eq!(json["losses"][1]["direction"], "destination");
    }

    // MigrationError serialization — DestinationUnreachable
    #[test]
    fn test_migration_error_serialization_destination_unreachable() {
        let err = MigrationError::DestinationUnreachable {
            message: "connection refused".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DESTINATION_UNREACHABLE");
        assert_eq!(json["message"], "connection refused");
    }

    // MigrationError serialization — SourceAuthFailed
    #[test]
    fn test_migration_error_serialization_source_auth_failed() {
        let err = MigrationError::SourceAuthFailed {
            message: "invalid grant".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "SOURCE_AUTH_FAILED");
        assert_eq!(json["message"], "invalid grant");
    }

    // MigrationError serialization — DestinationConflict
    #[test]
    fn test_migration_error_serialization_destination_conflict() {
        let err = MigrationError::DestinationConflict {
            message: "account exists but session was lost".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DESTINATION_CONFLICT");
        assert_eq!(json["message"], "account exists but session was lost");
    }

    // ── Task 5 tests: source-PDS password login ────────────────────────────

    // authenticate_migration_source with the wrong DID returns MIGRATION_NOT_READY (pure gate)
    #[test]
    fn test_authenticate_migration_source_did_mismatch_gate() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::Resolved,
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:different", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // authenticate_migration_source gates at phase >= Resolved. Resolved is the first phase, so a
    // "phase too low" case is impossible; the only gate failures are no-state and did-mismatch.
    #[test]
    fn test_authenticate_migration_source_no_state_gate() {
        // No state → gate fails
        let result = ensure_phase_did(&None, "did:plc:abc123", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // ── source-login error mapping ──────────────────────────────────────────────

    /// The shared `createSession` body + account-match guard now live in `source_login`, tested
    /// once there against a mock PDS. What remains migration-specific is the
    /// `From<SourceLoginError>` mapping into `MigrationError`; this unit test pins that contract so
    /// a variant can't silently remap. `authenticate_migration_source_impl` is a thin
    /// `.map_err(MigrationError::from)` over the shared core, so the mapping is the only
    /// migration-owned behavior left to cover.
    #[test]
    fn test_source_login_error_maps_to_migration_error() {
        use crate::source_login::SourceLoginError as S;

        assert!(matches!(
            MigrationError::from(S::TwoFactorRequired),
            MigrationError::TwoFactorRequired
        ));
        assert!(matches!(
            MigrationError::from(S::AccountMismatch),
            MigrationError::AccountMismatch
        ));
        assert!(matches!(
            MigrationError::from(S::InsecureSourceUrl),
            MigrationError::InsecureSourceUrl
        ));
        assert!(matches!(
            MigrationError::from(S::SourceAuthFailed {
                message: "The PDS did not accept that password.".to_string()
            }),
            MigrationError::SourceAuthFailed { message } if message == "The PDS did not accept that password."
        ));
        assert!(matches!(
            MigrationError::from(S::RateLimited {
                retry_after: Some("120".to_string())
            }),
            MigrationError::RateLimited { retry_after: Some(r) } if r == "120"
        ));
        assert!(matches!(
            MigrationError::from(S::ServerError {
                message: "handle is required".to_string()
            }),
            MigrationError::ServerError { message } if message == "handle is required"
        ));
        assert!(matches!(
            MigrationError::from(S::NetworkError {
                message: "connection refused".to_string()
            }),
            MigrationError::NetworkError { message } if message == "connection refused"
        ));
    }

    // Serialization of the password-login error variants (frontend switches on these codes).
    #[test]
    fn test_migration_error_serialization_two_factor_required() {
        let json = serde_json::to_value(MigrationError::TwoFactorRequired).unwrap();
        assert_eq!(json["code"], "TWO_FACTOR_REQUIRED");
    }

    #[test]
    fn test_migration_error_serialization_account_mismatch() {
        let json = serde_json::to_value(MigrationError::AccountMismatch).unwrap();
        assert_eq!(json["code"], "ACCOUNT_MISMATCH");
    }

    #[test]
    fn test_migration_error_serialization_insecure_source_url() {
        let json = serde_json::to_value(MigrationError::InsecureSourceUrl).unwrap();
        assert_eq!(json["code"], "INSECURE_SOURCE_URL");
    }

    #[test]
    fn test_migration_error_serialization_rate_limited() {
        let json = serde_json::to_value(MigrationError::RateLimited {
            retry_after: Some("30".into()),
        })
        .unwrap();
        assert_eq!(json["code"], "RATE_LIMITED");
        // Serialized as camelCase `retryAfter`, matching the frontend MigrationError union.
        assert_eq!(json["retryAfter"], "30");
    }

    #[test]
    fn test_migration_error_serialization_server_error() {
        let json = serde_json::to_value(MigrationError::ServerError {
            message: "handle is required".into(),
        })
        .unwrap();
        assert_eq!(json["code"], "SERVER_ERROR");
        assert_eq!(json["message"], "handle is required");
    }

    // `prepare_migration` returns this to the source-auth screen; the frontend `PreparedMigration`
    // type reads `handle` + `sourcePdsUrl`, so the camelCase rename must stay exact.
    #[test]
    fn test_prepared_migration_serializes_camel_case() {
        let json = serde_json::to_value(PreparedMigration {
            handle: "alice.test".into(),
            source_pds_url: "https://source.pds".into(),
        })
        .unwrap();
        assert_eq!(json["handle"], "alice.test");
        assert_eq!(json["sourcePdsUrl"], "https://source.pds");
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

    // create_destination_account_impl with an existing dest_client returns it (idempotent
    // re-establish) WITHOUT any network — the fast path short-circuits before reserve/serviceAuth/
    // createAccount, so this also covers "409-with-existing is tolerated" (createAccount is never
    // reached when a client is held). No #[ignore] needed: no socket is bound.
    #[tokio::test]
    async fn test_create_destination_account_impl_idempotent_with_existing_client() {
        let existing = Arc::new(
            OAuthClient::new_bearer(
                make_bearer_jwt(9999999999),
                String::new(),
                "https://dest.pds".into(),
            )
            .unwrap(),
        );
        // Dummy deps that must never be touched (unreachable URLs prove the fast path took over).
        let pds_client = crate::pds_client::PdsClient::new();
        let source_client = Arc::new(
            OAuthClient::new_bearer(
                make_bearer_jwt(9999999999),
                String::new(),
                "http://127.0.0.1:1".into(),
            )
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

    // createAccount 409 with NO existing dest_client → DESTINATION_CONFLICT (session lost).
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
            OAuthClient::new_bearer(
                make_bearer_jwt(9999999999),
                String::new(),
                source.base_url(),
            )
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
            OAuthClient::new_bearer(
                make_bearer_jwt(9999999999),
                String::new(),
                source.base_url(),
            )
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

    // create_destination_account before SourceAuthed phase returns MIGRATION_NOT_READY
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
            accepted_blob_loss: Vec::new(),
            recovery: false,
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

    // Only non-at:// entries present → None.
    #[test]
    fn test_extract_handle_from_also_known_as_no_at_uri() {
        let entries = vec![
            "https://example.com/user/alice".to_string(),
            "mailto:alice@example.com".to_string(),
        ];
        let result = extract_handle_from_also_known_as(&entries);
        assert_eq!(result, None);
    }

    #[test]
    fn test_preferred_login_identifier_skips_did_alias_for_handle() {
        let entries = vec![
            "at://did:plc:abc123".to_string(),
            "at://alice.test".to_string(),
        ];

        assert_eq!(
            preferred_login_identifier(&entries, "did:plc:abc123"),
            "alice.test"
        );
    }

    #[test]
    fn test_preferred_login_identifier_falls_back_to_did() {
        let entries = vec!["at://did:plc:abc123".to_string()];

        assert_eq!(
            preferred_login_identifier(&entries, "did:plc:abc123"),
            "did:plc:abc123"
        );
    }

    // ── Task 1 tests: transfer_repo ────────────────────────────────────────

    // transfer_repo fetches source CAR and imports to dest, advances phase.
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
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::DestCreated);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // transfer_repo phase gate (pure test, no network)
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
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::DestCreated);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // ── Task 2 tests: transfer_blobs ───────────────────────────────────────

    // transfer_blobs phase gate (pure test, no network)
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
            accepted_blob_loss: Vec::new(),
            recovery: false,
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

    // Fetch the source CAR and POST the exact bytes to the destination importRepo.
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

        let result = transfer_repo_impl(
            &pds_client,
            &dest_client,
            &source.base_url(),
            "did:plc:abc123",
            None,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(get_repo.calls(), 1);
        assert_eq!(import.calls(), 1);
    }

    // Failure case: a dest importRepo 500 → RepoTransferFailed (command leaves phase un-advanced).
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

        let result = transfer_repo_impl(
            &pds_client,
            &dest_client,
            &source.base_url(),
            "did:plc:abc123",
            None,
        )
        .await;

        assert!(matches!(
            result,
            Err(MigrationError::RepoTransferFailed { .. })
        ));
    }

    // The payoff: the source PDS can't serve getRepo, but the wallet has a validated iCloud snapshot
    // for the DID — the transfer recovers the repo from the mirror and imports it, so a dead source
    // repo is a non-event for a backed-up user.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_transfer_repo_falls_back_to_local_mirror_on_source_failure() {
        let did = "did:plc:repomirrorfallback";

        // Seed a local mirror with a valid snapshot, as a completed repo-backup pass would leave it.
        let mirror = tempfile::tempdir().unwrap();
        let car = crate::repo_backup::seed_mirror_repo_for_test(mirror.path(), did).await;

        // The source PDS permanently 500s getRepo (the repo twin of the observed migration fault).
        let source = MockServer::start();
        let get_repo = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo");
            then.status(500).body("repo bytes are gone");
        });
        // The destination importRepo must succeed — reached only via the mirror fallback.
        let dest = MockServer::start();
        let import = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo");
            then.status(200);
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result = transfer_repo_impl(
            &pds_client,
            &dest_client,
            &source.base_url(),
            did,
            Some(mirror.path()),
        )
        .await;

        assert!(
            result.is_ok(),
            "the repo was recovered from the iCloud mirror after the source getRepo failure"
        );
        assert!(
            get_repo.calls() >= 1,
            "the source was tried before falling back"
        );
        assert_eq!(
            import.calls(),
            1,
            "the mirror's validated snapshot was imported to the destination"
        );
        // Sanity: the seeded snapshot is a real, non-empty CAR (it is what got imported).
        assert!(!car.is_empty());
    }

    // The fallback never masks a genuine failure: with the mirror empty (no snapshot for the DID),
    // a source getRepo failure is surfaced unchanged as REPO_TRANSFER_FAILED and no import happens.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_transfer_repo_preserves_source_failure_with_empty_mirror() {
        let did = "did:plc:repomirrormiss";

        // An empty mirror (no snapshot seeded for this DID).
        let mirror = tempfile::tempdir().unwrap();

        let source = MockServer::start();
        let get_repo = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo");
            then.status(500).body("gone");
        });
        let dest = MockServer::start();
        let import = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo");
            then.status(200);
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result = transfer_repo_impl(
            &pds_client,
            &dest_client,
            &source.base_url(),
            did,
            Some(mirror.path()),
        )
        .await;

        assert!(
            matches!(result, Err(MigrationError::RepoTransferFailed { .. })),
            "an empty mirror preserves the original source failure unchanged"
        );
        assert!(get_repo.calls() >= 1);
        assert_eq!(
            import.calls(),
            0,
            "no import is attempted when the mirror has no valid snapshot"
        );
    }

    // ── Task 2 mock tests: drain_missing_blobs ─────────────────────────────

    // An empty first page completes immediately with no getBlob/uploadBlob calls.
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
        let result = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some("http://127.0.0.1:1"),
            "did:plc:abc123",
            None,
        )
        .await;

        assert!(result.is_ok());
    }

    // Walk two cursor pages, fetch every missing CID from source and upload to dest
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

        let result = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some(&source.base_url()),
            "did:plc:abc123",
            None,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(get_a.calls(), 1, "cid_a fetched once");
        assert_eq!(get_b.calls(), 1, "cid_b fetched once");
        assert_eq!(get_c.calls(), 1, "cid_c fetched once");
        assert_eq!(upload.calls(), 3, "each of the 3 blobs uploaded once");
    }

    // A permanently-failing source getBlob no longer aborts the drain. The blob is retried,
    // given up on, and returned in the loss manifest (direction=Source) — the drain still completes.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_missing_blobs_records_loss_instead_of_aborting() {
        let source = MockServer::start();
        let get = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob");
            then.status(500).body("blob fetch error");
        });
        let dest = MockServer::start();
        // Stateless mock: keeps re-reporting cid_a as missing. The drain's give-up set must still
        // converge the loop and return the loss.
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs");
            then.status(200).json_body(serde_json::json!({
                "blobs": [ { "cid": "cid_a", "recordUri": "at://did:plc:abc123/x/1" } ],
                "cursor": null
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let losses = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some(&source.base_url()),
            "did:plc:abc123",
            None,
        )
        .await
        .expect("drain degrades per-blob rather than erroring");

        assert_eq!(losses.len(), 1, "the one dead blob is on the manifest");
        assert_eq!(losses[0].cid, "cid_a");
        assert_eq!(losses[0].direction, BlobTransferDirection::Source);
        assert_eq!(losses[0].record_uri, "at://did:plc:abc123/x/1");
        assert_eq!(
            get.calls(),
            BLOB_TRANSFER_ATTEMPTS as usize,
            "fetch retried up to the cap"
        );
    }

    // A good blob is transferred while a dead one is skipped onto the manifest — one bad
    // blob doesn't take the healthy ones down with it.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_missing_blobs_mixed_good_and_bad() {
        let source = MockServer::start();
        let get_good = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob")
                .query_param("cid", "cid_good");
            then.status(200).body("good-bytes");
        });
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob")
                .query_param("cid", "cid_bad");
            then.status(500).body("gone");
        });
        let dest = MockServer::start();
        // Page 1 (no cursor): both blobs, cursor c1. Page 2 (c1): empty — a real server drops the
        // uploaded good blob from the missing set, so the drain advances to the empty page and
        // returns with only the given-up bad blob on the manifest.
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param_missing("cursor");
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "cid_good", "recordUri": "at://did:plc:abc123/x/1" },
                    { "cid": "cid_bad", "recordUri": "at://did:plc:abc123/x/2" }
                ],
                "cursor": "c1"
            }));
        });
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "c1");
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

        let losses = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some(&source.base_url()),
            "did:plc:abc123",
            None,
        )
        .await
        .expect("drain completes with a partial loss");

        assert_eq!(get_good.calls(), 1, "the good blob is fetched once");
        assert_eq!(upload.calls(), 1, "only the good blob is uploaded");
        assert_eq!(losses.len(), 1, "only the bad blob is on the manifest");
        assert_eq!(losses[0].cid, "cid_bad");
    }

    // The payoff: a blob the source PDS can't serve is recovered from the local mirror instead of
    // being recorded as lost. The mirror holds a verified copy; the drain uploads it to the
    // destination and the loss manifest stays empty.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_falls_back_to_local_mirror_on_source_failure() {
        let did = "did:plc:mirrorfallback";
        let blob = b"media the source PDS lost but the wallet backed up".to_vec();

        // Seed a local mirror with the verified blob, as a completed backup pass would leave it.
        let mirror = tempfile::tempdir().unwrap();
        let cid =
            crate::blob_backup::seed_mirror_blob_for_test(mirror.path(), did, &blob, "image/png")
                .await;

        // The source PDS permanently 500s getBlob for this CID (the observed real-migration fault).
        let source = MockServer::start();
        let get = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob");
            then.status(500).body("blob bytes are gone");
        });

        // Two pages: page 1 lists the CID, page 2 is empty so the loop terminates after the
        // mirror-sourced upload removes it from the destination's missing set.
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param_missing("cursor");
            then.status(200).json_body(serde_json::json!({
                "blobs": [ { "cid": cid, "recordUri": "at://did:plc:mirrorfallback/app.bsky.feed.post/1" } ],
                "cursor": "c1"
            }));
        });
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "c1");
            then.status(200)
                .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
        });
        let upload = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.uploadBlob")
                .body(std::str::from_utf8(&blob).unwrap());
            then.status(200)
                .json_body(serde_json::json!({ "blob": { "$type": "blob" } }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let losses = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some(&source.base_url()),
            did,
            Some(mirror.path()),
        )
        .await
        .expect("drain completes by recovering the blob from the mirror");

        assert!(
            losses.is_empty(),
            "the blob was recovered from the mirror, not lost"
        );
        assert_eq!(
            get.calls(),
            BLOB_TRANSFER_ATTEMPTS as usize,
            "the source was tried up to the retry cap before falling back"
        );
        assert_eq!(
            upload.calls(),
            1,
            "the mirror's verified bytes were uploaded to the destination"
        );
    }

    // The fallback never masks a genuine loss: when the mirror is present but doesn't hold the
    // failing blob, the drain still records it (direction=Source) rather than silently succeeding.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_records_loss_when_mirror_lacks_the_blob() {
        let did = "did:plc:mirrormiss";

        // An empty mirror (no manifest entry for the failing CID).
        let mirror = tempfile::tempdir().unwrap();

        let source = MockServer::start();
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob");
            then.status(500).body("gone");
        });
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs");
            then.status(200).json_body(serde_json::json!({
                "blobs": [ { "cid": "cid_absent", "recordUri": "at://did:plc:mirrormiss/x/1" } ],
                "cursor": null
            }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let losses = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some(&source.base_url()),
            did,
            Some(mirror.path()),
        )
        .await
        .expect("drain degrades per-blob rather than erroring");

        assert_eq!(losses.len(), 1, "the blob the mirror lacks is still lost");
        assert_eq!(losses[0].cid, "cid_absent");
        assert_eq!(losses[0].direction, BlobTransferDirection::Source);
    }

    // Failing to even enumerate the missing set is a hard error (no manifest is possible),
    // so the drain still aborts with BlobTransferFailed and the phase never advances.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_drain_missing_blobs_list_failure_is_hard_error() {
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs");
            then.status(500).body("cannot list");
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some("http://127.0.0.1:1"),
            "did:plc:abc123",
            None,
        )
        .await;

        assert!(matches!(
            result,
            Err(MigrationError::BlobTransferFailed { .. })
        ));
    }

    // ── Task 3 tests: transfer_preferences ─────────────────────────────────

    // Pure gate test: transfer_preferences before BlobsTransferred phase fails
    #[test]
    fn test_transfer_preferences_phase_too_low() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::RepoTransferred, // Too early for transfer_preferences!
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::BlobsTransferred);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // transfer_preferences fetches from source and posts to destination, advances phase.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_transfer_preferences_impl_success() {
        let source = MockServer::start();
        let get_prefs = source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences");
            then.status(200).json_body(serde_json::json!({
                "preferences": [
                    { "name": "theme", "value": "dark" }
                ]
            }));
        });

        let dest = MockServer::start();
        let put_prefs = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/app.bsky.actor.putPreferences")
                .json_body(serde_json::json!({
                    "preferences": [
                        { "name": "theme", "value": "dark" }
                    ]
                }));
            then.status(200);
        });

        let source_client = bearer_client_at(source.base_url());
        let dest_client = bearer_client_at(dest.base_url());

        let result = transfer_preferences_impl(&source_client, &dest_client).await;

        assert!(result.is_ok());
        assert_eq!(get_prefs.calls(), 1);
        assert_eq!(put_prefs.calls(), 1);
    }

    // Failure case: source getPreferences 500 → PreferencesTransferFailed
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_transfer_preferences_impl_source_failure() {
        let source = MockServer::start();
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences");
            then.status(500).body("server error");
        });

        let dest = MockServer::start();

        let source_client = bearer_client_at(source.base_url());
        let dest_client = bearer_client_at(dest.base_url());

        let result = transfer_preferences_impl(&source_client, &dest_client).await;

        assert!(matches!(
            result,
            Err(MigrationError::PreferencesTransferFailed { .. })
        ));
    }

    // Failure case: dest putPreferences 500 → PreferencesTransferFailed
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_transfer_preferences_impl_dest_failure() {
        let source = MockServer::start();
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences");
            then.status(200).json_body(serde_json::json!({
                "preferences": []
            }));
        });

        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/app.bsky.actor.putPreferences");
            then.status(500).body("server error");
        });

        let source_client = bearer_client_at(source.base_url());
        let dest_client = bearer_client_at(dest.base_url());

        let result = transfer_preferences_impl(&source_client, &dest_client).await;

        assert!(matches!(
            result,
            Err(MigrationError::PreferencesTransferFailed { .. })
        ));
    }

    // ── Task 4 tests: verify_import ────────────────────────────────────────

    // Pure: import_reconciles is true when imported_blobs == expected_blobs AND repo_commit exists
    #[test]
    fn test_import_reconciles_true_when_complete() {
        let status = crate::pds_client::AccountStatus {
            activated: false,
            valid_did: true,
            repo_commit: Some("baffy".to_string()),
            repo_rev: Some("rev".to_string()),
            stored_blocks: 10,
            indexed_records: 5,
            private_state_values: 0,
            expected_blobs: 10,
            imported_blobs: 10,
        };

        assert!(import_reconciles_with_loss(&status, 0));
    }

    // Pure: import_reconciles is true even when valid_did = false
    #[test]
    fn test_import_reconciles_ignores_valid_did() {
        let status = crate::pds_client::AccountStatus {
            activated: false,
            valid_did: false, // Still invalid DID, but import reconciles
            repo_commit: Some("baffy".to_string()),
            repo_rev: Some("rev".to_string()),
            stored_blocks: 10,
            indexed_records: 5,
            private_state_values: 0,
            expected_blobs: 10,
            imported_blobs: 10,
        };

        assert!(import_reconciles_with_loss(&status, 0));
    }

    // Pure: import_reconciles is false when imported_blobs < expected_blobs
    #[test]
    fn test_import_reconciles_false_when_blobs_incomplete() {
        let status = crate::pds_client::AccountStatus {
            activated: false,
            valid_did: true,
            repo_commit: Some("baffy".to_string()),
            repo_rev: Some("rev".to_string()),
            stored_blocks: 10,
            indexed_records: 5,
            private_state_values: 0,
            expected_blobs: 10,
            imported_blobs: 5, // Incomplete
        };

        assert!(!import_reconciles_with_loss(&status, 0));
    }

    // Pure: import_reconciles is false when repo_commit is None
    #[test]
    fn test_import_reconciles_false_when_repo_absent() {
        let status = crate::pds_client::AccountStatus {
            activated: false,
            valid_did: true,
            repo_commit: None, // No repo yet
            repo_rev: None,
            stored_blocks: 0,
            indexed_records: 0,
            private_state_values: 0,
            expected_blobs: 10,
            imported_blobs: 10,
        };

        assert!(!import_reconciles_with_loss(&status, 0));
    }

    // Pure: a degraded import reconciles when imported + accepted-loss == expected. The
    // skipped blobs never arrive, so without the tolerance verify_import would reject forever.
    #[test]
    fn test_import_reconciles_with_loss_tolerates_accepted_skips() {
        let status = crate::pds_client::AccountStatus {
            activated: false,
            valid_did: true,
            repo_commit: Some("baffy".to_string()),
            repo_rev: Some("rev".to_string()),
            stored_blocks: 10,
            indexed_records: 5,
            private_state_values: 0,
            expected_blobs: 10,
            imported_blobs: 7, // 3 blobs permanently lost
        };

        // 3 accepted losses close the gap; 2 leaves it open; 0 (exact) fails.
        assert!(import_reconciles_with_loss(&status, 3));
        assert!(!import_reconciles_with_loss(&status, 2));
        assert!(!import_reconciles_with_loss(&status, 0));
    }

    // Pure: accepted loss never papers over a MISSING repo — a degraded blob set with no
    // repo commit must still fail the gate.
    #[test]
    fn test_import_reconciles_with_loss_still_requires_repo() {
        let status = crate::pds_client::AccountStatus {
            activated: false,
            valid_did: true,
            repo_commit: None,
            repo_rev: None,
            stored_blocks: 0,
            indexed_records: 0,
            private_state_values: 0,
            expected_blobs: 10,
            imported_blobs: 7,
        };

        assert!(!import_reconciles_with_loss(&status, 3));
    }

    // Pure: the per-blob backoff is 250ms after the 1st failure, 500ms after the 2nd.
    #[test]
    fn test_blob_backoff_schedule() {
        assert_eq!(blob_backoff(1), std::time::Duration::from_millis(250));
        assert_eq!(blob_backoff(2), std::time::Duration::from_millis(500));
    }

    // A real checkAccountStatus payload with imported==expected and a repo commit passes the
    // import_reconciles gate (the branch verify_import uses to decide whether to advance to Verified).
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_verify_import_gate_reconciles_on_complete_status() {
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus");
            then.status(200).json_body(serde_json::json!({
                "activated": false,
                "validDid": true,
                "repoCommit": "baffy",
                "repoRev": "rev",
                "storedBlocks": 10,
                "indexedRecords": 5,
                "privateStateValues": 0,
                "expectedBlobs": 10,
                "importedBlobs": 10
            }));
        });

        let dest_client = bearer_client_at(dest.base_url());

        let status = crate::pds_client::check_account_status(&dest_client)
            .await
            .unwrap();

        assert!(import_reconciles_with_loss(&status, 0));
        assert_eq!(status.imported_blobs, 10);
        assert_eq!(status.expected_blobs, 10);
    }

    // A real checkAccountStatus payload with imported<expected fails the import_reconciles
    // gate (the branch on which verify_import returns VerificationIncomplete with these counts).
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_verify_import_gate_rejects_incomplete_status() {
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus");
            then.status(200).json_body(serde_json::json!({
                "activated": false,
                "validDid": false,
                "repoCommit": null,
                "repoRev": null,
                "storedBlocks": 0,
                "indexedRecords": 0,
                "privateStateValues": 0,
                "expectedBlobs": 10,
                "importedBlobs": 5
            }));
        });

        let dest_client = bearer_client_at(dest.base_url());

        let status = crate::pds_client::check_account_status(&dest_client)
            .await
            .unwrap();

        // Verify the pure gate catches the incompleteness
        assert!(!import_reconciles_with_loss(&status, 0));
        assert_eq!(status.imported_blobs, 5);
        assert_eq!(status.expected_blobs, 10);
    }

    // ── Task 1 tests: arm_identity_leg ─────────────────────────────────────

    // Pure gate: arm_identity_leg before Verified phase returns MIGRATION_NOT_READY
    #[test]
    fn test_arm_identity_leg_phase_gate_too_low() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: Some(Arc::new(bearer_client_at("https://dest.pds".into()))),
            phase: MigrationPhase::PreferencesTransferred, // Too early!
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::Verified);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // Build a Verified OutboundMigrationState with both clients populated.
    fn verified_state(did: &str) -> OutboundMigrationState {
        OutboundMigrationState {
            did: did.into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: Some(Arc::new(bearer_client_at("https://source.pds".into()))),
            dest_client: Some(Arc::new(bearer_client_at("https://dest.pds".into()))),
            phase: MigrationPhase::Verified,
            accepted_blob_loss: Vec::new(),
            recovery: false,
        }
    }

    // The REAL arm_identity_leg_core parks a migrate::MigrationState AND advances the
    // orchestration phase to IdentityArmed (drives production code, not a hand-rolled copy).
    #[tokio::test]
    async fn test_arm_identity_leg_core_populates_state_and_advances_phase() {
        let did = "did:plc:abc123";
        let orchestration = tokio::sync::Mutex::new(Some(verified_state(did)));
        let migration_state = tokio::sync::Mutex::new(None);

        arm_identity_leg_core(&orchestration, &migration_state, did)
            .await
            .expect("arm should succeed on a Verified state");

        // migrate::MigrationState parked with the right DID …
        let mig = migration_state.lock().await;
        assert_eq!(mig.as_ref().expect("migration_state parked").did, did);
        // … and the orchestration phase advanced to IdentityArmed.
        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::IdentityArmed
        );
    }

    // arm_identity_leg_core before Verified → MIGRATION_NOT_READY, and nothing is parked.
    #[tokio::test]
    async fn test_arm_identity_leg_core_gate_before_verified() {
        let did = "did:plc:abc123";
        let mut early = verified_state(did);
        early.phase = MigrationPhase::PreferencesTransferred; // one below Verified
        let orchestration = tokio::sync::Mutex::new(Some(early));
        let migration_state = tokio::sync::Mutex::new(None);

        let result = arm_identity_leg_core(&orchestration, &migration_state, did).await;
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
        assert!(
            migration_state.lock().await.is_none(),
            "must not park on a failed gate"
        );
    }

    // Missing dest_client (impossible past DestCreated, but defended) → AccountCreationFailed.
    #[tokio::test]
    async fn test_arm_identity_leg_core_missing_dest_client() {
        let did = "did:plc:abc123";
        let mut state = verified_state(did);
        state.dest_client = None;
        let orchestration = tokio::sync::Mutex::new(Some(state));
        let migration_state = tokio::sync::Mutex::new(None);

        let result = arm_identity_leg_core(&orchestration, &migration_state, did).await;
        assert!(matches!(
            result,
            Err(MigrationError::AccountCreationFailed { .. })
        ));
    }

    // ── Task 2 tests: finalize_migration ───────────────────────────────────

    // Gate: finalize_migration before IdentityArmed returns MIGRATION_NOT_READY
    #[test]
    fn test_finalize_migration_phase_gate_too_low() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::Verified, // Too early for finalize!
            accepted_blob_loss: Vec::new(),
            recovery: false,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::IdentityArmed);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // Build an IdentityArmed state wired to two live mock servers for cutover tests.
    fn armed_state_at(did: &str, dest_url: &str, source_url: &str) -> OutboundMigrationState {
        let mut s = armed_state(did);
        s.dest_client = Some(Arc::new(bearer_client_at(dest_url.to_string())));
        s.source_client = Some(Arc::new(bearer_client_at(source_url.to_string())));
        s
    }

    // The cutover runs in strict order: activate destination → sovereign session → deactivate
    // source. Ordering is OBSERVED — the two account mocks and the injected session step each
    // record their name into a shared vec, and we assert the recorded sequence.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_finalize_migration_core_orders_activate_session_deactivate() {
        use std::sync::Mutex as StdMutex;
        let did = "did:plc:abc123";
        let order: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));

        let dest = MockServer::start();
        let order_a = order.clone();
        let activate = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount")
                .is_true(move |_req| {
                    order_a.lock().unwrap().push("activate".to_string());
                    true
                });
            then.status(200).body("{}");
        });

        let source = MockServer::start();
        let order_d = order.clone();
        let deactivate = source.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount")
                .is_true(move |_req| {
                    order_d.lock().unwrap().push("deactivate".to_string());
                    true
                });
            then.status(200).body("{}");
        });

        let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
            did,
            &dest.base_url(),
            &source.base_url(),
        )));
        let migration_state = tokio::sync::Mutex::new(None);

        let order_s = order.clone();
        let result =
            finalize_migration_core(&orchestration, &migration_state, did, || async move {
                order_s.lock().unwrap().push("session".to_string());
                Ok::<(), MigrationError>(())
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(activate.calls(), 1, "activate must be called once");
        assert_eq!(deactivate.calls(), 1, "deactivate must be called once");
        assert_eq!(
            *order.lock().unwrap(),
            vec![
                "activate".to_string(),
                "session".to_string(),
                "deactivate".to_string()
            ],
            "activate → persist sovereign session → deactivate"
        );
        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::Finalized
        );
    }

    // A sovereign-login failure (401/429/5xx/transport) after activation leaves the source
    // account untouched (deactivate never called) and the phase un-advanced — retryable.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_finalize_migration_core_sovereign_failure_leaves_source_untouched() {
        let did = "did:plc:abc123";
        let dest = MockServer::start();
        let activate = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount");
            then.status(200).body("{}");
        });
        let source = MockServer::start();
        let deactivate = source.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount");
            then.status(200).body("{}");
        });

        let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
            did,
            &dest.base_url(),
            &source.base_url(),
        )));
        let migration_state = tokio::sync::Mutex::new(None);

        let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
            Err::<(), MigrationError>(MigrationError::SovereignLoginFailed {
                message: "destination rejected the device-key proof".into(),
            })
        })
        .await;

        assert!(matches!(
            result,
            Err(MigrationError::SovereignLoginFailed { .. })
        ));
        assert_eq!(
            activate.calls(),
            1,
            "destination activated before the sovereign leg"
        );
        assert_eq!(
            deactivate.calls(),
            0,
            "source untouched — deactivate not called"
        );
        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::IdentityArmed,
            "phase not advanced — the cutover is retryable"
        );
    }

    // A Keychain write failure (session minted but not persisted) also leaves the source untouched
    // and keeps the phase resumable, without corrupting an existing token record.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_finalize_migration_core_persist_failure_leaves_source_untouched() {
        let did = "did:plc:abc123";
        let dest = MockServer::start();
        let activate = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount");
            then.status(200).body("{}");
        });
        let source = MockServer::start();
        let deactivate = source.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount");
            then.status(200).body("{}");
        });

        let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
            did,
            &dest.base_url(),
            &source.base_url(),
        )));
        let migration_state = tokio::sync::Mutex::new(None);

        let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
            Err::<(), MigrationError>(MigrationError::SessionPersistFailed {
                message: "keychain write denied".into(),
            })
        })
        .await;

        assert!(matches!(
            result,
            Err(MigrationError::SessionPersistFailed { .. })
        ));
        assert_eq!(
            deactivate.calls(),
            0,
            "source untouched — deactivate not called"
        );
        assert_eq!(activate.calls(), 1);
        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::IdentityArmed
        );
    }

    // Repeating finalize after a successful activation is safe: activate/deactivate are server
    // idempotent and the account is never recreated or reactivated. (No reserveSigningKey /
    // createAccount mock exists, so a re-finalize that tried to recreate would fail loudly.)
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_finalize_migration_core_repeat_is_safe() {
        let did = "did:plc:abc123";
        let dest = MockServer::start();
        let activate = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount");
            then.status(200).body("{}");
        });
        let source = MockServer::start();
        let deactivate = source.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount");
            then.status(200).body("{}");
        });

        let orchestration = tokio::sync::Mutex::new(Some(armed_state_at(
            did,
            &dest.base_url(),
            &source.base_url(),
        )));
        let migration_state = tokio::sync::Mutex::new(None);

        for _ in 0..2 {
            finalize_migration_core(&orchestration, &migration_state, did, || async {
                Ok::<(), MigrationError>(())
            })
            .await
            .expect("repeating finalize after activation is safe");
        }

        assert_eq!(
            activate.calls(),
            2,
            "activate is server-idempotent (no-op when active)"
        );
        assert_eq!(
            deactivate.calls(),
            2,
            "source deactivated, never reactivated"
        );
        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::Finalized
        );
    }

    // Idempotency of the sovereign leg itself: when a persisted record with an unexpired refresh
    // token already exists, ensure_sovereign_session_persisted returns Ok WITHOUT minting (no
    // device-key signature, no network). Proven by pointing the PdsClient at an unroutable address
    // — a mint attempt would error, so Ok is only reachable via the skip.
    #[tokio::test]
    async fn test_ensure_sovereign_session_persisted_skips_when_valid_record_exists() {
        let did = "did:plc:idempotentskip";
        crate::keychain::clear_for_test();
        let store = crate::identity_store::IdentityStore;
        store.add_identity(did).unwrap();
        store.get_or_create_device_key(did).unwrap();

        let now = 1_000i64;
        let record = crate::identity_store::SovereignTokenRecord {
            version: crate::identity_store::SovereignTokenRecord::VERSION,
            access_jwt: "access".into(),
            refresh_jwt: "refresh".into(),
            pds_url: "https://dest.example".into(),
            server_did: "did:web:dest.example".into(),
            access_expires_at: Some(9_999),
            refresh_expires_at: Some(9_999), // well beyond `now`
            stored_at: now as u64,
        };
        store.store_oauth_tokens(did, &record).unwrap();

        let pds_client = crate::pds_client::PdsClient::new_for_test("http://127.0.0.1:1/".into());
        let result =
            ensure_sovereign_session_persisted(&pds_client, &store, did, now, "nonce").await;
        assert!(
            result.is_ok(),
            "valid persisted session → skip mint (no network, no signature)"
        );

        // The pre-existing record is untouched.
        let loaded = store.load_oauth_tokens(did).unwrap().unwrap();
        assert_eq!(loaded.refresh_jwt, "refresh");

        let _ = store.remove_identity(did);
    }

    // An IdentityArmed OutboundMigrationState with both clients populated.
    fn armed_state(did: &str) -> OutboundMigrationState {
        let mut s = verified_state(did);
        s.phase = MigrationPhase::IdentityArmed;
        s
    }

    // The REAL finalize_migration_core refuses while migrate::migration_state is still Some
    // (identity op not yet submitted). No network is reached, so this is a pure test.
    #[tokio::test]
    async fn test_finalize_migration_core_rejects_when_identity_op_not_submitted() {
        let did = "did:plc:abc123";
        let orchestration = tokio::sync::Mutex::new(Some(armed_state(did)));
        // migration_state still Some → the identity op has NOT been submitted.
        let migration_state = tokio::sync::Mutex::new(Some(crate::migrate::MigrationState {
            did: did.into(),
            dest_oauth_client: Arc::new(bearer_client_at("https://dest.pds".into())),
            signed_op: None,
            op_cid: None,
        }));

        let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
            Ok::<(), MigrationError>(())
        })
        .await;
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
        // Phase must not advance on a failed gate.
        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::IdentityArmed
        );
    }

    // Phase gate: finalize_migration_core before IdentityArmed → MIGRATION_NOT_READY.
    #[tokio::test]
    async fn test_finalize_migration_core_gate_before_identity_armed() {
        let did = "did:plc:abc123";
        let orchestration = tokio::sync::Mutex::new(Some(verified_state(did))); // Verified, not armed
        let migration_state = tokio::sync::Mutex::new(None);

        let result = finalize_migration_core(&orchestration, &migration_state, did, || async {
            Ok::<(), MigrationError>(())
        })
        .await;
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // End-to-end via the core: armed + cleared migration_state + mock activate/deactivate
    // → Ok AND the orchestration phase advances to Finalized.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_finalize_migration_core_advances_to_finalized() {
        let did = "did:plc:abc123";
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount");
            then.status(200).body("{}");
        });
        let source = MockServer::start();
        source.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount");
            then.status(200).body("{}");
        });

        let mut state = armed_state(did);
        state.dest_client = Some(Arc::new(bearer_client_at(dest.base_url())));
        state.source_client = Some(Arc::new(bearer_client_at(source.base_url())));
        let orchestration = tokio::sync::Mutex::new(Some(state));
        let migration_state = tokio::sync::Mutex::new(None); // identity op already submitted

        finalize_migration_core(&orchestration, &migration_state, did, || async {
            Ok::<(), MigrationError>(())
        })
        .await
        .expect("finalize should succeed when armed + identity op submitted");

        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::Finalized
        );
    }

    // ── Task 3 tests: Full-pipeline integration test ────────────────────────

    // Full migration pipeline with three mock servers
    // (source/old-PDS, dest/new-PDS, plc.directory). Drives the sequence:
    // 1. reserveSigningKey + getServiceAuth + createAccount → dest_client
    // 2. getRepo + importRepo (assert importRepo before uploadBlob)
    // 3. listMissingBlobs + getBlob + uploadBlob (loop until empty)
    // 4. getPreferences + putPreferences
    // 5. checkAccountStatus → import_reconciles
    // 6. arm_identity_leg (populates migration_state)
    // 7. getRecommendedDidCredentials + plc.directory POST (identity submit)
    // 8. activateAccount (dest) BEFORE deactivateAccount (source) — last hit (ordering enforced)
    // Asserts: full sequence completes, all three legs hit in order,
    // plc.directory POST exactly once, resume with partial blobs,
    // abort before identity leg leaves dest deactivated.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_full_migration_pipeline_happy_path() {
        let did = "did:plc:fullpipe";

        // The identity leg (build_migration_op) self-signs with the per-DID device key, which must
        // be registered first (IdentityStore/Keychain) and must be rotationKeys[0] in the current
        // audit log for the guard to pass. Mirrors migrate.rs's build/submit test setup.
        let store = crate::identity_store::IdentityStore;
        let _ = store.remove_identity(did);
        store.add_identity(did).expect("add_identity");
        let device_key_id = store
            .get_or_create_device_key(did)
            .expect("device key generation")
            .key_id;

        // ─ Set up three MockServers (source, dest, plc.directory) ─
        let source = MockServer::start();
        let source_url = source.base_url();

        let dest = MockServer::start();
        let dest_url = dest.base_url();

        let plc = MockServer::start();
        let plc_url = plc.base_url();

        // ─ Mock dest.reserveSigningKey ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.reserveSigningKey");
            then.status(200)
                .json_body(serde_json::json!({ "signingKey": "did:key:zDEST" }));
        });

        // ─ Mock source.getServiceAuth ─
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth");
            then.status(200)
                .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
        });

        // ─ Mock dest.createAccount ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount");
            then.status(200).json_body(serde_json::json!({
                "accessJwt": make_bearer_jwt(9999999999),
                "refreshJwt": "refresh",
                "handle": "alice.test",
                "did": did
            }));
        });

        // ─ Mock source.getRepo (CAR bytes) ─
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo");
            then.status(200).body("CAR-DATA");
        });

        // ─ Mock dest.importRepo ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo");
            then.status(200);
        });

        // ─ Mock dest.listMissingBlobs (empty on first call) ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs");
            then.status(200)
                .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
        });

        // ─ Mock source.getPreferences ─
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences");
            then.status(200)
                .json_body(serde_json::json!({ "preferences": [] }));
        });

        // ─ Mock dest.putPreferences ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/app.bsky.actor.putPreferences");
            then.status(200);
        });

        // ─ Mock dest.checkAccountStatus ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus");
            then.status(200).json_body(serde_json::json!({
                "activated": false,
                "validDid": false,
                "repoCommit": "baffy",
                "repoRev": "rev",
                "storedBlocks": 1,
                "indexedRecords": 0,
                "privateStateValues": 0,
                "expectedBlobs": 0,
                "importedBlobs": 0
            }));
        });

        // ─ Mock dest.getRecommendedDidCredentials ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200).json_body(serde_json::json!({
                "rotationKeys": ["did:key:zDEST"],
                "alsoKnownAs": ["at://alice.test"],
                "verificationMethods": { "atproto": "did:key:zDEST" },
                "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": &dest_url } }
            }));
        });

        // ─ Mock plc.directory POST (identity submit) ─
        let plc_post = plc.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path(format!("/{}", did));
            then.status(200);
        });

        // ─ Mock plc.directory GET (audit log fetch for build_migration_op) ─
        let plc_get_audit = plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{}/log/audit", did));
            then.status(200)
                .json_body(serde_json::json!([{
                    "did": did,
                    "cid": "bafy_current",
                    "createdAt": "2026-07-03T00:00:00Z",
                    "nullified": false,
                    "operation": {
                        "type": "plc_operation",
                        // rotationKeys[0] must be the real per-DID device key (guard: sovereignty +
                        // authorization — the wallet key must already be in the current rotation set).
                        "rotationKeys": [device_key_id.clone(), "did:key:zOLD"],
                        "verificationMethods": { "atproto": "did:key:zOLDSIGN" },
                        "alsoKnownAs": ["at://alice.test"],
                        "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": &source_url } },
                        "prev": "bafy_prev",
                        "sig": "placeholder"
                    }
                }]));
        });

        // ─ Mock plc.directory GET (DID doc refetch — the PLC *data* document,
        //   the cached shape with rotationKeys) ─
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{}/data", did));
            then.status(200).json_body(serde_json::json!({
                "did": did,
                "alsoKnownAs": ["at://alice.test"],
                "rotationKeys": [device_key_id.clone(), "did:key:zNEWSIGN"],
                "verificationMethods": { "atproto": "did:key:zNEWSIGN" },
                "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": &dest_url } }
            }));
        });

        // ─ Mock dest.activateAccount ─
        let activate = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount");
            then.status(200);
        });

        // ─ Mock source.deactivateAccount ─
        let deactivate = source.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.deactivateAccount");
            then.status(200);
        });

        // ─ Sovereign-session leg (cutover step 2) ─
        // discover_pds resolves the DID doc from plc.directory (now pointing at dest after the
        // identity op landed) and HEAD-probes the endpoint; describeServer yields the server DID;
        // then the device-key-signed proof is POSTed to /v1/sessions/sovereign.

        // plc.directory GET /{did} — the W3C DID document (dest is the current PDS).
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET).path(format!("/{}", did));
            then.status(200).json_body(serde_json::json!({
                "id": did,
                "alsoKnownAs": ["at://alice.test"],
                "verificationMethod": [],
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": &dest_url,
                }],
            }));
        });

        // dest HEAD / — discover_pds reachability probe.
        dest.mock(|when, then| {
            when.method(httpmock::Method::HEAD).path("/");
            then.status(200);
        });

        // dest describeServer — yields the destination server DID used as the proof audience.
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.describeServer");
            then.status(200).json_body(serde_json::json!({
                "did": "did:web:dest",
                "availableUserDomains": [".dest.example"],
            }));
        });

        // Sovereign-session response JWTs: sub == did, aud == dest PDS URL (so
        // audience_matches_server accepts them), exp far in the future.
        let sovereign_jwt = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let payload = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "exp": 9_999_999_999u64,
                    "sub": did,
                    "aud": dest_url.as_str(),
                }))
                .unwrap(),
            );
            format!("e30.{payload}.sig")
        };

        // dest POST /v1/sessions/sovereign — mints the durable full-access session.
        let sovereign = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path(crypto::SOVEREIGN_SESSION_PATH);
            then.status(200).json_body(serde_json::json!({
                "accessJwt": &sovereign_jwt,
                "refreshJwt": &sovereign_jwt,
                "handle": "alice.test",
                "did": did,
            }));
        });

        // ─ Build clients and state ─
        let pds_client = crate::pds_client::PdsClient::new_for_test(plc_url.clone());

        let source_client = Arc::new(bearer_client_at(source_url.clone()));

        // ─ Step 1: create_destination_account_impl (returns the real dest Bearer client) ─
        let dest_result = create_destination_account_impl(
            &pds_client,
            &source_client,
            &dest_url,
            "did:web:dest",
            did,
            "alice.test",
            "alice@example.com",
            None,
            None,
        )
        .await;
        assert!(
            dest_result.is_ok(),
            "create_destination_account_impl should succeed"
        );
        let dest_client = dest_result.unwrap();

        // ─ Step 2: transfer_repo_impl ─
        let repo_result =
            transfer_repo_impl(&pds_client, &dest_client, &source_url, did, None).await;
        assert!(repo_result.is_ok(), "transfer_repo_impl should succeed");

        // ─ Step 3: drain_missing_blobs ─
        let blobs_result =
            drain_missing_blobs(&pds_client, &dest_client, Some(&source_url), did, None).await;
        assert!(blobs_result.is_ok(), "drain_missing_blobs should succeed");

        // ─ Step 4: transfer_preferences_impl ─
        let prefs_result = transfer_preferences_impl(&source_client, &dest_client).await;
        assert!(
            prefs_result.is_ok(),
            "transfer_preferences_impl should succeed"
        );

        // ─ Step 5: check_account_status via import_reconciles ─
        let status = crate::pds_client::check_account_status(&dest_client)
            .await
            .expect("check_account_status should succeed");
        assert!(
            import_reconciles_with_loss(&status, 0),
            "import should reconcile"
        );

        // ─ Step 6/7: identity leg — build_migration_op (dest getRecommendedDidCredentials +
        //   plc.directory audit fetch). arm_identity_leg (parking migrate::MigrationState) is a
        //   thin State mutation covered by its own gate test; here we drive the pure core. ─
        let built_op = crate::migrate::build_migration_op(&pds_client, &dest_client, did)
            .await
            .expect("build_migration_op should succeed");
        plc_get_audit.assert();

        // ─ Step 8: submit_migration_op (plc.directory POST) ─
        crate::migrate::submit_migration_op(&pds_client, did, &built_op.signed_op)
            .await
            .expect("submit_migration_op should succeed");
        plc_post.assert(); // Verify plc.directory was hit exactly once

        // ─ Step 9: the safe cutover via the production seam — activate dest → mint + persist the
        //   sovereign session → deactivate source → Finalized. Driven through finalize_migration_core
        //   with the real ensure_sovereign_session_persisted closure so the new seam is covered
        //   end-to-end (not the pure activate/deactivate helper). ─
        let now = 1_720_000_000i64;
        let nonce = crate::sovereign_session::fresh_nonce();
        let orchestration = tokio::sync::Mutex::new(Some(OutboundMigrationState {
            did: did.into(),
            source_pds_url: source_url.clone(),
            dest_pds_url: dest_url.clone(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: Some(source_client.clone()),
            dest_client: Some(dest_client),
            phase: MigrationPhase::IdentityArmed,
            accepted_blob_loss: Vec::new(),
            recovery: false,
        }));
        let migration_state = tokio::sync::Mutex::new(None); // identity op already submitted

        finalize_migration_core(&orchestration, &migration_state, did, || async move {
            ensure_sovereign_session_persisted(
                &pds_client,
                &crate::identity_store::IdentityStore,
                did,
                now,
                &nonce,
            )
            .await
        })
        .await
        .expect("safe cutover should succeed");

        // ─ Verify plc.directory POST was hit exactly once ─
        assert_eq!(
            plc_post.calls(),
            1,
            "plc.directory POST must be hit exactly once"
        );

        // ─ Verify the full cutover: activate, mint sovereign session, deactivate ─
        assert_eq!(activate.calls(), 1, "activate must be called");
        assert_eq!(
            sovereign.calls(),
            1,
            "sovereign session must be minted once"
        );
        assert_eq!(deactivate.calls(), 1, "deactivate must be called");
        assert_eq!(
            orchestration.lock().await.as_ref().unwrap().phase,
            MigrationPhase::Finalized
        );

        // ─ The destination credential is durable: after this cutover a fresh client can be
        //   reconstructed from the persisted record alone (no in-memory session truth). ─
        assert!(
            crate::sovereign_session::stored_bearer_client(did)
                .expect("stored session should load")
                .is_some(),
            "migrated DID must have a persisted destination session"
        );

        let _ = store.remove_identity(did);
    }

    // Resume scenario — listMissingBlobs returns partial set on first call, then empty
    // Verify only the still-missing blobs are uploaded (not the full set)
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_full_migration_resume_partial_blobs() {
        let source = MockServer::start();
        let dest = MockServer::start();

        // ─ First page (no cursor): the still-missing set left by a partial prior drain ─
        // Matched only on the no-cursor request (query_param_missing) so it can't also match the
        // cursor=c1 re-list below (overlapping mocks would be ambiguous and could loop forever).
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param_missing("cursor");
            then.status(200).json_body(serde_json::json!({
                "blobs": [
                    { "cid": "cid_a", "recordUri": "at://did/1" },
                    { "cid": "cid_b", "recordUri": "at://did/2" }
                ],
                "cursor": "c1"
            }));
        });

        // ─ Second listMissingBlobs (cursor=c1): drained → empty, terminates the loop ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs")
                .query_param("cursor", "c1");
            then.status(200)
                .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
        });

        // ─ Mock source.getBlob for each CID ─
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getBlob");
            then.status(200).body("blob-data");
        });

        // ─ Mock dest.uploadBlob ─
        let upload = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.uploadBlob");
            then.status(200)
                .json_body(serde_json::json!({ "blob": { "$type": "blob" } }));
        });

        let pds_client = crate::pds_client::PdsClient::new();
        let dest_client = bearer_client_at(dest.base_url());

        let result = drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some(&source.base_url()),
            "did:plc:test",
            None,
        )
        .await;

        assert!(result.is_ok(), "drain should complete successfully");
        // uploadBlob must be hit exactly twice (only the blobs on the first page)
        assert_eq!(
            upload.calls(),
            2,
            "uploadBlob hit count must match still-missing blobs (not full set)"
        );
    }

    // Abort before the identity leg — verify the dest stays deactivated (coherent state).
    // Drives: create dest account → transfer repo → blobs → prefs → verify, then STOPS (no
    // arm_identity_leg / finalize). Asserts activateAccount is never hit.
    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_full_migration_abort_before_identity_leg_leaves_dest_deactivated() {
        let source = MockServer::start();
        let dest = MockServer::start();
        let plc = MockServer::start();

        // ─ dest.reserveSigningKey ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.reserveSigningKey");
            then.status(200)
                .json_body(serde_json::json!({ "signingKey": "did:key:zDEST" }));
        });

        // ─ source.getServiceAuth ─
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.getServiceAuth");
            then.status(200)
                .json_body(serde_json::json!({ "token": make_bearer_jwt(9999999999) }));
        });

        // ─ dest.createAccount ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.createAccount");
            then.status(200).json_body(serde_json::json!({
                "accessJwt": make_bearer_jwt(9999999999),
                "refreshJwt": "refresh",
                "handle": "alice.test",
                "did": "did:plc:test"
            }));
        });

        // ─ source.getRepo ─
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepo");
            then.status(200).body("CAR");
        });

        // ─ dest.importRepo ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.repo.importRepo");
            then.status(200);
        });

        // ─ dest.listMissingBlobs (empty) ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.repo.listMissingBlobs");
            then.status(200)
                .json_body(serde_json::json!({ "blobs": [], "cursor": null }));
        });

        // ─ source.getPreferences ─
        source.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/app.bsky.actor.getPreferences");
            then.status(200)
                .json_body(serde_json::json!({ "preferences": [] }));
        });

        // ─ dest.putPreferences ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/app.bsky.actor.putPreferences");
            then.status(200);
        });

        // ─ dest.checkAccountStatus ─
        dest.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.server.checkAccountStatus");
            then.status(200).json_body(serde_json::json!({
                "activated": false,
                "validDid": false,
                "repoCommit": "baffy",
                "repoRev": "rev",
                "storedBlocks": 1,
                "indexedRecords": 0,
                "privateStateValues": 0,
                "expectedBlobs": 0,
                "importedBlobs": 0
            }));
        });

        // ─ Mock dest.activateAccount (MUST NEVER BE HIT) ─
        let activate = dest.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/xrpc/com.atproto.server.activateAccount");
            then.status(200);
        });

        let pds_client = crate::pds_client::PdsClient::new_for_test(plc.base_url());
        let source_client = Arc::new(bearer_client_at(source.base_url()));

        // ─ Run through steps 1–5 (up to verify_import, but NOT arm/finalize) ─
        let dest_client = create_destination_account_impl(
            &pds_client,
            &source_client,
            &dest.base_url(),
            "did:web:dest",
            "did:plc:test",
            "alice.test",
            "alice@example.com",
            None,
            None,
        )
        .await
        .expect("create dest");

        transfer_repo_impl(
            &pds_client,
            &dest_client,
            &source.base_url(),
            "did:plc:test",
            None,
        )
        .await
        .expect("transfer repo");

        drain_missing_blobs(
            &pds_client,
            &dest_client,
            Some(&source.base_url()),
            "did:plc:test",
            None,
        )
        .await
        .expect("drain blobs");

        transfer_preferences_impl(&source_client, &dest_client)
            .await
            .expect("transfer prefs");

        // Verify import is reconciled (now would come arm_identity_leg → identity op → finalize)
        // BUT: we stop here without calling finalize, simulating an abort.
        let status = crate::pds_client::check_account_status(&dest_client)
            .await
            .expect("check status");
        assert!(import_reconciles_with_loss(&status, 0));

        // ─ Verify dest was NEVER activated (coherent state on abort) ─
        assert_eq!(
            activate.calls(),
            0,
            "activateAccount must never be hit on abort before identity leg"
        );
    }
}
