// pattern: Mixed (Functional Core types + Imperative Shell commands)

//! Wallet-authorized outbound migration state machine (ADR-0002, path 1) — the driver
//! behind the `prepareMigration()`…`finalizeMigration()` IPC wrappers, as fine-grained
//! per-step Tauri commands for the source→dest transfer:
//!
//! - `prepare_migration` — resolve dest describeServer + source; returns
//!   `PreparedMigration { handle, sourcePdsUrl }` for the source-auth screen.
//! - `authenticate_migration_source` — password `createSession` → full-session Bearer
//!   client via the shared `source_login.rs` core (mirrors
//!   `claim::authenticate_source_pds`). Per ADR-0021 a full session — which no OAuth
//!   `transition:generic` grant supplies on a spec-strict PDS such as bsky.social — is
//!   required to mint the source's `createAccount` service-auth token. HTTPS +
//!   account-match guards + email-2FA; the password is used once and never stored.
//! - `create_destination_account` — reserveSigningKey → getServiceAuth → deactivated
//!   `createAccount` → Bearer session; tolerates `DidAlreadyExists` for resume.
//! - `transfer_repo` — getRepo → importRepo. On a source `getRepo` failure it falls
//!   back to the local iCloud repo mirror (`repo_backup::mirror_repo_car`) when that
//!   mirror holds a CID/commit-valid snapshot for the DID, else surfaces the original
//!   source failure unchanged — the repo twin of the blob drain's mirror fallback. A source
//!   `429` is the exception: it surfaces as `RateLimited` and never falls back.
//! - `transfer_blobs` — cursor-paginated `listMissingBlobs` drain
//!   (`drain_missing_blobs` / `transfer_one_blob`) that degrades PER BLOB rather than
//!   aborting: an unrecoverable blob becomes a `BlobLoss` (cid, record_uri,
//!   `BlobTransferDirection`, reason) folded into a loss manifest and surfaced as
//!   `MigrationError::BlobDrainIncomplete` for the user to accept (re-invoke
//!   `transferBlobs(did, acceptLoss=true)`). On a source `getBlob` failure the drain
//!   substitutes the local blob mirror's copy (`blob_backup::mirror_fallback_blob`)
//!   when one is CID-verified, recording the loss only when it is not. Only a hard
//!   enumerate failure aborts, as `BlobTransferFailed`.
//! - `transfer_preferences` (get→put); `verify_import` (`checkAccountStatus`
//!   completeness gate, returns `AccountStatus`); `arm_identity_leg` (populate
//!   `migrate::MigrationState.dest_oauth_client`, then run
//!   `migrate::build_migration_op_cmd` / `submit_migration_op_cmd`).
//! - `finalize_migration` — the safe cutover: activate dest → durably persist the
//!   destination session → deactivate source → `Finalized`. The source stays active
//!   until the durable credential is stored, so a crash or retry never strands the
//!   account credential-less; `SOVEREIGN_LOGIN_FAILED` / `SESSION_PERSIST_FAILED` are
//!   the retryable cutover-mint failures that abort before deactivation.
//!
//! Which credential gets persisted is capability-gated, not assumed:
//! `destination_credential` (pure, unit-tested) answers `Sovereign` or `Bearer` from
//! the DID method plus the destination's advertised `sovereignSessions`
//! (`pds_capabilities`, warm from `prepare_migration`'s describeServer). A host that
//! ANSWERED without advertising it — the reference PDS, bsky.social, any
//! spec-compliant PDS, a Custos with the capability off — takes the Bearer branch:
//! minting against a route it does not serve would fail AFTER the identity op already
//! landed. A did:web takes it unconditionally (no rotation keys to sign the proof). A
//! host that could NOT be asked keeps the sovereign branch: `activateAccount` has
//! already succeeded against it by then, so `reached: false` is a describeServer
//! blink, not grounds to downgrade a Custos destination's credential. The same branch
//! serves outbound migration and sovereign disaster recovery, which share this
//! command.
//!
//! Pure cores are split out for testability: `ensure_phase_did`,
//! `create_destination_account_impl`, `drain_missing_blobs`, `transfer_repo_impl`,
//! `transfer_preferences_impl`, `import_reconciles`, the
//! `activate_destination_account` / `deactivate_source_account` cutover halves,
//! `destination_credential`, `ensure_sovereign_session_persisted` (idempotent skip
//! while a persisted record's refresh token is unexpired, else
//! `sovereign_session::sovereign_login` → persist),
//! `ensure_bearer_session_persisted` (the same idempotent skip, then sub/aud-validate
//! and persist the pair `createAccount` already issued into the same
//! `{did}:oauth-tokens` record — from that write on, `session_provider` restores and
//! refreshes it identically, and re-unlock rides `password_unlock`'s password
//! `createSession` route), and the `*_core` mutex-parameterized command cores.
//! `finalize_migration_core` takes an injected `ensure_session` step so the
//! activate → session → deactivate ordering is unit-testable without a Keychain or
//! live PDS; `finalize_migration` above it holds the whole snapshot → capability
//! probe → branch → cutover path, drivable against mock servers through a test `Core` —
//! which is what proves the non-Custos cutover never calls `/v1/sessions/sovereign`.
//!
//! Migration state is IN-MEMORY only (`Core.orchestration_state`): an app kill
//! restarts from `prepare_migration`, but the destination session persisted via
//! `{did}:oauth-tokens` survives — a restarted wallet reconstructs the destination
//! client from that record (`sovereign_session::stored_bearer_client`), never from
//! `OutboundMigrationState`. The orchestrator never POSTs plc.directory — the single
//! PLC write is `migrate::submit_migration_op_cmd`. `MigrationError`
//! (MIGRATION_NOT_READY, DESTINATION_UNREACHABLE, SOURCE_AUTH_FAILED,
//! TWO_FACTOR_REQUIRED, ACCOUNT_MISMATCH, INSECURE_SOURCE_URL, RATE_LIMITED,
//! SERVER_REJECTED, SERVICE_AUTH_FAILED, ACCOUNT_CREATION_FAILED, DESTINATION_CONFLICT,
//! REPO_TRANSFER_FAILED, BLOB_TRANSFER_FAILED, BLOB_DRAIN_INCOMPLETE,
//! BACKUP_UNAVAILABLE — recovery-specific — PREFERENCES_TRANSFER_FAILED,
//! VERIFICATION_INCOMPLETE, ACTIVATION_FAILED, SOVEREIGN_LOGIN_FAILED,
//! SESSION_PERSIST_FAILED, DEACTIVATION_FAILED, NETWORK_ERROR) serializes as
//! SCREAMING_SNAKE_CASE; the `$lib/ipc` union must match exactly.

use crate::oauth_client::OAuthClient;
use crate::pds_capabilities::ServerCapabilities;
use ceremony_journal::JournalStore;
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

/// Outbound migration state persisted in `Core`.
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
    /// The source PDS rate-limited the login or the repo export (HTTP 429). `retry_after` carries the server's
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
    #[error("server rejected the request: {message}")]
    ServerRejected { message: String },
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
pub fn ensure_phase_did<'a>(
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

// ── Journal store ──────────────────────────────────────────────────────────

impl ceremony_journal::Step for MigrationPhase {}

/// The orchestration slot as the migration's journal store, bound to one DID. Each migration
/// command is its own IPC call, so the cursor is `OutboundMigrationState.phase` and every command
/// records its step here. Recording an earlier phase rewinds it (see `ceremony_journal`): a
/// re-run step re-opens the steps after it, so a re-drained migration must verify again before
/// it can finalize.
///
/// In-memory only, like the slot itself: an app kill restarts from `prepare_migration`.
pub(crate) struct MigrationJournal<'a> {
    state: &'a tokio::sync::Mutex<Option<OutboundMigrationState>>,
    did: &'a str,
}

impl<'a> MigrationJournal<'a> {
    pub(crate) fn new(
        state: &'a tokio::sync::Mutex<Option<OutboundMigrationState>>,
        did: &'a str,
    ) -> Self {
        Self { state, did }
    }

    /// Record `phase` together with the state its step produced, under one lock. Refused when the
    /// active migration is gone, or is now for another DID (a concurrent `prepare_migration`
    /// swapped it while the step was on the network).
    pub(crate) async fn commit(
        &self,
        phase: MigrationPhase,
        write: impl FnOnce(&mut OutboundMigrationState),
    ) -> Result<(), MigrationError> {
        let mut orchestration = self.state.lock().await;
        let Some(mig) = orchestration.as_mut() else {
            return Err(MigrationError::MigrationNotReady {
                message: "orchestration state lost".into(),
            });
        };
        if mig.did != self.did {
            tracing::warn!(did = %self.did, ?phase, "orchestration state did mismatch");
            return Err(MigrationError::MigrationNotReady {
                message: "did mismatch with orchestration state".into(),
            });
        }
        write(mig);
        mig.phase = phase;
        Ok(())
    }
}

impl ceremony_journal::JournalStore<MigrationPhase> for MigrationJournal<'_> {
    type Error = MigrationError;

    async fn load(&self) -> Result<Option<MigrationPhase>, MigrationError> {
        let orchestration = self.state.lock().await;
        Ok(orchestration
            .as_ref()
            .filter(|mig| mig.did == self.did)
            .map(|mig| mig.phase))
    }

    async fn save(&self, phase: MigrationPhase) -> Result<(), MigrationError> {
        self.commit(phase, |_| {}).await
    }
}

// ── Steps, one module per concern ───────────────────────────────────────────

mod cutover;
mod prepare;
mod transfer;

pub use cutover::*;
pub use prepare::*;
pub use transfer::*;

#[cfg(test)]
mod tests;
