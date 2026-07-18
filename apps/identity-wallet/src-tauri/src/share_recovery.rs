// pattern: Imperative Shell
//
// The "Recover existing identity" ceremony — the consuming inverse of
// `share_ceremony.rs`. Two shares of the 2-of-3 split reconstruct the recovery
// seed; the seed re-derives the recovery rotation key (`rotationKeys[1]` in the
// `[device, recovery, PDS]` layout); that key signs a PLC rotation op installing a
// fresh device key at `rotationKeys[0]` on the new device.
//
// Two collection paths feed the same core:
//   - escrow-assisted: Share 1 auto-loads from the iCloud-synced per-DID
//     `recovery-share-1:{did}` slot (falling back to the legacy global slot for
//     pre-unification identities); Share 2 arrives via the PDS escrow-release flow (initiate → email OTP →
//     release, with a cancellable pending-delay window).
//   - fully sovereign: Share 1 (or a manually entered share) plus Share 3 (word
//     phrase or base32/QR). This path touches ONLY plc.directory until the
//     re-escrow step of the rotation epilogue — never the Custos PDS — which is
//     the credible-exit property the split exists to provide.
//
// Reconstruction is verified against the authoritative plc.directory audit log
// (never a cached DID document — the PLC-native shape is the only one carrying
// `rotationKeys`) BEFORE anything is signed, so "these shares don't match this
// identity" surfaces as a pre-signature failure.
//
// The mandatory rotation epilogue (fresh seed, new set_id, new recovery key
// swapped into the recovery slot, Share 2 re-escrowed, Share 1 rewritten, Share 3
// walked through) persists its progress in a durable Keychain record BEFORE any
// network step, so an app kill mid-epilogue resumes on next launch instead of
// stranding the account with the lost device's (now void) share world.

use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::handle_change::{latest_full_state, CurrentHandleState};
use crate::identity_store::{IdentityStore, IdentityStoreError, PerDidSignError};
use crate::keychain;
use crate::oauth::AppState;
use crate::pds_client::{PdsClient, PdsClientError};
use crate::sovereign_session;

/// Durable Keychain account for the in-flight rotation epilogue. Written before the
/// epilogue's first network step and deleted only by `confirm_recovery_backup`, so an
/// interrupted epilogue is resumable across app restarts.
pub const EPILOGUE_ACCOUNT: &str = "recovery-epilogue";

/// The legacy app-global Share 1 slot. Share 1 now lives in the per-DID slot
/// `recovery-share-1:{did}` (`crate::rekey::recovery_share1_account`); this literal is kept
/// only as the auto-load fallback for identities created before the per-DID unification,
/// whose iCloud-synced Share 1 is still under this global account.
const RECOVERY_SHARE1_ACCOUNT: &str = "recovery-share-1";

/// Read a Keychain slot and decode its bytes as an index-1 v2 share envelope, or `None` if
/// the slot is absent, unreadable, non-UTF-8, not a valid envelope, or not Share 1. A bare
/// legacy share (pre-envelope format) or foreign bytes are unusable for this ceremony and
/// read as "not loaded" — manual entry covers the gap.
fn load_share1_envelope(account: &str) -> Option<crypto::ShareEnvelope> {
    // Sensitive key material — wipe the in-memory copy when this scope ends.
    let bytes = zeroize::Zeroizing::new(keychain::get_item(account).ok()?);
    let env = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| crypto::ShareEnvelope::decode_share(s).ok())?;
    (env.index() == 1).then_some(env)
}

/// Bumped only on a breaking epilogue-record format change; a mismatched version reads
/// as corrupt and fails closed.
const EPILOGUE_VERSION: u32 = 1;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum ShareRecoveryError {
    /// The share is not a decodable v2 envelope (bad base32, bad word, wrong length).
    #[error("share envelope malformed: {message}")]
    ShareFormat { message: String },
    /// The envelope decoded but its checksum does not match — a corrupted or
    /// mistranscribed share. Distinct from a set mismatch by design.
    #[error("share envelope checksum mismatch")]
    ShareChecksum,
    #[error("share envelope has an unsupported version")]
    ShareVersion,
    /// The share is valid but belongs to a different split generation than the
    /// share(s) already collected — combining would reconstruct garbage.
    #[error("share belongs to a different share set")]
    ShareSetMismatch {
        expected_set_id: u32,
        got_set_id: u32,
    },
    /// A share with this index has already been collected.
    #[error("share {index} already collected")]
    DuplicateShare { index: u8 },
    #[error("two shares are required before verification")]
    SharesIncomplete,
    /// The combined seed derives a recovery key that is not in the DID's current
    /// rotationKeys — these shares do not match this identity.
    #[error("shares do not match this identity")]
    SharesDoNotMatchIdentity,
    #[error("no recovery session in progress")]
    NoRecoverySession,
    /// Only did:plc identities carry PLC rotation keys; did:web has no share-based
    /// recovery analogue.
    #[error("only did:plc identities support share recovery")]
    UnsupportedIdentity,
    #[error("handle not found")]
    HandleNotFound,
    #[error("DID not found")]
    DidNotFound,
    #[error("invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    #[error("plc.directory rejected the operation: {message}")]
    PlcDirectoryError { message: String },
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The escrow release was refused. The server answers uniformly (wrong/expired
    /// OTP, cancelled release, unknown account, escrow opted out) so the wallet cannot
    /// and does not distinguish — the screen copy explains the possibilities.
    #[error("escrow release could not be authorized")]
    ReleaseUnauthorized,
    #[error("escrow deposit failed: {message}")]
    EscrowDepositFailed { message: String },
    #[error("session bootstrap failed: {message}")]
    SessionFailed { message: String },
    #[error("keychain failure: {message}")]
    KeychainError { message: String },
    #[error("signing failed: {message}")]
    SigningFailed { message: String },
    #[error("no rotation epilogue is pending")]
    NoPendingEpilogue,
    /// The epilogue record exists but cannot be read. Fail closed — it may hold the
    /// only copy of the new share set, so it is never overwritten with fresh material.
    #[error("epilogue record present but unreadable: {message}")]
    EpilogueCorrupt { message: String },
    #[error("invalid server response: {message}")]
    InvalidResponse { message: String },
}

fn map_pds_error(e: PdsClientError) -> ShareRecoveryError {
    match e {
        PdsClientError::HandleNotFound => ShareRecoveryError::HandleNotFound,
        PdsClientError::DidNotFound => ShareRecoveryError::DidNotFound,
        PdsClientError::RateLimited { retry_after, .. } => {
            ShareRecoveryError::RateLimited { retry_after }
        }
        PdsClientError::NetworkError { message } => ShareRecoveryError::NetworkError { message },
        other => ShareRecoveryError::NetworkError {
            message: other.to_string(),
        },
    }
}

fn map_decode_error(e: crypto::CryptoError) -> ShareRecoveryError {
    match e {
        crypto::CryptoError::ShareChecksum(_) => ShareRecoveryError::ShareChecksum,
        crypto::CryptoError::ShareVersion(_) => ShareRecoveryError::ShareVersion,
        other => ShareRecoveryError::ShareFormat {
            message: other.to_string(),
        },
    }
}

fn map_keychain_error(e: keychain::KeychainError) -> ShareRecoveryError {
    ShareRecoveryError::KeychainError {
        message: e.to_string(),
    }
}

fn map_store_error(e: IdentityStoreError) -> ShareRecoveryError {
    ShareRecoveryError::KeychainError {
        message: e.to_string(),
    }
}

// ── Session state (in-memory, AppState) ──────────────────────────────────────

/// One collected share envelope, held encoded so the raw payload is only
/// materialized at combine time.
struct StoredShare {
    encoded: Zeroizing<String>,
    set_id: u32,
    index: u8,
}

impl StoredShare {
    fn from_envelope(env: &crypto::ShareEnvelope) -> Self {
        Self {
            encoded: env.encode_share(),
            set_id: env.set_id(),
            index: env.index(),
        }
    }

    fn decode(&self) -> Result<crypto::ShareEnvelope, ShareRecoveryError> {
        crypto::ShareEnvelope::decode_share(&self.encoded).map_err(map_decode_error)
    }
}

/// Verified reconstruction: the seed and the recovery key it derives. The seed is the
/// signing material for the re-anchor op; it never leaves this in-memory state.
struct VerifiedShares {
    seed: Zeroizing<[u8; 32]>,
    recovery_key_id: String,
}

/// The in-flight recovery ceremony (share collection through re-anchor). In-memory
/// only — the pre-anchor phase is safely restartable from the entry screen (the
/// escrow release state machine lives server-side, and Share 1 reloads from the
/// Keychain), so nothing here needs to survive an app kill. The rotation epilogue,
/// which is NOT safely restartable from scratch, persists its own durable record.
pub struct ShareRecoveryState {
    pub did: String,
    pub handle: Option<String>,
    /// The account's PDS endpoint from the authoritative DID state — the escrow
    /// release target for the assisted path.
    pub pds_url: Option<String>,
    shares: Vec<StoredShare>,
    verified: Option<VerifiedShares>,
}

// ── Result shapes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectedShare {
    pub set_id: u32,
    pub index: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryTarget {
    pub did: String,
    pub handle: Option<String>,
    /// Whether Share 1 auto-loaded from the iCloud-synced Keychain slot.
    pub share1_loaded: bool,
    pub collected: Vec<CollectedShare>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EscrowReleaseStatus {
    /// `"pending"` (delay window open) or `"released"` (Share 2 collected).
    pub status: String,
    /// Server timestamp after which the share becomes collectable (pending only).
    pub available_at: Option<String>,
    /// The collected Share 2's metadata (released only).
    pub share: Option<CollectedShare>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveredIdentity {
    pub did: String,
    pub handle: Option<String>,
    /// did:key the combined seed derives — verified present in the DID's current
    /// rotationKeys before this is returned.
    pub recovery_key_id: String,
    pub rotation_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryAnchor {
    pub did: String,
    /// CID of the submitted re-anchor op, or None when a prior attempt already landed
    /// it (idempotent retry).
    pub op_cid: Option<String>,
    pub already_anchored: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpilogueResult {
    /// The NEW Share 3 (base32 envelope, QR form).
    pub share3: String,
    /// The NEW Share 3 as the word phrase.
    pub share3_words: String,
    pub escrow_deposited: bool,
    pub escrow_skipped: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingEpilogue {
    pub did: String,
    pub op_submitted: bool,
    pub escrow_deposited: bool,
    pub escrow_skipped: bool,
    pub share1_written: bool,
}

type StateSlot = tokio::sync::Mutex<Option<ShareRecoveryState>>;

// ── Start: resolve the identity and auto-load Share 1 ────────────────────────

/// Begin a recovery ceremony for a handle or did:plc. Resolves the identifier,
/// reads the authoritative current state from plc.directory, and auto-loads Share 1
/// from the iCloud-synced Keychain slot when a valid v2 envelope is present.
#[tauri::command]
pub async fn start_share_recovery(
    state: tauri::State<'_, AppState>,
    identifier: String,
) -> Result<RecoveryTarget, ShareRecoveryError> {
    start_impl(state.pds_client(), &state.share_recovery_state, &identifier).await
}

pub(crate) async fn start_impl(
    pds: &PdsClient,
    slot: &StateSlot,
    identifier: &str,
) -> Result<RecoveryTarget, ShareRecoveryError> {
    let identifier = identifier.trim();
    let did = if identifier.starts_with("did:plc:") {
        identifier.to_string()
    } else if identifier.starts_with("did:") {
        return Err(ShareRecoveryError::UnsupportedIdentity);
    } else {
        pds.resolve_handle(identifier)
            .await
            .map_err(map_pds_error)?
    };
    if !did.starts_with("did:plc:") {
        return Err(ShareRecoveryError::UnsupportedIdentity);
    }

    let current = fetch_current_state(pds, &did).await?;
    let handle = current
        .also_known_as
        .first()
        .map(|aka| aka.strip_prefix("at://").unwrap_or(aka).to_string());
    let pds_url = current
        .services
        .get("atproto_pds")
        .map(|s| s.endpoint.clone());

    // Share 1 auto-load: prefer the resolved DID's per-DID slot; fall back to the legacy
    // app-global slot so an identity created before the per-DID unification (whose
    // iCloud-synced Share 1 is still global) is recoverable on a fresh device. A valid v2
    // index-1 envelope joins the session.
    let mut shares = Vec::new();
    let per_did_account = crate::rekey::recovery_share1_account(&did);
    let share1_loaded = match load_share1_envelope(&per_did_account)
        .or_else(|| load_share1_envelope(RECOVERY_SHARE1_ACCOUNT))
    {
        Some(env) => {
            shares.push(StoredShare::from_envelope(&env));
            true
        }
        None => {
            tracing::warn!(
                "no usable v2 Share 1 envelope in the per-DID or legacy slot; falling back to manual entry"
            );
            false
        }
    };

    let collected = shares
        .iter()
        .map(|s| CollectedShare {
            set_id: s.set_id,
            index: s.index,
        })
        .collect();

    *slot.lock().await = Some(ShareRecoveryState {
        did: did.clone(),
        handle: handle.clone(),
        pds_url,
        shares,
        verified: None,
    });

    Ok(RecoveryTarget {
        did,
        handle,
        share1_loaded,
        collected,
    })
}

// ── Share collection ─────────────────────────────────────────────────────────

/// Add a manually entered share — base32 envelope or the Share 3 word phrase.
/// Surfaces checksum corruption and cross-set mixing as distinct errors BEFORE any
/// combine is attempted.
#[tauri::command]
pub async fn add_recovery_share(
    state: tauri::State<'_, AppState>,
    share: String,
) -> Result<CollectedShare, ShareRecoveryError> {
    add_share_impl(&state.share_recovery_state, &share).await
}

pub(crate) async fn add_share_impl(
    slot: &StateSlot,
    share: &str,
) -> Result<CollectedShare, ShareRecoveryError> {
    let trimmed = share.trim();
    if trimmed.is_empty() {
        return Err(ShareRecoveryError::ShareFormat {
            message: "share is empty".to_string(),
        });
    }
    // A word phrase contains whitespace between words; the base32 form never does.
    let envelope = if trimmed.split_whitespace().nth(1).is_some() {
        crypto::ShareEnvelope::decode_share_words(trimmed).map_err(map_decode_error)?
    } else {
        crypto::ShareEnvelope::decode_share(trimmed).map_err(map_decode_error)?
    };

    let mut guard = slot.lock().await;
    let session = guard
        .as_mut()
        .ok_or(ShareRecoveryError::NoRecoverySession)?;

    if let Some(existing) = session.shares.first() {
        if existing.set_id != envelope.set_id() {
            return Err(ShareRecoveryError::ShareSetMismatch {
                expected_set_id: existing.set_id,
                got_set_id: envelope.set_id(),
            });
        }
    }
    if session.shares.iter().any(|s| s.index == envelope.index()) {
        return Err(ShareRecoveryError::DuplicateShare {
            index: envelope.index(),
        });
    }

    let collected = CollectedShare {
        set_id: envelope.set_id(),
        index: envelope.index(),
    };
    session.shares.push(StoredShare::from_envelope(&envelope));
    // Adding material invalidates any previous verification.
    session.verified = None;
    Ok(collected)
}

/// Drop a collected share (user correction), e.g. after pasting the wrong phrase.
#[tauri::command]
pub async fn remove_recovery_share(
    state: tauri::State<'_, AppState>,
    index: u8,
) -> Result<Vec<CollectedShare>, ShareRecoveryError> {
    let mut guard = state.share_recovery_state.lock().await;
    let session = guard
        .as_mut()
        .ok_or(ShareRecoveryError::NoRecoverySession)?;
    session.shares.retain(|s| s.index != index);
    session.verified = None;
    Ok(session
        .shares
        .iter()
        .map(|s| CollectedShare {
            set_id: s.set_id,
            index: s.index,
        })
        .collect())
}

// ── Escrow release (assisted path) ───────────────────────────────────────────

/// Ask the account's PDS to email a release OTP. Always succeeds server-side for any
/// identifier (no enumeration), so success here only means "the request was sent".
#[tauri::command]
pub async fn initiate_escrow_release(
    state: tauri::State<'_, AppState>,
) -> Result<(), ShareRecoveryError> {
    initiate_impl(state.pds_client(), &state.share_recovery_state).await
}

pub(crate) async fn initiate_impl(
    pds: &PdsClient,
    slot: &StateSlot,
) -> Result<(), ShareRecoveryError> {
    let (did, pds_url) = escrow_target(slot).await?;
    let url = format!("{}/v1/recovery/initiate", pds_url.trim_end_matches('/'));
    let response = pds
        .client()
        .post(url)
        .json(&serde_json::json!({ "identifier": did }))
        .send()
        .await
        .map_err(|e| ShareRecoveryError::NetworkError {
            message: e.to_string(),
        })?;
    match response.status().as_u16() {
        200 => Ok(()),
        429 => Err(rate_limited(&response)),
        status => Err(ShareRecoveryError::InvalidResponse {
            message: format!("initiate returned HTTP {status}"),
        }),
    }
}

/// Open (with the OTP) or poll (without it) the escrow release. A pending result
/// carries the server's `availableAt`; a released result decodes, validates, and
/// collects the Share 2 envelope. The server's uniform 401 — wrong/expired OTP,
/// cancelled release, unknown account — maps to `ReleaseUnauthorized`.
#[tauri::command]
pub async fn request_escrow_release(
    state: tauri::State<'_, AppState>,
    otp: Option<String>,
) -> Result<EscrowReleaseStatus, ShareRecoveryError> {
    release_impl(state.pds_client(), &state.share_recovery_state, otp).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseResponse {
    status: String,
    available_at: Option<String>,
    share: Option<String>,
}

pub(crate) async fn release_impl(
    pds: &PdsClient,
    slot: &StateSlot,
    otp: Option<String>,
) -> Result<EscrowReleaseStatus, ShareRecoveryError> {
    let (did, pds_url) = escrow_target(slot).await?;
    let url = format!("{}/v1/recovery/release", pds_url.trim_end_matches('/'));
    let mut body = serde_json::json!({ "identifier": did });
    if let Some(otp) = otp {
        body["otp"] = serde_json::Value::String(otp);
    }
    let response = pds
        .client()
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| ShareRecoveryError::NetworkError {
            message: e.to_string(),
        })?;
    match response.status().as_u16() {
        200 => {}
        401 => return Err(ShareRecoveryError::ReleaseUnauthorized),
        429 => return Err(rate_limited(&response)),
        status => {
            return Err(ShareRecoveryError::InvalidResponse {
                message: format!("release returned HTTP {status}"),
            })
        }
    }
    let release: ReleaseResponse =
        response
            .json()
            .await
            .map_err(|e| ShareRecoveryError::InvalidResponse {
                message: e.to_string(),
            })?;

    match release.status.as_str() {
        "pending" => Ok(EscrowReleaseStatus {
            status: "pending".to_string(),
            available_at: release.available_at,
            share: None,
        }),
        "released" => {
            let share = release
                .share
                .ok_or_else(|| ShareRecoveryError::InvalidResponse {
                    message: "released without a share".to_string(),
                })?;
            let envelope = crypto::ShareEnvelope::decode_share(&share).map_err(map_decode_error)?;
            if envelope.index() != 2 {
                return Err(ShareRecoveryError::ShareFormat {
                    message: format!("escrow returned share index {}", envelope.index()),
                });
            }
            let mut guard = slot.lock().await;
            let session = guard
                .as_mut()
                .ok_or(ShareRecoveryError::NoRecoverySession)?;
            if let Some(existing) = session.shares.iter().find(|s| s.index != 2) {
                if existing.set_id != envelope.set_id() {
                    // The escrowed share is from a different generation than the
                    // locally held one — surfaced before any combine.
                    return Err(ShareRecoveryError::ShareSetMismatch {
                        expected_set_id: existing.set_id,
                        got_set_id: envelope.set_id(),
                    });
                }
            }
            let collected = CollectedShare {
                set_id: envelope.set_id(),
                index: envelope.index(),
            };
            // Replace-if-present keeps a re-poll after a completed release idempotent.
            session.shares.retain(|s| s.index != 2);
            session.shares.push(StoredShare::from_envelope(&envelope));
            session.verified = None;
            Ok(EscrowReleaseStatus {
                status: "released".to_string(),
                available_at: None,
                share: Some(collected),
            })
        }
        other => Err(ShareRecoveryError::InvalidResponse {
            message: format!("unknown release status {other:?}"),
        }),
    }
}

async fn escrow_target(slot: &StateSlot) -> Result<(String, String), ShareRecoveryError> {
    let guard = slot.lock().await;
    let session = guard
        .as_ref()
        .ok_or(ShareRecoveryError::NoRecoverySession)?;
    let pds_url = session
        .pds_url
        .clone()
        .ok_or_else(|| ShareRecoveryError::InvalidResponse {
            message: "the identity's DID document lists no PDS endpoint".to_string(),
        })?;
    Ok((session.did.clone(), pds_url))
}

fn rate_limited(response: &reqwest::Response) -> ShareRecoveryError {
    ShareRecoveryError::RateLimited {
        retry_after: response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
    }
}

// ── Verify: combine → derive → compare against plc.directory ─────────────────

/// Combine the two collected shares, derive the recovery keypair, and verify the
/// derived public key against the DID's authoritative current `rotationKeys` from
/// plc.directory. Nothing is signed before this check passes.
#[tauri::command]
pub async fn verify_recovery_shares(
    state: tauri::State<'_, AppState>,
) -> Result<RecoveredIdentity, ShareRecoveryError> {
    verify_impl(state.pds_client(), &state.share_recovery_state).await
}

pub(crate) async fn verify_impl(
    pds: &PdsClient,
    slot: &StateSlot,
) -> Result<RecoveredIdentity, ShareRecoveryError> {
    // Derive under the lock, then drop it for the network fetch.
    let (did, handle, seed, recovery_key_id) = {
        let guard = slot.lock().await;
        let session = guard
            .as_ref()
            .ok_or(ShareRecoveryError::NoRecoverySession)?;
        if session.shares.len() < 2 {
            return Err(ShareRecoveryError::SharesIncomplete);
        }
        let a = session.shares[0].decode()?;
        let b = session.shares[1].decode()?;
        let seed = crypto::combine_envelopes(&a, &b).map_err(|e| match e {
            crypto::CryptoError::ShareVersion(_) => ShareRecoveryError::ShareVersion,
            other => ShareRecoveryError::ShareFormat {
                message: other.to_string(),
            },
        })?;
        let keypair = crypto::derive_recovery_keypair(&seed).map_err(|e| {
            ShareRecoveryError::SigningFailed {
                message: e.to_string(),
            }
        })?;
        (
            session.did.clone(),
            session.handle.clone(),
            seed,
            keypair.key_id.0,
        )
    };

    let current = fetch_current_state(pds, &did).await?;
    if !current.rotation_keys.iter().any(|k| k == &recovery_key_id) {
        return Err(ShareRecoveryError::SharesDoNotMatchIdentity);
    }

    let mut guard = slot.lock().await;
    let session = guard
        .as_mut()
        .ok_or(ShareRecoveryError::NoRecoverySession)?;
    session.verified = Some(VerifiedShares {
        seed,
        recovery_key_id: recovery_key_id.clone(),
    });

    Ok(RecoveredIdentity {
        did,
        handle,
        recovery_key_id,
        rotation_keys: current.rotation_keys,
    })
}

// ── Re-anchor: recovery key signs in a fresh device key ──────────────────────

/// Generate a fresh device key on this device and submit the recovery-key-signed PLC
/// rotation op replacing `rotationKeys[0]` with it. Idempotent: a retry that finds
/// the new device key already at the root slot skips the submission. On success the
/// rotation epilogue is staged durably so it cannot be skipped.
///
/// This command talks only to plc.directory — the sovereign-session bootstrap against
/// the PDS happens in the epilogue's re-escrow step, keeping the fully-sovereign path
/// free of PDS contact until then.
#[tauri::command]
pub async fn recover_identity(
    state: tauri::State<'_, AppState>,
) -> Result<RecoveryAnchor, ShareRecoveryError> {
    recover_impl(state.pds_client(), &state.share_recovery_state).await
}

pub(crate) async fn recover_impl(
    pds: &PdsClient,
    slot: &StateSlot,
) -> Result<RecoveryAnchor, ShareRecoveryError> {
    let (did, seed, recovery_key_id) = {
        let guard = slot.lock().await;
        let session = guard
            .as_ref()
            .ok_or(ShareRecoveryError::NoRecoverySession)?;
        let verified = session
            .verified
            .as_ref()
            .ok_or(ShareRecoveryError::SharesIncomplete)?;
        (
            session.did.clone(),
            verified.seed.clone(),
            verified.recovery_key_id.clone(),
        )
    };

    let store = IdentityStore;
    match store.add_identity(&did) {
        Ok(()) | Err(IdentityStoreError::IdentityAlreadyExists) => {}
        Err(e) => return Err(map_store_error(e)),
    }
    let device = store
        .get_or_create_device_key(&did)
        .map_err(map_store_error)?;

    let current = fetch_current_state(pds, &did).await?;

    let (op_cid, already_anchored) = if current.rotation_keys.first() == Some(&device.key_id) {
        // A prior attempt's op already landed; nothing to sign.
        (None, true)
    } else {
        if !current.rotation_keys.iter().any(|k| k == &recovery_key_id) {
            // The doc changed since verification (or verification was skipped).
            return Err(ShareRecoveryError::SharesDoNotMatchIdentity);
        }
        let new_keys = anchored_rotation_keys(&current.rotation_keys, &device.key_id);

        let sign = recovery_sign_closure(seed);
        let op = crypto::build_did_plc_rotation_op(
            &current.prev_cid,
            new_keys,
            current.verification_methods.clone(),
            current.also_known_as.clone(),
            current.services.clone(),
            sign,
        )
        .map_err(|e| ShareRecoveryError::SigningFailed {
            message: e.to_string(),
        })?;
        let op_json: serde_json::Value = serde_json::from_str(&op.signed_op_json).map_err(|e| {
            ShareRecoveryError::SigningFailed {
                message: format!("signed op is not valid JSON: {e}"),
            }
        })?;
        pds.post_plc_operation(&did, &op_json).await.map_err(|e| {
            ShareRecoveryError::PlcDirectoryError {
                message: e.to_string(),
            }
        })?;
        (Some(op.cid), false)
    };

    refresh_identity_cache(pds, &store, &did).await?;

    // Stage the mandatory rotation epilogue durably BEFORE returning: from here on
    // the lost device's share world must be voided even if the app dies right now.
    stage_epilogue(&did, &recovery_key_id)?;

    Ok(RecoveryAnchor {
        did,
        op_cid,
        already_anchored,
    })
}

/// The rotation-key list after the re-anchor: the fresh device key takes the root
/// slot (replacing the lost device's key); every other key keeps its position.
fn anchored_rotation_keys(current: &[String], device_key: &str) -> Vec<String> {
    let mut new_keys: Vec<String> = current
        .iter()
        .filter(|k| k.as_str() != device_key)
        .cloned()
        .collect();
    if new_keys.is_empty() {
        new_keys.push(device_key.to_string());
    } else {
        new_keys[0] = device_key.to_string();
    }
    new_keys
}

/// The rotation-key list after the epilogue swap: the new recovery key replaces the
/// old one in place; if the old key vanished (external rotation), the new key is
/// installed at the recovery slot position without displacing other keys.
fn swapped_rotation_keys(current: &[String], old_key: &str, new_key: &str) -> Vec<String> {
    let mut new_keys = current.to_vec();
    if let Some(pos) = new_keys.iter().position(|k| k == old_key) {
        new_keys[pos] = new_key.to_string();
    } else {
        let pos = 1.min(new_keys.len());
        new_keys.insert(pos, new_key.to_string());
    }
    new_keys
}

/// Signing closure over the reconstructed recovery seed. Mirrors the device-key
/// closures: raw 64-byte r||s, low-S normalized (plc.directory rejects high-S).
fn recovery_sign_closure(
    seed: Zeroizing<[u8; 32]>,
) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError> {
    move |message: &[u8]| {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        let keypair = crypto::derive_recovery_keypair(&seed)?;
        let signing_key = SigningKey::from_slice(keypair.private_key_bytes.as_slice())
            .map_err(|e| crypto::CryptoError::KeyGeneration(e.to_string()))?;
        let signature: Signature = signing_key.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().to_vec())
    }
}

async fn fetch_current_state(
    pds: &PdsClient,
    did: &str,
) -> Result<CurrentHandleState, ShareRecoveryError> {
    let audit_json = pds.fetch_audit_log(did).await.map_err(map_pds_error)?;
    let audit =
        crypto::parse_audit_log(&audit_json).map_err(|e| ShareRecoveryError::InvalidAuditLog {
            message: e.to_string(),
        })?;
    latest_full_state(&audit).map_err(|e| ShareRecoveryError::InvalidAuditLog {
        message: e.to_string(),
    })
}

/// Refresh the per-identity caches with the PLC *data* document (never the W3C form,
/// which carries no `rotationKeys` and degrades the home badge to "Unknown").
async fn refresh_identity_cache(
    pds: &PdsClient,
    store: &IdentityStore,
    did: &str,
) -> Result<(), ShareRecoveryError> {
    let updated_log = pds.fetch_audit_log(did).await.map_err(map_pds_error)?;
    store
        .store_plc_log(did, &updated_log)
        .map_err(map_store_error)?;
    let did_doc = pds
        .fetch_plc_data_document(did)
        .await
        .map_err(map_pds_error)?;
    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(map_store_error)?;
    Ok(())
}

// ── Rotation epilogue (durable, resumable) ───────────────────────────────────

/// The durable epilogue record. The share fields are share material held in plain
/// `String`s only while (de)serialized — wiped on drop, same rule as the ceremony
/// staging record.
#[derive(Serialize, Deserialize)]
struct EpilogueRecord {
    version: u32,
    did: String,
    /// The recovery key the shares reconstructed — replaced by the swap op.
    old_recovery_key_id: String,
    /// did:key derived from the NEW seed.
    new_recovery_key_id: String,
    share1: String,
    share2: String,
    share3: String,
    op_submitted: bool,
    escrow_deposited: bool,
    escrow_skipped: bool,
    share1_written: bool,
}

impl Drop for EpilogueRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.share1.zeroize();
        self.share2.zeroize();
        self.share3.zeroize();
    }
}

/// Generate the epilogue's fresh share world (new seed, new set_id, new recovery
/// key) and persist it durably. Reuses an existing record for the same DID (a retry
/// must not orphan an already-escrowed set); refuses to clobber one for another DID.
fn stage_epilogue(did: &str, old_recovery_key_id: &str) -> Result<(), ShareRecoveryError> {
    if let Some(existing) = load_epilogue()? {
        if existing.did == did {
            return Ok(());
        }
        return Err(ShareRecoveryError::EpilogueCorrupt {
            message: format!(
                "a rotation epilogue is already pending for {}",
                existing.did
            ),
        });
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|e| ShareRecoveryError::SigningFailed {
            message: format!("OS RNG unavailable: {e}"),
        })?;
    let mut set_id_bytes = [0u8; 4];
    OsRng
        .try_fill_bytes(&mut set_id_bytes)
        .map_err(|e| ShareRecoveryError::SigningFailed {
            message: format!("OS RNG unavailable: {e}"),
        })?;
    let set_id = u32::from_be_bytes(set_id_bytes);

    let envelopes = crypto::split_secret_into_envelopes(&seed, set_id).map_err(|e| {
        ShareRecoveryError::SigningFailed {
            message: e.to_string(),
        }
    })?;
    let new_recovery =
        crypto::derive_recovery_keypair(&seed).map_err(|e| ShareRecoveryError::SigningFailed {
            message: e.to_string(),
        })?;

    let record = EpilogueRecord {
        version: EPILOGUE_VERSION,
        did: did.to_string(),
        old_recovery_key_id: old_recovery_key_id.to_string(),
        new_recovery_key_id: new_recovery.key_id.0,
        share1: envelopes[0].encode_share().to_string(),
        share2: envelopes[1].encode_share().to_string(),
        share3: envelopes[2].encode_share().to_string(),
        op_submitted: false,
        escrow_deposited: false,
        escrow_skipped: false,
        share1_written: false,
    };
    save_epilogue(&record)
}

fn save_epilogue(record: &EpilogueRecord) -> Result<(), ShareRecoveryError> {
    let json = Zeroizing::new(
        serde_json::to_string(record).expect("epilogue record serialization cannot fail"),
    );
    keychain::store_item(EPILOGUE_ACCOUNT, json.as_bytes()).map_err(map_keychain_error)
}

/// Read the epilogue record. Fail-closed contract: only a genuinely absent slot is
/// `Ok(None)`; a present-but-unreadable record errors and is preserved — it may hold
/// the only copy of a share set the swap op already bound to the DID.
fn load_epilogue() -> Result<Option<EpilogueRecord>, ShareRecoveryError> {
    let bytes = match keychain::get_item(EPILOGUE_ACCOUNT) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if keychain::is_not_found(&e) => return Ok(None),
        Err(e) => {
            return Err(ShareRecoveryError::EpilogueCorrupt {
                message: format!("keychain read failed: {e}"),
            })
        }
    };
    let record: EpilogueRecord =
        serde_json::from_slice(&bytes).map_err(|e| ShareRecoveryError::EpilogueCorrupt {
            message: format!("unparseable epilogue record: {e}"),
        })?;
    if record.version != EPILOGUE_VERSION {
        return Err(ShareRecoveryError::EpilogueCorrupt {
            message: format!("unsupported epilogue record version {}", record.version),
        });
    }
    Ok(Some(record))
}

/// Report a pending (interrupted) rotation epilogue, if any — the launch-time resume
/// hook. A corrupt record errors (and stays put) rather than reading as absent.
#[tauri::command]
pub fn get_pending_recovery_epilogue() -> Result<Option<PendingEpilogue>, ShareRecoveryError> {
    Ok(load_epilogue()?.map(|record| PendingEpilogue {
        did: record.did.clone(),
        op_submitted: record.op_submitted,
        escrow_deposited: record.escrow_deposited,
        escrow_skipped: record.escrow_skipped,
        share1_written: record.share1_written,
    }))
}

/// Run (or resume) the rotation epilogue: swap the new recovery key into the doc
/// (signed by the new device key), re-escrow the new Share 2 over a sovereign
/// session, and rewrite the Keychain Share 1. Every step is idempotent and recorded
/// durably as it completes, so this command can be re-invoked after any failure or
/// an app restart. `skip_escrow` records an explicit opt-out of the re-escrow step
/// (the fully-sovereign posture when the PDS is gone or untrusted).
#[tauri::command]
pub async fn run_recovery_epilogue(
    state: tauri::State<'_, AppState>,
    skip_escrow: Option<bool>,
) -> Result<EpilogueResult, ShareRecoveryError> {
    epilogue_impl(state.pds_client(), skip_escrow.unwrap_or(false)).await
}

pub(crate) async fn epilogue_impl(
    pds: &PdsClient,
    skip_escrow: bool,
) -> Result<EpilogueResult, ShareRecoveryError> {
    let mut record = load_epilogue()?.ok_or(ShareRecoveryError::NoPendingEpilogue)?;
    let store = IdentityStore;

    // Step 1 — swap the recovery slot. The new device key (rotationKeys[0] after the
    // re-anchor) signs. A doc already carrying the new recovery key marks the step
    // complete without re-submitting.
    if !record.op_submitted {
        let current = fetch_current_state(pds, &record.did).await?;
        if current
            .rotation_keys
            .iter()
            .any(|k| k == &record.new_recovery_key_id)
        {
            record.op_submitted = true;
        } else {
            let new_keys = swapped_rotation_keys(
                &current.rotation_keys,
                &record.old_recovery_key_id,
                &record.new_recovery_key_id,
            );
            let sign =
                crate::identity_store::per_did_sign_closure(&record.did).map_err(|e| match e {
                    PerDidSignError::DeviceKeyNotFound { message }
                    | PerDidSignError::SigningSetupFailed { message } => {
                        ShareRecoveryError::SigningFailed { message }
                    }
                })?;
            let op = crypto::build_did_plc_rotation_op(
                &current.prev_cid,
                new_keys,
                current.verification_methods.clone(),
                current.also_known_as.clone(),
                current.services.clone(),
                sign,
            )
            .map_err(|e| ShareRecoveryError::SigningFailed {
                message: e.to_string(),
            })?;
            let op_json: serde_json::Value =
                serde_json::from_str(&op.signed_op_json).map_err(|e| {
                    ShareRecoveryError::SigningFailed {
                        message: format!("signed op is not valid JSON: {e}"),
                    }
                })?;
            pds.post_plc_operation(&record.did, &op_json)
                .await
                .map_err(|e| ShareRecoveryError::PlcDirectoryError {
                    message: e.to_string(),
                })?;
            record.op_submitted = true;
        }
        save_epilogue(&record)?;
        refresh_identity_cache(pds, &store, &record.did).await?;
    }

    // Step 2 — re-escrow the new Share 2 over a sovereign session. This is the first
    // PDS contact of the fully-sovereign path; skipping it records an explicit
    // opt-out rather than silently losing the escrow leg.
    if !record.escrow_deposited && !record.escrow_skipped {
        if skip_escrow {
            record.escrow_skipped = true;
            save_epilogue(&record)?;
        } else {
            let (pds_url, access_jwt) = ensure_session(pds, &store, &record.did).await?;
            deposit_escrow_share(pds, &pds_url, &access_jwt, &record.share2).await?;
            record.escrow_deposited = true;
            save_epilogue(&record)?;
        }
    }

    // Step 3 — rewrite the recovered DID's durable per-DID Share 1 slot, with a read-back
    // verify (the teardown in `confirm_recovery_backup` re-checks it before destroying the
    // record, mirroring the create-flow ceremony's invariant).
    if !record.share1_written {
        let share1_account = crate::rekey::recovery_share1_account(&record.did);
        keychain::store_item(&share1_account, record.share1.as_bytes())
            .map_err(map_keychain_error)?;
        let read_back = keychain::get_item(&share1_account).map_err(map_keychain_error)?;
        if read_back != record.share1.as_bytes() {
            return Err(ShareRecoveryError::KeychainError {
                message: "Share 1 read-back verification failed".to_string(),
            });
        }
        record.share1_written = true;
        save_epilogue(&record)?;
    }

    let envelope3 =
        crypto::ShareEnvelope::decode_share(&record.share3).map_err(map_decode_error)?;
    Ok(EpilogueResult {
        share3: record.share3.clone(),
        share3_words: envelope3.encode_share_words().to_string(),
        escrow_deposited: record.escrow_deposited,
        escrow_skipped: record.escrow_skipped,
    })
}

/// A usable full-access session for the epilogue's escrow deposit: a persisted
/// record with a live access token, else a fresh device-key sovereign login (the new
/// device key is a current rotation key the moment the re-anchor op lands, so the
/// recovered wallet authenticates passwordlessly).
async fn ensure_session(
    pds: &PdsClient,
    store: &IdentityStore,
    did: &str,
) -> Result<(String, String), ShareRecoveryError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(Some(record)) = store.load_oauth_tokens(did) {
        if record
            .access_expires_at
            .is_some_and(|exp| exp > now.saturating_add(60))
        {
            return Ok((record.pds_url, record.access_jwt));
        }
    }
    let nonce = sovereign_session::fresh_nonce();
    let timestamp =
        sovereign_session::unix_timestamp().map_err(|e| ShareRecoveryError::SessionFailed {
            message: e.to_string(),
        })?;
    sovereign_session::sovereign_login_impl(pds, store, did, timestamp, &nonce)
        .await
        .map_err(|e| ShareRecoveryError::SessionFailed {
            message: e.to_string(),
        })?;
    let record = store
        .load_oauth_tokens(did)
        .map_err(map_store_error)?
        .ok_or_else(|| ShareRecoveryError::SessionFailed {
            message: "sovereign login succeeded but no session was persisted".to_string(),
        })?;
    Ok((record.pds_url, record.access_jwt))
}

async fn deposit_escrow_share(
    pds: &PdsClient,
    pds_url: &str,
    access_jwt: &str,
    share2: &str,
) -> Result<(), ShareRecoveryError> {
    let url = format!("{}/v1/recovery/escrow-share", pds_url.trim_end_matches('/'));
    let response = pds
        .client()
        .put(url)
        .bearer_auth(access_jwt)
        .json(&serde_json::json!({ "share": share2 }))
        .send()
        .await
        .map_err(|e| ShareRecoveryError::NetworkError {
            message: e.to_string(),
        })?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(ShareRecoveryError::EscrowDepositFailed {
            message: format!("escrow deposit returned HTTP {}", status.as_u16()),
        })
    }
}

/// Teardown gate for the recovered wallet's backup: verifies the NEW Share 1 is
/// durably in its slot, then destroys the epilogue record (the new seed material's
/// last transient home) and the in-memory ceremony session. Idempotent.
#[tauri::command]
pub async fn confirm_recovery_backup(
    state: tauri::State<'_, AppState>,
) -> Result<(), crate::ShareBackupError> {
    confirm_backup_core(&state.share_recovery_state).await
}

pub(crate) async fn confirm_backup_core(slot: &StateSlot) -> Result<(), crate::ShareBackupError> {
    let record = match load_epilogue() {
        Ok(Some(record)) => record,
        // Already confirmed (or never staged) — nothing to tear down.
        Ok(None) => {
            *slot.lock().await = None;
            return Ok(());
        }
        Err(_) => return Err(crate::ShareBackupError::KeychainError),
    };
    match keychain::get_item(&crate::rekey::recovery_share1_account(&record.did)) {
        Ok(bytes) if bytes == record.share1.as_bytes() => {}
        Ok(_) => return Err(crate::ShareBackupError::ShareNotStored),
        // A missing slot means the durable write never landed; an operational Keychain
        // failure (e.g. a locked device) is not evidence the share is absent — surface it
        // as retryable rather than the misleading "not saved yet" (mirrors confirm_share_backup).
        Err(ref e) if keychain::is_not_found(e) => {
            return Err(crate::ShareBackupError::ShareNotStored)
        }
        Err(_) => return Err(crate::ShareBackupError::KeychainError),
    }
    match keychain::delete_item(EPILOGUE_ACCOUNT) {
        Ok(()) => {}
        Err(e) if keychain::is_not_found(&e) => {}
        Err(_) => return Err(crate::ShareBackupError::KeychainError),
    }
    *slot.lock().await = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;

    const DID: &str = "did:plc:recoverytest0123456789ab";

    /// Generate a real 2-of-3 split plus the recovery key its seed derives.
    fn make_split(set_id: u32) -> ([crypto::ShareEnvelope; 3], String) {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(seed.as_mut()).unwrap();
        let envelopes = crypto::split_secret_into_envelopes(&seed, set_id).unwrap();
        let keypair = crypto::derive_recovery_keypair(&seed).unwrap();
        (envelopes, keypair.key_id.0)
    }

    fn fresh_slot(did: &str, pds_url: Option<String>) -> StateSlot {
        tokio::sync::Mutex::new(Some(ShareRecoveryState {
            did: did.to_string(),
            handle: Some("alice.example.com".to_string()),
            pds_url,
            shares: Vec::new(),
            verified: None,
        }))
    }

    async fn push_share(slot: &StateSlot, env: &crypto::ShareEnvelope) {
        add_share_impl(slot, &env.encode_share()).await.unwrap();
    }

    fn audit_log_json(rotation_keys: &[&str], pds_endpoint: &str, prev_cid: &str) -> String {
        serde_json::json!([{
            "did": DID,
            "cid": prev_cid,
            "createdAt": "2026-07-01T00:00:00.000Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "rotationKeys": rotation_keys,
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": { "atproto": "did:key:zPdsSigning" },
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": pds_endpoint
                    }
                }
            }
        }])
        .to_string()
    }

    // ── Share collection: distinct, human-legible failures before any combine ──

    #[tokio::test]
    async fn add_share_surfaces_checksum_set_mismatch_and_duplicate_distinctly() {
        let (set_a, _) = make_split(0x1111_1111);
        let (set_b, _) = make_split(0x2222_2222);
        let slot = fresh_slot(DID, None);

        // Word-phrase entry works and reports metadata.
        let collected = add_share_impl(&slot, &set_a[2].encode_share_words())
            .await
            .unwrap();
        assert_eq!(collected.index, 3);
        assert_eq!(collected.set_id, 0x1111_1111);

        // A corrupted share fails the checksum — distinct from a format error. Flip a
        // character in the payload region (char 20 ≈ byte 12): the leading character
        // encodes the version byte, whose corruption is a ShareVersion error instead.
        let share1 = set_a[0].encode_share();
        let flipped = if &share1[20..21] == "A" { "B" } else { "A" };
        let mut corrupt = share1.to_string();
        corrupt.replace_range(20..21, flipped);
        assert!(matches!(
            add_share_impl(&slot, &corrupt).await,
            Err(ShareRecoveryError::ShareChecksum)
        ));

        // Garbage is a format error, not a checksum error.
        assert!(matches!(
            add_share_impl(&slot, "not-a-share").await,
            Err(ShareRecoveryError::ShareFormat { .. })
        ));

        // A share from another split generation is a set mismatch, named by set_id.
        match add_share_impl(&slot, &set_b[0].encode_share()).await {
            Err(ShareRecoveryError::ShareSetMismatch {
                expected_set_id,
                got_set_id,
            }) => {
                assert_eq!(expected_set_id, 0x1111_1111);
                assert_eq!(got_set_id, 0x2222_2222);
            }
            other => panic!("expected ShareSetMismatch, got {other:?}"),
        }

        // The same index twice is a duplicate.
        assert!(matches!(
            add_share_impl(&slot, &set_a[2].encode_share()).await,
            Err(ShareRecoveryError::DuplicateShare { index: 3 })
        ));
    }

    // ── Verification against the authoritative doc ─────────────────────────────

    #[tokio::test]
    async fn verify_accepts_matching_shares_and_rejects_foreign_ones() {
        let (set_a, recovery_key) = make_split(0x3333_3333);

        let plc = MockServer::start();
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{DID}/log/audit"));
            then.status(200).body(audit_log_json(
                &["did:key:zOldDevice", recovery_key.as_str(), "did:key:zPds"],
                "https://pds.example.com",
                "bafyprev1",
            ));
        });
        let pds = PdsClient::new_for_test(plc.base_url());

        let slot = fresh_slot(DID, None);
        push_share(&slot, &set_a[0]).await;
        push_share(&slot, &set_a[2]).await;

        let verified = verify_impl(&pds, &slot).await.unwrap();
        assert_eq!(verified.recovery_key_id, recovery_key);
        assert_eq!(verified.did, DID);

        // Different shares (a different identity's split) fail the pubkey check
        // loudly, before anything would be signed.
        let (foreign, _) = make_split(0x4444_4444);
        let slot2 = fresh_slot(DID, None);
        push_share(&slot2, &foreign[0]).await;
        push_share(&slot2, &foreign[2]).await;
        assert!(matches!(
            verify_impl(&pds, &slot2).await,
            Err(ShareRecoveryError::SharesDoNotMatchIdentity)
        ));
    }

    #[tokio::test]
    async fn verify_requires_two_shares() {
        let pds = PdsClient::new_for_test("http://127.0.0.1:1".to_string());
        let (set_a, _) = make_split(1);
        let slot = fresh_slot(DID, None);
        push_share(&slot, &set_a[0]).await;
        assert!(matches!(
            verify_impl(&pds, &slot).await,
            Err(ShareRecoveryError::SharesIncomplete)
        ));
    }

    // ── Escrow release client (assisted path) ──────────────────────────────────

    #[tokio::test]
    async fn release_flow_handles_pending_released_and_unauthorized() {
        let (set_a, _) = make_split(0x5555_5555);
        let custos = MockServer::start();

        // Opening with the OTP enters the pending window.
        let mut pending = custos.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/v1/recovery/release")
                .body_includes("\"otp\"");
            then.status(200).json_body(serde_json::json!({
                "status": "pending",
                "availableAt": "2026-07-19 00:00:00"
            }));
        });

        let slot = fresh_slot(DID, Some(custos.base_url()));
        push_share(&slot, &set_a[0]).await;
        let pds = PdsClient::new_for_test(custos.base_url());

        let status = release_impl(&pds, &slot, Some("123456".to_string()))
            .await
            .unwrap();
        assert_eq!(status.status, "pending");
        assert_eq!(status.available_at.as_deref(), Some("2026-07-19 00:00:00"));
        assert_eq!(pending.calls(), 1);
        pending.delete();

        // A later poll (no OTP) returns the share, which joins the session.
        let mut released = custos.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/v1/recovery/release");
            then.status(200).json_body(serde_json::json!({
                "status": "released",
                "share": set_a[1].encode_share().to_string()
            }));
        });
        let status = release_impl(&pds, &slot, None).await.unwrap();
        assert_eq!(status.status, "released");
        assert_eq!(status.share.as_ref().unwrap().index, 2);
        assert_eq!(released.calls(), 1);
        released.delete();
        {
            let guard = slot.lock().await;
            let session = guard.as_ref().unwrap();
            assert_eq!(session.shares.len(), 2);
        }

        // The server's uniform 401 (wrong OTP / cancelled / expired) maps to one
        // typed error — the wallet cannot distinguish, by server design.
        custos.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/v1/recovery/release");
            then.status(401)
                .json_body(serde_json::json!({ "error": "Unauthorized" }));
        });
        assert!(matches!(
            release_impl(&pds, &slot, None).await,
            Err(ShareRecoveryError::ReleaseUnauthorized)
        ));
    }

    #[tokio::test]
    async fn released_share_from_wrong_set_is_a_set_mismatch() {
        let (set_a, _) = make_split(0x6666_6666);
        let (set_b, _) = make_split(0x7777_7777);
        let custos = MockServer::start();
        custos.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/v1/recovery/release");
            then.status(200).json_body(serde_json::json!({
                "status": "released",
                "share": set_b[1].encode_share().to_string()
            }));
        });
        let slot = fresh_slot(DID, Some(custos.base_url()));
        push_share(&slot, &set_a[0]).await;
        let pds = PdsClient::new_for_test(custos.base_url());
        assert!(matches!(
            release_impl(&pds, &slot, Some("123456".to_string())).await,
            Err(ShareRecoveryError::ShareSetMismatch { .. })
        ));
    }

    // ── Re-anchor: zero PDS contact, device key takes the root slot ────────────

    #[tokio::test]
    async fn recover_identity_is_zero_custos_and_stages_the_epilogue() {
        crate::keychain::clear_for_test();
        let (set_a, recovery_key) = make_split(0x8888_8888);

        // A PDS mock with a catch-all: the sovereign path must never touch it
        // before the epilogue's re-escrow step.
        let custos = MockServer::start();
        // No `when` criteria: matches every request, so `calls()` counts all contact.
        let custos_any = custos.mock(|_when, then| {
            then.status(500);
        });

        let plc = MockServer::start();
        let audit = audit_log_json(
            &["did:key:zLostDevice", recovery_key.as_str(), "did:key:zPds"],
            &custos.base_url(),
            "bafyprev1",
        );
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{DID}/log/audit"));
            then.status(200).body(audit.clone());
        });
        let post_op = plc.mock(|when, then| {
            when.method(httpmock::Method::POST).path(format!("/{DID}"));
            then.status(200).json_body(serde_json::json!({}));
        });
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{DID}/data"));
            then.status(200).json_body(serde_json::json!({
                "did": DID,
                "rotationKeys": ["did:key:zNewDevice", recovery_key, "did:key:zPds"],
                "alsoKnownAs": ["at://alice.example.com"],
                "verificationMethods": {},
                "services": {}
            }));
        });
        let pds = PdsClient::new_for_test(plc.base_url());

        let slot = fresh_slot(DID, Some(custos.base_url()));
        push_share(&slot, &set_a[0]).await;
        push_share(&slot, &set_a[2]).await;
        verify_impl(&pds, &slot).await.unwrap();

        let anchor = recover_impl(&pds, &slot).await.unwrap();
        assert!(!anchor.already_anchored);
        assert!(anchor.op_cid.is_some());
        assert_eq!(post_op.calls(), 1, "exactly one re-anchor op submitted");
        assert_eq!(
            custos_any.calls(),
            0,
            "the fully sovereign path must make zero PDS requests up to re-escrow"
        );

        // The mandatory rotation epilogue is staged durably before returning.
        let pending = get_pending_recovery_epilogue().unwrap().unwrap();
        assert_eq!(pending.did, DID);
        assert!(!pending.op_submitted);
    }

    #[tokio::test]
    async fn recover_identity_retry_after_landed_op_is_idempotent() {
        crate::keychain::clear_for_test();
        let (set_a, recovery_key) = make_split(0x9999_9999);

        // Register the identity first so the device key exists and can be read back
        // as the already-anchored rotationKeys[0].
        let store = IdentityStore;
        store.add_identity(DID).unwrap();
        let device = store.get_or_create_device_key(DID).unwrap();

        let plc = MockServer::start();
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{DID}/log/audit"));
            then.status(200).body(audit_log_json(
                &[
                    device.key_id.as_str(),
                    recovery_key.as_str(),
                    "did:key:zPds",
                ],
                "https://pds.example.com",
                "bafyprev2",
            ));
        });
        let post_op = plc.mock(|when, then| {
            when.method(httpmock::Method::POST).path(format!("/{DID}"));
            then.status(200).json_body(serde_json::json!({}));
        });
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{DID}/data"));
            then.status(200)
                .json_body(serde_json::json!({ "did": DID }));
        });
        let pds = PdsClient::new_for_test(plc.base_url());

        let slot = fresh_slot(DID, None);
        push_share(&slot, &set_a[0]).await;
        push_share(&slot, &set_a[2]).await;
        verify_impl(&pds, &slot).await.unwrap();

        let anchor = recover_impl(&pds, &slot).await.unwrap();
        assert!(anchor.already_anchored);
        assert!(anchor.op_cid.is_none());
        assert_eq!(
            post_op.calls(),
            0,
            "an already-landed op is never re-submitted"
        );
    }

    // ── Rotation-key construction ──────────────────────────────────────────────

    #[test]
    fn anchored_rotation_keys_replaces_the_root_slot_only() {
        let current = vec![
            "did:key:zLost".to_string(),
            "did:key:zRecovery".to_string(),
            "did:key:zPds".to_string(),
        ];
        assert_eq!(
            anchored_rotation_keys(&current, "did:key:zNew"),
            vec!["did:key:zNew", "did:key:zRecovery", "did:key:zPds"]
        );
        // A somehow-already-present device key is deduped, not duplicated.
        assert_eq!(
            anchored_rotation_keys(&current, "did:key:zRecovery"),
            vec!["did:key:zRecovery", "did:key:zPds"]
        );
    }

    #[test]
    fn swapped_rotation_keys_replaces_in_place_or_inserts_at_recovery_slot() {
        let current = vec![
            "did:key:zDevice".to_string(),
            "did:key:zOldRecovery".to_string(),
            "did:key:zPds".to_string(),
        ];
        assert_eq!(
            swapped_rotation_keys(&current, "did:key:zOldRecovery", "did:key:zNewRecovery"),
            vec!["did:key:zDevice", "did:key:zNewRecovery", "did:key:zPds"]
        );
        // Old key externally rotated away: install at the recovery slot position.
        let without_old = vec!["did:key:zDevice".to_string(), "did:key:zPds".to_string()];
        assert_eq!(
            swapped_rotation_keys(&without_old, "did:key:zOldRecovery", "did:key:zNewRecovery"),
            vec!["did:key:zDevice", "did:key:zNewRecovery", "did:key:zPds"]
        );
    }

    // ── Epilogue: interruption, resume, escrow deposit, teardown ───────────────

    /// Register the identity + device key and stage an epilogue, returning the plc
    /// mock preloaded with the swap-op surface.
    fn stage_for_epilogue(recovery_key: &str) -> (MockServer, String) {
        let store = IdentityStore;
        store.add_identity(DID).unwrap();
        let device = store.get_or_create_device_key(DID).unwrap();
        stage_epilogue(DID, recovery_key).unwrap();

        let plc = MockServer::start();
        let audit = audit_log_json(
            &[device.key_id.as_str(), recovery_key, "did:key:zPds"],
            "https://pds.example.com",
            "bafyprev3",
        );
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{DID}/log/audit"));
            then.status(200).body(audit);
        });
        plc.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/{DID}/data"));
            then.status(200)
                .json_body(serde_json::json!({ "did": DID }));
        });
        (plc, device.key_id)
    }

    #[tokio::test]
    async fn interrupted_epilogue_resumes_without_resubmitting_or_regenerating() {
        crate::keychain::clear_for_test();
        let (_, old_recovery_key) = make_split(0xaaaa_aaaa);
        let (plc, _) = stage_for_epilogue(&old_recovery_key);
        let post_op = plc.mock(|when, then| {
            when.method(httpmock::Method::POST).path(format!("/{DID}"));
            then.status(200).json_body(serde_json::json!({}));
        });
        let pds = PdsClient::new_for_test(plc.base_url());

        let staged_before = load_epilogue().unwrap().unwrap();
        let new_key_before = staged_before.new_recovery_key_id.clone();
        let share1_before = staged_before.share1.clone();

        // First run: the swap op lands, then the escrow step fails (no session and
        // no reachable PDS) — the interruption case.
        let err = epilogue_impl(&pds, false).await.unwrap_err();
        assert!(matches!(err, ShareRecoveryError::SessionFailed { .. }));
        assert_eq!(post_op.calls(), 1);
        let pending = get_pending_recovery_epilogue().unwrap().unwrap();
        assert!(pending.op_submitted, "swap-op progress must be durable");
        assert!(!pending.share1_written);

        // Resume (as after an app restart): same record, no re-submit, no
        // regeneration — and the user may explicitly skip escrow.
        let result = epilogue_impl(&pds, true).await.unwrap();
        assert!(result.escrow_skipped);
        assert!(!result.escrow_deposited);
        assert!(!result.share3_words.is_empty());
        assert_eq!(post_op.calls(), 1, "resume must not re-submit the swap op");

        let staged_after = load_epilogue().unwrap().unwrap();
        assert_eq!(
            staged_after.new_recovery_key_id, new_key_before,
            "resume must reuse the staged share set, not regenerate"
        );
        assert_eq!(staged_after.share1, share1_before);

        // Share 1 reached its durable per-DID slot and the teardown verifies it.
        assert_eq!(
            keychain::get_item(&crate::rekey::recovery_share1_account(DID)).unwrap(),
            share1_before.as_bytes()
        );
        let slot = fresh_slot(DID, None);
        confirm_backup_core(&slot).await.unwrap();
        assert!(get_pending_recovery_epilogue().unwrap().is_none());
        // Idempotent re-confirm.
        confirm_backup_core(&slot).await.unwrap();
    }

    #[tokio::test]
    async fn epilogue_deposits_new_share2_over_the_stored_session() {
        crate::keychain::clear_for_test();
        let (_, old_recovery_key) = make_split(0xbbbb_bbbb);
        let (plc, _) = stage_for_epilogue(&old_recovery_key);
        plc.mock(|when, then| {
            when.method(httpmock::Method::POST).path(format!("/{DID}"));
            then.status(200).json_body(serde_json::json!({}));
        });
        let pds = PdsClient::new_for_test(plc.base_url());

        // A persisted sovereign session pointing at the PDS mock (the restart-resume
        // seam: the epilogue reuses it instead of re-minting).
        let custos = MockServer::start();
        let record = crate::identity_store::SovereignTokenRecord {
            version: crate::identity_store::SovereignTokenRecord::VERSION,
            access_jwt: "test-access".to_string(),
            refresh_jwt: "test-refresh".to_string(),
            pds_url: custos.base_url(),
            server_did: "did:web:custos.test".to_string(),
            access_expires_at: Some(u64::MAX),
            refresh_expires_at: Some(u64::MAX),
            stored_at: 0,
        };
        IdentityStore.store_oauth_tokens(DID, &record).unwrap();

        let staged = load_epilogue().unwrap().unwrap();
        let share2 = staged.share2.clone();
        let deposit = custos.mock(move |when, then| {
            when.method(httpmock::Method::PUT)
                .path("/v1/recovery/escrow-share")
                .header("authorization", "Bearer test-access")
                .body_includes(&share2);
            then.status(200)
                .json_body(serde_json::json!({ "status": "deposited" }));
        });

        let result = epilogue_impl(&pds, false).await.unwrap();
        assert!(result.escrow_deposited);
        assert!(!result.escrow_skipped);
        assert_eq!(deposit.calls(), 1, "the NEW Share 2 must be re-escrowed");
    }
}
