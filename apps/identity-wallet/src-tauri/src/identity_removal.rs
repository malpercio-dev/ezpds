// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Permanent identity removal: the wallet-side counterpart to the PDS's
// `requestAccountDelete`/`deleteAccount` endpoints plus a did:plc tombstone.
//
// A removal has three network/local effects, applied in a strict order:
//   1. deleteAccount   — the PDS purges all account data and emits an `#account`
//                        (`status="deleted"`) firehose frame relays consume.
//   2. plc_tombstone   — the wallet signs a tombstone with the DID's device key
//                        (rotationKeys[0]) and POSTs it to plc.directory, so the
//                        did:plc itself is retired network-wide (the PDS cannot do
//                        this — it never holds the rotation key, ADR-0001).
//   3. local wipe      — `IdentityStore::remove_identity` deletes every per-DID
//                        Keychain entry.
//
// Ordering invariant: the local wipe runs LAST and only after the tombstone
// submits, because the wipe deletes the device key that signs the tombstone. If the
// tombstone submit fails, the account is already deleted (its single-use email token
// spent) but the device key survives — the UI resumes via `tombstone_identity`, which
// retries only the tombstone + wipe.

use serde::Serialize;

use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::pds_client::{PdsClient, PdsClientError};
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};

/// Keychain account holding the durable "removal in progress (post-delete)" index:
/// a JSON array of DIDs whose PDS account was deleted but whose tombstone + local
/// wipe has not yet completed. This is the recovery marker that makes a removal
/// interrupted after `deleteAccount` (e.g. iOS killing the app mid-tombstone)
/// resumable — on launch the UI reconciles any listed DID straight to the
/// tombstone-only retry rather than the full request flow (which would fail against
/// the already-deleted account).
const PENDING_REMOVALS_ACCOUNT: &str = "pending-removals";

/// Load the set of DIDs with a pending post-delete removal, propagating a genuine
/// Keychain read failure.
///
/// A missing entry is an empty set, and corrupt JSON reads as empty (the marker is a
/// best-effort payload — a decode failure must not wedge the flow). But a real
/// Keychain security/IO error is returned, NOT swallowed: the mutators
/// (`mark_removal_pending` / `clear_removal_pending`) do a read-modify-write, so
/// silently treating a transient read failure as "empty" would let the subsequent
/// save overwrite the Keychain and drop any *other* DIDs' pending markers.
fn load_pending_removals_strict() -> Result<Vec<String>, crate::keychain::KeychainError> {
    match crate::keychain::get_item(PENDING_REMOVALS_ACCOUNT) {
        Ok(bytes) => Ok(serde_json::from_slice::<Vec<String>>(&bytes).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "pending-removals Keychain entry is not valid JSON; treating as empty");
            Vec::new()
        })),
        Err(e) if crate::keychain::is_not_found(&e) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Best-effort read of the pending-removal set for the infallible launch check.
///
/// Any Keychain trouble reads as an empty set — `list_pending_removals` is called
/// unconditionally on every launch and must never surface an error that could block it.
/// Read-modify-write callers must use [`load_pending_removals_strict`] instead, so a
/// transient read failure cannot clobber unrelated markers.
fn load_pending_removals() -> Vec<String> {
    load_pending_removals_strict().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Keychain error loading pending-removals; treating as empty");
        Vec::new()
    })
}

/// Persist the pending-removals set. An empty set deletes the entry entirely so the
/// Keychain never carries a stale `[]`.
fn save_pending_removals(dids: &[String]) -> Result<(), crate::keychain::KeychainError> {
    if dids.is_empty() {
        return match crate::keychain::delete_item(PENDING_REMOVALS_ACCOUNT) {
            Ok(()) => Ok(()),
            Err(e) if crate::keychain::is_not_found(&e) => Ok(()),
            Err(e) => Err(e),
        };
    }
    // Vec<String> → JSON is infallible; unwrap keeps the signature Keychain-only.
    let json = serde_json::to_vec(dids).expect("Vec<String> always serializes to JSON");
    crate::keychain::store_item(PENDING_REMOVALS_ACCOUNT, &json)
}

/// Mark `did` as having a pending post-delete removal (idempotent).
///
/// Called the instant `deleteAccount` succeeds, before the tombstone network round
/// trip — the step iOS is most likely to interrupt by backgrounding the app.
fn mark_removal_pending(did: &str) -> Result<(), crate::keychain::KeychainError> {
    let mut dids = load_pending_removals_strict()?;
    if !dids.iter().any(|d| d == did) {
        dids.push(did.to_string());
        save_pending_removals(&dids)?;
    }
    Ok(())
}

/// Clear `did`'s pending-removal marker once the tombstone + wipe have completed.
fn clear_removal_pending(did: &str) -> Result<(), crate::keychain::KeychainError> {
    let mut dids = load_pending_removals_strict()?;
    let before = dids.len();
    dids.retain(|d| d != did);
    if dids.len() != before {
        save_pending_removals(&dids)?;
    }
    Ok(())
}

/// Best-effort clear of the pending-removal marker after a successful removal.
///
/// A failure here is non-fatal: the removal already succeeded, and a lingering marker
/// only re-offers the (now idempotent, wipe-only) tombstone retry on the next launch,
/// which clears it. Never fail the removal over marker cleanup.
fn clear_removal_pending_best_effort(did: &str) {
    if let Err(e) = clear_removal_pending(did) {
        tracing::warn!(did = did, error = %e, "failed to clear pending-removal marker after removal");
    }
}

/// Errors from the identity-removal flow.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the other wallet
/// error enums (`RecoveryError`, `SessionError`, …). Variants are ordered by the step
/// that produces them so the UI can tell what already happened — notably, a
/// `PlcDirectoryError`/`RateLimited`/`NetworkError` *after* `InvalidToken` succeeded
/// means the PDS account is gone and only the tombstone + wipe remain (resume via
/// `tombstone_identity`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum RemovalError {
    /// The identity has no usable session; the UI must run the passwordless
    /// `sovereignLogin(did)` unlock before requesting deletion.
    #[error("identity needs a passwordless unlock before removal")]
    SessionRequired { reason: UnlockReason },
    /// `requestAccountDelete` failed (could not mint/send the confirmation code).
    #[error("failed to request account deletion: {message}")]
    RequestDeleteFailed { message: String },
    /// The PDS rejected the account password or the emailed confirmation code.
    #[error("invalid password or confirmation code")]
    InvalidToken,
    /// `deleteAccount` failed for a reason other than bad credentials.
    #[error("account deletion failed: {message}")]
    AccountDeleteFailed { message: String },
    /// The DID's plc.directory audit log could not be fetched/parsed for the tombstone `prev`.
    #[error("could not read the identity's PLC log: {message}")]
    InvalidAuditLog { message: String },
    /// Building or signing the tombstone with the device key failed.
    #[error("failed to sign the tombstone: {message}")]
    TombstoneSigningFailed { message: String },
    /// plc.directory rejected the tombstone. The account is already deleted — retry via
    /// `tombstone_identity`.
    #[error("plc.directory rejected the tombstone: {message}")]
    PlcDirectoryError { message: String },
    /// The DID's device key / managed-dids entry is missing.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
    /// The account was deleted and tombstoned, but the local Keychain wipe failed.
    #[error("local cleanup failed after removal: {message}")]
    LocalWipeFailed { message: String },
    /// A server rate-limited a step; the UI can retry after `retryAfter`.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// Transport failure reaching the PDS or plc.directory.
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// The successful result of a removal (or a `tombstone_identity` resume).
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RemovalOutcome {
    /// The CID of the submitted did:plc tombstone operation.
    pub tombstone_cid: String,
    /// `true` if the removed DID was the last managed identity — the UI returns to
    /// onboarding rather than the identity list.
    pub was_last_identity: bool,
}

/// Map a `deleteAccount` `PdsClientError` onto the removal error surface.
///
/// A 401 (wrong password) and a 400 `INVALID_TOKEN` (bad/expired confirmation code)
/// both collapse to `InvalidToken` — the UI re-prompts for both — while other XRPC
/// failures are a distinct `AccountDeleteFailed`.
fn map_delete_account_error(e: PdsClientError) -> RemovalError {
    match e {
        PdsClientError::Unauthorized { .. } => RemovalError::InvalidToken,
        PdsClientError::XrpcError { status: 400, .. } => RemovalError::InvalidToken,
        PdsClientError::RateLimited { retry_after, .. } => {
            RemovalError::RateLimited { retry_after }
        }
        PdsClientError::NetworkError { message } => RemovalError::NetworkError { message },
        other => RemovalError::AccountDeleteFailed {
            message: other.to_string(),
        },
    }
}

/// Map a `requestAccountDelete` `PdsClientError` onto the removal error surface.
fn map_request_delete_error(e: PdsClientError) -> RemovalError {
    match e {
        PdsClientError::RateLimited { retry_after, .. } => {
            RemovalError::RateLimited { retry_after }
        }
        PdsClientError::NetworkError { message } => RemovalError::NetworkError { message },
        other => RemovalError::RequestDeleteFailed {
            message: other.to_string(),
        },
    }
}

/// Map a `SessionProvider` failure onto the removal error surface.
fn map_session_error(e: SessionError) -> RemovalError {
    match e {
        SessionError::NeedsUnlock { reason } => RemovalError::SessionRequired { reason },
        SessionError::IdentityNotFound => RemovalError::IdentityNotFound {
            message: "no managed identity for this DID".to_string(),
        },
        SessionError::RateLimited { retry_after } => RemovalError::RateLimited { retry_after },
        SessionError::Offline { message } => RemovalError::NetworkError { message },
        other => RemovalError::RequestDeleteFailed {
            message: other.to_string(),
        },
    }
}

/// Submit the tombstone, then — only if that succeeded — run the local wipe.
///
/// Split out so the ordering invariant ("the wipe never runs on a submit failure",
/// which keeps the device key alive for a `tombstone_identity` retry) is unit-testable
/// without a Keychain or a live plc.directory.
async fn submit_then_wipe<Submit, Wipe>(submit: Submit, wipe: Wipe) -> Result<(), RemovalError>
where
    Submit: std::future::Future<Output = Result<(), RemovalError>>,
    Wipe: FnOnce() -> Result<(), RemovalError>,
{
    submit.await?;
    wipe()
}

/// Build + sign + submit the did:plc tombstone, then wipe local Keychain material.
///
/// Shared by `confirm_identity_removal` (after the PDS account is deleted) and
/// `tombstone_identity` (the resume path, where the account is already gone). Returns
/// the tombstone CID on success.
async fn tombstone_and_wipe(pds_client: &PdsClient, did: &str) -> Result<String, RemovalError> {
    let store = IdentityStore;

    // 1. Fetch + parse the audit log and locate the head (newest non-nullified) operation.
    let audit_log_json =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| RemovalError::InvalidAuditLog {
                message: format!("failed to fetch audit log: {e}"),
            })?;
    let audit_log =
        crypto::parse_audit_log(&audit_log_json).map_err(|e| RemovalError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let head = audit_log
        .iter()
        .rev()
        .find(|e| !e.nullified)
        .ok_or_else(|| RemovalError::InvalidAuditLog {
            message: "audit log has no non-nullified operation to chain onto".to_string(),
        })?;
    let head_cid = head.cid.clone();

    // Idempotent resume: if the DID is already tombstoned (its head IS a tombstone), the
    // submit already landed on plc.directory — only the local wipe remains. Submitting a
    // second tombstone would be rejected (a retired DID accepts no further ops), so a resume
    // after a wipe-only failure must skip straight to the wipe. This is what makes
    // `tombstone_identity` safe to call after a partial success.
    let head_is_tombstone =
        head.operation.get("type").and_then(|t| t.as_str()) == Some("plc_tombstone");
    if head_is_tombstone {
        wipe_local(&store, did)?;
        return Ok(head_cid);
    }

    // The tombstone chains onto the head and must be signed by one of the head op's
    // `rotationKeys`. Verifying against those (not merely the local device key) is what
    // proves the wallet's key is still a *current* rotation key — the exact authorization
    // plc.directory will enforce — so a device key that is no longer in the rotation set
    // (e.g. after a migrate-away) fails fast locally instead of after the network round trip.
    let head_rotation_keys = extract_rotation_keys(&head.operation);
    if head_rotation_keys.is_empty() {
        return Err(RemovalError::InvalidAuditLog {
            message: "head operation has no rotationKeys to authorize the tombstone".to_string(),
        });
    }

    // 2. Obtain the per-DID device-key signing closure (rotationKeys[0]).
    let sign = crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
        PerDidSignError::DeviceKeyNotFound { message } => {
            RemovalError::IdentityNotFound { message }
        }
        PerDidSignError::SigningSetupFailed { message } => {
            RemovalError::TombstoneSigningFailed { message }
        }
    })?;

    // 3. Build + sign the tombstone (prev = the head CID).
    let tombstone = crypto::build_did_plc_tombstone_op(&head_cid, sign).map_err(|e| {
        RemovalError::TombstoneSigningFailed {
            message: format!("failed to build tombstone: {e}"),
        }
    })?;

    // 3b. Local self-check against the head op's authorized rotation keys (see above).
    crypto::verify_plc_tombstone_op(&tombstone.signed_op_json, &head_rotation_keys).map_err(
        |e| RemovalError::TombstoneSigningFailed {
            message: format!("tombstone self-verification failed: {e}"),
        },
    )?;

    let op_value: serde_json::Value =
        serde_json::from_str(&tombstone.signed_op_json).map_err(|e| {
            RemovalError::TombstoneSigningFailed {
                message: format!("failed to parse signed tombstone JSON: {e}"),
            }
        })?;

    // 4. Submit to plc.directory, THEN (only on success) 5. wipe local material.
    //    Every failure in this function is post-delete (the account is already gone when
    //    `confirm_identity_removal` calls us), so PLC-submit transport/rate-limit failures
    //    fold into `PlcDirectoryError` rather than the bare `NetworkError`/`RateLimited` the
    //    deletion stage uses — that keeps the two stages' error codes disjoint, so the UI
    //    only enters the tombstone-retry path for genuinely post-delete failures.
    let did_owned = did.to_string();
    submit_then_wipe(
        async {
            pds_client
                .post_plc_operation(&did_owned, &op_value)
                .await
                .map_err(|e| RemovalError::PlcDirectoryError {
                    message: format!("plc.directory rejected the tombstone: {e}"),
                })
        },
        || wipe_local(&store, &did_owned),
    )
    .await?;

    Ok(tombstone.cid)
}

/// Extract a PLC operation's `rotationKeys` as typed did:key URIs (empty if absent/malformed).
fn extract_rotation_keys(operation: &serde_json::Value) -> Vec<crypto::DidKeyUri> {
    operation
        .get("rotationKeys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| crypto::DidKeyUri(s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Wipe the DID's local Keychain material. Best-effort and idempotent: a missing
/// managed-dids entry (already removed by a prior partial run) is success, not failure.
fn wipe_local(store: &IdentityStore, did: &str) -> Result<(), RemovalError> {
    match store.remove_identity(did) {
        Ok(()) => Ok(()),
        Err(crate::identity_store::IdentityStoreError::IdentityNotFound) => Ok(()),
        Err(e) => Err(RemovalError::LocalWipeFailed {
            message: format!("failed to wipe local identity material: {e}"),
        }),
    }
}

/// `true` if no managed identities remain — the UI returns to onboarding rather than the
/// identity list. Shared by the tombstone-completing paths and the local-only forget path.
fn no_identities_remain() -> Result<bool, RemovalError> {
    IdentityStore
        .list_identities()
        .map(|ids| ids.is_empty())
        .map_err(|e| RemovalError::LocalWipeFailed {
            message: format!("failed to re-read managed identities: {e}"),
        })
}

/// Compute the `RemovalOutcome` after a successful `tombstone_and_wipe`.
fn removal_outcome(tombstone_cid: String) -> Result<RemovalOutcome, RemovalError> {
    Ok(RemovalOutcome {
        tombstone_cid,
        was_last_identity: no_identities_remain()?,
    })
}

/// Tauri command: request permanent deletion — emails a single-use confirmation code.
///
/// Obtains a full-access session for `did` (the frontend runs the passwordless unlock
/// first if this returns `SessionRequired`) and calls `requestAccountDelete`. The PDS
/// emails a 1-hour code to the account address; the user then supplies that code plus
/// the account password to `confirm_identity_removal`.
#[tauri::command]
pub async fn request_identity_removal(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<(), RemovalError> {
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| RemovalError::NetworkError {
            message: "system clock is unavailable".to_string(),
        })?;
    let session = SessionProvider
        .full_access_client(state.pds_client(), &IdentityStore, &did, now)
        .await
        .map_err(map_session_error)?;

    crate::pds_client::request_account_delete(&session.client)
        .await
        .map_err(map_request_delete_error)
}

/// Tauri command: confirm removal — delete on the PDS, tombstone the DID, wipe locally.
///
/// `password` is the account password (set during the DID ceremony); `token` is the
/// emailed confirmation code. `deleteAccount` is attempted FIRST, so a wrong
/// password/code (`InvalidToken`) leaves everything intact and the UI re-prompts. Once
/// the account is deleted, the tombstone + wipe run via `tombstone_and_wipe`.
#[tauri::command]
pub async fn confirm_identity_removal(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    password: String,
    token: String,
) -> Result<RemovalOutcome, RemovalError> {
    // The account's PDS base URL comes from its still-present token record (the wipe is
    // last). Falling back to live discovery keeps a stale/absent record from stranding
    // an otherwise-deletable account.
    let pds_url = resolve_pds_url(state.pds_client(), &did).await?;

    // 1. Permanently delete the account on the PDS (body-authed; no session needed).
    state
        .pds_client()
        .delete_account(&pds_url, &did, &password, &token)
        .await
        .map_err(map_delete_account_error)?;

    // The account is now permanently gone and the single-use email code is spent — from
    // here on, only the tombstone + local wipe remain. Persist a durable marker BEFORE the
    // tombstone's network round trip so that if iOS kills/suspends the app mid-tombstone,
    // the next launch resumes via `tombstone_identity` rather than the request flow (which
    // would fail against the deleted account). A marker-write failure is logged but never
    // blocks the removal: the account is already deleted, so aborting here would only strand
    // the identity harder.
    if let Err(e) = mark_removal_pending(&did) {
        tracing::warn!(did = %did, error = %e, "failed to persist pending-removal marker after deleteAccount");
    }

    // 2 + 3. Tombstone the did:plc, then wipe local material.
    let tombstone_cid = tombstone_and_wipe(state.pds_client(), &did).await?;
    clear_removal_pending_best_effort(&did);
    removal_outcome(tombstone_cid)
}

/// Tauri command: resume a removal whose PDS account was already deleted.
///
/// Used when `confirm_identity_removal` deleted the account but the tombstone or wipe
/// failed: the single-use deletion token is already spent, so re-running `confirm`
/// would 401 at `deleteAccount`. `tombstone_and_wipe` is idempotent — if the tombstone
/// already landed (the DID's head is a tombstone), it does a wipe-only retry rather than
/// submitting a second, doomed operation; otherwise it completes the tombstone + wipe.
#[tauri::command]
pub async fn tombstone_identity(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<RemovalOutcome, RemovalError> {
    let tombstone_cid = tombstone_and_wipe(state.pds_client(), &did).await?;
    clear_removal_pending_best_effort(&did);
    removal_outcome(tombstone_cid)
}

/// Tauri command: list DIDs with a pending post-delete removal.
///
/// Backs the launch-time reconciliation: if a removal deleted the PDS account but was
/// interrupted before the tombstone + wipe finished, the DID stays listed here so the UI
/// can resume it (idempotent `tombstone_identity`) instead of re-entering the request
/// flow. Infallible — any Keychain/decoding trouble reads as an empty list, so it can be
/// called unconditionally on every launch.
#[tauri::command]
pub fn list_pending_removals() -> Vec<String> {
    load_pending_removals()
}

/// Tauri command: forget an identity's local material WITHOUT any network step.
///
/// The escape hatch for an identity that can no longer be removed through the normal flow
/// because its PDS account no longer exists — deleted from another device, purged
/// server-side, or migrated away. In every such case the deletion endpoints can only answer
/// with an opaque 401: the PDS deliberately does not expose account existence, so an unknown
/// DID and a wrong password are indistinguishable (see
/// `crates/pds/src/routes/delete_account.rs`). The request/confirm flow can therefore never
/// make progress, and without this the identity would be stranded in the wallet forever.
///
/// This wipes the DID's Keychain material and clears any pending-removal marker. It
/// deliberately does NOT tombstone the did:plc: the DID may already be retired, or (the
/// migrate-away case) the device key is no longer a rotation key and the identity now lives
/// on another PDS — so "forget locally" only promises to remove the identity from THIS
/// device. The frontend states that plainly and gates the call behind the biometric prompt.
///
/// Returns `was_last_identity` (mirroring `RemovalOutcome`) so the UI can route back to
/// onboarding rather than the identity list when the wallet is now empty.
#[tauri::command]
pub fn forget_identity_locally(did: String) -> Result<bool, RemovalError> {
    wipe_local(&IdentityStore, &did)?;
    clear_removal_pending_best_effort(&did);
    no_identities_remain()
}

/// Resolve the PDS base URL for `did`: the stored token record first, then live
/// discovery. Used only to address the body-authed `deleteAccount` endpoint.
async fn resolve_pds_url(pds_client: &PdsClient, did: &str) -> Result<String, RemovalError> {
    if let Ok(Some(record)) = IdentityStore.load_oauth_tokens(did) {
        if !record.pds_url.is_empty() {
            return Ok(record.pds_url);
        }
    }
    let (pds_url, _doc) =
        pds_client
            .discover_pds(did)
            .await
            .map_err(|e| RemovalError::NetworkError {
                message: format!("could not resolve the identity's PDS: {e}"),
            })?;
    Ok(pds_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn removal_error_serializes_screaming_snake_case() {
        let err = RemovalError::InvalidToken;
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(
            v.get("code").and_then(|c| c.as_str()),
            Some("INVALID_TOKEN")
        );

        let err = RemovalError::PlcDirectoryError {
            message: "rejected".to_string(),
        };
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(
            v.get("code").and_then(|c| c.as_str()),
            Some("PLC_DIRECTORY_ERROR")
        );
        assert_eq!(v.get("message").and_then(|m| m.as_str()), Some("rejected"));

        let err = RemovalError::SessionRequired {
            reason: UnlockReason::NoRefreshChain,
        };
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(
            v.get("code").and_then(|c| c.as_str()),
            Some("SESSION_REQUIRED")
        );
        // rename_all_fields = camelCase → the UnlockReason lands under `reason`.
        assert_eq!(
            v.get("reason").and_then(|r| r.as_str()),
            Some("NO_REFRESH_CHAIN")
        );
    }

    #[test]
    fn removal_outcome_serializes_camel_case() {
        let outcome = RemovalOutcome {
            tombstone_cid: "bafyfake".to_string(),
            was_last_identity: true,
        };
        let v = serde_json::to_value(&outcome).unwrap();
        assert_eq!(
            v.get("tombstoneCid").and_then(|c| c.as_str()),
            Some("bafyfake")
        );
        assert_eq!(
            v.get("wasLastIdentity").and_then(|b| b.as_bool()),
            Some(true)
        );
    }

    /// Ordering guarantee: the local wipe MUST NOT run when the tombstone submit fails
    /// (so the device key survives for a `tombstone_identity` retry).
    #[tokio::test]
    async fn wipe_is_skipped_when_submit_fails() {
        let wiped = Arc::new(AtomicBool::new(false));
        let w = wiped.clone();
        let result = submit_then_wipe(
            async {
                Err(RemovalError::PlcDirectoryError {
                    message: "boom".to_string(),
                })
            },
            move || {
                w.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(RemovalError::PlcDirectoryError { .. })
        ));
        assert!(
            !wiped.load(Ordering::SeqCst),
            "local wipe must not run after a failed tombstone submit"
        );
    }

    /// Conversely, the wipe runs exactly once after a successful submit.
    #[tokio::test]
    async fn wipe_runs_after_successful_submit() {
        let wiped = Arc::new(AtomicBool::new(false));
        let w = wiped.clone();
        let result = submit_then_wipe(async { Ok(()) }, move || {
            w.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;

        assert!(result.is_ok());
        assert!(
            wiped.load(Ordering::SeqCst),
            "local wipe must run after a successful tombstone submit"
        );
    }

    /// A 401 from deleteAccount (wrong password) and a 400 INVALID_TOKEN (bad/expired
    /// code) both surface as `InvalidToken`, so the UI re-prompts identically.
    #[test]
    fn delete_account_credential_failures_map_to_invalid_token() {
        assert!(matches!(
            map_delete_account_error(PdsClientError::Unauthorized {
                error: Some("InvalidToken".to_string()),
                message: "bad password".to_string(),
            }),
            RemovalError::InvalidToken
        ));
        assert!(matches!(
            map_delete_account_error(PdsClientError::XrpcError {
                status: 400,
                error: Some("InvalidToken".to_string()),
                message: "expired".to_string(),
            }),
            RemovalError::InvalidToken
        ));
        // A non-credential XRPC failure is distinct.
        assert!(matches!(
            map_delete_account_error(PdsClientError::XrpcError {
                status: 500,
                error: Some("InternalError".to_string()),
                message: "oops".to_string(),
            }),
            RemovalError::AccountDeleteFailed { .. }
        ));
    }

    // ── Pending-removal marker lifecycle ──────────────────────────────────────
    //
    // The marker is the post-delete recovery hook: `deleteAccount` succeeding but the
    // tombstone/wipe not finishing must leave a durable, resumable trace.

    #[test]
    fn pending_removal_marker_round_trip() {
        crate::keychain::clear_for_test();
        assert!(load_pending_removals().is_empty());

        mark_removal_pending("did:plc:alice").unwrap();
        assert_eq!(load_pending_removals(), vec!["did:plc:alice".to_string()]);

        // Idempotent: marking the same DID twice does not duplicate it.
        mark_removal_pending("did:plc:alice").unwrap();
        assert_eq!(load_pending_removals(), vec!["did:plc:alice".to_string()]);

        mark_removal_pending("did:plc:bob").unwrap();
        assert_eq!(
            load_pending_removals(),
            vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()]
        );

        clear_removal_pending("did:plc:alice").unwrap();
        assert_eq!(load_pending_removals(), vec!["did:plc:bob".to_string()]);

        // Clearing the last DID empties the set (and removes the backing entry).
        clear_removal_pending("did:plc:bob").unwrap();
        assert!(load_pending_removals().is_empty());
    }

    #[test]
    fn clearing_absent_marker_is_a_noop() {
        crate::keychain::clear_for_test();
        // Never marked — clearing must not error and must leave the set empty.
        clear_removal_pending("did:plc:ghost").unwrap();
        assert!(load_pending_removals().is_empty());
        clear_removal_pending_best_effort("did:plc:ghost");
        assert!(load_pending_removals().is_empty());
    }

    #[test]
    fn corrupt_marker_entry_reads_as_empty() {
        crate::keychain::clear_for_test();
        // A non-JSON blob must never surface as an error — the marker is a best-effort
        // safety net, and `list_pending_removals` is called unconditionally on launch.
        crate::keychain::store_item(PENDING_REMOVALS_ACCOUNT, b"not json").unwrap();
        assert!(load_pending_removals().is_empty());
    }

    // ── Local-only "forget" escape hatch ──────────────────────────────────────
    //
    // For an identity whose PDS account no longer exists (deleted elsewhere / migrated
    // away), `forget_identity_locally` must wipe local state with no network step and
    // clear any stale pending-removal marker.

    #[test]
    fn forget_identity_locally_wipes_and_clears_marker() {
        crate::keychain::clear_for_test();
        let store = IdentityStore;
        store.add_identity("did:plc:gone").unwrap();
        assert_eq!(
            store.list_identities().unwrap(),
            vec!["did:plc:gone".to_string()]
        );
        // A stale marker from an interrupted prior attempt must be cleared too.
        mark_removal_pending("did:plc:gone").unwrap();

        let was_last = forget_identity_locally("did:plc:gone".to_string()).unwrap();

        assert!(
            was_last,
            "forgetting the only identity reports wasLast=true"
        );
        assert!(
            store.list_identities().unwrap().is_empty(),
            "the identity is gone from the managed set"
        );
        assert!(
            load_pending_removals().is_empty(),
            "the pending-removal marker was cleared"
        );
    }

    #[test]
    fn forget_identity_locally_is_idempotent_for_unknown_did() {
        crate::keychain::clear_for_test();
        // Never registered — a wipe of a not-found identity is success, not an error, so a
        // second "forget" (or one against a DID some other path already removed) never wedges.
        let was_last = forget_identity_locally("did:plc:never".to_string()).unwrap();
        assert!(was_last, "an empty wallet reports wasLast=true");
    }

    #[test]
    fn forget_identity_locally_reports_not_last_when_others_remain() {
        crate::keychain::clear_for_test();
        let store = IdentityStore;
        store.add_identity("did:plc:gone").unwrap();
        store.add_identity("did:plc:keep").unwrap();

        let was_last = forget_identity_locally("did:plc:gone".to_string()).unwrap();

        assert!(!was_last, "another identity remains, so not the last");
        assert_eq!(
            store.list_identities().unwrap(),
            vec!["did:plc:keep".to_string()]
        );
    }
}
