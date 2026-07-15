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
        PdsClientError::XrpcError { status, .. } if status == 400 => RemovalError::InvalidToken,
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

    // 1. Fetch the current audit log and take the newest non-nullified op's CID as `prev`.
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
    let prev_cid = audit_log
        .iter()
        .rev()
        .find(|e| !e.nullified)
        .map(|e| e.cid.clone())
        .ok_or_else(|| RemovalError::InvalidAuditLog {
            message: "audit log has no non-nullified operation to chain onto".to_string(),
        })?;

    // 2. Obtain the per-DID device-key signing closure (rotationKeys[0]).
    let sign = crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
        PerDidSignError::DeviceKeyNotFound { message } => {
            RemovalError::IdentityNotFound { message }
        }
        PerDidSignError::SigningSetupFailed { message } => {
            RemovalError::TombstoneSigningFailed { message }
        }
    })?;

    // 3. Build + sign the tombstone.
    let tombstone = crypto::build_did_plc_tombstone_op(&prev_cid, sign).map_err(|e| {
        RemovalError::TombstoneSigningFailed {
            message: format!("failed to build tombstone: {e}"),
        }
    })?;

    // 3b. Cheap local self-check: a mis-signed op turns into a local error here rather
    //     than a plc.directory 4xx after the network round trip. The device key is the
    //     authorized signer (it is rotationKeys[0] of the head op).
    let device_pub =
        store
            .get_or_create_device_key(did)
            .map_err(|e| RemovalError::IdentityNotFound {
                message: format!("failed to load device key: {e}"),
            })?;
    let device_key_uri = crypto::DidKeyUri(device_pub.key_id.clone());
    crypto::verify_plc_tombstone_op(
        &tombstone.signed_op_json,
        std::slice::from_ref(&device_key_uri),
    )
    .map_err(|e| RemovalError::TombstoneSigningFailed {
        message: format!("tombstone self-verification failed: {e}"),
    })?;

    let op_value: serde_json::Value =
        serde_json::from_str(&tombstone.signed_op_json).map_err(|e| {
            RemovalError::TombstoneSigningFailed {
                message: format!("failed to parse signed tombstone JSON: {e}"),
            }
        })?;

    // 4. Submit to plc.directory, THEN (only on success) 5. wipe local material.
    let did_owned = did.to_string();
    submit_then_wipe(
        async {
            pds_client
                .post_plc_operation(&did_owned, &op_value)
                .await
                .map_err(|e| match e {
                    PdsClientError::RateLimited { retry_after, .. } => {
                        RemovalError::RateLimited { retry_after }
                    }
                    PdsClientError::NetworkError { message } => {
                        RemovalError::NetworkError { message }
                    }
                    other => RemovalError::PlcDirectoryError {
                        message: other.to_string(),
                    },
                })
        },
        || {
            // `remove_identity` is best-effort and idempotent; a missing managed-dids
            // entry (already removed by a prior partial run) is success, not failure.
            match store.remove_identity(&did_owned) {
                Ok(()) => Ok(()),
                Err(crate::identity_store::IdentityStoreError::IdentityNotFound) => Ok(()),
                Err(e) => Err(RemovalError::LocalWipeFailed {
                    message: format!("failed to wipe local identity material: {e}"),
                }),
            }
        },
    )
    .await?;

    Ok(tombstone.cid)
}

/// Compute the `RemovalOutcome` after a successful `tombstone_and_wipe`.
fn removal_outcome(tombstone_cid: String) -> Result<RemovalOutcome, RemovalError> {
    let was_last_identity = IdentityStore
        .list_identities()
        .map(|ids| ids.is_empty())
        .map_err(|e| RemovalError::LocalWipeFailed {
            message: format!("failed to re-read managed identities: {e}"),
        })?;
    Ok(RemovalOutcome {
        tombstone_cid,
        was_last_identity,
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

    // 2 + 3. Tombstone the did:plc, then wipe local material.
    let tombstone_cid = tombstone_and_wipe(state.pds_client(), &did).await?;
    removal_outcome(tombstone_cid)
}

/// Tauri command: resume a removal whose PDS account was already deleted.
///
/// Used when `confirm_identity_removal` deleted the account but the tombstone or wipe
/// failed: the single-use deletion token is already spent, so re-running `confirm`
/// would 401 at `deleteAccount`. This retries only the tombstone + wipe.
#[tauri::command]
pub async fn tombstone_identity(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<RemovalOutcome, RemovalError> {
    let tombstone_cid = tombstone_and_wipe(state.pds_client(), &did).await?;
    removal_outcome(tombstone_cid)
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
                error: "InvalidToken".to_string(),
                message: "expired".to_string(),
            }),
            RemovalError::InvalidToken
        ));
        // A non-credential XRPC failure is distinct.
        assert!(matches!(
            map_delete_account_error(PdsClientError::XrpcError {
                status: 500,
                error: "InternalError".to_string(),
                message: "oops".to_string(),
            }),
            RemovalError::AccountDeleteFailed { .. }
        ));
    }
}
