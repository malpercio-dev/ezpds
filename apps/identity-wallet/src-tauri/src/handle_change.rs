// pattern: Mixed (Functional Core guard/parsers/classifiers; Imperative Shell command)
//
// Functional Core: the strict alsoKnownAs-only guard, current-state extraction from
//                  the audit log, the new-alsoKnownAs computation, and the
//                  updateHandle-failure classifier (all pure).
// Imperative Shell: change_handle / build_handle_op / submit_handle_op (network +
//                   Keychain + signing) and their Tauri command wrappers.
//
// This is the sovereign "change handle" flow for a wallet-custodied did:plc identity.
// On a reference PDS, changing a handle is one call because the PDS custodies the
// rotation key and rewrites the PLC doc itself. In our sovereign model the
// alsoKnownAs op is DEVICE-KEY-SIGNED, like the migration identity leg — but the two
// existing wallet guards both forbid it:
//   * migrate::guard_migration_op REQUIRES alsoKnownAs preserved (its invariant 4);
//   * the claim guard forbids all mutation except inserting the device key.
// So this module is a THIRD allowlist, the mirror image of migration's: alsoKnownAs
// MAY change; rotationKeys, verificationMethods, and services must NOT.
//
// The flow is fully passwordless end to end (sovereign login + the per-DID session
// provider supply the full-access session; the biometric gate lives in the frontend,
// in front of the Secure-Enclave signing):
//   1. Resolve a full-access session for the DID via SessionProvider.
//   2. `com.atproto.identity.updateHandle` on the hosting PDS — the PDS arbitrates
//      served-domain allocation / uniqueness / reserved names (this half cannot be
//      removed; its auth is the device key, transitively).
//   3. Build + device-key-sign the alsoKnownAs PLC op (strict guard) and POST it to
//      plc.directory.
//   4. Refresh the cached PLC log + DID document so the home card updates.
//
// Ordering: updateHandle FIRST (PDS-side validation/uniqueness), the PLC op SECOND. A
// failure between the two leaves handle resolution ahead of the DID doc, which
// self-heals on retry: build_handle_op re-reads the audit log every attempt, and if
// the op already landed (a prior attempt whose HTTP response was lost) the desired
// alsoKnownAs is already current, so the flow reconciles to success instead of
// re-POSTing a stale op.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::claim::ClaimResult;
use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::pds_client::PdsClient;
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};
use crypto::{AuditEntry, PlcService};

/// The atproto handle URI scheme prefix inside a PLC operation's `alsoKnownAs` array.
const HANDLE_AKA_PREFIX: &str = "at://";

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the sovereign change-handle flow.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling
/// wallet error enums (`MigrateError`, `RecoveryError`, `SessionError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum HandleChangeError {
    /// The wallet holds no authorized key in the DID's current rotationKeys, so it
    /// cannot self-sign the alsoKnownAs op.
    #[error("wallet is not authorized to self-sign for this DID (no device key in current rotationKeys)")]
    WalletNotAuthorized,
    /// The identity's session could not be resolved without a passwordless unlock —
    /// the frontend should run the biometric sovereign login and retry.
    #[error("identity is locked and needs a passwordless unlock")]
    SessionLocked { reason: UnlockReason },
    /// The hosting PDS or plc.directory rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The requested handle is already taken / not available on the hosting PDS.
    #[error("handle is not available")]
    HandleNotAvailable { message: String },
    /// The requested handle is syntactically invalid or not a served domain.
    #[error("handle is invalid: {message}")]
    InvalidHandle { message: String },
    /// `updateHandle` failed for a reason the wallet does not model specifically.
    #[error("updateHandle failed (HTTP {status}): {message}")]
    UpdateHandleFailed { status: u16, message: String },
    /// The strict pre-sign allowlist rejected the proposed operation.
    #[error("handle-change operation rejected by pre-sign guard: {reason}")]
    GuardRejected { reason: String },
    /// The audit log could not be parsed or contained no usable current state.
    #[error("invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    /// Local signing failed.
    #[error("signing failed: {message}")]
    SigningFailed { message: String },
    /// plc.directory rejected the submitted operation.
    #[error("PLC directory error: {message}")]
    PlcDirectoryError { message: String },
    /// A network / transport call failed.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The DID's device key or identity record could not be found.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
}

/// Map a session-lifecycle failure into the change-handle surface. A needed unlock
/// stays a distinct, actionable signal; a rate limit is preserved; everything else
/// degrades to a transport error the frontend can retry.
fn map_session_error(error: SessionError) -> HandleChangeError {
    match error {
        SessionError::NeedsUnlock { reason } => HandleChangeError::SessionLocked { reason },
        SessionError::RateLimited { retry_after } => HandleChangeError::RateLimited { retry_after },
        SessionError::IdentityNotFound => HandleChangeError::IdentityNotFound {
            message: "identity not found".to_string(),
        },
        SessionError::Offline { message } => HandleChangeError::NetworkError { message },
        other => HandleChangeError::NetworkError {
            message: other.to_string(),
        },
    }
}

// ── Pure inputs to the guard ─────────────────────────────────────────────────

/// The facts the strict pre-sign guard needs to decide whether a proposed handle
/// change is safe to sign. Flattened to plain values so the guard is a pure,
/// trivially-testable function (mirrors `migrate::MigrationInputs`).
#[derive(Debug, Clone)]
pub struct HandleChangeInputs {
    /// The wallet's per-DID device key (`did:key:z...`). Must be in the current set.
    pub device_key_id: String,
    /// The DID's CURRENT rotation keys (from the latest audit-log op).
    pub current_rotation_keys: Vec<String>,
    /// The rotation keys we intend to put in the op — must EQUAL the current set.
    pub proposed_rotation_keys: Vec<String>,
    /// The DID's CURRENT verificationMethods — must be preserved unchanged.
    pub current_verification_methods: BTreeMap<String, String>,
    /// The verificationMethods we intend to put in the op — must EQUAL the current.
    pub proposed_verification_methods: BTreeMap<String, String>,
    /// The DID's CURRENT services — must be preserved unchanged.
    pub current_services: BTreeMap<String, PlcService>,
    /// The services we intend to put in the op — must EQUAL the current.
    pub proposed_services: BTreeMap<String, PlcService>,
    /// The alsoKnownAs we intend to put in the op (the ONLY field allowed to change).
    pub proposed_also_known_as: Vec<String>,
}

// ── The strict pre-sign guard (STRICT ALLOWLIST) ─────────────────────────────

/// Reject the proposed handle-change operation unless it satisfies the strict
/// allowlist. This is the security core of the sovereign change-handle flow: the
/// device key can technically sign anything, so safety comes entirely from validating
/// the INPUTS before a signature is produced.
///
/// It is the mirror image of `migrate::guard_migration_op`. A migration MUST rewrite
/// services / rotationKeys[1] / verificationMethods and MUST preserve alsoKnownAs; a
/// handle change is the inverse — alsoKnownAs MAY change, but nothing else may.
///
/// Return `Ok(())` if every rule holds. Otherwise the most specific error:
/// - `WalletNotAuthorized` when the device key is not among `current_rotation_keys`.
/// - `GuardRejected { reason }` for any other violation.
///
/// Rules:
///  1. Authorization: `device_key_id` is present in `current_rotation_keys`.
///  2. Rotation keys unchanged: `proposed_rotation_keys` equals `current_rotation_keys`.
///  3. Verification methods unchanged: `proposed_verification_methods` equals current.
///  4. Services unchanged: `proposed_services` equals `current_services`.
///  5. Non-empty handle: `proposed_also_known_as` is not empty (a change-handle op
///     must never erase the handle set).
pub fn guard_handle_change(inputs: &HandleChangeInputs) -> Result<(), HandleChangeError> {
    // Rule 1 (authorization): the wallet must currently hold an authorized key for
    // this DID, or it cannot self-sign. Checked first so the distinct
    // `WalletNotAuthorized` signal wins over any proposed-op quibble.
    if !inputs.current_rotation_keys.contains(&inputs.device_key_id) {
        return Err(HandleChangeError::WalletNotAuthorized);
    }

    // Rule 2 (rotation keys unchanged): a handle change must not touch custody.
    if inputs.proposed_rotation_keys != inputs.current_rotation_keys {
        return Err(HandleChangeError::GuardRejected {
            reason: "rotationKeys must be preserved across a handle change".to_string(),
        });
    }

    // Rule 3 (verification methods unchanged): the repo signing key must not move.
    if inputs.proposed_verification_methods != inputs.current_verification_methods {
        return Err(HandleChangeError::GuardRejected {
            reason: "verificationMethods must be preserved across a handle change".to_string(),
        });
    }

    // Rule 4 (services unchanged): the atproto_pds endpoint must not move.
    if inputs.proposed_services != inputs.current_services {
        return Err(HandleChangeError::GuardRejected {
            reason: "services must be preserved across a handle change".to_string(),
        });
    }

    // Rule 5 (non-empty handle): never sign a handle-erasing op.
    if inputs.proposed_also_known_as.is_empty() {
        return Err(HandleChangeError::GuardRejected {
            reason: "alsoKnownAs must not be empty".to_string(),
        });
    }

    Ok(())
}

// ── Current-state extraction from the audit log ──────────────────────────────

/// The full current DID state a handle change needs, derived from the latest
/// non-nullified audit-log operation. Unlike `migrate::CurrentState`, this carries the
/// complete `verificationMethods` and `services` maps, because the handle op must
/// re-sign them BYTE-FOR-BYTE unchanged (and the guard proves it did).
#[derive(Debug, Clone)]
pub(crate) struct CurrentHandleState {
    /// CID of the latest op — becomes the new op's `prev`.
    pub prev_cid: String,
    /// Current rotation keys (preserved; also the authorization set).
    pub rotation_keys: Vec<String>,
    /// Current verificationMethods (preserved).
    pub verification_methods: BTreeMap<String, String>,
    /// Current alsoKnownAs (the field being replaced).
    pub also_known_as: Vec<String>,
    /// Current services (preserved).
    pub services: BTreeMap<String, PlcService>,
}

/// Read the complete resulting DID state from the latest non-nullified audit-log
/// entry. A PLC operation's JSON encodes the DID's state AFTER it is applied, so the
/// newest entry's `operation` object is the current state. Every field is parsed
/// strictly — a malformed or missing required field is an error, never a silently
/// truncated value that would be re-signed.
pub(crate) fn latest_full_state(
    audit_log: &[AuditEntry],
) -> Result<CurrentHandleState, HandleChangeError> {
    let latest = audit_log
        .iter()
        .rev()
        .find(|e| !e.nullified)
        .ok_or_else(|| HandleChangeError::InvalidAuditLog {
            message: "audit log is empty or fully nullified".to_string(),
        })?;

    let op = &latest.operation;

    let rotation_keys = string_array_field(op, "rotationKeys")?;
    if rotation_keys.is_empty() {
        return Err(HandleChangeError::InvalidAuditLog {
            message: "operation.rotationKeys is empty".to_string(),
        });
    }
    // A missing alsoKnownAs must NOT coerce to []: that would let the build "preserve"
    // an empty handle set and the guard's non-empty rule would be the only backstop.
    let also_known_as = string_array_field(op, "alsoKnownAs")?;
    let verification_methods = string_map_field(op, "verificationMethods")?;
    let services = services_field(op)?;

    Ok(CurrentHandleState {
        prev_cid: latest.cid.clone(),
        rotation_keys,
        verification_methods,
        also_known_as,
        services,
    })
}

/// Parse a required string-array field, rejecting a missing field, a non-array value,
/// or any non-string element.
fn string_array_field(
    op: &serde_json::Value,
    field: &str,
) -> Result<Vec<String>, HandleChangeError> {
    let arr = op.get(field).and_then(|v| v.as_array()).ok_or_else(|| {
        HandleChangeError::InvalidAuditLog {
            message: format!("operation.{field} is missing or not an array"),
        }
    })?;
    arr.iter()
        .enumerate()
        .map(|(idx, value)| {
            value
                .as_str()
                .map(String::from)
                .ok_or_else(|| HandleChangeError::InvalidAuditLog {
                    message: format!("operation.{field}[{idx}] is not a string"),
                })
        })
        .collect()
}

/// Parse a required `{ name: "did:key:..." }` object field into a `BTreeMap`,
/// rejecting a missing field, a non-object value, or any non-string value.
fn string_map_field(
    op: &serde_json::Value,
    field: &str,
) -> Result<BTreeMap<String, String>, HandleChangeError> {
    let obj = op.get(field).and_then(|v| v.as_object()).ok_or_else(|| {
        HandleChangeError::InvalidAuditLog {
            message: format!("operation.{field} is missing or not an object"),
        }
    })?;
    let mut map = BTreeMap::new();
    for (name, value) in obj {
        let key = value
            .as_str()
            .ok_or_else(|| HandleChangeError::InvalidAuditLog {
                message: format!("operation.{field}.{name} is not a string"),
            })?;
        map.insert(name.clone(), key.to_string());
    }
    Ok(map)
}

/// Parse the required `services` map (`{ id: { type, endpoint } }`) into a typed map,
/// rejecting a missing field, a non-object value, or a malformed entry.
fn services_field(
    op: &serde_json::Value,
) -> Result<BTreeMap<String, PlcService>, HandleChangeError> {
    let obj = op
        .get("services")
        .and_then(|v| v.as_object())
        .ok_or_else(|| HandleChangeError::InvalidAuditLog {
            message: "operation.services is missing or not an object".to_string(),
        })?;
    let mut map = BTreeMap::new();
    for (id, svc) in obj {
        let service_type = svc.get("type").and_then(|t| t.as_str()).ok_or_else(|| {
            HandleChangeError::InvalidAuditLog {
                message: format!("operation.services.{id} is missing a string 'type'"),
            }
        })?;
        let endpoint = svc
            .get("endpoint")
            .and_then(|e| e.as_str())
            .ok_or_else(|| HandleChangeError::InvalidAuditLog {
                message: format!("operation.services.{id} is missing a string 'endpoint'"),
            })?;
        map.insert(
            id.clone(),
            PlcService {
                service_type: service_type.to_string(),
                endpoint: endpoint.to_string(),
            },
        );
    }
    Ok(map)
}

// ── New alsoKnownAs computation ──────────────────────────────────────────────

/// Compute the new `alsoKnownAs` array for a handle change: the new `at://{handle}`
/// becomes the primary (first) handle, every prior `at://` handle is dropped, and any
/// non-handle aliases (e.g. a `did:web:` alias) are preserved after it. Pure.
pub(crate) fn compute_new_also_known_as(current: &[String], new_handle: &str) -> Vec<String> {
    let mut result = vec![format!("{HANDLE_AKA_PREFIX}{new_handle}")];
    for alias in current {
        // Drop every existing at:// handle (there is exactly one primary now); keep
        // any non-handle alias exactly as it was.
        if !alias.starts_with(HANDLE_AKA_PREFIX) {
            result.push(alias.clone());
        }
    }
    result
}

// ── updateHandle failure classification ──────────────────────────────────────

/// Classify a non-success `com.atproto.identity.updateHandle` response by HTTP status
/// and the atproto error envelope's `error` code. Pure, so the mapping is testable
/// without a live PDS.
pub(crate) fn classify_update_handle_error(
    status: u16,
    error_code: Option<&str>,
    message: String,
    retry_after: Option<String>,
) -> HandleChangeError {
    match status {
        429 => HandleChangeError::RateLimited { retry_after },
        // A 400 is either "taken / reserved" (HandleNotAvailable) or "malformed"
        // (InvalidHandle / anything else the PDS reports as a bad request).
        400 => match error_code {
            Some("HandleNotAvailable") => HandleChangeError::HandleNotAvailable { message },
            _ => HandleChangeError::InvalidHandle { message },
        },
        // 401/403/5xx and anything else: a reason the wallet does not model specially.
        _ => HandleChangeError::UpdateHandleFailed { status, message },
    }
}

// ── A built, signed handle op ────────────────────────────────────────────────

/// A locally-built, device-key-signed alsoKnownAs operation ready to submit.
struct SignedHandleOp {
    /// The signed PLC operation JSON, ready to POST to plc.directory.
    signed_op: serde_json::Value,
    /// CID the op will carry once it lands — the reconciliation key.
    op_cid: String,
}

// ── Imperative shell: build + submit + full flow ─────────────────────────────

/// Build and locally device-key-sign the alsoKnownAs PLC operation.
///
/// Fetches the DID's audit log (for `prev` + current state), replaces the handle in
/// `alsoKnownAs`, runs the strict pre-sign guard (which proves ONLY alsoKnownAs
/// changed), and signs with the per-DID device key. Returns `Ok(None)` when the DID
/// already carries the requested handle — the caller reconciles that to success
/// (idempotent: a prior attempt's op landed, or the user re-requested their handle).
async fn build_handle_op(
    pds_client: &PdsClient,
    did: &str,
    new_handle: &str,
) -> Result<Option<SignedHandleOp>, HandleChangeError> {
    let store = IdentityStore;

    // 1. Per-DID device key (rotationKeys[0] for a wallet-custodied identity).
    let device =
        store
            .get_or_create_device_key(did)
            .map_err(|e| HandleChangeError::IdentityNotFound {
                message: format!("failed to get device key: {e}"),
            })?;
    let device_key_id = device.key_id;

    // 2. Current audit log -> prev + full current state.
    let log_json =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| HandleChangeError::NetworkError {
                message: format!("failed to fetch audit log: {e}"),
            })?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| HandleChangeError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let current = latest_full_state(&audit_log)?;

    // 3. Compute the new alsoKnownAs. If it already matches the current state, the DID
    //    doc already carries this handle — nothing to sign.
    let proposed_also_known_as = compute_new_also_known_as(&current.also_known_as, new_handle);
    if proposed_also_known_as == current.also_known_as {
        return Ok(None);
    }

    // 4. Strict pre-sign guard — the security gate. Everything but alsoKnownAs is
    //    passed through as current==proposed, so the guard proves the op is a pure
    //    handle change.
    let inputs = HandleChangeInputs {
        device_key_id: device_key_id.clone(),
        current_rotation_keys: current.rotation_keys.clone(),
        proposed_rotation_keys: current.rotation_keys.clone(),
        current_verification_methods: current.verification_methods.clone(),
        proposed_verification_methods: current.verification_methods.clone(),
        current_services: current.services.clone(),
        proposed_services: current.services.clone(),
        proposed_also_known_as: proposed_also_known_as.clone(),
    };
    guard_handle_change(&inputs)?;

    // 5. Sign locally with the per-DID device key.
    let sign_closure = crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
        PerDidSignError::DeviceKeyNotFound { message } => {
            HandleChangeError::IdentityNotFound { message }
        }
        PerDidSignError::SigningSetupFailed { message } => {
            HandleChangeError::SigningFailed { message }
        }
    })?;
    let signed = crypto::build_did_plc_rotation_op(
        &current.prev_cid,
        current.rotation_keys.clone(),
        current.verification_methods.clone(),
        proposed_also_known_as,
        current.services.clone(),
        sign_closure,
    )
    .map_err(|e| HandleChangeError::SigningFailed {
        message: format!("failed to build rotation op: {e}"),
    })?;

    Ok(Some(SignedHandleOp {
        signed_op: serde_json::from_str(&signed.signed_op_json).map_err(|e| {
            HandleChangeError::SigningFailed {
                message: format!("failed to parse signed op JSON: {e}"),
            }
        })?,
        op_cid: signed.cid,
    }))
}

/// Submit the signed handle op to plc.directory, then refresh the local cache.
async fn submit_handle_op(
    pds_client: &PdsClient,
    did: &str,
    signed_op: &serde_json::Value,
) -> Result<ClaimResult, HandleChangeError> {
    pds_client
        .post_plc_operation(did, signed_op)
        .await
        .map_err(|e| HandleChangeError::PlcDirectoryError {
            message: format!("plc.directory rejected the operation: {e}"),
        })?;
    refresh_handle_cache(pds_client, did).await
}

/// Re-fetch the PLC audit log + DID document from plc.directory and cache them,
/// returning the equivalent `ClaimResult`. Caches the PLC *data* document (which
/// carries `rotationKeys`), not the W3C form — the home card's custody badge reads
/// `rotationKeys[0]`, so the W3C shape would degrade it to "Unknown".
async fn refresh_handle_cache(
    pds_client: &PdsClient,
    did: &str,
) -> Result<ClaimResult, HandleChangeError> {
    let store = IdentityStore;

    let updated_log =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| HandleChangeError::NetworkError {
                message: format!("failed to fetch updated audit log: {e}"),
            })?;
    store
        .store_plc_log(did, &updated_log)
        .map_err(|e| HandleChangeError::SigningFailed {
            message: format!("failed to cache updated PLC log: {e}"),
        })?;

    let did_doc = pds_client.fetch_plc_data_document(did).await.map_err(|e| {
        HandleChangeError::NetworkError {
            message: format!("failed to fetch DID document: {e}"),
        }
    })?;
    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(|e| HandleChangeError::SigningFailed {
            message: format!("failed to cache updated DID document: {e}"),
        })?;

    Ok(ClaimResult {
        updated_did_doc: did_doc,
    })
}

/// Call `com.atproto.identity.updateHandle` on the hosting PDS with the full-access
/// session. The PDS arbitrates served-domain allocation, uniqueness, and reserved
/// names; a non-2xx is classified into a specific `HandleChangeError`.
async fn call_update_handle(
    session: &crate::oauth_client::OAuthClient,
    new_handle: &str,
) -> Result<(), HandleChangeError> {
    let response = session
        .post(
            "/xrpc/com.atproto.identity.updateHandle",
            &serde_json::json!({ "handle": new_handle }),
        )
        .await
        .map_err(|e| HandleChangeError::NetworkError {
            message: format!("updateHandle request failed: {e}"),
        })?;

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }

    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    // Read the atproto error envelope `{ error, message }` best-effort.
    let body = response.text().await.unwrap_or_default();
    let envelope: Option<serde_json::Value> = serde_json::from_str(&body).ok();
    let error_code = envelope
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let message = envelope
        .as_ref()
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| {
            if body.is_empty() {
                format!("updateHandle returned HTTP {}", status.as_u16())
            } else {
                body.clone()
            }
        });

    Err(classify_update_handle_error(
        status.as_u16(),
        error_code.as_deref(),
        message,
        retry_after,
    ))
}

/// Drive the full sovereign change-handle flow for a wallet-custodied did:plc.
///
/// 1. Resolve a full-access session for the DID (the per-DID session provider — restore / refresh,
///    or `SessionLocked` if a passwordless unlock is needed first).
/// 2. `updateHandle` on the hosting PDS (validates + allocates the served domain).
/// 3. Build + device-key-sign the alsoKnownAs PLC op and POST it to plc.directory.
/// 4. Refresh the cached PLC log + DID doc.
///
/// If the built op reveals the DID already carries the requested handle (a prior
/// attempt's op landed but its response was lost, or the user re-requested their own
/// handle), the flow reconciles to success by refreshing the cache instead of
/// re-POSTing a stale op.
pub async fn change_handle(
    pds_client: &PdsClient,
    did: &str,
    new_handle: &str,
) -> Result<ClaimResult, HandleChangeError> {
    let now = crate::sovereign_session::unix_timestamp().map_err(|_| {
        HandleChangeError::SigningFailed {
            message: "system clock is unavailable".to_string(),
        }
    })?;

    // 1. Full-access session (the per-DID session-provider seam). NEEDS_UNLOCK surfaces distinctly so
    //    the frontend can run the biometric sovereign login and retry.
    let session = SessionProvider
        .full_access_client(pds_client, &IdentityStore, did, now)
        .await
        .map_err(map_session_error)?;

    // 2. updateHandle first — PDS-side validation/uniqueness. Idempotent on retry
    //    (setting the same handle again is a no-op the PDS accepts).
    call_update_handle(&session.client, new_handle).await?;

    // 3 + 4. Build + sign the alsoKnownAs op, then submit + refresh. A `None` build
    //    means the DID doc already carries this handle — reconcile to success.
    match build_handle_op(pds_client, did, new_handle).await? {
        Some(signed) => {
            tracing::info!(did = %did, op_cid = %signed.op_cid, "submitting alsoKnownAs handle op");
            submit_handle_op(pds_client, did, &signed.signed_op).await
        }
        None => {
            tracing::info!(did = %did, "handle already current in DID doc; reconciling cache");
            refresh_handle_cache(pds_client, did).await
        }
    }
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: change the handle of a wallet-custodied did:plc identity.
///
/// Passwordless end to end. The frontend gates this call behind
/// `authenticateBiometric()` (the Secure-Enclave owner-proof for the PLC signing) and,
/// on a `SESSION_LOCKED` result, runs `sovereignLogin(did)` before retrying.
#[tauri::command]
pub async fn change_handle_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    handle: String,
) -> Result<ClaimResult, HandleChangeError> {
    change_handle(state.pds_client(), &did, &handle).await
}

/// Tauri command: list the served handle domains offered by the DID's HOSTING PDS
/// (`describeServer.availableUserDomains`). Unlike the create flow's
/// `get_available_user_domains` (which queries the single configured Custos), this
/// discovers the identity's actual host, so a claimed/migrated DID gets the right
/// domain list.
#[tauri::command]
pub async fn get_identity_handle_domains(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<Vec<String>, HandleChangeError> {
    let (pds_url, _doc) = state.pds_client().discover_pds(&did).await.map_err(|e| {
        HandleChangeError::NetworkError {
            message: format!("failed to discover hosting PDS: {e}"),
        }
    })?;
    let description = state
        .pds_client()
        .describe_server(&pds_url)
        .await
        .map_err(|e| HandleChangeError::NetworkError {
            message: format!("describeServer failed: {e}"),
        })?;
    Ok(description.available_user_domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "did:key:zDEVICE";
    const PDS: &str = "did:key:zPDS";
    const SIGN: &str = "did:key:zSIGN";
    const OLD_HANDLE: &str = "at://alice.old.example";
    const NEW_HANDLE: &str = "bob.new.example";

    fn vms() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("atproto".to_string(), SIGN.to_string());
        m
    }

    fn services() -> BTreeMap<String, PlcService> {
        let mut m = BTreeMap::new();
        m.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example".to_string(),
            },
        );
        m
    }

    /// A well-formed handle change: only alsoKnownAs differs, device key authorized.
    fn ok_inputs() -> HandleChangeInputs {
        HandleChangeInputs {
            device_key_id: DEVICE.to_string(),
            current_rotation_keys: vec![DEVICE.to_string(), PDS.to_string()],
            proposed_rotation_keys: vec![DEVICE.to_string(), PDS.to_string()],
            current_verification_methods: vms(),
            proposed_verification_methods: vms(),
            current_services: services(),
            proposed_services: services(),
            proposed_also_known_as: vec![format!("at://{NEW_HANDLE}")],
        }
    }

    // ── Guard ────────────────────────────────────────────────────────────────

    #[test]
    fn guard_accepts_a_well_formed_handle_change() {
        assert!(guard_handle_change(&ok_inputs()).is_ok());
    }

    #[test]
    fn guard_rejects_when_wallet_holds_no_current_key() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![PDS.to_string()];
        // proposed must equal current for the other rules; make them match so the
        // authorization rule is what fires.
        inputs.proposed_rotation_keys = vec![PDS.to_string()];
        assert!(matches!(
            guard_handle_change(&inputs),
            Err(HandleChangeError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_a_rotation_key_change() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_rotation_keys
            .push("did:key:zEVIL".to_string());
        assert!(matches!(
            guard_handle_change(&inputs),
            Err(HandleChangeError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_verification_method_change() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_verification_methods
            .insert("atproto".to_string(), "did:key:zEVIL".to_string());
        assert!(matches!(
            guard_handle_change(&inputs),
            Err(HandleChangeError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_service_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://evil.example".to_string(),
            },
        );
        assert!(matches!(
            guard_handle_change(&inputs),
            Err(HandleChangeError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_an_empty_also_known_as() {
        let mut inputs = ok_inputs();
        inputs.proposed_also_known_as = vec![];
        assert!(matches!(
            guard_handle_change(&inputs),
            Err(HandleChangeError::GuardRejected { .. })
        ));
    }

    // ── compute_new_also_known_as ──────────────────────────────────────────────

    #[test]
    fn new_aka_replaces_the_primary_handle() {
        let current = vec![OLD_HANDLE.to_string()];
        let result = compute_new_also_known_as(&current, NEW_HANDLE);
        assert_eq!(result, vec![format!("at://{NEW_HANDLE}")]);
    }

    #[test]
    fn new_aka_preserves_non_handle_aliases() {
        let current = vec![OLD_HANDLE.to_string(), "did:web:alice.example".to_string()];
        let result = compute_new_also_known_as(&current, NEW_HANDLE);
        assert_eq!(
            result,
            vec![
                format!("at://{NEW_HANDLE}"),
                "did:web:alice.example".to_string()
            ]
        );
    }

    #[test]
    fn new_aka_drops_every_prior_handle() {
        let current = vec![
            "at://alice.one.example".to_string(),
            "at://alice.two.example".to_string(),
        ];
        let result = compute_new_also_known_as(&current, NEW_HANDLE);
        assert_eq!(result, vec![format!("at://{NEW_HANDLE}")]);
    }

    #[test]
    fn new_aka_equals_current_when_handle_unchanged() {
        // Re-requesting the existing handle yields an identical array, which the build
        // path treats as "already current" (idempotent reconcile).
        let current = vec![format!("at://{NEW_HANDLE}")];
        let result = compute_new_also_known_as(&current, NEW_HANDLE);
        assert_eq!(result, current);
    }

    // ── latest_full_state ──────────────────────────────────────────────────────

    fn audit_entry(cid: &str, nullified: bool, operation: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "did": "did:plc:test",
            "cid": cid,
            "createdAt": "2026-07-14T00:00:00Z",
            "nullified": nullified,
            "operation": operation
        })
    }

    fn full_op(aka: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "type": "plc_operation",
            "rotationKeys": [DEVICE, PDS],
            "verificationMethods": { "atproto": SIGN },
            "alsoKnownAs": aka,
            "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example" } }
        })
    }

    #[test]
    fn latest_full_state_reads_newest_non_nullified_entry() {
        let log = serde_json::json!([
            audit_entry("bafy_old", false, full_op(serde_json::json!([OLD_HANDLE]))),
            audit_entry(
                "bafy_latest",
                false,
                full_op(serde_json::json!(["at://current.example"]))
            ),
            audit_entry(
                "bafy_null",
                true,
                full_op(serde_json::json!(["at://evil.example"]))
            ),
        ]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        let state = latest_full_state(&entries).expect("state");
        assert_eq!(state.prev_cid, "bafy_latest");
        assert_eq!(
            state.rotation_keys,
            vec![DEVICE.to_string(), PDS.to_string()]
        );
        assert_eq!(
            state.also_known_as,
            vec!["at://current.example".to_string()]
        );
        assert_eq!(state.verification_methods, vms());
        assert_eq!(state.services, services());
    }

    #[test]
    fn latest_full_state_rejects_missing_also_known_as() {
        let op = serde_json::json!({
            "rotationKeys": [DEVICE],
            "verificationMethods": { "atproto": SIGN },
            "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example" } }
        });
        let log = serde_json::json!([audit_entry("bafy_bad", false, op)]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        assert!(matches!(
            latest_full_state(&entries),
            Err(HandleChangeError::InvalidAuditLog { .. })
        ));
    }

    #[test]
    fn latest_full_state_rejects_missing_services() {
        let op = serde_json::json!({
            "rotationKeys": [DEVICE],
            "verificationMethods": { "atproto": SIGN },
            "alsoKnownAs": [OLD_HANDLE]
        });
        let log = serde_json::json!([audit_entry("bafy_bad", false, op)]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        assert!(matches!(
            latest_full_state(&entries),
            Err(HandleChangeError::InvalidAuditLog { .. })
        ));
    }

    #[test]
    fn latest_full_state_errors_on_empty_log() {
        assert!(matches!(
            latest_full_state(&[]),
            Err(HandleChangeError::InvalidAuditLog { .. })
        ));
    }

    // ── classify_update_handle_error ───────────────────────────────────────────

    #[test]
    fn classify_maps_handle_not_available() {
        let err = classify_update_handle_error(
            400,
            Some("HandleNotAvailable"),
            "taken".to_string(),
            None,
        );
        assert!(matches!(err, HandleChangeError::HandleNotAvailable { .. }));
    }

    #[test]
    fn classify_maps_invalid_handle() {
        let err = classify_update_handle_error(400, Some("InvalidHandle"), "bad".to_string(), None);
        assert!(matches!(err, HandleChangeError::InvalidHandle { .. }));
    }

    #[test]
    fn classify_maps_rate_limit_with_retry_after() {
        let err =
            classify_update_handle_error(429, None, "slow down".to_string(), Some("30".into()));
        assert!(matches!(
            err,
            HandleChangeError::RateLimited { retry_after: Some(v) } if v == "30"
        ));
    }

    #[test]
    fn classify_maps_other_status_to_update_handle_failed() {
        let err = classify_update_handle_error(500, None, "boom".to_string(), None);
        assert!(matches!(
            err,
            HandleChangeError::UpdateHandleFailed { status: 500, .. }
        ));
    }

    // ── Error serialization ────────────────────────────────────────────────────

    #[test]
    fn error_serializes_screaming_snake_case() {
        let json = serde_json::to_value(HandleChangeError::WalletNotAuthorized).expect("serialize");
        assert_eq!(
            json.get("code").and_then(|v| v.as_str()),
            Some("WALLET_NOT_AUTHORIZED")
        );
    }

    #[test]
    fn session_locked_carries_unlock_reason() {
        let json = serde_json::to_value(HandleChangeError::SessionLocked {
            reason: UnlockReason::NoRefreshChain,
        })
        .expect("serialize");
        assert_eq!(
            json.get("code").and_then(|v| v.as_str()),
            Some("SESSION_LOCKED")
        );
        assert_eq!(
            json.get("reason").and_then(|v| v.as_str()),
            Some("NO_REFRESH_CHAIN")
        );
    }
}
