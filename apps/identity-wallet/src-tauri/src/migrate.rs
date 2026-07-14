// pattern: Mixed (Functional Core types + guard/converters; Imperative Shell commands)
//
// Functional Core: MigrationInputs, SignedMigrationOp, MigrateError, the strict
//                  pre-sign guard, the RecommendedCredentials -> typed-map
//                  converters, current-state extraction, and diff computation
//                  (all pure).
// Imperative Shell: build_migration_op / submit_migration_op (network + Keychain +
//                   signing) and their Tauri command wrappers.
//
// This is the wallet-authorized (self-signed) identity leg of account migration
// (ADR-0002, path 1). The DID-repointing PLC operation is built and signed LOCALLY
// with the per-DID device key and submitted directly to plc.directory — no email
// token, no signPlcOperation round-trip. It is applicable whenever the wallet holds
// an authorized key in the DID's current rotationKeys; otherwise it refuses and the
// migration orchestrator falls back to the PDS-signed interop path.
//
// Contrast with claim.rs: a claim must change NOTHING but insert the device key at
// rotationKeys[0], so its guard rejects every key/service mutation. A migration is
// the inverse — it MUST rewrite services.atproto_pds, rotationKeys[1], and
// verificationMethods.atproto to the destination's values. The one invariant that
// must survive is rotationKeys[0] == the wallet device key; that single fact is the
// entire "credible exit" guarantee (and any op the user did not initiate is caught
// by plc_monitor and reversible via recovery.rs).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::claim::{ChangeType, ClaimResult, OpDiff, ServiceChange};
use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::oauth_client::OAuthClient;
use crate::pds_client::{get_recommended_did_credentials, PdsClient, RecommendedCredentials};
use crypto::{AuditEntry, PlcService};

/// The atproto PDS service id in a PLC operation's `services` map.
const ATPROTO_PDS_SERVICE_ID: &str = "atproto_pds";
/// The atproto verification-method id in a PLC operation's `verificationMethods` map.
const ATPROTO_VERIFICATION_METHOD_ID: &str = "atproto";

// ── Output types ────────────────────────────────────────────────────────────

/// A migration identity-leg operation, built and signed locally, ready to submit.
///
/// Mirrors `SignedRecoveryOp` from `recovery.rs`: the `diff` drives the review /
/// biometric-approval UI, and `signed_op` is the JSON POSTed to plc.directory.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedMigrationOp {
    /// Human-readable diff of what the migration op changes (endpoint + key swap).
    pub diff: OpDiff,
    /// The signed PLC operation JSON, ready to POST to plc.directory.
    pub signed_op: serde_json::Value,
}

/// State for a pending migration, held between build and submit (mirrors
/// `RecoveryState`). The authenticated destination-PDS `OAuthClient` is populated by
/// the migration orchestrator after it drives the destination OAuth login — this
/// leg never logs in on its own.
pub struct MigrationState {
    /// The DID being migrated.
    pub did: String,
    /// Authenticated client for the DESTINATION PDS (used for getRecommendedDidCredentials).
    pub dest_oauth_client: std::sync::Arc<OAuthClient>,
    /// The signed PLC op, set by `build_migration_op_cmd`, consumed by submit.
    pub signed_op: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidWebMigrationDocument {
    pub document_text: String,
    pub device_key: String,
    pub repo_key: String,
    pub pds_endpoint: String,
}

fn multibase(key: &str) -> &str {
    key.strip_prefix("did:key:").unwrap_or(key)
}

fn did_web_url(did: &str) -> Result<String, MigrateError> {
    let host = did
        .strip_prefix("did:web:")
        .ok_or(MigrateError::GuardRejected {
            reason: "identity is not did:web".into(),
        })?;
    if host.contains(':') || host.contains('/') || host.is_empty() {
        return Err(MigrateError::GuardRejected {
            reason: "only hostname-form did:web identities are supported".into(),
        });
    }
    Ok(format!("https://{host}/.well-known/did.json"))
}

#[tauri::command]
pub async fn build_did_web_migration_document_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<DidWebMigrationDocument, MigrateError> {
    let dest_client = {
        let guard = state.migration_state.lock().await;
        let migration = guard
            .as_ref()
            .ok_or_else(|| MigrateError::IdentityNotFound {
                message: "no identity leg is armed".into(),
            })?;
        if migration.did != did || !did.starts_with("did:web:") {
            return Err(MigrateError::IdentityNotFound {
                message: "DID mismatch".into(),
            });
        }
        migration.dest_oauth_client.clone()
    };
    let (_, current) =
        state
            .pds_client()
            .discover_pds(&did)
            .await
            .map_err(|e| MigrateError::NetworkError {
                message: e.to_string(),
            })?;
    let recommended = get_recommended_did_credentials(&dest_client)
        .await
        .map_err(|e| MigrateError::NetworkError {
            message: e.to_string(),
        })?;
    let repo_key = recommended
        .verification_methods
        .as_ref()
        .and_then(|value| value.get(ATPROTO_VERIFICATION_METHOD_ID))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MigrateError::InvalidRecommendedCredentials {
            message: "missing verificationMethods.atproto".into(),
        })?
        .to_string();
    let pds_endpoint = recommended
        .services
        .as_ref()
        .and_then(|value| value.get(ATPROTO_PDS_SERVICE_ID))
        .and_then(|value| value.get("endpoint"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MigrateError::InvalidRecommendedCredentials {
            message: "missing services.atproto_pds.endpoint".into(),
        })?
        .to_string();
    let device = crate::device_key::get_or_create().map_err(|e| MigrateError::SigningFailed {
        message: e.to_string(),
    })?;

    let mut methods = Vec::new();
    if let Some(existing) = current.verification_methods.as_object() {
        for (name, value) in existing {
            if name != ATPROTO_VERIFICATION_METHOD_ID {
                if let Some(key) = value.as_str() {
                    methods.push(serde_json::json!({
                        "id": format!("{did}#{name}"), "type": "Multikey", "controller": did,
                        "publicKeyMultibase": multibase(key)
                    }));
                }
            }
        }
    }
    methods.retain(|method| {
        method.get("id").and_then(serde_json::Value::as_str) != Some(&format!("{did}#device"))
    });
    methods.push(serde_json::json!({"id": format!("{did}#device"), "type": "Multikey", "controller": did, "publicKeyMultibase": device.multibase}));
    methods.push(serde_json::json!({"id": format!("{did}#atproto"), "type": "Multikey", "controller": did, "publicKeyMultibase": multibase(&repo_key)}));
    let document = serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        // Domain migration must never let destination recommendations change the user's handle.
        "alsoKnownAs": current.also_known_as,
        "verificationMethod": methods,
        "service": [{"id": format!("{did}#atproto_pds"), "type": "AtprotoPersonalDataServer", "serviceEndpoint": pds_endpoint}],
    });
    let document_text = format!(
        "{}\n",
        serde_json::to_string_pretty(&document).map_err(|e| MigrateError::SigningFailed {
            message: e.to_string(),
        })?
    );
    Ok(DidWebMigrationDocument {
        document_text,
        device_key: format!("{did}#device"),
        repo_key: format!("{did}#atproto"),
        pds_endpoint,
    })
}

#[tauri::command]
pub async fn submit_did_web_migration_document_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    document_text: String,
    enable_managed_hosting: bool,
) -> Result<ClaimResult, MigrateError> {
    let dest_client = {
        let guard = state.migration_state.lock().await;
        let migration = guard
            .as_ref()
            .ok_or_else(|| MigrateError::IdentityNotFound {
                message: "no identity leg is armed".into(),
            })?;
        if migration.did != did {
            return Err(MigrateError::IdentityNotFound {
                message: "DID mismatch".into(),
            });
        }
        migration.dest_oauth_client.clone()
    };
    let live = state
        .pds_client()
        .client()
        .get(did_web_url(&did)?)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| MigrateError::NetworkError {
            message: e.to_string(),
        })?
        .text()
        .await
        .map_err(|e| MigrateError::NetworkError {
            message: e.to_string(),
        })?;
    if live.as_bytes() != document_text.as_bytes() {
        return Err(MigrateError::GuardRejected {
            reason: "published did.json does not match the reviewed bytes".into(),
        });
    }
    let refreshed = dest_client
        .post(
            "/xrpc/com.atproto.identity.refreshIdentity",
            &serde_json::json!({ "identifier": did }),
        )
        .await
        .map_err(|e| MigrateError::NetworkError {
            message: e.to_string(),
        })?;
    if !refreshed.status().is_success() {
        return Err(MigrateError::NetworkError {
            message: "destination did not accept the published document".into(),
        });
    }
    if enable_managed_hosting {
        let result = dest_client
            .post("/v1/did-web/hosting", &serde_json::json!({"enabled": true}))
            .await;
        match result {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::warn!(status = %response.status(), did = %did, "migration verified, but optional managed hosting was not enabled")
            }
            Err(error) => {
                tracing::warn!(error = %error, did = %did, "migration verified, but optional managed hosting was unreachable")
            }
        }
    }
    *state.migration_state.lock().await = None;
    let updated_did_doc: serde_json::Value =
        serde_json::from_str(&document_text).map_err(|e| MigrateError::GuardRejected {
            reason: format!("reviewed did.json is invalid: {e}"),
        })?;
    let store = IdentityStore;
    if let Err(e) = store.add_identity(&did) {
        if !matches!(
            e,
            crate::identity_store::IdentityStoreError::IdentityAlreadyExists
        ) {
            return Err(MigrateError::IdentityNotFound {
                message: e.to_string(),
            });
        }
    }
    store
        .adopt_global_device_key(&did)
        .map_err(|e| MigrateError::IdentityNotFound {
            message: e.to_string(),
        })?;
    store
        .store_did_doc(&did, &document_text)
        .map_err(|e| MigrateError::IdentityNotFound {
            message: e.to_string(),
        })?;
    Ok(ClaimResult { updated_did_doc })
}

/// Errors from the migration identity leg.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrateError {
    /// The wallet does not hold an authorized key in the DID's current rotationKeys,
    /// so it cannot self-sign. The orchestrator must fall back to the interop path.
    #[error("Wallet is not authorized to self-sign for this DID (no device key in current rotationKeys)")]
    WalletNotAuthorized,
    /// The strict pre-sign allowlist rejected the proposed operation.
    #[error("Migration operation rejected by pre-sign guard: {reason}")]
    GuardRejected { reason: String },
    /// The destination PDS's recommended credentials were missing or malformed.
    #[error("Invalid recommended credentials from destination PDS: {message}")]
    InvalidRecommendedCredentials { message: String },
    /// The audit log could not be parsed or contained no usable current state.
    #[error("Invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    /// Local signing failed.
    #[error("Signing failed: {message}")]
    SigningFailed { message: String },
    /// plc.directory rejected the submitted operation.
    #[error("PLC directory error: {message}")]
    PlcDirectoryError { message: String },
    /// A network call failed.
    #[error("Network error: {message}")]
    NetworkError { message: String },
    /// The DID's device key could not be found/created.
    #[error("Identity not found: {message}")]
    IdentityNotFound { message: String },
    /// No pending migration (build must run before submit), or DID mismatch.
    #[error("Migration not ready: {message}")]
    MigrationNotReady { message: String },
}

/// Which outbound-migration authorization path the wallet should use for a DID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPath {
    /// The wallet holds an authorized rotation key and can self-sign the PLC op.
    SelfSigned,
    /// The wallet does not hold an authorized rotation key; use the PDS-signed interop path.
    Interop,
    /// The wallet cannot safely choose a path (for example, plc.directory is unreachable).
    CannotDetermine,
}

/// Result of deciding which outbound-migration path applies to a DID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MigrationPathDecision {
    pub path: MigrationPath,
    /// The wallet's per-DID device key, when available.
    pub device_key_id: Option<String>,
    /// Index of the device key in the DID's current rotationKeys, if present.
    pub rotation_key_index: Option<usize>,
    /// Human-readable explanation for UI/orchestrator logging.
    pub reason: String,
}

// ── Pure inputs to the guard ─────────────────────────────────────────────────

/// The facts the strict pre-sign guard needs to decide whether a proposed migration
/// operation is safe to sign. Deliberately flattened to plain strings/vecs so the
/// guard is a pure, trivially testable function.
#[derive(Debug, Clone)]
pub struct MigrationInputs {
    /// The wallet's per-DID device key (`did:key:z...`). Must remain at rotationKeys[0].
    pub device_key_id: String,
    /// The DID's CURRENT rotation keys (from the latest audit-log op).
    pub current_rotation_keys: Vec<String>,
    /// The DID's CURRENT alsoKnownAs (handle URIs) — a migration must preserve these.
    pub current_also_known_as: Vec<String>,
    /// The rotation keys the DESTINATION PDS recommended — the allowlist for keys
    /// permitted beyond the device key at [0].
    pub recommended_rotation_keys: Vec<String>,
    /// The rotation keys we intend to put in the op (device key at [0] + recommended).
    pub proposed_rotation_keys: Vec<String>,
    /// The alsoKnownAs we intend to put in the op.
    pub proposed_also_known_as: Vec<String>,
    /// The service ids we intend to put in the op's `services` map.
    pub proposed_service_ids: Vec<String>,
}

// ── The strict pre-sign guard (STRICT ALLOWLIST) ─────────────────────────────

/// Reject the proposed migration operation unless it satisfies the strict allowlist.
///
/// This is the security core of the self-signed migration leg. The device key can
/// technically sign anything, so safety comes entirely from validating the INPUTS
/// before a signature is ever produced. The policy is a strict allowlist: the op must
/// make ONLY the changes a migration is supposed to make, and nothing else, or we
/// abort.
///
/// Return `Ok(())` if every rule holds. Otherwise return the most specific error:
/// - `MigrateError::WalletNotAuthorized` when the wallet holds no authorized key for
///   the DID (device key is not among `current_rotation_keys`) — the caller will
///   defer to the PDS-signed interop path.
/// - `MigrateError::GuardRejected { reason }` for any other violation, with a short
///   human-readable `reason`.
///
/// The rules the strict allowlist must enforce:
///  1. Sovereignty: `proposed_rotation_keys[0]` equals `device_key_id`.
///  2. Authorization: `device_key_id` is present in `current_rotation_keys`
///     (otherwise → `WalletNotAuthorized`).
///  3. Key allowlist: every proposed rotation key AFTER index 0 appears in
///     `recommended_rotation_keys` (no smuggled keys).
///  4. Handle preservation: `proposed_also_known_as` equals `current_also_known_as`.
///  5. Service allowlist: the proposed op touches ONLY the atproto PDS service —
///     `proposed_service_ids` is exactly `[ATPROTO_PDS_SERVICE_ID]`.
pub fn guard_migration_op(inputs: &MigrationInputs) -> Result<(), MigrateError> {
    // Rule 2 (authorization): the wallet must currently hold an authorized key for
    // this DID, or it cannot self-sign — the caller falls back to the interop path.
    // Checked first so the distinct `WalletNotAuthorized` signal wins over any
    // proposed-op quibble.
    if !inputs.current_rotation_keys.contains(&inputs.device_key_id) {
        return Err(MigrateError::WalletNotAuthorized);
    }

    // Rule 1 (sovereignty): the device key must remain at rotationKeys[0].
    if inputs.proposed_rotation_keys.first() != Some(&inputs.device_key_id) {
        return Err(MigrateError::GuardRejected {
            reason: format!(
                "device key must be rotationKeys[0]; found {:?}",
                inputs.proposed_rotation_keys.first()
            ),
        });
    }

    // Rule 3 (key allowlist): every proposed rotation key after [0] must be one the
    // destination recommended — no smuggled keys.
    for key in inputs.proposed_rotation_keys.iter().skip(1) {
        if !inputs.recommended_rotation_keys.contains(key) {
            return Err(MigrateError::GuardRejected {
                reason: format!("rotation key not recommended by destination: {key}"),
            });
        }
    }

    // Rule 4 (handle preservation): a migration must not alter alsoKnownAs.
    if inputs.proposed_also_known_as != inputs.current_also_known_as {
        return Err(MigrateError::GuardRejected {
            reason: "alsoKnownAs (handle) must be preserved across migration".to_string(),
        });
    }

    // Rule 5 (service allowlist): the op may touch only the atproto PDS service.
    if inputs.proposed_service_ids.len() != 1
        || inputs.proposed_service_ids.first().map(String::as_str) != Some(ATPROTO_PDS_SERVICE_ID)
    {
        return Err(MigrateError::GuardRejected {
            reason: format!(
                "migration may only set the '{ATPROTO_PDS_SERVICE_ID}' service; found {:?}",
                inputs.proposed_service_ids
            ),
        });
    }

    Ok(())
}

// ── Current-state extraction from the audit log ──────────────────────────────

/// The slice of current DID state the migration build needs, derived from the latest
/// non-nullified audit-log operation.
#[derive(Debug, Clone)]
pub(crate) struct CurrentState {
    /// CID of the latest op — becomes the new op's `prev`.
    pub prev_cid: String,
    /// Current rotation keys (for authorization + diff).
    pub rotation_keys: Vec<String>,
    /// Current alsoKnownAs (preserved into the new op).
    pub also_known_as: Vec<String>,
    /// Current atproto_pds endpoint, if present (for the diff's `old_endpoint`).
    pub pds_endpoint: Option<String>,
}

/// Read the resulting DID state from the latest non-nullified audit-log entry.
///
/// A PLC operation's JSON encodes the DID's state AFTER it is applied, so the newest
/// entry's `operation` object is the current state. We read fields defensively; an
/// empty log or a missing `prev`-able CID is an error (a genesis-only DID that the
/// wallet controls still has a CID to chain against).
pub(crate) fn latest_op_state(audit_log: &[AuditEntry]) -> Result<CurrentState, MigrateError> {
    let latest = audit_log
        .iter()
        .rev()
        .find(|e| !e.nullified)
        .ok_or_else(|| MigrateError::InvalidAuditLog {
            message: "audit log is empty or fully nullified".to_string(),
        })?;

    let op = &latest.operation;

    // Parse the required arrays strictly: a malformed or missing `rotationKeys` /
    // `alsoKnownAs` must be an error, never a silently-truncated `[]`. Truncating
    // `alsoKnownAs` to `[]` would let the build "preserve" an empty handle set and
    // sign a handle-removing op that the guard's `proposed == current` check misses.
    let rotation_keys = string_array_field(op, "rotationKeys")?;
    if rotation_keys.is_empty() {
        return Err(MigrateError::InvalidAuditLog {
            message: "operation.rotationKeys is empty".to_string(),
        });
    }
    let also_known_as = string_array_field(op, "alsoKnownAs")?;

    let pds_endpoint = op
        .get("services")
        .and_then(|s| s.get(ATPROTO_PDS_SERVICE_ID))
        .and_then(|svc| svc.get("endpoint"))
        .and_then(|e| e.as_str())
        .map(String::from);

    Ok(CurrentState {
        prev_cid: latest.cid.clone(),
        rotation_keys,
        also_known_as,
        pds_endpoint,
    })
}

/// Parse a required string-array field from a PLC operation, rejecting a missing
/// field, a non-array value, or any non-string element. This keeps malformed
/// audit-log state from being silently coerced into a value we would then sign.
fn string_array_field(op: &serde_json::Value, field: &str) -> Result<Vec<String>, MigrateError> {
    let arr =
        op.get(field)
            .and_then(|v| v.as_array())
            .ok_or_else(|| MigrateError::InvalidAuditLog {
                message: format!("operation.{field} is missing or not an array"),
            })?;

    arr.iter()
        .enumerate()
        .map(|(idx, value)| {
            value
                .as_str()
                .map(String::from)
                .ok_or_else(|| MigrateError::InvalidAuditLog {
                    message: format!("operation.{field}[{idx}] is not a string"),
                })
        })
        .collect()
}

/// Read current rotation keys from the latest non-nullified PLC audit-log entry.
///
/// Unlike `pds_client::rotation_keys_from_audit_log`, this helper is strict: malformed
/// logs are an error so path detection can fail closed as `CannotDetermine` instead
/// of silently picking the interop path from an accidental empty key set.
pub(crate) fn current_rotation_keys_from_audit_log(
    raw_json: &str,
) -> Result<Vec<String>, MigrateError> {
    let audit_log =
        crypto::parse_audit_log(raw_json).map_err(|e| MigrateError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let latest = audit_log
        .iter()
        .rev()
        .find(|e| !e.nullified)
        .ok_or_else(|| MigrateError::InvalidAuditLog {
            message: "audit log is empty or fully nullified".to_string(),
        })?;
    let rotation_keys = string_array_field(&latest.operation, "rotationKeys")?;
    if rotation_keys.is_empty() {
        return Err(MigrateError::InvalidAuditLog {
            message: "operation.rotationKeys is empty".to_string(),
        });
    }
    Ok(rotation_keys)
}

/// Decide whether the wallet can self-sign a migration for this DID.
///
/// The detector encodes ADR-0002's two-path model: if the wallet's per-DID device
/// key appears anywhere in the current rotationKeys, the wallet can use the
/// self-signed path; otherwise it must fall back to the PDS-signed interop path.
/// A key at index 1+ is still authorized, but the index is surfaced so the UI can
/// explain that the wallet is not the primary rotation key.
pub(crate) fn decide_migration_path(
    rotation_keys: &[String],
    device_key_id: Option<&str>,
) -> MigrationPathDecision {
    let Some(device_key_id) = device_key_id else {
        return MigrationPathDecision {
            path: MigrationPath::Interop,
            device_key_id: None,
            rotation_key_index: None,
            reason: "wallet has no device key for this DID; use PDS-signed interop".to_string(),
        };
    };

    match rotation_keys.iter().position(|key| key == device_key_id) {
        Some(index) => MigrationPathDecision {
            path: MigrationPath::SelfSigned,
            device_key_id: Some(device_key_id.to_string()),
            rotation_key_index: Some(index),
            reason: if index == 0 {
                "wallet device key is the primary rotation key; self-signed migration is available"
                    .to_string()
            } else {
                format!(
                    "wallet device key is authorized at rotationKeys[{index}]; self-signed migration is available"
                )
            },
        },
        None => MigrationPathDecision {
            path: MigrationPath::Interop,
            device_key_id: Some(device_key_id.to_string()),
            rotation_key_index: None,
            reason: "wallet device key is not in current rotationKeys; use PDS-signed interop"
                .to_string(),
        },
    }
}

/// Fetch current PLC state and decide which migration path should be used.
pub async fn detect_migration_path(pds_client: &PdsClient, did: &str) -> MigrationPathDecision {
    let log_json = match pds_client.fetch_audit_log(did).await {
        Ok(log_json) => log_json,
        Err(e) => {
            return MigrationPathDecision {
                path: MigrationPath::CannotDetermine,
                device_key_id: None,
                rotation_key_index: None,
                reason: format!("cannot fetch PLC audit log: {e}"),
            }
        }
    };

    let rotation_keys = match current_rotation_keys_from_audit_log(&log_json) {
        Ok(keys) => keys,
        Err(e) => {
            return MigrationPathDecision {
                path: MigrationPath::CannotDetermine,
                device_key_id: None,
                rotation_key_index: None,
                reason: e.to_string(),
            }
        }
    };

    let store = IdentityStore;
    let device_key_id = match store.get_or_create_device_key(did) {
        Ok(key) => Some(key.key_id),
        Err(crate::identity_store::IdentityStoreError::IdentityNotFound) => None,
        Err(e) => {
            return MigrationPathDecision {
                path: MigrationPath::CannotDetermine,
                device_key_id: None,
                rotation_key_index: None,
                reason: format!("cannot load wallet device key: {e}"),
            }
        }
    };

    decide_migration_path(&rotation_keys, device_key_id.as_deref())
}

// ── RecommendedCredentials -> typed maps ─────────────────────────────────────

/// Convert the destination PDS's recommended `verificationMethods` (untyped JSON of
/// `{ id: "did:key:z..." }`) into the `BTreeMap<String, String>` that
/// `build_did_plc_rotation_op` expects. Requires at least the `atproto` method.
pub(crate) fn recommended_verification_methods(
    recommended: &RecommendedCredentials,
) -> Result<BTreeMap<String, String>, MigrateError> {
    let value = recommended.verification_methods.as_ref().ok_or_else(|| {
        MigrateError::InvalidRecommendedCredentials {
            message: "destination did not recommend any verificationMethods".to_string(),
        }
    })?;

    let obj = value
        .as_object()
        .ok_or_else(|| MigrateError::InvalidRecommendedCredentials {
            message: "verificationMethods is not a JSON object".to_string(),
        })?;

    let mut methods = BTreeMap::new();
    for (id, key) in obj {
        // Every verification method here is signed into the op, but the guard only
        // reasons about rotation keys — so an unexpected method would reach the
        // signature unchecked. A migration only ever sets the atproto method.
        if id != ATPROTO_VERIFICATION_METHOD_ID {
            return Err(MigrateError::InvalidRecommendedCredentials {
                message: format!(
                    "unexpected verificationMethods.{id}; only '{ATPROTO_VERIFICATION_METHOD_ID}' is allowed"
                ),
            });
        }
        let key_str = key
            .as_str()
            .ok_or_else(|| MigrateError::InvalidRecommendedCredentials {
                message: format!("verificationMethods.{id} is not a string"),
            })?;
        methods.insert(id.clone(), key_str.to_string());
    }

    if !methods.contains_key(ATPROTO_VERIFICATION_METHOD_ID) {
        return Err(MigrateError::InvalidRecommendedCredentials {
            message: "destination recommended no 'atproto' verification method".to_string(),
        });
    }

    Ok(methods)
}

/// Convert the destination PDS's recommended `services` (untyped JSON of
/// `{ id: { type, endpoint } }`) into the `BTreeMap<String, PlcService>` that
/// `build_did_plc_rotation_op` expects. Requires the `atproto_pds` service.
pub(crate) fn recommended_services(
    recommended: &RecommendedCredentials,
) -> Result<BTreeMap<String, PlcService>, MigrateError> {
    let value = recommended.services.as_ref().ok_or_else(|| {
        MigrateError::InvalidRecommendedCredentials {
            message: "destination did not recommend any services".to_string(),
        }
    })?;

    let obj = value
        .as_object()
        .ok_or_else(|| MigrateError::InvalidRecommendedCredentials {
            message: "services is not a JSON object".to_string(),
        })?;

    let mut services = BTreeMap::new();
    for (id, svc) in obj {
        let service_type = svc.get("type").and_then(|t| t.as_str()).ok_or_else(|| {
            MigrateError::InvalidRecommendedCredentials {
                message: format!("services.{id} is missing a string 'type'"),
            }
        })?;
        let endpoint = svc
            .get("endpoint")
            .and_then(|e| e.as_str())
            .ok_or_else(|| MigrateError::InvalidRecommendedCredentials {
                message: format!("services.{id} is missing a string 'endpoint'"),
            })?;
        services.insert(
            id.clone(),
            PlcService {
                service_type: service_type.to_string(),
                endpoint: endpoint.to_string(),
            },
        );
    }

    if !services.contains_key(ATPROTO_PDS_SERVICE_ID) {
        return Err(MigrateError::InvalidRecommendedCredentials {
            message: "destination recommended no 'atproto_pds' service".to_string(),
        });
    }

    Ok(services)
}

// ── Diff computation ─────────────────────────────────────────────────────────

/// Build the review diff for a migration op: the atproto_pds endpoint change plus the
/// rotation-key additions/removals implied by the swap.
pub(crate) fn build_migration_diff(
    current: &CurrentState,
    proposed_rotation_keys: &[String],
    proposed_pds_endpoint: &str,
) -> OpDiff {
    let current_set: std::collections::HashSet<&String> = current.rotation_keys.iter().collect();
    let proposed_set: std::collections::HashSet<&String> = proposed_rotation_keys.iter().collect();

    let added_keys = proposed_rotation_keys
        .iter()
        .filter(|k| !current_set.contains(*k))
        .cloned()
        .collect();
    let removed_keys = current
        .rotation_keys
        .iter()
        .filter(|k| !proposed_set.contains(*k))
        .cloned()
        .collect();

    let changed_services = vec![ServiceChange {
        id: ATPROTO_PDS_SERVICE_ID.to_string(),
        change_type: ChangeType::Modified,
        old_endpoint: current.pds_endpoint.clone(),
        new_endpoint: Some(proposed_pds_endpoint.to_string()),
    }];

    OpDiff {
        added_keys,
        removed_keys,
        changed_services,
        prev_cid: Some(current.prev_cid.clone()),
    }
}

// ── Imperative shell: build + submit ─────────────────────────────────────────

/// Build and locally sign the migration identity-leg operation.
///
/// Fetches the DID's audit log (for `prev` + current state), reads the destination
/// PDS's recommended credentials, assembles the proposed op (device key preserved at
/// rotationKeys[0]), runs the strict pre-sign guard, and signs with the per-DID device
/// key. `dest_client` is an already-authenticated client for the DESTINATION PDS,
/// supplied by the migration orchestrator.
pub async fn build_migration_op(
    pds_client: &PdsClient,
    dest_client: &OAuthClient,
    did: &str,
) -> Result<SignedMigrationOp, MigrateError> {
    let store = IdentityStore;

    // 1. Per-DID device key.
    let device_pub =
        store
            .get_or_create_device_key(did)
            .map_err(|e| MigrateError::IdentityNotFound {
                message: format!("failed to get device key: {e}"),
            })?;
    let device_key_id = device_pub.key_id;

    // 2. Current audit log -> prev + current state.
    let log_json =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| MigrateError::NetworkError {
                message: format!("failed to fetch audit log: {e}"),
            })?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| MigrateError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let current = latest_op_state(&audit_log)?;

    // 3. Destination-recommended credentials.
    let recommended = get_recommended_did_credentials(dest_client)
        .await
        .map_err(|e| MigrateError::NetworkError {
            message: format!("getRecommendedDidCredentials failed: {e}"),
        })?;

    // 4. Assemble the proposed op (device key forced to rotationKeys[0]).
    //    The destination MUST recommend at least one rotation key (its reserved
    //    signing key) — otherwise the op would leave the new PDS unable to act.
    let recommended_rotation_keys = match recommended.rotation_keys.clone() {
        Some(keys) if !keys.is_empty() => keys,
        _ => {
            return Err(MigrateError::InvalidRecommendedCredentials {
                message: "destination recommended no rotation keys".to_string(),
            })
        }
    };
    let mut proposed_rotation_keys = vec![device_key_id.clone()];
    for key in &recommended_rotation_keys {
        if key != &device_key_id {
            proposed_rotation_keys.push(key.clone());
        }
    }
    let proposed_vms = recommended_verification_methods(&recommended)?;
    let proposed_services = recommended_services(&recommended)?;
    let proposed_endpoint = proposed_services
        .get(ATPROTO_PDS_SERVICE_ID)
        .map(|s| s.endpoint.clone())
        .expect("recommended_services guarantees atproto_pds is present");
    // A migration preserves the handle: keep current alsoKnownAs.
    let also_known_as = current.also_known_as.clone();

    // 5. Strict pre-sign guard — the security gate.
    let inputs = MigrationInputs {
        device_key_id: device_key_id.clone(),
        current_rotation_keys: current.rotation_keys.clone(),
        current_also_known_as: current.also_known_as.clone(),
        recommended_rotation_keys: recommended_rotation_keys.clone(),
        proposed_rotation_keys: proposed_rotation_keys.clone(),
        proposed_also_known_as: also_known_as.clone(),
        proposed_service_ids: proposed_services.keys().cloned().collect(),
    };
    guard_migration_op(&inputs)?;

    // 6. Sign locally with the per-DID device key.
    let sign_closure = crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
        PerDidSignError::DeviceKeyNotFound { message } => {
            MigrateError::IdentityNotFound { message }
        }
        PerDidSignError::SigningSetupFailed { message } => MigrateError::SigningFailed { message },
    })?;
    let signed = crypto::build_did_plc_rotation_op(
        &current.prev_cid,
        proposed_rotation_keys.clone(),
        proposed_vms,
        also_known_as,
        proposed_services,
        sign_closure,
    )
    .map_err(|e| MigrateError::SigningFailed {
        message: format!("failed to build rotation op: {e}"),
    })?;

    // 7. Diff for review.
    let diff = build_migration_diff(&current, &proposed_rotation_keys, &proposed_endpoint);

    Ok(SignedMigrationOp {
        diff,
        signed_op: serde_json::from_str(&signed.signed_op_json).map_err(|e| {
            MigrateError::SigningFailed {
                message: format!("failed to parse signed op JSON: {e}"),
            }
        })?,
    })
}

/// Submit the signed migration op to plc.directory and refresh the local cache.
/// Mirrors `recovery::submit_recovery_override`.
pub async fn submit_migration_op(
    pds_client: &PdsClient,
    did: &str,
    signed_op: &serde_json::Value,
) -> Result<ClaimResult, MigrateError> {
    let store = IdentityStore;

    pds_client
        .post_plc_operation(did, signed_op)
        .await
        .map_err(|e| MigrateError::PlcDirectoryError {
            message: format!("plc.directory rejected the operation: {e}"),
        })?;

    let updated_log =
        pds_client
            .fetch_audit_log(did)
            .await
            .map_err(|e| MigrateError::NetworkError {
                message: format!("failed to fetch updated audit log: {e}"),
            })?;
    store
        .store_plc_log(did, &updated_log)
        .map_err(|e| MigrateError::SigningFailed {
            message: format!("failed to cache updated PLC log: {e}"),
        })?;

    // Fetch the PLC *data* document, not the W3C DID document: the per-identity
    // cache — and everything that reads it (the home card's rotationKeys[0]
    // custody badge, `extractPdsFromPlcDoc`'s `services` map) — expects the PLC
    // shape. The W3C form carries no `rotationKeys`, so caching it degrades the
    // badge to "Unknown".
    let did_doc =
        pds_client
            .fetch_plc_data_document(did)
            .await
            .map_err(|e| MigrateError::NetworkError {
                message: format!("failed to fetch DID document: {e}"),
            })?;
    store
        .store_did_doc(did, &serde_json::to_string(&did_doc).unwrap_or_default())
        .map_err(|e| MigrateError::SigningFailed {
            message: format!("failed to cache updated DID document: {e}"),
        })?;

    Ok(ClaimResult {
        updated_did_doc: did_doc,
    })
}

// ── Tauri commands ───────────────────────────────────────────────────────────
//
// The destination-PDS `OAuthClient` must already be populated in `MigrationState` by
// the migration orchestrator before `build_migration_op_cmd` runs — this leg does
// not perform the destination login.

/// Tauri command: decide whether to use self-signed migration or PDS-signed interop.
#[tauri::command]
pub async fn detect_migration_path_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<MigrationPathDecision, MigrateError> {
    Ok(detect_migration_path(state.pds_client(), &did).await)
}

/// Tauri command: build + sign the migration op, parking it in `MigrationState`.
#[tauri::command]
pub async fn build_migration_op_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<SignedMigrationOp, MigrateError> {
    let dest_client = {
        let migration = state.migration_state.lock().await;
        let ms = migration
            .as_ref()
            .ok_or_else(|| MigrateError::MigrationNotReady {
                message: "no pending migration; destination authentication must run first"
                    .to_string(),
            })?;
        if ms.did != did {
            return Err(MigrateError::MigrationNotReady {
                message: format!(
                    "migration state DID mismatch: expected {}, got {did}",
                    ms.did
                ),
            });
        }
        ms.dest_oauth_client.clone()
    };

    let result = build_migration_op(state.pds_client(), &dest_client, &did).await?;

    // Re-acquire and re-validate: a concurrent migration could have replaced the
    // state while we awaited, so we must not park this DID's op into another's slot.
    let mut migration = state.migration_state.lock().await;
    let ms = migration
        .as_mut()
        .ok_or_else(|| MigrateError::MigrationNotReady {
            message: "pending migration was cleared while building".to_string(),
        })?;
    if ms.did != did {
        return Err(MigrateError::MigrationNotReady {
            message: format!(
                "migration state changed while building: expected {}, got {did}",
                ms.did
            ),
        });
    }
    ms.signed_op = Some(result.signed_op.clone());

    Ok(result)
}

/// Tauri command: submit the pending migration op to plc.directory.
#[tauri::command]
pub async fn submit_migration_op_cmd(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<ClaimResult, MigrateError> {
    // Take (not clone) the signed op under the lock, so a concurrent or retried
    // submit cannot double-post the same non-idempotent PLC operation. The
    // destination client is left in place, so a failed submit can be rebuilt.
    let signed_op = {
        let mut migration = state.migration_state.lock().await;
        let ms = migration
            .as_mut()
            .ok_or_else(|| MigrateError::MigrationNotReady {
                message: "no pending migration to submit".to_string(),
            })?;
        if ms.did != did {
            return Err(MigrateError::MigrationNotReady {
                message: format!(
                    "migration state DID mismatch: expected {}, got {did}",
                    ms.did
                ),
            });
        }
        ms.signed_op
            .take()
            .ok_or_else(|| MigrateError::MigrationNotReady {
                message: "no signed op; build the migration operation first".to_string(),
            })?
    };

    let result = submit_migration_op(state.pds_client(), &did, &signed_op).await?;

    // Migration complete — clear the state.
    let mut migration = state.migration_state.lock().await;
    *migration = None;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pds_client::RecommendedCredentials;

    const DEVICE: &str = "did:key:zDEVICE";
    const DEST: &str = "did:key:zDESTPDS";
    const OLD_PDS: &str = "did:key:zOLDPDS";
    const HANDLE: &str = "at://alice.test";

    // ── Guard (strict allowlist) ─────────────────────────────────────────────
    //
    // These tests are the spec for `guard_migration_op`. Until it is implemented
    // they fail (the stub is `todo!()`); once the five rules are in place they pass.

    /// A well-formed migration: device key stays at [0], the only extra key is the
    /// destination's recommended key, the handle is preserved, and only atproto_pds
    /// is touched.
    fn ok_inputs() -> MigrationInputs {
        MigrationInputs {
            device_key_id: DEVICE.to_string(),
            current_rotation_keys: vec![DEVICE.to_string(), OLD_PDS.to_string()],
            current_also_known_as: vec![HANDLE.to_string()],
            recommended_rotation_keys: vec![DEST.to_string()],
            proposed_rotation_keys: vec![DEVICE.to_string(), DEST.to_string()],
            proposed_also_known_as: vec![HANDLE.to_string()],
            proposed_service_ids: vec![ATPROTO_PDS_SERVICE_ID.to_string()],
        }
    }

    #[test]
    fn guard_accepts_a_well_formed_migration() {
        assert!(guard_migration_op(&ok_inputs()).is_ok());
    }

    #[test]
    fn path_detector_returns_self_signed_for_key_at_index_zero() {
        let keys = vec![DEVICE.to_string(), OLD_PDS.to_string()];
        let decision = decide_migration_path(&keys, Some(DEVICE));
        assert_eq!(decision.path, MigrationPath::SelfSigned);
        assert_eq!(decision.rotation_key_index, Some(0));
        assert_eq!(decision.device_key_id.as_deref(), Some(DEVICE));
    }

    #[test]
    fn path_detector_returns_self_signed_for_key_at_later_index() {
        let keys = vec![OLD_PDS.to_string(), DEVICE.to_string()];
        let decision = decide_migration_path(&keys, Some(DEVICE));
        assert_eq!(decision.path, MigrationPath::SelfSigned);
        assert_eq!(decision.rotation_key_index, Some(1));
        assert!(decision.reason.contains("rotationKeys[1]"));
    }

    #[test]
    fn path_detector_returns_interop_when_key_absent() {
        let keys = vec![OLD_PDS.to_string()];
        let decision = decide_migration_path(&keys, Some(DEVICE));
        assert_eq!(decision.path, MigrationPath::Interop);
        assert_eq!(decision.rotation_key_index, None);
    }

    #[test]
    fn path_detector_returns_interop_without_wallet_key() {
        let keys = vec![OLD_PDS.to_string()];
        let decision = decide_migration_path(&keys, None);
        assert_eq!(decision.path, MigrationPath::Interop);
        assert_eq!(decision.device_key_id, None);
    }

    #[test]
    fn current_rotation_keys_reads_latest_non_nullified_audit_entry() {
        let log = serde_json::json!([
            audit_entry(
                "bafy_old",
                false,
                serde_json::json!({
                    "rotationKeys": [OLD_PDS],
                    "alsoKnownAs": [HANDLE]
                })
            ),
            audit_entry(
                "bafy_latest",
                false,
                serde_json::json!({
                    "rotationKeys": [DEVICE, OLD_PDS],
                    "alsoKnownAs": [HANDLE]
                })
            ),
            audit_entry(
                "bafy_nullified",
                true,
                serde_json::json!({
                    "rotationKeys": ["did:key:zEVIL"],
                    "alsoKnownAs": [HANDLE]
                })
            ),
        ]);
        let keys = current_rotation_keys_from_audit_log(&log.to_string()).expect("rotation keys");
        assert_eq!(keys, vec![DEVICE.to_string(), OLD_PDS.to_string()]);
    }

    #[test]
    fn current_rotation_keys_rejects_malformed_audit_log() {
        let log = serde_json::json!([audit_entry(
            "bafy_bad",
            false,
            serde_json::json!({
                "rotationKeys": [DEVICE, 42],
                "alsoKnownAs": [HANDLE]
            })
        )]);
        assert!(matches!(
            current_rotation_keys_from_audit_log(&log.to_string()),
            Err(MigrateError::InvalidAuditLog { .. })
        ));
    }

    #[test]
    fn current_rotation_keys_rejects_empty_rotation_keys() {
        let log = serde_json::json!([audit_entry(
            "bafy_bad",
            false,
            serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": [HANDLE]
            })
        )]);
        assert!(matches!(
            current_rotation_keys_from_audit_log(&log.to_string()),
            Err(MigrateError::InvalidAuditLog { .. })
        ));
    }

    #[test]
    fn guard_rejects_when_wallet_holds_no_current_key() {
        // Device key is NOT among the DID's current rotation keys → defer to interop.
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![OLD_PDS.to_string()];
        assert!(matches!(
            guard_migration_op(&inputs),
            Err(MigrateError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_when_device_key_not_at_index_zero() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys = vec![DEST.to_string(), DEVICE.to_string()];
        assert!(matches!(
            guard_migration_op(&inputs),
            Err(MigrateError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_smuggled_rotation_key() {
        // A key that the destination did not recommend must not appear.
        let mut inputs = ok_inputs();
        inputs
            .proposed_rotation_keys
            .push("did:key:zEVIL".to_string());
        assert!(matches!(
            guard_migration_op(&inputs),
            Err(MigrateError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_a_handle_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_also_known_as = vec!["at://mallory.test".to_string()];
        assert!(matches!(
            guard_migration_op(&inputs),
            Err(MigrateError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_touching_a_non_pds_service() {
        let mut inputs = ok_inputs();
        inputs.proposed_service_ids = vec![
            ATPROTO_PDS_SERVICE_ID.to_string(),
            "some_other_service".to_string(),
        ];
        assert!(matches!(
            guard_migration_op(&inputs),
            Err(MigrateError::GuardRejected { .. })
        ));
    }

    // ── Converters ───────────────────────────────────────────────────────────

    fn creds(
        rotation_keys: Option<Vec<String>>,
        verification_methods: Option<serde_json::Value>,
        services: Option<serde_json::Value>,
    ) -> RecommendedCredentials {
        RecommendedCredentials {
            rotation_keys,
            also_known_as: None,
            verification_methods,
            services,
        }
    }

    #[test]
    fn verification_methods_convert_and_require_atproto() {
        let ok = creds(None, Some(serde_json::json!({ "atproto": DEST })), None);
        let map = recommended_verification_methods(&ok).expect("should convert");
        assert_eq!(map.get("atproto").map(String::as_str), Some(DEST));

        let missing_atproto = creds(None, Some(serde_json::json!({ "other": DEST })), None);
        assert!(matches!(
            recommended_verification_methods(&missing_atproto),
            Err(MigrateError::InvalidRecommendedCredentials { .. })
        ));

        let none = creds(None, None, None);
        assert!(recommended_verification_methods(&none).is_err());
    }

    #[test]
    fn verification_methods_reject_unexpected_id() {
        // An extra (non-atproto) verification method would be signed into the op but
        // is never seen by the guard, so the converter must reject it outright.
        let extra = creds(
            None,
            Some(serde_json::json!({ "atproto": DEST, "sneaky": "did:key:zEVIL" })),
            None,
        );
        assert!(matches!(
            recommended_verification_methods(&extra),
            Err(MigrateError::InvalidRecommendedCredentials { .. })
        ));
    }

    #[test]
    fn services_convert_and_require_atproto_pds() {
        let ok = creds(
            None,
            None,
            Some(serde_json::json!({
                ATPROTO_PDS_SERVICE_ID: {
                    "type": "AtprotoPersonalDataServer",
                    "endpoint": "https://new.pds.example"
                }
            })),
        );
        let map = recommended_services(&ok).expect("should convert");
        let svc = map
            .get(ATPROTO_PDS_SERVICE_ID)
            .expect("atproto_pds present");
        assert_eq!(svc.endpoint, "https://new.pds.example");
        assert_eq!(svc.service_type, "AtprotoPersonalDataServer");

        let missing_endpoint = creds(
            None,
            None,
            Some(serde_json::json!({
                ATPROTO_PDS_SERVICE_ID: { "type": "AtprotoPersonalDataServer" }
            })),
        );
        assert!(matches!(
            recommended_services(&missing_endpoint),
            Err(MigrateError::InvalidRecommendedCredentials { .. })
        ));

        let missing_pds = creds(
            None,
            None,
            Some(serde_json::json!({
                "other": { "type": "X", "endpoint": "https://x" }
            })),
        );
        assert!(recommended_services(&missing_pds).is_err());
    }

    // ── Current-state extraction ─────────────────────────────────────────────

    fn audit_entry(cid: &str, nullified: bool, operation: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "did": "did:plc:test",
            "cid": cid,
            "createdAt": "2026-07-03T00:00:00Z",
            "nullified": nullified,
            "operation": operation
        })
    }

    #[test]
    fn latest_op_state_reads_newest_non_nullified_entry() {
        let log = serde_json::json!([
            audit_entry(
                "bafy_genesis",
                false,
                serde_json::json!({
                    "rotationKeys": [DEVICE],
                    "alsoKnownAs": [HANDLE],
                    "services": { ATPROTO_PDS_SERVICE_ID: { "type": "AtprotoPersonalDataServer", "endpoint": "https://old.pds" } }
                })
            ),
            audit_entry(
                "bafy_latest",
                false,
                serde_json::json!({
                    "rotationKeys": [DEVICE, OLD_PDS],
                    "alsoKnownAs": [HANDLE],
                    "services": { ATPROTO_PDS_SERVICE_ID: { "type": "AtprotoPersonalDataServer", "endpoint": "https://current.pds" } }
                })
            ),
        ]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        let state = latest_op_state(&entries).expect("state");

        assert_eq!(state.prev_cid, "bafy_latest");
        assert_eq!(
            state.rotation_keys,
            vec![DEVICE.to_string(), OLD_PDS.to_string()]
        );
        assert_eq!(state.also_known_as, vec![HANDLE.to_string()]);
        assert_eq!(state.pds_endpoint.as_deref(), Some("https://current.pds"));
    }

    #[test]
    fn latest_op_state_skips_nullified_tail() {
        let log = serde_json::json!([
            audit_entry(
                "bafy_good",
                false,
                serde_json::json!({
                    "rotationKeys": [DEVICE],
                    "alsoKnownAs": [HANDLE],
                    "services": { ATPROTO_PDS_SERVICE_ID: { "type": "AtprotoPersonalDataServer", "endpoint": "https://good.pds" } }
                })
            ),
            audit_entry(
                "bafy_nullified",
                true,
                serde_json::json!({
                    "rotationKeys": ["did:key:zEVIL"],
                    "alsoKnownAs": [HANDLE],
                    "services": {}
                })
            ),
        ]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        let state = latest_op_state(&entries).expect("state");
        assert_eq!(state.prev_cid, "bafy_good");
        assert_eq!(state.rotation_keys, vec![DEVICE.to_string()]);
    }

    #[test]
    fn latest_op_state_errors_on_empty_log() {
        assert!(matches!(
            latest_op_state(&[]),
            Err(MigrateError::InvalidAuditLog { .. })
        ));
    }

    #[test]
    fn latest_op_state_rejects_missing_also_known_as() {
        // A missing alsoKnownAs must NOT be silently coerced to []: that would let the
        // build "preserve" an empty handle set and sign a handle-removing op.
        let log = serde_json::json!([audit_entry(
            "bafy_bad",
            false,
            serde_json::json!({
                "rotationKeys": [DEVICE],
                "services": { ATPROTO_PDS_SERVICE_ID: { "type": "AtprotoPersonalDataServer", "endpoint": "https://x" } }
            })
        )]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        assert!(matches!(
            latest_op_state(&entries),
            Err(MigrateError::InvalidAuditLog { .. })
        ));
    }

    #[test]
    fn latest_op_state_rejects_non_string_rotation_key() {
        let log = serde_json::json!([audit_entry(
            "bafy_bad",
            false,
            serde_json::json!({
                "rotationKeys": [DEVICE, 42],
                "alsoKnownAs": [HANDLE],
                "services": {}
            })
        )]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        assert!(matches!(
            latest_op_state(&entries),
            Err(MigrateError::InvalidAuditLog { .. })
        ));
    }

    #[test]
    fn latest_op_state_rejects_empty_rotation_keys() {
        let log = serde_json::json!([audit_entry(
            "bafy_bad",
            false,
            serde_json::json!({
                "rotationKeys": [],
                "alsoKnownAs": [HANDLE],
                "services": {}
            })
        )]);
        let entries = crypto::parse_audit_log(&log.to_string()).expect("parse");
        assert!(matches!(
            latest_op_state(&entries),
            Err(MigrateError::InvalidAuditLog { .. })
        ));
    }

    // ── Diff ─────────────────────────────────────────────────────────────────

    #[test]
    fn migration_diff_shows_endpoint_and_key_swap() {
        let current = CurrentState {
            prev_cid: "bafy_prev".to_string(),
            rotation_keys: vec![DEVICE.to_string(), OLD_PDS.to_string()],
            also_known_as: vec![HANDLE.to_string()],
            pds_endpoint: Some("https://old.pds".to_string()),
        };
        let proposed = vec![DEVICE.to_string(), DEST.to_string()];
        let diff = build_migration_diff(&current, &proposed, "https://new.pds");

        assert_eq!(diff.added_keys, vec![DEST.to_string()]);
        assert_eq!(diff.removed_keys, vec![OLD_PDS.to_string()]);
        assert_eq!(diff.prev_cid.as_deref(), Some("bafy_prev"));
        assert_eq!(diff.changed_services.len(), 1);
        let svc = &diff.changed_services[0];
        assert_eq!(svc.id, ATPROTO_PDS_SERVICE_ID);
        assert_eq!(svc.change_type, ChangeType::Modified);
        assert_eq!(svc.old_endpoint.as_deref(), Some("https://old.pds"));
        assert_eq!(svc.new_endpoint.as_deref(), Some("https://new.pds"));
    }

    #[test]
    fn migrate_error_serializes_screaming_snake_case() {
        let err = MigrateError::WalletNotAuthorized;
        let json = serde_json::to_value(&err).expect("serialize");
        assert_eq!(
            json.get("code").and_then(|v| v.as_str()),
            Some("WALLET_NOT_AUTHORIZED")
        );
    }

    // ── End-to-end integration (build → verify → submit) ─────────────────────
    //
    // Exercises the full self-signed identity leg against mock plc.directory and
    // destination-PDS servers: build a repoint op, prove it verifies under the device
    // key with rotationKeys[0] preserved, then submit it. Requires socket binding, so
    // it is ignored in sandboxed environments (same convention as recovery.rs).
    // Run with: cargo test -p identity-wallet test_build_and_submit_migration -- --ignored

    #[tokio::test]
    #[ignore] // Requires socket binding; ignore in sandboxed environments
    async fn test_build_and_submit_migration_self_signs_repoint() {
        use crate::oauth::{DPoPKeypair, OAuthSession};
        use httpmock::prelude::*;
        use std::sync::{Arc, Mutex};

        let did = "did:plc:migratetest";
        const DEST_SIGN: &str = "did:key:zDESTSIGN";

        // Identity + per-DID device key (the wallet's rotationKeys[0]).
        let store = IdentityStore;
        let _ = store.remove_identity(did);
        store.add_identity(did).expect("add_identity");
        let device_pub = store
            .get_or_create_device_key(did)
            .expect("device key generation");
        let device_key_id = device_pub.key_id.clone();

        // Current audit log: the wallet already holds rotationKeys[0]; the DID points
        // at the OLD PDS.
        let audit_log_json = serde_json::json!([{
            "did": did,
            "cid": "bafy_current",
            "createdAt": "2026-07-03T00:00:00Z",
            "nullified": false,
            "operation": {
                "type": "plc_operation",
                "rotationKeys": [device_key_id, OLD_PDS],
                "verificationMethods": { ATPROTO_VERIFICATION_METHOD_ID: "did:key:zOLDSIGN" },
                "alsoKnownAs": [HANDLE],
                "services": { ATPROTO_PDS_SERVICE_ID: { "type": "AtprotoPersonalDataServer", "endpoint": "https://old.pds" } },
                "prev": "bafy_prev",
                "sig": "placeholder"
            }
        }]);

        // plc.directory mock (audit log fetch, op submit, DID-doc refetch).
        let plc = MockServer::start();
        let audit_mock = plc.mock(|when, then| {
            when.method(GET).path(format!("/{did}/log/audit"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(audit_log_json.clone());
        });
        let submit_mock = plc.mock(|when, then| {
            when.method(POST).path(format!("/{did}"));
            then.status(200).json_body(serde_json::json!({}));
        });
        // The refetch must hit the PLC *data* endpoint — the cached shape needs
        // `rotationKeys` (the home card's custody badge reads rotationKeys[0]).
        let diddoc_mock = plc.mock(|when, then| {
            when.method(GET).path(format!("/{did}/data"));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({
                    "did": did,
                    "alsoKnownAs": [HANDLE],
                    "rotationKeys": ["did:key:zMigratedDeviceKey", DEST_SIGN],
                    "verificationMethods": { "atproto": DEST_SIGN },
                    "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://new.pds" } }
                }));
        });
        let pds_client = PdsClient::new_for_test(plc.base_url());

        // Destination PDS mock: getRecommendedDidCredentials for the NEW PDS.
        let dest = MockServer::start();
        dest.mock(|when, then| {
            when.method(GET)
                .path("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({
                    "rotationKeys": [DEST_SIGN],
                    "alsoKnownAs": [HANDLE],
                    "verificationMethods": { ATPROTO_VERIFICATION_METHOD_ID: DEST_SIGN },
                    "services": { ATPROTO_PDS_SERVICE_ID: { "type": "AtprotoPersonalDataServer", "endpoint": "https://new.pds" } }
                }));
        });
        let keypair = DPoPKeypair::get_or_create().expect("dpop keypair");
        let session = Arc::new(Mutex::new(OAuthSession {
            access_token: "test-access".to_string(),
            refresh_token: "test-refresh".to_string(),
            expires_at: u64::MAX, // never trigger a refresh
            dpop_nonce: None,
        }));
        let dest_client =
            crate::oauth_client::OAuthClient::new_for_test(keypair, session, dest.base_url());

        // Build the self-signed repoint op.
        let built = build_migration_op(&pds_client, &dest_client, did)
            .await
            .expect("build_migration_op should succeed");
        audit_mock.assert();

        // Diff reflects the endpoint change + key swap.
        assert_eq!(built.diff.prev_cid.as_deref(), Some("bafy_current"));
        assert!(built.diff.added_keys.contains(&DEST_SIGN.to_string()));
        assert!(built.diff.removed_keys.contains(&OLD_PDS.to_string()));
        assert_eq!(
            built.diff.changed_services[0].new_endpoint.as_deref(),
            Some("https://new.pds")
        );

        // The op verifies under the device key, and rotationKeys[0] is preserved —
        // the "credible exit" guarantee, proven cryptographically.
        let signed_json = serde_json::to_string(&built.signed_op).expect("serialize signed op");
        let verified = crypto::verify_plc_operation(
            &signed_json,
            std::slice::from_ref(&crypto::DidKeyUri(device_key_id.clone())),
        )
        .expect("signed op must verify under the device key");
        assert_eq!(verified.rotation_keys.first(), Some(&device_key_id));
        assert_eq!(verified.prev.as_deref(), Some("bafy_current"));
        assert_eq!(
            verified.rotation_keys,
            vec![device_key_id.clone(), DEST_SIGN.to_string()]
        );

        // Submit accepts and refreshes the cache.
        submit_migration_op(&pds_client, did, &built.signed_op)
            .await
            .expect("submit_migration_op should succeed");
        submit_mock.assert();
        diddoc_mock.assert();

        // The cached doc must be the PLC data shape — rotationKeys present — or the
        // home card's custody badge degrades to "Unknown" after migration.
        let cached = store
            .get_did_doc(did)
            .expect("get_did_doc should succeed")
            .expect("DID document should be cached after submission");
        let cached: serde_json::Value = serde_json::from_str(&cached).expect("cached doc parses");
        assert!(
            cached["rotationKeys"].is_array(),
            "cached DID doc must carry rotationKeys (PLC data shape), got: {cached}"
        );

        let _ = store.remove_identity(did);
    }
}
