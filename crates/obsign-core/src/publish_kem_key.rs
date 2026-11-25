// pattern: Mixed (Functional Core guard/composers; Imperative Shell prepare/complete commands)

//! "Update identity for Spaces": the wallet's half of publishing an account's Spaces KEM key
//! (ADR-0043 owns the why; the server half is `crates/pds/src/routes/kem_key.rs`).
//!
//! **What is being published.** Custos holds a P-256 key per account whose public half must
//! appear in the DID document as `#atproto_kem`. Syncers use it to agree a one-off MAC secret
//! with the host, which is how a space record proves it came from this account's host
//! without that proof convincing anyone else. Accounts created before KEM keys existed have
//! no such entry, and Custos refuses their space writes with `KemKeyNotPublished` until they
//! publish one. The same flow rotates the key later.
//!
//! **Why the wallet is involved at all.** A did:plc document only changes through a PLC op
//! signed by a rotation key, and the wallet's device key outranks Custos's key there
//! (ADR-0001). So Custos can mint the key but cannot publish it: the wallet must build, check,
//! and sign the op, and the user approves it with biometrics. A self-hosted did:web is a file
//! the user serves from their own domain, so the user uploads the update.
//!
//! **The ceremony, as two commands.**
//!
//! 1. `prepare_kem_key_publish_cmd(did) -> KemKeyPlan`. `POST /v1/kem-key` asks Custos to
//!    stage a fresh key and returns its `did:key`. What happens next depends on the DID:
//!    - *did:plc:* read the audit log for the current state, compose an op that sets
//!      `verificationMethods.atproto_kem` to the staged key and drops the retired
//!      `atproto_space` method and `atproto_space_host` service, run [`guard_kem_op`], sign
//!      it with the device key, and park it. Nothing has left the phone yet.
//!    - *self-hosted did:web:* fetch the live `did.json`, rewrite it with
//!      [`did_web_document_with_kem_key`], and hand the text back for the user to export.
//!    - *Custos-hosted did:web:* Custos serves that document itself, so staging already
//!      published the key. The plan says `published` and there is nothing to complete.
//!      The frontend asks for biometrics before this call on every did:web, because here the
//!      stage call is the change.
//! 2. `complete_kem_key_publish_cmd(did) -> ClaimResult`. `POST /v1/kem-key/complete`. For
//!    did:plc it carries the parked op: Custos re-checks it against the DID's current state,
//!    submits it to plc.directory, and only then promotes the staged key to active. For
//!    did:web it carries nothing: Custos fetches the live document and promotes only if it
//!    publishes exactly the staged key. The frontend asks for biometrics before the did:plc
//!    call, the moment the signed op leaves the phone. Then the cached DID document refreshes.
//!
//! Like ADR-0025's rotation, the wallet never posts this op to plc.directory itself: Custos
//! submits it, so the key it promotes is always the one the document names. `complete` is
//! retry-safe on the server, so the parked op survives a failed call.
//!
//! `guard_kem_op` is the EIGHTH strict wallet allowlist, modeled on the repo-key rotation
//! guard: the op may set `atproto_kem` to exactly the staged key and delete `atproto_space`
//! / `atproto_space_host`, and must change nothing else. Custos runs the mirror check before
//! submitting, but the wallet's guard is what stands between the device key and a signature.
//!
//! `KemKeyError` (WALLET_NOT_AUTHORIZED, GUARD_REJECTED, INVALID_AUDIT_LOG,
//! INVALID_DID_DOCUMENT, SIGNING_FAILED, KEM_KEY_FAILED, NO_PENDING_KEM_KEY,
//! UNSUPPORTED_IDENTITY) serializes as SCREAMING_SNAKE_CASE beside the shared vocabulary in
//! [`crate::failure`]; `KEM_KEY_FAILED` carries the server `status`.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::claim::ClaimResult;
use crate::failure::SharedFailure;
use crate::handle_change::latest_full_state;
use crate::rotate_repo_key::{classify_host_rejection, refresh_cached_plc_state};
use crate::session_provider::SessionProvider;
use crypto::PlcService;

/// The verification method the KEM key is published under.
pub const KEM_VERIFICATION_METHOD_ID: &str = "atproto_kem";
/// The retired Spaces method Custos once recommended; a KEM op removes it.
pub const SPACE_VERIFICATION_METHOD_ID: &str = "atproto_space";
/// The retired Spaces service Custos once recommended; a KEM op removes it.
pub const SPACE_HOST_SERVICE_ID: &str = "atproto_space_host";

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from publishing the Spaces KEM key. Serializes as
/// `{ "code": "SCREAMING_SNAKE_CASE", ... }` like the sibling ceremony enums.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum KemKeyError {
    /// The wallet holds no key in the DID's current rotationKeys, so it cannot sign the op.
    #[error("wallet is not authorized to self-sign for this DID (no device key in current rotationKeys)")]
    WalletNotAuthorized,
    /// The strict pre-sign allowlist rejected the proposed operation or document.
    #[error("KEM key update rejected by pre-sign guard: {reason}")]
    GuardRejected { reason: String },
    /// The audit log could not be parsed or contained no usable current state.
    #[error("invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    /// The live did:web document could not be read as this DID's document.
    #[error("invalid DID document: {message}")]
    InvalidDidDocument { message: String },
    /// Local signing failed.
    #[error("signing failed: {message}")]
    SigningFailed { message: String },
    /// The hosting PDS rejected a stage or complete call.
    #[error("KEM key request failed (HTTP {status}): {message}")]
    KemKeyFailed { status: u16, message: String },
    /// No prepared update is pending for this DID (prepare must run first).
    #[error("no KEM key update is pending")]
    NoPendingKemKey,
    /// The DID is neither a did:plc nor a hostname-form did:web.
    #[error("this identity's DID method cannot publish a KEM key here")]
    UnsupportedIdentity,
    /// See [`SharedFailure`].
    #[serde(untagged)]
    #[error(transparent)]
    Shared(#[from] SharedFailure),
}

// ── The strict pre-sign guard (EIGHTH STRICT ALLOWLIST) ──────────────────────

/// Everything [`guard_kem_op`] compares, flattened to plain values so the guard is a pure
/// function (mirrors `RotationInputs`).
#[derive(Debug, Clone)]
pub struct KemOpInputs {
    /// The wallet's per-DID device key: the key that will sign.
    pub device_key_id: String,
    /// The KEM key Custos staged: the only key this op may add.
    pub staged_key_id: String,
    pub current_rotation_keys: Vec<String>,
    pub proposed_rotation_keys: Vec<String>,
    pub current_verification_methods: BTreeMap<String, String>,
    pub proposed_verification_methods: BTreeMap<String, String>,
    pub current_services: BTreeMap<String, PlcService>,
    pub proposed_services: BTreeMap<String, PlcService>,
    pub current_also_known_as: Vec<String>,
    pub proposed_also_known_as: Vec<String>,
}

/// Reject the proposed KEM-key op unless it makes exactly the allowed change. The device key
/// could sign anything, so this check on the inputs is the whole of the safety.
///
/// Rules:
///  1. Authorization: the device key is a current rotation key (else `WalletNotAuthorized`).
///  2. Freshness: the staged key is new. It must not already be the published KEM key (a
///     no-op), and must not be any rotation key or the `atproto` signing key: a KEM key that
///     doubles as a signing key is exactly what ADR-0043 rules out.
///  3. `rotationKeys` and `alsoKnownAs` are unchanged.
///  4. `verificationMethods` is the current map with `atproto_space` removed and
///     `atproto_kem` set to the staged key. Nothing else is added, removed, or changed.
///  5. `services` is the current map with `atproto_space_host` removed, and nothing else.
pub fn guard_kem_op(inputs: &KemOpInputs) -> Result<(), KemKeyError> {
    let reject = |reason: &str| {
        Err(KemKeyError::GuardRejected {
            reason: reason.to_string(),
        })
    };

    if !inputs.current_rotation_keys.contains(&inputs.device_key_id) {
        return Err(KemKeyError::WalletNotAuthorized);
    }

    let staged = &inputs.staged_key_id;
    if inputs
        .current_verification_methods
        .get(KEM_VERIFICATION_METHOD_ID)
        == Some(staged)
    {
        return reject("the staged KEM key is already published");
    }
    if staged == &inputs.device_key_id
        || inputs.current_rotation_keys.contains(staged)
        || inputs.current_verification_methods.get("atproto") == Some(staged)
    {
        return reject("the staged KEM key must not be a rotation or signing key");
    }

    if inputs.proposed_rotation_keys != inputs.current_rotation_keys {
        return reject("rotationKeys must not change");
    }
    if inputs.proposed_also_known_as != inputs.current_also_known_as {
        return reject("alsoKnownAs must not change");
    }

    let mut expected_methods = inputs.current_verification_methods.clone();
    expected_methods.remove(SPACE_VERIFICATION_METHOD_ID);
    expected_methods.insert(KEM_VERIFICATION_METHOD_ID.to_string(), staged.clone());
    if inputs.proposed_verification_methods != expected_methods {
        return reject(
            "verificationMethods may only set atproto_kem to the staged key and drop atproto_space",
        );
    }

    let mut expected_services = inputs.current_services.clone();
    expected_services.remove(SPACE_HOST_SERVICE_ID);
    if inputs.proposed_services != expected_services {
        return reject("services may only drop atproto_space_host");
    }

    Ok(())
}

// ── Pure composers ───────────────────────────────────────────────────────────

/// The did:plc `verificationMethods` a KEM op proposes: the current map, retired
/// `atproto_space` removed, `atproto_kem` set to the staged key.
pub fn propose_kem_verification_methods(
    current: &BTreeMap<String, String>,
    staged_key_id: &str,
) -> BTreeMap<String, String> {
    let mut methods = current.clone();
    methods.remove(SPACE_VERIFICATION_METHOD_ID);
    methods.insert(
        KEM_VERIFICATION_METHOD_ID.to_string(),
        staged_key_id.to_string(),
    );
    methods
}

/// The did:plc `services` a KEM op proposes: the current map without `atproto_space_host`.
pub fn propose_kem_services(
    current: &BTreeMap<String, PlcService>,
) -> BTreeMap<String, PlcService> {
    let mut services = current.clone();
    services.remove(SPACE_HOST_SERVICE_ID);
    services
}

/// What an update changes, for the review screen. The same shape serves both DID methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KemKeyDiff {
    /// The KEM key being published (`did:key:z…`).
    pub kem_key: String,
    /// The KEM key it replaces, when this is a rotation rather than a first publish.
    pub replaced_kem_key: Option<String>,
    /// The retired `atproto_space` key being removed, when present.
    pub removed_space_key: Option<String>,
    /// The retired `atproto_space_host` endpoint being removed, when present.
    pub removed_space_host: Option<String>,
}

/// The did:plc review diff, read off the current state. Pure.
pub fn build_kem_diff(
    current_verification_methods: &BTreeMap<String, String>,
    current_services: &BTreeMap<String, PlcService>,
    staged_key_id: &str,
) -> KemKeyDiff {
    KemKeyDiff {
        kem_key: staged_key_id.to_string(),
        replaced_kem_key: current_verification_methods
            .get(KEM_VERIFICATION_METHOD_ID)
            .cloned(),
        removed_space_key: current_verification_methods
            .get(SPACE_VERIFICATION_METHOD_ID)
            .cloned(),
        removed_space_host: current_services
            .get(SPACE_HOST_SERVICE_ID)
            .map(|service| service.endpoint.clone()),
    }
}

/// Whether a did:web document entry's `id` names `fragment`, in either the relative
/// (`#frag`) or absolute (`did:web:host#frag`) spelling.
fn names_fragment(entry: &serde_json::Value, did: &str, fragment: &str) -> bool {
    entry
        .get("id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| id.strip_prefix(did).unwrap_or(id) == format!("#{fragment}"))
}

/// Rewrite a self-hosted did:web document to publish `staged_key_id` as `#atproto_kem`: drop
/// any existing `#atproto_kem` and the retired `#atproto_space` method and
/// `#atproto_space_host` service, append the new method, and leave every other field and
/// entry exactly as it was. Returns the new document and the review diff. Pure.
///
/// This is the did:web counterpart of [`guard_kem_op`]: the document is the user's own, so
/// the rewrite is built to touch nothing else rather than checked after the fact.
pub fn did_web_document_with_kem_key(
    document: &serde_json::Value,
    did: &str,
    staged_key_id: &str,
) -> Result<(serde_json::Value, KemKeyDiff), KemKeyError> {
    let invalid = |message: &str| KemKeyError::InvalidDidDocument {
        message: message.to_string(),
    };
    if document.get("id").and_then(serde_json::Value::as_str) != Some(did) {
        return Err(invalid("the live did.json does not name this DID"));
    }
    let methods = match document.get("verificationMethod") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .cloned()
            .ok_or_else(|| invalid("verificationMethod is not an array"))?,
    };
    let key_of = |fragment: &str| {
        methods
            .iter()
            .find(|m| names_fragment(m, did, fragment))
            .and_then(|m| m.get("publicKeyMultibase"))
            .and_then(serde_json::Value::as_str)
            .map(|multibase| format!("did:key:{multibase}"))
    };
    let replaced_kem_key = key_of(KEM_VERIFICATION_METHOD_ID);
    if replaced_kem_key.as_deref() == Some(staged_key_id) {
        return Err(KemKeyError::GuardRejected {
            reason: "the staged KEM key is already published".to_string(),
        });
    }
    let removed_space_key = key_of(SPACE_VERIFICATION_METHOD_ID);

    let mut updated = document.clone();
    let mut kept: Vec<serde_json::Value> = methods
        .iter()
        .filter(|m| {
            !names_fragment(m, did, KEM_VERIFICATION_METHOD_ID)
                && !names_fragment(m, did, SPACE_VERIFICATION_METHOD_ID)
        })
        .cloned()
        .collect();
    kept.push(serde_json::json!({
        "id": format!("#{KEM_VERIFICATION_METHOD_ID}"),
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": crate::migrate::multibase(staged_key_id),
    }));
    updated["verificationMethod"] = serde_json::Value::Array(kept);

    let mut removed_space_host = None;
    if let Some(services) = updated
        .get_mut("service")
        .and_then(serde_json::Value::as_array_mut)
    {
        removed_space_host = services
            .iter()
            .find(|s| names_fragment(s, did, SPACE_HOST_SERVICE_ID))
            .and_then(|s| s.get("serviceEndpoint"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        services.retain(|s| !names_fragment(s, did, SPACE_HOST_SERVICE_ID));
    }

    Ok((
        updated,
        KemKeyDiff {
            kem_key: staged_key_id.to_string(),
            replaced_kem_key,
            removed_space_key,
            removed_space_host,
        },
    ))
}

// ── Output types / pending state ─────────────────────────────────────────────

/// What `prepare` produced, and so what the review screen shows.
#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum KemKeyPlan {
    /// did:plc: a signed op is parked, waiting for the user's approval.
    PlcOperation { diff: KemKeyDiff },
    /// Self-hosted did:web: the updated `did.json` to export and upload before `complete`.
    DidWebDocument {
        diff: KemKeyDiff,
        document_text: String,
        document_url: String,
    },
    /// Custos-hosted did:web: Custos published the key while staging it. Nothing to complete.
    Published { kem_key: String },
}

/// A prepared update, held between prepare and complete. `signed_op` is the did:plc op;
/// a did:web update parks with `None`, because `complete` sends nothing for it.
pub struct KemKeyState {
    pub did: String,
    pub signed_op: Option<serde_json::Value>,
}

// ── PDS ceremony calls ───────────────────────────────────────────────────────

/// The `POST /v1/kem-key` answer: the key, and whether it still needs publishing.
#[derive(Debug, PartialEq, Eq)]
pub struct StagedKemKey {
    pub kem_key: String,
    pub published: bool,
}

async fn rejection(response: reqwest::Response) -> KemKeyError {
    classify_host_rejection(response, |status, message| KemKeyError::KemKeyFailed {
        status,
        message,
    })
    .await
}

fn network(context: &str, e: impl std::fmt::Display) -> KemKeyError {
    SharedFailure::NetworkError {
        message: format!("{context}: {e}"),
    }
    .into()
}

/// `POST /v1/kem-key`: Custos mints a fresh key every time, replacing anything staged
/// before, so re-running prepare is safe.
pub async fn stage_kem_key_on_pds(
    session: &crate::oauth_client::OAuthClient,
) -> Result<StagedKemKey, KemKeyError> {
    let response = session
        .post_no_body("/v1/kem-key")
        .await
        .map_err(|e| network("KEM key stage request failed", e))?;
    if !response.status().is_success() {
        return Err(rejection(response).await);
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| network("failed to read KEM key stage response", e))?;
    let kem_key = body
        .get("kemKey")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SharedFailure::InvalidResponse {
            message: "KEM key stage response is missing kemKey".to_string(),
        })?
        .to_string();
    let published = body.get("status").and_then(serde_json::Value::as_str) == Some("published");
    Ok(StagedKemKey { kem_key, published })
}

/// `POST /v1/kem-key/complete`, carrying the signed op for a did:plc and nothing for a
/// did:web.
pub async fn complete_kem_key_on_pds(
    session: &crate::oauth_client::OAuthClient,
    signed_op: Option<&serde_json::Value>,
) -> Result<(), KemKeyError> {
    let body = match signed_op {
        Some(op) => serde_json::json!({ "operation": op }),
        None => serde_json::json!({}),
    };
    let response = session
        .post("/v1/kem-key/complete", &body)
        .await
        .map_err(|e| network("KEM key complete request failed", e))?;
    if !response.status().is_success() {
        return Err(rejection(response).await);
    }
    Ok(())
}

/// Fetch the live `did.json` a hostname-form did:web serves.
async fn fetch_live_did_web(core: &crate::oauth::Core, did: &str) -> Result<String, KemKeyError> {
    let url =
        crate::migrate::did_web_document_url(did).map_err(|_| KemKeyError::UnsupportedIdentity)?;
    core.pds_client()
        .client()
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| network("failed to fetch the live did.json", e))?
        .text()
        .await
        .map_err(|e| network("failed to read the live did.json", e))
}

// ── Imperative shell: prepare + complete ─────────────────────────────────────

/// Stage a fresh KEM key and prepare its publication, returning the plan and the op to park
/// (did:plc only).
pub async fn prepare_kem_key_publish(
    core: &crate::oauth::Core,
    did: &str,
) -> Result<(KemKeyPlan, Option<serde_json::Value>), KemKeyError> {
    if !did.starts_with("did:plc:") && !did.starts_with("did:web:") {
        return Err(KemKeyError::UnsupportedIdentity);
    }

    // 1. A full-access session on the hosting PDS (KEM calls are owner-only).
    let session = SessionProvider.full_access_client(core, did).await?;

    // 2. Ask Custos to mint and hold the new key. Only its public half comes back.
    let staged = stage_kem_key_on_pds(&session.client).await?;

    if did.starts_with("did:web:") {
        // A Custos-hosted document was rewritten during staging; nothing is left to do.
        if staged.published {
            return Ok((
                KemKeyPlan::Published {
                    kem_key: staged.kem_key,
                },
                None,
            ));
        }
        // 3w. Start from what the domain serves right now, so the user's own edits survive.
        let live = fetch_live_did_web(core, did).await?;
        let document: serde_json::Value =
            serde_json::from_str(&live).map_err(|_| KemKeyError::InvalidDidDocument {
                message: "the live did.json is not valid JSON".to_string(),
            })?;
        let (updated, diff) = did_web_document_with_kem_key(&document, did, &staged.kem_key)?;
        let document_text = format!(
            "{}\n",
            serde_json::to_string_pretty(&updated).map_err(|e| {
                KemKeyError::InvalidDidDocument {
                    message: e.to_string(),
                }
            })?
        );
        let document_url = crate::migrate::did_web_document_url(did)
            .map_err(|_| KemKeyError::UnsupportedIdentity)?;
        return Ok((
            KemKeyPlan::DidWebDocument {
                diff,
                document_text,
                document_url,
            },
            None,
        ));
    }

    // did:plc from here. Staging a did:plc never publishes; a server that says otherwise is
    // not the ceremony this wallet speaks.
    if staged.published {
        return Err(SharedFailure::InvalidResponse {
            message: "server reported a did:plc KEM key as already published".to_string(),
        }
        .into());
    }

    // 3p. The device key that will sign (rotationKeys[0] for a wallet-custodied identity).
    let device_key_id = core
        .identities()
        .get_or_create_device_key(did)
        .map_err(SharedFailure::from)?
        .key_id;

    // 4p. The DID's current state: the op chains onto its newest entry (`prev`).
    let log_json = core
        .pds_client()
        .fetch_audit_log(did)
        .await
        .map_err(|e| SharedFailure::from_plc_fetch("failed to fetch audit log", e))?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| KemKeyError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let current = latest_full_state(&audit_log).map_err(|e| KemKeyError::InvalidAuditLog {
        message: e.to_string(),
    })?;

    // 5p. Compose: everything carried over, except the KEM entry and the retired space ones.
    let proposed_methods =
        propose_kem_verification_methods(&current.verification_methods, &staged.kem_key);
    let proposed_services = propose_kem_services(&current.services);

    // 6p. The strict allowlist. Nothing is signed unless it passes.
    guard_kem_op(&KemOpInputs {
        device_key_id,
        staged_key_id: staged.kem_key.clone(),
        current_rotation_keys: current.rotation_keys.clone(),
        proposed_rotation_keys: current.rotation_keys.clone(),
        current_verification_methods: current.verification_methods.clone(),
        proposed_verification_methods: proposed_methods.clone(),
        current_services: current.services.clone(),
        proposed_services: proposed_services.clone(),
        current_also_known_as: current.also_known_as.clone(),
        proposed_also_known_as: current.also_known_as.clone(),
    })?;

    // 7p. Sign with the device key. The op stays on the phone until the user approves.
    let sign_closure = crate::identity_store::per_did_sign_closure(core.signer(), did)
        .map_err(|e| e.classify(|message| KemKeyError::SigningFailed { message }))?;
    let signed = crypto::build_did_plc_rotation_op(
        &current.prev_cid,
        current.rotation_keys.clone(),
        proposed_methods,
        current.also_known_as.clone(),
        proposed_services,
        sign_closure,
    )
    .map_err(|e| KemKeyError::SigningFailed {
        message: format!("failed to build KEM key op: {e}"),
    })?;
    let signed_op: serde_json::Value =
        serde_json::from_str(&signed.signed_op_json).map_err(|e| KemKeyError::SigningFailed {
            message: format!("failed to parse signed op JSON: {e}"),
        })?;

    let diff = build_kem_diff(
        &current.verification_methods,
        &current.services,
        &staged.kem_key,
    );
    Ok((KemKeyPlan::PlcOperation { diff }, Some(signed_op)))
}

/// Hand the prepared update to Custos and refresh the cached DID document.
pub async fn complete_kem_key_publish(
    core: &crate::oauth::Core,
    did: &str,
    signed_op: Option<&serde_json::Value>,
) -> Result<ClaimResult, KemKeyError> {
    let session = SessionProvider.full_access_client(core, did).await?;
    complete_kem_key_on_pds(&session.client, signed_op).await?;

    let store_failed = |message| KemKeyError::SigningFailed { message };
    if did.starts_with("did:plc:") {
        let did_doc = refresh_cached_plc_state(core, did, store_failed).await?;
        return Ok(ClaimResult {
            updated_did_doc: did_doc,
        });
    }

    // did:web: Custos just checked the live copy; cache the same bytes it saw.
    let live = fetch_live_did_web(core, did).await?;
    let did_doc = serde_json::from_str(&live).map_err(|_| KemKeyError::InvalidDidDocument {
        message: "the live did.json is not valid JSON".to_string(),
    })?;
    core.identities()
        .store_did_doc(did, &live)
        .map_err(|e| store_failed(format!("failed to cache updated DID document: {e}")))?;
    Ok(ClaimResult {
        updated_did_doc: did_doc,
    })
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: stage the key and prepare the update for review.
pub async fn prepare_kem_key_publish_cmd(
    state: &crate::oauth::Core,
    did: String,
) -> Result<KemKeyPlan, KemKeyError> {
    let (plan, signed_op) = prepare_kem_key_publish(state, &did).await?;
    let mut pending = state.kem_key_state.lock().await;
    *pending = match plan {
        KemKeyPlan::Published { .. } => None,
        _ => Some(KemKeyState {
            did: did.clone(),
            signed_op,
        }),
    };
    Ok(plan)
}

/// Tauri command: publish the prepared update. The parked state is cleared only on success,
/// so a failed call can simply be retried.
pub async fn complete_kem_key_publish_cmd(
    state: &crate::oauth::Core,
    did: String,
) -> Result<ClaimResult, KemKeyError> {
    let signed_op = {
        let pending = state.kem_key_state.lock().await;
        match pending.as_ref() {
            Some(update) if update.did == did => update.signed_op.clone(),
            _ => return Err(KemKeyError::NoPendingKemKey),
        }
    };

    let result = complete_kem_key_publish(state, &did, signed_op.as_ref()).await?;

    let mut pending = state.kem_key_state.lock().await;
    if pending.as_ref().is_some_and(|u| u.did == did) {
        *pending = None;
    }
    Ok(result)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DEVICE: &str = "did:key:zDEVICE";
    const PDS_KEY: &str = "did:key:zPDS";
    const STAGED: &str = "did:key:zSTAGEDKEM";
    const OLD_KEM: &str = "did:key:zOLDKEM";
    const SPACE_KEY: &str = "did:key:zSPACE";

    fn pds_service(endpoint: &str) -> PlcService {
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: endpoint.to_string(),
        }
    }

    fn current_methods() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("atproto".to_string(), PDS_KEY.to_string()),
            (
                SPACE_VERIFICATION_METHOD_ID.to_string(),
                SPACE_KEY.to_string(),
            ),
        ])
    }

    fn current_services() -> BTreeMap<String, PlcService> {
        BTreeMap::from([
            (
                "atproto_pds".to_string(),
                pds_service("https://pds.example"),
            ),
            (
                SPACE_HOST_SERVICE_ID.to_string(),
                PlcService {
                    service_type: "AtprotoSpaceHost".to_string(),
                    endpoint: "https://pds.example".to_string(),
                },
            ),
        ])
    }

    /// The op the shell composes for an account that still carries the retired entries.
    fn ok_inputs() -> KemOpInputs {
        let methods = current_methods();
        let services = current_services();
        KemOpInputs {
            device_key_id: DEVICE.to_string(),
            staged_key_id: STAGED.to_string(),
            current_rotation_keys: vec![DEVICE.to_string(), PDS_KEY.to_string()],
            proposed_rotation_keys: vec![DEVICE.to_string(), PDS_KEY.to_string()],
            proposed_verification_methods: propose_kem_verification_methods(&methods, STAGED),
            current_verification_methods: methods,
            proposed_services: propose_kem_services(&services),
            current_services: services,
            current_also_known_as: vec!["at://alice.example".to_string()],
            proposed_also_known_as: vec!["at://alice.example".to_string()],
        }
    }

    fn rejected(inputs: &KemOpInputs) -> bool {
        matches!(guard_kem_op(inputs), Err(KemKeyError::GuardRejected { .. }))
    }

    // ── Guard ────────────────────────────────────────────────────────────────

    #[test]
    fn guard_accepts_the_composed_op() {
        guard_kem_op(&ok_inputs()).expect("the composed op is exactly the allowed change");
    }

    #[test]
    fn guard_accepts_a_rotation_of_an_already_published_key() {
        let mut inputs = ok_inputs();
        inputs
            .current_verification_methods
            .insert(KEM_VERIFICATION_METHOD_ID.into(), OLD_KEM.into());
        inputs.proposed_verification_methods =
            propose_kem_verification_methods(&inputs.current_verification_methods, STAGED);
        guard_kem_op(&inputs).expect("replacing the KEM key is allowed");
    }

    #[test]
    fn guard_requires_a_device_key_in_the_rotation_set() {
        let mut inputs = ok_inputs();
        inputs.current_rotation_keys = vec![PDS_KEY.to_string()];
        inputs.proposed_rotation_keys = inputs.current_rotation_keys.clone();
        assert!(matches!(
            guard_kem_op(&inputs),
            Err(KemKeyError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_republishing_the_same_key() {
        let mut inputs = ok_inputs();
        inputs
            .current_verification_methods
            .insert(KEM_VERIFICATION_METHOD_ID.into(), STAGED.into());
        assert!(rejected(&inputs));
    }

    #[test]
    fn guard_rejects_a_kem_key_that_is_a_signing_or_rotation_key() {
        for reused in [DEVICE, PDS_KEY] {
            let mut inputs = ok_inputs();
            inputs.staged_key_id = reused.to_string();
            inputs.proposed_verification_methods =
                propose_kem_verification_methods(&inputs.current_verification_methods, reused);
            assert!(rejected(&inputs), "{reused} must not become the KEM key");
        }
    }

    #[test]
    fn guard_rejects_a_kem_entry_pointing_elsewhere() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_verification_methods
            .insert(KEM_VERIFICATION_METHOD_ID.into(), "did:key:zEVIL".into());
        assert!(rejected(&inputs));
    }

    #[test]
    fn guard_rejects_moving_the_signing_key() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_verification_methods
            .insert("atproto".into(), "did:key:zEVIL".into());
        assert!(rejected(&inputs));
    }

    #[test]
    fn guard_rejects_keeping_the_retired_space_method() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_verification_methods
            .insert(SPACE_VERIFICATION_METHOD_ID.into(), SPACE_KEY.into());
        assert!(rejected(&inputs));
    }

    #[test]
    fn guard_rejects_dropping_an_unrelated_method() {
        let mut inputs = ok_inputs();
        inputs
            .current_verification_methods
            .insert("other".into(), "did:key:zOTHER".into());
        assert!(rejected(&inputs), "the proposal silently lost `other`");
    }

    #[test]
    fn guard_rejects_any_rotation_key_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys.push("did:key:zEVIL".into());
        assert!(rejected(&inputs));
        let mut inputs = ok_inputs();
        inputs.proposed_rotation_keys.reverse();
        assert!(rejected(&inputs));
    }

    #[test]
    fn guard_rejects_a_service_change_beyond_the_space_host() {
        let mut inputs = ok_inputs();
        inputs
            .proposed_services
            .insert("atproto_pds".into(), pds_service("https://evil.example"));
        assert!(rejected(&inputs));
        let mut inputs = ok_inputs();
        inputs.proposed_services = inputs.current_services.clone();
        assert!(rejected(&inputs), "the retired space host must go");
    }

    #[test]
    fn guard_rejects_a_handle_change() {
        let mut inputs = ok_inputs();
        inputs.proposed_also_known_as = vec!["at://mallory.example".into()];
        assert!(rejected(&inputs));
    }

    #[test]
    fn diff_names_what_leaves_and_what_arrives() {
        let mut methods = current_methods();
        methods.insert(KEM_VERIFICATION_METHOD_ID.into(), OLD_KEM.into());
        let diff = build_kem_diff(&methods, &current_services(), STAGED);
        assert_eq!(
            diff,
            KemKeyDiff {
                kem_key: STAGED.into(),
                replaced_kem_key: Some(OLD_KEM.into()),
                removed_space_key: Some(SPACE_KEY.into()),
                removed_space_host: Some("https://pds.example".into()),
            }
        );
    }

    // ── The did:plc ceremony, end to end through both commands ───────────────

    const PLC_DID: &str = "did:plc:kemwalletaaaaaaaaaaaaaaa";
    const SERVER_DID: &str = "did:web:pds.example.com";
    const NOW: u64 = 1_720_000_000;

    /// An unsigned Bearer JWT for `PLC_DID`. Its `exp` is far off because the HTTP client
    /// checks it against the real clock; the session record's expiry, checked against the
    /// test clock, is what the session provider reads.
    fn session_jwt() -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let claims = json!({ "exp": 9_999_999_999u64, "sub": PLC_DID, "aud": SERVER_DID });
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    /// An account created before KEM keys existed: no `atproto_kem`, still carrying the
    /// retired space entries, its device key at `rotationKeys[0]`. One mock server plays
    /// both Custos and plc.directory.
    #[tokio::test]
    async fn an_existing_did_plc_account_publishes_its_kem_key() {
        let server = httpmock::MockServer::start_async().await;
        let core = crate::test_support::core_at(NOW)
            .with_pds_client(crate::pds_client::new_for_test(server.base_url()));
        let store = core.identities();
        store.add_identity(PLC_DID).unwrap();
        store
            .store_oauth_tokens(
                PLC_DID,
                &crate::identity_store::SovereignTokenRecord {
                    version: crate::identity_store::SovereignTokenRecord::VERSION,
                    access_jwt: session_jwt(),
                    refresh_jwt: session_jwt(),
                    pds_url: server.base_url(),
                    server_did: SERVER_DID.into(),
                    access_expires_at: Some(NOW + 3_600),
                    refresh_expires_at: Some(NOW + 86_400),
                    stored_at: NOW,
                },
            )
            .unwrap();
        let device = store.get_or_create_device_key(PLC_DID).unwrap().key_id;

        let head = json!({
            "type": "plc_operation",
            "prev": null,
            "sig": "genesis",
            "rotationKeys": [device, PDS_KEY],
            "verificationMethods": { "atproto": PDS_KEY, "atproto_space": SPACE_KEY },
            "alsoKnownAs": ["at://alice.example"],
            "services": {
                "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": server.base_url() },
                "atproto_space_host": { "type": "AtprotoSpaceHost", "endpoint": server.base_url() }
            }
        });
        let audit_log = json!([{
            "did": PLC_DID, "cid": "bafyreihead", "nullified": false,
            "createdAt": "2026-01-01T00:00:00Z", "operation": head
        }]);
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST).path("/v1/kem-key");
                then.status(200)
                    .json_body(json!({ "kemKey": STAGED, "status": "staged" }));
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET)
                    .path(format!("/{PLC_DID}/log/audit"));
                then.status(200).json_body(audit_log.clone());
            })
            .await;

        // Prepare: nothing is sent anywhere but the stage call; the signed op is parked.
        let plan = prepare_kem_key_publish_cmd(&core, PLC_DID.into())
            .await
            .unwrap();
        let KemKeyPlan::PlcOperation { diff } = plan else {
            panic!("a did:plc prepares an op, got {plan:?}");
        };
        assert_eq!(diff.kem_key, STAGED);
        assert_eq!(diff.removed_space_key.as_deref(), Some(SPACE_KEY));
        let parked = core
            .kem_key_state
            .lock()
            .await
            .as_ref()
            .unwrap()
            .signed_op
            .clone();
        let parked = parked.expect("a did:plc parks its op");

        // The parked op is signed by the device key and makes only the allowed change.
        let verified =
            crypto::verify_plc_operation(&parked.to_string(), &[crypto::DidKeyUri(device.clone())])
                .unwrap();
        assert_eq!(verified.prev.as_deref(), Some("bafyreihead"));
        assert_eq!(
            verified.rotation_keys,
            vec![device.clone(), PDS_KEY.to_string()]
        );
        assert_eq!(
            verified.verification_methods,
            BTreeMap::from([
                ("atproto".to_string(), PDS_KEY.to_string()),
                (KEM_VERIFICATION_METHOD_ID.to_string(), STAGED.to_string()),
            ])
        );
        assert_eq!(
            verified.services.keys().collect::<Vec<_>>(),
            ["atproto_pds"]
        );

        // Complete: the op goes to Custos (never plc.directory), then the cache refreshes.
        let complete = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST)
                    .path("/v1/kem-key/complete")
                    .json_body(json!({ "operation": parked }));
                then.status(200)
                    .json_body(json!({ "kemKey": STAGED, "status": "published" }));
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET)
                    .path(format!("/{PLC_DID}/data"));
                then.status(200).json_body(json!({
                    "did": PLC_DID,
                    "rotationKeys": [device, PDS_KEY],
                    "verificationMethods": { "atproto": PDS_KEY, "atproto_kem": STAGED },
                    "alsoKnownAs": ["at://alice.example"],
                    "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": server.base_url() } }
                }));
            })
            .await;
        let result = complete_kem_key_publish_cmd(&core, PLC_DID.into())
            .await
            .unwrap();
        complete.assert_async().await;
        assert_eq!(
            result.updated_did_doc["verificationMethods"]["atproto_kem"],
            STAGED
        );
        assert!(
            core.kem_key_state.lock().await.is_none(),
            "a published update is no longer pending"
        );
        assert!(matches!(
            complete_kem_key_publish_cmd(&core, PLC_DID.into()).await,
            Err(KemKeyError::NoPendingKemKey)
        ));
    }

    // ── did:web document rewrite ─────────────────────────────────────────────

    const WEB_DID: &str = "did:web:alice.example";

    fn live_document() -> serde_json::Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": WEB_DID,
            "alsoKnownAs": ["at://alice.example"],
            "verificationMethod": [
                { "id": "#device", "type": "Multikey", "controller": WEB_DID, "publicKeyMultibase": "zDEVICE" },
                { "id": "#atproto", "type": "Multikey", "controller": WEB_DID, "publicKeyMultibase": "zPDS" },
                { "id": format!("{WEB_DID}#atproto_space"), "type": "Multikey", "controller": WEB_DID, "publicKeyMultibase": "zSPACE" }
            ],
            "service": [
                { "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://pds.example" },
                { "id": "#atproto_space_host", "type": "AtprotoSpaceHost", "serviceEndpoint": "https://pds.example" }
            ],
            "x-user-field": "kept"
        })
    }

    #[test]
    fn did_web_rewrite_adds_the_key_and_drops_the_retired_entries() {
        let (updated, diff) =
            did_web_document_with_kem_key(&live_document(), WEB_DID, STAGED).unwrap();
        let ids = |field: &str| -> Vec<String> {
            updated[field]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["id"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            ids("verificationMethod"),
            ["#device", "#atproto", "#atproto_kem"]
        );
        assert_eq!(ids("service"), ["#atproto_pds"]);
        assert_eq!(
            updated["verificationMethod"][2]["publicKeyMultibase"],
            "zSTAGEDKEM"
        );
        assert_eq!(updated["x-user-field"], "kept", "unrelated fields survive");
        assert_eq!(updated["alsoKnownAs"], live_document()["alsoKnownAs"]);
        assert_eq!(
            diff,
            KemKeyDiff {
                kem_key: STAGED.into(),
                replaced_kem_key: None,
                removed_space_key: Some(SPACE_KEY.into()),
                removed_space_host: Some("https://pds.example".into()),
            }
        );
    }

    #[test]
    fn did_web_rewrite_replaces_an_existing_kem_key() {
        let (once, _) = did_web_document_with_kem_key(&live_document(), WEB_DID, OLD_KEM).unwrap();
        let (twice, diff) = did_web_document_with_kem_key(&once, WEB_DID, STAGED).unwrap();
        let kem_entries: Vec<_> = twice["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["id"] == "#atproto_kem")
            .collect();
        assert_eq!(kem_entries.len(), 1);
        assert_eq!(kem_entries[0]["publicKeyMultibase"], "zSTAGEDKEM");
        assert_eq!(diff.replaced_kem_key.as_deref(), Some(OLD_KEM));
    }

    #[test]
    fn did_web_rewrite_refuses_someone_elses_document() {
        assert!(matches!(
            did_web_document_with_kem_key(&live_document(), "did:web:mallory.example", STAGED),
            Err(KemKeyError::InvalidDidDocument { .. })
        ));
    }

    #[test]
    fn did_web_rewrite_refuses_a_no_op() {
        let (once, _) = did_web_document_with_kem_key(&live_document(), WEB_DID, STAGED).unwrap();
        assert!(matches!(
            did_web_document_with_kem_key(&once, WEB_DID, STAGED),
            Err(KemKeyError::GuardRejected { .. })
        ));
    }

    // ── The PDS ceremony calls ───────────────────────────────────────────────

    fn client_for(server: &httpmock::MockServer) -> crate::oauth_client::OAuthClient {
        crate::oauth_client::bearer_for_test(&session_jwt(), server.base_url())
    }

    #[tokio::test]
    async fn stage_reads_the_key_and_its_status() {
        let server = httpmock::MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST).path("/v1/kem-key");
                then.status(200)
                    .json_body(json!({ "kemKey": STAGED, "status": "staged" }));
            })
            .await;
        let staged = stage_kem_key_on_pds(&client_for(&server)).await.unwrap();
        assert_eq!(
            staged,
            StagedKemKey {
                kem_key: STAGED.into(),
                published: false
            }
        );
    }

    #[tokio::test]
    async fn complete_sends_the_op_for_plc_and_nothing_for_web() {
        let server = httpmock::MockServer::start_async().await;
        let op = json!({ "type": "plc_operation", "sig": "x" });
        let with_op = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST)
                    .path("/v1/kem-key/complete")
                    .json_body(json!({ "operation": { "type": "plc_operation", "sig": "x" } }));
                then.status(200)
                    .json_body(json!({ "kemKey": STAGED, "status": "published" }));
            })
            .await;
        complete_kem_key_on_pds(&client_for(&server), Some(&op))
            .await
            .unwrap();
        with_op.assert_async().await;

        let server = httpmock::MockServer::start_async().await;
        let empty = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST)
                    .path("/v1/kem-key/complete")
                    .json_body(json!({}));
                then.status(200)
                    .json_body(json!({ "kemKey": STAGED, "status": "published" }));
            })
            .await;
        complete_kem_key_on_pds(&client_for(&server), None)
            .await
            .unwrap();
        empty.assert_async().await;
    }

    #[tokio::test]
    async fn a_refused_complete_carries_the_server_status() {
        let server = httpmock::MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST).path("/v1/kem-key/complete");
                then.status(400).json_body(json!({
                    "error": "InvalidRequest",
                    "message": "published did:web document does not carry the staged KEM key as #atproto_kem"
                }));
            })
            .await;
        match complete_kem_key_on_pds(&client_for(&server), None).await {
            Err(KemKeyError::KemKeyFailed { status, .. }) => assert_eq!(status, 400),
            other => panic!("expected KEM_KEY_FAILED, got {other:?}"),
        }
    }
}
