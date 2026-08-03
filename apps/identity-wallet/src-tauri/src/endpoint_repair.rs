// pattern: Mixed (Functional Core guard/normalizer; Imperative Shell command)

//! The sovereign "repair hosting endpoint" flow for a wallet-custodied did:plc — one
//! Tauri IPC command, `repair_hosting_endpoint(did, new_endpoint)`: rewrite
//! `services.atproto_pds.endpoint` to the hosting server's new public URL after the
//! server changes hostname underneath the account (the DID doc then points at a dead
//! host, so every client misroutes). On a reference PDS this would be a server-signed
//! `signPlcOperation`, but that route is gated behind a full-access session — which a
//! passwordless account can only mint against the very endpoint that just died. So
//! the wallet device-key-signs the op itself and submits DIRECTLY to plc.directory:
//! the only network dependencies are plc.directory and the NEW endpoint, never the
//! dead one.
//!
//! The new endpoint is normalized to a bare https origin (`normalize_endpoint`) and
//! probed via the public `com.atproto.sync.getRepoStatus` to prove it actually hosts
//! this DID before anything signs (`DESTINATION_NOT_HOSTING` otherwise).
//!
//! `guard_endpoint_repair` is the SIXTH strict wallet allowlist and the narrowest
//! service mutation: ONLY the `atproto_pds` endpoint string may change. rotationKeys
//! (the sovereignty anchor), verificationMethods, alsoKnownAs, every other service,
//! and even the `atproto_pds` service TYPE must be re-signed byte-for-byte unchanged;
//! and a no-op endpoint must reconcile rather than sign — an already-correct document
//! returns success with `opCid: null`. A migration op (`migrate::guard_migration_op`)
//! also rewrites keys; a repair must never touch them — the hosting server did not
//! change, only its name did.
//!
//! `EndpointRepairError` (WALLET_NOT_AUTHORIZED, INVALID_ENDPOINT,
//! DESTINATION_UNREACHABLE, DESTINATION_NOT_HOSTING, GUARD_REJECTED,
//! INVALID_AUDIT_LOG, SIGNING_FAILED, PLC_DIRECTORY_ERROR, RATE_LIMITED,
//! NETWORK_ERROR, IDENTITY_NOT_FOUND) serializes as
//! `{ code: "SCREAMING_SNAKE_CASE" }` with camelCase fields. The frontend gates
//! `repairHostingEndpoint` behind `authenticateBiometric()`; the screen is reached
//! from the Advanced tools "Repair hosting endpoint" row, behind the vestibule
//! (root-key did:plc only).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::handle_change::latest_full_state;
use crate::identity_store::{IdentityStore, PerDidSignError};
use crate::pds_client::{PdsClient, PdsClientError};
use crypto::PlcService;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the sovereign endpoint-repair flow.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling
/// wallet error enums (`HandleChangeError`, `MigrateError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum EndpointRepairError {
    /// The wallet holds no authorized key in the DID's current rotationKeys, so it
    /// cannot self-sign the repair op.
    #[error("wallet is not authorized to self-sign for this DID (no device key in current rotationKeys)")]
    WalletNotAuthorized,
    /// The proposed endpoint URL is not https (loopback excepted) or not a valid URL.
    #[error("endpoint URL is invalid or insecure: {message}")]
    InvalidEndpoint { message: String },
    /// The new endpoint is unreachable or is not an atproto PDS.
    #[error("new endpoint is unreachable: {message}")]
    DestinationUnreachable { message: String },
    /// The new endpoint answers, but does not host this account.
    #[error("new endpoint does not host this account: {message}")]
    DestinationNotHosting { message: String },
    /// The strict pre-sign allowlist rejected the proposed operation.
    #[error("endpoint-repair operation rejected by pre-sign guard: {reason}")]
    GuardRejected { reason: String },
    /// The audit log could not be parsed or contained no usable current state.
    #[error("invalid audit log: {message}")]
    InvalidAuditLog { message: String },
    /// Local signing failed.
    #[error("signing failed: {message}")]
    SigningFailed { message: String },
    /// plc.directory rejected a request with an HTTP verdict.
    #[error("PLC directory error: {message}")]
    PlcDirectoryError { message: String },
    /// plc.directory or the new endpoint rate-limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// A network / transport call failed.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The DID's device key or identity record could not be found.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
}

/// Map a plc.directory read/submit failure into the repair surface: a throttle is
/// retryable (`RateLimited`), an HTTP verdict is the directory's problem
/// (`PlcDirectoryError`), and only a transport failure is `NetworkError`.
fn map_plc_error(context: &str, error: PdsClientError) -> EndpointRepairError {
    match error {
        PdsClientError::RateLimited { retry_after, .. } => {
            EndpointRepairError::RateLimited { retry_after }
        }
        PdsClientError::XrpcError {
            status, message, ..
        } => EndpointRepairError::PlcDirectoryError {
            message: format!("{context}: plc.directory returned HTTP {status}: {message}"),
        },
        // A 404 on the audit log is the directory's definite "no such DID" verdict.
        PdsClientError::DidNotFound => EndpointRepairError::PlcDirectoryError {
            message: format!("{context}: plc.directory has no record of this DID"),
        },
        // `post_plc_operation` reports a non-429 rejection body as InvalidResponse —
        // that is the directory refusing the operation, not a connectivity problem.
        PdsClientError::InvalidResponse { message, .. } => EndpointRepairError::PlcDirectoryError {
            message: format!("{context}: {message}"),
        },
        PdsClientError::Unauthorized { .. } => EndpointRepairError::PlcDirectoryError {
            message: format!("{context}: plc.directory returned HTTP 401"),
        },
        other => EndpointRepairError::NetworkError {
            message: format!("{context}: {other}"),
        },
    }
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

/// Normalize a proposed endpoint URL to the form a PLC `atproto_pds` service entry
/// carries: scheme + host (+ non-default port), no trailing slash, no path/query.
/// Rejects non-https schemes (loopback http excepted, for local development) and any
/// URL carrying a path, query, fragment, or userinfo — an endpoint is an origin.
pub(crate) fn normalize_endpoint(url: &str) -> Result<String, EndpointRepairError> {
    let parsed = url::Url::parse(url.trim()).map_err(|e| EndpointRepairError::InvalidEndpoint {
        message: format!("not a valid URL: {e}"),
    })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| EndpointRepairError::InvalidEndpoint {
            message: "URL has no host".to_string(),
        })?;
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(EndpointRepairError::InvalidEndpoint {
            message: "endpoint must be https".to_string(),
        });
    }
    if !parsed.username().is_empty()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(EndpointRepairError::InvalidEndpoint {
            message: "endpoint must be a bare origin (no path, query, or credentials)".to_string(),
        });
    }
    let mut origin = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        origin.push_str(&format!(":{port}"));
    }
    Ok(origin)
}

/// The facts the strict pre-sign guard needs. Flattened to plain values so the guard
/// is a pure, trivially-testable function (mirrors `HandleChangeInputs`).
#[derive(Debug, Clone)]
pub struct EndpointRepairInputs {
    /// The wallet's per-DID device key (`did:key:z...`). Must be in the current set.
    pub device_key_id: String,
    /// The DID's CURRENT rotation keys — must be preserved unchanged.
    pub current_rotation_keys: Vec<String>,
    /// The rotation keys we intend to put in the op — must EQUAL the current set.
    pub proposed_rotation_keys: Vec<String>,
    /// The DID's CURRENT verificationMethods — must be preserved unchanged.
    pub current_verification_methods: BTreeMap<String, String>,
    /// The verificationMethods we intend to put in the op — must EQUAL the current.
    pub proposed_verification_methods: BTreeMap<String, String>,
    /// The DID's CURRENT alsoKnownAs — must be preserved unchanged.
    pub current_also_known_as: Vec<String>,
    /// The alsoKnownAs we intend to put in the op — must EQUAL the current.
    pub proposed_also_known_as: Vec<String>,
    /// The DID's CURRENT services map.
    pub current_services: BTreeMap<String, PlcService>,
    /// The services we intend to put in the op.
    pub proposed_services: BTreeMap<String, PlcService>,
}

/// Reject the proposed endpoint-repair operation unless it satisfies the strict
/// allowlist. The device key can technically sign anything; safety comes entirely
/// from validating the INPUTS before a signature is produced.
///
/// Rules:
///  1. Authorization: `device_key_id` is present in `current_rotation_keys`.
///  2. Rotation keys unchanged (custody must not move on a rename).
///  3. Verification methods unchanged (the repo signing key must not move).
///  4. alsoKnownAs unchanged (a repair is not a handle change).
///  5. Services: same key set; every service except `atproto_pds` byte-identical;
///     `atproto_pds` keeps its service type and changes ONLY its endpoint string, to a
///     DIFFERENT value (a no-op repair must reconcile before the guard, not sign).
pub fn guard_endpoint_repair(inputs: &EndpointRepairInputs) -> Result<(), EndpointRepairError> {
    if !inputs.current_rotation_keys.contains(&inputs.device_key_id) {
        return Err(EndpointRepairError::WalletNotAuthorized);
    }
    if inputs.proposed_rotation_keys != inputs.current_rotation_keys {
        return Err(EndpointRepairError::GuardRejected {
            reason: "rotationKeys must be preserved across an endpoint repair".to_string(),
        });
    }
    if inputs.proposed_verification_methods != inputs.current_verification_methods {
        return Err(EndpointRepairError::GuardRejected {
            reason: "verificationMethods must be preserved across an endpoint repair".to_string(),
        });
    }
    if inputs.proposed_also_known_as != inputs.current_also_known_as {
        return Err(EndpointRepairError::GuardRejected {
            reason: "alsoKnownAs must be preserved across an endpoint repair".to_string(),
        });
    }

    let current_keys: Vec<&String> = inputs.current_services.keys().collect();
    let proposed_keys: Vec<&String> = inputs.proposed_services.keys().collect();
    if current_keys != proposed_keys {
        return Err(EndpointRepairError::GuardRejected {
            reason: "services may not be added or removed by an endpoint repair".to_string(),
        });
    }
    for (id, current) in &inputs.current_services {
        let proposed = &inputs.proposed_services[id];
        if id == "atproto_pds" {
            if proposed.service_type != current.service_type {
                return Err(EndpointRepairError::GuardRejected {
                    reason: "the atproto_pds service type must be preserved".to_string(),
                });
            }
            if proposed.endpoint == current.endpoint {
                return Err(EndpointRepairError::GuardRejected {
                    reason: "the proposed endpoint equals the current one (nothing to repair)"
                        .to_string(),
                });
            }
        } else if proposed != current {
            return Err(EndpointRepairError::GuardRejected {
                reason: format!("service '{id}' must be preserved across an endpoint repair"),
            });
        }
    }
    if !inputs.current_services.contains_key("atproto_pds") {
        return Err(EndpointRepairError::GuardRejected {
            reason: "the DID has no atproto_pds service to repair".to_string(),
        });
    }
    Ok(())
}

// ── Result type ──────────────────────────────────────────────────────────────

/// Outcome of `repair_hosting_endpoint`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointRepairResult {
    /// The endpoint the DID document pointed at before the repair.
    pub old_endpoint: String,
    /// The endpoint it points at now.
    pub new_endpoint: String,
    /// The submitted op's CID — `None` when the repair reconciled to a no-op
    /// (the DID document already pointed at the new endpoint).
    pub op_cid: Option<String>,
}

// ── The flow ─────────────────────────────────────────────────────────────────

/// Prove the proposed endpoint actually hosts this account before any signing: the
/// public `com.atproto.sync.getRepoStatus` on the NEW host must answer 200 for the
/// DID. This is what stops a typo'd (but real) PDS URL from being signed into the DID
/// document — a wrong host answers 400/404 here.
async fn verify_destination_hosts(
    pds_client: &PdsClient,
    endpoint: &str,
    did: &str,
) -> Result<(), EndpointRepairError> {
    let url = format!("{endpoint}/xrpc/com.atproto.sync.getRepoStatus?did={did}");
    let resp = pds_client.client().get(&url).send().await.map_err(|e| {
        EndpointRepairError::DestinationUnreachable {
            message: format!("getRepoStatus probe failed: {e}"),
        }
    })?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    if status.as_u16() == 429 {
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        return Err(EndpointRepairError::RateLimited { retry_after });
    }
    let body = resp.text().await.unwrap_or_default();
    let message = format!("getRepoStatus returned HTTP {status}: {body}");
    Err(EndpointRepairError::DestinationNotHosting { message })
}

async fn repair_hosting_endpoint_impl(
    pds_client: &PdsClient,
    did: &str,
    new_endpoint: &str,
) -> Result<EndpointRepairResult, EndpointRepairError> {
    let store = IdentityStore;
    let new_endpoint = normalize_endpoint(new_endpoint)?;

    // 1. Device key (the op's signer).
    let device_pub =
        store
            .get_or_create_device_key(did)
            .map_err(|e| EndpointRepairError::IdentityNotFound {
                message: format!("failed to get device key: {e}"),
            })?;

    // 2. Current state from the authoritative audit log (never a cached doc, and
    //    never the dead endpoint).
    let log_json = pds_client
        .fetch_audit_log(did)
        .await
        .map_err(|e| map_plc_error("failed to fetch audit log", e))?;
    let audit_log =
        crypto::parse_audit_log(&log_json).map_err(|e| EndpointRepairError::InvalidAuditLog {
            message: format!("failed to parse audit log: {e}"),
        })?;
    let current =
        latest_full_state(&audit_log).map_err(|e| EndpointRepairError::InvalidAuditLog {
            message: e.to_string(),
        })?;
    let old_endpoint = current
        .services
        .get("atproto_pds")
        .map(|s| s.endpoint.clone())
        .unwrap_or_default();

    // 3. Reconcile: a prior attempt (or another rotation-key holder) may already have
    //    repointed the document. Checked before the destination probe so an offline
    //    destination cannot block acknowledging an already-correct document.
    if old_endpoint == new_endpoint {
        return Ok(EndpointRepairResult {
            old_endpoint,
            new_endpoint,
            op_cid: None,
        });
    }

    // 4. The new endpoint must actually host this account.
    verify_destination_hosts(pds_client, &new_endpoint, did).await?;

    // 5. Propose: swap ONLY the atproto_pds endpoint string.
    let mut proposed_services = current.services.clone();
    match proposed_services.get_mut("atproto_pds") {
        Some(service) => service.endpoint = new_endpoint.clone(),
        None => {
            return Err(EndpointRepairError::GuardRejected {
                reason: "the DID has no atproto_pds service to repair".to_string(),
            })
        }
    }

    // 6. Strict pre-sign guard — the security gate.
    let inputs = EndpointRepairInputs {
        device_key_id: device_pub.key_id.clone(),
        current_rotation_keys: current.rotation_keys.clone(),
        proposed_rotation_keys: current.rotation_keys.clone(),
        current_verification_methods: current.verification_methods.clone(),
        proposed_verification_methods: current.verification_methods.clone(),
        current_also_known_as: current.also_known_as.clone(),
        proposed_also_known_as: current.also_known_as.clone(),
        current_services: current.services.clone(),
        proposed_services: proposed_services.clone(),
    };
    guard_endpoint_repair(&inputs)?;

    // 7. Device-key-sign and submit directly to plc.directory.
    let sign_closure = crate::identity_store::per_did_sign_closure(did).map_err(|e| match e {
        PerDidSignError::DeviceKeyNotFound { message } => {
            EndpointRepairError::IdentityNotFound { message }
        }
        PerDidSignError::SigningSetupFailed { message } => {
            EndpointRepairError::SigningFailed { message }
        }
    })?;
    let signed = crypto::build_did_plc_rotation_op(
        &current.prev_cid,
        inputs.proposed_rotation_keys,
        inputs.proposed_verification_methods,
        inputs.proposed_also_known_as,
        proposed_services,
        sign_closure,
    )
    .map_err(|e| EndpointRepairError::SigningFailed {
        message: format!("failed to build repair op: {e}"),
    })?;
    let signed_op: serde_json::Value =
        serde_json::from_str(&signed.signed_op_json).map_err(|e| {
            EndpointRepairError::SigningFailed {
                message: format!("failed to parse signed op JSON: {e}"),
            }
        })?;

    pds_client
        .post_plc_operation(did, &signed_op)
        .await
        .map_err(|e| map_plc_error("plc.directory rejected the repair operation", e))?;

    // 8. Best-effort cache refresh so the home card and the monitor see the wallet's
    //    own op as expected.
    if let Ok(updated) = pds_client.fetch_audit_log(did).await {
        let _ = store.store_plc_log(did, &updated);
    }
    if let Ok(resp) = pds_client
        .client()
        .get(format!("{}/{did}", pds_client.plc_directory_url()))
        .send()
        .await
    {
        // Gate on HTTP success AND a JSON body: a directory error page must never be
        // cached as the identity's DID document.
        if resp.status().is_success() {
            if let Ok(doc) = resp.text().await {
                if serde_json::from_str::<serde_json::Value>(&doc).is_ok() {
                    let _ = store.store_did_doc(did, &doc);
                }
            }
        }
    }

    Ok(EndpointRepairResult {
        old_endpoint,
        new_endpoint,
        op_cid: Some(signed.cid),
    })
}

/// Repoint the DID document's `atproto_pds` endpoint to the hosting server's new
/// public URL: device-key-signed, submitted directly to plc.directory. The biometric
/// gate lives in the frontend, in front of the Secure-Enclave signing.
#[tauri::command]
pub async fn repair_hosting_endpoint(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    new_endpoint: String,
) -> Result<EndpointRepairResult, EndpointRepairError> {
    tracing::info!(did = %did, new_endpoint = %new_endpoint, "repair_hosting_endpoint");
    repair_hosting_endpoint_impl(state.pds_client(), &did, &new_endpoint).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(endpoint: &str) -> PlcService {
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: endpoint.to_string(),
        }
    }

    fn base_inputs() -> EndpointRepairInputs {
        let services: BTreeMap<String, PlcService> =
            [("atproto_pds".to_string(), service("https://old.example"))].into();
        let mut proposed = services.clone();
        proposed.get_mut("atproto_pds").unwrap().endpoint = "https://new.example".to_string();
        EndpointRepairInputs {
            device_key_id: "did:key:zDevice".to_string(),
            current_rotation_keys: vec!["did:key:zDevice".to_string(), "did:key:zPds".to_string()],
            proposed_rotation_keys: vec!["did:key:zDevice".to_string(), "did:key:zPds".to_string()],
            current_verification_methods: [("atproto".to_string(), "did:key:zPds".to_string())]
                .into(),
            proposed_verification_methods: [("atproto".to_string(), "did:key:zPds".to_string())]
                .into(),
            current_also_known_as: vec!["at://alice.example".to_string()],
            proposed_also_known_as: vec!["at://alice.example".to_string()],
            current_services: services,
            proposed_services: proposed,
        }
    }

    #[test]
    fn guard_accepts_pure_endpoint_change() {
        assert!(guard_endpoint_repair(&base_inputs()).is_ok());
    }

    #[test]
    fn guard_rejects_missing_device_key() {
        let mut inputs = base_inputs();
        inputs.device_key_id = "did:key:zStranger".to_string();
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::WalletNotAuthorized)
        ));
    }

    #[test]
    fn guard_rejects_rotation_key_change() {
        let mut inputs = base_inputs();
        inputs.proposed_rotation_keys = vec!["did:key:zDevice".to_string()];
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_verification_method_change() {
        let mut inputs = base_inputs();
        inputs
            .proposed_verification_methods
            .insert("atproto".to_string(), "did:key:zEvil".to_string());
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_also_known_as_change() {
        let mut inputs = base_inputs();
        inputs.proposed_also_known_as = vec!["at://mallory.example".to_string()];
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_added_service() {
        let mut inputs = base_inputs();
        inputs.proposed_services.insert(
            "atproto_labeler".to_string(),
            service("https://evil.example"),
        );
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_service_type_change() {
        let mut inputs = base_inputs();
        inputs
            .proposed_services
            .get_mut("atproto_pds")
            .unwrap()
            .service_type = "SomethingElse".to_string();
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_touching_other_service() {
        let mut inputs = base_inputs();
        inputs.current_services.insert(
            "atproto_labeler".to_string(),
            service("https://labeler.example"),
        );
        let mut proposed = inputs.current_services.clone();
        proposed.get_mut("atproto_pds").unwrap().endpoint = "https://new.example".to_string();
        proposed.get_mut("atproto_labeler").unwrap().endpoint = "https://evil.example".to_string();
        inputs.proposed_services = proposed;
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::GuardRejected { .. })
        ));
    }

    #[test]
    fn guard_rejects_no_op_endpoint() {
        let mut inputs = base_inputs();
        inputs.proposed_services = inputs.current_services.clone();
        assert!(matches!(
            guard_endpoint_repair(&inputs),
            Err(EndpointRepairError::GuardRejected { .. })
        ));
    }

    #[test]
    fn normalize_accepts_bare_https_origin() {
        assert_eq!(
            normalize_endpoint("https://pds.example.org").unwrap(),
            "https://pds.example.org"
        );
        assert_eq!(
            normalize_endpoint(" https://pds.example.org/ ").unwrap(),
            "https://pds.example.org"
        );
        assert_eq!(
            normalize_endpoint("https://pds.example.org:8443").unwrap(),
            "https://pds.example.org:8443"
        );
        assert_eq!(
            normalize_endpoint("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn map_plc_error_classifies_verdicts_not_transport() {
        // A rejection body from post_plc_operation (InvalidResponse) is the directory's
        // verdict on the operation, never a connectivity problem.
        assert!(matches!(
            map_plc_error(
                "ctx",
                PdsClientError::InvalidResponse {
                    message: "plc.directory rejected operation: bad prev".to_string(),
                }
            ),
            EndpointRepairError::PlcDirectoryError { .. }
        ));
        assert!(matches!(
            map_plc_error("ctx", PdsClientError::DidNotFound),
            EndpointRepairError::PlcDirectoryError { .. }
        ));
        assert!(matches!(
            map_plc_error(
                "ctx",
                PdsClientError::RateLimited {
                    retry_after: Some("30".to_string()),
                    message: "slow down".to_string(),
                }
            ),
            EndpointRepairError::RateLimited {
                retry_after: Some(_)
            }
        ));
        assert!(matches!(
            map_plc_error(
                "ctx",
                PdsClientError::NetworkError {
                    message: "connection reset".to_string(),
                }
            ),
            EndpointRepairError::NetworkError { .. }
        ));
    }

    #[tokio::test]
    async fn destination_probe_accepts_a_hosting_server() {
        let server = httpmock::MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepoStatus");
            then.status(200)
                .json_body(serde_json::json!({"did": "did:plc:abc", "active": true}));
        });
        let client = PdsClient::new_for_test(server.base_url());
        verify_destination_hosts(&client, &server.base_url(), "did:plc:abc")
            .await
            .expect("200 probe must pass");
        mock.assert();
    }

    #[tokio::test]
    async fn destination_probe_rejects_a_non_hosting_server() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepoStatus");
            then.status(400)
                .json_body(serde_json::json!({"error": "RepoNotFound"}));
        });
        let client = PdsClient::new_for_test(server.base_url());
        let err = verify_destination_hosts(&client, &server.base_url(), "did:plc:abc")
            .await
            .expect_err("400 probe must fail");
        assert!(matches!(
            err,
            EndpointRepairError::DestinationNotHosting { .. }
        ));
    }

    #[tokio::test]
    async fn destination_probe_surfaces_retry_after_on_429() {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/xrpc/com.atproto.sync.getRepoStatus");
            then.status(429).header("Retry-After", "17");
        });
        let client = PdsClient::new_for_test(server.base_url());
        let err = verify_destination_hosts(&client, &server.base_url(), "did:plc:abc")
            .await
            .expect_err("429 probe must fail");
        match err {
            EndpointRepairError::RateLimited { retry_after } => {
                assert_eq!(retry_after.as_deref(), Some("17"));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn normalize_rejects_insecure_and_non_origin() {
        for bad in [
            "http://pds.example.org",
            "https://pds.example.org/xrpc",
            "https://pds.example.org/?x=1",
            "https://user@pds.example.org",
            "not a url",
            "ftp://pds.example.org",
        ] {
            assert!(
                matches!(
                    normalize_endpoint(bad),
                    Err(EndpointRepairError::InvalidEndpoint { .. })
                ),
                "expected rejection for {bad}"
            );
        }
    }
}
