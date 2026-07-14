// pattern: Mixed (unavoidable)
//
// Shared machinery for the PDS-signed interop account-migration path (ADR-0002):
// reading a DID's current PLC state from plc.directory (so the PDS can build the
// next operation on top of it) and rendering an updated DID document from an
// operation's fields. The audit-log fetch is the one Imperative Shell function
// here (an outbound HTTP GET); everything else is pure construction.
//
// The wallet-authorized path does NOT use these — it builds and submits its
// identity leg locally with the device key. These endpoints exist so off-the-shelf
// tooling can migrate off ezpds and so ezpds can serve as a migration destination.

use std::collections::BTreeMap;

use common::{ApiError, ErrorCode};
use serde::Deserialize;

/// Reject a DID whose method is not `did:plc`.
///
/// The `identity.*PlcOperation` endpoints only make sense for a `did:plc` identity — they build,
/// sign, and submit operations against plc.directory's hash-linked operation log. A `did:web`
/// identity (the operator hosts its own `did.json`; see ADR-0003) has no PLC log at all, so
/// calling these endpoints for one would otherwise fail confusingly deep in the flow — a 404 on
/// the plc.directory audit-log fetch. Guard the method up front instead, returning an explicit
/// "not a did:plc" error the caller can act on: a did:web account repoints its PDS by editing its
/// own `did.json`, not by signing a PLC operation.
pub fn ensure_did_plc(did: &str) -> Result<(), ApiError> {
    if did.starts_with("did:plc:") {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "this account is not a did:plc identity; PLC operations do not apply. \
             A did:web identity is repointed by editing its own did.json, not by signing a \
             PLC operation.",
        ))
    }
}

/// A DID's current PLC state, distilled from its latest non-nullified audit-log
/// entry. `cid` is the head operation's CID — the `prev` of the next operation.
#[derive(Debug)]
pub struct CurrentPlcState {
    pub cid: String,
    pub rotation_keys: Vec<String>,
    pub verification_methods: BTreeMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: BTreeMap<String, crypto::PlcService>,
}

/// The mutable fields of a `plc_operation`, as they appear in a plc.directory
/// audit-log entry's `operation` object (and in a `signPlcOperation` request body).
#[derive(Deserialize)]
struct PlcOpFields {
    #[serde(rename = "rotationKeys", default)]
    rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods", default)]
    verification_methods: BTreeMap<String, String>,
    #[serde(rename = "alsoKnownAs", default)]
    also_known_as: Vec<String>,
    #[serde(default)]
    services: BTreeMap<String, crypto::PlcService>,
}

/// Fetch a DID's current PLC state from `{plc_directory_url}/{did}/log/audit`.
///
/// Returns the most recent **non-nullified** operation's CID and mutable fields.
/// The caller uses `cid` as the next operation's `prev` and the fields as the
/// defaults that a `signPlcOperation` request overlays its changes onto.
///
/// # Errors
/// - `PlcDirectoryError` if plc.directory is unreachable or returns non-success.
/// - `DidNotFound` if the audit log is empty or every entry is nullified.
/// - `InternalError` if the response is not parseable as an audit log / operation.
pub async fn fetch_current_plc_state(
    http_client: &reqwest::Client,
    plc_directory_url: &str,
    did: &str,
) -> Result<CurrentPlcState, ApiError> {
    let url = format!("{plc_directory_url}/{did}/log/audit");
    let response = http_client.get(&url).send().await.map_err(|e| {
        tracing::error!(error = %e, url = %url, "failed to contact plc.directory for audit log");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "failed to contact plc.directory",
        )
    })?;

    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!(status = %status, did = %did, "plc.directory audit log request failed");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            format!("plc.directory returned {status} for the audit log"),
        ));
    }

    let body = response.text().await.map_err(|e| {
        tracing::error!(error = %e, "failed to read plc.directory audit log body");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "failed to read plc.directory response",
        )
    })?;

    let entries = crypto::parse_audit_log(&body).map_err(|e| {
        tracing::error!(error = %e, "failed to parse plc.directory audit log");
        ApiError::new(ErrorCode::InternalError, "failed to parse PLC audit log")
    })?;

    // The current state is the newest operation that plc.directory has not nullified.
    let head = entries.iter().rev().find(|e| !e.nullified).ok_or_else(|| {
        ApiError::new(
            ErrorCode::DidNotFound,
            "no active PLC operation found for this DID",
        )
    })?;

    let fields: PlcOpFields = serde_json::from_value(head.operation.clone()).map_err(|e| {
        tracing::error!(error = %e, "PLC audit-log operation is not a recognised plc_operation");
        ApiError::new(
            ErrorCode::InternalError,
            "unexpected PLC operation shape in audit log",
        )
    })?;

    Ok(CurrentPlcState {
        cid: head.cid.clone(),
        rotation_keys: fields.rotation_keys,
        verification_methods: fields.verification_methods,
        also_known_as: fields.also_known_as,
        services: fields.services,
    })
}

/// Render a minimal DID Core document from a PLC operation's fields.
///
/// Used to refresh the locally-cached DID document after a self-submitted PLC
/// operation repoints the identity (`submitPlcOperation`). Mirrors the shape
/// `genesis::build_did_document` produces for a genesis op.
///
/// # Errors
/// Returns `InternalError` if `verificationMethods["atproto"]` is absent or not a
/// `did:key:` URI, or if there is no `atproto_pds` service endpoint.
pub fn build_did_document_from_op(
    did: &str,
    verification_methods: &BTreeMap<String, String>,
    also_known_as: &[String],
    services: &BTreeMap<String, crypto::PlcService>,
) -> Result<serde_json::Value, ApiError> {
    let atproto_did_key = verification_methods.get("atproto").ok_or_else(|| {
        ApiError::new(
            ErrorCode::InternalError,
            "operation verificationMethods.atproto is missing",
        )
    })?;
    let public_key_multibase = atproto_did_key.strip_prefix("did:key:").ok_or_else(|| {
        ApiError::new(
            ErrorCode::InternalError,
            "operation atproto key is not a did:key: URI",
        )
    })?;
    let service_endpoint = services
        .get("atproto_pds")
        .map(|s| s.endpoint.as_str())
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InternalError,
                "operation is missing an atproto_pds service endpoint",
            )
        })?;

    Ok(serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": also_known_as,
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": service_endpoint
        }]
    }))
}

/// Deserialize a request-supplied `verificationMethods` JSON object into the map
/// shape the PLC op builder expects. Returns `InvalidRequest` on a malformed value.
pub fn parse_verification_methods(
    value: &serde_json::Value,
) -> Result<BTreeMap<String, String>, ApiError> {
    serde_json::from_value(value.clone()).map_err(|e| {
        tracing::warn!(error = %e, "invalid verificationMethods in request");
        ApiError::new(
            ErrorCode::InvalidRequest,
            "verificationMethods must be a map of method name to did:key URI",
        )
    })
}

/// Deserialize a request-supplied `services` JSON object into the map shape the
/// PLC op builder expects. Returns `InvalidRequest` on a malformed value.
pub fn parse_services(
    value: &serde_json::Value,
) -> Result<BTreeMap<String, crypto::PlcService>, ApiError> {
    serde_json::from_value(value.clone()).map_err(|e| {
        tracing::warn!(error = %e, "invalid services in request");
        ApiError::new(
            ErrorCode::InvalidRequest,
            "services must be a map of service name to { type, endpoint }",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn plc_service(endpoint: &str) -> crypto::PlcService {
        crypto::PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: endpoint.to_string(),
        }
    }

    fn audit_entry(cid: &str, nullified: bool, endpoint: &str) -> serde_json::Value {
        serde_json::json!({
            "did": "did:plc:test",
            "cid": cid,
            "createdAt": "2026-07-02T00:00:00Z",
            "nullified": nullified,
            "operation": {
                "type": "plc_operation",
                "prev": null,
                "rotationKeys": ["did:key:zRot", "did:key:zSign"],
                "verificationMethods": { "atproto": "did:key:zSign" },
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": endpoint
                    }
                }
            }
        })
    }

    #[tokio::test]
    async fn fetches_latest_non_nullified_entry() {
        let server = MockServer::start().await;
        let did = "did:plc:test";
        // Newest entry (last) is nullified; the one before it is the real head.
        let log = serde_json::json!([
            audit_entry("bafyGenesis", false, "https://old.example.com"),
            audit_entry("bafyHead", false, "https://pds.example.com"),
            audit_entry("bafyReverted", true, "https://attacker.example.com"),
        ]);
        Mock::given(method("GET"))
            .and(path(format!("/{did}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let state = fetch_current_plc_state(&http, &server.uri(), did)
            .await
            .expect("state");
        assert_eq!(state.cid, "bafyHead");
        assert_eq!(
            state.services.get("atproto_pds").unwrap().endpoint,
            "https://pds.example.com"
        );
        assert_eq!(state.rotation_keys, vec!["did:key:zRot", "did:key:zSign"]);
    }

    #[tokio::test]
    async fn empty_or_all_nullified_log_is_did_not_found() {
        let server = MockServer::start().await;
        let did = "did:plc:test";
        let log = serde_json::json!([audit_entry("bafyReverted", true, "https://x.example.com")]);
        Mock::given(method("GET"))
            .and(path(format!("/{did}/log/audit")))
            .respond_with(ResponseTemplate::new(200).set_body_json(log))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let err = fetch_current_plc_state(&http, &server.uri(), did)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 404, "empty log → DID_NOT_FOUND (404)");
    }

    #[tokio::test]
    async fn plc_directory_error_maps_to_502() {
        let server = MockServer::start().await;
        let did = "did:plc:test";
        Mock::given(method("GET"))
            .and(path(format!("/{did}/log/audit")))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let err = fetch_current_plc_state(&http, &server.uri(), did)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 502, "plc.directory failure → 502");
    }

    #[test]
    fn builds_did_document_from_op_fields() {
        let mut vms = BTreeMap::new();
        vms.insert("atproto".to_string(), "did:key:zSign".to_string());
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            plc_service("https://pds.example.com"),
        );

        let doc = build_did_document_from_op(
            "did:plc:test",
            &vms,
            &["at://alice.example.com".to_string()],
            &services,
        )
        .expect("doc");
        assert_eq!(doc["id"], "did:plc:test");
        assert_eq!(doc["verificationMethod"][0]["publicKeyMultibase"], "zSign");
        assert_eq!(
            doc["service"][0]["serviceEndpoint"],
            "https://pds.example.com"
        );
        assert_eq!(doc["alsoKnownAs"][0], "at://alice.example.com");
    }

    #[test]
    fn build_did_document_from_op_requires_atproto_key() {
        let vms = BTreeMap::new();
        let services = BTreeMap::new();
        let err = build_did_document_from_op("did:plc:test", &vms, &[], &services).unwrap_err();
        assert_eq!(err.status_code(), 500);
    }

    #[test]
    fn ensure_did_plc_accepts_did_plc_and_rejects_others() {
        assert!(ensure_did_plc("did:plc:abc123").is_ok());
        // did:web (and any non-plc method) is a 400 with an explicit, actionable message.
        for did in [
            "did:web:malpercio.dev",
            "did:key:zabc",
            "did:web:example.com:users:alice",
        ] {
            let err = ensure_did_plc(did).unwrap_err();
            assert_eq!(
                err.status_code(),
                400,
                "{did} must be rejected as not-a-did:plc"
            );
        }
    }
}
