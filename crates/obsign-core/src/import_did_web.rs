// pattern: Imperative Shell

//! Importing an existing did:web identity: resolve the live document, register the DID, and
//! mint a per-DID device key. No PDS account is created and no ceremony runs — control of a
//! did:web is proven by the domain, so registering one the user does not control grants nothing
//! (every consequential flow still demands the account password and a byte-exact publish).

use crate::oauth::Core;
use crate::{identity_store, migration_orchestrator, pds_client};
use serde::Serialize;

/// Error returned by `import_did_web_identity`.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImportDidWebError {
    #[error("not a usable did:web domain: {message}")]
    InvalidDomain { message: String },
    #[error("no DID document found at the domain")]
    DocumentNotFound,
    #[error("the domain's DID document is not usable: {message}")]
    InvalidDocument { message: String },
    #[error("the PDS in the DID document is unreachable")]
    PdsUnreachable,
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("failed to persist identity to device storage")]
    KeychainError,
}

/// The imported identity's resolved coordinates, for the UI to route with.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedDidWebIdentity {
    pub did: String,
    /// Preferred handle from the live document's `alsoKnownAs`, when it carries one.
    pub handle: Option<String>,
    pub pds_url: String,
}

/// Normalize user input ("example.com", "https://example.com/", "did:web:example.com")
/// to the hostname-form did:web the wallet supports. The shape rules mirror the
/// frontend's `didWebFromDomain`: no scheme, path, port, or userinfo — a colon would
/// smuggle a port or path segment into the document URL.
fn normalize_did_web_input(input: &str) -> Result<String, ImportDidWebError> {
    let mut host = input.trim().to_ascii_lowercase();
    if let Some(rest) = host.strip_prefix("did:web:") {
        host = rest.to_string();
    }
    host = host
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let valid_shape = !host.is_empty()
        && host.contains('.')
        && !host.contains([':', '/', '@'])
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    if !valid_shape {
        return Err(ImportDidWebError::InvalidDomain {
            message: "enter a public domain name without a path or port".to_string(),
        });
    }
    Ok(format!("did:web:{host}"))
}

/// Persist a resolved did:web identity into `IdentityStore` (the network-free half of
/// `import_did_web_identity`, split out for tests).
///
/// `rotationKeys` is deliberately empty: a did:web document has no PLC rotation keys, and
/// the per-DID device key minted here becomes authoritative only when a later flow (the
/// migration identity leg) publishes it as `#device` in the live document — showing it as
/// a root key before that would be a lie.
fn persist_imported_did_web(
    store: &identity_store::IdentityStore,
    did: &str,
    pds_url: &str,
    also_known_as: &[String],
) -> Result<Option<String>, ImportDidWebError> {
    if let Err(e) = store.add_identity(did) {
        if !matches!(e, identity_store::IdentityStoreError::IdentityAlreadyExists) {
            tracing::error!(did = %did, error = %e, "import_did_web_identity: add_identity failed");
            return Err(ImportDidWebError::KeychainError);
        }
    }
    // Mint the per-DID device key now so `detect_migration_path`'s did:web branch (which
    // requires a managed DID with a device key) can classify this identity as SelfSigned.
    store.get_or_create_device_key(did).map_err(|e| {
        tracing::error!(did = %did, error = %e, "import_did_web_identity: device key mint failed");
        ImportDidWebError::KeychainError
    })?;

    let did_doc_json = serde_json::json!({
        "did": did,
        "alsoKnownAs": also_known_as,
        "rotationKeys": [],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_url,
            }
        }
    })
    .to_string();
    store.store_did_doc(did, &did_doc_json).map_err(|e| {
        tracing::error!(did = %did, error = %e, "import_did_web_identity: store_did_doc failed");
        ImportDidWebError::KeychainError
    })?;

    Ok(migration_orchestrator::extract_handle_from_also_known_as(
        also_known_as,
    ))
}

/// Bring an EXISTING did:web identity under wallet management, so the method-agnostic
/// flows (outbound migration first among them) can operate on it.
///
/// For did:web there is no claim ceremony: control is proven by the domain (publishing
/// the document) and, later, by the source-PDS password login — so "import" is resolving
/// the live document, registering the DID, and minting a local device key. Registering an
/// identity you don't control grants nothing: every consequential flow still demands the
/// account password and a byte-exact document publish on the domain.
///
/// Idempotent — re-importing an already-managed DID refreshes its cached document.
pub async fn import_did_web_identity(
    state: &Core,
    input: String,
) -> Result<ImportedDidWebIdentity, ImportDidWebError> {
    let did = normalize_did_web_input(&input)?;

    // Resolve + validate the live document (fetch, parse, atproto_pds extraction, PDS
    // reachability probe) through the same seam every other did:web read uses.
    let (pds_url, doc) = state.pds_client().discover_pds(&did).await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "import_did_web_identity: discovery failed");
        match e {
            pds_client::PdsClientError::DidNotFound => ImportDidWebError::DocumentNotFound,
            pds_client::PdsClientError::PdsUnreachable { .. } => ImportDidWebError::PdsUnreachable,
            pds_client::PdsClientError::InvalidResponse { message } => {
                ImportDidWebError::InvalidDocument { message }
            }
            other => ImportDidWebError::NetworkError {
                message: other.to_string(),
            },
        }
    })?;

    let store = identity_store::IdentityStore;
    let handle = persist_imported_did_web(&store, &did, &pds_url, &doc.also_known_as)?;

    tracing::info!(did = %did, pds_url = %pds_url, "existing did:web identity imported");
    Ok(ImportedDidWebIdentity {
        did,
        handle,
        pds_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- import_did_web_identity --

    #[test]
    fn normalize_did_web_input_accepts_domain_did_and_url_forms() {
        for input in [
            "malpercio.dev",
            "  Malpercio.DEV ",
            "https://malpercio.dev/",
            "did:web:malpercio.dev",
        ] {
            assert_eq!(
                normalize_did_web_input(input).unwrap(),
                "did:web:malpercio.dev",
                "input {input:?}"
            );
        }
    }

    #[test]
    fn normalize_did_web_input_rejects_unsupported_shapes() {
        // Ports, paths, userinfo, bare labels, and empty input all refuse rather than
        // misresolve into a wrong document URL.
        for input in [
            "",
            "localhost",
            "example.com:8080",
            "did:web:example.com:user:alice",
            "example.com/path",
            "user@example.com",
            ".example.com",
            "example.com.",
        ] {
            assert!(
                matches!(
                    normalize_did_web_input(input),
                    Err(ImportDidWebError::InvalidDomain { .. })
                ),
                "input {input:?} should be rejected"
            );
        }
    }

    #[test]
    fn persist_imported_did_web_registers_and_stores_doc() {
        crate::keystore::clear_for_test();
        let store = identity_store::IdentityStore;
        let did = "did:web:import.example";
        let aka = vec!["at://import.example".to_string()];

        let handle = persist_imported_did_web(&store, did, "https://pds.example", &aka).unwrap();
        assert_eq!(handle.as_deref(), Some("import.example"));

        // Registered, device key minted, and the stored doc carries the card fields
        // with rotationKeys honestly empty (a did:web has none until migration
        // publishes #device).
        assert!(store.list_identities().unwrap().contains(&did.to_string()));
        assert!(store.get_or_create_device_key(did).is_ok());
        let doc: serde_json::Value =
            serde_json::from_str(&store.get_did_doc(did).unwrap().unwrap()).unwrap();
        assert_eq!(doc["did"], did);
        assert_eq!(doc["alsoKnownAs"][0], "at://import.example");
        assert_eq!(doc["rotationKeys"].as_array().unwrap().len(), 0);
        assert_eq!(
            doc["services"]["atproto_pds"]["endpoint"],
            "https://pds.example"
        );

        // Idempotent: a re-import refreshes rather than fails.
        let again = persist_imported_did_web(&store, did, "https://pds2.example", &aka).unwrap();
        assert_eq!(again.as_deref(), Some("import.example"));
        let doc: serde_json::Value =
            serde_json::from_str(&store.get_did_doc(did).unwrap().unwrap()).unwrap();
        assert_eq!(
            doc["services"]["atproto_pds"]["endpoint"],
            "https://pds2.example"
        );

        let _ = store.remove_identity(did);
    }

    #[test]
    fn import_did_web_error_serializes_as_code() {
        let json = serde_json::to_value(ImportDidWebError::DocumentNotFound).unwrap();
        assert_eq!(json["code"], "DOCUMENT_NOT_FOUND");
        let json = serde_json::to_value(ImportDidWebError::InvalidDomain {
            message: "x".into(),
        })
        .unwrap();
        assert_eq!(json["code"], "INVALID_DOMAIN");
    }
}
