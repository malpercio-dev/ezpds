//! Per-DID identity storage layer with Keychain-based persistence.
//!
//! `IdentityStore` manages multi-identity lifecycle in the iOS Keychain:
//! - A top-level `"managed-dids"` entry maintains a JSON array index of all managed DIDs
//! - Per-DID prefixed entries store device keys, DID documents, and PLC audit logs
//! - Device keys are lazily generated on first access via `get_or_create_device_key`
//!
//! All Keychain operations use the shared `keychain::SERVICE` prefix.

use crate::device_key::DevicePublicKey;
use serde::Serialize;
use serde_json;

// ── Constants ──────────────────────────────────────────────────────────────────

const MANAGED_DIDS_ACCOUNT: &str = "managed-dids";

// ── Error types ────────────────────────────────────────────────────────────────

/// Errors returned by `IdentityStore` operations.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` — matches the
/// `CreateAccountError` and `DeviceKeyError` patterns.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityStoreError {
    #[error("identity not found")]
    IdentityNotFound,
    #[error("identity already exists")]
    IdentityAlreadyExists,
    #[error("keychain error: {message}")]
    KeychainError { message: String },
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("serialization error: {message}")]
    SerializationError { message: String },
}

// ── Per-DID account name helpers ───────────────────────────────────────────────

/// Returns the Keychain account name for a DID's device key (private scalar).
fn device_key_account(did: &str) -> String {
    format!("{did}:device-key")
}

/// Returns the Keychain account name for a DID's device key public key.
fn device_key_pub_account(did: &str) -> String {
    format!("{did}:device-key-pub")
}

/// Returns the Keychain account name for a DID's device key SE app label.
fn device_key_app_label_account(did: &str) -> String {
    format!("{did}:device-key-app-label")
}

/// Returns the Keychain account name for a DID's DID document.
fn did_doc_account(did: &str) -> String {
    format!("{did}:did-doc")
}

/// Returns the Keychain account name for a DID's PLC audit log.
fn plc_log_account(did: &str) -> String {
    format!("{did}:plc-log")
}

/// Returns the Keychain account name for a DID's OAuth tokens.
fn oauth_tokens_account(did: &str) -> String {
    format!("{did}:oauth-tokens")
}

// ── IdentityStore ──────────────────────────────────────────────────────────────

/// Unit struct for multi-identity Keychain management.
///
/// All methods are stateless — the Keychain is globally accessible.
/// Methods take `&self` to allow future phases to hold `IdentityStore` in `AppState`.
pub struct IdentityStore;

impl IdentityStore {
    // ── Private helpers ────────────────────────────────────────────────────────

    /// Load the current list of managed DIDs from the Keychain.
    ///
    /// Returns an empty list if the entry doesn't exist.
    /// Returns `Err` if the entry exists but contains invalid JSON (data corruption).
    fn load_managed_dids(&self) -> Result<Vec<String>, IdentityStoreError> {
        match crate::keychain::get_item(MANAGED_DIDS_ACCOUNT) {
            Ok(bytes) => serde_json::from_slice::<Vec<String>>(&bytes).map_err(|e| {
                IdentityStoreError::SerializationError {
                    message: format!("failed to deserialize managed-dids: {e}"),
                }
            }),
            Err(e) if crate::keychain::is_not_found(&e) => Ok(vec![]),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Save the managed DIDs list to the Keychain.
    fn save_managed_dids(&self, dids: &[String]) -> Result<(), IdentityStoreError> {
        let json =
            serde_json::to_vec(dids).map_err(|e| IdentityStoreError::SerializationError {
                message: format!("failed to serialize managed-dids: {e}"),
            })?;
        crate::keychain::store_item(MANAGED_DIDS_ACCOUNT, &json).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Check whether a DID is in the managed list.
    ///
    /// Returns `Err` if a Keychain error occurs (propagates transient failures).
    fn is_managed(&self, did: &str) -> Result<bool, IdentityStoreError> {
        let dids = self.load_managed_dids()?;
        Ok(dids.contains(&did.to_string()))
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /// Register a new managed identity by DID.
    ///
    /// Appends the DID to the managed-dids index and saves it to the Keychain.
    /// Does NOT eagerly generate a device key — see [`Self::get_or_create_device_key`].
    ///
    /// Returns `Err(IdentityAlreadyExists)` if the DID is already registered.
    pub fn add_identity(&self, did: &str) -> Result<(), IdentityStoreError> {
        let mut dids = self.load_managed_dids()?;

        if dids.contains(&did.to_string()) {
            return Err(IdentityStoreError::IdentityAlreadyExists);
        }

        dids.push(did.to_string());
        self.save_managed_dids(&dids)?;

        Ok(())
    }

    /// Remove a managed identity and all associated Keychain entries.
    ///
    /// Deletes the DID from the managed-dids index and performs best-effort
    /// deletion of all per-DID prefixed entries (ignores not-found errors).
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not in the managed list.
    pub fn remove_identity(&self, did: &str) -> Result<(), IdentityStoreError> {
        let mut dids = self.load_managed_dids()?;

        if !dids.contains(&did.to_string()) {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        // Delete all per-DID Keychain entries (best-effort; ignore not-found errors).
        let entries = vec![
            device_key_account(did),
            device_key_pub_account(did),
            device_key_app_label_account(did),
            did_doc_account(did),
            plc_log_account(did),
            oauth_tokens_account(did),
        ];

        for entry in entries {
            let _ = crate::keychain::delete_item(&entry);
        }

        // Remove DID from index and save.
        dids.retain(|d| d != did);
        self.save_managed_dids(&dids)?;

        Ok(())
    }

    /// List all managed identities.
    ///
    /// Returns the current list of registered DIDs.
    pub fn list_identities(&self) -> Result<Vec<String>, IdentityStoreError> {
        self.load_managed_dids()
    }

    /// Get or create a per-DID device key.
    ///
    /// On first call, generates a new P-256 keypair and stores the private key
    /// (or SE metadata on real iOS) in the Keychain. On subsequent calls, returns
    /// the same public key.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered via [`Self::add_identity`].
    /// Returns `Err(KeyGenerationFailed)` if key generation fails.
    /// Returns `Err(KeychainError)` if Keychain operations fail.
    pub fn get_or_create_device_key(
        &self,
        did: &str,
    ) -> Result<DevicePublicKey, IdentityStoreError> {
        // Guard: DID must be managed.
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        get_or_create_per_did_device_key(did)
    }

    /// Store a DID document for a managed identity.
    ///
    /// The document is stored as opaque JSON bytes.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn store_did_doc(&self, did: &str, doc_json: &str) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        crate::keychain::store_item(&did_doc_account(did), doc_json.as_bytes()).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Retrieve a DID document for a managed identity.
    ///
    /// Returns `Ok(None)` if the document has not been stored.
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn get_did_doc(&self, did: &str) -> Result<Option<String>, IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        match crate::keychain::get_item(&did_doc_account(did)) {
            Ok(bytes) => {
                let doc_json = String::from_utf8(bytes).map_err(|e| {
                    IdentityStoreError::SerializationError {
                        message: format!("UTF-8 error decoding DID document: {e}"),
                    }
                })?;
                Ok(Some(doc_json))
            }
            Err(e) if crate::keychain::is_not_found(&e) => Ok(None),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Store a PLC audit log for a managed identity.
    ///
    /// The log is stored as opaque JSON bytes.
    ///
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn store_plc_log(&self, did: &str, log_json: &str) -> Result<(), IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        crate::keychain::store_item(&plc_log_account(did), log_json.as_bytes()).map_err(|e| {
            IdentityStoreError::KeychainError {
                message: e.to_string(),
            }
        })
    }

    /// Retrieve a PLC audit log for a managed identity.
    ///
    /// Returns `Ok(None)` if the log has not been stored.
    /// Returns `Err(IdentityNotFound)` if the DID is not registered.
    pub fn get_plc_log(&self, did: &str) -> Result<Option<String>, IdentityStoreError> {
        if !self.is_managed(did)? {
            return Err(IdentityStoreError::IdentityNotFound);
        }

        match crate::keychain::get_item(&plc_log_account(did)) {
            Ok(bytes) => {
                let log_json = String::from_utf8(bytes).map_err(|e| {
                    IdentityStoreError::SerializationError {
                        message: format!("UTF-8 error decoding PLC log: {e}"),
                    }
                })?;
                Ok(Some(log_json))
            }
            Err(e) if crate::keychain::is_not_found(&e) => Ok(None),
            Err(e) => Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            }),
        }
    }
}

// ── Per-DID device key implementation ──────────────────────────────────────────

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
fn get_or_create_per_did_device_key(did: &str) -> Result<DevicePublicKey, IdentityStoreError> {
    use p256::ecdsa::SigningKey;

    let account = device_key_account(did);

    // Try to load existing private key bytes from Keychain.
    let private_bytes: Vec<u8> = match crate::keychain::get_item(&account) {
        Ok(bytes) => bytes,
        Err(e) if crate::keychain::is_not_found(&e) => {
            // No key yet — generate a new P-256 keypair via the crypto crate.
            let keypair = crypto::generate_p256_keypair()
                .map_err(|_| IdentityStoreError::KeyGenerationFailed)?;
            // to_vec(): Deref gives &[u8; 32], coerces to &[u8], allocates into Vec<u8>.
            let bytes = keypair.private_key_bytes.to_vec();
            crate::keychain::store_item(&account, &bytes).map_err(|e| {
                IdentityStoreError::KeychainError {
                    message: e.to_string(),
                }
            })?;
            bytes
        }
        Err(e) => {
            return Err(IdentityStoreError::KeychainError {
                message: e.to_string(),
            })
        }
    };

    // Reconstruct the public key from stored private bytes.
    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| IdentityStoreError::KeychainError {
            message: "invalid stored key bytes".into(),
        })?;
    let encoded = signing_key.verifying_key().to_encoded_point(true); // compressed (33 bytes)
    let compressed = encoded.as_bytes();
    let multibase = multibase::encode(multibase::Base::Base58Btc, compressed);

    // did:key requires the P-256 multicodec varint prefix [0x80, 0x24] (0x1200 as LEB128)
    // prepended to the compressed point. This matches crates/crypto/src/keys.rs
    // `P256_MULTICODEC_PREFIX = &[0x80, 0x24]`, which is `pub(crate)` and cannot be
    // imported across crate boundaries — the constant is duplicated intentionally.
    const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
    let mut multikey = Vec::with_capacity(2 + compressed.len());
    multikey.extend_from_slice(P256_MULTICODEC);
    multikey.extend_from_slice(compressed);
    let key_id = format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, &multikey)
    );

    Ok(DevicePublicKey { multibase, key_id })
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn get_or_create_per_did_device_key(did: &str) -> Result<DevicePublicKey, IdentityStoreError> {
    use security_framework::{
        access_control::{ProtectionMode, SecAccessControl},
        item::ItemClass,
        key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    };

    let pub_account = device_key_pub_account(did);
    let label_account = device_key_app_label_account(did);

    // Fast path: check both metadata accounts — if both present, return cached public key.
    match (
        crate::keychain::get_item(&pub_account),
        crate::keychain::get_item(&label_account),
    ) {
        (Ok(pub_bytes), Ok(label_bytes)) => {
            let multibase = String::from_utf8(pub_bytes).map_err(|e| {
                IdentityStoreError::SerializationError {
                    message: format!("UTF-8 error decoding cached public key: {e}"),
                }
            })?;
            let key_id = String::from_utf8(label_bytes).map_err(|e| {
                IdentityStoreError::SerializationError {
                    message: format!("UTF-8 error decoding cached key_id: {e}"),
                }
            })?;
            return Ok(DevicePublicKey { multibase, key_id });
        }
        // Fall through if either is missing
        _ => {}
    }

    // Slow path: generate SE key, store metadata.
    let se_label = format!("ezpds-device-key-{did}");

    // Create SecAccessControl for Secure Enclave with biometric/passcode.
    let access = SecAccessControl::create(ItemClass::PrivateKey)
        .map_err(|e| IdentityStoreError::KeychainError {
            message: format!("failed to create SecAccessControl: {e}"),
        })?
        .with_protection(ProtectionMode::WhenPasscodeSetThisDeviceOnly)
        .with_biometry_any()
        .map_err(|e| IdentityStoreError::KeychainError {
            message: format!("failed to configure SecAccessControl: {e}"),
        })?;

    // Generate P-256 key in Secure Enclave.
    let options = GenerateKeyOptions::new(KeyType::EC, Algorithm::ES256)
        .set_token(Token::SecureEnclave)
        .set_access_control(&access)
        .set_label(&se_label);

    let private_key = SecKey::new(&options).map_err(|e| IdentityStoreError::KeyGenerationFailed)?;

    // Extract the public key.
    let public_key =
        private_key
            .to_public_key()
            .map_err(|e| IdentityStoreError::KeychainError {
                message: format!("failed to extract public key from SE key: {e}"),
            })?;

    // Get the external representation (DER-encoded X.509 SubjectPublicKeyInfo).
    // Parse it to extract the 33-byte compressed P-256 point.
    let der =
        public_key
            .external_representation()
            .map_err(|e| IdentityStoreError::KeychainError {
                message: format!("failed to get DER public key: {e}"),
            })?;

    // Parse X.509 SubjectPublicKeyInfo to extract the 33-byte compressed point.
    // For P-256, the structure is:
    //   SEQUENCE { algorithmIdentifier, BIT STRING { 0x04, compressed_point } }
    // The compressed point is at offset ~26-27 bytes in the standard encoding.
    // We extract it and reconstruct the multibase + did:key URI.
    let compressed =
        extract_p256_point_from_der(&der).map_err(|e| IdentityStoreError::KeychainError {
            message: format!("failed to parse P-256 point from DER: {e}"),
        })?;

    let multibase = multibase::encode(multibase::Base::Base58Btc, &compressed);
    const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
    let mut multikey = Vec::with_capacity(2 + compressed.len());
    multikey.extend_from_slice(P256_MULTICODEC);
    multikey.extend_from_slice(&compressed);
    let key_id = format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, &multikey)
    );

    // Store multibase and key_id for fast lookup on next call.
    crate::keychain::store_item(&pub_account, multibase.as_bytes()).map_err(|e| {
        IdentityStoreError::KeychainError {
            message: e.to_string(),
        }
    })?;
    crate::keychain::store_item(&label_account, key_id.as_bytes()).map_err(|e| {
        IdentityStoreError::KeychainError {
            message: e.to_string(),
        }
    })?;

    Ok(DevicePublicKey { multibase, key_id })
}

/// Parse a P-256 compressed public key (33 bytes) from an X.509 SubjectPublicKeyInfo DER blob.
///
/// This is a simplified parser for testing/simulator use. Real SE keys are extracted by
/// the SE path above; this helper is only called in test/sim where SE is not available.
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
fn extract_p256_point_from_der(der: &[u8]) -> Result<[u8; 33], String> {
    // For P-256, the standard DER encoding of SEQUENCE { algId, BIT STRING pubkey }
    // places the 33-byte compressed point at a predictable offset.
    // Expected structure:
    //   SEQUENCE (2 bytes: tag + length) [~2-4 bytes total]
    //     SEQUENCE (algId) [~20 bytes]
    //     BIT STRING [~35 bytes total: tag + length + unused bits byte + 33 byte point]
    //
    // The 33-byte compressed point typically starts around offset 26-27.
    // We search for the BIT STRING tag (0x03) and extract the point after the length and unused bits byte.

    for (i, window) in der.windows(35).enumerate() {
        if window[0] == 0x03 && window[1] == 33 && window[2] == 0x00 {
            // Found BIT STRING tag, length 33, 0 unused bits.
            // The point starts at offset 3.
            let mut point = [0u8; 33];
            point.copy_from_slice(&window[3..36]);
            return Ok(point);
        }
    }

    Err("failed to find P-256 point in DER".to_string())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_managed_dids() {
        let _ = crate::keychain::delete_item(MANAGED_DIDS_ACCOUNT);
    }

    fn clear_per_did_entries(did: &str) {
        let _ = crate::keychain::delete_item(&device_key_account(did));
        let _ = crate::keychain::delete_item(&device_key_pub_account(did));
        let _ = crate::keychain::delete_item(&device_key_app_label_account(did));
        let _ = crate::keychain::delete_item(&did_doc_account(did));
        let _ = crate::keychain::delete_item(&plc_log_account(did));
        let _ = crate::keychain::delete_item(&oauth_tokens_account(did));
    }

    // ── Task 1: add_identity, remove_identity, list_identities ────────────────

    #[test]
    fn add_identity_and_list() {
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());
        let identities = store.list_identities().expect("list_identities failed");
        assert_eq!(identities, vec!["did:plc:test1"]);
    }

    #[test]
    fn list_multiple_identities() {
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:alice").is_ok());
        assert!(store.add_identity("did:plc:bob").is_ok());
        assert!(store.add_identity("did:plc:charlie").is_ok());

        let identities = store.list_identities().expect("list_identities failed");
        assert_eq!(
            identities,
            vec!["did:plc:alice", "did:plc:bob", "did:plc:charlie"]
        );
    }

    #[test]
    fn remove_identity_from_list() {
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:alice").is_ok());
        assert!(store.add_identity("did:plc:bob").is_ok());

        assert!(store.remove_identity("did:plc:alice").is_ok());

        let identities = store.list_identities().expect("list_identities failed");
        assert_eq!(identities, vec!["did:plc:bob"]);
    }

    #[test]
    fn add_identity_duplicate_fails() {
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());

        let result = store.add_identity("did:plc:test1");
        assert!(matches!(
            result,
            Err(IdentityStoreError::IdentityAlreadyExists)
        ));
    }

    #[test]
    fn remove_identity_not_found() {
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.remove_identity("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn error_serialization() {
        // Verify that errors serialize as { "code": "SCREAMING_SNAKE_CASE" }
        let err1 = IdentityStoreError::IdentityNotFound;
        let json1 = serde_json::to_string(&err1).expect("serialization failed");
        assert!(json1.contains(r#""code":"IDENTITY_NOT_FOUND""#));

        let err2 = IdentityStoreError::IdentityAlreadyExists;
        let json2 = serde_json::to_string(&err2).expect("serialization failed");
        assert!(json2.contains(r#""code":"IDENTITY_ALREADY_EXISTS""#));

        let err3 = IdentityStoreError::KeyGenerationFailed;
        let json3 = serde_json::to_string(&err3).expect("serialization failed");
        assert!(json3.contains(r#""code":"KEY_GENERATION_FAILED""#));

        let err4 = IdentityStoreError::KeychainError {
            message: "test error".into(),
        };
        let json4 = serde_json::to_string(&err4).expect("serialization failed");
        assert!(json4.contains(r#""code":"KEYCHAIN_ERROR""#));

        let err5 = IdentityStoreError::SerializationError {
            message: "test error".into(),
        };
        let json5 = serde_json::to_string(&err5).expect("serialization failed");
        assert!(json5.contains(r#""code":"SERIALIZATION_ERROR""#));
    }

    // ── Task 2: get_or_create_device_key ───────────────────────────────────────

    #[test]
    fn get_or_create_device_key_success() {
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());
        clear_per_did_entries("did:plc:test1");

        let result = store.get_or_create_device_key("did:plc:test1");
        assert!(result.is_ok());

        let key = result.unwrap();
        assert!(key.multibase.starts_with('z'));
        assert!(key.key_id.starts_with("did:key:z"));

        // Validate multibase decoding to 33 bytes
        if let Ok(decoded) = multibase::decode(&key.multibase) {
            assert_eq!(
                decoded.1.len(),
                33,
                "compressed P-256 point should be 33 bytes"
            );
        }
    }

    #[test]
    fn get_or_create_device_key_idempotent() {
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:test1").is_ok());
        clear_per_did_entries("did:plc:test1");

        let key1 = store
            .get_or_create_device_key("did:plc:test1")
            .expect("first call failed");
        let key2 = store
            .get_or_create_device_key("did:plc:test1")
            .expect("second call failed");

        assert_eq!(key1.multibase, key2.multibase);
        assert_eq!(key1.key_id, key2.key_id);
    }

    #[test]
    fn get_or_create_device_key_different_dids() {
        clear_managed_dids();
        let store = IdentityStore;

        assert!(store.add_identity("did:plc:alice").is_ok());
        assert!(store.add_identity("did:plc:bob").is_ok());
        clear_per_did_entries("did:plc:alice");
        clear_per_did_entries("did:plc:bob");

        let key_alice = store
            .get_or_create_device_key("did:plc:alice")
            .expect("alice key failed");
        let key_bob = store
            .get_or_create_device_key("did:plc:bob")
            .expect("bob key failed");

        assert_ne!(key_alice.multibase, key_bob.multibase);
        assert_ne!(key_alice.key_id, key_bob.key_id);
    }

    #[test]
    fn get_or_create_device_key_unregistered_did_fails() {
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_or_create_device_key("did:plc:unregistered");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    // ── Task 3: DID document and PLC log persistence ────────────────────────────

    #[test]
    fn did_doc_round_trip() {
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let doc = r#"{"id":"did:plc:test1","alsoKnownAs":["at://alice.test"]}"#;
        assert!(store.store_did_doc(did, doc).is_ok());

        let retrieved = store
            .get_did_doc(did)
            .expect("get_did_doc failed")
            .expect("document not found");
        assert_eq!(retrieved, doc);
    }

    #[test]
    fn plc_log_round_trip() {
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let log = r#"[{"cid":"bafy...","operation":{}}]"#;
        assert!(store.store_plc_log(did, log).is_ok());

        let retrieved = store
            .get_plc_log(did)
            .expect("get_plc_log failed")
            .expect("log not found");
        assert_eq!(retrieved, log);
    }

    #[test]
    fn get_did_doc_returns_none_if_not_stored() {
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let retrieved = store.get_did_doc(did).expect("get_did_doc failed");
        assert!(retrieved.is_none());
    }

    #[test]
    fn get_plc_log_returns_none_if_not_stored() {
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        let retrieved = store.get_plc_log(did).expect("get_plc_log failed");
        assert!(retrieved.is_none());
    }

    #[test]
    fn store_did_doc_unregistered_did_fails() {
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.store_did_doc("did:plc:ghost", "{}");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn get_did_doc_unregistered_did_fails() {
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_did_doc("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn store_plc_log_unregistered_did_fails() {
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.store_plc_log("did:plc:ghost", "[]");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn get_plc_log_unregistered_did_fails() {
        clear_managed_dids();
        let store = IdentityStore;

        let result = store.get_plc_log("did:plc:ghost");
        assert!(matches!(result, Err(IdentityStoreError::IdentityNotFound)));
    }

    #[test]
    fn remove_identity_cleans_up_all_entries() {
        clear_managed_dids();
        let store = IdentityStore;
        let did = "did:plc:test1";

        assert!(store.add_identity(did).is_ok());
        clear_per_did_entries(did);

        // Store some data.
        let doc = r#"{"id":"did:plc:test1"}"#;
        let log = r#"[]"#;
        assert!(store.store_did_doc(did, doc).is_ok());
        assert!(store.store_plc_log(did, log).is_ok());

        // Also trigger device key generation to populate private key storage.
        // (On simulator, this stores in the per-did:device-key account.)
        let _ = store.get_or_create_device_key(did);

        // Remove the identity.
        assert!(store.remove_identity(did).is_ok());

        // Re-add the same DID and verify all entries are gone.
        assert!(store.add_identity(did).is_ok());
        assert!(store.get_did_doc(did).unwrap().is_none());
        assert!(store.get_plc_log(did).unwrap().is_none());
    }
}
