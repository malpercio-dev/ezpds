use serde::Serialize;

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePublicKey {
    /// Multibase base58btc-encoded compressed P-256 public key point.
    /// Format: 'z' + base58btc(33-byte SEC1 compressed point).
    pub multibase: String,
    /// Full did:key URI. Format: "did:key:z...".
    pub key_id: String,
}

/// Errors returned by device key operations.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` — matches the
/// `CreateAccountError` pattern in `lib.rs`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceKeyError {
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("key not found; call get_or_create before sign")]
    KeyNotFound,
    #[error("signing failed")]
    SigningFailed,
    /// DER → r||s parse failed (SE path only; not reachable on simulator).
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("keychain error: {message}")]
    KeychainError { message: String },
}

// ── Simulator / macOS host path ───────────────────────────────────────────────
//
// Covers:
//   - macOS (target_os = "macos"): used for `cargo test` on developer machines
//   - iOS Simulator (target_os = "ios", target_env = "sim"): no Secure Enclave hardware
//
// Note: the design doc cfg (all(target_vendor = "apple", target_env = "sim")) does not
// match macOS host where target_env = "". We extend to include target_os = "macos" so
// that `cargo test` exercises the software path rather than the SE stubs below.

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    use p256::ecdsa::SigningKey;

    const ACCOUNT: &str = "device-rotation-key-priv";

    // Try to load existing private key bytes from Keychain.
    let private_bytes: Vec<u8> = match crate::keychain::get_item(ACCOUNT) {
        Ok(bytes) => bytes,
        Err(_) => {
            // No key yet — generate a new P-256 keypair via the crypto crate.
            let keypair =
                crypto::generate_p256_keypair().map_err(|_| DeviceKeyError::KeyGenerationFailed)?;
            // Deref Zeroizing<[u8; 32]> to [u8; 32], then collect as Vec<u8>.
            let bytes = keypair.private_key_bytes.to_vec();
            crate::keychain::store_item(ACCOUNT, &bytes).map_err(|e| {
                DeviceKeyError::KeychainError {
                    message: e.to_string(),
                }
            })?;
            bytes
        }
    };

    // Reconstruct the public key from stored private bytes.
    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| DeviceKeyError::KeychainError {
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

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    const ACCOUNT: &str = "device-rotation-key-priv";

    // If the key doesn't exist, signal that get_or_create must be called first.
    let private_bytes =
        crate::keychain::get_item(ACCOUNT).map_err(|_| DeviceKeyError::KeyNotFound)?;

    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| DeviceKeyError::SigningFailed)?;

    // sign() uses the deterministic Signer impl (RFC 6979 nonce).
    // It internally hashes `data` with SHA-256 before signing.
    let signature: Signature = signing_key.sign(data);

    // to_bytes() returns a fixed 64-byte GenericArray<u8, U64> (raw r||s).
    Ok(signature.to_bytes().to_vec())
}

// ── Real device (Secure Enclave) path ────────────────────────────────────────
//
// Phase 2 implementation using security_framework 3.x safe wrapper.
// The SE private key is permanent and non-extractable; the public key and
// application_label (SHA1 hash) are stored in the regular Keychain for lookup.

/// Account names used to store SE key metadata in the regular Keychain.
/// The SE private key itself is stored in the Secure Enclave and never leaves it.
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
const SE_PUB_ACCOUNT: &str = "device-rotation-key-pub";
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
const SE_APP_LABEL_ACCOUNT: &str = "device-rotation-key-app-label";

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    // Fast path: if we already stored the compressed public key, return it directly.
    // This avoids SE hardware interaction on every call after first generation.
    if let Ok(compressed) = crate::keychain::get_item(SE_PUB_ACCOUNT) {
        let multibase = multibase::encode(multibase::Base::Base58Btc, &compressed);
        // did:key requires the P-256 multicodec varint prefix [0x80, 0x24] (0x1200 as LEB128).
        const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
        let mut multikey = Vec::with_capacity(2 + compressed.len());
        multikey.extend_from_slice(P256_MULTICODEC);
        multikey.extend_from_slice(&compressed);
        let key_id = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &multikey)
        );
        return Ok(DevicePublicKey { multibase, key_id });
    }

    // Generate a new SE-backed P-256 key.
    // set_location(DataProtectionKeychain) is required — without it, security_framework sets
    // kSecAttrIsPermanent = false, meaning the key is not persisted to the Keychain and will
    // not survive app restart (key would not survive app restart).
    // set_access_control with PRIVATE_KEY_USAGE is required for SE keys — the SE enforces
    // that only explicitly-authorized operations can use the private key for signing.
    //
    // Note: SecAccessControl::create_with_protection takes Option<ProtectionMode> and a raw
    // flags u64. The PRIVATE_KEY_USAGE flag is kSecAccessControlPrivateKeyUsage = 1 << 30.
    // If the compiler reports an ambiguous type on the flags argument, use `0x4000_0000_u64`.
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        1 << 30, // kSecAccessControlPrivateKeyUsage
    )
    .map_err(|_| DeviceKeyError::KeyGenerationFailed)?;

    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_label("ezpds-device-rotation-key")
        .set_location(Location::DataProtectionKeychain)
        .set_access_control(access_control); // takes ownership (by value)

    let priv_key = SecKey::new(&opts).map_err(|_| DeviceKeyError::KeyGenerationFailed)?;

    // Retrieve the public key and its external representation.
    // SecKeyCopyExternalRepresentation on the *public* key returns the uncompressed
    // 65-byte X9.62 point (0x04 || x[32] || y[32]).
    let pub_key = priv_key
        .public_key()
        .ok_or(DeviceKeyError::KeyGenerationFailed)?;
    let pub_repr = pub_key
        .external_representation()
        .ok_or(DeviceKeyError::KeyGenerationFailed)?;
    let uncompressed: Vec<u8> = pub_repr.to_vec(); // 65 bytes

    // Compress: prefix byte = 0x02 (even y) or 0x03 (odd y); keep x[32].
    // The last byte of the y coordinate determines parity.
    let mut compressed = [0u8; 33];
    compressed[0] = if uncompressed[64] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    compressed[1..].copy_from_slice(&uncompressed[1..33]);

    // Store the compressed public key for the fast path on future calls.
    crate::keychain::store_item(SE_PUB_ACCOUNT, &compressed).map_err(|e| {
        DeviceKeyError::KeychainError {
            message: e.to_string(),
        }
    })?;

    // Store the application_label (OS-assigned SHA1 of public key, 20 bytes)
    // so sign() can locate the SE private key on future app launches.
    let app_label = priv_key
        .application_label()
        .ok_or(DeviceKeyError::KeyGenerationFailed)?;
    crate::keychain::store_item(SE_APP_LABEL_ACCOUNT, &app_label).map_err(|e| {
        DeviceKeyError::KeychainError {
            message: e.to_string(),
        }
    })?;

    let multibase = multibase::encode(multibase::Base::Base58Btc, &compressed);
    // did:key requires the P-256 multicodec varint prefix [0x80, 0x24] (0x1200 as LEB128).
    const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
    let mut multikey = Vec::with_capacity(2 + compressed.len());
    multikey.extend_from_slice(P256_MULTICODEC);
    multikey.extend_from_slice(&compressed);
    let key_id = format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, &multikey)
    );
    Ok(DevicePublicKey { multibase, key_id })
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::Signature;

    // Load the application_label to look up the SE private key.
    let app_label =
        crate::keychain::get_item(SE_APP_LABEL_ACCOUNT).map_err(|_| DeviceKeyError::KeyNotFound)?;

    // Find the SE private key in the Keychain by its application_label.
    // load_refs(true) returns SearchResult::Ref(CFType) containing the SecKeyRef.
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .application_label(&app_label)
        .load_refs(true)
        .limit(1);

    let results = search.search().map_err(|_| DeviceKeyError::KeyNotFound)?;

    // Extract the SecKey from the typed Reference result.
    // SearchResult::Ref wraps a Reference enum; Reference::Key holds the already-wrapped SecKey.
    // No unsafe code is needed — security_framework handles the SecKeyRef wrapping internally.
    let sec_key = match results.into_iter().next() {
        Some(SearchResult::Ref(Reference::Key(key))) => key,
        _ => return Err(DeviceKeyError::KeyNotFound),
    };

    // create_signature uses kSecKeyAlgorithmECDSASignatureMessageX962SHA256.
    // The SE hashes `data` with SHA-256 internally before signing.
    // Returns DER-encoded ECDSA signature (70–72 bytes).
    let der_sig = sec_key
        .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
        .map_err(|_| DeviceKeyError::SigningFailed)?;

    // Convert DER to raw 64-byte r||s (the format expected by ATProto/did:plc).
    // from_der() is a pure parser — it does NOT normalize low-S. Apple's SE may return
    // high-S signatures. normalize_s() ensures s <= order/2 as required by ATProto.
    let sig = Signature::from_der(&der_sig).map_err(|_| DeviceKeyError::InvalidSignature)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests use the real macOS Keychain under service "ezpds-identity-wallet".
    // Run with `cargo test -- --test-threads=1` to prevent Keychain races between tests.

    // multibase starts with 'z' and decodes to 33 bytes
    #[test]
    fn get_or_create_returns_valid_multibase() {
        let result = get_or_create().expect("get_or_create should succeed");
        assert!(
            result.multibase.starts_with('z'),
            "multibase must start with 'z'"
        );
        let (_, decoded) = multibase::decode(&result.multibase).expect("multibase must decode");
        assert_eq!(decoded.len(), 33, "compressed P-256 point must be 33 bytes");
    }

    // two successive calls are idempotent
    #[test]
    fn get_or_create_is_idempotent() {
        let first = get_or_create().expect("first call should succeed");
        let second = get_or_create().expect("second call should succeed");
        assert_eq!(
            first.multibase, second.multibase,
            "multibase must be stable"
        );
        assert_eq!(first.key_id, second.key_id, "key_id must be stable");
    }

    // key_id starts with "did:key:z"
    #[test]
    fn key_id_has_did_key_prefix() {
        let result = get_or_create().expect("get_or_create should succeed");
        assert!(
            result.key_id.starts_with("did:key:z"),
            "key_id must start with 'did:key:z', got: {}",
            result.key_id
        );
    }

    // sign returns exactly 64 bytes
    #[test]
    fn sign_returns_64_bytes() {
        get_or_create().expect("must have key before signing");
        let sig = sign(b"test payload").expect("sign should succeed");
        assert_eq!(sig.len(), 64, "raw r||s signature must be 64 bytes");
    }

    // signing is deterministic (RFC 6979)
    #[test]
    fn sign_is_deterministic() {
        get_or_create().expect("must have key before signing");
        let sig1 = sign(b"determinism test").expect("first sign should succeed");
        let sig2 = sign(b"determinism test").expect("second sign should succeed");
        assert_eq!(
            sig1, sig2,
            "same data with same key must produce same signature"
        );
    }

    // sign before get_or_create returns KeyNotFound
    #[test]
    fn sign_before_generate_returns_key_not_found() {
        // Delete any key left by previous tests to simulate a fresh state.
        let _ = crate::keychain::delete_item("device-rotation-key-priv");
        let result = sign(b"should fail");
        assert!(
            matches!(result, Err(DeviceKeyError::KeyNotFound)),
            "expected KeyNotFound, got: {:?}",
            result
        );
    }

    // DeviceKeyError variants serialize as { "code": "SCREAMING_SNAKE_CASE" }
    #[test]
    fn device_key_error_serializes_as_code() {
        let err = DeviceKeyError::KeyGenerationFailed;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "KEY_GENERATION_FAILED");

        let err2 = DeviceKeyError::KeyNotFound;
        let json2 = serde_json::to_value(&err2).unwrap();
        assert_eq!(json2["code"], "KEY_NOT_FOUND");

        let err3 = DeviceKeyError::KeychainError {
            message: "os error".into(),
        };
        let json3 = serde_json::to_value(&err3).unwrap();
        assert_eq!(json3["code"], "KEYCHAIN_ERROR");
        assert_eq!(json3["message"], "os error");
    }

    // Ensures DevicePublicKey serializes key_id as keyId (camelCase) for Tauri IPC.
    // Without #[serde(rename_all = "camelCase")], this test fails.
    #[test]
    fn device_public_key_serializes_camel_case() {
        let key = DevicePublicKey {
            multibase: "zTest".into(),
            key_id: "did:key:zTest".into(),
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["multibase"], "zTest");
        assert_eq!(
            json["keyId"], "did:key:zTest",
            "key_id must serialize as keyId for TypeScript"
        );
        // Confirm the snake_case version is NOT present.
        assert!(
            json.get("key_id").is_none(),
            "key_id must not appear as snake_case in JSON"
        );
    }
}
