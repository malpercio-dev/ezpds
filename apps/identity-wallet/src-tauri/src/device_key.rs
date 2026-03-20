use serde::Serialize;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
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
            let keypair = crypto::generate_p256_keypair()
                .map_err(|_| DeviceKeyError::KeyGenerationFailed)?;
            // Deref Zeroizing<[u8; 32]> to [u8; 32], then collect as Vec<u8>.
            let bytes = keypair.private_key_bytes.to_vec();
            crate::keychain::store_item(ACCOUNT, &bytes)
                .map_err(|e| DeviceKeyError::KeychainError { message: e.to_string() })?;
            bytes
        }
    };

    // Reconstruct the public key from stored private bytes.
    let signing_key = SigningKey::from_slice(&private_bytes)
        .map_err(|_| DeviceKeyError::KeychainError { message: "invalid stored key bytes".into() })?;
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
    let key_id = format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, &multikey));

    Ok(DevicePublicKey { multibase, key_id })
}

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::{Signature, SigningKey};
    use p256::ecdsa::signature::Signer;

    const ACCOUNT: &str = "device-rotation-key-priv";

    // If the key doesn't exist, signal that get_or_create must be called first.
    let private_bytes = crate::keychain::get_item(ACCOUNT)
        .map_err(|_| DeviceKeyError::KeyNotFound)?;

    let signing_key = SigningKey::from_slice(&private_bytes)
        .map_err(|_| DeviceKeyError::SigningFailed)?;

    // sign() uses the deterministic Signer impl (RFC 6979 nonce).
    // It internally hashes `data` with SHA-256 before signing.
    let signature: Signature = signing_key.sign(data);

    // to_bytes() returns a fixed 64-byte GenericArray<u8, U64> (raw r||s).
    Ok(signature.to_bytes().to_vec())
}

// ── Real device (Secure Enclave) stubs ───────────────────────────────────────
//
// Phase 1 placeholder. The SE path is implemented in Phase 2.
// These compile for `cargo build --target aarch64-apple-ios` but always error.

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    Err(DeviceKeyError::KeyGenerationFailed)
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn sign(_data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    Err(DeviceKeyError::KeyGenerationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests use the real macOS Keychain under service "ezpds-identity-wallet".
    // Run with `cargo test -- --test-threads=1` to prevent Keychain races between tests.

    // AC1.1 — multibase starts with 'z' and decodes to 33 bytes
    #[test]
    fn get_or_create_returns_valid_multibase() {
        let result = get_or_create().expect("get_or_create should succeed");
        assert!(result.multibase.starts_with('z'), "multibase must start with 'z'");
        let (_, decoded) = multibase::decode(&result.multibase).expect("multibase must decode");
        assert_eq!(decoded.len(), 33, "compressed P-256 point must be 33 bytes");
    }

    // AC1.2 — two successive calls are idempotent
    #[test]
    fn get_or_create_is_idempotent() {
        let first = get_or_create().expect("first call should succeed");
        let second = get_or_create().expect("second call should succeed");
        assert_eq!(first.multibase, second.multibase, "multibase must be stable");
        assert_eq!(first.key_id, second.key_id, "key_id must be stable");
    }

    // AC1.3 — key_id starts with "did:key:z"
    #[test]
    fn key_id_has_did_key_prefix() {
        let result = get_or_create().expect("get_or_create should succeed");
        assert!(
            result.key_id.starts_with("did:key:z"),
            "key_id must start with 'did:key:z', got: {}",
            result.key_id
        );
    }

    // AC3.1 — sign returns exactly 64 bytes
    #[test]
    fn sign_returns_64_bytes() {
        get_or_create().expect("must have key before signing");
        let sig = sign(b"test payload").expect("sign should succeed");
        assert_eq!(sig.len(), 64, "raw r||s signature must be 64 bytes");
    }

    // AC3.2 — signing is deterministic (RFC 6979)
    #[test]
    fn sign_is_deterministic() {
        get_or_create().expect("must have key before signing");
        let sig1 = sign(b"determinism test").expect("first sign should succeed");
        let sig2 = sign(b"determinism test").expect("second sign should succeed");
        assert_eq!(sig1, sig2, "same data with same key must produce same signature");
    }

    // AC3.3 — sign before get_or_create returns KeyNotFound
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

    // AC4.1 — DeviceKeyError variants serialize as { "code": "SCREAMING_SNAKE_CASE" }
    #[test]
    fn device_key_error_serializes_as_code() {
        let err = DeviceKeyError::KeyGenerationFailed;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "KEY_GENERATION_FAILED");

        let err2 = DeviceKeyError::KeyNotFound;
        let json2 = serde_json::to_value(&err2).unwrap();
        assert_eq!(json2["code"], "KEY_NOT_FOUND");

        let err3 = DeviceKeyError::KeychainError { message: "os error".into() };
        let json3 = serde_json::to_value(&err3).unwrap();
        assert_eq!(json3["code"], "KEYCHAIN_ERROR");
        assert_eq!(json3["message"], "os error");
    }
}
