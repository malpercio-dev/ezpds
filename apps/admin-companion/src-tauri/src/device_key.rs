//! Per-device admin key: a P-256 keypair the operator console uses to sign every
//! request to the relay. Ported from the identity-wallet device-key module
//! ([`apps/identity-wallet/src-tauri/src/device_key.rs`]); the cryptography is
//! identical, only the framing differs.
//!
//! In the identity wallet this key signs did:plc rotation operations. Here it is
//! the device's *admin credential*: the relay stores only the public key (as a
//! `did:key`) and verifies the signature on each request, so no replayable
//! secret ever sits on the phone. Request-envelope signing (binding method, path,
//! timestamp, nonce, and a body hash) is layered on top elsewhere; this module
//! owns only key generation and raw message signing.
//!
//! Two compile-time paths share one public API (`get_or_create`, `sign`):
//!   - **Secure Enclave** on a real iOS device — the private key is generated in,
//!     and never leaves, the SE.
//!   - **Software key** on macOS (`cargo test`) and the iOS Simulator, which have
//!     no SE hardware — the private scalar lives in the (test or real) Keychain.

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
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` for the frontend, matching
/// the error-shape convention shared across both apps' Tauri commands.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceKeyError {
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("key not found; call get_or_create before sign")]
    KeyNotFound,
    #[error("signing failed")]
    SigningFailed,
    /// DER → r||s parse failed. Constructed only on the Secure Enclave path; the
    /// software path never DER-parses, so the host build sees it as unconstructed —
    /// but the variant stays in the serialized contract the frontend's
    /// `DeviceKeyError` union mirrors.
    #[allow(dead_code)]
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("keychain error: {message}")]
    KeychainError { message: String },
}

// ── Admin device-key Keychain account names ─────────────────────────────────
//
// The single admin device key for this app. Software path uses only the
// private-scalar account; the Secure Enclave path uses the pub + app-label
// metadata accounts (the SE private key never leaves the enclave).
const DEVICE_KEY_PRIV_ACCOUNT: &str = "admin-device-key-priv";
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
const DEVICE_KEY_PUB_ACCOUNT: &str = "admin-device-key-pub";
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
const DEVICE_KEY_APP_LABEL_ACCOUNT: &str = "admin-device-key-app-label";

// ── Error helpers ─────────────────────────────────────────────────────────────

/// Wrap any display-able error as [`DeviceKeyError::KeychainError`].
/// Avoids repeating the struct literal at every map_err call site.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn keychain_err(e: impl std::fmt::Display) -> DeviceKeyError {
    DeviceKeyError::KeychainError {
        message: e.to_string(),
    }
}

// ── did:key construction ──────────────────────────────────────────────────────

/// Build a [`DevicePublicKey`] from a compressed (33-byte SEC1) P-256 point.
///
/// Produces the multibase base58btc encoding of the raw point and the full
/// did:key URI (P-256 multicodec varint prefix [0x80, 0x24] prepended, then
/// base58btc-encoded). This matches `crates/crypto/src/keys.rs`
/// `P256_MULTICODEC_PREFIX = &[0x80, 0x24]`, which is `pub(crate)` there and
/// cannot be imported across crate boundaries — the constant is duplicated
/// intentionally (same rationale as the identity-wallet module).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn make_device_public_key(compressed: &[u8]) -> DevicePublicKey {
    let multibase = multibase::encode(multibase::Base::Base58Btc, compressed);
    const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
    let mut multikey = Vec::with_capacity(2 + compressed.len());
    multikey.extend_from_slice(P256_MULTICODEC);
    multikey.extend_from_slice(compressed);
    let key_id = format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, &multikey)
    );
    DevicePublicKey { multibase, key_id }
}

// ── Simulator / macOS host path ───────────────────────────────────────────────
//
// Covers:
//   - macOS (target_os = "macos"): used for `cargo test` on developer machines
//   - iOS Simulator (target_os = "ios", target_env = "sim"): no Secure Enclave hardware

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    use p256::ecdsa::SigningKey;

    const ACCOUNT: &str = DEVICE_KEY_PRIV_ACCOUNT;

    // Try to load existing private key bytes from Keychain.
    let private_bytes: Vec<u8> = match crate::keychain::get_item(ACCOUNT) {
        Ok(bytes) => bytes,
        // Only a genuine "item not found" means we should mint a key. A transient or
        // permission error must NOT silently generate a new one — that would orphan the
        // device's real admin key and re-enroll this device as a stranger to the relay.
        Err(e) if crate::keychain::is_not_found(&e) => {
            let keypair =
                crypto::generate_p256_keypair().map_err(|_| DeviceKeyError::KeyGenerationFailed)?;
            let bytes = keypair.private_key_bytes.to_vec();
            crate::keychain::store_item(ACCOUNT, &bytes).map_err(keychain_err)?;
            bytes
        }
        Err(e) => return Err(keychain_err(e)),
    };

    // Reconstruct the public key from stored private bytes.
    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| DeviceKeyError::KeychainError {
            message: "invalid stored key bytes".into(),
        })?;
    let encoded = signing_key.verifying_key().to_encoded_point(true); // compressed (33 bytes)
    let compressed = encoded.as_bytes();

    Ok(make_device_public_key(compressed))
}

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    const ACCOUNT: &str = DEVICE_KEY_PRIV_ACCOUNT;

    // If the key doesn't exist, signal that get_or_create must be called first.
    // Distinguish ItemNotFound from other OS errors.
    let private_bytes = crate::keychain::get_item(ACCOUNT).map_err(|e| {
        if crate::keychain::is_not_found(&e) {
            DeviceKeyError::KeyNotFound
        } else {
            keychain_err(e)
        }
    })?;

    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| DeviceKeyError::SigningFailed)?;

    // sign() uses the deterministic Signer impl (RFC 6979 nonce).
    // It internally hashes `data` with SHA-256 before signing.
    let signature: Signature = signing_key.sign(data);

    // Normalize to low-S form. The relay verifies P-256 signatures via the same
    // crypto crate the PLC directory uses, which rejects high-S; without this,
    // roughly half of all signatures would be rejected even though they are
    // mathematically valid. normalize_s() returns Some(normalized) if s was high,
    // None if already low.
    let signature = signature.normalize_s().unwrap_or(signature);

    // to_bytes() returns a fixed 64-byte GenericArray<u8, U64> (raw r||s).
    Ok(signature.to_bytes().to_vec())
}

// ── Real device (Secure Enclave) path ────────────────────────────────────────
//
// The SE private key is permanent and non-extractable; the public key and
// application_label (SHA1 hash) are stored in the regular Keychain for lookup.

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    // Fast path: if we already stored the compressed public key and app_label, return it directly.
    // This avoids SE hardware interaction on every call after first generation.
    // Check BOTH accounts to ensure state consistency.
    match (
        crate::keychain::get_item(DEVICE_KEY_PUB_ACCOUNT),
        crate::keychain::get_item(DEVICE_KEY_APP_LABEL_ACCOUNT),
    ) {
        (Ok(compressed), Ok(_)) => {
            // Both present — fast path. Return the cached public key.
            return Ok(make_device_public_key(&compressed));
        }
        (Err(e), _) | (_, Err(e)) if !crate::keychain::is_not_found(&e) => {
            // Transient OS error — do not fall through to generation.
            return Err(keychain_err(e));
        }
        _ => {
            // One or both missing — fall through to generate.
        }
    }

    // Generate a new SE-backed P-256 key.
    // set_location(DataProtectionKeychain) is required — without it, security_framework sets
    // kSecAttrIsPermanent = false, meaning the key is not persisted to the Keychain and will
    // not survive app restart.
    // set_access_control with PRIVATE_KEY_USAGE is required for SE keys — the SE enforces
    // that only explicitly-authorized operations can use the private key for signing.
    // The PRIVATE_KEY_USAGE flag is kSecAccessControlPrivateKeyUsage = 1 << 30.
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        1 << 30, // kSecAccessControlPrivateKeyUsage
    )
    .map_err(|_| DeviceKeyError::KeyGenerationFailed)?;

    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_label("ezpds-admin-device-key")
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
    crate::keychain::store_item(DEVICE_KEY_PUB_ACCOUNT, &compressed).map_err(keychain_err)?;

    // Get and store application_label. Roll back the pub account if this fails.
    let app_label = priv_key.application_label().ok_or_else(|| {
        let _ = crate::keychain::delete_item(DEVICE_KEY_PUB_ACCOUNT);
        DeviceKeyError::KeychainError {
            message: "SE key created but application_label returned None; do not retry".into(),
        }
    })?;
    crate::keychain::store_item(DEVICE_KEY_APP_LABEL_ACCOUNT, &app_label).map_err(|e| {
        let _ = crate::keychain::delete_item(DEVICE_KEY_PUB_ACCOUNT);
        keychain_err(e)
    })?;

    Ok(make_device_public_key(&compressed))
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::Signature;

    // Load the application_label to look up the SE private key. Distinguish a genuine
    // not-found (key was never created) from a transient/permission error, so a flaky
    // Keychain read does not masquerade as "no key" and trip the caller into re-pairing.
    let app_label = crate::keychain::get_item(DEVICE_KEY_APP_LABEL_ACCOUNT).map_err(|e| {
        if crate::keychain::is_not_found(&e) {
            DeviceKeyError::KeyNotFound
        } else {
            keychain_err(e)
        }
    })?;

    // Find the SE private key in the Keychain by its application_label.
    // load_refs(true) returns SearchResult::Ref(CFType) containing the SecKeyRef.
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .application_label(&app_label)
        .load_refs(true)
        .limit(1);

    let results = search.search().map_err(keychain_err)?;

    // Extract the SecKey from the typed Reference result.
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

    // Convert DER to raw 64-byte r||s. from_der() is a pure parser — it does NOT
    // normalize low-S, and Apple's SE may return high-S signatures, so normalize
    // explicitly (the relay's verifier rejects high-S).
    let sig = Signature::from_der(&der_sig).map_err(|_| DeviceKeyError::InvalidSignature)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // multibase starts with 'z' and decodes to 33 bytes
    #[test]
    fn get_or_create_returns_valid_multibase() {
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
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
        crate::keychain::clear_for_test();
        get_or_create().expect("must have key before signing");
        let sig = sign(b"test payload").expect("sign should succeed");
        assert_eq!(sig.len(), 64, "raw r||s signature must be 64 bytes");
    }

    // signing is deterministic (RFC 6979)
    #[test]
    fn sign_is_deterministic() {
        crate::keychain::clear_for_test();
        get_or_create().expect("must have key before signing");
        let sig1 = sign(b"determinism test").expect("first sign should succeed");
        let sig2 = sign(b"determinism test").expect("second sign should succeed");
        assert_eq!(
            sig1, sig2,
            "same data with same key must produce same signature"
        );
    }

    // The round-trip: a signature produced by sign() verifies against the public key
    // get_or_create() advertised. This is the exact contract the relay's require_admin
    // guard relies on.
    #[test]
    fn sign_output_verifies_against_public_key() {
        crate::keychain::clear_for_test();
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let key = get_or_create().expect("must have key");
        let (_, compressed) = multibase::decode(&key.multibase).expect("must decode");
        let verifying_key = VerifyingKey::from_sec1_bytes(&compressed).expect("must parse");
        let data = b"verification test";
        let sig_bytes = sign(data).expect("sign must succeed");
        let sig = Signature::from_bytes(sig_bytes.as_slice().into()).expect("must parse sig");
        verifying_key
            .verify(data, &sig)
            .expect("signature must verify");
    }

    // sign before get_or_create returns KeyNotFound
    #[test]
    fn sign_before_generate_returns_key_not_found() {
        crate::keychain::clear_for_test();
        let _ = crate::keychain::delete_item(DEVICE_KEY_PRIV_ACCOUNT);
        let result = sign(b"should fail");
        assert!(
            matches!(result, Err(DeviceKeyError::KeyNotFound)),
            "expected KeyNotFound, got: {:?}",
            result
        );
    }

    // Signatures must be in low-S form; the relay's verifier rejects high-S.
    // normalize_s() returns None when the signature is already low-S.
    #[test]
    fn sign_produces_low_s_signature() {
        crate::keychain::clear_for_test();
        use p256::ecdsa::Signature;
        get_or_create().expect("must have key");
        let sig_bytes = sign(b"low-s test").expect("sign must succeed");
        let sig = Signature::from_bytes(sig_bytes.as_slice().into()).expect("must parse sig");
        assert!(
            sig.normalize_s().is_none(),
            "signature must already be in low-S form (normalize_s returns None when already low-S)"
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

        let err3 = DeviceKeyError::SigningFailed;
        let json3 = serde_json::to_value(&err3).unwrap();
        assert_eq!(json3["code"], "SIGNING_FAILED");

        let err4 = DeviceKeyError::InvalidSignature;
        let json4 = serde_json::to_value(&err4).unwrap();
        assert_eq!(json4["code"], "INVALID_SIGNATURE");

        let err5 = DeviceKeyError::KeychainError {
            message: "os error".into(),
        };
        let json5 = serde_json::to_value(&err5).unwrap();
        assert_eq!(json5["code"], "KEYCHAIN_ERROR");
        assert_eq!(json5["message"], "os error");
    }

    // Ensures DevicePublicKey serializes key_id as keyId (camelCase) for Tauri IPC.
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
        assert!(
            json.get("key_id").is_none(),
            "key_id must not appear as snake_case in JSON"
        );
    }
}
