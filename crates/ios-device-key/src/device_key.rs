//! The two compile-time key paths behind [`get_or_create`] and [`sign`].
//!
//! The `#[cfg]`s are exact complements, so exactly one path compiles for any target: a real
//! iOS device gets the Secure Enclave, everything else the software key. Stating the software
//! path as "not a real iOS device" rather than enumerating macOS and the simulator is what
//! lets the Linux PDS gate compile and run this crate's tests; it changes nothing for the
//! three Apple targets, which resolve exactly as before.

use crate::{
    keychain_err, make_device_public_key, DeviceKeyAccounts, DeviceKeyError, DevicePublicKey,
    KeychainStore,
};

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
};

// ── Software path (macOS, iOS Simulator, Linux CI host) ──────────────────────
//
// No Secure Enclave hardware, so the private scalar lives in the Keychain.

#[cfg(not(all(target_os = "ios", not(target_env = "sim"))))]
pub fn get_or_create<K: KeychainStore>(
    accounts: &DeviceKeyAccounts,
) -> Result<DevicePublicKey, DeviceKeyError> {
    use p256::ecdsa::SigningKey;

    let account = accounts.private_scalar;

    let private_bytes: Vec<u8> = match K::get(account) {
        Ok(bytes) => bytes,
        // Only a genuine "item not found" means we should mint a key. A transient or
        // permission error must NOT silently generate a new one — that would orphan the
        // device's real key.
        Err(e) if K::is_not_found(&e) => {
            let keypair =
                crypto::generate_p256_keypair().map_err(|_| DeviceKeyError::KeyGenerationFailed)?;
            let bytes = keypair.private_key_bytes.to_vec();
            K::store(account, &bytes).map_err(keychain_err)?;
            bytes
        }
        Err(e) => return Err(keychain_err(e)),
    };

    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| DeviceKeyError::KeychainError {
            message: "invalid stored key bytes".into(),
        })?;
    let encoded = signing_key.verifying_key().to_encoded_point(true);

    Ok(make_device_public_key(encoded.as_bytes()))
}

#[cfg(not(all(target_os = "ios", not(target_env = "sim"))))]
pub fn sign<K: KeychainStore>(
    accounts: &DeviceKeyAccounts,
    data: &[u8],
) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    let private_bytes = K::get(accounts.private_scalar).map_err(|e| {
        if K::is_not_found(&e) {
            DeviceKeyError::KeyNotFound
        } else {
            keychain_err(e)
        }
    })?;

    let signing_key =
        SigningKey::from_slice(&private_bytes).map_err(|_| DeviceKeyError::SigningFailed)?;

    // The deterministic Signer impl (RFC 6979 nonce); it hashes `data` with SHA-256 first.
    let signature: Signature = signing_key.sign(data);

    // Normalize to low-S. The verifiers on the other end reject high-S, and RFC 6979 fixes
    // only the nonce — without this roughly half of all signatures would be rejected even
    // though they are mathematically valid.
    let signature = signature.normalize_s().unwrap_or(signature);

    Ok(signature.to_bytes().to_vec())
}

// ── Real device (Secure Enclave) path ────────────────────────────────────────
//
// The SE private key is permanent and non-extractable; the public key and
// application_label (SHA1 hash) are stored in the regular Keychain for lookup.

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn get_or_create<K: KeychainStore>(
    accounts: &DeviceKeyAccounts,
) -> Result<DevicePublicKey, DeviceKeyError> {
    // Fast path: both metadata accounts present means the key already exists, so no SE
    // hardware interaction is needed. Checking both keeps a half-written pair from being
    // read as complete.
    match (
        K::get(accounts.public_key),
        K::get(accounts.application_label),
    ) {
        (Ok(compressed), Ok(_)) => {
            return Ok(make_device_public_key(&compressed));
        }
        (Err(e), _) | (_, Err(e)) if !K::is_not_found(&e) => {
            // Transient OS error — do not fall through to generation.
            return Err(keychain_err(e));
        }
        _ => {
            // One or both missing — fall through to generate.
        }
    }

    // set_location(DataProtectionKeychain) is required — without it, security_framework sets
    // kSecAttrIsPermanent = false, meaning the key is not persisted to the Keychain and will
    // not survive app restart.
    // set_access_control with PRIVATE_KEY_USAGE is required for SE keys — the SE enforces
    // that only explicitly-authorized operations can use the private key for signing.
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        1 << 30, // kSecAccessControlPrivateKeyUsage
    )
    .map_err(|_| DeviceKeyError::KeyGenerationFailed)?;

    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_label(accounts.secure_enclave_label)
        .set_location(Location::DataProtectionKeychain)
        .set_access_control(access_control); // takes ownership (by value)

    let priv_key = SecKey::new(&opts).map_err(|_| DeviceKeyError::KeyGenerationFailed)?;

    // SecKeyCopyExternalRepresentation on the *public* key returns the uncompressed
    // 65-byte X9.62 point (0x04 || x[32] || y[32]).
    let pub_key = priv_key
        .public_key()
        .ok_or(DeviceKeyError::KeyGenerationFailed)?;
    let pub_repr = pub_key
        .external_representation()
        .ok_or(DeviceKeyError::KeyGenerationFailed)?;
    let uncompressed: Vec<u8> = pub_repr.to_vec();

    // Compress: prefix byte = 0x02 (even y) or 0x03 (odd y); keep x[32].
    let mut compressed = [0u8; 33];
    compressed[0] = if uncompressed[64] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    compressed[1..].copy_from_slice(&uncompressed[1..33]);

    K::store(accounts.public_key, &compressed).map_err(keychain_err)?;

    // Roll the public account back if the label cannot be stored: a public key with no label
    // is unusable and would take the fast path above forever.
    let app_label = priv_key.application_label().ok_or_else(|| {
        let _ = K::delete(accounts.public_key);
        DeviceKeyError::KeychainError {
            message: "SE key created but application_label returned None; do not retry".into(),
        }
    })?;
    K::store(accounts.application_label, &app_label).map_err(|e| {
        let _ = K::delete(accounts.public_key);
        keychain_err(e)
    })?;

    Ok(make_device_public_key(&compressed))
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn sign<K: KeychainStore>(
    accounts: &DeviceKeyAccounts,
    data: &[u8],
) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::Signature;

    let app_label = K::get(accounts.application_label).map_err(|e| {
        if K::is_not_found(&e) {
            DeviceKeyError::KeyNotFound
        } else {
            keychain_err(e)
        }
    })?;

    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .application_label(&app_label)
        .load_refs(true)
        .limit(1);

    let results = search.search().map_err(keychain_err)?;

    let sec_key = match results.into_iter().next() {
        Some(SearchResult::Ref(Reference::Key(key))) => key,
        _ => return Err(DeviceKeyError::KeyNotFound),
    };

    // kSecKeyAlgorithmECDSASignatureMessageX962SHA256: the SE hashes `data` with SHA-256
    // internally and returns a DER-encoded signature (70–72 bytes).
    let der_sig = sec_key
        .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
        .map_err(|_| DeviceKeyError::SigningFailed)?;

    // from_der() is a pure parser — it does NOT normalize low-S, and Apple's SE may return
    // high-S signatures, so normalize explicitly.
    let sig = Signature::from_der(&der_sig).map_err(|_| DeviceKeyError::InvalidSignature)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fmt;

    const ACCOUNTS: DeviceKeyAccounts = DeviceKeyAccounts {
        private_scalar: "test-device-key-priv",
        public_key: "test-device-key-pub",
        application_label: "test-device-key-app-label",
        secure_enclave_label: "test-device-key",
    };

    thread_local! {
        static ITEMS: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());
        /// Set to make the next `get` fail as a transient error rather than an absence.
        static FAIL_READS: RefCell<bool> = const { RefCell::new(false) };
    }

    #[derive(Debug)]
    enum TestError {
        NotFound,
        Transient,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TestError::NotFound => write!(f, "item not found"),
                TestError::Transient => write!(f, "keychain unavailable"),
            }
        }
    }

    struct TestStore;

    impl KeychainStore for TestStore {
        type Error = TestError;

        fn get(account: &str) -> Result<Vec<u8>, TestError> {
            if FAIL_READS.with(|f| *f.borrow()) {
                return Err(TestError::Transient);
            }
            ITEMS.with(|s| s.borrow().get(account).cloned().ok_or(TestError::NotFound))
        }

        fn store(account: &str, data: &[u8]) -> Result<(), TestError> {
            ITEMS.with(|s| s.borrow_mut().insert(account.to_string(), data.to_vec()));
            Ok(())
        }

        fn delete(account: &str) -> Result<(), TestError> {
            ITEMS.with(|s| s.borrow_mut().remove(account));
            Ok(())
        }

        fn is_not_found(error: &TestError) -> bool {
            matches!(error, TestError::NotFound)
        }
    }

    fn reset() {
        ITEMS.with(|s| s.borrow_mut().clear());
        FAIL_READS.with(|f| *f.borrow_mut() = false);
    }

    fn create() -> DevicePublicKey {
        get_or_create::<TestStore>(&ACCOUNTS).expect("get_or_create should succeed")
    }

    #[test]
    fn get_or_create_returns_valid_multibase() {
        reset();
        let result = create();
        assert!(
            result.multibase.starts_with('z'),
            "multibase must start with 'z'"
        );
        let (_, decoded) = multibase::decode(&result.multibase).expect("multibase must decode");
        assert_eq!(decoded.len(), 33, "compressed P-256 point must be 33 bytes");
    }

    #[test]
    fn get_or_create_is_idempotent() {
        reset();
        let first = create();
        let second = create();
        assert_eq!(
            first.multibase, second.multibase,
            "multibase must be stable"
        );
        assert_eq!(first.key_id, second.key_id, "key_id must be stable");
    }

    #[test]
    fn key_id_has_did_key_prefix() {
        reset();
        let result = create();
        assert!(
            result.key_id.starts_with("did:key:z"),
            "key_id must start with 'did:key:z', got: {}",
            result.key_id
        );
    }

    /// A Keychain that is failing rather than empty must never be read as "no key yet":
    /// minting a replacement orphans the device's real key with no way back.
    #[test]
    fn a_transient_keychain_error_does_not_mint_a_new_key() {
        reset();
        let original = create();

        FAIL_READS.with(|f| *f.borrow_mut() = true);
        assert!(
            matches!(
                get_or_create::<TestStore>(&ACCOUNTS),
                Err(DeviceKeyError::KeychainError { .. })
            ),
            "a transient read failure must surface, not mint"
        );
        assert!(
            matches!(
                sign::<TestStore>(&ACCOUNTS, b"x"),
                Err(DeviceKeyError::KeychainError { .. })
            ),
            "a transient read failure must not masquerade as KeyNotFound"
        );

        FAIL_READS.with(|f| *f.borrow_mut() = false);
        assert_eq!(
            create().multibase,
            original.multibase,
            "the original key survived the outage"
        );
    }

    #[test]
    fn sign_returns_64_bytes() {
        reset();
        create();
        let sig = sign::<TestStore>(&ACCOUNTS, b"test payload").expect("sign should succeed");
        assert_eq!(sig.len(), 64, "raw r||s signature must be 64 bytes");
    }

    #[test]
    fn sign_is_deterministic() {
        reset();
        create();
        let sig1 = sign::<TestStore>(&ACCOUNTS, b"determinism test").expect("first sign");
        let sig2 = sign::<TestStore>(&ACCOUNTS, b"determinism test").expect("second sign");
        assert_eq!(
            sig1, sig2,
            "same data with same key must produce same signature"
        );
    }

    /// The round trip: a signature produced by `sign` verifies against the public key
    /// `get_or_create` advertised. This is the contract every remote verifier relies on.
    #[test]
    fn sign_output_verifies_against_public_key() {
        reset();
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let key = create();
        let (_, compressed) = multibase::decode(&key.multibase).expect("must decode");
        let verifying_key = VerifyingKey::from_sec1_bytes(&compressed).expect("must parse");
        let data = b"verification test";
        let sig_bytes = sign::<TestStore>(&ACCOUNTS, data).expect("sign must succeed");
        let sig = Signature::from_bytes(sig_bytes.as_slice().into()).expect("must parse sig");
        verifying_key
            .verify(data, &sig)
            .expect("signature must verify");
    }

    #[test]
    fn sign_before_generate_returns_key_not_found() {
        reset();
        let result = sign::<TestStore>(&ACCOUNTS, b"should fail");
        assert!(
            matches!(result, Err(DeviceKeyError::KeyNotFound)),
            "expected KeyNotFound, got: {result:?}"
        );
    }

    /// Signatures must be in low-S form; the verifiers on the other end reject high-S.
    /// `normalize_s()` returns None when the signature is already low-S.
    #[test]
    fn sign_produces_low_s_signature() {
        reset();
        use p256::ecdsa::Signature;
        create();
        let sig_bytes = sign::<TestStore>(&ACCOUNTS, b"low-s test").expect("sign must succeed");
        let sig = Signature::from_bytes(sig_bytes.as_slice().into()).expect("must parse sig");
        assert!(
            sig.normalize_s().is_none(),
            "signature must already be in low-S form"
        );
    }

    /// The IPC error shape both apps' TypeScript unions mirror.
    #[test]
    fn device_key_error_serializes_as_code() {
        let cases = [
            (DeviceKeyError::KeyGenerationFailed, "KEY_GENERATION_FAILED"),
            (DeviceKeyError::KeyNotFound, "KEY_NOT_FOUND"),
            (DeviceKeyError::SigningFailed, "SIGNING_FAILED"),
            (DeviceKeyError::InvalidSignature, "INVALID_SIGNATURE"),
        ];
        for (err, code) in cases {
            let json = serde_json::to_value(&err).unwrap();
            assert_eq!(json["code"], code);
        }

        let with_message = DeviceKeyError::KeychainError {
            message: "os error".into(),
        };
        let json = serde_json::to_value(&with_message).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
        assert_eq!(json["message"], "os error");
    }

    /// `key_id` must reach TypeScript as `keyId`.
    #[test]
    fn device_public_key_serializes_camel_case() {
        let key = DevicePublicKey {
            multibase: "zTest".into(),
            key_id: "did:key:zTest".into(),
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["multibase"], "zTest");
        assert_eq!(json["keyId"], "did:key:zTest");
        assert!(
            json.get("key_id").is_none(),
            "key_id must not appear as snake_case in JSON"
        );
    }
}
