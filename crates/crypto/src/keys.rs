use aes_gcm::aead::{Aead, AeadCore, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use multibase::Base;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand_core::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::CryptoError;

/// P-256 multicodec varint prefix for did:key URIs.
/// 0x1200 encoded as LEB128 varint = [0x80, 0x24].
pub(crate) const P256_MULTICODEC_PREFIX: &[u8] = &[0x80, 0x24];

/// secp256k1 multicodec varint prefix for did:key URIs (`did:key:zQ3…`).
/// 0xe7 encoded as LEB128 varint = [0xe7, 0x01]. The reference ATProto
/// ecosystem (bsky.social) uses secp256k1 rotation/signing keys; this crate
/// verifies against them but never signs with this curve.
pub(crate) const SECP256K1_MULTICODEC_PREFIX: &[u8] = &[0xe7, 0x01];

/// A `did:key:z...` URI — the canonical identifier for a P-256 keypair.
///
/// Distinct from `public_key` (a bare multibase string) at the type level to prevent
/// positional swap bugs in SQL binds and API responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKeyUri(pub String);

impl std::fmt::Display for DidKeyUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A generated P-256 keypair.
///
/// `private_key_bytes` is zeroized on drop. Callers must encrypt it with
/// [`encrypt_private_key`] before storing and drop this struct promptly.
pub struct P256Keypair {
    /// Full `did:key:z...` URI — use as the database primary key.
    pub key_id: DidKeyUri,
    /// Multibase base58btc-encoded compressed public key point (no `did:key:` prefix).
    pub public_key: String,
    /// Raw 32-byte P-256 private key scalar. Zeroized on drop.
    pub private_key_bytes: Zeroizing<[u8; 32]>,
}

/// Generate a fresh P-256 keypair and derive its `did:key` identifier.
pub fn generate_p256_keypair() -> Result<P256Keypair, CryptoError> {
    Ok(keypair_from_secret_key(&SecretKey::random(&mut OsRng)))
}

/// Rebuild a [`P256Keypair`] from a stored 32-byte private scalar.
///
/// Lets a caller that persists only the secret re-derive the `did:key` on demand rather than
/// storing the public half beside it — one stored secret cannot disagree with a public key
/// that was never stored separately.
///
/// Errors when the bytes are not a valid scalar (zero, or ≥ the curve order).
pub fn p256_keypair_from_secret(private_key: &[u8; 32]) -> Result<P256Keypair, CryptoError> {
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|_| CryptoError::KeyGeneration("invalid P-256 private key".to_string()))?;
    Ok(keypair_from_secret_key(&secret_key))
}

/// Decode a P-256 `did:key:z…` URI to its compressed SEC1 public-key bytes.
///
/// The inverse of the encoding in [`keypair_from_secret_key`]. Every layer is validated —
/// the URI prefix, the multibase alphabet, the multicodec prefix, and finally the point
/// itself against the curve — so a caller receives either a genuine P-256 public key or an
/// error, never bytes that merely look like one.
///
/// Rejecting a non-P-256 multicodec (notably secp256k1's `zQ3…`, which is otherwise a
/// perfectly well-formed did:key in this ecosystem) matters: the notification suite is pinned
/// to DHKEM(P-256), so a secp256k1 key would fail deep inside HPKE with an opaque error
/// instead of at the boundary where the caller can say what is wrong.
pub fn p256_public_key_from_did_key(did_key: &str) -> Result<Vec<u8>, CryptoError> {
    let invalid = |why: &str| CryptoError::KeyGeneration(format!("invalid P-256 did:key: {why}"));

    let multibase_part = did_key
        .strip_prefix("did:key:")
        .ok_or_else(|| invalid("missing the did:key: prefix"))?;
    let (_, multikey) =
        multibase::decode(multibase_part).map_err(|_| invalid("not valid multibase"))?;
    let key_bytes = multikey
        .strip_prefix(P256_MULTICODEC_PREFIX)
        .ok_or_else(|| invalid("not a P-256 multicodec key"))?;

    // A validating decode, not a reformat: `p256` rejects off-curve and identity points.
    let public_key =
        p256::PublicKey::from_sec1_bytes(key_bytes).map_err(|_| invalid("not a curve point"))?;
    Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
}

/// Build the public [`P256Keypair`] representation (did:key URI, multibase public key, and
/// zeroized private scalar) from a P-256 `SecretKey`. Shared by [`generate_p256_keypair`] and
/// [`derive_recovery_keypair`] so both emit byte-identical did:key encodings.
fn keypair_from_secret_key(secret_key: &SecretKey) -> P256Keypair {
    let public_key = secret_key.public_key();

    // Compressed point: 0x02/0x03 prefix byte + 32-byte x-coordinate = 33 bytes.
    let compressed = public_key.to_encoded_point(true);
    let compressed_bytes = compressed.as_bytes();

    // did:key multikey: P-256 multicodec varint + compressed public key bytes.
    let mut multikey = Vec::with_capacity(P256_MULTICODEC_PREFIX.len() + compressed_bytes.len());
    multikey.extend_from_slice(P256_MULTICODEC_PREFIX);
    multikey.extend_from_slice(compressed_bytes);

    // multibase::encode with Base58Btc prepends the 'z' prefix automatically.
    let multibase_encoded = multibase::encode(Base::Base58Btc, &multikey);
    let key_id = DidKeyUri(format!("did:key:{multibase_encoded}"));
    let public_key_str = multibase::encode(Base::Base58Btc, compressed_bytes);

    // Copy private key bytes into a Zeroizing wrapper.
    let raw_bytes = Zeroizing::new(secret_key.to_bytes());
    let mut private_key_bytes = Zeroizing::new([0u8; 32]);
    private_key_bytes.copy_from_slice(raw_bytes.as_slice());

    P256Keypair {
        key_id,
        public_key: public_key_str,
        private_key_bytes,
    }
}

/// HKDF salt binding recovery-key derivation to this protocol and version.
const RECOVERY_KEY_HKDF_SALT: &[u8] = b"ezpds/recovery-seed/v1";
/// HKDF `info` domain-separation string. The rejection-sampling counter is appended to this so a
/// rejected candidate scalar re-expands to fresh bytes rather than looping forever.
const RECOVERY_KEY_HKDF_INFO: &[u8] = b"ezpds recovery rotation key (P-256)";

/// Derive the recovery P-256 keypair from a 32-byte recovery seed.
///
/// The recovery seed is the secret reconstructed from the Shamir shares. Its did:key sits in the
/// account's `rotationKeys` (as the recovery slot), so reconstructing the seed and re-deriving this
/// keypair is what lets an owner re-key their DID without the device key.
///
/// Derivation is HKDF-SHA256 with a fixed salt + `info` domain-separation string, rejection-sampled
/// into the P-256 scalar range `[1, n)`: an all-zero or out-of-range candidate re-expands with an
/// incremented counter appended to `info` (overwhelmingly the first candidate succeeds — P-256's
/// order is within ~2⁻³² of 2²⁵⁶). The result is fully deterministic: the same seed always yields
/// the same keypair (pinned by a golden test).
///
/// # Errors
/// Returns [`CryptoError::KeyGeneration`] only in the practically-impossible case that HKDF fails or
/// no valid scalar is found within the counter space.
pub fn derive_recovery_keypair(seed: &[u8; 32]) -> Result<P256Keypair, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(RECOVERY_KEY_HKDF_SALT), seed.as_slice());

    for counter in 0u32..=u32::MAX {
        let mut okm = Zeroizing::new([0u8; 32]);
        // info = domain string || counter(4B, big-endian). The counter only advances on the rare
        // rejection, so a golden seed pins counter 0's output.
        let mut info = Vec::with_capacity(RECOVERY_KEY_HKDF_INFO.len() + 4);
        info.extend_from_slice(RECOVERY_KEY_HKDF_INFO);
        info.extend_from_slice(&counter.to_be_bytes());

        hk.expand(&info, okm.as_mut())
            .map_err(|e| CryptoError::KeyGeneration(format!("hkdf expand: {e}")))?;

        // SecretKey::from_slice rejects a zero scalar or one ≥ the curve order — exactly the
        // rejection-sampling condition — and copies the bytes into its own zeroizing storage rather
        // than a plain FieldBytes. On the near-certain success it returns the scalar in [1, n).
        if let Ok(secret_key) = SecretKey::from_slice(okm.as_slice()) {
            return Ok(keypair_from_secret_key(&secret_key));
        }
    }

    Err(CryptoError::KeyGeneration(
        "exhausted HKDF counter space without a valid P-256 scalar".to_string(),
    ))
}

/// HKDF salt binding delegation-seed derivation to this protocol and version.
const DELEGATION_SEED_HKDF_SALT: &[u8] = b"ezpds/delegation-seed/v1";
/// HKDF `info` domain-separation string for the delegation seed.
const DELEGATION_SEED_HKDF_INFO: &[u8] = b"ezpds delegation seed";

/// HKDF salt binding child-seed derivation to this protocol and version.
const CHILD_SEED_HKDF_SALT: &[u8] = b"ezpds/child-seed/v1";
/// HKDF `info` domain-separation string. The child index is appended big-endian, so each index
/// expands to an independent seed.
const CHILD_SEED_HKDF_INFO: &[u8] = b"ezpds child account seed";

/// Derive the delegation seed — the root of the child-account key subtree — from a recovery seed.
///
/// This is the one at-rest secret the wallet stores per identity to mint child accounts. It sits a
/// full HKDF step below the recovery seed, so compromising it exposes the child subtree and never
/// the recovery seed itself. Callers hold the recovery seed only transiently (share ceremony, or
/// share-recovery verification) and persist just this output.
///
/// HKDF-SHA256, domain-separated by salt + `info`. No rejection sampling: the output is an opaque
/// 32-byte seed, not a curve scalar — the scalar step stays in [`derive_recovery_keypair`], which
/// this hierarchy reuses unchanged as its leaf. The published relative of this construction is
/// SLIP-0010 nist256p1, which likewise wraps HMAC-SHA512/HKDF around a seed to grow a P-256 tree;
/// this one is deliberately simpler (no chain codes, no public-key derivation) because only the
/// holder of the delegation seed ever derives from it.
///
/// **Changing the salt, info string, or ordering here orphans every existing child identity** — the
/// re-derived key would no longer match the one recorded in the child's `rotationKeys` at
/// plc.directory, leaving the account unrecoverable. Pinned by a golden vector.
pub fn derive_delegation_seed(recovery_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(DELEGATION_SEED_HKDF_SALT), recovery_seed.as_slice());
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 bytes is far under HKDF-SHA256's 255*32 output ceiling, the only documented failure.
    hk.expand(DELEGATION_SEED_HKDF_INFO, okm.as_mut())
        .expect("hkdf expand of 32 bytes cannot fail");
    okm
}

/// Derive the seed for child account `index` from a delegation seed.
///
/// Feed the result to [`derive_recovery_keypair`] to get the child's rotation keypair; that leaf
/// step is frozen and shared with recovery keys, so the child key is a P-256 scalar derived by
/// exactly the same already-pinned path.
///
/// HKDF-SHA256 with the index appended big-endian to `info`, so distinct indices yield unrelated
/// seeds and the index space is walked without re-deriving anything. See
/// [`derive_delegation_seed`] for the SLIP-0010 relationship.
///
/// **Changing the salt, info string, or index encoding here orphans every existing child identity.**
/// Pinned by golden vectors.
pub fn derive_child_seed(delegation_seed: &[u8; 32], index: u32) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(CHILD_SEED_HKDF_SALT), delegation_seed.as_slice());
    let mut info = Vec::with_capacity(CHILD_SEED_HKDF_INFO.len() + 4);
    info.extend_from_slice(CHILD_SEED_HKDF_INFO);
    info.extend_from_slice(&index.to_be_bytes());

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut())
        .expect("hkdf expand of 32 bytes cannot fail");
    okm
}

/// Encrypt an arbitrary-length secret using AES-256-GCM.
///
/// The generic-length form of [`encrypt_private_key`], sharing the identical storage
/// envelope — `base64( nonce(12) || ciphertext+tag(16) )` — so a column wrapped with
/// either function decrypts with [`decrypt_secret_bytes`]. Exists for secrets that are
/// not 32-byte key scalars (e.g. a 42-byte Shamir share envelope). A fresh 12-byte
/// nonce is generated from the OS RNG on every call, so two calls with the same input
/// produce different output.
pub fn encrypt_secret_bytes(
    plaintext: &[u8],
    master_key: &[u8; 32],
) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_slice())
        .map_err(|e| CryptoError::Encryption(format!("invalid master key length: {e}")))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // encrypt() appends the 16-byte authentication tag.
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(format!("aes-gcm encryption failed: {e}")))?;

    // Storage format: nonce(12) || ciphertext_with_tag(plaintext_len + 16).
    let mut storage = Vec::with_capacity(12 + ciphertext.len());
    storage.extend_from_slice(nonce.as_slice());
    storage.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&storage))
}

/// Decrypt a secret encrypted by [`encrypt_secret_bytes`] (or [`encrypt_private_key`] —
/// the envelope is identical), returning the plaintext at whatever length it was.
///
/// Returns `CryptoError::Decryption` for any failure — malformed base64, truncated
/// storage, or authentication tag mismatch. The caller cannot distinguish between
/// these cases intentionally (no oracle).
pub fn decrypt_secret_bytes(
    encrypted: &str,
    master_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let storage = BASE64
        .decode(encrypted)
        .map_err(|e| CryptoError::Decryption(format!("invalid base64: {e}")))?;

    // Minimum envelope: nonce(12) + tag(16) around an empty plaintext.
    if storage.len() < 12 + 16 {
        return Err(CryptoError::Decryption(format!(
            "expected at least 28 bytes (nonce + tag), got {}",
            storage.len()
        )));
    }

    let nonce = Nonce::from_slice(&storage[..12]);
    let ciphertext_with_tag = &storage[12..];

    let cipher = Aes256Gcm::new_from_slice(master_key.as_slice())
        .map_err(|e| CryptoError::Decryption(format!("invalid master key length: {e}")))?;

    // Use decrypt() — NOT decrypt_in_place_detached — to avoid GHSA-423w-p2w9-r7vq.
    // Tag is verified before plaintext is returned; wrapped in Zeroizing immediately.
    cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decryption("authentication tag mismatch".to_string()))
}

/// Encrypt a 32-byte P-256 private key using AES-256-GCM.
///
/// Returns `base64( nonce(12) || ciphertext+tag(48) )` — always 80 base64 chars.
/// A fresh 12-byte nonce is generated from the OS RNG on every call, so two calls
/// with the same input produce different output.
pub fn encrypt_private_key(
    key_bytes: &[u8; 32],
    master_key: &[u8; 32],
) -> Result<String, CryptoError> {
    encrypt_secret_bytes(key_bytes.as_slice(), master_key)
}

/// Decrypt a private key encrypted by [`encrypt_private_key`].
///
/// Returns `CryptoError::Decryption` for any failure — malformed base64, wrong
/// length, or authentication tag mismatch. The caller cannot distinguish between
/// these cases intentionally (no oracle).
pub fn decrypt_private_key(
    encrypted: &str,
    master_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let storage = BASE64
        .decode(encrypted)
        .map_err(|e| CryptoError::Decryption(format!("invalid base64: {e}")))?;

    if storage.len() != 60 {
        return Err(CryptoError::Decryption(format!(
            "expected 60 bytes (nonce + ciphertext + tag), got {}",
            storage.len()
        )));
    }

    let nonce = Nonce::from_slice(&storage[..12]);
    let ciphertext_with_tag = &storage[12..];

    let cipher = Aes256Gcm::new_from_slice(master_key.as_slice())
        .map_err(|e| CryptoError::Decryption(format!("invalid master key length: {e}")))?;

    // Use decrypt() — NOT decrypt_in_place_detached — to avoid GHSA-423w-p2w9-r7vq.
    // Tag is verified before plaintext is returned. Wrap the returned buffer in
    // Zeroizing immediately so the decrypted key never outlives this scope unscrubbed.
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| CryptoError::Decryption("authentication tag mismatch".to_string()))?,
    );

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_did_key_round_trips_back_to_its_compressed_point() {
        let keypair = generate_p256_keypair().unwrap();
        let decoded = p256_public_key_from_did_key(&keypair.key_id.0).unwrap();

        assert_eq!(decoded.len(), 33, "compressed SEC1 is 33 bytes");
        let (_, expected) = multibase::decode(&keypair.public_key).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn malformed_did_keys_are_rejected_by_layer() {
        let keypair = generate_p256_keypair().unwrap();
        let multibase_part = keypair.key_id.0.strip_prefix("did:key:").unwrap();

        // Missing prefix, bad multibase, and a valid-multibase-but-wrong-multicodec key.
        assert!(p256_public_key_from_did_key(multibase_part).is_err());
        assert!(p256_public_key_from_did_key("did:key:z!!!not-base58!!!").is_err());

        let secp256k1 = multibase::encode(
            Base::Base58Btc,
            [SECP256K1_MULTICODEC_PREFIX, &[0x02; 33]].concat(),
        );
        let err = p256_public_key_from_did_key(&format!("did:key:{secp256k1}")).unwrap_err();
        assert!(
            err.to_string().contains("multicodec"),
            "a secp256k1 did:key must be refused at the boundary, not inside HPKE: {err}"
        );

        // Right multicodec, but the x-coordinate is larger than the field modulus, so it
        // names no point at all. (A merely arbitrary x is a poor negative case — roughly half
        // of them are genuine curve points.)
        let off_curve = multibase::encode(
            Base::Base58Btc,
            [P256_MULTICODEC_PREFIX, &[0x02], &[0xff; 32][..]].concat(),
        );
        assert!(p256_public_key_from_did_key(&format!("did:key:{off_curve}")).is_err());
    }

    #[test]
    fn generate_keypair_produces_valid_did_key() {
        let keypair = generate_p256_keypair().unwrap();

        // key_id must be a valid did:key URI with P-256 multicodec prefix.
        assert!(
            keypair.key_id.0.starts_with("did:key:z"),
            "key_id must start with did:key:z"
        );

        // Decode the multibase portion and verify the multicodec prefix.
        let multibase_part = keypair.key_id.0.strip_prefix("did:key:").unwrap();
        let (_, multikey_bytes) = multibase::decode(multibase_part).unwrap();
        assert_eq!(
            &multikey_bytes[..2],
            P256_MULTICODEC_PREFIX,
            "multikey must start with P-256 multicodec varint [0x80, 0x24]"
        );
        // P-256 compressed point: 2 (prefix varint) + 33 (compressed) = 35 bytes.
        assert_eq!(multikey_bytes.len(), 35);
    }

    #[test]
    fn generate_keypair_public_key_is_multibase_without_did_prefix() {
        let keypair = generate_p256_keypair().unwrap();

        // public_key is multibase (starts with 'z') but has no 'did:key:' prefix.
        assert!(keypair.public_key.starts_with('z'));
        assert!(!keypair.public_key.starts_with("did:key:"));

        // Decodes to a compressed P-256 point: 33 bytes.
        let (_, point_bytes) = multibase::decode(&keypair.public_key).unwrap();
        assert_eq!(point_bytes.len(), 33);
        assert!(
            point_bytes[0] == 0x02 || point_bytes[0] == 0x03,
            "compressed point prefix must be 0x02 or 0x03"
        );
    }

    #[test]
    fn generate_keypair_private_key_is_32_bytes() {
        let keypair = generate_p256_keypair().unwrap();
        assert_eq!(keypair.private_key_bytes.len(), 32);
    }

    /// Round-trip encrypt → decrypt returns original bytes.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let master_key = [0xab_u8; 32];
        let private_key = [0x42_u8; 32];

        let encrypted = encrypt_private_key(&private_key, &master_key).unwrap();
        let decrypted = decrypt_private_key(&encrypted, &master_key).unwrap();

        assert_eq!(*decrypted, private_key);
    }

    /// Wrong master key returns CryptoError::Decryption.
    #[test]
    fn decrypt_with_wrong_master_key_fails() {
        let master_key = [0xab_u8; 32];
        let wrong_key = [0xcd_u8; 32];
        let private_key = [0x42_u8; 32];

        let encrypted = encrypt_private_key(&private_key, &master_key).unwrap();
        let result = decrypt_private_key(&encrypted, &wrong_key);

        assert!(
            matches!(result, Err(CryptoError::Decryption(_))),
            "expected CryptoError::Decryption, got {result:?}"
        );
    }

    /// Malformed base64 returns CryptoError::Decryption.
    #[test]
    fn decrypt_invalid_base64_fails() {
        let master_key = [0xab_u8; 32];

        let result = decrypt_private_key("not-valid-base64!!!", &master_key);
        assert!(matches!(result, Err(CryptoError::Decryption(_))));
    }

    /// Base64 that decodes but is wrong length.
    #[test]
    fn decrypt_wrong_length_fails() {
        let master_key = [0xab_u8; 32];
        // Valid base64 of 10 bytes — decodes OK but is not 60 bytes.
        let short = BASE64.encode([0u8; 10]);
        let result = decrypt_private_key(&short, &master_key);
        assert!(matches!(result, Err(CryptoError::Decryption(_))));
    }

    /// Two encryptions of the same key produce different ciphertexts (random nonce).
    #[test]
    fn encrypt_produces_different_ciphertexts_for_same_input() {
        let master_key = [0xab_u8; 32];
        let private_key = [0x42_u8; 32];

        let first = encrypt_private_key(&private_key, &master_key).unwrap();
        let second = encrypt_private_key(&private_key, &master_key).unwrap();

        assert_ne!(
            first, second,
            "random nonce must produce distinct ciphertexts"
        );
    }

    #[test]
    fn encrypted_output_is_80_base64_chars() {
        let master_key = [0xab_u8; 32];
        let private_key = [0x42_u8; 32];

        let encrypted = encrypt_private_key(&private_key, &master_key).unwrap();
        assert_eq!(
            encrypted.len(),
            80,
            "base64(60 bytes) must be exactly 80 characters"
        );
    }

    /// The generic-length pair round-trips arbitrary lengths and shares the fixed-length
    /// functions' envelope: a 32-byte secret wrapped by either encryptor decrypts with either
    /// decryptor.
    #[test]
    fn secret_bytes_round_trip_and_envelope_compatibility() {
        let master_key = [0xab_u8; 32];

        for len in [0usize, 1, 32, 42, 100] {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encrypted = encrypt_secret_bytes(&plaintext, &master_key).unwrap();
            let decrypted = decrypt_secret_bytes(&encrypted, &master_key).unwrap();
            assert_eq!(*decrypted, plaintext, "length {len} must round-trip");
            assert!(
                decrypt_secret_bytes(&encrypted, &[0xcd_u8; 32]).is_err(),
                "wrong key must fail"
            );
        }

        let key32 = [0x42_u8; 32];
        let via_fixed = encrypt_private_key(&key32, &master_key).unwrap();
        assert_eq!(
            decrypt_secret_bytes(&via_fixed, &master_key)
                .unwrap()
                .as_slice(),
            key32.as_slice(),
            "fixed-length ciphertext must decrypt via the generic decryptor"
        );
        let via_generic = encrypt_secret_bytes(&key32, &master_key).unwrap();
        assert_eq!(
            *decrypt_private_key(&via_generic, &master_key).unwrap(),
            key32,
            "generic 32-byte ciphertext must decrypt via the fixed-length decryptor"
        );
    }

    /// Truncated generic-envelope storage (shorter than nonce + tag) is refused before decryption.
    #[test]
    fn decrypt_secret_bytes_truncated_storage_fails() {
        let master_key = [0xab_u8; 32];
        let short = BASE64.encode([0u8; 20]);
        assert!(matches!(
            decrypt_secret_bytes(&short, &master_key),
            Err(CryptoError::Decryption(_))
        ));
    }

    // ── Recovery keypair derivation ───────────────────────────────────────────

    /// Golden vector: a fixed seed derives a fixed did:key. Pinning this catches any accidental
    /// change to the HKDF salt/info/counter scheme, which would silently produce a *different*
    /// recovery key and orphan every account whose rotationKeys already carry the old one.
    ///
    /// Seed is the 32 bytes 0x00..=0x1f.
    const GOLDEN_RECOVERY_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const GOLDEN_RECOVERY_DID_KEY: &str =
        "did:key:zDnaeoYytsARBq9NiBk1TbJESQcPRy5RPVvdT7FqpjrQtJ5DL";

    #[test]
    fn derive_recovery_keypair_is_deterministic() {
        let a = derive_recovery_keypair(&GOLDEN_RECOVERY_SEED).unwrap();
        let b = derive_recovery_keypair(&GOLDEN_RECOVERY_SEED).unwrap();
        assert_eq!(a.key_id, b.key_id);
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(*a.private_key_bytes, *b.private_key_bytes);
    }

    #[test]
    fn derive_recovery_keypair_matches_golden() {
        let kp = derive_recovery_keypair(&GOLDEN_RECOVERY_SEED).unwrap();
        assert_eq!(
            kp.key_id.0, GOLDEN_RECOVERY_DID_KEY,
            "recovery-key derivation drifted; if the change is intentional, regenerate the golden"
        );
    }

    // ── Delegation + child seed derivation ────────────────────────────────────

    /// Golden vectors for the child-account key hierarchy. Pinning these catches any accidental
    /// change to the HKDF salt/info/index scheme, which would silently derive *different* child
    /// keys and orphan every child identity whose rotationKeys already carry the old ones.
    ///
    /// Rooted at [`GOLDEN_RECOVERY_SEED`] (0x00..=0x1f).
    const GOLDEN_DELEGATION_SEED_HEX: &str =
        "65bad4d783bf0a2371dcca6d6dd7a8256e6ac32bfb9fb4f809144bbc4dd9aa03";
    const GOLDEN_CHILD_0_SEED_HEX: &str =
        "c9d52b67be6c2fe97f83834cd5c4fb6e05434629db998fcff935447d8d61262a";
    const GOLDEN_CHILD_1_SEED_HEX: &str =
        "0a6453c99c9ebb123c9e9a713695582f197cbc2a77f8259ea4688c73a60f748d";
    /// `derive_recovery_keypair(child_seed(0))` — the frozen leaf step applied to the child seed.
    const GOLDEN_CHILD_0_DID_KEY: &str =
        "did:key:zDnaevCpGTC8k2Lb4jTtsM24JDARvsZDBwRh7uUPZtKDRib4T";

    #[test]
    fn derive_delegation_seed_matches_golden() {
        let seed = derive_delegation_seed(&GOLDEN_RECOVERY_SEED);
        assert_eq!(
            crate::hex::to_hex(seed.as_slice()),
            GOLDEN_DELEGATION_SEED_HEX,
            "delegation-seed derivation drifted; changing it orphans every child identity"
        );
        // A full HKDF step below the recovery seed, never equal to it.
        assert_ne!(*seed, GOLDEN_RECOVERY_SEED);
    }

    #[test]
    fn derive_child_seed_matches_golden_and_is_index_distinct() {
        let delegation = derive_delegation_seed(&GOLDEN_RECOVERY_SEED);
        let c0 = derive_child_seed(&delegation, 0);
        let c1 = derive_child_seed(&delegation, 1);
        assert_eq!(
            crate::hex::to_hex(c0.as_slice()),
            GOLDEN_CHILD_0_SEED_HEX,
            "child-seed derivation drifted; changing it orphans every child identity"
        );
        assert_eq!(crate::hex::to_hex(c1.as_slice()), GOLDEN_CHILD_1_SEED_HEX);
        assert_ne!(*c0, *c1);
        assert_ne!(*c0, *delegation);
    }

    #[test]
    fn derive_child_seed_indices_are_all_distinct() {
        let delegation = derive_delegation_seed(&GOLDEN_RECOVERY_SEED);
        let seeds: std::collections::BTreeSet<[u8; 32]> = (0u32..64)
            .map(|i| *derive_child_seed(&delegation, i))
            .collect();
        assert_eq!(seeds.len(), 64, "child seeds collided across indices");
    }

    #[test]
    fn derive_child_seed_distinct_delegation_seeds_are_independent() {
        let a = derive_child_seed(&[0x11_u8; 32], 0);
        let b = derive_child_seed(&[0x22_u8; 32], 0);
        assert_ne!(*a, *b);
    }

    #[test]
    fn child_keypair_matches_golden() {
        let delegation = derive_delegation_seed(&GOLDEN_RECOVERY_SEED);
        let child = derive_child_seed(&delegation, 0);
        let kp = derive_recovery_keypair(&child).unwrap();
        assert_eq!(
            kp.key_id.0, GOLDEN_CHILD_0_DID_KEY,
            "child keypair drifted; changing it orphans every child identity"
        );
        // The leaf step is shared with recovery keys but the subtree is disjoint from the root.
        assert_ne!(
            kp.key_id.0,
            derive_recovery_keypair(&GOLDEN_RECOVERY_SEED)
                .unwrap()
                .key_id
                .0
        );
    }

    #[test]
    fn derive_recovery_keypair_distinct_seeds_distinct_keys() {
        let a = derive_recovery_keypair(&[0x11_u8; 32]).unwrap();
        let b = derive_recovery_keypair(&[0x22_u8; 32]).unwrap();
        assert_ne!(a.key_id, b.key_id);
    }

    #[test]
    fn derive_recovery_keypair_produces_p256_did_key() {
        let kp = derive_recovery_keypair(&GOLDEN_RECOVERY_SEED).unwrap();
        assert!(kp.key_id.0.starts_with("did:key:z"));
        let multibase_part = kp.key_id.0.strip_prefix("did:key:").unwrap();
        let (_, multikey_bytes) = multibase::decode(multibase_part).unwrap();
        assert_eq!(&multikey_bytes[..2], P256_MULTICODEC_PREFIX);
    }

    /// The derived key must sign a valid low-S signature that verifies against its own did:key —
    /// the same canonical form every other signer in this crate emits.
    #[test]
    fn derived_recovery_key_signs_low_s_and_verifies() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let kp = derive_recovery_keypair(&GOLDEN_RECOVERY_SEED).unwrap();
        let signing_key = SigningKey::from_slice(kp.private_key_bytes.as_slice()).unwrap();

        let message = b"recovery ceremony proof";
        let sig: Signature = signing_key.sign(message);
        // atproto requires low-S; normalize like the crate's other signers do.
        let sig = sig.normalize_s().unwrap_or(sig);
        // A low-S signature has no high-S twin — normalize_s() returns None once already canonical.
        assert!(
            sig.normalize_s().is_none(),
            "signature must be low-S canonical"
        );

        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        crate::plc::verify_p256_signature(&kp.key_id, message, &sig_bytes)
            .expect("derived recovery key must verify its own low-S signature");
    }
}
