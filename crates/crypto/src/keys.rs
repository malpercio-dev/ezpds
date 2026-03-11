use aes_gcm::aead::{Aead, AeadCore, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use multibase::Base;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::CryptoError;

/// P-256 multicodec varint prefix for did:key URIs.
/// 0x1200 encoded as LEB128 varint = [0x80, 0x24].
const P256_MULTICODEC_PREFIX: &[u8] = &[0x80, 0x24];

/// A generated P-256 keypair.
///
/// `private_key_bytes` is zeroized on drop. Callers must encrypt it with
/// [`encrypt_private_key`] before storing and drop this struct promptly.
pub struct P256Keypair {
    /// Full `did:key:z...` URI — use as the database primary key.
    pub key_id: String,
    /// Multibase base58btc-encoded compressed public key point (no `did:key:` prefix).
    pub public_key: String,
    /// Raw 32-byte P-256 private key scalar. Zeroized on drop.
    pub private_key_bytes: Zeroizing<[u8; 32]>,
}

/// Generate a fresh P-256 keypair and derive its `did:key` identifier.
pub fn generate_p256_keypair() -> Result<P256Keypair, CryptoError> {
    let secret_key = SecretKey::random(&mut OsRng);
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
    let key_id = format!("did:key:{multibase_encoded}");
    let public_key_str = multibase::encode(Base::Base58Btc, compressed_bytes);

    // Copy private key bytes into a Zeroizing wrapper.
    let raw_bytes = secret_key.to_bytes();
    let mut private_key_bytes = Zeroizing::new([0u8; 32]);
    private_key_bytes.copy_from_slice(raw_bytes.as_slice());

    Ok(P256Keypair {
        key_id,
        public_key: public_key_str,
        private_key_bytes,
    })
}

/// Encrypt a 32-byte P-256 private key using AES-256-GCM.
///
/// Returns `base64( nonce(12) || ciphertext+tag(48) )` — always 80 base64 chars.
/// A fresh 12-byte nonce is generated from the OS RNG on every call, so two calls
/// with the same input produce different output (AC3.4).
pub fn encrypt_private_key(
    key_bytes: &[u8; 32],
    master_key: &[u8; 32],
) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_slice())
        .map_err(|e| CryptoError::Encryption(format!("invalid master key length: {e}")))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // encrypt() appends the 16-byte authentication tag: output = 32 + 16 = 48 bytes.
    let ciphertext = cipher
        .encrypt(&nonce, key_bytes.as_slice())
        .map_err(|e| CryptoError::Encryption(format!("aes-gcm encryption failed: {e}")))?;

    // Storage format: nonce(12) || ciphertext_with_tag(48) = 60 bytes → 80 base64 chars.
    let mut storage = Vec::with_capacity(12 + ciphertext.len());
    storage.extend_from_slice(nonce.as_slice());
    storage.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&storage))
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
    // Tag is verified before plaintext is returned.
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| CryptoError::Decryption("authentication tag mismatch".to_string()))?;

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_did_key() {
        let keypair = generate_p256_keypair().unwrap();

        // key_id must be a valid did:key URI with P-256 multicodec prefix.
        assert!(
            keypair.key_id.starts_with("did:key:z"),
            "key_id must start with did:key:z"
        );

        // Decode the multibase portion and verify the multicodec prefix.
        let multibase_part = keypair.key_id.strip_prefix("did:key:").unwrap();
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

    /// MM-92.AC3.1: Round-trip encrypt → decrypt returns original bytes.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let master_key = [0xab_u8; 32];
        let private_key = [0x42_u8; 32];

        let encrypted = encrypt_private_key(&private_key, &master_key).unwrap();
        let decrypted = decrypt_private_key(&encrypted, &master_key).unwrap();

        assert_eq!(*decrypted, private_key);
    }

    /// MM-92.AC3.2: Wrong master key returns CryptoError::Decryption.
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

    /// MM-92.AC3.3: Malformed base64 returns CryptoError::Decryption.
    #[test]
    fn decrypt_invalid_base64_fails() {
        let master_key = [0xab_u8; 32];

        let result = decrypt_private_key("not-valid-base64!!!", &master_key);
        assert!(matches!(result, Err(CryptoError::Decryption(_))));
    }

    /// MM-92.AC3.3 (variant): Base64 that decodes but is wrong length.
    #[test]
    fn decrypt_wrong_length_fails() {
        let master_key = [0xab_u8; 32];
        // Valid base64 of 10 bytes — decodes OK but is not 60 bytes.
        let short = BASE64.encode(&[0u8; 10]);
        let result = decrypt_private_key(&short, &master_key);
        assert!(matches!(result, Err(CryptoError::Decryption(_))));
    }

    /// MM-92.AC3.4: Two encryptions of the same key produce different ciphertexts (random nonce).
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
}
