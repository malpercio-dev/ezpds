# Crypto Crate

Last verified: 2026-03-11

## Purpose
Provides cryptographic primitives for the ezpds workspace: P-256 key generation,
did:key derivation, and AES-256-GCM encryption/decryption of private key material.
This is a pure functional core -- no I/O, no database, no config.

## Contracts
- **Exposes**: `generate_p256_keypair() -> Result<P256Keypair, CryptoError>`, `encrypt_private_key(&[u8; 32], &[u8; 32]) -> Result<String, CryptoError>`, `decrypt_private_key(&str, &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError>`, `P256Keypair`, `CryptoError`
- **P256Keypair fields**: `key_id` (full `did:key:z...` URI), `public_key` (multibase base58btc compressed point, no did:key: prefix), `private_key_bytes` (`Zeroizing<[u8; 32]>` -- zeroized on drop)
- **Encryption format**: `base64(nonce(12) || ciphertext(32) || tag(16))` = 80 base64 chars. Fresh 12-byte nonce from OS RNG per call.
- **did:key format**: P-256 multicodec varint `[0x80, 0x24]` + compressed public key, multibase base58btc encoded
- **CryptoError variants**: `KeyGeneration`, `Encryption`, `Decryption`, `InvalidKeyId`

## Dependencies
- **Uses**: p256 (ECDSA/key generation), aes-gcm (AES-256-GCM), multibase (base58btc encoding), rand_core (OS RNG), base64 (storage encoding), zeroize (secret cleanup)
- **Used by**: `crates/relay/` (key generation endpoint)

## Invariants
- Private key bytes are always wrapped in `Zeroizing` -- callers must not copy them into non-zeroizing storage
- `encrypt_private_key` always generates a fresh nonce; two calls with identical input produce different ciphertext
- `decrypt_private_key` returns a single opaque `CryptoError::Decryption` for all failure modes (no oracle)

## Key Files
- `src/lib.rs` - Re-exports public API
- `src/keys.rs` - P-256 key generation, AES-256-GCM encrypt/decrypt
- `src/error.rs` - CryptoError enum
