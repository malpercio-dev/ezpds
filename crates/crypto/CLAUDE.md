# Crypto Crate

Last verified: 2026-03-14

## Purpose
Provides cryptographic primitives for the ezpds workspace: P-256 key generation,
did:key derivation, AES-256-GCM encryption/decryption of private key material,
Shamir Secret Sharing for DID rotation key recovery, and did:plc genesis
operation building and verification.
This is a pure functional core -- no I/O, no database, no config.

## Contracts

### Public API functions

**`generate_p256_keypair`**
```rust
pub fn generate_p256_keypair() -> Result<P256Keypair, CryptoError>
```
- Generates a fresh P-256 keypair from OS RNG
- Returns `key_id` (full `did:key:z...` URI), `public_key` (multibase base58btc, no prefix), `private_key_bytes` (zeroized)

**`encrypt_private_key`**
```rust
pub fn encrypt_private_key(&[u8; 32], &[u8; 32]) -> Result<String, CryptoError>
```
- Encrypts a 32-byte secret with a 32-byte master key using AES-256-GCM
- Fresh 12-byte nonce per call; returns `base64(nonce(12) || ciphertext(32) || tag(16))` (80 base64 chars)

**`decrypt_private_key`**
```rust
pub fn decrypt_private_key(&str, &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError>
```
- Decrypts a base64-encoded ciphertext with a master key
- Returns opaque `CryptoError::Decryption` on all failure modes (no oracle)

**`split_secret`**
```rust
pub fn split_secret(&[u8; 32]) -> Result<[ShamirShare; 3], CryptoError>
```
- Shamir secret sharing (2-of-3 scheme) with fresh OS RNG polynomial coefficients
- Information-theoretic security: a single share reveals nothing

**`combine_shares`**
```rust
pub fn combine_shares(&ShamirShare, &ShamirShare) -> Result<Zeroizing<[u8; 32]>, CryptoError>
```
- Reconstructs secret from 2 distinct shares (indices [1,3])
- Returns `CryptoError::SecretReconstruction` if indices are duplicate or out of range

**`build_did_plc_genesis_op`** (new, MM-89)
```rust
pub fn build_did_plc_genesis_op(
    rotation_key: &DidKeyUri,       // user's root rotation key (rotationKeys[0])
    signing_key: &DidKeyUri,        // relay's signing key (rotationKeys[1] + verificationMethods.atproto)
    signing_private_key: &[u8; 32], // raw P-256 private key scalar for signing_key
    handle: &str,                   // e.g. "alice.example.com"
    service_endpoint: &str,         // e.g. "https://relay.example.com"
) -> Result<PlcGenesisOp, CryptoError>
```
- Constructs a signed did:plc genesis operation
- Returns `PlcGenesisOp { did, signed_op_json }`
- `did` matches `^did:plc:[a-z2-7]{24}$`; derived from SHA-256 of CBOR-encoded signed op, base32-lowercase, first 24 chars
- `signed_op_json` is ready to POST to `https://plc.directory/{did}`
- Deterministic: same inputs → same DID (RFC 6979 ECDSA + SHA-256 + base32)
- Errors: `CryptoError::PlcOperation` if `signing_private_key` is an invalid P-256 scalar

**`verify_genesis_op`** (new, MM-90)
```rust
pub fn verify_genesis_op(
    signed_op_json: &str,           // JSON-encoded signed genesis op from client
    rotation_key: &DidKeyUri,       // P-256 did:key URI to verify signature against
) -> Result<VerifiedGenesisOp, CryptoError>
```
- Parses signed op JSON (rejects unknown fields via `serde(deny_unknown_fields)`)
- Reconstructs unsigned op with DAG-CBOR canonical field ordering, verifies ECDSA-SHA256 signature
- Derives DID from SHA-256 of signed CBOR (same algorithm as `build_did_plc_genesis_op`)
- Returns extracted op fields for semantic validation by the caller
- Errors: `CryptoError::PlcOperation` for any parse, format, or signature failure

### Public types

**`P256Keypair`**
- `key_id`: full `did:key:z...` URI
- `public_key`: multibase base58btc compressed point (no prefix)
- `private_key_bytes`: `Zeroizing<[u8; 32]>` (zeroized on drop)

**`PlcGenesisOp`** (new, MM-89)
- `did`: `"did:plc:xxxx..."` (28 chars total)
- `signed_op_json`: contains `type`, `rotationKeys`, `verificationMethods`, `alsoKnownAs`, `services`, `prev` (null), `sig`

**`VerifiedGenesisOp`** (new, MM-90)
- `did`: derived DID string
- `rotation_keys`: full `rotationKeys` array from the op
- `also_known_as`: full `alsoKnownAs` array from the op
- `verification_methods`: full `verificationMethods` map from the op
- `atproto_pds_endpoint`: endpoint from `services["atproto_pds"]`, if present

**`ShamirShare`**
- `index`: u8 in [1, 3] (not secret)
- `data`: `Zeroizing<[u8; 32]>` (zeroized on drop)

**`CryptoError`** variants:
- `KeyGeneration`, `Encryption`, `Decryption`, `SecretSharing`, `SecretReconstruction`, `PlcOperation` (new, MM-89)

### Format guarantees

- **did:key**: P-256 multicodec varint `[0x80, 0x24]` + compressed point, multibase base58btc encoded
- **Encryption**: `base64(nonce(12) || ciphertext(32) || tag(16))` = 80 base64 chars; fresh nonce per call
- **did:plc genesis op sig**: base64url (no padding) decoding to exactly 64 bytes (r‖s, big-endian, low-S canonical)

## Dependencies
- **Uses**: p256 (ECDSA/key generation), aes-gcm (AES-256-GCM), multibase (base58btc encoding), rand_core (OS RNG), base64 (storage encoding), zeroize (secret cleanup), ciborium (CBOR serialization for did:plc), data-encoding (base32-lowercase), sha2 (SHA-256), serde/serde_json (struct serialization)
- **Used by**: `crates/relay/` (key generation, did:plc genesis building and verification in POST /v1/dids)

## Invariants
- Private key bytes are always wrapped in `Zeroizing` -- callers must not copy them into non-zeroizing storage
- `encrypt_private_key` always generates a fresh nonce; two calls with identical input produce different ciphertext
- `decrypt_private_key` returns a single opaque `CryptoError::Decryption` for all failure modes (no oracle)
- `ShamirShare.data` is zeroized on drop -- callers must not copy share bytes into non-zeroizing storage
- `split_secret` polynomial coefficients are fresh OS RNG per call; information-theoretic security (a single share reveals nothing)
- `combine_shares` requires exactly 2 shares with distinct indices in [1, 3]; returns `CryptoError::SecretReconstruction` otherwise
- GF(2^8) arithmetic uses the AES irreducible polynomial (0x11b); secret bytes are always the first argument to `gf_mul` (non-branching position)

## Key Files
- `src/lib.rs` - Re-exports public API
- `src/keys.rs` - P-256 key generation, AES-256-GCM encrypt/decrypt
- `src/plc.rs` - did:plc genesis operation builder (MM-89) and verifier (MM-90)
- `src/shamir.rs` - Shamir Secret Sharing (split/combine, GF(2^8) arithmetic)
- `src/error.rs` - CryptoError enum
