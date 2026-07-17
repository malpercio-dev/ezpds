# Crypto Crate

Last verified: 2026-07-17

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

**`derive_recovery_keypair`**
```rust
pub fn derive_recovery_keypair(seed: &[u8; 32]) -> Result<P256Keypair, CryptoError>
```
- Deterministically derives the recovery `P256Keypair` from a 32-byte recovery seed (the secret reconstructed from the Shamir shares). Same seed → same keypair, pinned by a golden test.
- HKDF-SHA256 with fixed salt (`ezpds/recovery-seed/v1`) + `info` domain string, rejection-sampled into the P-256 scalar range `[1, n)` (a rejected candidate re-expands with an incremented counter appended to `info`; the first candidate succeeds with overwhelming probability)
- The derived key's did:key sits in `rotationKeys` (recovery slot); it signs low-S like every other signer in the crate
- Errors: `CryptoError::KeyGeneration` only if HKDF fails or the counter space is exhausted (practically impossible)

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

**`split_secret_into_envelopes`**
```rust
pub fn split_secret_into_envelopes(&[u8; 32], set_id: u32) -> Result<[ShareEnvelope; 3], CryptoError>
```
- Same GF(2^8) split as `split_secret`, then wraps each share in a v2 [`ShareEnvelope`] tied to `set_id`
- Caller supplies `set_id` (typically fresh random per split) so a generation's three shares can be told apart from a later re-split's

**`combine_envelopes`**
```rust
pub fn combine_envelopes(&ShareEnvelope, &ShareEnvelope) -> Result<Zeroizing<[u8; 32]>, CryptoError>
```
- Reconstructs the secret from two envelopes; indices come from the envelopes, not caller bookkeeping
- **Refuses mismatched `set_id` loudly** with `CryptoError::SecretReconstruction` — cross-generation shares must never reconstruct a silently-wrong seed. Distinct indices in [1,3] still required (via `combine_shares`).

**`ShareEnvelope` (de)serialization** — the self-describing share transport (v2)
```rust
impl ShareEnvelope {
    pub fn to_bytes(&self) -> Zeroizing<[u8; SHARE_ENVELOPE_LEN]>;        // 42 bytes
    pub fn from_bytes(&[u8]) -> Result<ShareEnvelope, CryptoError>;
    pub fn encode_share(&self) -> String;                                // uppercase base32 (QR-friendly)
    pub fn decode_share(&str) -> Result<ShareEnvelope, CryptoError>;
    pub fn encode_share_words(&self) -> String;                          // BIP-39-style mnemonic
    pub fn decode_share_words(&str) -> Result<ShareEnvelope, CryptoError>;
}
```
- Wire layout: `version(1B) || set_id(4B, big-endian) || index(1B) || payload(32B) || checksum(4B = SHA-256(preceding 38B)[..4])` = `SHARE_ENVELOPE_LEN` (42) bytes.
- `encode_share`/`decode_share` use unpadded **uppercase** base32 (RFC 4648) — only QR alphanumeric-mode characters. Decode ignores whitespace and accepts lowercase. Shares 1/2 use this machine format.
- `encode_share_words`/`decode_share_words` render the whole 42-byte envelope as a mnemonic (one word per byte, fixed 256-word list) for the human-custody Share 3; the phrase stays self-describing (carries version/set_id/index/checksum).
- `from_bytes` rejects with **distinct** errors: `ShareVersion` (unsupported version, checked before checksum), `ShareChecksum` (body/checksum mismatch), `ShareFormat` (wrong length, index ∉ [1,3], bad base32/word). A corrupted share therefore fails at decode, before `combine_envelopes`.
- `Debug` for `ShareEnvelope` redacts the payload.

**`build_did_plc_genesis_op`**
```rust
pub fn build_did_plc_genesis_op(
    rotation_key: &DidKeyUri,       // user's root rotation key (rotationKeys[0])
    signing_key: &DidKeyUri,        // PDS's signing key (rotationKeys[1] + verificationMethods.atproto)
    signing_private_key: &[u8; 32], // raw P-256 private key scalar for signing_key
    handle: &str,                   // e.g. "alice.example.com"
    service_endpoint: &str,         // e.g. "https://PDS.example.com"
) -> Result<PlcGenesisOp, CryptoError>
```
- Constructs a signed did:plc genesis operation
- Returns `PlcGenesisOp { did, signed_op_json }`
- `did` matches `^did:plc:[a-z2-7]{24}$`; derived from SHA-256 of CBOR-encoded signed op, base32-lowercase, first 24 chars
- `signed_op_json` is ready to POST to `https://plc.directory/{did}`
- Deterministic: same inputs → same DID (RFC 6979 ECDSA + SHA-256 + base32)
- Errors: `CryptoError::PlcOperation` if `signing_private_key` is an invalid P-256 scalar
- Delegates internally to `build_did_plc_genesis_op_with_external_signer` with a closure wrapping `SigningKey::sign`

**`build_did_plc_genesis_op_with_external_signer`**
```rust
pub fn build_did_plc_genesis_op_with_external_signer<F>(
    rotation_key: &DidKeyUri,       // user's device key (rotationKeys[0])
    signing_key: &DidKeyUri,        // PDS's signing key (rotationKeys[1] + verificationMethods.atproto)
    handle: &str,                   // e.g. "alice.example.com"
    service_endpoint: &str,         // e.g. "https://PDS.example.com"
    sign: F,                        // callback: &[u8] -> Result<Vec<u8>, CryptoError>
) -> Result<PlcGenesisOp, CryptoError>
where F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>
```
- Same as `build_did_plc_genesis_op` but accepts a signing callback instead of raw private key bytes
- Enables signing with non-extractable keys (e.g. Apple Secure Enclave)
- Callback receives CBOR-encoded unsigned op bytes; must return raw 64-byte r||s P-256 ECDSA signature (big-endian, low-S canonical)
- Errors: propagates any `CryptoError` returned by the callback, or `CryptoError::PlcOperation` for serialization failures

**`build_did_plc_genesis_op_multi_rotation_with_external_signer`** / **`build_did_plc_genesis_op_multi_rotation`**
```rust
pub fn build_did_plc_genesis_op_multi_rotation_with_external_signer<F>(
    rotation_keys: &[DidKeyUri],    // ordered, highest-priority first, e.g. [device, recovery, PDS]
    signing_key: &DidKeyUri,        // PDS key → verificationMethods.atproto (need not be in rotation_keys)
    handle: &str,
    service_endpoint: &str,
    sign: F,                        // callback: &[u8] -> Result<Vec<u8>, CryptoError>
) -> Result<PlcGenesisOp, CryptoError>
where F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>

pub fn build_did_plc_genesis_op_multi_rotation(
    rotation_keys: &[DidKeyUri],
    signing_key: &DidKeyUri,
    signing_private_key: &[u8; 32],  // private key for signing_key; op signed with it, low-S normalized
    handle: &str,
    service_endpoint: &str,
) -> Result<PlcGenesisOp, CryptoError>
```
- Like the two-key builders but takes the **full ordered `rotationKeys` list** instead of hardcoding `[device, PDS]`. For key recovery the list is `[device, recovery, PDS]` — recovery in a middle slot so the device key stays highest-priority. `verificationMethods.atproto` is always the PDS `signing_key`, regardless of the rotation-key list.
- The two-key `build_did_plc_genesis_op[_with_external_signer]` now delegate to the same internal core, so their output is byte-identical to before (guarded by the golden DID test).
- Server-side note: `verify_and_validate_genesis_op` only pins `rotationKeys[0]`, so a 3-key op already passes validation — this is a builder-side capability.
- Errors: `CryptoError::PlcOperation` if `rotation_keys` is empty, the callback errors, `signing_private_key` is an invalid P-256 scalar, or serialization fails.

**`compute_cid`**
```rust
pub fn compute_cid(signed_op_cbor: &[u8]) -> Result<String, CryptoError>
```
- Computes a CIDv1 (dag-cbor, sha-256) from signed operation CBOR bytes: `version(1) || codec(0x71) || hash(0x12) || length(0x20) || sha256(bytes)`
- Returns a multibase base32lower-encoded CID string (`b` prefix), the format used in did:plc `prev` fields
- Used as the `prev` value chaining a rotation op onto the operation before it

**`encode_sovereign_session_envelope`**
```rust
pub fn encode_sovereign_session_envelope(
    server_did: &str,
    account_did: &str,
    signing_key_did: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<u8>
```
- Produces the shared server/wallet version-1 bytes for `POST /v1/sessions/sovereign`
- Binds the protocol domain/version, destination server DID, method/path, account DID, signing-key DID, Unix timestamp, and nonce in a fixed field order
- UTF-8 byte-length-prefixes every value so separators inside a future identifier syntax cannot make two field tuples encode identically
- `SOVEREIGN_SESSION_DOMAIN`, `SOVEREIGN_SESSION_METHOD`, and `SOVEREIGN_SESSION_PATH` expose the pinned protocol constants

**`build_did_plc_rotation_op`**
```rust
pub fn build_did_plc_rotation_op<F>(
    prev_cid: &str,                                    // CID of the previous op in the chain (from `compute_cid`)
    rotation_keys: Vec<String>,                         // new rotationKeys array
    verification_methods: BTreeMap<String, String>,     // method name → did:key: URI
    also_known_as: Vec<String>,                         // new alsoKnownAs array
    services: BTreeMap<String, PlcService>,             // new services map (service name → PlcService)
    sign: F,                                            // callback: &[u8] -> Result<Vec<u8>, CryptoError>
) -> Result<SignedPlcOperation, CryptoError>
where F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>
```
- Builds and signs a did:plc **rotation** operation (non-null `prev`, arbitrary rotation keys/verification methods/alsoKnownAs/services supplied by the caller — unlike genesis, this function does not decide the new state)
- Same external-signer-callback shape as `build_did_plc_genesis_op_with_external_signer` (raw 64-byte r‖s P-256 ECDSA signature, big-endian, low-S canonical)
- Returns `SignedPlcOperation { cid, signed_op_json }` — `cid` (via `compute_cid`) is ready to use as the next op's `prev`; `signed_op_json` is ready to POST to plc.directory
- Errors: propagates any `CryptoError` from the callback, or `CryptoError::PlcOperation` for serialization failures

**`build_did_plc_tombstone_op`**

```rust
pub fn build_did_plc_tombstone_op<F>(
    prev_cid: &str,                 // CID of the DID's current head op (newest non-nullified)
    sign: F,                        // callback: &[u8] -> Result<Vec<u8>, CryptoError>
) -> Result<SignedPlcOperation, CryptoError>
where F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>
```

- Builds and signs a did:plc **tombstone** op — exactly `{ "type": "plc_tombstone", "prev": <cid>, "sig": <b64url> }`, no rotationKeys/verificationMethods/alsoKnownAs/services (a different, smaller field set than genesis/rotation ops). Permanently retires the DID once plc.directory accepts it.
- Same external-signer-callback shape as the other builders (raw 64-byte r‖s P-256 ECDSA, low-S canonical; the sig covers the **unsigned** CBOR = `prev` + `type` only). Signed with any key in the head op's `rotationKeys` (the wallet uses its device key at `rotationKeys[0]`).
- Returns `SignedPlcOperation { cid, signed_op_json }`; `signed_op_json` is ready to POST to plc.directory.
- Errors: propagates any `CryptoError` from the callback, or `CryptoError::PlcOperation` for a non-64-byte/high-S signature or a serialization failure

**`verify_plc_tombstone_op`**

```rust
pub fn verify_plc_tombstone_op(
    signed_op_json: &str,                       // JSON-encoded signed tombstone op
    authorized_rotation_keys: &[DidKeyUri],     // the PREVIOUS (head) op's rotationKeys
) -> Result<VerifiedTombstoneOp, CryptoError>
```

- Dedicated tombstone verifier (a tombstone's `type != "plc_operation"` and its field set differ, so it is verified separately from `verify_plc_operation`/`verify_genesis_op`, which both reject any non-`plc_operation` type). Parses (rejecting unknown fields), requires `type == "plc_tombstone"`, reconstructs the unsigned CBOR, and tries each authorized key (dual-curve, low-S enforced) until one verifies
- Caller obligation: `authorized_rotation_keys` are the previous op's `rotationKeys` (same contract as `verify_plc_operation` for a rotation op)
- Returns `VerifiedTombstoneOp { cid, prev }`
- Errors: `CryptoError::PlcOperation` for a malformed/wrong-type op or if no authorized key verifies the signature

**`verify_genesis_op`**
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

**`verify_plc_operation`**
```rust
pub fn verify_plc_operation(
    signed_op_json: &str,                       // JSON-encoded signed PLC operation (genesis or rotation)
    authorized_rotation_keys: &[DidKeyUri],     // candidate signer keys, tried in order
) -> Result<VerifiedPlcOp, CryptoError>
```
- General-purpose signed-op verifier covering **both** genesis and rotation ops (unlike `verify_genesis_op`, which only accepts genesis ops against a single key)
- **Accepts both curves for verification**: P-256 (`zDn…`, multicodec `[0x80, 0x24]`) and secp256k1 (`zQ3…`, multicodec `[0xe7, 0x01]`) — dispatched per key by multicodec prefix. The reference ecosystem (bsky.social) signs PLC ops with secp256k1; a golden test pins verification of a real bsky.social-signed operation. Signing in this crate remains P-256-only. Unknown prefixes get an explicit "unsupported did:key type" error.
- Reconstructs the unsigned op with DAG-CBOR canonical field ordering and tries each key in `authorized_rotation_keys` until one verifies the ECDSA-SHA256 signature
- Caller obligation: supplies the correct authorized-key set for this op — the op's own `rotationKeys` for a genesis op, or the **previous** op's `rotationKeys` for a rotation op; this function only checks that *some* provided key signed it, not that the set is right for the DID's current state
- Returns `VerifiedPlcOp { did, cid, prev, rotation_keys, also_known_as, verification_methods, services }` — `did` is `Some` (derived from signed CBOR) only for a genesis op (`prev.is_none()`), `None` for a rotation op; `cid` is this op's own CID (via `compute_cid`)
- Errors: `CryptoError::PlcOperation` if no authorized key verifies the signature, or for any parse/format failure

**`verify_p256_signature`**

```rust
pub fn verify_p256_signature(
    public_key: &DidKeyUri,         // signer's P-256 did:key URI
    message: &[u8],                 // exact bytes that were signed (not pre-hashed)
    signature: &[u8; 64],           // raw r||s ECDSA signature, big-endian
) -> Result<(), CryptoError>
```

- General-purpose P-256 ECDSA-SHA256 verification, decoupled from did:plc operation JSON; the relay uses it to authenticate signed admin requests
- **Deliberately P-256-only** even though PLC operation verification accepts secp256k1 too: the admin-device model is P-256 (Secure Enclave) by design, so a `zQ3…` key is rejected with "not a P-256 key" rather than quietly verified
- Message is hashed with SHA-256 internally — pass the bytes exactly as signed, do not pre-hash
- Errors: `CryptoError::SignatureVerification` for a malformed public key, an unparseable signature, or a verification mismatch

**`parse_audit_log`**
```rust
pub fn parse_audit_log(json: &str) -> Result<Vec<AuditEntry>, CryptoError>
```
- Parses a plc.directory audit log response (`GET https://plc.directory/{did}/log/audit`) into a list of `AuditEntry`
- Purely structural — does not verify the operations it returns; pass each `AuditEntry.operation` to `verify_plc_operation` to validate cryptographically
- Errors: `CryptoError::PlcOperation` if the JSON cannot be parsed

**`diff_audit_logs`**
```rust
pub fn diff_audit_logs(cached: &[AuditEntry], current: &[AuditEntry]) -> Vec<AuditEntry>
```
- Finds entries in `current` not present in `cached`, compared by CID
- Returns the new entries in the order they appear in `current`
- Used to detect PLC operations a caller's cache hasn't seen yet (e.g. a refreshed audit log fetch)

### Public types

**`P256Keypair`**
- `key_id`: full `did:key:z...` URI
- `public_key`: multibase base58btc compressed point (no prefix)
- `private_key_bytes`: `Zeroizing<[u8; 32]>` (zeroized on drop)

**`PlcGenesisOp`**
- `did`: `"did:plc:xxxx..."` (28 chars total)
- `signed_op_json`: contains `type`, `rotationKeys`, `verificationMethods`, `alsoKnownAs`, `services`, `prev` (null), `sig`

**`PlcService`**
- A single entry in a PLC operation's `services` map (e.g. the `atproto_pds` entry)
- `service_type`: e.g. `"AtprotoPersonalDataServer"` (serialized as `type`)
- `endpoint`: the service's URL, e.g. `"https://pds.example.com"`

**`VerifiedGenesisOp`**
- `did`: derived DID string
- `rotation_keys`: full `rotationKeys` array from the op
- `also_known_as`: full `alsoKnownAs` array from the op
- `verification_methods`: full `verificationMethods` map from the op
- `atproto_pds_endpoint`: endpoint from `services["atproto_pds"]`, if present

**`VerifiedPlcOp`**
- Returned by `verify_plc_operation`; covers both genesis and rotation ops
- `did`: `Some(derived DID)` for a genesis op (`prev.is_none()`), `None` for a rotation op (caller supplies the DID from context)
- `cid`: this op's own CID
- `prev`: `None` for genesis, `Some(cid)` for rotation
- `rotation_keys` / `also_known_as` / `verification_methods` / `services`: full corresponding fields from the op

**`VerifiedTombstoneOp`**
- Returned by `verify_plc_tombstone_op`
- `cid`: this tombstone op's own CID
- `prev`: the head CID this tombstone chains onto

**`AuditEntry`**
- A single entry from a plc.directory audit log, as returned by `parse_audit_log`
- `did`: the DID this operation belongs to
- `cid`: this operation's CID
- `created_at`: ISO 8601 timestamp when plc.directory received the operation (serialized as `createdAt`)
- `nullified`: whether plc.directory considers this operation invalidated
- `operation`: the raw signed PLC operation as a JSON `Value` — pass to `verify_plc_operation` to validate cryptographically

**`ShamirShare`**
- `index`: u8 in [1, 3] (not secret)
- `data`: `Zeroizing<[u8; 32]>` (zeroized on drop)

**`ShareEnvelope`**
- Self-describing v2 share transport (see the (de)serialization contract above)
- `version`: u8 (`SHARE_ENVELOPE_VERSION` = 2), `set_id`: u32, `index`: u8 in [1,3], `payload`: `Zeroizing<[u8; 32]>` (zeroized on drop)
- `Debug` redacts `payload`

**`CryptoError`** variants:
- `KeyGeneration`, `Encryption`, `Decryption`, `SecretSharing`, `SecretReconstruction`, `ShareVersion`, `ShareChecksum`, `ShareFormat`, `PlcOperation`, `SignatureVerification`
- The three `Share*` variants are the **distinct** share-envelope decode failures: `ShareVersion` (unsupported version), `ShareChecksum` (integrity check failed), `ShareFormat` (structural/encoding error)

### Format guarantees

- **did:key**: P-256 multicodec varint `[0x80, 0x24]` + compressed point, multibase base58btc encoded
- **Encryption**: `base64(nonce(12) || ciphertext(32) || tag(16))` = 80 base64 chars; fresh nonce per call
- **did:plc genesis op sig**: base64url (no padding) decoding to exactly 64 bytes (r‖s, big-endian, low-S canonical). `build_did_plc_genesis_op` low-S normalizes its own signature; external-signer callbacks must return low-S themselves.
- **Low-S enforced on verify (both curves)**: every verification path (`verify_genesis_op`, `verify_plc_operation`, `verify_p256_signature`) rejects non-canonical high-S signatures on P-256 and secp256k1 alike, matching `@atproto/crypto`/plc.directory strict verification. Because DIDs/CIDs are derived from the *signed* CBOR, accepting a malleated high-S twin would let one signature yield a second valid op with a different DID/CID.
- **secp256k1 is verify-only**: `SECP256K1_MULTICODEC_PREFIX` (`[0xe7, 0x01]`, `zQ3…`) exists for verifying ops signed by the reference ecosystem; nothing in this crate generates or signs with secp256k1 keys.

## Dependencies
- **Uses**: p256 (ECDSA/key generation), k256 (secp256k1 ECDSA — verification only, for ops signed by the reference ecosystem), aes-gcm (AES-256-GCM), multibase (base58btc encoding), rand_core (OS RNG), base64 (storage encoding), zeroize (secret cleanup), ciborium (CBOR serialization for did:plc), data-encoding (base32-lowercase for DIDs; base32 uppercase for share envelopes), sha2 (SHA-256), hkdf (HKDF-SHA256 for recovery-key derivation), serde/serde_json (struct serialization)
- **Used by**: `crates/pds/` (key generation, did:plc genesis building and verification in POST /v1/dids; sovereign-session canonical proof encoding and dual-curve verification; `crates/pds/src/plc_ops.rs` shares the interop PLC-signing surface's audit-log fetch + service parsing; `routes/sign_plc_operation.rs`/`routes/submit_plc_operation.rs` build/verify rotation ops via `build_did_plc_rotation_op`/`verify_plc_operation`), `apps/identity-wallet/` (external signer genesis op building in DID ceremony; shared sovereign-session encoder for the wallet client)

## Invariants
- Private key bytes are always wrapped in `Zeroizing` -- callers must not copy them into non-zeroizing storage
- `encrypt_private_key` always generates a fresh nonce; two calls with identical input produce different ciphertext
- `decrypt_private_key` returns a single opaque `CryptoError::Decryption` for all failure modes (no oracle)
- `ShamirShare.data` is zeroized on drop -- callers must not copy share bytes into non-zeroizing storage
- `split_secret` polynomial coefficients are fresh OS RNG per call; information-theoretic security (a single share reveals nothing)
- `combine_shares` requires exactly 2 shares with distinct indices in [1, 3]; returns `CryptoError::SecretReconstruction` otherwise
- **Share envelope v2 is self-describing and checksummed.** A `ShareEnvelope` carries its own version, `set_id`, index, and a 4-byte SHA-256 checksum, so a corrupted share fails at `from_bytes`/`decode_share*` (distinct `ShareVersion`/`ShareChecksum`/`ShareFormat` errors) before it can reach `combine_envelopes`, and `combine_envelopes` refuses shares whose `set_id` differs (cross-generation shares never reconstruct a silently-wrong seed). The GF(2^8) split/combine core is shared with `split_secret`/`combine_shares` and unchanged. The Share-3 mnemonic and the base32 form encode the identical 42 bytes; the mnemonic uses a fixed 256-word list (one word per byte) whose length/uniqueness are test-pinned — never reorder or replace an entry, as that invalidates every previously written human share.
- **`derive_recovery_keypair` is deterministic and pinned.** The HKDF salt (`ezpds/recovery-seed/v1`) + `info` domain string + rejection-sampling counter scheme is fixed by a golden test; changing any of it produces a different recovery key and orphans accounts whose `rotationKeys` already carry the old one. The `ShareEnvelope` `set_id` and this derivation are independent.
- GF(2^8) arithmetic uses the AES irreducible polynomial (0x11b); secret bytes are always the first argument to `gf_mul` (non-branching position)
- **did:plc tombstone op is `{type, prev, sig}` only, in canonical DAG-CBOR key order.** The tombstone structs carry no maps (unlike genesis/rotation ops), so they need no `CanonicalMap`; canonical ordering comes from serde field declaration order — unsigned is `prev`(4) before `type`(4) (`prev` < `type` bytewise), signed leads with `sig`(3). `prev` is a required non-null CID string (typed `String`, never CBOR null). Pinned by `tombstone_cbor_key_order_is_canonical`; `build_tombstone_round_trips` proves builder↔verifier byte-identity via the CID.
- **did:plc op CBOR is canonical DAG-CBOR for any number of map entries.** The op structs wrap `services` / `verificationMethods` in an internal `CanonicalMap` that serializes keys length-first (DAG-CBOR order) instead of `BTreeMap`/`ciborium`'s bytewise order — bytewise would emit a non-canonical op for keys of differing length (e.g. `atproto_pds` + `atproto_labeler`) that plc.directory rejects. Cross-checked against `@ipld/dag-cbor` by the `golden_*` tests (genesis op bytes + derived DID, proving byte-identity transitively via the hash) and `rotation_op_with_multiple_services_encodes_canonically` (multi-service CID). Public APIs still take/return plain `BTreeMap<String, _>`; the canonical ordering is internal to the op encoder.

## Key Files
- `src/lib.rs` - Re-exports public API
- `src/keys.rs` - P-256 key generation, AES-256-GCM encrypt/decrypt
- `src/plc.rs` - did:plc genesis operation builder and verifier
- `src/sovereign_session.rs` - canonical sovereign-session signed-envelope encoder and protocol constants
- `src/shamir.rs` - Shamir Secret Sharing (split/combine, GF(2^8) arithmetic) + share envelope v2 (`ShareEnvelope`, base32/mnemonic encode-decode, `split_secret_into_envelopes`/`combine_envelopes`)
- `src/mnemonic.rs` - BIP-39-style 256-word list + byte↔word encoding for the human-custody Share 3 (module-private; used by `shamir.rs`)
- `src/error.rs` - CryptoError enum
