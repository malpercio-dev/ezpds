# MM-90 Implementation Plan — Phase 1: crypto crate verify_genesis_op

**Goal:** Add `verify_genesis_op` as a pure function to the crypto crate; no I/O.

**Architecture:** Functional Core only. Extends `crates/crypto/src/plc.rs` with a verification counterpart to `build_did_plc_genesis_op`. No relay changes in this phase.

**Tech Stack:** Rust stable; p256 0.13 (ecdsa feature), ciborium 0.2, multibase (already in crate), base64 0.21, sha2 0.10, data-encoding 2, serde/serde_json 1.

**Scope:** Phase 1 of 2 (crypto crate only)

**Codebase verified:** 2026-03-13

---

## Acceptance Criteria Coverage

### MM-90.AC1: `verify_genesis_op` in the crypto crate
- **MM-90.AC1.1 Success:** Valid signed genesis op JSON with matching rotation key returns `VerifiedGenesisOp` with correct `did`, `also_known_as`, `verification_methods`, and `atproto_pds_endpoint`
- **MM-90.AC1.2 Success:** DID returned by `verify_genesis_op` matches the DID returned by `build_did_plc_genesis_op` with the same inputs (round-trip consistency confirms both functions use identical CBOR encoding)
- **MM-90.AC1.3 Failure:** Signed op verified against a different rotation key returns `CryptoError::PlcOperation`
- **MM-90.AC1.4 Failure:** Op with a corrupted signature (one byte changed in the base64url string) returns `CryptoError::PlcOperation`
- **MM-90.AC1.5 Failure:** Op JSON containing unknown/extra fields is rejected with `CryptoError::PlcOperation`

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add `Deserialize`, `VerifiedGenesisOp`, and `verify_genesis_op` to `plc.rs`; update `lib.rs`

**Verifies:** MM-90.AC1.1, MM-90.AC1.2, MM-90.AC1.3, MM-90.AC1.4, MM-90.AC1.5

**Files:**
- Modify: `crates/crypto/src/plc.rs`
- Modify: `crates/crypto/src/lib.rs`

**Implementation:**

**1. Update imports in `plc.rs` — add `Verifier`, `VerifyingKey`, `Deserialize`, and `multibase`:**

```rust
// Replace:
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    FieldBytes,
};
use serde::Serialize;

// With:
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    FieldBytes,
};
use serde::{Deserialize, Serialize};
```

Also add `multibase` after the existing use statements (before `use crate::{...}`):
```rust
use multibase;
```

**2. Add a module-level constant for the P-256 multicodec prefix (after the `use` block, before `// ── Internal serialization types`):**

```rust
/// P-256 multicodec varint prefix for did:key URIs.
/// 0x1200 encoded as LEB128 varint = [0x80, 0x24].
///
/// This constant is redefined here rather than promoted to `pub(crate)` in
/// `keys.rs` to avoid cross-module coupling between two sibling functional
/// modules. Each module owns its own copy; if the value ever needs to change,
/// both sites are easy to find via the shared literal `[0x80, 0x24]`.
const P256_MULTICODEC_PREFIX: &[u8] = &[0x80, 0x24];
```

**3. Add `Deserialize` to `PlcService` and `SignedPlcOp`; add `deny_unknown_fields` to `SignedPlcOp` (AC1.5):**

`PlcService` — add `Deserialize`:
```rust
#[derive(Serialize, Deserialize, Clone)]
struct PlcService {
    #[serde(rename = "type")]
    service_type: String,
    endpoint: String,
}
```

`UnsignedPlcOp` — no change to derives (never deserialized from JSON, reconstructed from `SignedPlcOp` fields).

`SignedPlcOp` — add `Deserialize` and `deny_unknown_fields`:
```rust
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPlcOp {
    sig: String,
    prev: Option<String>,
    #[serde(rename = "type")]
    op_type: String,
    services: BTreeMap<String, PlcService>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
    #[serde(rename = "rotationKeys")]
    rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods")]
    verification_methods: BTreeMap<String, String>,
}
```

**4. Add `VerifiedGenesisOp` struct in the `// ── Public API` section, before `build_did_plc_genesis_op`:**

```rust
/// The result of verifying a client-submitted did:plc genesis operation.
///
/// Returned by [`verify_genesis_op`]. Fields are extracted directly from the
/// verified signed op; the relay uses them for semantic validation and DID
/// document construction.
pub struct VerifiedGenesisOp {
    /// The derived DID, e.g. `"did:plc:abcdefghijklmnopqrstuvwx"`.
    pub did: String,
    /// Full `rotationKeys` array from the op.
    pub rotation_keys: Vec<String>,
    /// Full `alsoKnownAs` array from the op.
    pub also_known_as: Vec<String>,
    /// Full `verificationMethods` map from the op.
    pub verification_methods: BTreeMap<String, String>,
    /// Endpoint from `services["atproto_pds"]`, if present.
    pub atproto_pds_endpoint: Option<String>,
}
```

**5. Add `verify_genesis_op` function after `build_did_plc_genesis_op` in the `// ── Public API` section:**

```rust
/// Verify a client-submitted did:plc signed genesis operation.
///
/// Parses `signed_op_json` into a [`SignedPlcOp`] (rejecting unknown fields),
/// reconstructs the unsigned operation with the same DAG-CBOR field ordering
/// as [`build_did_plc_genesis_op`], verifies the ECDSA-SHA256 signature against
/// `rotation_key`, derives the DID (SHA-256 of signed CBOR → base32-lowercase
/// first 24 chars), and returns the extracted operation fields.
///
/// # Errors
/// Returns `CryptoError::PlcOperation` for any parse, format, or cryptographic failure.
pub fn verify_genesis_op(
    signed_op_json: &str,
    rotation_key: &DidKeyUri,
) -> Result<VerifiedGenesisOp, CryptoError> {
    // Step 1: Parse the signed op, rejecting unknown fields (AC1.5).
    let signed_op: SignedPlcOp = serde_json::from_str(signed_op_json)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid signed op JSON: {e}")))?;

    // Step 2: Base64url-decode the signature field.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&signed_op.sig)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid sig base64url: {e}")))?;

    // Step 3: Parse the 64-byte r‖s fixed-size ECDSA signature.
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| CryptoError::PlcOperation(format!("invalid ECDSA signature bytes: {e}")))?;

    // Step 4: Reconstruct the unsigned operation from signed op fields.
    // Field order must match UnsignedPlcOp's DAG-CBOR canonical ordering.
    let unsigned_op = UnsignedPlcOp {
        prev: signed_op.prev.clone(),
        op_type: signed_op.op_type.clone(),
        services: signed_op.services.clone(),
        also_known_as: signed_op.also_known_as.clone(),
        rotation_keys: signed_op.rotation_keys.clone(),
        verification_methods: signed_op.verification_methods.clone(),
    };

    // Step 5: CBOR-encode the unsigned op — byte-exact match to what was signed.
    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Step 6: Parse rotation key URI → P-256 VerifyingKey.
    let key_str = rotation_key
        .0
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            CryptoError::PlcOperation("rotation key missing did:key: prefix".to_string())
        })?;
    let (_, multikey_bytes) = multibase::decode(key_str)
        .map_err(|e| CryptoError::PlcOperation(format!("decode rotation key multibase: {e}")))?;
    if multikey_bytes.get(..2) != Some(P256_MULTICODEC_PREFIX) {
        return Err(CryptoError::PlcOperation(
            "rotation key is not a P-256 key (wrong multicodec prefix)".to_string(),
        ));
    }
    let verifying_key = VerifyingKey::from_sec1_bytes(&multikey_bytes[2..])
        .map_err(|e| CryptoError::PlcOperation(format!("invalid P-256 public key: {e}")))?;

    // Step 7: Verify the ECDSA-SHA256 signature (SHA-256 applied internally by p256).
    verifying_key
        .verify(&unsigned_cbor, &signature)
        .map_err(|e| CryptoError::PlcOperation(format!("signature verification failed: {e}")))?;

    // Step 8: CBOR-encode the signed op and derive the DID.
    let mut signed_cbor = Vec::new();
    into_writer(&signed_op, &mut signed_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode signed op: {e}")))?;

    let hash = Sha256::digest(&signed_cbor);
    let base32_encoding = {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
        spec.encoding()
            .map_err(|e| CryptoError::PlcOperation(format!("build base32 encoding: {e}")))?
    };
    let encoded = base32_encoding.encode(hash.as_ref());
    let did = format!("did:plc:{}", &encoded[..24]);

    // Step 9: Extract atproto_pds endpoint from services map.
    let atproto_pds_endpoint = signed_op
        .services
        .get("atproto_pds")
        .map(|s| s.endpoint.clone());

    Ok(VerifiedGenesisOp {
        did,
        rotation_keys: signed_op.rotation_keys,
        also_known_as: signed_op.also_known_as,
        verification_methods: signed_op.verification_methods,
        atproto_pds_endpoint,
    })
}
```

**6. Update `crates/crypto/src/lib.rs` — add re-exports for `verify_genesis_op` and `VerifiedGenesisOp`:**

```rust
// Replace:
pub use plc::{build_did_plc_genesis_op, PlcGenesisOp};

// With:
pub use plc::{build_did_plc_genesis_op, verify_genesis_op, PlcGenesisOp, VerifiedGenesisOp};
```

**Verification:**

Run: `cargo build -p crypto`
Expected: Compiles with zero errors

Run: `cargo clippy -p crypto -- -D warnings`
Expected: Zero warnings

**Commit:** `feat(crypto): add verify_genesis_op and VerifiedGenesisOp (MM-90 Phase 1, step 1)`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Write tests for MM-90.AC1.1–AC1.5

**Verifies:** MM-90.AC1.1, MM-90.AC1.2, MM-90.AC1.3, MM-90.AC1.4, MM-90.AC1.5

**Files:**
- Modify: `crates/crypto/src/plc.rs` — append to existing `#[cfg(test)]` `mod tests` block

**Testing:**

Add a helper function inside `mod tests` that produces a verifiable signed op. Note: `build_did_plc_genesis_op` signs with the `signing_key` private key — so `verify_genesis_op` must be called with `signing_kp.key_id` (not `rotation_kp.key_id`) to succeed:

```rust
/// Returns (signing_key_uri, PlcGenesisOp) for MM-90 verification tests.
/// build_did_plc_genesis_op signs with signing_key_bytes; verify_genesis_op
/// must receive signing_kp.key_id as its rotation_key argument.
fn make_op_for_verify() -> (DidKeyUri, PlcGenesisOp) {
    let rotation_kp = generate_p256_keypair().expect("rotation keypair");
    let signing_kp = generate_p256_keypair().expect("signing keypair");
    let private_key_bytes = *signing_kp.private_key_bytes;
    let op = build_did_plc_genesis_op(
        &rotation_kp.key_id,
        &signing_kp.key_id,
        &private_key_bytes,
        "alice.example.com",
        "https://relay.example.com",
    )
    .expect("genesis op");
    (signing_kp.key_id, op)
}
```

Tests to add (each in its own `#[test]` function):

- **`verify_valid_op_returns_correct_fields`** (MM-90.AC1.1):
  Call `make_op_for_verify()`, then `verify_genesis_op(&op.signed_op_json, &signing_key)`.
  Assert `Result::is_ok()`. On the returned `VerifiedGenesisOp`, assert:
  - `verified.did.starts_with("did:plc:")` and `verified.did.len() == 28`
  - `verified.also_known_as` contains `"at://alice.example.com"`
  - `verified.verification_methods.contains_key("atproto")`
  - `verified.atproto_pds_endpoint == Some("https://relay.example.com".to_string())`

- **`verify_did_matches_build_did_plc_genesis_op`** (MM-90.AC1.2):
  Call `build_did_plc_genesis_op` with fixed test keypairs and inputs, then call
  `verify_genesis_op` with the resulting `signed_op_json` and `signing_kp.key_id`.
  Assert `verified_op.did == genesis_op.did`.

- **`verify_wrong_rotation_key_returns_error`** (MM-90.AC1.3):
  Call `make_op_for_verify()`. Generate a fresh third keypair (`wrong_kp`).
  Call `verify_genesis_op(&op.signed_op_json, &wrong_kp.key_id)`.
  Assert `matches!(result, Err(CryptoError::PlcOperation(_)))`.

- **`verify_corrupted_signature_returns_error`** (MM-90.AC1.4):
  Call `make_op_for_verify()`. Parse `op.signed_op_json` as `serde_json::Value`.
  Get the `sig` string, base64url-decode it, flip one byte (e.g. `sig_bytes[0] ^= 0xff`),
  re-encode with `URL_SAFE_NO_PAD`, set `v["sig"] = ...`, re-serialize.
  Call `verify_genesis_op` with the corrupted JSON and the signing key.
  Assert `matches!(result, Err(CryptoError::PlcOperation(_)))`.

- **`verify_unknown_fields_returns_error`** (MM-90.AC1.5):
  Call `make_op_for_verify()`. Parse `op.signed_op_json` as `serde_json::Value`.
  Add `v["unknownField"] = serde_json::json!("surprise")`, re-serialize.
  Call `verify_genesis_op` with the modified JSON and signing key.
  Assert `matches!(result, Err(CryptoError::PlcOperation(_)))`.

**Verification:**

Run: `cargo test -p crypto`
Expected: All tests pass, including 5 new `MM-90.AC1.*` tests

Run: `cargo clippy --workspace -- -D warnings`
Expected: Zero warnings

**Commit:** `test(crypto): add MM-90.AC1.1–AC1.5 tests for verify_genesis_op`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->
