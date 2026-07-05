# MM-146 DID Ceremony Implementation Plan

**Goal:** Add `build_did_plc_genesis_op_with_external_signer` to the crypto crate so callers with non-extractable keys (Secure Enclave) can sign without exposing raw private key bytes.

**Architecture:** Pure functional core addition to `crates/crypto/src/plc.rs`. The new function accepts an `FnOnce` signing callback instead of raw key bytes; the existing `build_did_plc_genesis_op` is refactored to a thin wrapper that constructs an inline callback from the private key bytes and delegates. No I/O, no new dependencies.

**Tech Stack:** Rust, p256 (ECDSA), ciborium (DAG-CBOR), base64, sha2

**Scope:** Phase 2 of 4 from the MM-146 design plan.

**Codebase verified:** 2026-03-20

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-146.AC2: build_did_plc_genesis_op_with_external_signer produces valid genesis op
- **MM-146.AC2.1 Success:** Callback receives CBOR-encoded unsigned op bytes; returned `PlcGenesisOp` passes `verify_genesis_op`
- **MM-146.AC2.2 Failure:** Callback returning `Err` propagates as `CryptoError::PlcOperation`
- **MM-146.AC2.3 Success:** Existing `build_did_plc_genesis_op` (now a wrapper) produces identical output to before (existing tests unchanged)

---

<!-- START_SUBCOMPONENT_A (tasks 1-5) -->

<!-- START_TASK_1 -->
### Task 1: Add build_did_plc_genesis_op_with_external_signer to plc.rs

**Files:**
- Modify: `crates/crypto/src/plc.rs` — insert new function before the existing `build_did_plc_genesis_op` (currently at line 161)

**Implementation:**

Insert the following block immediately after the `base32_lowercase` function (currently ending around line 159), and before the existing `build_did_plc_genesis_op` function:

```rust
/// Build and sign a did:plc genesis operation using an external signing callback.
///
/// This variant accepts a signing callback instead of raw private key bytes, enabling
/// use with non-extractable keys such as Apple Secure Enclave keys.
///
/// # Parameters
/// - `rotation_key`: The user's device key (highest-priority rotation key). Placed at `rotationKeys[0]`.
/// - `signing_key`: The relay's signing key. Placed at `rotationKeys[1]` and `verificationMethods.atproto`.
/// - `handle`: The account handle, e.g. `"alice.example.com"`. Stored as `"at://alice.example.com"` in `alsoKnownAs`.
/// - `service_endpoint`: The relay's public URL, e.g. `"https://relay.example.com"`.
/// - `sign`: A callback that receives the CBOR-encoded unsigned op bytes and must return the
///   raw 64-byte r‖s P-256 ECDSA signature bytes (big-endian, low-S canonical).
///
/// # Errors
/// Returns `CryptoError::PlcOperation` if `sign` returns `Err`, or if any serialization step fails.
pub fn build_did_plc_genesis_op_with_external_signer<F>(
    rotation_key: &DidKeyUri,
    signing_key: &DidKeyUri,
    handle: &str,
    service_endpoint: &str,
    sign: F,
) -> Result<PlcGenesisOp, CryptoError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>,
{
    // Step 1: Build the unsigned operation.
    let mut verification_methods = BTreeMap::new();
    verification_methods.insert("atproto".to_string(), signing_key.0.clone());

    let mut services = BTreeMap::new();
    services.insert(
        "atproto_pds".to_string(),
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: service_endpoint.to_string(),
        },
    );

    let unsigned_op = UnsignedPlcOp {
        prev: None,
        op_type: "plc_operation".to_string(),
        services: services.clone(),
        also_known_as: vec![format!("at://{handle}")],
        rotation_keys: vec![rotation_key.0.clone(), signing_key.0.clone()],
        verification_methods: verification_methods.clone(),
    };

    // Step 2: CBOR-encode the unsigned operation.
    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Step 3: Call external signer with the CBOR bytes.
    // The callback must return raw 64-byte r‖s P-256 ECDSA signature bytes.
    let sig_bytes = sign(&unsigned_cbor)?;

    // Step 4: base64url-encode the signature (no padding).
    let sig_str = URL_SAFE_NO_PAD.encode(&sig_bytes);

    // Step 5: Build the signed operation (same fields + sig).
    let signed_op = SignedPlcOp {
        sig: sig_str,
        prev: None,
        op_type: "plc_operation".to_string(),
        services,
        also_known_as: vec![format!("at://{handle}")],
        rotation_keys: vec![rotation_key.0.clone(), signing_key.0.clone()],
        verification_methods,
    };

    // Step 6: CBOR-encode the signed operation.
    let mut signed_cbor = Vec::new();
    into_writer(&signed_op, &mut signed_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode signed op: {e}")))?;

    // Step 7: SHA-256 hash of the signed CBOR.
    let hash = Sha256::digest(&signed_cbor);

    // Step 8: base32-lowercase, take first 24 characters.
    let encoded = base32_lowercase()?.encode(hash.as_ref());
    let did = format!("did:plc:{}", &encoded[..24]);

    // Step 9: JSON-serialize the signed operation.
    let signed_op_json = serde_json::to_string(&signed_op)
        .map_err(|e| CryptoError::PlcOperation(format!("json serialize signed op: {e}")))?;

    Ok(PlcGenesisOp {
        did,
        signed_op_json,
    })
}
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Refactor build_did_plc_genesis_op into a thin wrapper

**Files:**
- Modify: `crates/crypto/src/plc.rs` — replace the body of `build_did_plc_genesis_op` (lines 161–239) with a delegation call to the new function

**Implementation:**

Replace the existing `build_did_plc_genesis_op` implementation (everything from the opening `{` on line 167 through the closing `}` on line 239) with this thin wrapper body:

```rust
pub fn build_did_plc_genesis_op(
    rotation_key: &DidKeyUri,
    signing_key: &DidKeyUri,
    signing_private_key: &[u8; 32],
    handle: &str,
    service_endpoint: &str,
) -> Result<PlcGenesisOp, CryptoError> {
    let field_bytes: FieldBytes = (*signing_private_key).into();
    let sk = SigningKey::from_bytes(&field_bytes)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid signing key: {e}")))?;
    build_did_plc_genesis_op_with_external_signer(
        rotation_key,
        signing_key,
        handle,
        service_endpoint,
        |data| {
            let sig: Signature = Signer::sign(&sk, data);
            Ok(sig.to_bytes().to_vec())
        },
    )
}
```

The function signature (parameter names, types, doc comment) is unchanged. Only the body changes.

**Verification:**

Run: `cargo build -p crypto`
Expected: Compiles without errors or warnings.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update lib.rs to re-export the new function

**Files:**
- Modify: `crates/crypto/src/lib.rs` line 12 — add `build_did_plc_genesis_op_with_external_signer` to the plc re-export

**Implementation:**

Change line 12 from:

```rust
pub use plc::{build_did_plc_genesis_op, verify_genesis_op, PlcGenesisOp, VerifiedGenesisOp};
```

To:

```rust
pub use plc::{
    build_did_plc_genesis_op, build_did_plc_genesis_op_with_external_signer, verify_genesis_op,
    PlcGenesisOp, VerifiedGenesisOp,
};
```

**Verification:**

Run: `cargo build -p crypto`
Expected: Compiles without errors or warnings.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Add tests for the external signer function

**Verifies:** MM-146.AC2.1, MM-146.AC2.2

**Files:**
- Modify: `crates/crypto/src/plc.rs` — append two new test functions to the existing `mod tests` block (before the closing `}` of the block, which ends at the final line of the file)

**Testing:**

Tests must verify each AC listed above. Both tests go inside the existing `#[cfg(test)] mod tests { use super::*; ... }` block, alongside the existing tests. Do not create a new test module.

Append these two test functions **before the final closing `}` of the `mod tests` block** — i.e., the very last `}` in the file. The existing block ends with `}` on the last line; insert the new functions just above it:

```rust
    // MM-146.AC2.1: Callback receives CBOR bytes; returned PlcGenesisOp passes verify_genesis_op.
    #[test]
    fn external_signer_callback_produces_valid_genesis_op() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes: [u8; 32] = *signing_kp.private_key_bytes;

        // Simulate SE: the key is available for signing but bytes are not "exposed" to the caller.
        let field_bytes: FieldBytes = private_key_bytes.into();
        let sk = SigningKey::from_bytes(&field_bytes).expect("valid signing key");

        let result = build_did_plc_genesis_op_with_external_signer(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            "alice.example.com",
            "https://relay.example.com",
            |data| {
                let sig: Signature = Signer::sign(&sk, data);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("external signer should succeed");

        // The resulting op must pass verify_genesis_op with the rotation key.
        let verified = verify_genesis_op(&result.signed_op_json, &rotation_kp.key_id)
            .expect("signed op must be verifiable with rotation key");
        assert_eq!(
            verified.did, result.did,
            "verified DID must match the DID returned by the builder"
        );
    }

    // MM-146.AC2.2: Callback returning Err propagates as CryptoError::PlcOperation.
    #[test]
    fn external_signer_callback_error_propagates_as_plc_operation() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");

        let result = build_did_plc_genesis_op_with_external_signer(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            "alice.example.com",
            "https://relay.example.com",
            |_data| Err(CryptoError::PlcOperation("SE signing failed".to_string())),
        );

        assert!(result.is_err(), "must return error when callback fails");
        match result.unwrap_err() {
            CryptoError::PlcOperation(msg) => {
                assert!(
                    msg.contains("SE signing failed"),
                    "error message must propagate from callback, got: {msg}"
                );
            }
            other => panic!("expected CryptoError::PlcOperation, got: {other:?}"),
        }
    }
```

**Verification:**

Run: `cargo test -p crypto`
Expected: All existing tests still pass (MM-146.AC2.3 confirmed) + 2 new tests pass.
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Commit

**Files:** All changes to `crates/crypto/src/plc.rs` and `crates/crypto/src/lib.rs`

```bash
git add crates/crypto/src/plc.rs crates/crypto/src/lib.rs
git commit -m "feat(crypto): add build_did_plc_genesis_op_with_external_signer for SE-backed signing"
```
<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_A -->
