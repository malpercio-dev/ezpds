# MM-89: DID Creation — did:plc via PLC Directory Proxy — Implementation Plan

**Goal:** Implement `build_did_plc_genesis_op` as a pure function in the `crypto` crate that produces a signed did:plc genesis operation and derives the resulting DID.

**Architecture:** Pure Functional Core in `crates/crypto/src/plc.rs`. No I/O, no HTTP, no DB. Takes key material and identity fields; returns a signed operation JSON string and the derived DID. The relay (Phase 2) will call this function and handle all I/O.

**Tech Stack:** Rust stable; `p256` 0.13 (ECDSA-SHA256, RFC 6979), `ciborium` 0.2 (CBOR serialization), `data-encoding` 2 (base32-lowercase), `sha2` 0.10 (SHA-256), `base64` 0.21 (base64url), `serde`/`serde_json` 1 (struct serialization)

**Scope:** Phase 1 of 2 from the original design

**Codebase verified:** 2026-03-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-89.AC1: crypto crate produces a valid did:plc genesis operation
- **MM-89.AC1.1 Success:** `build_did_plc_genesis_op` with valid inputs returns `PlcGenesisOp` with `did` matching `^did:plc:[a-z2-7]{24}$`
- **MM-89.AC1.2 Success:** `signed_op_json` contains all required fields: `type`, `rotationKeys`, `verificationMethods`, `alsoKnownAs`, `services`, `prev` (null), `sig`
- **MM-89.AC1.3 Success:** `rotation_key` appears as `rotationKeys[0]`; `signing_key` appears as both `rotationKeys[1]` and `verificationMethods.atproto`
- **MM-89.AC1.4 Success:** Calling `build_did_plc_genesis_op` twice with identical inputs returns the same `did` (RFC 6979 determinism)
- **MM-89.AC1.5 Failure:** Invalid `signing_private_key` bytes (wrong length or invalid scalar) returns `CryptoError::PlcOperation`

### MM-89.AC3: Schema migration and protocol correctness
- **MM-89.AC3.2:** `sig` field in `signed_op_json` is a base64url string (no padding) decoding to exactly 64 bytes
- **MM-89.AC3.3:** `alsoKnownAs` in `signed_op_json` contains `at://{handle}` (not bare handle)

---

## External Dependency Research Findings

- ✓ **ciborium 0.2**: `ciborium::ser::into_writer(&value, &mut buf)` serializes serde-compatible structs. Struct fields serialized in declaration order — MUST match DAG-CBOR canonical ordering (sort by key byte length, then alphabetically).
- ✓ **data-encoding 2**: No built-in lowercase base32 constant. Must build via `Specification::new()` with alphabet `"abcdefghijklmnopqrstuvwxyz234567"`. Take `[0..24]` of result for DID suffix.
- ✓ **p256 0.13 (ecdsa feature)**: `SigningKey::from_bytes(&FieldBytes)` from 32-byte scalar. RFC 6979 deterministic by default. `Signer::sign(&bytes)` internally SHA-256 hashes and signs. `sig.to_bytes()` → `[u8; 64]` (r‖s, big-endian). Low-S canonical automatically applied.
- ✓ **base64 0.21** (already in workspace): `URL_SAFE_NO_PAD.encode(&bytes)` for base64url without padding.
- ✓ **did:plc spec**: `type` = `"plc_operation"`. `prev` must be `null` (present, not omitted). Sig absent during signing CBOR, present in final JSON. DID derived from SHA-256 of **signed** CBOR op (with sig field). POST target is `https://plc.directory/{did}`.
- ⚠ **DAG-CBOR note**: did:plc spec requires DAG-CBOR (IPLD-canonical). ciborium produces regular CBOR. For determinism, struct fields must be declared in DAG-CBOR canonical order (length-then-alpha). This implementation's DID derivation will be consistent with itself but must be validated against a real plc.directory in Phase 2 integration tests.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Add workspace and crate Cargo.toml dependencies

**Verifies:** None (infrastructure)

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/crypto/Cargo.toml`

**Step 1: Add ciborium and data-encoding to workspace Cargo.toml**

In `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/Cargo.toml`, in the `[workspace.dependencies]` section, add these two lines after the existing `base64` entry:

```toml
ciborium = "0.2"
data-encoding = "2"
```

**Step 2: Add new deps to crates/crypto/Cargo.toml**

In `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/crypto/Cargo.toml`, add to the `[dependencies]` section:

```toml
ciborium = { workspace = true }
data-encoding = { workspace = true }
serde = { workspace = true }
sha2 = { workspace = true }
```

The file after edits:

```toml
[package]
name = "crypto"
version.workspace = true
edition.workspace = true
publish.workspace = true

# crypto: signing, Shamir secret sharing, DID operations.
# Depends on rsky-crypto (added when Wave 3 DID/key work begins).

[dependencies]
p256 = { workspace = true }
aes-gcm = { workspace = true }
multibase = { workspace = true }
rand_core = { workspace = true }
base64 = { workspace = true }
thiserror = { workspace = true }
zeroize = { workspace = true }
ciborium = { workspace = true }
data-encoding = { workspace = true }
serde = { workspace = true }
sha2 = { workspace = true }
```

**Step 3: Verify build resolves**

```bash
cargo check -p crypto
```

Expected: resolves without errors (plc module not yet created, but deps should resolve).

**Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock crates/crypto/Cargo.toml
git commit -m "chore(crypto): add ciborium, data-encoding, sha2, serde deps for did:plc"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add CryptoError::PlcOperation variant, implement plc.rs, and update lib.rs

**Verifies:** MM-89.AC1.1, MM-89.AC1.2, MM-89.AC1.3, MM-89.AC1.4, MM-89.AC1.5, MM-89.AC3.2, MM-89.AC3.3

**Files:**
- Modify: `crates/crypto/src/error.rs` (add variant)
- Create: `crates/crypto/src/plc.rs` (new file — pure Functional Core)
- Modify: `crates/crypto/src/lib.rs` (add module + re-exports)

---

**Step 1: Add PlcOperation variant to error.rs**

In `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/crypto/src/error.rs`, add the new variant to the `CryptoError` enum:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("secret sharing failed: {0}")]
    SecretSharing(String),
    #[error("secret reconstruction failed: {0}")]
    SecretReconstruction(String),
    #[error("plc operation failed: {0}")]
    PlcOperation(String),
}
```

---

**Step 2: Create crates/crypto/src/plc.rs**

Create `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/crypto/src/plc.rs` with this content:

```rust
// pattern: Functional Core
//
// Pure did:plc genesis operation builder. No I/O, no HTTP, no DB.
// Builds a signed genesis operation from key material and identity fields,
// derives the DID, and returns both for use by the relay's imperative shell.
//
// Algorithm:
//   1. Construct UnsignedPlcOp (fields in DAG-CBOR canonical order)
//   2. CBOR-encode unsigned op (ciborium)
//   3. ECDSA-SHA256 sign the CBOR bytes (p256, RFC 6979 deterministic, low-S)
//   4. base64url-encode the 64-byte r‖s signature
//   5. Construct SignedPlcOp (same fields + sig)
//   6. CBOR-encode signed op
//   7. SHA-256 hash of signed CBOR
//   8. base32-lowercase first 24 chars → DID suffix
//   9. JSON-serialize signed op → signed_op_json
//
// References:
//   - did:plc spec v0.1: https://web.plc.directory/spec/v0.1/did-plc
//   - RFC 6979: deterministic ECDSA nonce generation
//   - DAG-CBOR: map keys sorted by byte-length then alphabetically

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::ser::into_writer;
use p256::{
    FieldBytes,
    ecdsa::{SigningKey, Signature, signature::Signer},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{CryptoError, DidKeyUri};

/// The result of building a did:plc genesis operation.
pub struct PlcGenesisOp {
    /// The derived DID, e.g. `"did:plc:abcdefghijklmnopqrstuvwx"`.
    /// Ready to use as the database primary key.
    pub did: String,
    /// The signed genesis operation as a JSON string.
    /// Ready to POST to plc.directory.
    pub signed_op_json: String,
}

// ── Internal serialization types ────────────────────────────────────────────
//
// Field declaration order matches DAG-CBOR canonical ordering:
// sort by UTF-8 byte length of the serialized key name, then alphabetically.
//
// For UnsignedPlcOp key lengths:
//   "prev"                 → 4 bytes
//   "type"                 → 4 bytes  ("prev" < "type" alphabetically)
//   "services"             → 8 bytes
//   "alsoKnownAs"          → 11 bytes
//   "rotationKeys"         → 12 bytes
//   "verificationMethods"  → 19 bytes

#[derive(Serialize, Clone)]
struct PlcService {
    // "type" → 4 bytes
    #[serde(rename = "type")]
    service_type: String,
    // "endpoint" → 8 bytes
    endpoint: String,
}

#[derive(Serialize)]
struct UnsignedPlcOp {
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

// For SignedPlcOp key lengths (includes "sig"):
//   "sig"                  → 3 bytes  (shortest — comes first)
//   "prev"                 → 4 bytes
//   "type"                 → 4 bytes
//   "services"             → 8 bytes
//   "alsoKnownAs"          → 11 bytes
//   "rotationKeys"         → 12 bytes
//   "verificationMethods"  → 19 bytes

#[derive(Serialize)]
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

// ── Public API ───────────────────────────────────────────────────────────────

/// Build and sign a did:plc genesis operation, returning the signed operation
/// JSON and the derived DID.
///
/// # Parameters
/// - `rotation_key`: The user's device key (highest-priority rotation key). Placed at `rotationKeys[0]`.
/// - `signing_key`: The relay's signing key. Placed at `rotationKeys[1]` and `verificationMethods.atproto`.
/// - `signing_private_key`: Raw 32-byte P-256 private key scalar for `signing_key`.
/// - `handle`: The account handle, e.g. `"alice.example.com"`. Stored as `"at://alice.example.com"` in `alsoKnownAs`.
/// - `service_endpoint`: The relay's public URL, e.g. `"https://relay.example.com"`.
///
/// # Errors
/// Returns `CryptoError::PlcOperation` if `signing_private_key` is not a valid P-256 scalar
/// (e.g. all-zero bytes, or a value ≥ the curve order).
pub fn build_did_plc_genesis_op(
    rotation_key: &DidKeyUri,
    signing_key: &DidKeyUri,
    signing_private_key: &[u8; 32],
    handle: &str,
    service_endpoint: &str,
) -> Result<PlcGenesisOp, CryptoError> {
    // Step 1: Construct signing key from raw scalar bytes.
    let field_bytes: FieldBytes = (*signing_private_key).into();
    let sk = SigningKey::from_bytes(&field_bytes)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid signing key: {e}")))?;

    // Step 2: Build the unsigned operation.
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

    // Step 3: CBOR-encode the unsigned operation.
    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Step 4: ECDSA-SHA256 sign (RFC 6979 deterministic, low-S canonical).
    // Signer::sign internally hashes with SHA-256 before signing.
    let sig: Signature = sk.sign(&unsigned_cbor);
    let sig_bytes = sig.to_bytes();

    // Step 5: base64url-encode the 64-byte r‖s signature (no padding).
    let sig_str = URL_SAFE_NO_PAD.encode(sig_bytes.as_ref());

    // Step 6: Build the signed operation (same fields + sig).
    let signed_op = SignedPlcOp {
        sig: sig_str,
        prev: None,
        op_type: "plc_operation".to_string(),
        services,
        also_known_as: vec![format!("at://{handle}")],
        rotation_keys: vec![rotation_key.0.clone(), signing_key.0.clone()],
        verification_methods,
    };

    // Step 7: CBOR-encode the signed operation.
    let mut signed_cbor = Vec::new();
    into_writer(&signed_op, &mut signed_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode signed op: {e}")))?;

    // Step 8: SHA-256 hash of the signed CBOR.
    let hash = Sha256::digest(&signed_cbor);

    // Step 9: base32-lowercase, take first 24 characters.
    let base32_encoding = {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
        spec.encoding()
            .map_err(|e| CryptoError::PlcOperation(format!("build base32 encoding: {e}")))?
    };
    let encoded = base32_encoding.encode(hash.as_ref());
    let did = format!("did:plc:{}", &encoded[..24]);

    // Step 10: JSON-serialize the signed operation.
    let signed_op_json = serde_json::to_string(&signed_op)
        .map_err(|e| CryptoError::PlcOperation(format!("json serialize signed op: {e}")))?;

    Ok(PlcGenesisOp { did, signed_op_json })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_p256_keypair;

    /// Generates two test keypairs and calls build_did_plc_genesis_op with them.
    /// Returns (rotation_key, signing_key, private_key_bytes, result).
    fn make_genesis_op() -> (DidKeyUri, DidKeyUri, [u8; 32], PlcGenesisOp) {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes = *signing_kp.private_key_bytes;
        let result = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("genesis op should succeed");
        (rotation_kp.key_id, signing_kp.key_id, private_key_bytes, result)
    }

    /// MM-89.AC1.1: did matches ^did:plc:[a-z2-7]{24}$
    #[test]
    fn did_matches_expected_format() {
        let (_, _, _, op) = make_genesis_op();
        assert!(
            op.did.starts_with("did:plc:"),
            "DID should start with 'did:plc:'"
        );
        let suffix = op.did.strip_prefix("did:plc:").unwrap();
        assert_eq!(suffix.len(), 24, "DID suffix should be 24 chars");
        assert!(
            suffix.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)),
            "DID suffix should only contain [a-z2-7], got: {suffix}"
        );
    }

    /// MM-89.AC1.2: signed_op_json contains all required fields with correct values
    #[test]
    fn signed_op_json_contains_required_fields() {
        let (_, _, _, op) = make_genesis_op();
        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");

        assert_eq!(v["type"], "plc_operation", "type field");
        assert!(v["rotationKeys"].is_array(), "rotationKeys is array");
        assert!(
            v["verificationMethods"].is_object(),
            "verificationMethods is object"
        );
        assert!(v["alsoKnownAs"].is_array(), "alsoKnownAs is array");
        assert!(v["services"].is_object(), "services is object");
        assert_eq!(v["prev"], serde_json::Value::Null, "prev is null");
        assert!(v["sig"].is_string(), "sig is string");
    }

    /// MM-89.AC1.3: rotation_key at rotationKeys[0]; signing_key at rotationKeys[1] and verificationMethods.atproto
    #[test]
    fn keys_placed_in_correct_positions() {
        let (rotation_key, signing_key, _, op) = make_genesis_op();
        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        assert_eq!(
            v["rotationKeys"][0].as_str().unwrap(),
            rotation_key.0,
            "rotationKeys[0] should be rotation_key"
        );
        assert_eq!(
            v["rotationKeys"][1].as_str().unwrap(),
            signing_key.0,
            "rotationKeys[1] should be signing_key"
        );
        assert_eq!(
            v["verificationMethods"]["atproto"].as_str().unwrap(),
            signing_key.0,
            "verificationMethods.atproto should be signing_key"
        );
    }

    /// MM-89.AC1.4: RFC 6979 determinism — same inputs produce same DID
    #[test]
    fn same_inputs_produce_same_did() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes = *signing_kp.private_key_bytes;

        let op1 = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("first call should succeed");

        let op2 = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("second call should succeed");

        assert_eq!(op1.did, op2.did, "DID must be identical for same inputs");
        assert_eq!(
            op1.signed_op_json, op2.signed_op_json,
            "signed_op_json must be identical for same inputs"
        );
    }

    /// MM-89.AC1.5: Invalid signing key (all-zero scalar) returns CryptoError::PlcOperation
    #[test]
    fn invalid_signing_key_returns_error() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let zero_bytes = [0u8; 32]; // Zero scalar is invalid for P-256

        let result = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &zero_bytes,
            "alice.example.com",
            "https://relay.example.com",
        );

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "Zero scalar should return CryptoError::PlcOperation, got: {result:?}"
        );
    }

    /// MM-89.AC3.2: sig field is base64url (no padding) decoding to exactly 64 bytes
    #[test]
    fn sig_field_is_base64url_no_padding_and_64_bytes() {
        let (_, _, _, op) = make_genesis_op();
        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let sig_str = v["sig"].as_str().expect("sig is a string");

        // No padding characters
        assert!(
            !sig_str.contains('='),
            "sig should not contain padding '=', got: {sig_str}"
        );
        // Decodes to exactly 64 bytes
        let decoded = URL_SAFE_NO_PAD
            .decode(sig_str)
            .expect("sig should be valid base64url");
        assert_eq!(
            decoded.len(),
            64,
            "sig should decode to 64 bytes (r‖s), got {} bytes",
            decoded.len()
        );
    }

    /// MM-89.AC3.3: alsoKnownAs contains at://{handle}
    #[test]
    fn also_known_as_contains_at_uri() {
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
        .expect("genesis op should succeed");

        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let also_known_as = v["alsoKnownAs"].as_array().expect("alsoKnownAs is array");
        assert!(
            also_known_as
                .iter()
                .any(|e| e.as_str() == Some("at://alice.example.com")),
            "alsoKnownAs should contain 'at://alice.example.com', got: {also_known_as:?}"
        );
    }
}
```

---

**Step 3: Add plc module to lib.rs and re-export public types**

In `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/crypto/src/lib.rs`, add the new module declaration and re-exports:

```rust
// crypto: signing, Shamir secret sharing, DID operations.

pub mod error;
pub mod keys;
pub mod plc;
pub mod shamir;

pub use error::CryptoError;
pub use keys::{
    decrypt_private_key, encrypt_private_key, generate_p256_keypair, DidKeyUri, P256Keypair,
};
pub use plc::{build_did_plc_genesis_op, PlcGenesisOp};
pub use shamir::{combine_shares, split_secret, ShamirShare};
```

---

**Step 4: Verify all tests pass**

```bash
cargo test -p crypto
```

Expected output: all tests pass, including the 7 new tests in `plc::tests`.

**Step 5: Verify no clippy warnings**

```bash
cargo clippy -p crypto -- -D warnings
```

Expected: no warnings.

**Step 6: Commit**

```bash
git add crates/crypto/src/error.rs crates/crypto/src/plc.rs crates/crypto/src/lib.rs
git commit -m "feat(crypto): implement build_did_plc_genesis_op for did:plc genesis ops (MM-89)"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update crates/crypto/CLAUDE.md

**Verifies:** None (documentation)

**Files:**
- Modify: `crates/crypto/CLAUDE.md`

**Step 1: Add new contracts to CLAUDE.md**

In `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/crypto/CLAUDE.md`, update the "Last verified" date to `2026-03-13` and add the following to the **Public API contracts** section (add after the existing contracts):

```markdown
### `build_did_plc_genesis_op`

```rust
pub fn build_did_plc_genesis_op(
    rotation_key: &DidKeyUri,       // user's root rotation key (rotationKeys[0])
    signing_key: &DidKeyUri,        // relay's signing key (rotationKeys[1] + verificationMethods.atproto)
    signing_private_key: &[u8; 32], // raw P-256 private key scalar for signing_key
    handle: &str,                   // e.g. "alice.example.com"
    service_endpoint: &str,         // e.g. "https://relay.example.com"
) -> Result<PlcGenesisOp, CryptoError>
```

- Constructs a signed did:plc genesis operation.
- Returns `PlcGenesisOp { did, signed_op_json }`.
- `did` matches `^did:plc:[a-z2-7]{24}$`.
- `signed_op_json` is ready to POST to `https://plc.directory/{did}`.
- Deterministic: same inputs → same DID (RFC 6979 + SHA-256 + base32).
- Errors: `CryptoError::PlcOperation` if `signing_private_key` is an invalid P-256 scalar.

### `PlcGenesisOp`

```rust
pub struct PlcGenesisOp {
    pub did: String,            // "did:plc:xxxx..." — 28 chars total
    pub signed_op_json: String, // signed operation JSON
}
```

- `did`: derived from SHA-256 of CBOR-encoded signed op, base32-lowercase, first 24 chars, prefixed with `"did:plc:"`.
- `signed_op_json`: JSON containing `type`, `rotationKeys`, `verificationMethods`, `alsoKnownAs`, `services`, `prev` (null), `sig`.
```

**Step 2: Also update the Dependencies section** to include the new deps:

Add to the existing dependencies list:
- `ciborium` — CBOR serialization for signing and DID derivation
- `data-encoding` — base32-lowercase encoding
- `sha2` — SHA-256 hashing
- `serde` — derive macros for CBOR/JSON serialization

**Step 3: Commit**

```bash
git add crates/crypto/CLAUDE.md
git commit -m "docs(crypto): update CLAUDE.md with build_did_plc_genesis_op contracts (MM-89)"
```
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->

---

## Phase Completion Verification

After all three tasks, verify the complete phase:

```bash
# All crypto tests pass
cargo test -p crypto

# No clippy warnings
cargo clippy -p crypto -- -D warnings

# No formatting issues
cargo fmt -p crypto --check
```

Expected: all tests pass (existing 9 + new 7 = 16 tests), zero warnings, formatted correctly.
