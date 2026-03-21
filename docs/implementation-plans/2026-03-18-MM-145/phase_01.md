# MM-145 — P-256 Keypair via Secure Enclave: Implementation Plan

**Goal:** Introduce `device_key.rs` with the software fallback (simulator + macOS host) implementation and full test coverage.

**Architecture:** A new Rust module `device_key.rs` with compile-time `#[cfg]`-based dispatch. The simulator + macOS host path uses `crypto::generate_p256_keypair()` for key generation, the `p256` crate for public-key reconstruction and signing, and `multibase` for base58btc encoding. The real-device (SE) path is stubbed with placeholder errors in Phase 1.

**Tech Stack:** Rust, `p256` 0.13 (ecdsa feature), `multibase` 0.9, `thiserror` 2, `security-framework` (Keychain via `keychain.rs`), `serde`

**Scope:** Phase 1 of 4 — simulator/macOS host path only. SE path stubs return `KeyGenerationFailed`.

**Codebase verified:** 2026-03-19

**cfg deviation from design:** The design doc uses `#[cfg(all(target_vendor = "apple", target_env = "sim"))]` for the simulator path. On macOS host (target of `cargo test`), `target_env` is `""` not `"sim"`, so that cfg would NOT match — tests would fail. This plan extends the software-path cfg to `any(target_os = "macos", all(target_os = "ios", target_env = "sim"))`, and the real-device stub cfg to `all(target_os = "ios", not(target_env = "sim"))`. This makes `cargo test` work on macOS while still providing correct behavior on simulator and real device.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-145.AC1: get_or_create_device_key returns a valid DevicePublicKey
- **MM-145.AC1.1 Success:** public key multibase string starts with `'z'` and decodes (via base58btc) to exactly 33 bytes
- **MM-145.AC1.2 Success:** two successive calls return identical `multibase` and `key_id` values (idempotent)
- **MM-145.AC1.3 Success:** `key_id` is prefixed with `"did:key:z"`
- **MM-145.AC1.4 Success:** key persists — a fresh call after app restart returns the same public key

  _Coverage note:_ AC1.4 is implicitly covered by AC1.2 on the simulator/macOS path. The `get_or_create()` function is stateless (no in-process caching) — it always calls `keychain::get_item()` on every invocation. Therefore, the idempotency test (which exercises Keychain write then Keychain read in sequence) proves Keychain round-trip correctness, which is the same property needed for persistence across app restarts. Cross-process persistence on real devices is verified manually in Phase 2 (AC2.1).

### MM-145.AC3: sign_with_device_key returns a valid ECDSA P-256 signature
- **MM-145.AC3.1 Success:** signing arbitrary data returns exactly 64 bytes
- **MM-145.AC3.2 Success:** signing the same data twice returns identical bytes (RFC 6979 deterministic, simulator path)
- **MM-145.AC3.3 Failure:** calling `sign` before `get_or_create` returns `DeviceKeyError::KeyNotFound`

### MM-145.AC4: DeviceKeyError and Tauri commands follow project conventions
- **MM-145.AC4.1 Success:** all `DeviceKeyError` variants serialize as `{ "code": "SCREAMING_SNAKE_CASE" }`

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add dependencies to Cargo.toml and mod declaration to lib.rs

**Verifies:** None (infrastructure)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml` (lines 15–26, the `[dependencies]` section)
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (lines 1–2, the `pub mod` declarations)

**Step 1: Add `p256` and `multibase` to `apps/identity-wallet/src-tauri/Cargo.toml`**

The current `[dependencies]` section (lines 15–26) is:

```toml
[dependencies]
tauri = { version = "2", features = [] }
serde = { workspace = true }
serde_json = { workspace = true }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
security-framework = "3"
thiserror = { workspace = true }
crypto = { workspace = true }
```

Add two lines at the end of the `[dependencies]` block:

```toml
p256 = { workspace = true }
multibase = { workspace = true }
```

Both are already declared at workspace level in the root `Cargo.toml` (lines 61 and 63):
- `p256 = { version = "0.13", features = ["ecdsa"] }`
- `multibase = "0.9"`

Note: the design doc calls for `bs58` but this repo already has `multibase` in the workspace (used by the `crypto` crate). `multibase::encode(Base::Base58Btc, bytes)` produces the same `'z'` + base58btc output as `'z'.to_string() + &bs58::encode(bytes).into_string()` — no additional dependency needed.

**Step 2: Add `pub mod device_key;` to `apps/identity-wallet/src-tauri/src/lib.rs`**

The current mod declarations at the top of `lib.rs` (lines 1–2):

```rust
pub mod http;
pub mod keychain;
```

Add a third line:

```rust
pub mod http;
pub mod keychain;
pub mod device_key;
```

**Step 3: Verify compilation**

Run:
```bash
cargo check -p identity-wallet 2>&1 | head -30
```

Expected: compile error "file not found for module `device_key`" — this is correct; the file doesn't exist yet. The error confirms the mod declaration is wired up.

**Commit:** Do not commit yet — continue to Task 2.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create `device_key.rs` — types, DeviceKeyError, and function stubs

**Verifies:** MM-145.AC4.1 (partially — DeviceKeyError exists; full serialization tested in Task 3)

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/device_key.rs`

**Step 1: Create `device_key.rs` with types, error enum, and function stubs**

Create `/Users/malpercio/workspace/malpercio-dev/ezpds/apps/identity-wallet/src-tauri/src/device_key.rs` with the following content:

```rust
use serde::Serialize;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DevicePublicKey {
    /// Multibase base58btc-encoded compressed P-256 public key point.
    /// Format: 'z' + base58btc(33-byte SEC1 compressed point).
    pub multibase: String,
    /// Full did:key URI. Format: "did:key:z...".
    pub key_id: String,
}

/// Errors returned by device key operations.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` — matches the
/// `CreateAccountError` pattern in `lib.rs`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceKeyError {
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("key not found; call get_or_create before sign")]
    KeyNotFound,
    #[error("signing failed")]
    SigningFailed,
    /// DER → r||s parse failed (SE path only; not reachable on simulator).
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("keychain error: {message}")]
    KeychainError { message: String },
}

// ── Simulator / macOS host path ───────────────────────────────────────────────
//
// Covers:
//   - macOS (target_os = "macos"): used for `cargo test` on developer machines
//   - iOS Simulator (target_os = "ios", target_env = "sim"): no Secure Enclave hardware
//
// Note: the design doc cfg (all(target_vendor = "apple", target_env = "sim")) does not
// match macOS host where target_env = "". We extend to include target_os = "macos" so
// that `cargo test` exercises the software path rather than the SE stubs below.

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    // Stub — implemented in Task 4.
    Err(DeviceKeyError::KeyGenerationFailed)
}

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn sign(_data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    // Stub — implemented in Task 4.
    Err(DeviceKeyError::KeyGenerationFailed)
}

// ── Real device (Secure Enclave) stubs ───────────────────────────────────────
//
// Phase 1 placeholder. The SE path is implemented in Phase 2.
// These compile for `cargo build --target aarch64-apple-ios` but always error.

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    Err(DeviceKeyError::KeyGenerationFailed)
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn sign(_data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    Err(DeviceKeyError::KeyGenerationFailed)
}
```

**Step 2: Verify compilation**

```bash
cargo check -p identity-wallet
```

Expected: compiles without errors or warnings (the stub functions are `dead_code` only on non-matching targets).

**Step 3: Confirm tests don't exist yet**

```bash
cargo test -p identity-wallet 2>&1 | grep "device_key"
```

Expected: no test output for device_key — confirms no tests yet.

**Commit:** Do not commit yet — tests come next.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-5) -->

<!-- START_TASK_3 -->
### Task 3: Write failing tests for all 7 ACs

**Verifies:** MM-145.AC1.1, MM-145.AC1.2, MM-145.AC1.3, MM-145.AC3.1, MM-145.AC3.2, MM-145.AC3.3, MM-145.AC4.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/device_key.rs` (append `#[cfg(test)]` module)

**Step 1: Append the test module to `device_key.rs`**

Append the following block at the end of `device_key.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Tests use the real macOS Keychain under service "ezpds-identity-wallet".
    // Run with `cargo test -- --test-threads=1` to prevent Keychain races between tests.

    // AC1.1 — multibase starts with 'z' and decodes to 33 bytes
    #[test]
    fn get_or_create_returns_valid_multibase() {
        let result = get_or_create().expect("get_or_create should succeed");
        assert!(result.multibase.starts_with('z'), "multibase must start with 'z'");
        let (_, decoded) = multibase::decode(&result.multibase).expect("multibase must decode");
        assert_eq!(decoded.len(), 33, "compressed P-256 point must be 33 bytes");
    }

    // AC1.2 — two successive calls are idempotent
    #[test]
    fn get_or_create_is_idempotent() {
        let first = get_or_create().expect("first call should succeed");
        let second = get_or_create().expect("second call should succeed");
        assert_eq!(first.multibase, second.multibase, "multibase must be stable");
        assert_eq!(first.key_id, second.key_id, "key_id must be stable");
    }

    // AC1.3 — key_id starts with "did:key:z"
    #[test]
    fn key_id_has_did_key_prefix() {
        let result = get_or_create().expect("get_or_create should succeed");
        assert!(
            result.key_id.starts_with("did:key:z"),
            "key_id must start with 'did:key:z', got: {}",
            result.key_id
        );
    }

    // AC3.1 — sign returns exactly 64 bytes
    #[test]
    fn sign_returns_64_bytes() {
        get_or_create().expect("must have key before signing");
        let sig = sign(b"test payload").expect("sign should succeed");
        assert_eq!(sig.len(), 64, "raw r||s signature must be 64 bytes");
    }

    // AC3.2 — signing is deterministic (RFC 6979)
    #[test]
    fn sign_is_deterministic() {
        get_or_create().expect("must have key before signing");
        let sig1 = sign(b"determinism test").expect("first sign should succeed");
        let sig2 = sign(b"determinism test").expect("second sign should succeed");
        assert_eq!(sig1, sig2, "same data with same key must produce same signature");
    }

    // AC3.3 — sign before get_or_create returns KeyNotFound
    #[test]
    fn sign_before_generate_returns_key_not_found() {
        // Delete any key left by previous tests to simulate a fresh state.
        let _ = crate::keychain::delete_item("device-rotation-key-priv");
        let result = sign(b"should fail");
        assert!(
            matches!(result, Err(DeviceKeyError::KeyNotFound)),
            "expected KeyNotFound, got: {:?}",
            result
        );
    }

    // AC4.1 — DeviceKeyError variants serialize as { "code": "SCREAMING_SNAKE_CASE" }
    #[test]
    fn device_key_error_serializes_as_code() {
        let err = DeviceKeyError::KeyGenerationFailed;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "KEY_GENERATION_FAILED");

        let err2 = DeviceKeyError::KeyNotFound;
        let json2 = serde_json::to_value(&err2).unwrap();
        assert_eq!(json2["code"], "KEY_NOT_FOUND");

        let err3 = DeviceKeyError::KeychainError { message: "os error".into() };
        let json3 = serde_json::to_value(&err3).unwrap();
        assert_eq!(json3["code"], "KEYCHAIN_ERROR");
        assert_eq!(json3["message"], "os error");
    }
}
```

**Step 2: Verify tests compile and fail**

```bash
cargo test -p identity-wallet -- --test-threads=1 2>&1 | tail -30
```

Expected: tests compile but most fail — the stubs return `Err(DeviceKeyError::KeyGenerationFailed)` so:
- `get_or_create_*` tests fail with "get_or_create should succeed: KeyGenerationFailed"
- `sign_*` tests fail similarly
- `device_key_error_serializes_as_code` passes (tests the error enum directly, no Keychain)
- `sign_before_generate_returns_key_not_found` will FAIL (stub returns `KeyGenerationFailed`, not `KeyNotFound`) — this is expected and correct; Task 4 fixes the stub to return `KeyNotFound`

**Commit:** Do not commit yet — implement in Task 4.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Implement simulator/macOS host path — get_or_create and sign

**Verifies:** MM-145.AC1.1, MM-145.AC1.2, MM-145.AC1.3, MM-145.AC3.1, MM-145.AC3.2, MM-145.AC3.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/device_key.rs` (replace the two simulator stub functions)

**Implementation:**

The simulator-path `get_or_create()` and `sign()` stubs from Task 2 (which return `Err(DeviceKeyError::KeyGenerationFailed)`) must be replaced with full implementations.

**Replace the two simulator-path stubs:**

Find these stubs in device_key.rs:

```rust
#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    // Stub — implemented in Task 4.
    Err(DeviceKeyError::KeyGenerationFailed)
}

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn sign(_data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    // Stub — implemented in Task 4.
    Err(DeviceKeyError::KeyGenerationFailed)
}
```

Replace them with:

```rust
#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    use p256::ecdsa::SigningKey;

    const ACCOUNT: &str = "device-rotation-key-priv";

    // Try to load existing private key bytes from Keychain.
    let private_bytes: Vec<u8> = match crate::keychain::get_item(ACCOUNT) {
        Ok(bytes) => bytes,
        Err(_) => {
            // No key yet — generate a new P-256 keypair via the crypto crate.
            let keypair = crypto::generate_p256_keypair()
                .map_err(|_| DeviceKeyError::KeyGenerationFailed)?;
            // Deref Zeroizing<[u8; 32]> to [u8; 32], then collect as Vec<u8>.
            let bytes = keypair.private_key_bytes.to_vec();
            crate::keychain::store_item(ACCOUNT, &bytes)
                .map_err(|e| DeviceKeyError::KeychainError { message: e.to_string() })?;
            bytes
        }
    };

    // Reconstruct the public key from stored private bytes.
    let signing_key = SigningKey::from_slice(&private_bytes)
        .map_err(|_| DeviceKeyError::KeychainError { message: "invalid stored key bytes".into() })?;
    let encoded = signing_key.verifying_key().to_encoded_point(true); // compressed (33 bytes)
    let compressed = encoded.as_bytes();
    let multibase = multibase::encode(multibase::Base::Base58Btc, compressed);
    // did:key requires the P-256 multicodec varint prefix [0x80, 0x24] (0x1200 as LEB128)
    // prepended to the compressed point. This matches crates/crypto/src/keys.rs
    // `P256_MULTICODEC_PREFIX = &[0x80, 0x24]`, which is `pub(crate)` and cannot be
    // imported across crate boundaries — the constant is duplicated intentionally.
    const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
    let mut multikey = Vec::with_capacity(2 + compressed.len());
    multikey.extend_from_slice(P256_MULTICODEC);
    multikey.extend_from_slice(compressed);
    let key_id = format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, &multikey));

    Ok(DevicePublicKey { multibase, key_id })
}

#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::{Signature, SigningKey};
    use p256::ecdsa::signature::Signer;

    const ACCOUNT: &str = "device-rotation-key-priv";

    // If the key doesn't exist, signal that get_or_create must be called first.
    let private_bytes = crate::keychain::get_item(ACCOUNT)
        .map_err(|_| DeviceKeyError::KeyNotFound)?;

    let signing_key = SigningKey::from_slice(&private_bytes)
        .map_err(|_| DeviceKeyError::SigningFailed)?;

    // sign() uses the deterministic Signer impl (RFC 6979 nonce).
    // It internally hashes `data` with SHA-256 before signing.
    let signature: Signature = signing_key.sign(data);

    // to_bytes() returns a fixed 64-byte GenericArray<u8, U64> (raw r||s).
    Ok(signature.to_bytes().to_vec())
}
```

**Compilation note:** `Zeroizing<[u8; 32]>` implements `Deref<Target = [u8; 32]>`, and `[u8; 32]` coerces to `[u8]` which has `.to_vec()`. If the compiler cannot resolve `.to_vec()` on the deref chain, use: `let bytes = (&*keypair.private_key_bytes as &[u8]).to_vec();`

**Step 2: Verify cargo check**

```bash
cargo check -p identity-wallet
```

Expected: compiles without errors.
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Run tests and commit Phase 1

**Verifies:** All 7 ACs listed in this phase

**Files:** No changes — verification only.

**Step 1: Run all tests**

```bash
cargo test -p identity-wallet -- --test-threads=1 2>&1
```

Expected output (all 7 tests pass):
```
running 7 tests
test device_key::tests::device_key_error_serializes_as_code ... ok
test device_key::tests::get_or_create_is_idempotent ... ok
test device_key::tests::get_or_create_returns_valid_multibase ... ok
test device_key::tests::key_id_has_did_key_prefix ... ok
test device_key::tests::sign_before_generate_returns_key_not_found ... ok
test device_key::tests::sign_is_deterministic ... ok
test device_key::tests::sign_returns_64_bytes ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; ...
```

Note: `--test-threads=1` is required because all tests share the same Keychain entry (`"device-rotation-key-priv"` under `"ezpds-identity-wallet"`). Without it, `sign_before_generate_returns_key_not_found` (which deletes the key) may race with `get_or_create_*` tests.

**Step 2: Run clippy**

```bash
cargo clippy -p identity-wallet -- -D warnings
```

Expected: no warnings.

**Step 3: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml \
        apps/identity-wallet/src-tauri/src/lib.rs \
        apps/identity-wallet/src-tauri/src/device_key.rs
git commit -m "feat(device-key): add device_key module with simulator/macOS software path and tests"
```
<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_B -->
