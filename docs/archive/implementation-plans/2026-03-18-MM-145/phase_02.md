# MM-145 — P-256 Keypair via Secure Enclave: Phase 2

**Goal:** Replace the Phase 1 real-device stubs with a Secure Enclave P-256 implementation using the safe `security_framework` 3.x wrapper.

**Architecture:** The SE path uses `security_framework::key::SecKey::new()` with `Token::SecureEnclave` for hardware-backed key generation. The generated key is permanent in the SE. The SE private key's `application_label` (SHA1 hash of public key, 20 bytes auto-set by the OS) is stored in the regular Keychain for lookup on subsequent launches. The compressed public key (33 bytes) is also stored in the regular Keychain so `get_or_create()` can return without touching the SE hardware on repeat calls. Signing uses `key.create_signature()` which returns DER (70–72 bytes); this is converted to raw r||s (64 bytes) via `p256::ecdsa::Signature::from_der`.

**Tech Stack:** `security_framework` 3.7.x with `OSX_10_12` feature (already in Cargo.toml; need feature flag added), `p256` 0.13 (ecdsa feature, for DER→r||s conversion), `multibase` 0.9

**Scope:** Phase 2 of 4 — real-device Secure Enclave path only. Simulator path (Phase 1) unchanged.

**Codebase verified:** 2026-03-19

**Deviation from design doc:**
- Design calls for raw FFI via `security-framework-sys` (`SecKeyCreateRandomKey`, `SecKeyCopyExternalRepresentation`, `SecKeyCreateSignature`). This plan uses the safe `security_framework` 3.x wrapper instead — same functionality, no `unsafe` blocks, no new dependency.
- Design calls for `kSecAttrApplicationTag` as the lookup key. This plan stores the OS-assigned `application_label` (SHA1 of public key) plus the compressed public key bytes in the regular Keychain (`keychain.rs`). This avoids needing `kSecAttrApplicationTag` FFI and is equally stable across app restarts.
- Design says add `security-framework-sys` as explicit dep. This plan adds `OSX_10_12` feature to the existing `security-framework` dep instead — no new crate needed.

---

## Acceptance Criteria Coverage

This phase implements (no automated tests — SE hardware required):

### MM-145.AC2: Private key material is protected (real device only)
- **MM-145.AC2.1 Success:** key retrieved after cold restart matches key from initial generation (persistence via SE; verified manually on physical device)
- **MM-145.AC2.2 Success:** private key bytes cannot be extracted from the Keychain (`SecKey::new` with `Token::SecureEnclave` is non-extractable by design — verified by attempting `external_representation()` on the private key, which the SE rejects)

---

<!-- START_SUBCOMPONENT_A (task 1) -->

<!-- START_TASK_1 -->
### Task 1: Add `OSX_10_12` feature flag to `security-framework` in Cargo.toml

**Verifies:** None (infrastructure — enables SE APIs)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml` (line 24, the `security-framework` dep)

**Why:** `security_framework::key::SecKey::new()`, `GenerateKeyOptions`, `Token`, `Algorithm`, and `ItemSearchOptions::load_refs()` are all gated behind the `OSX_10_12` feature in the `security-framework` crate (they were introduced in macOS 10.12 / iOS 10). Without this feature, the SE path code won't compile.

**Step 1: Update the `security-framework` dep**

In `apps/identity-wallet/src-tauri/Cargo.toml`, find line 24:

```toml
security-framework = "3"
```

Replace with:

```toml
security-framework = { version = "3", features = ["OSX_10_12"] }
```

**Step 2: Verify `cargo check` still passes**

```bash
cargo check -p identity-wallet
```

Expected: compiles without errors. The `OSX_10_12` feature is additive and backwards-compatible with existing `keychain.rs` usage.

**Commit:** Do not commit yet — continue to Task 2.
<!-- END_TASK_1 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 2-3) -->

<!-- START_TASK_2 -->
### Task 2: Implement SE path `get_or_create()` and `sign()` — replace Phase 1 real-device stubs

**Verifies:** MM-145.AC2.1, MM-145.AC2.2 (manual device verification only)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/device_key.rs` (replace the two `#[cfg(all(target_os = "ios", not(target_env = "sim")))]` stub functions)

**Step 1: Add required imports at the top of `device_key.rs`**

Add to the top of `device_key.rs` (after the existing `use serde::Serialize;` line):

```rust
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
};
```

These imports are gated to the real-device cfg so they don't cause unused-import warnings on macOS/simulator.

**Step 2: Replace the two real-device stubs**

Find these stubs in `device_key.rs`:

```rust
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    Err(DeviceKeyError::KeyGenerationFailed)
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn sign(_data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    Err(DeviceKeyError::KeyGenerationFailed)
}
```

Replace them with:

```rust
/// Account names used to store SE key metadata in the regular Keychain.
/// The SE private key itself is stored in the Secure Enclave and never leaves it.
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
const SE_PUB_ACCOUNT: &str = "device-rotation-key-pub";
#[cfg(all(target_os = "ios", not(target_env = "sim")))]
const SE_APP_LABEL_ACCOUNT: &str = "device-rotation-key-app-label";

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn get_or_create() -> Result<DevicePublicKey, DeviceKeyError> {
    // Fast path: if we already stored the compressed public key, return it directly.
    // This avoids SE hardware interaction on every call after first generation.
    if let Ok(compressed) = crate::keychain::get_item(SE_PUB_ACCOUNT) {
        let multibase = multibase::encode(multibase::Base::Base58Btc, &compressed);
        // did:key requires the P-256 multicodec varint prefix [0x80, 0x24] (0x1200 as LEB128).
        const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
        let mut multikey = Vec::with_capacity(2 + compressed.len());
        multikey.extend_from_slice(P256_MULTICODEC);
        multikey.extend_from_slice(&compressed);
        let key_id = format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, &multikey));
        return Ok(DevicePublicKey { multibase, key_id });
    }

    // Generate a new SE-backed P-256 key.
    // set_location(DataProtectionKeychain) is required — without it, security_framework sets
    // kSecAttrIsPermanent = false, meaning the key is not persisted to the Keychain and will
    // not survive app restart (breaking AC2.1).
    // set_access_control with PRIVATE_KEY_USAGE is required for SE keys — the SE enforces
    // that only explicitly-authorized operations can use the private key for signing.
    //
    // Note: SecAccessControl::create_with_protection takes Option<ProtectionMode> and a raw
    // flags u64. The PRIVATE_KEY_USAGE flag is kSecAccessControlPrivateKeyUsage = 1 << 30.
    // If the compiler reports an ambiguous type on the flags argument, use `0x4000_0000_u64`.
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        1 << 30, // kSecAccessControlPrivateKeyUsage
    )
    .map_err(|_| DeviceKeyError::KeyGenerationFailed)?;

    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_label("ezpds-device-rotation-key")
        .set_location(Location::DataProtectionKeychain)
        .set_access_control(access_control); // takes ownership (by value)

    let priv_key = SecKey::new(&opts).map_err(|_| DeviceKeyError::KeyGenerationFailed)?;

    // Retrieve the public key and its external representation.
    // SecKeyCopyExternalRepresentation on the *public* key returns the uncompressed
    // 65-byte X9.62 point (0x04 || x[32] || y[32]).
    let pub_key = priv_key.public_key().ok_or(DeviceKeyError::KeyGenerationFailed)?;
    let pub_repr = pub_key
        .external_representation()
        .ok_or(DeviceKeyError::KeyGenerationFailed)?;
    let uncompressed: Vec<u8> = pub_repr.to_vec(); // 65 bytes

    // Compress: prefix byte = 0x02 (even y) or 0x03 (odd y); keep x[32].
    // The last byte of the y coordinate determines parity.
    let mut compressed = [0u8; 33];
    compressed[0] = if uncompressed[64] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..].copy_from_slice(&uncompressed[1..33]);

    // Store the compressed public key for the fast path on future calls.
    crate::keychain::store_item(SE_PUB_ACCOUNT, &compressed)
        .map_err(|e| DeviceKeyError::KeychainError { message: e.to_string() })?;

    // Store the application_label (OS-assigned SHA1 of public key, 20 bytes)
    // so sign() can locate the SE private key on future app launches.
    if let Some(app_label) = priv_key.application_label() {
        crate::keychain::store_item(SE_APP_LABEL_ACCOUNT, &app_label)
            .map_err(|e| DeviceKeyError::KeychainError { message: e.to_string() })?;
    }

    let multibase = multibase::encode(multibase::Base::Base58Btc, &compressed);
    // did:key requires the P-256 multicodec varint prefix [0x80, 0x24] (0x1200 as LEB128).
    const P256_MULTICODEC: &[u8] = &[0x80, 0x24];
    let mut multikey = Vec::with_capacity(2 + compressed.len());
    multikey.extend_from_slice(P256_MULTICODEC);
    multikey.extend_from_slice(&compressed);
    let key_id = format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, &multikey));
    Ok(DevicePublicKey { multibase, key_id })
}

#[cfg(all(target_os = "ios", not(target_env = "sim")))]
pub fn sign(data: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
    use p256::ecdsa::Signature;

    // Load the application_label to look up the SE private key.
    let app_label = crate::keychain::get_item(SE_APP_LABEL_ACCOUNT)
        .map_err(|_| DeviceKeyError::KeyNotFound)?;

    // Find the SE private key in the Keychain by its application_label.
    // load_refs(true) returns SearchResult::Ref(CFType) containing the SecKeyRef.
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .application_label(&app_label)
        .load_refs(true)
        .limit(1);

    let results = search.search().map_err(|_| DeviceKeyError::KeyNotFound)?;

    // Extract the SecKey from the typed Reference result.
    // SearchResult::Ref wraps a Reference enum; Reference::Key holds the already-wrapped SecKey.
    // No unsafe code is needed — security_framework handles the SecKeyRef wrapping internally.
    let sec_key = match results.into_iter().next() {
        Some(SearchResult::Ref(Reference::Key(key))) => key,
        _ => return Err(DeviceKeyError::KeyNotFound),
    };

    // create_signature uses kSecKeyAlgorithmECDSASignatureMessageX962SHA256.
    // The SE hashes `data` with SHA-256 internally before signing.
    // Returns DER-encoded ECDSA signature (70–72 bytes).
    let der_sig = sec_key
        .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
        .map_err(|_| DeviceKeyError::SigningFailed)?;

    // Convert DER to raw 64-byte r||s (the format expected by ATProto/did:plc).
    // from_der() is a pure parser — it does NOT normalize low-S. Apple's SE may return
    // high-S signatures. normalize_s() ensures s <= order/2 as required by ATProto.
    let sig = Signature::from_der(&der_sig).map_err(|_| DeviceKeyError::InvalidSignature)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_bytes().to_vec())
}
```

**Implementation notes:**

1. **`external_representation()` on private SE key:** Returns `None` — the SE rejects export of private key material. Only the public key's `external_representation()` returns data. This verifies AC2.2 by design.

2. **`SearchResult::Ref(Reference::Key(key))`:** The `security_framework` 3.7.0 safe API wraps the OS-returned `SecKeyRef` inside a typed `Reference::Key(SecKey)`. No unsafe code is needed — the library handles the cast internally.

3. **`set_location` and `set_access_control` on iOS:** `GenerateKeyOptions::to_dictionary()` in `security_framework` 3.7.0 only propagates `kSecAttrIsPermanent` and `kSecAttrAccessControl` into the attributes dictionary under `#[cfg(target_os = "macos")]` — the private key sub-dictionary is skipped on iOS. These calls are included as defensive coding and to document intent, but they have no runtime effect on `aarch64-apple-ios` in this library version. SE keys on iOS are permanent by default through the `Token::SecureEnclave` setting, so AC2.1 is still satisfied. If a future version of `security_framework` corrects this iOS gap, these calls will take effect without code changes.

4. **`ItemSearchOptions::limit()`:** Takes a `u32` or `Limit::Max(1)` — check the installed version's API. If `limit()` takes a different type, use `Limit::Max(1)` from `security_framework::item::Limit`.

5. **`Algorithm::ECDSASignatureMessageX962SHA256`:** Available from `security_framework::key::Algorithm` with the `OSX_10_12` feature. Verify this exact variant name matches the installed version; the underlying constant is `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`.

6. **`normalize_s()` on SE signatures:** Apple's Secure Enclave may return DER signatures where `s > order/2` (high-S). `Signature::from_der` is a pure parser and does not normalize low-S. The `normalize_s()` call ensures the 64-byte r||s output always has low-S as required by the ATProto/did:plc verification protocol. For the simulator path, the `p256` crate's `sign()` trait uses RFC 6979 which inherently produces low-S, so no normalization is needed there.

**Step 3: Verify `cargo check`**

```bash
cargo check -p identity-wallet
```

Expected: compiles without errors. If `security_framework_sys` is not in scope, see note 3 above.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Verify simulator tests still pass + iOS build compiles + commit

**Verifies:** MM-145.AC2.1, MM-145.AC2.2 (build + manual); Phase 1 ACs still pass

**Files:** No changes — verification only.

**Step 1: Simulator path tests unchanged**

```bash
cargo test -p identity-wallet -- --test-threads=1 2>&1
```

Expected: All 7 Phase 1 tests still pass. The SE path changes are gated behind `#[cfg(all(target_os = "ios", not(target_env = "sim")))]` and do not affect the macOS host test run.

**Step 2: Verify iOS build compiles (SE path)**

```bash
cargo build -p identity-wallet --target aarch64-apple-ios 2>&1
```

Expected: compiles without errors. This confirms the SE path code compiles correctly for the real-device target.

If the build fails with "error[E0432]: unresolved import `security_framework_sys`": add `security-framework-sys = { version = "2" }` to `apps/identity-wallet/src-tauri/Cargo.toml` and retry.

**Step 3: Run clippy**

```bash
cargo clippy -p identity-wallet -- -D warnings
```

Expected: no warnings.

**Step 4: Manual device verification (required before Phase 3)**

On a physical iOS device:
1. Build and run the app via `cargo tauri ios dev` targeting the device
2. Call `device_key::get_or_create()` — verify it returns a `DevicePublicKey` with a valid multibase string
3. Force-kill and relaunch the app (cold restart)
4. Call `device_key::get_or_create()` again — verify it returns the **same** multibase string (AC2.1)
5. Try to export the private key via Keychain access — verify it fails (AC2.2, guaranteed by SE hardware)

**Step 5: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml \
        apps/identity-wallet/src-tauri/src/device_key.rs
git commit -m "feat(device-key): add Secure Enclave path for real iOS device (Phase 2)"
```
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_B -->
