# MM-145 — P-256 Keypair via Secure Enclave: Phase 3

**Goal:** Replace the `crypto::generate_p256_keypair()` call in `create_account` with `device_key::get_or_create()` so the relay receives the SE-backed (or simulator-fallback) public key.

**Architecture:** `lib.rs`'s `create_account` function currently generates a software P-256 keypair, stores the private bytes in the Keychain, and sends the public key to the relay. After this phase: `create_account` calls `device_key::get_or_create()`, uses `DevicePublicKey.multibase` as `device_public_key`, and removes the explicit private-key Keychain store step (which `device_key` handles internally). Cleanup code that deleted `"device-private-key"` on error is also removed.

**Tech Stack:** Pure Rust refactoring — no new dependencies.

**Scope:** Phase 3 of 4 — wiring only.

**Codebase verified:** 2026-03-19

---

## Acceptance Criteria Coverage

### MM-145.AC5: create_account uses the device key
- **MM-145.AC5.1 Success:** `create_account` sends `DevicePublicKey.multibase` as the `device_public_key` field in the relay request (not a freshly-generated software keypair)

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Write failing test for AC5.1

**Verifies:** MM-145.AC5.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (append to the existing `#[cfg(test)] mod tests` block, around line 198)

**Why this test:** `create_account` makes a real HTTP call to the relay, so we can't integration-test it without a live server. Instead, we test the device key contract that `create_account` depends on: that `device_key::get_or_create()` is the source of the public key, and that it's stable across calls (so `create_account` will always send the same key for a given device).

**Step 1: Add test to the existing `#[cfg(test)] mod tests` block in `lib.rs`**

Find the closing `}` of the existing `mod tests` block (around line 326) and insert before it:

```rust
    // AC5.1 — create_account will use this key as device_public_key.
    // We verify: (a) the key exists and is correctly formatted, (b) it's stable so
    // create_account always sends the same device_public_key for this device.
    #[test]
    fn create_account_uses_device_key_public_key() {
        let key = crate::device_key::get_or_create()
            .expect("device_key::get_or_create must succeed — create_account depends on it");
        // The relay expects multibase: 'z' + base58btc(33-byte compressed P-256 point).
        assert!(
            key.multibase.starts_with('z'),
            "device_public_key sent to relay must be multibase base58btc ('z' prefix), got: {}",
            key.multibase
        );
        // Calling again returns the same key — create_account sends consistent device_public_key.
        let key2 = crate::device_key::get_or_create()
            .expect("second call must also succeed");
        assert_eq!(
            key.multibase,
            key2.multibase,
            "device_public_key must be stable across calls (idempotent)"
        );
    }
```

**Step 2: Run the test — verify it passes (the test doesn't depend on the wiring change)**

```bash
cargo test -p identity-wallet -- create_account_uses_device_key_public_key --test-threads=1 2>&1
```

Expected: test passes. The test validates the `device_key` contract that `create_account` relies on — it doesn't call `create_account` itself (which requires a live relay).

**Why this test doesn't call `create_account` directly:** `create_account` makes a real HTTP call to the relay (no mock server in this codebase). Testing the full wiring would require a running relay instance, which is out of scope for unit tests. Instead, this test guards the API contract: it verifies that `device_key::get_or_create()` succeeds and is idempotent (the same values `create_account` will use). If Phase 3's wiring is incorrect at compile time, `cargo check` catches it; at runtime, the manual test in AC5.1 verifies the full flow against a live relay.

Note: this test passes even before Task 2 because it only tests `device_key::get_or_create()`, not the wiring in `create_account`. It acts as a regression guard — if device key generation breaks, this test will fail, which means `create_account` would also be broken.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Update `create_account` to use `device_key::get_or_create()`

**Verifies:** MM-145.AC5.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

All line numbers reference the current state of the file (before this task's changes).

**Step 1: Update the import at line 4**

Find line 4:
```rust
use crypto::generate_p256_keypair;
```

Replace with (remove the crypto import; `device_key` is already accessible as `pub mod device_key` declared at line 3):
```rust
// (removed — device_key::get_or_create() replaces crypto::generate_p256_keypair)
```

Actually: just delete line 4 entirely. No replacement import is needed because `device_key` is already declared as a module in this file (`pub mod device_key;` at line 3) and is accessed as `device_key::get_or_create()`.

**Step 2: Replace the keypair generation (lines 116–118)**

Find:
```rust
    // 1. Generate P-256 device keypair.
    let keypair = generate_p256_keypair().map_err(|e| CreateAccountError::Unknown {
        message: e.to_string(),
    })?;
```

Replace with:
```rust
    // 1. Get or create the device's SE-backed (or simulator-fallback) P-256 key.
    let device_key = device_key::get_or_create().map_err(|e| CreateAccountError::Unknown {
        message: e.to_string(),
    })?;
```

**Step 3: Remove the private key Keychain store step (lines 120–123)**

Find and delete:
```rust
    // 2. Store private key bytes in Keychain before any network call.
    //    private_key_bytes is Zeroizing<[u8; 32]>; deref to &[u8] via AsRef.
    keychain::store_item("device-private-key", keypair.private_key_bytes.as_ref())
        .map_err(|_| CreateAccountError::KeychainError)?;
```

This entire block is deleted. `device_key::get_or_create()` handles its own Keychain storage internally.

**Step 4: Update `device_public_key` in the request (line 129)**

Find:
```rust
        device_public_key: keypair.public_key,
```

Replace with:
```rust
        device_public_key: device_key.multibase,
```

**Step 5: Remove cleanup calls for `"device-private-key"` (lines 155 and 162–163)**

In the error-handling blocks after the token Keychain stores, find and remove (two occurrences):
```rust
            let _ = keychain::delete_item("device-private-key");
```

These lines were cleanup for the private key that `device_key` now manages. The SE-backed device key is intentionally persistent — it should NOT be deleted on account creation failure.

After Steps 5, 5b, and 5c, the cleanup blocks look like:
```rust
        keychain::store_item("device-token", body.device_token.as_bytes()).map_err(|_| {
            // device-token write failed — nothing to clean up; the device key is persistent by design.
            CreateAccountError::KeychainError
        })?;

        keychain::store_item("session-token", body.session_token.as_bytes()).map_err(|_| {
            // Best-effort cleanup: remove the already-written device-token.
            let _ = keychain::delete_item("device-token");
            CreateAccountError::KeychainError
        })?;
```

**Step 5b: Update the comment on the session-token error handler**

The original comment ("Best-effort cleanup: also remove the already-written device-token and device-private-key.") references the private key cleanup that was just removed. Update it to reflect only what the block now does:

Find (in the session-token `map_err` closure):
```rust
            // Best-effort cleanup: also remove the already-written device-token and device-private-key.
```

Replace with:
```rust
            // Best-effort cleanup: remove the already-written device-token.
```

If the original comment does not mention "device-private-key" (exact wording depends on the current file), update it so it only references `device-token`. The intent is: on session-token write failure, we undo the already-written device-token, but we do NOT touch the device key (it is persistent by design).

**Step 5c: Update the comment on the device-token error handler**

After removing the `let _ = keychain::delete_item("device-private-key")` from the device-token closure, that block contains no deletion — the old comment "ignore deletion errors" is stale. Update it:

Find (in the device-token `map_err` closure):
```rust
            // Best-effort cleanup: ignore deletion errors.
```

Replace with:
```rust
            // device-token write failed — nothing to clean up; the device key is persistent by design.
```

**Step 6: Verify `cargo check`**

```bash
cargo check -p identity-wallet
```

Expected: compiles without errors. If the compiler warns about unused `crypto` import or unused variables, address them.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Verify all tests pass and commit

**Verifies:** All Phase 1 ACs + MM-145.AC5.1

**Files:** No changes — verification only.

**Step 1: Run full test suite**

```bash
cargo test -p identity-wallet -- --test-threads=1 2>&1
```

Expected: all tests pass, including the new `create_account_uses_device_key_public_key` test and all 7 Phase 1 tests.

**Step 2: Run clippy**

```bash
cargo clippy -p identity-wallet -- -D warnings
```

Expected: no warnings. Specifically, the removed `use crypto::generate_p256_keypair;` import should not produce an "unused import" warning (it was deleted).

**Step 3: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/lib.rs
git commit -m "feat(create-account): use device_key::get_or_create() for device public key"
```
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
