# MM-145 — P-256 Keypair via Secure Enclave: Phase 4

**Goal:** Expose `device_key::get_or_create()` and `device_key::sign()` as Tauri IPC commands, and add typed TypeScript wrappers in `ipc.ts`.

**Architecture:** Two new async Tauri commands (`get_or_create_device_key`, `sign_with_device_key`) are added to `lib.rs` and registered in `generate_handler![]`. `DevicePublicKey` gains `#[serde(rename_all = "camelCase")]` so `key_id` serializes to `keyId`. Typed TypeScript wrappers in `ipc.ts` convert `Vec<u8>` ↔ `Uint8Array` at the IPC boundary.

**Tech Stack:** Rust (Tauri v2 IPC), TypeScript (`@tauri-apps/api/core` invoke)

**Scope:** Phase 4 of 4 — IPC wiring only.

**Codebase verified:** 2026-03-19

**IPC binary data behavior (Tauri v2):**
- `Vec<u8>` parameters: JavaScript must pass `number[]`, NOT `Uint8Array` nested in an object — Tauri's JSON deserializer does not auto-convert `Uint8Array` inside object properties.
- `Vec<u8>` return values: JavaScript receives `number[]` from `invoke()` with standard `#[tauri::command]`.
- The TypeScript wrappers convert at the boundary: `Array.from(uint8array)` outbound, `new Uint8Array(numbers)` inbound.

---

## Acceptance Criteria Coverage

### MM-145.AC4: DeviceKeyError and Tauri commands follow project conventions
- **MM-145.AC4.1 Success:** all `DeviceKeyError` variants serialize as `{ "code": "SCREAMING_SNAKE_CASE" }` (tested in Phase 1; verified again by Phase 4 serialization test for `DevicePublicKey`)
- **MM-145.AC4.2 Success:** frontend `ipc.ts` can call `getOrCreateDeviceKey()` and `signWithDeviceKey()` and receive correct TypeScript types (manual verification on simulator)

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Write failing serialization test for `DevicePublicKey` camelCase

**Verifies:** MM-145.AC4.1 (partially — ensures DevicePublicKey serializes correctly for Tauri IPC)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/device_key.rs` (add one test to the existing `#[cfg(test)] mod tests` block)

**Why this task first:** `DevicePublicKey` currently has no `#[serde(rename_all = "camelCase")]` attribute. Without it, `key_id` serializes as `"key_id"` in JSON — the TypeScript side would receive `key_id` not `keyId`, breaking the TypeScript type definition. The test exposes this gap before we fix it.

**Step 1: Add a failing test to the `#[cfg(test)] mod tests` block in `device_key.rs`**

Find the closing `}` of the `mod tests` block (after the `device_key_error_serializes_as_code` test) and insert before it:

```rust
    // Ensures DevicePublicKey serializes key_id as keyId (camelCase) for Tauri IPC.
    // Without #[serde(rename_all = "camelCase")], this test fails.
    #[test]
    fn device_public_key_serializes_camel_case() {
        let key = DevicePublicKey {
            multibase: "zTest".into(),
            key_id: "did:key:zTest".into(),
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["multibase"], "zTest");
        assert_eq!(json["keyId"], "did:key:zTest", "key_id must serialize as keyId for TypeScript");
        // Confirm the snake_case version is NOT present.
        assert!(json.get("key_id").is_none(), "key_id must not appear as snake_case in JSON");
    }
```

**Step 2: Run the test — verify it FAILS**

```bash
cargo test -p identity-wallet -- device_public_key_serializes_camel_case --test-threads=1 2>&1
```

Expected: test fails because `DevicePublicKey` does not yet have `#[serde(rename_all = "camelCase")]`.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add `#[serde(rename_all = "camelCase")]` to `DevicePublicKey` and add Tauri commands to `lib.rs`

**Verifies:** MM-145.AC4.1, MM-145.AC4.2

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/device_key.rs` (add serde attribute to `DevicePublicKey`)
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (add two Tauri commands, update `generate_handler![]`)

**Step 1: Add `#[serde(rename_all = "camelCase")]` to `DevicePublicKey` in `device_key.rs`**

Find:
```rust
#[derive(Debug, Serialize)]
pub struct DevicePublicKey {
```

Replace with:
```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePublicKey {
```

**Step 2: Verify the previously failing test now passes**

```bash
cargo test -p identity-wallet -- device_public_key_serializes_camel_case --test-threads=1 2>&1
```

Expected: passes. `keyId` appears in JSON; `key_id` does not.

**Step 3: Add two new Tauri commands to `lib.rs`**

Add the following two functions anywhere in `lib.rs` after the existing `create_account` function (before the `pub fn run()` function). These are thin wrappers — all logic lives in `device_key`:

```rust
#[tauri::command]
async fn get_or_create_device_key() -> Result<device_key::DevicePublicKey, device_key::DeviceKeyError> {
    device_key::get_or_create()
}

#[tauri::command]
async fn sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, device_key::DeviceKeyError> {
    device_key::sign(&data)
}
```

**Step 4: Register the new commands in `generate_handler![]` (line 193)**

Find:
```rust
.invoke_handler(tauri::generate_handler![create_account])
```

Replace with:
```rust
.invoke_handler(tauri::generate_handler![
    create_account,
    get_or_create_device_key,
    sign_with_device_key,
])
```

**Step 5: Verify `cargo check`**

```bash
cargo check -p identity-wallet
```

Expected: compiles without errors or warnings.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Add TypeScript wrappers to `ipc.ts`

**Verifies:** MM-145.AC4.2

**Files:**
- Modify: `apps/identity-wallet/src/lib/ipc.ts` (append after the `createAccount` export)

**Step 1: Append to `apps/identity-wallet/src/lib/ipc.ts`**

Phases 1–3 do not touch `ipc.ts`, so line 47 is stable and is the insertion point. After line 47 (the end of the `createAccount` export), append:

```typescript
// ── Device Key types ──────────────────────────────────────────────────────────

/**
 * Device public key returned by the `get_or_create_device_key` Rust command.
 * Matches DevicePublicKey struct with #[serde(rename_all = "camelCase")].
 */
export type DevicePublicKey = {
  /** 'z' + base58btc(33-byte compressed P-256 public key point). */
  multibase: string;
  /** Full did:key URI: 'did:key:z...' */
  keyId: string;
};

/**
 * Error returned by device key commands.
 *
 * Serialized as `{ code: "KEY_GENERATION_FAILED" }` etc. by the Rust backend.
 * `message` is present only for KEYCHAIN_ERROR.
 */
export type DeviceKeyError = {
  code:
    | 'KEY_GENERATION_FAILED'
    | 'KEY_NOT_FOUND'
    | 'SIGNING_FAILED'
    | 'INVALID_SIGNATURE'
    | 'KEYCHAIN_ERROR';
  message?: string;
};

// ── get_or_create_device_key ─────────────────────────────────────────────────

/**
 * Get or create the device's SE-backed (or simulator-fallback) P-256 keypair.
 *
 * Idempotent — returns the same key on every call for a given device.
 * On failure, the Promise rejects with a `DeviceKeyError`.
 */
export const getOrCreateDeviceKey = (): Promise<DevicePublicKey> =>
  invoke('get_or_create_device_key');

// ── sign_with_device_key ─────────────────────────────────────────────────────

/**
 * Sign arbitrary bytes using the device's SE-backed (or simulator-fallback) P-256 key.
 *
 * Returns the raw 64-byte ECDSA r||s signature as a Uint8Array.
 *
 * IMPORTANT: `data` is converted to `number[]` before passing to Tauri's IPC
 * because Tauri v2's JSON deserializer cannot accept a `Uint8Array` nested inside
 * an object property — it must be a plain number array. See tauri#10336.
 *
 * On failure, the Promise rejects with a `DeviceKeyError` (code: KEY_NOT_FOUND
 * if `getOrCreateDeviceKey` has never been called for this device).
 */
export const signWithDeviceKey = (data: Uint8Array): Promise<Uint8Array> =>
  (invoke('sign_with_device_key', { data: Array.from(data) }) as Promise<number[]>).then(
    (bytes) => new Uint8Array(bytes),
  );
```

**Step 2: Verify the TypeScript file is syntactically valid**

```bash
cd apps/identity-wallet && pnpm tsc --noEmit 2>&1 | head -20
```

Expected: no TypeScript errors. If `pnpm` is not available, use `npx tsc --noEmit`.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Run full test suite, verify build, and commit

**Verifies:** All Phase 1 ACs + MM-145.AC4.1 + MM-145.AC4.2

**Files:** No changes — verification only.

**Step 1: Run all Rust tests**

```bash
cargo test -p identity-wallet -- --test-threads=1 2>&1
```

Expected: all tests pass, including the new `device_public_key_serializes_camel_case` test (8 device_key tests total now, plus existing lib.rs tests).

**Step 2: Run clippy**

```bash
cargo clippy -p identity-wallet -- -D warnings
```

Expected: no warnings.

**Step 3: Verify iOS build compiles**

```bash
cargo build -p identity-wallet --target aarch64-apple-ios 2>&1
```

Expected: compiles without errors.

**Step 4: Manual simulator verification (AC4.2)**

On the iOS Simulator (via `cargo tauri ios dev`):
1. Call `getOrCreateDeviceKey()` from a Svelte component — verify it resolves with `{ multibase: 'z...', keyId: 'did:key:z...' }`
2. Call `signWithDeviceKey(new Uint8Array([1,2,3]))` — verify it resolves with a `Uint8Array` of length 64
3. Call `signWithDeviceKey` before `getOrCreateDeviceKey` is ever called (fresh install) — verify it rejects with `{ code: 'KEY_NOT_FOUND' }`

**Step 5: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/device_key.rs \
        apps/identity-wallet/src-tauri/src/lib.rs \
        apps/identity-wallet/src/lib/ipc.ts
git commit -m "feat(ipc): expose get_or_create_device_key and sign_with_device_key Tauri commands"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->
