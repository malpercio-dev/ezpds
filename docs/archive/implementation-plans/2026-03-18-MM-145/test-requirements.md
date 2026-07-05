# MM-145 Test Requirements

## Automated Tests

| AC | Test Name | Type | File |
|----|-----------|------|------|
| MM-145.AC1.1 | `get_or_create_returns_valid_multibase` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC1.2 | `get_or_create_is_idempotent` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC1.3 | `key_id_has_did_key_prefix` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC3.1 | `sign_returns_64_bytes` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC3.2 | `sign_is_deterministic` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC3.3 | `sign_before_generate_returns_key_not_found` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC4.1 | `device_key_error_serializes_as_code` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC4.1 | `device_public_key_serializes_camel_case` | unit | `apps/identity-wallet/src-tauri/src/device_key.rs` |
| MM-145.AC5.1 | `create_account_uses_device_key_public_key` | unit | `apps/identity-wallet/src-tauri/src/lib.rs` |

## Human Verification

| AC | What to Verify | How |
|----|---------------|-----|
| MM-145.AC1.4 | Key persists across app restarts (real Keychain round-trip) | Implicitly covered by `get_or_create_is_idempotent` on the simulator/macOS path (stateless function always reads from Keychain). Cross-process persistence on a real device is verified manually via AC2.1 below. |
| MM-145.AC2.1 | Key retrieved after cold restart matches key from initial generation (SE tag persistence) | On a physical iOS device: (1) build and run the app via `cargo tauri ios dev`; (2) call `device_key::get_or_create()` and record the returned multibase string; (3) force-kill and relaunch the app (cold restart); (4) call `device_key::get_or_create()` again and verify the multibase string is identical. |
| MM-145.AC2.2 | Private key bytes cannot be extracted from the Keychain (SE non-extractable guarantee) | On a physical iOS device: (1) `SecKey::new` with `Token::SecureEnclave` creates a non-extractable key by hardware design; (2) verify that calling `external_representation()` on the SE private key returns `None` (the SE rejects export). This is a design-level guarantee of Apple's Secure Enclave hardware and cannot be tested in the simulator or via `cargo test`. |
| MM-145.AC4.2 | Frontend `ipc.ts` can call `getOrCreateDeviceKey()` and `signWithDeviceKey()` and receive correct TypeScript types | On the iOS Simulator via `cargo tauri ios dev`: (1) call `getOrCreateDeviceKey()` from a Svelte component and verify it resolves with `{ multibase: 'z...', keyId: 'did:key:z...' }`; (2) call `signWithDeviceKey(new Uint8Array([1,2,3]))` and verify it resolves with a `Uint8Array` of length 64; (3) call `signWithDeviceKey` before `getOrCreateDeviceKey` is ever called (fresh install) and verify it rejects with `{ code: 'KEY_NOT_FOUND' }`. |

## Notes

- **Test isolation:** All unit tests share the macOS Keychain entry `"device-rotation-key-priv"` under service `"ezpds-identity-wallet"`. The `sign_before_generate_returns_key_not_found` test deletes this entry to simulate a fresh state. Tests must run single-threaded to prevent Keychain races.
- **Run command:** `cargo test -p identity-wallet -- --test-threads=1`
- **Platform requirements:** Automated tests run on macOS host via `cargo test`. The simulator/macOS software path is selected at compile time by `#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]`. The Secure Enclave path (`#[cfg(all(target_os = "ios", not(target_env = "sim")))]`) compiles only for `aarch64-apple-ios` and requires a physical iOS device for manual verification.
- **Phase ordering:** Tests are introduced incrementally across phases. Phase 1 adds 7 tests in `device_key.rs`. Phase 3 adds 1 test in `lib.rs`. Phase 4 adds 1 test in `device_key.rs`. Total: 9 automated tests.
- **No mock server:** `create_account` makes a real HTTP call to the relay, so AC5.1 is tested indirectly by verifying the `device_key::get_or_create()` contract (correct format, idempotent) rather than calling `create_account` directly. Compile-time verification ensures the wiring is correct (`cargo check` catches type mismatches).
