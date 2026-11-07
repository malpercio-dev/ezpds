# ios-device-key

Last verified: 2026-11-07

## Purpose
The operator console's per-device P-256 key — Secure Enclave on a real iOS device,
software key everywhere else — over a Keychain the calling app supplies; the key is the
device's admin credential. The identity wallet's device keys go through
`obsign_core::signer::Signer` instead (the Secure Enclave implementation is
`crates/obsign-platform-ios`), so the wallet reaches this crate only for the
`KeychainStore` seam `custos_client::DpopKeypair` stores the DPoP key through.

The module docs are the authority: `src/lib.rs` for the seam (why the Keychain is a trait
and not a `#[cfg(test)]` switch), `src/device_key.rs` for the two key paths.

## Map
| File | What it is |
|---|---|
| `src/lib.rs` | the `KeychainStore` seam, `DeviceKeyAccounts`, the IPC-shaped `DeviceKeyError`, and the `crypto` re-exports `DevicePublicKey`/`make_device_public_key` |
| `src/device_key.rs` | `get_or_create` + `sign` on both compile-time paths, and the test battery over an in-memory store |

## Contracts
- `get_or_create` is idempotent and mints a key **only** on a genuine `errSecItemNotFound`.
  Anything else — locked Keychain, permission failure — surfaces as an error, because
  minting over a transient failure orphans the device's real key with no recovery path.
- `sign` returns raw 64-byte `r||s`, low-S normalized on both paths.
- `DeviceKeyError` serializes as `{ code: "SCREAMING_SNAKE_CASE" }`; both apps' TypeScript
  `DeviceKeyError` unions mirror it, so a variant change is a wire-contract change.
- Account names live in the app, not here. The console pins its own `DeviceKeyAccounts`;
  changing a name orphans existing keys.
- `DevicePublicKey` and `make_device_public_key` are `crypto`'s, re-exported, so the two
  apps encode one point alike.

## Boundaries
- No `#[cfg(test)]` Keychain here — an app's in-memory store would not apply to a
  dependency's test build, and a Cargo feature that did would ship one into a release.
- `security-framework` is target-gated to Apple, so the crate builds and its tests run on
  the Linux PDS gate. The two `#[cfg]` paths are exact complements; the Apple targets
  resolve exactly as they did when this lived in each app.
- Adding a dependency here widens both iOS lanes' `paths:` filters — `just ios-paths-check`
  recomputes them from `cargo metadata` and fails on drift.
