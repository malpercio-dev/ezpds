# ADR-0039: The wallet's Rust is a platform-free core bound into shells

- **Status:** Accepted
- **Date:** 2026-10-20
- **Deciders:** mal
- **Related:** [ADR-0013](0013-native-swiftui-shell-over-rust-core.md) (the native shell, split out of the same record and still Deferred) · [ADR-0005](0005-functional-core-imperative-shell.md) · [ADR-0030](0030-stable-keychain-group-and-frozen-icloud-container.md) · [`docs/design-plans/2026-09-06-v2-in-place.md`](../../design-plans/2026-09-06-v2-in-place.md) §4 · [`crates/ios-device-key`](../../../crates/ios-device-key) · [`crates/obsign-platform-ios/src/scheduler.rs`](../../../crates/obsign-platform-ios/src/scheduler.rs)

## Context

ADR-0013 held two decisions in one record. The first: the wallet's Rust (did:plc
genesis, rotation and recovery, P-256 and the Secure Enclave, DAG-CBOR, Shamir) is
the asset, and no shell may reimplement it. The second: a native SwiftUI shell
waits on a trigger. Only the second is deferred. The first already governs every
change to the wallet, and it deserves a record that says Accepted.

Most of the wallet's Rust is already a library. Its Tauri coupling sits in
command wrappers, `tauri::State` injection, and `AppHandle` events; none of it is
in the logic (design plan §4.1). `ios-device-key`'s `KeychainStore` is already a
platform trait. What has been missing is a rule saying where the core ends, so
new code keeps landing behind `cfg(target_os = "ios")` inside the logic itself.

Android requests have arrived. A core designed only for iOS would bake iCloud
Keychain, `BGTaskScheduler`, and APNs into its signatures, and the Android port
would then have to unpick them.

## Decision

The wallet's Rust becomes **`obsign-core`**: a platform-free crate that every
shell binds to. The Tauri app is its first shell. A native shell, if ADR-0013's
trigger fires, binds the same crate through **UniFFI** (proc-macro mode; a Swift
package for iOS, an AAR for Android).

The core reaches the platform only through five traits:

| Trait | Covers | iOS today | Android |
| --- | --- | --- | --- |
| `KeyStore` | Keychain-class storage, including the synchronizable share-1 slot, which is **optional** | Keychain + iCloud Keychain | Keystore-backed storage; no cloud slot |
| `Signer` | Device-key P-256 signing; reports whether the key is hardware-bound | Secure Enclave | Android Keystore / StrongBox |
| `EventSink` | Events from core to UI | Tauri `emit` | the shell's own observer |
| `Scheduler` | "Run this background job"; the core never knows how | `BGTaskScheduler` | WorkManager |
| `Clock` | Wall time, so ceremonies and the PLC window are testable | system clock | system clock |

The rule: **`obsign-core` has no `cfg(target_os)` and no Apple crate (`objc2*`,
`block2`, `security-framework`, `system-configuration`) in its dependency list.**
Platform code lives in a platform crate (`obsign-platform-ios` is the only one
that links Security.framework) or in the shell.

**No shell reimplements anything in `crypto` or the core.** Swift and Kotlin
handle UI, biometric prompts, and the OS callbacks the traits wrap. This rule
carries over from ADR-0013 unchanged.

## Consequences

- The no-`cfg` rule can be checked. A wasm build of `obsign-core` in CI proves it
  and keeps it proved, and the same build can back the browser harness in place
  of its hand-written fake.
- Background work moves onto `Scheduler`. `plc_monitor`'s foreground loop can run
  on the `BGTaskScheduler` bridge `bg_backup.rs` already drives from Rust,
  without leaving Tauri.
- The optional cloud slot is the one real design change Android forces. The
  share ceremony must handle "no cloud slot" by routing share 1 to the user or a
  second escrow.
- The frozen device contracts (ADR-0030: bundle ids, access group, iCloud
  container, Keychain account names) bind the `KeyStore` impl. Moving code into
  the core must not rename a Keychain account.
- The Brass Console is out of scope. It authenticates with ADR-0018 envelopes,
  shares only `ios-device-key` with the wallet, and stays on Tauri.
- Costs: the extraction is mechanical but wide (every command becomes a one-line
  delegate to a `Core` method). UniFFI bindings and a Swift package are later
  work and are not built until a shell needs them.

## Alternatives considered

- **Keep the core implicit inside `src-tauri`.** Rejected: no boundary means
  platform code keeps leaking into the logic, and an Android port would find
  out the hard way.
- **Design the traits for iOS only and generalise later.** Rejected: iCloud
  Keychain and `BGTaskScheduler` would show up in core signatures, and removing
  them later means editing every ceremony that uses them.
- **swift-bridge.** Better Swift ergonomics, but no Android path.
- **flutter_rust_bridge.** Only fits if a shell becomes Flutter, whose UI
  fidelity suits neither app's brief.
- **Hand-written FFI over cbindgen.** Every type marshalled by hand.
