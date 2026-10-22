# obsign-platform-ios

Last verified: 2026-10-21

## Purpose

The iOS implementations of `obsign-core`'s platform traits ([ADR-0039](../../docs/architecture/decisions/0039-obsign-core-bound-rust-core.md)). The wallet's `run()` constructs and installs them. Apple-only: off Apple targets the crate compiles to nothing, so the Linux PDS gate builds the workspace without the Apple toolchain, and its tests run in the iOS PR lane (`just ios-pr-check`).

## Map

| File | What it is |
|---|---|
| `src/keychain.rs` | `AppleKeychain`, the `KeyStore`: generic-password items under the app's service name, the `kSecAttrSynchronizable` store as the cloud slot, delete-then-add for `AfterFirstUnlock` |
| `src/enclave_signer.rs` | `EnclaveSigner`, the Secure Enclave `Signer` (real device only), and `classify_se_fast_path`, the host-tested decision behind its restore-safe fast path |
| `src/icloud.rs` | `ICloudBackupStore`, the `BackupStore`: the iCloud Drive ubiquity container, no location on a device with iCloud Drive off, the shell's local folder off-device; and the evicted-placeholder download |
| `src/scheduler.rs` | `IosScheduler`, the `Scheduler` (iOS only): each job a `BGProcessingTask` under an app-supplied identifier, re-armed as it fires, "unmetered only" checked at fire time, completed exactly once |

## Contracts

- **Nothing here names an app.** The Keychain service, the `BGTaskScheduler` identifiers, and the off-device backup folder are constructor arguments. Each identifier must also be listed in the app's `Info.ios.plist` `BGTaskSchedulerPermittedIdentifiers`.
- **`IosScheduler::register` runs before app launch completes** (the wallet calls it from Tauri's `setup`). It needs a `StartJob` from the shell, which owns the async runtime and the app's `Core`.

## Boundaries

- No Tauri. The APNs bridge stays in the wallet: it patches the Tauri app delegate's class.
- `ios-device-key` and `custos-client` still link Security.framework themselves on Apple targets, for the global device key and the DPoP key.
