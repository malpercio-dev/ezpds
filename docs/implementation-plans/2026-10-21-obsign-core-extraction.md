# Extracting obsign-core from the wallet

Linear: MM-569 (M1 of the Wave 11 umbrella, MM-557). Decision: [ADR-0039](../architecture/decisions/0039-obsign-core-bound-rust-core.md). Design: [v2 in place](../design-plans/2026-09-06-v2-in-place.md) §4 and §6.

## Why this order

The design plan says to move the Tauri-free modules first. A survey on 2026-10-21 found that "Tauri-free" is not the same as "movable": `keychain.rs` links Security.framework, and roughly 200 call sites across nearly every module reach it as free functions. No module that touches storage can enter a crate that forbids Apple dependencies until storage sits behind a trait. So the `KeyStore` seam comes first, and module moves follow.

Each step is its own PR and must not share a release with a ceremony change (design plan §6, risks).

## Steps

| # | PR | What moves | Gate |
|---|---|---|---|
| 1 | `KeyStore` seam | Create `crates/obsign-core` with the five traits. The Keychain accessors (`store_item`, `get_item`, the `*_synced` family, `is_not_found`) and the Share 1 cloud-slot allowlist move to `obsign_core::keystore`. `keychain.rs` becomes `AppleKeychain`, the iOS `KeyStore` that `run()` installs. Every call site changes only its path. | Wallet host tests; the account-name pin test unchanged; iOS cross-compile |
| 2 | Leaf modules | `diagnostics`, `http`, `oauth_client`, `pds_capabilities`, `pds_client`, `source_login`, `share_ceremony` move into the core; the wallet re-exports each under its old name. `oauth.rs`'s two observers move to the modules they feed, and `WalletKeychain` (the `ios-device-key` adapter) moves into `keystore`. `device_key` waits for step 3 (it is the Secure Enclave path, so it belongs behind `Signer`); `notification_routes` waits for step 5. | Same, plus `just docs-generate` shows no IPC diff |
| 3 | `Signer` seam | Each identity's device key goes behind `Signer` (keyed by DID; two-phase signing keeps "no key" and "refused to sign" distinct). `SoftwareSigner` lives in the core; the Secure Enclave path becomes the wallet's `EnclaveSigner`, with its host-tested fast-path classifier. `identity_store` and `device_key` move into the core, and `identity_store` takes ownership of the three backup and kit account names it deletes on removal. The global device key still goes through `ios-device-key`, whose own `cfg` picks the enclave; folding it into `Signer` waits until a shell needs it. | Same, plus an `aarch64-apple-ios` build, the only one that compiles `EnclaveSigner` |
| 4 | `State` to `Core` | `oauth.rs`'s `AppState` becomes `Core`. Every command's body becomes a plain function taking `&Core` (and `AppHandle`, where it still needs one) ahead of its IPC arguments, with no Tauri attribute; `commands.rs` generates the 112 `#[tauri::command]` wrappers and the invoke handler from one table, so a function and its registration cannot drift. `Core` stays in `src-tauri` until the ceremony modules whose state it holds move in step 5. | Same, plus the registered command set is identical (names and order) |
| 5 | Ceremonies, `EventSink`, `BackupStore` | `plc_alert` goes through `EventSink`; the backup location and evicted-file download go behind `BackupStore` (the iCloud code becomes the wallet's `icloud.rs`), so no ceremony takes an `AppHandle`. Then the 24 remaining logic modules and `Core` move into the core. The PLC monitor's 15-minute timer stays in the shell until `Scheduler`. | Same, plus the registered command set is identical |
| 6 | Platform crate, `Scheduler` | `crates/obsign-platform-ios` takes the Keychain `KeyStore` (now parameterised by service name), the Secure Enclave `Signer`, the iCloud `BackupStore`, and an `IosScheduler` over `BGTaskScheduler`. The background-backup policy becomes the core's `backup_policy` and asks `Scheduler` for a periodic request ("unmetered only" replaces the iOS-specific Wi-Fi check); `bg_backup.rs` is gone. The APNs bridge stays in the wallet (it patches the Tauri app delegate). | Same, plus the platform crate's tests in `just ios-pr-check` and a TestFlight build installed over the previous one lists every identity and unlocks every session |

Two follow-ups stay open after step 6:

- **The PLC monitor in the background.** Adding `BackgroundJob::PlcCheck` needs a second permitted identifier in `Info.ios.plist` and changes what the app does while closed, so it ships as its own change, verified on a device.
- **`Clock`.** Declared, not wired: routing every wall-clock read through it matters first for the wasm build.

M2 (MM-573) then builds `obsign-core` for wasm in CI, which turns the no-Apple-crate rule into a check.

## A sixth trait

ADR-0039 named five traits. Step 5 needed a sixth, `BackupStore`: the user-held mirrors live wherever the platform says (the iCloud Drive container on iOS, nothing on a device with iCloud Drive off), and a cloud folder can evict a file that restore must download first. Neither fits `KeyStore` (secrets, not files) or `Scheduler`. ADR-0039's "iCloud container" consequence already put the implementation in the platform crate, and the ADR's trait table now carries the row.

## Decisions taken in step 1

- **One installed store, not a store passed to every call.** `obsign_core::keystore::install` takes a boxed `KeyStore` once at startup, and the free functions dispatch to it. That matches how the code already behaved (one process-wide Keychain), so step 1 rewrites paths, not signatures. Step 4's `Core` takes ownership of the store.
- **No store installed is an error, not an empty store.** Every call returns `NotInstalled`, which `is_not_found` rejects, so a wiring bug fails closed instead of reading as "no identities".
- **The test store is a Cargo feature.** A `cfg(test)` inside the core does not fire when a dependent's tests build it, so the thread-local in-memory store sits behind `test-support`, which the wallet enables only from `[dev-dependencies]`. A `compile_error!` refuses the feature without `debug_assertions`.
- **The cloud slot is optional.** The `*_synced` trait methods default to `NoCloudSlot`. Routing Share 1 when a platform has no cloud slot is the share-slot issue's work, not this plan's.
- **`ios-device-key`'s `KeychainStore` stays.** It is the narrow, static seam that crate and `custos-client` already use. The wallet's `WalletKeychain` adapts it onto `KeyStore`, so both reach the same installed store.
- **`custos-client` still pulls `ios-device-key`, which links security-framework on Apple targets.** Step 2 adds `custos-client` to the core's dependencies, so M2's wasm build is what proves the core itself is clean. On wasm, that `security-framework` dependency is never enabled.
