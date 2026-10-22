# obsign-core

Last verified: 2026-10-21

## Purpose

The Obsign wallet's platform-free core ([ADR-0039](../../docs/architecture/decisions/0039-obsign-core-bound-rust-core.md)). The wallet's logic moves in from `apps/identity-wallet/src-tauri` step by step; the order is [the extraction plan](../../docs/implementation-plans/2026-10-21-obsign-core-extraction.md). Today the crate holds the five platform traits, the Keychain accessors, and the wallet's network and share-generation leaf modules. `apps/identity-wallet/src-tauri/src/lib.rs` re-exports each moved module under its old name.

## Map

| File | What it is |
|---|---|
| `src/keystore.rs` | `KeyStore` (the trait a shell implements), `install`, `WalletKeychain` (the installed store as `ios_device_key::KeychainStore`, for the device and DPoP keys), the accessors every wallet module calls (`store_item`, `get_item`, the `*_synced` family, `is_not_found`), and the Share 1 cloud-slot allowlist (`syncs_to_icloud`). The module doc owns the two-namespace and protection-class semantics |
| `src/diagnostics.rs` | redacted-by-construction network-error breadcrumbs, exported on demand from Settings, and `WalletTransportObserver`, the `custos_client` observer that records into it; capture scope and redaction rules in the module doc |
| `src/http.rs` | Re-exports `custos_client::CustosClient` for the one configured PDS (runtime URL, Keychain-persisted); owns the compile-time default base URL and `new_configured`, which wires this app's diagnostics observer — see module doc |
| `src/oauth_client.rs` | Re-exports `custos_client::OAuthClient` (DPoP and Bearer modes, lazy refresh, nonce retry, non-nonce 400s passed through intact — see that crate's module doc) plus `diagnostics_observer()`, the one seam a real `new_bearer_with_observer` call site should pass |
| `src/pds_client.rs` | Re-exports `custos_client::PdsClient` (discovery/auth/XRPC against arbitrary PDSes + plc.directory) plus this app's OAuth identity constants (canonical client_id, reverse-FQDN redirect, V042 sync) and `new_with_diagnostics`/`new_for_test`, which wire this app's diagnostics + `pds_capabilities` observers (`new_for_test` wires *real* observers unlike the crate's own — see `crates/custos-client/AGENTS.md`'s Boundaries for why). Also re-exports `PdsClientError` + the claim/app-password/migration typed XRPC types, and wraps `custos_client::{identity,app_passwords,migration}`'s methods with this app's diagnostics observer — full inventory and error reachability in the module doc |
| `src/pds_capabilities.rs` | per-host cache of `describeServer`'s `custos` extension; absence is not an error, gates ask about features never vendors; `WalletDescribeServerObserver` warms it from every `describeServer` call — cache contract in the module doc |
| `src/source_login.rs` | the one shared password `createSession` core (HTTPS + account-match + 2FA) behind the claim, migration, and password-unlock paths (ADR-0021) — see module doc |
| `src/share_ceremony.rs` | client-side 2-of-3 share generation + the three fail-closed staging slots (create / re-key / self-held kit); staging contract and load-bearing teardown order in the module doc |
| `src/device_key.rs` | the global P-256 device key: this app's Keychain and account names bound to the shared `crates/ios-device-key` implementation (software-or-Secure-Enclave by `#[cfg]`; `get_or_create` idempotent, `sign` low-S-normalized r\|\|s) — see both module docs |
| `src/identity_store.rs` | multi-identity Keychain lifecycle (`managed-dids` index + per-DID entries), per-DID device keys through the installed `Signer` (`per_did_sign_closure` is the one signing seam), the shared `SovereignTokenRecord` session record; removal semantics and the Share 1 exception in the module doc |
| `src/signer.rs` | `Signer` (each identity's device key, by DID: get-or-create public key, two-phase signing, `is_hardware_bound`), `install`, and `SoftwareSigner`, the implementation for every target without hardware-bound keys |
| `src/platform.rs` | `EventSink`, `Scheduler`, `Clock`: declared, not yet wired (see the plan for which step wires each) |

## Contracts

- **The shell installs a `KeyStore` before anything touches storage.** Uninstalled calls return `NotInstalled`, never an empty store. The wallet's `run()` installs `keychain::AppleKeychain`.
- **The shell installs a `Signer` too,** with the same fail-closed rule: production never falls back to a software key, which would mint keys the DID documents do not name. The wallet installs `EnclaveSigner` on a real device and `SoftwareSigner` elsewhere.
- **The cloud-slot allowlist is enforced here,** before any `KeyStore` is reached, so no implementation can widen what leaves the device.
- **`test-support` is for `[dev-dependencies]` only.** It selects a thread-local in-memory store when nothing is installed, and refuses to compile without `debug_assertions`.

## Boundaries

- No `tauri`, no `cfg(target_os)`, and no Apple crate (`objc2*`, `block2`, `security-framework`, `system-configuration`) in `[dependencies]`.
- Keychain account names belong to the app that stores them (the wallet's `keychain.rs` is the inventory and holds the pin test). The one exception is the Share 1 account naming, which lives here because the allowlist needs it.
