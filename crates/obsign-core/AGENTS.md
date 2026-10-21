# obsign-core

Last verified: 2026-10-21

## Purpose

The Obsign wallet's platform-free core ([ADR-0039](../../docs/architecture/decisions/0039-obsign-core-bound-rust-core.md)). The wallet's logic moves in from `apps/identity-wallet/src-tauri` step by step; the order is [the extraction plan](../../docs/implementation-plans/2026-10-21-obsign-core-extraction.md). Today the crate holds the five platform traits and the Keychain accessors.

## Map

| File | What it is |
|---|---|
| `src/keystore.rs` | `KeyStore` (the trait a shell implements), `install`, the accessors every wallet module calls (`store_item`, `get_item`, the `*_synced` family, `is_not_found`), and the Share 1 cloud-slot allowlist (`syncs_to_icloud`). The module doc owns the two-namespace and protection-class semantics |
| `src/platform.rs` | `Signer`, `EventSink`, `Scheduler`, `Clock`: declared, not yet wired (see the plan for which step wires each) |

## Contracts

- **The shell installs a `KeyStore` before anything touches storage.** Uninstalled calls return `NotInstalled`, never an empty store. The wallet's `run()` installs `keychain::AppleKeychain`.
- **The cloud-slot allowlist is enforced here,** before any `KeyStore` is reached, so no implementation can widen what leaves the device.
- **`test-support` is for `[dev-dependencies]` only.** It selects a thread-local in-memory store when nothing is installed, and refuses to compile without `debug_assertions`.

## Boundaries

- No `tauri`, no `cfg(target_os)`, and no Apple crate (`objc2*`, `block2`, `security-framework`, `system-configuration`) in `[dependencies]`.
- Keychain account names belong to the app that stores them (the wallet's `keychain.rs` is the inventory and holds the pin test). The one exception is the Share 1 account naming, which lives here because the allowlist needs it.
