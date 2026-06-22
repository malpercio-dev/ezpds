---
type: entity
category: project
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-001, sources/SRC-2026-06-22-002, sources/SRC-2026-06-22-005]
---

# Identity Wallet

A Tauri v2 iOS application — SvelteKit 2 + Svelte 5 frontend running in a native WKWebView, communicating with a Rust backend exclusively through Tauri's IPC bridge. The first frontend code in the [[concepts/ezpds-workspace|ezpds repository]].

## Purpose

Guides users through account creation, [[concepts/did-plc|DID ceremony]], handle registration, [[concepts/oauth-dpop|OAuth authentication]], PLC monitoring, and identity recovery. Keys are backed by the device [[entities/secure-enclave|Secure Enclave]].

## Architecture

- **Frontend**: SvelteKit 2 + Svelte 5, SSR disabled (fully static SPA), loaded from disk by WKWebView. IPC wrappers in `src/lib/ipc.ts`.
- **Rust backend**: Tauri IPC commands in `src-tauri/src/lib.rs`. Modules: `device_key.rs`, `oauth.rs`, `oauth_client.rs`, `keychain.rs`, `http.rs`, `identity_store.rs`, `pds_client.rs`, `plc_monitor.rs`, `recovery.rs`, `claim.rs`, `home.rs`.

## Key Flows

- **Create**: mode_select → relay_config → welcome → claim_code → email → handle → password → loading → did_ceremony → did_success → shamir_backup → handle_registration → home
- **Import**: mode_select → identity_input → pds_auth → email_verification → review_operation → claim_success → home
- **PLC Monitoring**: Background check every 15 minutes + foreground on `visibilitychange`

## Key Design Decisions

- **Device key dispatch**: `#[cfg]`-based compile-time path — software P-256 on macOS/simulator, Secure Enclave on real iOS. Same public API.
- **Per-DID Keychain namespacing**: Multi-identity support via `"{did}:suffix"` Keychain accounts. Top-level `"managed-dids"` JSON array index.
- **OAuth 2.0 + DPoP + PKCE**: PAR → Safari redirect → deep-link callback → token exchange. Transparent lazy refresh (<60s remaining).
- **Always-Ok pattern**: `load_home_data` and `log_out` never return Err — partial failures encoded as fields.
- **72-hour recovery window**: PLC unauthorized changes trigger alerts with countdown. Recovery override restores pre-unauthorized state.

## Related

- [[entities/relay|Relay Server]] — API backend
- [[entities/crypto|Crypto Crate]] — Cryptographic primitives
- [[entities/tauri|Tauri v2]] — App framework
- [[entities/sveltekit|SvelteKit 2]] — Frontend framework
- [[concepts/device-key-dispatch|Device Key Dispatch]]
- [[concepts/plc-monitoring|PLC Monitoring]]
- [[concepts/recovery-override|Recovery Override]]
- [[sources/SRC-2026-06-22-005]] — Full architecture documentation
