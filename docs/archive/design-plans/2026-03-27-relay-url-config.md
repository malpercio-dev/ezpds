# Relay URL Configuration Design

## Summary

The relay URL configuration feature makes the identity wallet's backend relay address configurable at runtime instead of hardcoding it at compile time. On first launch, users see a new configuration screen pre-filled with the production relay URL (`https://relay.ezpds.com`); they can accept it or supply a custom URL for development or self-hosted deployments. Before saving, the app pings the relay's `/xrpc/_health` endpoint to confirm it is reachable, surfacing inline errors if the URL is malformed or the host is unreachable. Once saved, the URL is written to the iOS Keychain so it survives app restarts and the configuration screen is never shown again.

On the Rust side, `RelayClient` is refactored from a compile-time static singleton into a runtime-initialized instance held in `AppState` behind a `OnceLock`. During startup, the app reads the saved URL from Keychain and populates the lock; if no URL is saved yet, the compile-time default serves as a fallback until the user completes first-time configuration. Three new Tauri IPC commands (`get_relay_url`, `check_relay_health`, `save_relay_url`) bridge the frontend configuration screen to the Rust backend. The implementation is structured in four sequential phases — refactoring `RelayClient`, migrating `AppState`, adding IPC commands, then adding the frontend screen — so each phase can be built and verified independently.

## Definition of Done

- Users can configure the relay URL before beginning onboarding
- The app ships with a default production relay URL pre-filled
- The configured URL is persisted across app restarts
- The app verifies the relay is reachable before accepting the URL
- Returning users (URL already saved) skip the configuration screen entirely

## Acceptance Criteria

### relay-url-config.AC1: Relay config screen shown on first launch
- **relay-url-config.AC1.1 Success:** On first launch (no saved relay URL), the relay config screen appears before the welcome screen
- **relay-url-config.AC1.2 Success:** User can accept the pre-filled default URL and proceed to welcome
- **relay-url-config.AC1.3 Success:** User can enter a custom URL and proceed if the relay is healthy
- **relay-url-config.AC1.4 Failure:** User cannot advance past the config screen without a valid, reachable URL

### relay-url-config.AC2: Default URL pre-filled
- **relay-url-config.AC2.1 Success:** URL input is pre-filled with `https://relay.ezpds.com` on first launch

### relay-url-config.AC3: URL persists across restarts
- **relay-url-config.AC3.1 Success:** After saving a URL and relaunching the app, the relay config screen is not shown
- **relay-url-config.AC3.2 Success:** All relay IPC commands on subsequent launches use the saved URL

### relay-url-config.AC4: Relay reachability verified before saving
- **relay-url-config.AC4.1 Success:** A URL whose `/xrpc/_health` returns HTTP 200 is accepted
- **relay-url-config.AC4.2 Failure:** An unreachable host surfaces an `UNREACHABLE` inline error
- **relay-url-config.AC4.3 Failure:** A malformed URL (not `http`/`https`, empty host) surfaces an `INVALID_URL` error before any network call
- **relay-url-config.AC4.4 Edge:** A URL with a trailing slash is accepted and normalized (slash stripped) before saving

### relay-url-config.AC5: Returning users skip config screen
- **relay-url-config.AC5.1 Success:** When a relay URL is already in Keychain on launch, the app starts at the welcome step (or home if authenticated)
- **relay-url-config.AC5.2 Edge:** The saved URL is used for relay calls on the same launch it was saved (no restart required)

### relay-url-config.AC6: Error and loading states
- **relay-url-config.AC6.1 Success:** A loading/spinner state is shown while the health check is in flight
- **relay-url-config.AC6.2 Failure:** `INVALID_URL` error is shown inline on the config screen (user stays on screen)
- **relay-url-config.AC6.3 Failure:** `UNREACHABLE` error is shown inline on the config screen (user stays on screen)

## Glossary

- **Relay**: The `ezpds` backend service (`crates/relay/`) that the identity wallet communicates with. Acts as a server-side intermediary for ATProto operations such as account creation and DID management.
- **IPC command**: A named function exposed by the Tauri Rust backend and callable from the SvelteKit frontend via `window.__TAURI__.invoke()`. All IPC calls in this project are wrapped in typed functions in `src/lib/ipc.ts`.
- **AppState**: A Rust struct shared across all Tauri IPC command handlers via Tauri's managed state mechanism. Acts as the single source of runtime state (relay client, OAuth session, pending auth).
- **`OnceLock`**: A Rust standard-library type that holds a value that can be written exactly once and then read many times concurrently. Used here so `RelayClient` can be initialized from either Keychain at startup or from the `save_relay_url` command, whichever happens first.
- **`RelayClient`**: The Rust struct in `http.rs` that wraps all outbound HTTP calls from the wallet to the relay, scoped to a single base URL.
- **Keychain**: iOS's system-provided secure credential store. This project uses it (via `keychain.rs`) to persist all non-sensitive app configuration and credentials across restarts, including the relay URL.
- **`/xrpc/_health`**: A conventional health-check endpoint on ATProto services. Returns HTTP 200 when the service is running and reachable. Used here to validate a candidate relay URL before saving it.
- **`OnceLock::set()` idempotency**: `OnceLock::set()` silently discards a second write rather than panicking or overwriting. The design relies on this behavior to safely ignore any redundant initialization call.
- **Onboarding step / step renderer**: The pattern in `+page.svelte` where the current screen is tracked as a string variable (`step`) and a conditional block renders the matching Svelte component. Each onboarding screen is a component in `src/lib/components/onboarding/`.
- **ATProto (AT Protocol)**: The open federated social protocol developed by Bluesky. This project implements a personal data server (PDS) and identity wallet on top of it.
- **Tauri**: A Rust-based framework for building desktop and mobile apps with a web frontend. Provides the bridge between the SvelteKit UI and the Rust backend, including the IPC mechanism.
- **SvelteKit**: The fullstack web framework used for the wallet's frontend. Runs inside Tauri's webview.
- **Compile-time constant / static singleton**: A value baked into the binary at build time. The existing `RELAY_CLIENT` global is such a constant; this design replaces it with a runtime-configurable instance.

---

## Architecture

One-time relay URL configuration screen inserted before the existing onboarding flow. On first launch the user sees a URL input pre-filled with the production relay URL; they can accept it or enter their own. The app pings the relay's health endpoint before saving. On every subsequent launch the saved URL is loaded from Keychain and the screen is skipped.

The relay URL threads through the Rust backend via `AppState`. `RelayClient` changes from a compile-time static singleton to an instance initialized at runtime with the configured URL. `AppState` gains a `relay_client: OnceLock<RelayClient>` field — set from Keychain during app startup for returning users, or set by the `save_relay_url` IPC command on first launch.

**Frontend flow:**

```
On mount:
  getRelayUrl() → null    →  show relay_config step
  getRelayUrl() → string  →  skip to welcome step

relay_config step:
  user edits URL (pre-filled with "https://relay.ezpds.com")
  user taps Connect
    → checkRelayHealth(url)   [shows spinner]
    → on failure: inline error, stay on screen
    → on success: saveRelayUrl(url) → advance to welcome
```

**Rust initialization path:**

```
run() setup:
  keychain::get_item("relay-base-url")
    → Some(url): state.set_relay_client(url)
    → None:      relay_client stays unset (get_or_init uses compile-time default as fallback)

save_relay_url command:
  validate URL format
  ping GET /xrpc/_health
  keychain::store_item("relay-base-url", url)
  state.set_relay_client(url)
```

## Existing Patterns

Investigation found the following patterns this design follows:

- **Keychain for persistence** — all persistent non-sensitive config in this app lives in the iOS Keychain under `keychain::SERVICE = "ezpds-identity-wallet"`. The relay URL follows this pattern, stored under a new `"relay-base-url"` account key. New keys are added as string constants in `keychain.rs`.
- **AppState for shared runtime state** — `oauth::AppState` is the existing mechanism for sharing mutable runtime state across Tauri commands (pending auth, OAuth session). Adding `relay_client: OnceLock<RelayClient>` to this struct follows the established pattern.
- **Typed IPC error codes** — all IPC commands return errors as `{ code: "SCREAMING_SNAKE_CASE" }`. The new `check_relay_health` and `save_relay_url` commands follow this convention.
- **`ipc.ts` as the IPC boundary** — frontend never calls `invoke()` directly; all commands are wrapped in typed functions in `src/lib/ipc.ts`. New commands get wrappers there.
- **Onboarding screen component pattern** — each step in `+page.svelte` corresponds to a component in `src/lib/components/onboarding/` that receives `onnext` / `onerror` callbacks and manages its own loading state.
- **Health endpoint reuse** — `GET /xrpc/_health` is already used in `home.rs` to check relay reachability. The new `check_relay_health` command makes the same call against a caller-supplied URL.

This design diverges from one existing decision: the AGENTS.md documents "Compile-time relay URL" as an intentional choice. This design supersedes that decision — the compile-time constant becomes the default fallback only, with runtime configuration taking precedence.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: RelayClient runtime URL support

**Goal:** Make `RelayClient` accept a runtime URL instead of the compile-time constant.

**Components:**
- `apps/identity-wallet/src-tauri/src/http.rs` — change `base_url: &'static str` to `base_url: String`; add `RelayClient::new_with_url(url: String) -> Self`; change `base_url()` from a `const fn` static method to an instance method `fn base_url(&self) -> &str`; keep `RelayClient::new()` using the compile-time default

**Dependencies:** None

**Done when:** `cargo build` succeeds with the updated `RelayClient`; all existing `http.rs` unit tests pass
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: AppState integration and command migration

**Goal:** Remove the `RELAY_CLIENT` global static and route all relay access through `AppState`.

**Components:**
- `apps/identity-wallet/src-tauri/src/oauth.rs` — add `relay_client: OnceLock<http::RelayClient>` to `AppState`; add `relay_client(&self) -> &RelayClient` (uses `get_or_init(RelayClient::new)` as fallback) and `set_relay_client(&self, url: String)` methods
- `apps/identity-wallet/src-tauri/src/lib.rs` — remove `static RELAY_CLIENT`; add `state: State<AppState>` to all commands that currently call `RELAY_CLIENT` directly (`create_account`, `perform_did_ceremony`, `register_handle`, `check_handle_resolution`); replace `RELAY_CLIENT.xxx()` calls with `state.relay_client().xxx()`; also update the call to `http::RelayClient::base_url()` in `perform_did_ceremony` (line 379) to use the instance method
- `apps/identity-wallet/src-tauri/src/oauth.rs` — replace `RelayClient::base_url()` static calls with `state.relay_client().base_url()`; `start_oauth_flow` already takes `State<AppState>`
- `apps/identity-wallet/src-tauri/src/oauth_client.rs` — `OAuthClient::new()` currently calls `RelayClient::base_url()` static; change to accept the URL as a parameter; update all call sites in `oauth.rs` and `home.rs` to pass `state.relay_client().base_url()`

**Dependencies:** Phase 1

**Done when:** `cargo build` succeeds; all existing tests in `oauth_client.rs` and `lib.rs` pass; no references to `RELAY_CLIENT` remain in the codebase
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Relay URL IPC commands and startup initialization

**Goal:** Expose relay URL configuration to the frontend and initialize the client from Keychain on startup.

**Components:**
- `apps/identity-wallet/src-tauri/src/keychain.rs` — add `"relay-base-url"` account constant; add `get_relay_url() -> Option<String>` and `store_relay_url(url: &str)` helpers
- `apps/identity-wallet/src-tauri/src/lib.rs` — in `run()` setup block, read relay URL from Keychain and call `state.set_relay_client(url)` if found; add three new Tauri IPC commands: `get_relay_url() -> Option<String>`, `check_relay_health(url: String) -> Result<(), RelayConfigError>`, `save_relay_url(url: String) -> Result<(), RelayConfigError>`; register them in `invoke_handler`
- New `RelayConfigError` type with variants `InvalidUrl` and `Unreachable`, serialized as `{ code: "INVALID_URL" | "UNREACHABLE" }`
- URL validation: must parse as HTTP or HTTPS with a non-empty host; strip trailing slash before saving
- Health check: `GET {url}/xrpc/_health` — any 200 response is accepted

**Dependencies:** Phase 2

**Done when:** `get_relay_url` returns `None` on first call and the stored URL on subsequent calls; `check_relay_health` returns `UNREACHABLE` for a non-existent host and succeeds for a live relay; `save_relay_url` persists to Keychain and initializes the relay client; tests cover success, `INVALID_URL`, and `UNREACHABLE` cases
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Frontend relay configuration screen

**Goal:** Show the relay URL screen on first launch; skip it on return visits.

**Components:**
- `apps/identity-wallet/src/lib/ipc.ts` — add `getRelayUrl(): Promise<string | null>`, `checkRelayHealth(url: string): Promise<void>`, `saveRelayUrl(url: string): Promise<void>` with `RelayConfigError` type (`{ code: 'INVALID_URL' | 'UNREACHABLE' }`)
- `apps/identity-wallet/src/lib/components/onboarding/RelayConfigScreen.svelte` — URL text input pre-filled with `"https://relay.ezpds.com"`; Connect button; loading state during health check; inline error display for `INVALID_URL` and `UNREACHABLE`; `onnext` callback on success
- `apps/identity-wallet/src/routes/+page.svelte` — add `relay_config` as the initial step; on mount call `getRelayUrl()`: if non-null advance directly to `welcome`; if null stay on `relay_config`; add `relay_config` case to the step renderer

**Dependencies:** Phase 3

**Done when:** Fresh-state app (no saved URL) shows the relay configuration screen first; app with a saved URL skips directly to the welcome screen; invalid URL shows `INVALID_URL` error inline; unreachable host shows `UNREACHABLE` error inline; successful configuration advances to welcome
<!-- END_PHASE_4 -->

## Additional Considerations

**Trailing slash normalization:** Strip trailing slashes from the URL before saving and before constructing request paths (`url.trim_end_matches('/')`). This prevents double-slash paths like `https://example.com//xrpc/_health`.

**`OnceLock::set()` idempotency:** `set()` silently drops a second call. `save_relay_url` is only reachable on first launch (subsequent launches skip the screen), so double-initialization is not a real-world concern — the silent-drop behavior is still the correct choice.

**`oauth_client.rs` tests:** The existing test suite uses `OAuthClient::new_for_test(keypair, session, base_url)`, which already accepts a URL string. Changing `OAuthClient::new()` to accept a URL string does not affect test code.
