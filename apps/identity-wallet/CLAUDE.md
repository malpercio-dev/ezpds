# Identity Wallet Mobile App

Last verified: 2026-03-28
Last updated: 2026-03-28

## Purpose

Tauri v2 iOS application — SvelteKit 2 + Svelte 5 frontend running in a native WKWebView, communicating with a Rust backend exclusively through Tauri's IPC bridge. First frontend code in the repository.

## Contracts

### Frontend (SvelteKit 2 + Svelte 5)

**Exposes:**
- `src/lib/ipc.ts` — typed wrappers for all Tauri IPC commands; import these instead of calling `invoke()` directly. Exports: `createAccount()`, `getOrCreateDeviceKey()`, `signWithDeviceKey()`, `performDIDCeremony()`, `startOAuthFlow()`, `loadHomeData()`, `logOut()`, `getRelayUrl()`, `saveRelayUrl()`, and their associated types (`DevicePublicKey`, `DeviceKeyError`, `CreateAccountResult`, `CreateAccountError`, `DIDCeremonyResult`, `DIDCeremonyError`, `OAuthError`, `SessionInfo`, `HomeData`, `RelayConfigError`)
- `src/lib/components/onboarding/` — twelve onboarding screen components (RelayConfigScreen, WelcomeScreen, ClaimCodeScreen, EmailScreen, HandleScreen, PasswordScreen, LoadingScreen, DIDCeremonyScreen, DIDSuccessScreen, ShamirBackupScreen, HandleRegistrationScreen, AuthenticatingScreen)
- `src/lib/components/home/` — three home screen components (HomeScreen, DIDDocumentScreen, RecoveryInfoScreen) plus DIDAvatar utility component (deterministic DID-derived hue circle)
- `src/routes/+page.svelte` — root page: seventeen-step state machine (relay_config -> welcome -> claim_code -> email -> handle -> password -> loading -> did_ceremony -> did_success -> shamir_backup -> handle_registration -> complete -> authenticating -> home -> did_document / recovery_info / auth_failed)

**Guarantees:**
- SSR is disabled globally (`ssr = false` in `src/routes/+layout.ts`); the frontend is a fully static SPA loaded from disk by WKWebView
- Build output lands in `dist/` (configured via `pages: 'dist'` in `svelte.config.js`)
- Frontend calls Tauri commands only through `src/lib/ipc.ts` — no raw `invoke()` calls in page components
- Relay error codes from `create_account` are mapped back to the originating screen (e.g. EXPIRED_CODE -> claim_code step, EMAIL_TAKEN -> email step)

**Expects:**
- `pnpm install` has been run in `apps/identity-wallet/`
- Node.js 22.x is in PATH (provided by the Nix dev shell)

### Rust Backend (src-tauri/)

**Exposes:**
- `src/lib.rs::create_account(claim_code, email, handle) -> Result<CreateAccountResult, CreateAccountError>` — Tauri IPC command: gets or creates device key via `device_key::get_or_create()`, POSTs to relay `/v1/accounts/mobile`, stores tokens in Keychain on success
- `src/lib.rs::get_or_create_device_key() -> Result<DevicePublicKey, DeviceKeyError>` — Tauri IPC command: delegates to `device_key::get_or_create()`
- `src/lib.rs::sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError>` — Tauri IPC command: delegates to `device_key::sign()`
- `src/lib.rs::perform_did_ceremony(handle: String, password: String) -> Result<DIDCeremonyResult, DIDCeremonyError>` — Tauri IPC command: fetches relay signing key (GET /v1/relay/keys), builds signed did:plc genesis op via `crypto::build_did_plc_genesis_op_with_external_signer` using device key as signer, POSTs genesis op + password to relay (POST /v1/dids with Bearer token), persists DID + upgraded session token + Share 1 in Keychain, returns `{ did, share3 }` to frontend
- `src/home.rs` — Home screen data module: `load_home_data(AppState) -> Result<HomeData, String>` (Tauri IPC command: fires GET /xrpc/_health and GET /xrpc/com.atproto.server.getSession concurrently via OAuthClient; always succeeds -- partial failures encoded as HomeData fields); `log_out(AppState) -> Result<(), String>` (Tauri IPC command: deletes oauth-access-token, oauth-refresh-token, and did from Keychain, clears in-memory oauth_session; always succeeds -- Keychain errors swallowed); output types: `HomeData` { relay_healthy, session, session_error, share1_in_keychain }, `SessionInfo` { did, handle, email, email_confirmed, did_doc }
- `src/oauth.rs` — OAuth PKCE client module: `AppState` (pending_auth + oauth_session mutexes + relay_client OnceLock + pds_client), `OAuthSession` (access/refresh/expiry/nonce), `DPoPKeypair` (P-256, persisted in Keychain), `OAuthError` enum, PKCE utilities (verifier + S256 challenge), `start_oauth_flow` (Tauri IPC command: DPoP keygen, PKCE, PAR, Safari redirect, deep-link callback, token exchange), `handle_deep_link` (routes deep-link URLs to pending flow); `AppState::pds_client()` accessor exposes `PdsClient` for Phase 4 Tauri commands
- `src/oauth_client.rs` — `OAuthClient`: authenticated HTTP client wrapping every request with `Authorization: DPoP {access_token}` + `DPoP` proof headers; transparent lazy refresh when token has <60s remaining; automatic retry on `use_dpop_nonce` 400 responses; methods: `get(path)`, `post(path, body)`
- `src/device_key.rs` — P-256 device key management with `#[cfg]`-based dispatch: macOS/simulator uses software keys via `crypto` crate + Keychain storage; real iOS device uses Secure Enclave via `security-framework`. Public API: `get_or_create() -> Result<DevicePublicKey, DeviceKeyError>` (idempotent), `sign(data) -> Result<Vec<u8>, DeviceKeyError>`
- `src/keychain.rs` — iOS Keychain abstraction (`store_item`, `get_item`, `delete_item`) under service `"ezpds-identity-wallet"`; Relay URL helpers: `store_relay_url`/`load_relay_url` (relay base URL); OAuth helpers: `store_dpop_key`/`load_dpop_key` (P-256 DPoP private key scalar), `store_oauth_tokens`/`load_oauth_tokens` (access + refresh token pair)
- `src/http.rs` — `RelayClient` with runtime-configurable base URL (initialized via `AppState::set_relay_client(url)` on first launch; localhost:8080 debug fallback); methods: `post()`, `get()`, `post_with_bearer()`, `par()` (POST /oauth/par with DPoP proof), `token_exchange()` (POST /oauth/token with PKCE verifier); response types: `ParResponse`, `TokenResponse`, `TokenErrorResponse`
- `src/identity_store.rs` — `IdentityStore` unit struct for multi-identity Keychain management with per-DID namespacing. Public API: `add_identity(did)` (registers DID in managed-dids index), `remove_identity(did)` (deletes DID and all per-DID entries), `list_identities()` (returns managed DIDs), `get_or_create_device_key(did)` (lazy per-DID P-256 key generation), `store_did_doc(did, json)` / `get_did_doc(did)` (DID document persistence), `store_plc_log(did, json)` / `get_plc_log(did)` (PLC audit log persistence). All methods require DID to be registered first (returns `IdentityNotFound` otherwise). `IdentityStoreError` enum: IDENTITY_NOT_FOUND, IDENTITY_ALREADY_EXISTS, KEYCHAIN_ERROR, KEY_GENERATION_FAILED, SERIALIZATION_ERROR (serialized as `{ code: "SCREAMING_SNAKE_CASE" }`)
- `src/pds_client.rs` — PDS discovery and OAuth module for arbitrary PDS endpoints (not just our relay). `PdsClient` struct (stateless, wraps a `reqwest::Client` + plc.directory URL). Public API: `resolve_handle(handle) -> Result<String, PdsClientError>` (DNS TXT `_atproto.{handle}` with HTTP `/.well-known/atproto-did` fallback), `discover_pds(did) -> Result<(String, PlcDidDocument), PdsClientError>` (fetches DID doc from plc.directory, extracts `atproto_pds` endpoint, verifies reachability via HEAD), `discover_auth_server(pds_url) -> Result<AuthServerMetadata, PdsClientError>` (fetches `/.well-known/oauth-authorization-server`, validates `code` response type + S256 challenge method), `pds_par(metadata, pkce_challenge, state, dpop_proof, dpop_jkt, login_hint?) -> Result<PdsParResponse, PdsClientError>` (PAR to arbitrary PDS), `pds_token_exchange(metadata, code, pkce_verifier, dpop_proof) -> Result<reqwest::Response, PdsClientError>` (returns raw response for caller nonce-retry), `build_pds_authorize_url(metadata, request_uri, login_hint?) -> String` (constructs browser redirect URL). Module-level XRPC functions (take `&OAuthClient`): `request_plc_operation_signature(client)`, `sign_plc_operation(client, request)`, `get_recommended_did_credentials(client)`. Types: `PlcDidDocument`, `PlcService`, `AuthServerMetadata`, `PdsParResponse`, `SignPlcOperationRequest`, `SignPlcOperationResponse`, `RecommendedCredentials`. `PdsClientError` enum: HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR, INVALID_RESPONSE, OAUTH_FAILED (serialized as `{ code: "SCREAMING_SNAKE_CASE" }`)
- `src/lib.rs::get_relay_url() -> Option<String>` — Tauri IPC command: loads relay base URL from Keychain, returns Some(url) if configured or None for first-launch
- `src/lib.rs::save_relay_url(url: String) -> Result<(), RelayConfigError>` — Tauri IPC command: validates URL format, pings `/xrpc/_health` on the relay, saves to Keychain, initializes `AppState.relay_client` (runtime configuration)

**Guarantees:**
- `crate-type = ["staticlib", "cdylib", "rlib"]` supports iOS (staticlib), Android (cdylib), and normal cargo builds (rlib)
- `src/main.rs` is the desktop entry point; `src/lib.rs::run()` is the iOS/Android entry point (via `#[cfg_attr(mobile, tauri::mobile_entry_point)]`)
- `tauri.conf.json` configures the bundle identifier, dev URL (`http://localhost:5173`), and frontend dist path (`../dist`)
- `create_account` maps relay HTTP error codes to typed `CreateAccountError` variants (EXPIRED_CODE, REDEEMED_CODE, EMAIL_TAKEN, HANDLE_TAKEN, NETWORK_ERROR, UNKNOWN) serialized as `{ code: "SCREAMING_SNAKE" }` for the frontend
- `perform_did_ceremony` maps failures to typed `DIDCeremonyError` variants (KEY_NOT_FOUND, RELAY_KEY_FETCH_FAILED, NO_RELAY_SIGNING_KEY, SIGNING_FAILED, DID_CREATION_FAILED, KEYCHAIN_ERROR, NETWORK_ERROR) serialized as `{ code: "SCREAMING_SNAKE_CASE" }` for the frontend
- `load_home_data` always returns Ok -- partial failures (relay unreachable, session expired) are encoded as `HomeData` fields (`relay_healthy: false`, `session: null`, `session_error: "NOT_AUTHENTICATED"`) so the UI can render whatever is available
- `log_out` always returns Ok -- Keychain delete errors are swallowed; the frontend unconditionally navigates to the welcome screen; device key and DPoP key are deliberately preserved (not deleted)
- `HomeData` and `SessionInfo` serialize with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ relayHealthy, session, sessionError, share1InKeychain }` and `{ did, handle, email, emailConfirmed, didDoc }`
- `start_oauth_flow` maps failures to typed `OAuthError` variants (DPOP_KEY_GEN_FAILED, DPOP_KEY_INVALID, DPOP_PROOF_FAILED, KEYCHAIN_ERROR, STATE_MISMATCH, CALLBACK_ABANDONED, PAR_FAILED, TOKEN_EXCHANGE_FAILED, TOKEN_REFRESH_FAILED, INVALID_GRANT, NOT_AUTHENTICATED) serialized as `{ code: "SCREAMING_SNAKE_CASE" }` for the frontend
- `tauri.conf.json` registers `deep-link` plugin with mobile scheme `dev.malpercio.identitywallet`; deep-link URLs matching `dev.malpercio.identitywallet:/oauth/callback?code=...&state=...` are routed to `handle_deep_link`
- On app startup, if OAuth tokens exist in Keychain, the session is restored into `AppState.oauth_session` and an `auth_ready` Tauri event is emitted after a 300ms delay (allows SvelteKit to boot and register its listener)
- `OAuthClient` transparently refreshes access tokens with <60s remaining before each request; retries once on `use_dpop_nonce` 400 responses from the server
- `DPoPKeypair` is idempotent: `get_or_create()` generates and persists to Keychain on first call, loads from Keychain on subsequent calls; the same key is used across all DPoP proofs and app sessions
- `device_key::get_or_create()` is idempotent -- returns the same key on every call for a given device
- `device_key::sign()` returns raw 64-byte r||s ECDSA signatures; low-S normalized on both paths (ATProto/PLC directory requires low-S); deterministic (RFC 6979) on simulator
- `DeviceKeyError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the `CreateAccountError` pattern
- Device key dispatch: `#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]` for software path, `#[cfg(all(target_os = "ios", not(target_env = "sim")))]` for Secure Enclave path
- `IdentityStore` is stateless (unit struct); all state lives in the Keychain. Methods take `&self` to allow future integration into `AppState`
- `IdentityStore::add_identity` does NOT eagerly generate a device key -- keys are lazily created on first `get_or_create_device_key` call
- `IdentityStore::remove_identity` performs best-effort cleanup of all six per-DID Keychain entries (device-key, device-key-pub, device-key-app-label, did-doc, plc-log, oauth-tokens); Keychain not-found errors during cleanup are ignored
- `IdentityStore::get_or_create_device_key` uses the same `#[cfg]` dispatch pattern as `device_key.rs` (software P-256 on macOS/simulator, Secure Enclave on real iOS) but with per-DID Keychain account namespacing (`"{did}:device-key"` instead of `"device-rotation-key-priv"`)
- `IdentityStoreError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the `CreateAccountError` pattern
- `PdsClientError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the `CreateAccountError` pattern; the `PdsUnreachable` variant's `reason` field is `#[serde(skip)]` (not sent to frontend)
- `PdsClient` is stateless (wraps `reqwest::Client` for connection pooling); default constructor targets `https://plc.directory`; test constructor accepts a custom URL for mock servers
- `PdsClient` is initialized eagerly in `AppState::new()` (not OnceLock) because it is cheap and stateless
- `pds_token_exchange` returns the raw `reqwest::Response` (not parsed) so callers can inspect `use_dpop_nonce` headers and implement retry logic
- XRPC identity functions (`request_plc_operation_signature`, `sign_plc_operation`, `get_recommended_did_credentials`) are module-level functions (not methods on `PdsClient`) because they require a DPoP-authenticated `OAuthClient` rather than the stateless HTTP client
- `resolve_handle` tries DNS TXT first (`_atproto.{handle}`), then HTTP `/.well-known/atproto-did`; returns `HANDLE_NOT_FOUND` only when both methods fail
- `discover_pds` verifies PDS reachability with a HEAD request (5-second timeout) after extracting the `atproto_pds` service endpoint from the DID document
- `discover_auth_server` validates that the OAuth metadata includes `"code"` in `response_types_supported` and `"S256"` in `code_challenge_methods_supported`
- `PdsClient` OAuth client_id and redirect_uri are hardcoded as `"dev.malpercio.identitywallet"` and `"dev.malpercio.identitywallet:/oauth/callback"` -- must match `oauth.rs` constants and relay V013 migration
- Per-DID Keychain accounts use `"{did}:suffix"` format (e.g. `"did:plc:abc123:device-key"`) -- the colon separator is part of the naming convention

**Expects:**
- `tauri.conf.json` exists in `src-tauri/` before `cargo build` runs — the config is read at compile time by `generate_context!()`
- `cargo-tauri` is in PATH (provided by the Nix dev shell)
- Xcode and iOS Simulator are installed on the developer's macOS machine
- Relay must be running at the configured URL (set via `RelayConfigScreen` on first launch, or the compile-time default) for `create_account` to succeed at runtime

## Dependencies

- Frontend -> Rust backend (via Tauri IPC -- `@tauri-apps/api/core` `invoke()`)
- Rust backend -> Cargo workspace (inherits `version`, `edition`, `publish` from root `Cargo.toml`)
- Rust backend -> `crates/crypto` (workspace dep: P-256 key generation in simulator/macOS software path)
- Rust backend -> `p256` (workspace dep: key reconstruction, signature types in both paths)
- Rust backend -> `multibase` (workspace dep: base58btc encoding for multibase/did:key output)
- Rust backend -> relay `/v1/accounts/mobile` endpoint (via `reqwest` HTTP at runtime)
- Rust backend -> relay `GET /v1/relay/keys` endpoint (public, no auth; fetches active signing key for DID ceremony)
- Rust backend -> relay `POST /v1/dids` endpoint (Bearer token auth; submits signed genesis op for DID promotion)
- Rust backend -> relay `POST /oauth/par` endpoint (PAR: push authorization request with PKCE challenge + DPoP proof)
- Rust backend -> relay `GET /oauth/authorize` endpoint (opened in Safari; user authenticates via browser)
- Rust backend -> relay `POST /oauth/token` endpoint (exchanges authorization code + PKCE verifier for DPoP-bound tokens)
- Rust backend -> relay `GET /xrpc/_health` endpoint (public, no auth; home screen relay health check)
- Rust backend -> relay `GET /xrpc/com.atproto.server.getSession` endpoint (DPoP-authenticated via OAuthClient; fetches session info for home screen)
- Rust backend -> `tauri-plugin-deep-link` (registers `dev.malpercio.identitywallet:` URL scheme for OAuth callback)
- Rust backend -> `tauri-plugin-opener` (opens Safari for OAuth authorization)
- Rust backend -> plc.directory (via `reqwest` HTTP at runtime; used by `PdsClient::discover_pds` to fetch DID documents)
- Rust backend -> arbitrary PDS endpoints (via `reqwest` HTTP at runtime; used by `PdsClient` for OAuth discovery, PAR, token exchange, and XRPC identity methods)
- Rust backend -> `hickory-resolver` (workspace dep: DNS TXT resolution for ATProto handle verification in `pds_client::try_resolve_dns`)
- Rust backend -> `urlencoding` (workspace dep: URL-encoding for OAuth authorize URL construction in `PdsClient::build_pds_authorize_url`)
- Rust backend -> iOS Keychain (via `security-framework` crate with `OSX_10_12` feature for SE access control APIs)
- Rust backend -> Secure Enclave hardware (real iOS device only; via `security-framework` `SecKey`/`GenerateKeyOptions`/`Token::SecureEnclave`)
- `src-tauri/gen/` -> NOT tracked in git; generated per-developer by `cargo tauri ios init` (gitignored)

## Prerequisites (macOS/iOS Development)

1. **macOS Ventura (13) or later**

2. **Xcode** (latest stable, from App Store)
   - After installing, open Xcode.app once to accept the license agreement — failing to do this causes `cargo tauri ios dev` to fail silently
   - Install the iOS Simulator platform: Xcode → Settings → Platforms → iOS

3. **Cocoapods** — Tauri's iOS build uses it to link native Apple frameworks:
   ```bash
   sudo gem install cocoapods
   ```

4. **Apple Developer account** — optional for Simulator; required for physical device (TestFlight/App Store) builds

## First-Time Setup

After cloning the repo, perform these steps once per developer machine:

```bash
# 1. Enter the Nix dev shell (provides cargo-tauri, node 22, pnpm, rustup)
#    On first entry, enterShell installs the Rust toolchain + iOS targets via rustup.
#    This reads rust-toolchain.toml and may download ~2-4 GB — takes a few minutes.
nix develop --impure --accept-flake-config

# 2. Install frontend dependencies
cd apps/identity-wallet
pnpm install

# 3. Generate the Xcode project (output is in src-tauri/gen/apple/ — gitignored)
cargo tauri ios init
```

Note: `src-tauri/gen/` contains a machine-specific Xcode project. It is gitignored and must be re-generated on each developer machine. Do not commit it.

### Xcode build phase PATH (one-time manual step after `cargo tauri ios init`)

Xcode's Run Script build phases do not inherit the Nix dev shell PATH. After regenerating `src-tauri/gen/`, the generated `project.pbxproj` script must be patched to expose both the devenv tools and the rustup-managed cargo:

Open `src-tauri/gen/apple/identity-wallet.xcodeproj/project.pbxproj` and find the `shellScript` line in the PBXShellScriptBuildPhase section. Prepend:

```
export PATH="<project-root>/.devenv/state/cargo/bin:<project-root>/.devenv/profile/bin:$PATH"
```

where `<project-root>` is the absolute path to the repo root (e.g. `/Users/you/workspace/malpercio-dev/ezpds`).

This step is required once per `cargo tauri ios init` run.

### Disable user script sandboxing (one-time manual step after `cargo tauri ios init`)

Xcode 14+ sets `ENABLE_USER_SCRIPT_SANDBOXING = YES` in generated projects, which wraps Run Script build phases in `sandbox-exec`. On macOS 26 (Tahoe), this blocks Cargo's directory walk (package fingerprinting) with:

```
Failed to update the excludes stack to see if a path is excluded
```

After regenerating `src-tauri/gen/`, run:

```bash
sed -i '' 's/ENABLE_USER_SCRIPT_SANDBOXING = YES/ENABLE_USER_SCRIPT_SANDBOXING = NO/g' \
  src-tauri/gen/apple/identity-wallet.xcodeproj/project.pbxproj
```

This step is required once per `cargo tauri ios init` run.

### Why rustup instead of Nix-managed Rust

`languages.rust` in devenv uses Nix's `rust-default` package, which only ships stdlibs for standard host targets. iOS Simulator requires `aarch64-apple-ios-sim` stdlib. Nix doesn't package iOS cross-compilation stdlibs; `rustup` downloads them from the Rust release infrastructure. The dev shell is configured with project-local `RUSTUP_HOME` and `CARGO_HOME` (inside `.devenv/state/`) so the toolchain is isolated per project.

## Development Workflow

```bash
# Enter the dev shell if not already active (MUST be run from the workspace root,
# not from apps/identity-wallet/ — CARGO_HOME resolves relative to devenv root)
nix develop --impure --accept-flake-config

# Launch the app in the iOS Simulator
# This starts pnpm dev + compiles the Rust crate for aarch64-apple-ios-sim + opens the Simulator
cd apps/identity-wallet
cargo tauri ios dev
```

**Do not click Run in Xcode directly.** `cargo tauri ios dev` starts a JSON-RPC server that
Xcode's build phase connects to; bypassing it causes "Connection refused" in the build log.

For a non-iOS build (CI or any machine without Xcode):

```bash
# From workspace root — builds all workspace crates including src-tauri for the host platform
cargo build
```

## Key Decisions

- **`adapter-static` + `ssr = false`**: Tauri WebViews load files from disk — there is no web server. SSR is meaningless and globally disabled.
- **`pages: 'dist'` in svelte.config.js**: Matches `tauri.conf.json`'s `frontendDist: "../dist"`.
- **`TAURI_DEV_HOST` for HMR**: Tauri v2 automatically sets this env var to the machine's LAN IP when running `cargo tauri ios dev`. The iOS simulator connects to the Vite dev server over LAN, not localhost.
- **`generate_context!()` is compile-time**: `tauri.conf.json` must exist when `src-tauri/` is compiled — the macro embeds the config at compile time and will fail to compile if the file is missing.
- **`src-tauri/gen/` is gitignored**: The Xcode project generated by `cargo tauri ios init` is machine-specific. Committing it causes merge conflicts and bloats the repo.
- **`tauri` and `tauri-build` declared locally**: These crates are not in `[workspace.dependencies]` because no other workspace crate uses them. `serde` and `serde_json` use `{ workspace = true }` per the standard workspace pattern.
- **`src-tauri/.cargo/config.toml` committed**: Overrides `CC`, `AR`, and `linker` for iOS, iOS Simulator, and macOS-host targets to use Xcode's unwrapped clang instead of the Nix cc-wrapper. The macOS-host `CC`/`AR` overrides (`CC_aarch64_apple_darwin`, `AR_aarch64_apple_darwin`) were added for `security-framework`'s C build scripts which fail under Nix's cc-wrapper. See the Troubleshooting section for the full explanation.
- **Runtime-configurable relay URL**: `http.rs` provides a compile-time default via `#[cfg(debug_assertions)]` (localhost:8080 debug, relay.ezpds.com release). At runtime, the user configures the relay URL on first launch via `RelayConfigScreen`; the URL is persisted to Keychain and restored on subsequent launches via `AppState::set_relay_client()`. The compile-time default is used only as the pre-filled value in the configuration UI.
- **Device key module (`device_key.rs`) with `#[cfg]` dispatch**: Two compile-time paths share the same public API (`get_or_create`, `sign`). macOS and iOS Simulator use software P-256 via `crypto` crate with private key bytes in Keychain. Real iOS device uses Secure Enclave -- private key never leaves the SE; only the compressed public key and application_label (SE-assigned SHA1) are stored in regular Keychain for lookup.
- **Idempotent key lifecycle**: `get_or_create()` generates on first call, returns the same key on subsequent calls. `create_account` delegates to `device_key::get_or_create()` so the same device key is sent to the relay on every attempt (retries are safe).
- **P-256 multicodec prefix duplicated**: `device_key.rs` duplicates the `[0x80, 0x24]` P-256 multicodec varint prefix from `crates/crypto/src/keys.rs` because the constant is `pub(crate)` there. This is intentional -- the identity-wallet crate should not depend on internal crypto crate layout.
- **Low-S normalization on both paths**: ATProto/PLC directory requires low-S ECDSA signatures (enforced by `@noble/curves` in strict mode). Both the SE path and the simulator path apply `normalize_s()` after signing. RFC 6979 only provides deterministic nonces — it does NOT guarantee low-S; that requires an explicit normalization step.
- **reqwest with rustls-tls**: Uses `default-features = false` + `rustls-tls` to avoid linking OpenSSL. On iOS, rustls handles TLS natively without additional system deps.
- **OAuth PKCE flow with DPoP**: The identity-wallet authenticates with the relay using OAuth 2.0 Authorization Code + PKCE (RFC 7636) with DPoP-bound tokens (RFC 9449). The flow is: generate DPoP keypair + PKCE verifier -> PAR (push parameters to relay) -> open Safari to `/oauth/authorize` -> deep-link callback with authorization code -> token exchange with PKCE verifier + DPoP proof -> store tokens in Keychain.
- **DPoP keypair persisted in Keychain**: The same P-256 DPoP key is reused across all OAuth flows and app sessions. This allows the relay to bind tokens to the key (via `jkt` thumbprint) and enables token refresh without re-authenticating.
- **Deep-link for OAuth callback**: Uses `tauri-plugin-deep-link` with custom URL scheme `dev.malpercio.identitywallet:` to receive the OAuth authorization code from Safari. The callback URL is `dev.malpercio.identitywallet:/oauth/callback?code=...&state=...`.
- **AppState with Mutex<Option>**: `pending_auth` is set before opening Safari and cleared by the deep-link handler; `oauth_session` holds the active tokens. Both use `Mutex<Option<T>>` so the state is cleanly empty before/after flows.
- **OAuthClient with lazy refresh**: `OAuthClient` checks token expiry before each request and refreshes if <60s remaining. Retries once on `use_dpop_nonce` 400 responses (server requires a nonce the client didn't have yet).
- **`load_home_data` always-Ok pattern**: `load_home_data` never returns Err -- partial failures (relay down, session expired, OAuthClient construction failure) are encoded as HomeData fields (e.g. `relay_healthy: false`, `session: null`, `session_error: "NOT_AUTHENTICATED"`). This lets the UI render whatever data is available rather than showing a generic error screen.
- **`log_out` preserves device key and DPoP key**: `log_out` only deletes OAuth tokens (access + refresh) and the DID from Keychain. The device rotation key and DPoP keypair are deliberately preserved so re-authentication does not require re-enrollment.
- **DIDAvatar deterministic hue**: `DIDAvatar.svelte` derives a stable hue (0-359) from the DID string using a polynomial hash (`h = (h * 31 + charCode) & 0xffffff; hue = h % 360`). The same DID always produces the same color across renders and sessions.
- **Home screen data flow**: HomeScreen calls `loadHomeData()` on mount, stores the result in local state, and passes the full HomeData to child screens (DIDDocumentScreen, RecoveryInfoScreen) via the page-level state machine in `+page.svelte` rather than having children re-fetch.
- **Startup token restore**: On app launch, `lib.rs::run()` checks Keychain for persisted OAuth tokens. If found, restores them into `AppState.oauth_session` with `expires_at = 0` (forces immediate refresh on first use) and emits `auth_ready` after 300ms delay so SvelteKit has time to boot.
- **Per-DID Keychain namespacing (`identity_store.rs`)**: Multi-identity support uses DID-prefixed Keychain accounts (`"{did}:device-key"`, etc.) instead of the single-identity global accounts in `device_key.rs`. A top-level `"managed-dids"` JSON array index tracks all registered DIDs. Device keys are lazily generated on first `get_or_create_device_key` rather than at identity registration time. The module uses the same `#[cfg]` dispatch pattern as `device_key.rs` for software vs. SE key generation but with per-DID scoping.
- **PDS client separate from relay client (`pds_client.rs`)**: `PdsClient` handles discovery and OAuth against arbitrary PDS endpoints (not just our relay), while `RelayClient` (in `http.rs`) handles communication with the user's configured relay. The separation exists because PDS discovery targets endpoints the wallet learns at runtime (plc.directory, user's PDS), whereas `RelayClient` targets a single configured relay. `PdsClient` is stateless and uses `reqwest::Client` directly; `RelayClient` holds a runtime-configured base URL.
- **XRPC identity functions as module-level functions**: `request_plc_operation_signature`, `sign_plc_operation`, and `get_recommended_did_credentials` are standalone functions in `pds_client.rs` (not methods on `PdsClient`) because they require a DPoP-authenticated `OAuthClient` for the Authorization header, which `PdsClient`'s plain HTTP client cannot provide. This keeps `PdsClient` focused on unauthenticated discovery while XRPC calls use the existing `OAuthClient` infrastructure.
- **DNS resolution via hickory-resolver**: Handle resolution uses `hickory-resolver` for DNS TXT lookups (`_atproto.{handle}`), matching the same DNS library used by the relay crate (`crates/relay/src/dns.rs`). Falls back to HTTP `/.well-known/atproto-did` when DNS fails.

## Invariants

- `src/lib/ipc.ts` is the only file that calls `invoke()` directly; page components import from `ipc.ts`
- `tauri.conf.json` bundle identifier `dev.malpercio.identitywallet` must match the iOS provisioning profile for physical device builds
- `src-tauri/gen/` is never committed -- regenerate with `cargo tauri ios init`
- `pnpm-lock.yaml` is committed and kept in sync with `package.json`
- Keychain service name is always `"ezpds-identity-wallet"` (constant `keychain::SERVICE`); changing it orphans previously stored credentials
- `CreateAccountError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `CreateAccountError.code` union must match exactly
- `DeviceKeyError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `DeviceKeyError.code` union must match exactly
- `DIDCeremonyError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `DIDCeremonyError.code` union must match exactly
- `RelayConfigError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `RelayConfigError.code` union must match exactly (INVALID_URL, UNREACHABLE, KEYCHAIN_ERROR)
- Keychain account `"relay-base-url"` stores the relay's base URL (e.g. `https://relay.ezpds.com`); persisted by `save_relay_url` on first launch; `get_relay_url` returns null if not yet set
- Keychain account `"device-rotation-key-priv"` stores the software P-256 private key (simulator/macOS path only); changing it orphans existing keys
- Keychain accounts `"device-rotation-key-pub"` and `"device-rotation-key-app-label"` store SE metadata (real iOS device path only); changing them orphans the SE key lookup
- Keychain account `"session-token"` stores the pending (pre-DID) or full (post-DID) session token; `perform_did_ceremony` reads the pending token and overwrites it with the upgraded token on success
- Keychain account `"did"` stores the user's did:plc after successful DID ceremony; persisted for use in subsequent app sessions
- Keychain account `"recovery-share-1"` stores Share 1 of the Shamir recovery split (base32, 52 chars); written by `perform_did_ceremony` immediately after DID promotion; never displayed to the user (iCloud Keychain automatic backup)
- Keychain account `"oauth-dpop-key-priv"` stores the P-256 DPoP private key scalar (32 bytes); generated once by `DPoPKeypair::get_or_create()`, reused across all app sessions; changing it invalidates all DPoP-bound tokens
- Keychain account `"oauth-access-token"` stores the OAuth access token; written by `start_oauth_flow` on success and by `OAuthClient` on refresh
- Keychain account `"oauth-refresh-token"` stores the OAuth refresh token; written alongside the access token
- `OAuthError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `OAuthError.code` union must match exactly
- `PdsClientError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `PdsClientError.code` union must match exactly (HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR, INVALID_RESPONSE, OAUTH_FAILED)
- OAuth client_id is always `"dev.malpercio.identitywallet"` -- must match the seeded row in relay migration V013 and the `tauri.conf.json` bundle identifier
- OAuth redirect_uri is always `"dev.malpercio.identitywallet:/oauth/callback"` -- must match the deep-link scheme in `tauri.conf.json` and the seeded client_metadata redirect_uris in V013
- `DevicePublicKey` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ multibase, keyId }` (not `key_id`)
- `HomeData` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ relayHealthy, session, sessionError, share1InKeychain }`; the TypeScript `HomeData` type in `ipc.ts` must match exactly
- `SessionInfo` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ did, handle, email, emailConfirmed, didDoc }`; the TypeScript `SessionInfo` type in `ipc.ts` must match exactly
- `log_out` deletes exactly three Keychain accounts: `"oauth-access-token"`, `"oauth-refresh-token"`, `"did"` -- adding or removing items from this list changes what data survives a logout
- Keychain account `"managed-dids"` stores a JSON array of all managed DID strings (e.g. `["did:plc:abc","did:plc:def"]`); the single source of truth for which identities are registered in `IdentityStore`
- Per-DID Keychain accounts follow the `"{did}:suffix"` pattern with six suffixes: `device-key` (P-256 private key scalar, software path only; not written on SE path), `device-key-pub` (compressed public key, SE path only), `device-key-app-label` (SE application_label, SE path only), `did-doc` (opaque DID document JSON), `plc-log` (opaque PLC audit log JSON), `oauth-tokens` (reserved for per-DID OAuth tokens)
- `IdentityStore` P-256 multicodec prefix `[0x80, 0x24]` is duplicated from `crates/crypto/src/keys.rs` (same rationale as `device_key.rs` -- `pub(crate)` constant cannot be imported cross-crate)

## Key Files

- `src-tauri/tauri.conf.json` -- Tauri config: bundle ID, devUrl, frontendDist, window settings
- `src-tauri/src/lib.rs` -- Tauri IPC commands (`get_relay_url`, `save_relay_url`, `create_account`, `get_or_create_device_key`, `sign_with_device_key`, `perform_did_ceremony`, `start_oauth_flow`, `home::load_home_data`, `home::log_out`), `run()` (mobile entry point), deep-link plugin setup, startup token restore
- `src-tauri/src/home.rs` -- Home screen Tauri commands: `load_home_data` (concurrent relay health + getSession), `log_out` (Keychain wipe + session clear); output types: HomeData, SessionInfo
- `src-tauri/src/device_key.rs` -- P-256 device key module: `#[cfg]`-dispatched `get_or_create()` and `sign()` (simulator software path vs. Secure Enclave)
- `src-tauri/src/identity_store.rs` -- Multi-identity Keychain management: IdentityStore (add/remove/list identities, per-DID device key generation, DID doc + PLC log persistence)
- `src-tauri/src/pds_client.rs` -- PDS discovery and OAuth to arbitrary PDS: PdsClient (resolve_handle, discover_pds, discover_auth_server, pds_par, pds_token_exchange, build_pds_authorize_url); XRPC identity functions (request_plc_operation_signature, sign_plc_operation, get_recommended_did_credentials)
- `src-tauri/src/main.rs` -- Desktop entry point (calls `lib::run()`)
- `src-tauri/src/oauth.rs` -- OAuth PKCE module: AppState, DPoPKeypair, OAuthSession, PKCE utilities, start_oauth_flow command, handle_deep_link
- `src-tauri/src/oauth_client.rs` -- OAuthClient: authenticated HTTP client with DPoP proofs and lazy token refresh
- `src-tauri/src/keychain.rs` -- iOS Keychain abstraction (store_item, get_item, delete_item); Relay URL helpers (store_relay_url, load_relay_url); OAuth helpers (store_dpop_key, load_dpop_key, store_oauth_tokens, load_oauth_tokens)
- `src-tauri/src/http.rs` -- RelayClient with runtime-configurable base URL; OAuth methods (par, token_exchange)
- `src-tauri/.cargo/config.toml` -- Cargo toolchain overrides for iOS cross-compilation (CC, AR, linker per target)
- `src/lib/ipc.ts` -- Typed TypeScript wrappers for all Tauri IPC commands (getRelayUrl, saveRelayUrl, createAccount, getOrCreateDeviceKey, signWithDeviceKey, performDIDCeremony, startOAuthFlow, loadHomeData, logOut)
- `src/lib/components/onboarding/` -- Eleven onboarding screen components (RelayConfigScreen, WelcomeScreen, ClaimCodeScreen, EmailScreen, HandleScreen, PasswordScreen, LoadingScreen, DIDCeremonyScreen, DIDSuccessScreen, ShamirBackupScreen, AuthenticatingScreen)
- `src/lib/components/home/` -- Three home screen components (HomeScreen, DIDDocumentScreen, RecoveryInfoScreen) plus DIDAvatar utility component
- `src/routes/+page.svelte` -- State machine (relay_config -> welcome -> claim_code -> email -> handle -> password -> loading -> did_ceremony -> did_success -> shamir_backup -> handle_registration -> complete -> authenticating -> home -> did_document / recovery_info / auth_failed)
- `src/routes/+layout.ts` -- `ssr = false; prerender = false` (global SPA config)
- `svelte.config.js` -- adapter-static with `pages: 'dist'` (SPA mode, matches tauri.conf.json)
- `vite.config.ts` -- Tauri-compatible Vite server (clearScreen, HMR via TAURI_DEV_HOST, envPrefix)

## Troubleshooting

### `cargo tauri ios dev` fails with "Connection refused"

You launched the Xcode build manually (clicking Run in Xcode) instead of through `cargo tauri ios dev`. Xcode's "Build Rust Code" phase calls `cargo tauri ios xcode-script`, which connects back to the `cargo tauri ios dev` process via JSON-RPC. There is no server to connect to if the build was not initiated by `cargo tauri ios dev`.

**Fix:** Always use `cargo tauri ios dev` from the terminal. Do not click Run in Xcode.

---

### `error: can't find crate for 'core'` — `aarch64-apple-ios-sim` target not installed

The Nix `rust-default` package (used by `languages.rust` in devenv) does not ship iOS cross-compilation stdlibs. This was the historical state of the project before the rustup migration.

**Fix:** Already resolved. `devenv.nix` uses `pkgs.rustup` with project-local `RUSTUP_HOME`/`CARGO_HOME`. On first `nix develop`, `enterShell` runs `rustup toolchain install` which reads `rust-toolchain.toml` and installs `aarch64-apple-ios-sim` stdlib automatically.

If you see this after a fresh clone: make sure you entered the dev shell from the **workspace root** (not from `apps/identity-wallet/`) so that `CARGO_HOME` resolves correctly.

---

### `error: tool 'simctl' not found` or `xcrun simctl list` fails

The Nix devenv's Darwin setup hooks override `DEVELOPER_DIR` to a Nix apple-sdk stub that has no runtime tools. The `xcbuild` xcrun shim in PATH delegates to `$DEVELOPER_DIR/usr/bin/xcrun` — if `DEVELOPER_DIR` points at a Nix stub, it fails.

**Fix:** Already resolved. `devenv.nix`'s `enterShell` re-exports `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` after all Nix hooks run.

If you still see this: verify with `echo $DEVELOPER_DIR` inside the dev shell. If it shows a Nix store path, exit and re-enter the shell from the workspace root.

---

### `clang: error: invalid argument '-mmacos-version-min=14.0' not allowed with '-mios-simulator-version-min=14.0'`

The Nix cc-wrapper (in `.devenv/profile/bin/clang`) injects `-mmacos-version-min` for the host platform. When a build script (e.g. `objc2-exception-helper`) compiles Objective-C for the iOS simulator target, clang rejects both version flags simultaneously.

**Fix:** Already resolved. `src-tauri/.cargo/config.toml` sets `CC_aarch64_apple_ios_sim` and `CC_aarch64_apple_ios` to Xcode's unwrapped clang, which handles iOS targets correctly.

---

### `ld: library not found for -liconv` (host proc-macro build)

Rust proc-macros (e.g. `phf_macros`) are compiled for the host (`aarch64-apple-darwin`) even during an iOS cross-compilation build. The Nix cc-wrapper uses a partial Nix apple-sdk as sysroot, which omits some `/usr/lib` stubs including `libiconv.tbd`. The linker passes `-liconv` but can't find it.

**Fix:** Already resolved. `src-tauri/.cargo/config.toml` sets `[target.aarch64-apple-darwin].linker` to Xcode's clang and adds `rustflags = ["-L", ".../MacOSX.sdk/usr/lib"]` so the linker finds `/usr/lib` stubs (including `libiconv.tbd`) from the real Xcode SDK sysroot.

---

### `ld: framework not found UIKit` (iOS target final link)

The final link of `identity-wallet.dylib` for `aarch64-apple-ios-sim` uses `cc` (the Nix cc-wrapper) as the linker. The cc-wrapper injects its macOS sysroot even when rustc passes `-target arm64-apple-ios-simulator`, so the linker searches the macOS SDK and can't find iOS-only frameworks like UIKit.

**Fix:** Already resolved. `src-tauri/.cargo/config.toml` sets `[target.aarch64-apple-ios-sim].linker` to Xcode's clang, which handles the iOS sysroot and frameworks correctly.

---

### `sandbox-exec: sandbox_apply: Operation not permitted` (Tauri ios-api build)

Swift Package Manager sandboxes its manifest compilation using `sandbox-exec`. On macOS 26 (Tahoe), `sandbox_apply()` returns `EPERM` in this context, causing `swift-rs`'s build script (used by Tauri) to fail with "Failed to compile swift package Tauri".

**Fix:** Already resolved. A local patch of `swift-rs` 1.0.7 at `apps/identity-wallet/swift-rs-patch/` adds `--disable-sandbox` to the `swift build` invocation inside `SwiftLinker::link`. The workspace `Cargo.toml` wires this in via `[patch.crates-io]`. Remove the patch entry when swift-rs ships a fix upstream.

---

### Xcode build phase: `cargo: command not found`

After running `cargo tauri ios init`, the generated `project.pbxproj` build script has the system PATH which doesn't include the Nix dev shell or rustup-managed cargo.

**Fix:** See "Xcode build phase PATH" in the First-Time Setup section above. Patch `project.pbxproj` to prepend `.devenv/state/cargo/bin` and `.devenv/profile/bin`.

---

### `Failed to update the excludes stack to see if a path is excluded` (Xcode user script sandbox)

Xcode 14+ enables `ENABLE_USER_SCRIPT_SANDBOXING=YES` by default in generated projects, wrapping Run Script build phases in `sandbox-exec`. On macOS 26 (Tahoe), this sandbox blocks Cargo's `readdir()` calls during package fingerprinting, producing:

```
error: failed to determine package fingerprint for build script for identity-wallet v0.1.0
Caused by: Failed to update the excludes stack to see if a path is excluded
```

**Fix:** See "Disable user script sandboxing" in the First-Time Setup section. Run the `sed` one-liner against `project.pbxproj` after each `cargo tauri ios init`.
