# Identity Wallet Mobile App

Last verified: 2026-06-20
Last updated: 2026-06-20

## Purpose

Tauri v2 iOS application — SvelteKit 2 + Svelte 5 frontend running in a native WKWebView, communicating with a Rust backend exclusively through Tauri's IPC bridge. First frontend code in the repository.

## Contracts

### Frontend (SvelteKit 2 + Svelte 5)

**Exposes:**
- `src/lib/ipc.ts` — typed wrappers for all Tauri IPC commands; import these instead of calling `invoke()` directly. Exports: `createAccount()`, `getOrCreateDeviceKey()`, `signWithDeviceKey()`, `performDIDCeremony()`, `startOAuthFlow()`, `loadHomeData()`, `logOut()`, `getRelayUrl()`, `saveRelayUrl()`, `resolveIdentity()`, `startPdsAuth()`, `requestClaimVerification()`, `signAndVerifyClaim()`, `submitClaim()`, `listIdentities()`, `getStoredDidDoc()`, `getDeviceKeyId()`, `checkIdentityStatus()`, `buildRecoveryOverride()`, `submitRecoveryOverride()`, and their associated types (`DevicePublicKey`, `DeviceKeyError`, `CreateAccountResult`, `CreateAccountError`, `DIDCeremonyResult`, `DIDCeremonyError`, `OAuthError`, `SessionInfo`, `HomeData`, `RelayConfigError`, `IdentityInfo`, `VerifiedClaimOp`, `OpDiff`, `ServiceChange`, `ClaimResult`, `ResolveError`, `ClaimError`, `IdentityStoreError`, `UnauthorizedChange`, `IdentityStatus`, `SignedRecoveryOp`, `RecoveryError`)
- `src/lib/components/onboarding/` — eighteen onboarding screen components (ModeSelectScreen, RelayConfigScreen, WelcomeScreen, ClaimCodeScreen, EmailScreen, HandleScreen, PasswordScreen, LoadingScreen, DIDCeremonyScreen, DIDSuccessScreen, ShamirBackupScreen, HandleRegistrationScreen, AuthenticatingScreen, IdentityInputScreen, PdsAuthScreen, EmailVerificationScreen, ReviewOperationScreen, ClaimSuccessScreen)
- `src/lib/components/home/` — six home screen components (IdentityListHome, HomeScreen, DIDDocumentScreen, RecoveryInfoScreen, AlertDetailScreen, RecoveryOverrideScreen) plus DIDAvatar utility component (deterministic DID-derived hue circle)
- `src/lib/utils/deadline.ts` — PLC recovery deadline utilities: `getDeadline(createdAt)` (adds 72h to ISO 8601 timestamp), `getUrgency(deadline)` (returns `'safe'` | `'warning'` | `'critical'` | `'expired'`), `formatCountdown(deadline)` (human-readable `"Xh Ym remaining"`). `Urgency` type exported. Thresholds: expired = 0, critical < 4h, warning < 24h, safe >= 24h
- `src/routes/+page.svelte` — root page: two-flow state machine starting at `mode_select`. **Create flow:** mode_select -> relay_config -> welcome -> claim_code -> email -> handle -> password -> loading -> did_ceremony -> did_success -> shamir_backup -> handle_registration -> complete -> authenticating -> home. **Import flow:** mode_select -> identity_input -> pds_auth -> email_verification -> review_operation -> claim_success -> home. **Home:** home -> identity_detail -> did_document / recovery_info / alert_detail -> recovery_override. On mount, checks for existing identities via `listIdentities()` and skips to `home` if any exist. Registers a `visibilitychange` listener that calls `checkIdentityStatus()` when the app returns to foreground while on the `home` step

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
- `src/oauth.rs` — OAuth PKCE client module: `AppState` (pending_auth + oauth_session mutexes + relay_client OnceLock + pds_client + claim_state + recovery_state), `OAuthSession` (access/refresh/expiry/nonce), `DPoPKeypair` (P-256, persisted in Keychain), `OAuthError` enum, PKCE utilities (verifier + S256 challenge), `start_oauth_flow` (Tauri IPC command: DPoP keygen, PKCE, PAR, Safari redirect, deep-link callback, token exchange), `handle_deep_link` (routes deep-link URLs to pending flow); `AppState::pds_client()` accessor exposes `PdsClient` for claim flow commands
- `src/claim.rs` — PLC rotation key claim flow module (5 Tauri IPC commands): `resolve_identity(handle_or_did) -> Result<IdentityInfo, ResolveError>` (resolves handle/DID to identity info via plc.directory, stores ClaimState), `start_pds_auth(pds_url) -> Result<(), ClaimError>` (OAuth PKCE+DPoP to arbitrary PDS, stores OAuthClient in ClaimState, emits `"pds_auth_ready"` event), `request_claim_verification(did) -> Result<(), ClaimError>` (calls `requestPlcOperationSignature` XRPC on old PDS to trigger email verification), `sign_and_verify_claim(did, token) -> Result<VerifiedClaimOp, ClaimError>` (calls `getRecommendedDidCredentials` and `signPlcOperation` on old PDS, fetches audit log, verifies signature + 4-point local checks, stores signed op in ClaimState), `submit_claim(did) -> Result<ClaimResult, ClaimError>` (POSTs signed op to plc.directory, persists identity to IdentityStore, clears ClaimState). Types: `IdentityInfo`, `VerifiedClaimOp`, `OpDiff`, `ServiceChange`, `ClaimResult`, `ClaimState`. Error enums: `ResolveError` (HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR), `ClaimError` (INVALID_TOKEN, VERIFICATION_FAILED, PLC_DIRECTORY_ERROR, UNAUTHORIZED, NETWORK_ERROR)
- `src/oauth_client.rs` — `OAuthClient`: authenticated HTTP client wrapping every request with `Authorization: DPoP {access_token}` + `DPoP` proof headers; transparent lazy refresh when token has <60s remaining; automatic retry on `use_dpop_nonce` 400 responses; methods: `get(path)`, `post(path, body)`
- `src/device_key.rs` — P-256 device key management with `#[cfg]`-based dispatch: macOS/simulator uses software keys via `crypto` crate + Keychain storage; real iOS device uses Secure Enclave via `security-framework`. Public API: `get_or_create() -> Result<DevicePublicKey, DeviceKeyError>` (idempotent), `sign(data) -> Result<Vec<u8>, DeviceKeyError>`
- `src/keychain.rs` — iOS Keychain abstraction (`store_item`, `get_item`, `delete_item`) under service `"ezpds-identity-wallet"`; Relay URL helpers: `store_relay_url`/`load_relay_url` (relay base URL); OAuth helpers: `store_dpop_key`/`load_dpop_key` (P-256 DPoP private key scalar), `store_oauth_tokens`/`load_oauth_tokens` (access + refresh token pair)
- `src/http.rs` — `RelayClient` with runtime-configurable base URL (initialized via `AppState::set_relay_client(url)` on first launch; localhost:8080 debug fallback); methods: `post()`, `get()`, `post_with_bearer()`, `par()` (POST /oauth/par with DPoP proof), `token_exchange()` (POST /oauth/token with PKCE verifier); response types: `ParResponse`, `TokenResponse`, `TokenErrorResponse`
- `src/identity_store.rs` — `IdentityStore` unit struct for multi-identity Keychain management with per-DID namespacing. Public API: `add_identity(did)` (registers DID in managed-dids index), `remove_identity(did)` (deletes DID and all per-DID entries), `list_identities()` (returns managed DIDs), `get_or_create_device_key(did)` (lazy per-DID P-256 key generation), `store_did_doc(did, json)` / `get_did_doc(did)` (DID document persistence), `store_plc_log(did, json)` / `get_plc_log(did)` (PLC audit log persistence). All methods require DID to be registered first (returns `IdentityNotFound` otherwise). `IdentityStoreError` enum: IDENTITY_NOT_FOUND, IDENTITY_ALREADY_EXISTS, KEYCHAIN_ERROR, KEY_GENERATION_FAILED, SERIALIZATION_ERROR (serialized as `{ code: "SCREAMING_SNAKE_CASE" }`)
- `src/pds_client.rs` — PDS discovery and OAuth module for arbitrary PDS endpoints (not just our relay). `PdsClient` struct (stateless, wraps a `reqwest::Client` + plc.directory URL). Public API: `plc_directory_url() -> &str` (returns the plc.directory base URL), `client() -> &Client` (returns the inner reqwest client), `resolve_handle(handle) -> Result<String, PdsClientError>` (DNS TXT `_atproto.{handle}` with HTTP `/.well-known/atproto-did` fallback), `discover_pds(did) -> Result<(String, PlcDidDocument), PdsClientError>` (fetches DID doc from plc.directory, extracts `atproto_pds` endpoint, verifies reachability via HEAD), `discover_auth_server(pds_url) -> Result<AuthServerMetadata, PdsClientError>` (fetches `/.well-known/oauth-authorization-server`, validates `code` response type + S256 challenge method), `pds_par(metadata, pkce_challenge, state, dpop_proof, dpop_jkt, login_hint?) -> Result<PdsParResponse, PdsClientError>` (PAR to arbitrary PDS), `pds_token_exchange(metadata, code, pkce_verifier, dpop_proof) -> Result<reqwest::Response, PdsClientError>` (returns raw response for caller nonce-retry), `build_pds_authorize_url(metadata, request_uri, login_hint?) -> String` (constructs browser redirect URL), `fetch_audit_log(did) -> Result<String, PdsClientError>` (fetches PLC operation audit log as raw JSON from `{plc_directory_url}/{did}/log/audit`), `post_plc_operation(did, operation) -> Result<(), PdsClientError>` (POSTs signed PLC operation JSON to `{plc_directory_url}/{did}`). Module-level XRPC functions (take `&OAuthClient`): `request_plc_operation_signature(client)`, `sign_plc_operation(client, request)`, `get_recommended_did_credentials(client)`. Types: `PlcDidDocument` (Clone), `PlcService` (Clone), `AuthServerMetadata`, `PdsParResponse`, `SignPlcOperationRequest`, `SignPlcOperationResponse`, `RecommendedCredentials`. `PdsClientError` enum: HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR, INVALID_RESPONSE, OAUTH_FAILED (serialized as `{ code: "SCREAMING_SNAKE_CASE" }`)
- `src/plc_monitor.rs` — PLC monitoring module: `PlcMonitor` (borrows `PdsClient`; `check_all()` iterates all managed DIDs, `check_for_changes(did)` diffs current audit log against cached log and classifies new entries as authorized/unauthorized by verifying signatures against the device key); `run_monitoring_loop(app_handle)` (spawned once at app startup, checks every 15 minutes via `tokio::time::interval` with `MissedTickBehavior::Delay`, emits `"plc_alert"` Tauri event to frontend when unauthorized changes detected); `check_identity_status` (Tauri IPC command: synchronous foreground check of all managed identities, returns `Vec<IdentityStatus>`). Types: `UnauthorizedChange` { cid, created_at, signing_key, operation } (camelCase serialization), `IdentityStatus` { did, alert_count, unauthorized_changes } (camelCase serialization), `MonitorError` { NetworkError, IdentityStoreError, ParseError } (SCREAMING_SNAKE_CASE tag serialization)
- `src/recovery.rs` — Recovery override module: `build_recovery_override(pds_client, did, unauthorized_op_cid) -> Result<SignedRecoveryOp, RecoveryError>` (fetches audit log, identifies fork point, builds counter-operation restoring pre-unauthorized state, signs with per-DID device key), `submit_recovery_override(pds_client, did, signed_op) -> Result<ClaimResult, RecoveryError>` (POSTs to plc.directory, updates cached log and DID doc); Tauri IPC commands: `build_recovery_override_cmd`, `submit_recovery_override_cmd`. Types: `SignedRecoveryOp` { diff, signed_op }, `RecoveryState` { did, signed_op }, `RecoveryError` (RECOVERY_WINDOW_EXPIRED, SIGNING_FAILED, PLC_DIRECTORY_ERROR, NETWORK_ERROR, IDENTITY_NOT_FOUND, UNAUTHORIZED_CHANGE_NOT_FOUND)
- `src/lib.rs::check_identity_status() -> Result<Vec<IdentityStatus>, MonitorError>` — Tauri IPC command (delegates to `PlcMonitor::check_all`)
- `src/lib.rs::list_identities() -> Result<Vec<String>, IdentityStoreError>` — Tauri IPC command: returns managed DIDs from Keychain via `IdentityStore::list_identities()`; returns empty list if no identities claimed
- `src/lib.rs::get_stored_did_doc(did: String) -> Result<Option<serde_json::Value>, IdentityStoreError>` — Tauri IPC command: retrieves stored DID document as parsed JSON for a claimed identity; returns None if not stored
- `src/lib.rs::get_device_key_id(did: String) -> Result<String, IdentityStoreError>` — Tauri IPC command: returns the device key's did:key URI for a claimed identity via `IdentityStore::get_or_create_device_key()`
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
- `ClaimState` in `AppState` uses `tokio::sync::Mutex` (not `std::sync::Mutex`) because claim commands hold the lock across `.await` points; initialized to `None` in `AppState::new()`
- `claim::resolve_identity` stores `ClaimState` in `AppState` for use by subsequent claim commands; calling it again resets the claim flow
- `plc_monitor::run_monitoring_loop` is spawned once during `setup()` in `lib.rs`; skips the first immediate tick (lets app finish initializing); uses `MissedTickBehavior::Delay` so iOS app suspension does not cause burst-fire of missed checks
- `plc_monitor::check_for_changes` returns `Ok(vec![])` (not an error) when plc.directory is unreachable or the audit log cannot be parsed; errors are logged via `tracing::warn` and the monitor retries on the next cycle
- `plc_monitor::check_for_changes` classifies new audit log entries by verifying signatures against the per-DID device key; entries signed by the device key are authorized (silently consumed); entries signed by any other key produce an `UnauthorizedChange` alert
- `plc_monitor::check_for_changes` updates the cached PLC audit log in Keychain (via `IdentityStore::store_plc_log`) after processing; subsequent cycles only see entries newer than the cache
- `MonitorError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the existing error pattern
- `UnauthorizedChange.created_at` is the ISO 8601 timestamp from plc.directory's audit log; the frontend computes the 72-hour recovery deadline from this value
- `IdentityListHome` accepts an optional `onalert` callback prop `(did: string, changes: UnauthorizedChange[]) => void`; identity cards display an alert badge when `alertData` has entries for that DID
- `AlertDetailScreen` accepts `did`, `changes: UnauthorizedChange[]`, `onback` callback, and `onoverride: (cid: string, createdAt: string) => void` callback props; displays each unauthorized change with signing key, recovery deadline, and urgency coloring; "Review & Override" button calls `onoverride` (disabled when urgency is `'expired'`); updates countdown every 60 seconds via `setInterval`
- `RecoveryOverrideScreen` accepts `did`, `operationCid`, `createdAt`, `onback`, and `onsuccess` callback props; calls `buildRecoveryOverride()` on mount, displays the signed operation diff for user review, then calls `submitRecoveryOverride()` on confirmation; shows recovery deadline countdown and error states
- `claim::start_pds_auth` reuses the existing deep-link callback mechanism (`pending_auth` oneshot channel) and emits `"pds_auth_ready"` event to the frontend on success
- `claim::sign_and_verify_claim` performs 4-point local verification: (1) rotationKeys[0] is the device key, (2) `prev` CID chains correctly against the audit log, (3) no unexpected key additions or removals, (4) no unexpected service mutations
- `claim::submit_claim` clears `ClaimState` on success (not on failure, allowing retries); validates caller DID matches `ClaimState.did` (defense-in-depth)
- `claim::submit_claim` persists identity via `IdentityStore`: registers DID, ensures device key, stores re-fetched DID document and PLC audit log; tolerates `IdentityAlreadyExists` from prior partial claims
- `ResolveError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the existing error pattern
- `ClaimError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the existing error pattern; both use `thiserror::Error` for Display impls
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
- Rust backend -> arbitrary PDS endpoints (via `reqwest` HTTP at runtime; used by `PdsClient` for OAuth discovery, PAR, token exchange, XRPC identity methods, and claim flow PDS authentication)
- Rust backend -> plc.directory `GET /{did}/log/audit` endpoint (via `PdsClient::fetch_audit_log`; fetches PLC operation audit log for signature verification during claim and recovery flows)
- Rust backend -> plc.directory `POST /{did}` endpoint (via `PdsClient::post_plc_operation`; submits signed PLC operations during claim and recovery flows)
- Rust backend -> plc.directory `GET /{did}` endpoint (via `PdsClient::client()` direct HTTP; fetches DID document after recovery override to update cache)
- Rust backend -> `hickory-resolver` (workspace dep: DNS TXT resolution for ATProto handle verification in `pds_client::try_resolve_dns`)
- Rust backend -> `urlencoding` (workspace dep: URL-encoding for OAuth authorize URL construction in `PdsClient::build_pds_authorize_url`)
- Rust backend -> `chrono` (workspace dep: date/time parsing for recovery window computation in `recovery.rs`)
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

# 4. Apply post-init patches (Run Script phase PATH + sandbox config + swift-rs patch)
cd .. # back to workspace root
just ios-postinit
```

Note: `src-tauri/gen/` contains a machine-specific Xcode project. It is gitignored and must be re-generated on each developer machine. Do not commit it.

### After every `cargo tauri ios init`: run `just ios-postinit`

`cargo tauri ios init` regenerates the gitignored Xcode project at
`src-tauri/gen/apple/`. Three workarounds must be (re-)applied to it. This is now
a single idempotent command, run from the repo root:

```bash
just ios-postinit
```

It (1) verifies the `swift-rs` `--disable-sandbox` patch is wired in the workspace
`Cargo.toml`, (2) sets `ENABLE_USER_SCRIPT_SANDBOXING = NO` (macOS 26 + Xcode
sandbox blocks Cargo's directory walk), and (3) injects `PATH` + `source
scripts/ios-env.sh` into the "Build Rust Code" Run Script phase (that phase does
not inherit the dev-shell environment). Verify at any time with `just ios-check`.

### Why rustup instead of Nix-managed Rust

`languages.rust` in devenv uses Nix's `rust-default` package, which only ships stdlibs for standard host targets. iOS Simulator requires `aarch64-apple-ios-sim` stdlib. Nix doesn't package iOS cross-compilation stdlibs; `rustup` downloads them from the Rust release infrastructure. The dev shell is configured with project-local `RUSTUP_HOME` and `CARGO_HOME` (inside `.devenv/state/`) so the toolchain is isolated per project.

The Apple toolchain (clang/ar/SDKs/`DEVELOPER_DIR`) is resolved dynamically by
`scripts/ios-env.sh` via `xcrun`/`xcode-select` — there are no hardcoded Xcode
paths, so the build follows whatever Xcode `xcode-select` points at. `ios-env.sh`
is sourced by the devenv `enterShell` and by the patched Xcode Run Script phase.

## Development Workflow

The primary iOS build commands are `just ios-dev` and `just ios-build`, run from the
workspace root:

```bash
# Enter the dev shell if not already active (MUST be run from the workspace root,
# not from apps/identity-wallet/ — CARGO_HOME resolves relative to devenv root)
nix develop --impure --accept-flake-config

# Launch the app in the iOS Simulator (starts pnpm dev + Rust compilation + Simulator)
just ios-dev

# Build (Xcode project only; does not launch Simulator)
just ios-build
```

Both commands automatically source `apps/identity-wallet/scripts/ios-env.sh` to set up
the Apple toolchain and run `just ios-postinit` to re-apply patches after Xcode init.

**Do not click Run in Xcode directly.** `just ios-dev` starts a JSON-RPC server that
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
- **Toolchain configuration**: `apps/identity-wallet/scripts/ios-env.sh` derives the Apple toolchain dynamically for cross-compiling to iOS (resolves `DEVELOPER_DIR` via `/usr/bin/xcode-select`, sets `CC`/`AR`/linker overrides for iOS and macOS-host targets via environment variables). The macOS-host `CC`/`AR` overrides are needed for `security-framework`'s C build scripts which fail under Nix's cc-wrapper. `src-tauri/.cargo/config.toml` now only holds `RUST_TEST_THREADS=1`; all toolchain overrides moved to the shell script for Phase 1 de-Nix compliance. See the Troubleshooting section for the full explanation.
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
- **Claim flow as multi-step state machine (`claim.rs`)**: The 5 claim commands form a sequential pipeline: `resolve_identity` -> `start_pds_auth` -> `request_claim_verification` -> `sign_and_verify_claim` -> `submit_claim`. State is persisted in `AppState.claim_state` (tokio::sync::Mutex) across commands. Each command validates prerequisites (e.g. `start_pds_auth` requires `ClaimState` to exist, `request_claim_verification` requires `pds_oauth_client`). The `_impl` test helpers extract core logic away from Tauri's `State` wrapper.
- **PDS OAuth reuses deep-link mechanism**: `start_pds_auth` reuses the same `pending_auth` oneshot channel and `handle_deep_link` callback as `start_oauth_flow` in `oauth.rs`, so both relay OAuth and PDS OAuth share a single deep-link handler. Only one OAuth flow can be in progress at a time.
- **PlcDidDocument and PlcService derive Clone**: Added to support cloning claim state data out of the tokio Mutex before releasing the lock for network calls. This pattern avoids holding the Mutex across `.await` points.
- **Mode selector as entry point**: The app starts at `mode_select` (not `relay_config`), offering two paths: "Create new identity" (original onboarding flow) and "Import existing identity" (claim flow). On mount, `+page.svelte` calls `listIdentities()` and skips directly to `home` if any identities exist. This identity-aware routing replaces the previous relay-URL-based skip logic.
- **IdentityListHome replaces HomeScreen at `home` step**: The `home` state now renders `IdentityListHome` (multi-identity card list) instead of the single-identity `HomeScreen`. `IdentityListHome` shows all managed identities with handle, PDS URL, and rotation key status badges. Tapping an identity navigates to `identity_detail` (renders `DIDDocumentScreen`). The original `HomeScreen` component still exists for legacy relay-authenticated sessions but is no longer wired into the state machine.
- **Identity store IPC commands are synchronous**: `list_identities`, `get_stored_did_doc`, and `get_device_key_id` are non-async Tauri commands (no `async fn`, no `State<>` parameter) -- they call `IdentityStore` methods directly since Keychain access is synchronous. This differs from most other Tauri commands which are async and take `State<AppState>`.
- **PLC monitoring: background timer + foreground check**: Two complementary mechanisms detect unauthorized PLC operations. (1) A background `tokio::time::interval` loop runs every 15 minutes, spawned once at app startup via `run_monitoring_loop`. (2) A `visibilitychange` listener in `+page.svelte` calls `checkIdentityStatus()` when the app returns to foreground. The timer uses `MissedTickBehavior::Delay` so iOS app suspension does not cause burst-fire of missed ticks.
- **PlcMonitor borrows PdsClient**: `PlcMonitor` takes `&PdsClient` (not owned) because `PdsClient` is a shared singleton on `AppState`. The monitor is constructed fresh on each cycle from the managed `AppState` reference, avoiding lifetime issues with long-lived borrows across async boundaries.
- **Graceful degradation on network errors**: `check_for_changes` returns `Ok(vec![])` when plc.directory is unreachable or audit log parsing fails, rather than surfacing errors to the UI. This prevents false alarms or error screens when the user has no network connectivity. Errors are logged via `tracing::warn` for diagnostics.
- **Signing key identification**: When an unauthorized change is detected, `identify_signing_key` attempts to identify the signer by trying each rotation key from the previous operation in the audit log. If no key matches, `signing_key` is `None`. This is best-effort -- the signer may have used a key not in the previous rotation key set.
- **Vitest for frontend unit tests**: `vitest` added as a dev dependency with `pnpm test` script (`vitest run`). Used for pure-logic utilities (e.g. `deadline.ts`) that do not require Tauri IPC mocking.
- **AlertDetailScreen countdown**: `AlertDetailScreen` updates `now` via a 60-second `setInterval`, which re-computes urgency and countdown display. The timer is cleaned up in `onDestroy` to prevent leaks if the component is unmounted.

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
- `ResolveError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `ResolveError` union must match exactly (HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR)
- `ClaimError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `ClaimError` union must match exactly (INVALID_TOKEN, VERIFICATION_FAILED, PLC_DIRECTORY_ERROR, UNAUTHORIZED, NETWORK_ERROR)
- `IdentityStoreError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `IdentityStoreError.code` union must match exactly (IDENTITY_NOT_FOUND, IDENTITY_ALREADY_EXISTS, KEYCHAIN_ERROR, KEY_GENERATION_FAILED, SERIALIZATION_ERROR)
- `MonitorError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript consumer (if any) must match exactly (NETWORK_ERROR, IDENTITY_STORE_ERROR, PARSE_ERROR)
- `UnauthorizedChange` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ cid, createdAt, signingKey, operation }`; the TypeScript `UnauthorizedChange` type in `ipc.ts` must match exactly
- `IdentityStatus` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ did, alertCount, unauthorizedChanges }`; the TypeScript `IdentityStatus` type in `ipc.ts` must match exactly
- Tauri event `"plc_alert"` payload is `Vec<IdentityStatus>` (JSON array of identity statuses); the frontend `IdentityListHome` component listens for this event to update alert badges in real time
- PLC monitoring interval is 15 minutes (`MONITOR_INTERVAL_SECS = 900`); changing this constant alters battery/network impact
- Recovery deadline window is 72 hours (`RECOVERY_WINDOW_MS` in `deadline.ts`); this matches the PLC directory's 72-hour recovery window specification
- OAuth client_id is always `"dev.malpercio.identitywallet"` -- must match the seeded row in relay migration V013 and the `tauri.conf.json` bundle identifier
- OAuth redirect_uri is always `"dev.malpercio.identitywallet:/oauth/callback"` -- must match the deep-link scheme in `tauri.conf.json` and the seeded client_metadata redirect_uris in V013
- `DevicePublicKey` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ multibase, keyId }` (not `key_id`)
- `HomeData` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ relayHealthy, session, sessionError, share1InKeychain }`; the TypeScript `HomeData` type in `ipc.ts` must match exactly
- `SessionInfo` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ did, handle, email, emailConfirmed, didDoc }`; the TypeScript `SessionInfo` type in `ipc.ts` must match exactly
- `log_out` deletes exactly three Keychain accounts: `"oauth-access-token"`, `"oauth-refresh-token"`, `"did"` -- adding or removing items from this list changes what data survives a logout
- Keychain account `"managed-dids"` stores a JSON array of all managed DID strings (e.g. `["did:plc:abc","did:plc:def"]`); the single source of truth for which identities are registered in `IdentityStore`
- Per-DID Keychain accounts follow the `"{did}:suffix"` pattern with six suffixes: `device-key` (P-256 private key scalar, software path only; not written on SE path), `device-key-pub` (compressed public key, SE path only), `device-key-app-label` (SE application_label, SE path only), `did-doc` (opaque DID document JSON), `plc-log` (opaque PLC audit log JSON), `oauth-tokens` (reserved for per-DID OAuth tokens)
- `IdentityStore` P-256 multicodec prefix `[0x80, 0x24]` is duplicated from `crates/crypto/src/keys.rs` (same rationale as `device_key.rs` -- `pub(crate)` constant cannot be imported cross-crate)
- `RecoveryError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `RecoveryError` union in `ipc.ts` must match exactly
- `SignedRecoveryOp` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ diff, signedOp }`
- Recovery window is 72 hours from the unauthorized operation's `created_at` timestamp; computed locally but enforced by plc.directory
- `RecoveryState` in `AppState` uses `tokio::sync::Mutex` (same as `ClaimState`) because recovery commands hold the lock across `.await` points

## Key Files

- `src-tauri/tauri.conf.json` -- Tauri config: bundle ID, devUrl, frontendDist, window settings
- `src-tauri/src/lib.rs` -- Tauri IPC commands (`get_relay_url`, `save_relay_url`, `create_account`, `get_or_create_device_key`, `sign_with_device_key`, `perform_did_ceremony`, `start_oauth_flow`, `home::load_home_data`, `home::log_out`, `claim::resolve_identity`, `claim::start_pds_auth`, `claim::request_claim_verification`, `claim::sign_and_verify_claim`, `claim::submit_claim`, `list_identities`, `get_stored_did_doc`, `get_device_key_id`, `plc_monitor::check_identity_status`, `recovery::build_recovery_override_cmd`, `recovery::submit_recovery_override_cmd`), `run()` (mobile entry point), deep-link plugin setup, startup token restore, PLC monitoring loop spawn
- `src-tauri/src/home.rs` -- Home screen Tauri commands: `load_home_data` (concurrent relay health + getSession), `log_out` (Keychain wipe + session clear); output types: HomeData, SessionInfo
- `src-tauri/src/device_key.rs` -- P-256 device key module: `#[cfg]`-dispatched `get_or_create()` and `sign()` (simulator software path vs. Secure Enclave)
- `src-tauri/src/identity_store.rs` -- Multi-identity Keychain management: IdentityStore (add/remove/list identities, per-DID device key generation, DID doc + PLC log persistence)
- `src-tauri/src/claim.rs` -- PLC rotation key claim flow: 5 Tauri IPC commands (resolve_identity, start_pds_auth, request_claim_verification, sign_and_verify_claim, submit_claim); types (IdentityInfo, VerifiedClaimOp, OpDiff, ServiceChange, ClaimResult, ClaimState); error enums (ResolveError, ClaimError)
- `src-tauri/src/plc_monitor.rs` -- PLC monitoring: PlcMonitor (check_all, check_for_changes), run_monitoring_loop (15-min background timer), check_identity_status (IPC command); types (UnauthorizedChange, IdentityStatus, MonitorError)
- `src-tauri/src/recovery.rs` -- Recovery override: build_recovery_override_cmd, submit_recovery_override_cmd; fork-point identification, per-DID signing, recovery window check
- `src-tauri/src/pds_client.rs` -- PDS discovery and OAuth to arbitrary PDS: PdsClient (resolve_handle, discover_pds, discover_auth_server, pds_par, pds_token_exchange, build_pds_authorize_url, fetch_audit_log, post_plc_operation); XRPC identity functions (request_plc_operation_signature, sign_plc_operation, get_recommended_did_credentials)
- `src-tauri/src/main.rs` -- Desktop entry point (calls `lib::run()`)
- `src-tauri/src/oauth.rs` -- OAuth PKCE module: AppState, DPoPKeypair, OAuthSession, PKCE utilities, start_oauth_flow command, handle_deep_link
- `src-tauri/src/oauth_client.rs` -- OAuthClient: authenticated HTTP client with DPoP proofs and lazy token refresh
- `src-tauri/src/keychain.rs` -- iOS Keychain abstraction (store_item, get_item, delete_item); Relay URL helpers (store_relay_url, load_relay_url); OAuth helpers (store_dpop_key, load_dpop_key, store_oauth_tokens, load_oauth_tokens)
- `src-tauri/src/http.rs` -- RelayClient with runtime-configurable base URL; OAuth methods (par, token_exchange)
- `src-tauri/.cargo/config.toml` -- Cargo configuration: `RUST_TEST_THREADS=1` (prevent test race conditions)
- `apps/identity-wallet/scripts/ios-env.sh` -- Apple toolchain derivation for iOS cross-compilation: resolves `DEVELOPER_DIR` via `/usr/bin/xcode-select`, sets `CC`/`AR`/linker overrides for iOS and macOS-host targets via environment variables
- `src/lib/ipc.ts` -- Typed TypeScript wrappers for all Tauri IPC commands (getRelayUrl, saveRelayUrl, createAccount, getOrCreateDeviceKey, signWithDeviceKey, performDIDCeremony, startOAuthFlow, loadHomeData, logOut, resolveIdentity, startPdsAuth, requestClaimVerification, signAndVerifyClaim, submitClaim, listIdentities, getStoredDidDoc, getDeviceKeyId, checkIdentityStatus, buildRecoveryOverride, submitRecoveryOverride)
- `src/lib/components/onboarding/` -- Eighteen onboarding screen components (ModeSelectScreen, RelayConfigScreen, WelcomeScreen, ClaimCodeScreen, EmailScreen, HandleScreen, PasswordScreen, LoadingScreen, DIDCeremonyScreen, DIDSuccessScreen, ShamirBackupScreen, HandleRegistrationScreen, AuthenticatingScreen, IdentityInputScreen, PdsAuthScreen, EmailVerificationScreen, ReviewOperationScreen, ClaimSuccessScreen)
- `src/lib/components/home/` -- Six home screen components (IdentityListHome, HomeScreen, DIDDocumentScreen, RecoveryInfoScreen, AlertDetailScreen, RecoveryOverrideScreen) plus DIDAvatar utility component
- `src/lib/utils/deadline.ts` -- PLC recovery deadline utilities (getDeadline, getUrgency, formatCountdown); tested by `deadline.test.ts`
- `src/routes/+page.svelte` -- Two-flow state machine starting at mode_select; Create flow: mode_select -> relay_config -> ... -> home; Import flow: mode_select -> identity_input -> pds_auth -> email_verification -> review_operation -> claim_success -> home; Home: home (IdentityListHome) -> identity_detail -> did_document / recovery_info / alert_detail -> recovery_override; visibilitychange handler calls checkIdentityStatus() on foreground
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

**Fix:** Already resolved automatically. `devenv.nix`'s `enterShell` sources `apps/identity-wallet/scripts/ios-env.sh`, which calls `/usr/bin/xcode-select -p` to resolve the real Xcode path and re-exports `DEVELOPER_DIR` to point at it. This happens after all Nix hooks run, so the corrected `DEVELOPER_DIR` takes precedence. Additionally, `just ios-postinit` re-applies this patching to the Xcode Run Script phase each time after `cargo tauri ios init`.

If you still see this: verify with `echo $DEVELOPER_DIR` inside the dev shell. If it shows a Nix store path, exit and re-enter the shell from the workspace root.

---

### `sandbox-exec: sandbox_apply: Operation not permitted` (Tauri ios-api build)

Swift Package Manager sandboxes its manifest compilation using `sandbox-exec`. On macOS 26 (Tahoe), `sandbox_apply()` returns `EPERM` in this context, causing `swift-rs`'s build script (used by Tauri) to fail with "Failed to compile swift package Tauri".

**Fix:** Already resolved and applied automatically. A local patch of `swift-rs` 1.0.7 at `apps/identity-wallet/swift-rs-patch/` adds `--disable-sandbox` to the `swift build` invocation inside `SwiftLinker::link`. The workspace `Cargo.toml` wires this in via `[patch.crates-io]`. See `docs/ios-upstream-bugs.md` for details. Remove the patch entry when swift-rs ships a fix upstream.

---

### `Failed to update the excludes stack to see if a path is excluded` (Xcode user script sandbox)

Xcode 14+ enables `ENABLE_USER_SCRIPT_SANDBOXING=YES` by default in generated projects, wrapping Run Script build phases in `sandbox-exec`. On macOS 26 (Tahoe), this sandbox blocks Cargo's `readdir()` calls during package fingerprinting, producing:

```
error: failed to determine package fingerprint for build script for identity-wallet v0.1.0
Caused by: Failed to update the excludes stack to see if a path is excluded
```

**Fix:** Already resolved automatically. `just ios-postinit` sets `ENABLE_USER_SCRIPT_SANDBOXING = NO` in the generated `project.pbxproj` after each `cargo tauri ios init`, and `just ios-check` verifies the setting is in place.
