# Obsign (identity-wallet) Mobile App

Last verified: 2026-07-08
Last updated: 2026-07-12

## Purpose

Tauri v2 iOS application — SvelteKit 2 + Svelte 5 frontend running in a native WKWebView, communicating with a Rust backend exclusively through Tauri's IPC bridge. First frontend code in the repository.

## Contracts

### Frontend (SvelteKit 2 + Svelte 5)

**Exposes:**
- `src/lib/ipc.ts` — typed wrappers for all Tauri IPC commands; import these instead of calling `invoke()` directly. Exports: `createAccount()`, `getOrCreateDeviceKey()`, `signWithDeviceKey()`, `performDIDCeremony()`, `registerHandle()`, `getAvailableUserDomains()`, `registerCreatedIdentity()`, `startOAuthFlow()`, `loadHomeData()`, `logOut()`, `getPdsUrl()`, `savePdsUrl()`, `getAppearancePreference()`, `setAppearancePreference()`, `resolveIdentity()`, `authenticateSourcePds()`, `requestClaimVerification()`, `signAndVerifyClaim()`, `submitClaim()`, `listIdentities()`, `getStoredDidDoc()`, `getDeviceKeyId()`, `checkIdentityStatus()`, `buildRecoveryOverride()`, `submitRecoveryOverride()`, and their associated types (`DevicePublicKey`, `DeviceKeyError`, `CreateAccountResult`, `CreateAccountError`, `DIDCeremonyResult`, `DIDCeremonyError`, `RegisterHandleResult`, `RegisterHandleError`, `RegisterIdentityError`, `OAuthError`, `SessionInfo`, `HomeData`, `PdsConfigError`, `AppearancePreference`, `AppearanceError`, `IdentityInfo`, `VerifiedClaimOp`, `OpDiff`, `ServiceChange`, `ClaimResult`, `ResolveError`, `ClaimError`, `IdentityStoreError`, `UnauthorizedChange`, `IdentityStatus`, `SignedRecoveryOp`, `RecoveryError`, `SignedMigrationOp`, `MigrateError`) and migration wrappers (`buildMigrationOp()`, `submitMigrationOp()`) and outbound-migration orchestrator wrappers (`prepareMigration()`, `authenticateMigrationSource()`, `createDestinationAccount()`, `transferRepo()`, `transferBlobs()`, `transferPreferences()`, `verifyImport()`, `armIdentityLeg()`, `finalizeMigration()`) with types (`AccountStatus`, `PreparedMigration`, `MigrationError`)
- `src/lib/components/onboarding/` — seventeen onboarding screen components (ModeSelectScreen, PdsConfigScreen, ClaimCodeScreen, EmailScreen, HandleScreen, PasswordScreen, LoadingScreen, DIDCeremonyScreen, DIDSuccessScreen, ShamirBackupScreen, HandleRegistrationScreen, AuthenticatingScreen, IdentityInputScreen, PdsAuthScreen, EmailVerificationScreen, ReviewOperationScreen, ClaimSuccessScreen)
- `src/lib/components/home/` — nine home screen components (IdentityListHome, HomeScreen, DIDDocumentScreen, RecoveryInfoScreen, AlertDetailScreen, RecoveryOverrideScreen, MyAgentsScreen, AgentClaimApprovalScreen, SettingsScreen) plus DIDAvatar utility component (deterministic DID-derived hue circle)
- `src/lib/appearance.ts` — in-app appearance override (System / Light / Dark): `normalizePreference()` / `toColorScheme()` (pure, tested by `appearance.test.ts`), `readLocalMirror()`, `initAppearance()` (launch-time reconcile: re-asserts the localStorage mirror, then reads the Keychain via IPC and lets it win), `setAppearance()` (applies the inline `color-scheme` override on `<html>` instantly, writes the mirror, then persists to the Keychain). The localStorage mirror (key `appearance-preference`) exists only so `src/app.html`'s inline `<head>` script can apply a forced appearance before first paint; the Keychain is the source of truth
- `src/lib/agent-scopes.ts` — plain-language descriptions of granular OAuth scope tokens for the agent-consent surfaces: `describeScope(token)` / `describeScopes(tokens)` return `{ summary, token, elevated }` (the raw token is always shown alongside the human sentence; `account:*`/`identity:*`/full-access grants are flagged `elevated`; an unknown token falls back to showing itself, never a vague label). Tested by `agent-scopes.test.ts`
- `src/lib/utils/deadline.ts` — PLC recovery deadline utilities: `getDeadline(createdAt)` (adds 72h to ISO 8601 timestamp), `getUrgency(deadline)` (returns `'safe'` | `'warning'` | `'critical'` | `'expired'`), `formatCountdown(deadline)` (human-readable `"Xh Ym remaining"`). `Urgency` type exported. Thresholds: expired = 0, critical < 4h, warning < 24h, safe >= 24h
- `src/routes/+page.svelte` — root page: two-flow state machine starting at `mode_select`. **Create flow:** mode_select -> pds_config -> claim_code -> email -> handle -> password (every pre-submit step wires `onback` to the previous step) -> loading -> did_ceremony -> did_success -> shamir_backup -> handle_registration -> complete -> authenticating -> home (after handle_registration succeeds, `finishCreateFlow()` calls `registerCreatedIdentity()` to persist the new identity to `IdentityStore` so it appears in `IdentityListHome` — best-effort, never blocks the flow). **Import flow:** mode_select -> identity_input -> pds_auth -> email_verification -> review_operation -> claim_success -> home. **Home:** home -> identity_detail -> did_document / recovery_info / alert_detail -> recovery_override. On mount, checks for existing identities via `listIdentities()` and skips to `home` if any exist. Registers a `visibilitychange` listener that calls `checkIdentityStatus()` when the app returns to foreground while on the `home` step

**Guarantees:**
- SSR is disabled globally (`ssr = false` in `src/routes/+layout.ts`); the frontend is a fully static SPA loaded from disk by WKWebView
- Build output lands in `dist/` (configured via `pages: 'dist'` in `svelte.config.js`)
- Frontend calls Tauri commands only through `src/lib/ipc.ts` — no raw `invoke()` calls in page components
- PDS error codes from `create_account` are mapped back to the originating screen (e.g. EXPIRED_CODE -> claim_code step, EMAIL_TAKEN -> email step)

**Expects:**
- `pnpm install` has been run in `apps/identity-wallet/`
- Node.js 22.x is in PATH (provided by the Nix dev shell)

### Rust Backend (src-tauri/)

**Exposes:**
- `src/lib.rs::create_account(claim_code, email, handle) -> Result<CreateAccountResult, CreateAccountError>` — Tauri IPC command: gets or creates device key via `device_key::get_or_create()`, POSTs to PDS `/v1/accounts/mobile`, stores tokens in Keychain on success
- `src/lib.rs::get_or_create_device_key() -> Result<DevicePublicKey, DeviceKeyError>` — Tauri IPC command: delegates to `device_key::get_or_create()`
- `src/lib.rs::sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError>` — Tauri IPC command: delegates to `device_key::sign()`
- `src/lib.rs::perform_did_ceremony(handle: String, password: String) -> Result<DIDCeremonyResult, DIDCeremonyError>` — Tauri IPC command: fetches PDS signing key (GET /v1/pds/keys), builds signed did:plc genesis op via `crypto::build_did_plc_genesis_op_with_external_signer` using device key as signer, POSTs genesis op + password to PDS (POST /v1/dids with Bearer token), persists DID + upgraded session token + Share 1 in Keychain, returns `{ did, share3 }` to frontend
- `src/home.rs` — Home screen data module: `load_home_data(AppState) -> Result<HomeData, String>` (Tauri IPC command: fires GET /xrpc/_health and GET /xrpc/com.atproto.server.getSession concurrently via OAuthClient; always succeeds -- partial failures encoded as HomeData fields); `log_out(AppState) -> Result<(), String>` (Tauri IPC command: deletes oauth-access-token, oauth-refresh-token, and did from Keychain, clears in-memory oauth_session; always succeeds -- Keychain errors swallowed); output types: `HomeData` { pds_healthy, session, session_error, share1_in_keychain }, `SessionInfo` { did, handle, email, email_confirmed, did_doc }
- `src/oauth.rs` — OAuth PKCE client module: `AppState` (pending_login + oauth_session mutexes + custos_client OnceLock + pds_client + claim_state + recovery_state + migration_state + orchestration_state; both source logins — the claim flow and the outbound migration — are password-based `createSession`, so neither parks OAuth state — see `claim::authenticate_source_pds` / `migration_orchestrator::authenticate_migration_source`), `OAuthSession` (access/refresh/expiry/nonce), `DPoPKeypair` (P-256, persisted in Keychain), `OAuthError` enum, PKCE utilities (verifier + S256 challenge), `OAuthPrepared` (the `{authUrl, callbackScheme}` returned to the frontend), `prepare_oauth_flow` + `complete_oauth_flow` (the create-flow login split around the in-app auth session: prepare does DPoP keygen/PKCE/PAR → authorize URL and parks the verifier+CSRF in `pending_login`; complete validates the callback URL + does the token exchange), `parse_callback_url` (shared callback-URL parser, `pub(crate)`); `AppState::pds_client()` accessor exposes `PdsClient` for claim flow commands
- `src/claim.rs` — PLC rotation key claim flow module (5 Tauri IPC commands): `resolve_identity(handle_or_did) -> Result<IdentityInfo, ResolveError>` (resolves handle/DID to identity info via plc.directory, stores ClaimState), `authenticate_source_pds(did, identifier, password, auth_factor_token?) -> Result<(), ClaimError>` (**password `createSession`** against the source PDS → full-session Bearer `OAuthClient` stored in ClaimState; the next steps are PLC/identity ops that no OAuth `transition:generic` token can drive, so a full session is required — ADR-0021/MM-289; the password is used once and never stored. An email-2FA account returns `TwoFactorRequired` on the token-less attempt — the PDS emails a code and the UI re-invokes with `auth_factor_token`), `request_claim_verification(did) -> Result<(), ClaimError>` (calls `requestPlcOperationSignature` XRPC on old PDS to trigger email verification), `sign_and_verify_claim(did, token) -> Result<VerifiedClaimOp, ClaimError>` (calls `getRecommendedDidCredentials` and `signPlcOperation` on old PDS, fetches audit log, verifies signature + 4-point local checks, stores signed op in ClaimState), `submit_claim(did) -> Result<ClaimResult, ClaimError>` (POSTs signed op to plc.directory, persists identity to IdentityStore, clears ClaimState). Types: `IdentityInfo`, `VerifiedClaimOp`, `OpDiff`, `ServiceChange`, `ClaimResult`, `ClaimState`. Error enums: `ResolveError` (HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR), `ClaimError` (INVALID_TOKEN, VERIFICATION_FAILED, PLC_DIRECTORY_ERROR, UNAUTHORIZED, SOURCE_AUTH_FAILED, TWO_FACTOR_REQUIRED, ACCOUNT_MISMATCH, INSECURE_SOURCE_URL, INSUFFICIENT_SCOPE, RATE_LIMITED, SERVER_ERROR, NETWORK_ERROR)
- `src/oauth_client.rs` — `OAuthClient`: authenticated HTTP client supporting two auth modes selected at construction (private `AuthMode` enum): `new(session, base_url)` builds a **DPoP** client (wraps every request with `Authorization: DPoP {access_token}` + a `DPoP` proof header, transparent lazy refresh when the token has <60s remaining, automatic retry on `use_dpop_nonce` 400 responses); `new_bearer(access_jwt, refresh_jwt, base_url)` builds a **Bearer** client (`Authorization: Bearer {access_jwt}`, no DPoP proof/nonce dance, expiry derived from the access JWT's `exp` claim) — used for the migration destination-PDS session, which is created via a service-auth `createAccount` rather than an OAuth flow. Methods: `get(path)`, `post(path, body)` (JSON), `post_no_body(path)` (zero bytes, no `Content-Type` — for no-input XRPC procedures like `requestPlcOperationSignature`/`activateAccount`, whose lexicons define no input; a spec-strict PDS rejects any body — MM-291), `post_bytes(path, content_type, body)` (raw byte body — CAR repo import + blob upload)
- `src/device_key.rs` — P-256 device key management with `#[cfg]`-based dispatch: macOS/simulator uses software keys via `crypto` crate + Keychain storage; real iOS device uses Secure Enclave via `security-framework`. Public API: `get_or_create() -> Result<DevicePublicKey, DeviceKeyError>` (idempotent), `sign(data) -> Result<Vec<u8>, DeviceKeyError>`. Exposes `pub(crate)` account-name consts `DEVICE_KEY_PRIV_ACCOUNT` / `DEVICE_KEY_PUB_ACCOUNT` / `DEVICE_KEY_APP_LABEL_ACCOUNT` (single source of truth for the global device-key Keychain accounts; copied into per-DID slots by `IdentityStore::adopt_global_device_key`)
- `src/keychain.rs` — iOS Keychain abstraction (`store_item`, `get_item`, `delete_item`) under service `"ezpds-identity-wallet"`; PDS URL helpers: `store_pds_url`/`load_pds_url` (PDS base URL); OAuth helpers: `store_dpop_key`/`load_dpop_key` (P-256 DPoP private key scalar), `store_oauth_tokens`/`load_oauth_tokens` (access + refresh token pair)
- `src/http.rs` — `CustosClient` with runtime-configurable base URL (initialized via `AppState::set_custos_client(url)` on first launch; localhost:8080 debug fallback); methods: `post()`, `get()`, `post_with_bearer()`, `par()` (POST /oauth/par with DPoP proof), `token_exchange()` (POST /oauth/token with PKCE verifier); response types: `ParResponse`, `TokenResponse`, `TokenErrorResponse`
- `src/identity_store.rs` — `IdentityStore` unit struct for multi-identity Keychain management with per-DID namespacing. Public API: `add_identity(did)` (registers DID in managed-dids index), `remove_identity(did)` (deletes DID and all per-DID entries), `list_identities()` (returns managed DIDs), `get_or_create_device_key(did)` (lazy per-DID P-256 key generation), `adopt_global_device_key(did)` (aliases the per-DID device key to the global `device_key.rs` key by copying its Keychain material into the per-DID slot — used by the create flow, whose genesis op is signed with the global key before the DID exists), `store_did_doc(did, json)` / `get_did_doc(did)` (DID document persistence), `store_plc_log(did, json)` / `get_plc_log(did)` (PLC audit log persistence). All methods require DID to be registered first (returns `IdentityNotFound` otherwise). `IdentityStoreError` enum: IDENTITY_NOT_FOUND, IDENTITY_ALREADY_EXISTS, KEYCHAIN_ERROR, KEY_GENERATION_FAILED, SERIALIZATION_ERROR (serialized as `{ code: "SCREAMING_SNAKE_CASE" }`)
- `src/pds_client.rs` — PDS discovery and OAuth module for arbitrary PDS endpoints (not just our PDS). `PdsClient` struct (stateless, wraps a `reqwest::Client` + plc.directory URL). Public API: `plc_directory_url() -> &str` (returns the plc.directory base URL), `client() -> &Client` (returns the inner reqwest client), `resolve_handle(handle) -> Result<String, PdsClientError>` (DNS TXT `_atproto.{handle}` with HTTP `/.well-known/atproto-did` fallback), `discover_pds(did) -> Result<(String, PlcDidDocument), PdsClientError>` (fetches DID doc from plc.directory, extracts `atproto_pds` endpoint, verifies reachability via HEAD), `discover_auth_server(pds_url) -> Result<AuthServerMetadata, PdsClientError>` (fetches `/.well-known/oauth-authorization-server`, validates `code` response type + S256 challenge method), `pds_par(metadata, pkce_challenge, state, dpop_proof, dpop_jkt, login_hint?) -> Result<PdsParResponse, PdsClientError>` (PAR to arbitrary PDS), `pds_token_exchange(metadata, code, pkce_verifier, dpop_proof) -> Result<reqwest::Response, PdsClientError>` (returns raw response for caller nonce-retry), `build_pds_authorize_url(metadata, request_uri, login_hint?) -> String` (constructs browser redirect URL), `fetch_audit_log(did) -> Result<String, PdsClientError>` (fetches PLC operation audit log as raw JSON from `{plc_directory_url}/{did}/log/audit`), `post_plc_operation(did, operation) -> Result<(), PdsClientError>` (POSTs signed PLC operation JSON to `{plc_directory_url}/{did}`), `describe_server(pds_url) -> Result<DescribeServerResponse, PdsClientError>` (GET `com.atproto.server.describeServer` — probes an arbitrary PDS for its `did`/available-user-domains before migration), `create_session(pds_url, identifier, password, auth_factor_token?) -> Result<CreateSessionResponse, PdsClientError>` (POST `com.atproto.server.createSession` — the claim flow's password source login; a 401 maps to `PdsClientError::InvalidCredentials`, or `AuthFactorTokenRequired` when the account has email 2FA and no code was supplied; the returned JWTs feed `OAuthClient::new_bearer`). Module-level XRPC functions (take `&OAuthClient`): the claim helpers `request_plc_operation_signature(client)`, `sign_plc_operation(client, request)`, `get_recommended_did_credentials(client)`; and the outbound-migration helpers `get_service_auth(client, aud, lxm)`, `create_account_migration(client, request)` (maps HTTP 409 → `PdsClientError::DidAlreadyExists` for resume), `import_repo(client, car_bytes)`, `upload_blob(client, mime, bytes)`, `list_missing_blobs(client, cursor)`, `get_preferences(client)`, `put_preferences(client, prefs)`, `check_account_status(client)`, `activate_account(client)`, `deactivate_account(client)`. Every authenticated XRPC helper routes its non-2xx branch through the private `classify_xrpc_response(context, resp)` (→ pure `classify_xrpc_error(status, retry_after, body)`), so a server response is classified by status — `429 → RateLimited{retry_after}`, `401 → Unauthorized`, else `XrpcError{status, error, message}` carrying the atproto error envelope — instead of being flattened into `NetworkError` (MM-290). `NetworkError` is now transport-only. Types: `PlcDidDocument` (Clone), `PlcService` (Clone), `AuthServerMetadata`, `PdsParResponse`, `SignPlcOperationRequest`, `SignPlcOperationResponse`, `RecommendedCredentials`, plus migration types `DescribeServerResponse`, `ServiceAuthToken`, `CreateAccountMigrationRequest`, `CreateAccountResponse`, `CreateSessionResponse`, `MissingBlob`/`MissingBlobs`, `UploadBlobResponse`, `AccountStatus` (from `checkAccountStatus`). `PdsClientError` enum: HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR, RATE_LIMITED, UNAUTHORIZED, XRPC_ERROR, INVALID_RESPONSE, OAUTH_FAILED, DID_ALREADY_EXISTS, INVALID_CREDENTIALS, AUTH_FACTOR_TOKEN_REQUIRED, INSECURE_PDS_URL (serialized as `{ code: "SCREAMING_SNAKE_CASE" }`)
- `src/plc_monitor.rs` — PLC monitoring module: `PlcMonitor` (borrows `PdsClient`; `check_all()` iterates all managed DIDs, `check_for_changes(did)` diffs current audit log against cached log and classifies new entries as authorized/unauthorized by verifying signatures against the device key); `run_monitoring_loop(app_handle)` (spawned once at app startup, checks every 15 minutes via `tokio::time::interval` with `MissedTickBehavior::Delay`, emits `"plc_alert"` Tauri event to frontend when unauthorized changes detected); `check_identity_status` (Tauri IPC command: synchronous foreground check of all managed identities, returns `Vec<IdentityStatus>`). Types: `UnauthorizedChange` { cid, created_at, signing_key, operation } (camelCase serialization), `IdentityStatus` { did, alert_count, unauthorized_changes } (camelCase serialization), `MonitorError` { NetworkError, IdentityStoreError, ParseError } (SCREAMING_SNAKE_CASE tag serialization)
- `src/agents.rs` — Agent consent + audit module (5 Tauri IPC commands, the wallet side of the auth.md claim ceremony + "My agents"): `preview_agent_claim(user_code) -> AgentClaimPreview` (POST `/v1/agents/claim-preview` — what approving would grant, shown before the biometric gate), `confirm_agent_claim(user_code) -> AgentClaimConfirmation` (POST `/agent/identity/claim/confirm` — the human gate; the frontend wraps it in `authenticateBiometric()`), `list_agents() -> Vec<AgentSummary>`, `revoke_agent(registration_id)`, `get_agent_audit(registration_id, cursor?) -> AgentAuditPage`. All five authenticate with the Keychain `"session-token"` (the full session the create flow leaves behind; missing → `NOT_AUTHENTICATED`). Network cores are `_impl` functions taking `&CustosClient`, tested against httpmock. `AgentsError` (NOT_AUTHENTICATED, CODE_NOT_FOUND, CODE_EXPIRED, ALREADY_CLAIMED, ACCESS_DENIED, AGENT_NOT_FOUND, RATE_LIMITED, NETWORK_ERROR, UNKNOWN) serialized as `{ code: "SCREAMING_SNAKE_CASE" }`; the ceremony's `{error}` codes map onto it in `map_ceremony_error` so denial/expiry render as explicit states
- `src/recovery.rs` — Recovery override module: `build_recovery_override(pds_client, did, unauthorized_op_cid) -> Result<SignedRecoveryOp, RecoveryError>` (fetches audit log, identifies fork point, builds counter-operation restoring pre-unauthorized state, signs with per-DID device key), `submit_recovery_override(pds_client, did, signed_op) -> Result<ClaimResult, RecoveryError>` (POSTs to plc.directory, updates cached log and DID doc); Tauri IPC commands: `build_recovery_override_cmd`, `submit_recovery_override_cmd`. Types: `SignedRecoveryOp` { diff, signed_op }, `RecoveryState` { did, signed_op }, `RecoveryError` (RECOVERY_WINDOW_EXPIRED, SIGNING_FAILED, PLC_DIRECTORY_ERROR, NETWORK_ERROR, IDENTITY_NOT_FOUND, UNAUTHORIZED_CHANGE_NOT_FOUND)
- `src/migrate.rs` — Self-signed account-migration identity leg (ADR-0002 path 1): builds and locally device-key-signs the DID-repointing PLC op and submits it directly to plc.directory — no email token, no `signPlcOperation` round-trip. `build_migration_op(pds_client, dest_client, did) -> Result<SignedMigrationOp, MigrateError>` (fetches audit log for `prev` + current state, reads `getRecommendedDidCredentials` from the DESTINATION PDS via the passed-in authed `OAuthClient`, assembles the op with the device key preserved at `rotationKeys[0]`, runs the strict pre-sign guard, signs with the per-DID device key), `submit_migration_op(pds_client, did, signed_op) -> Result<ClaimResult, MigrateError>` (POSTs to plc.directory, refreshes cached log + DID doc); Tauri IPC commands: `build_migration_op_cmd`, `submit_migration_op_cmd`. Pure helpers: `guard_migration_op` (strict allowlist), `recommended_verification_methods`/`recommended_services` (RecommendedCredentials JSON → typed maps), `latest_op_state` (current state from newest non-nullified audit entry), `build_migration_diff`. Types: `SignedMigrationOp` { diff, signed_op }, `MigrationState` { did, dest_oauth_client, signed_op }, `MigrationInputs`; `MigrateError` (WALLET_NOT_AUTHORIZED, GUARD_REJECTED, INVALID_RECOMMENDED_CREDENTIALS, INVALID_AUDIT_LOG, SIGNING_FAILED, PLC_DIRECTORY_ERROR, NETWORK_ERROR, IDENTITY_NOT_FOUND, MIGRATION_NOT_READY). The destination-PDS OAuth login is NOT owned here — the migration orchestrator authenticates and populates `MigrationState.dest_oauth_client` before `build_migration_op_cmd` runs
- `src/migration_orchestrator.rs` — wallet-authorized outbound migration state machine (ADR-0002 path 1). Fine-grained per-step Tauri commands driving the source→dest transfer: `prepare_migration` (resolve dest describeServer + source; returns `PreparedMigration { handle, sourcePdsUrl }` for the source-auth screen), `authenticate_migration_source` (password `createSession` → full-session Bearer client, mirrors `claim::authenticate_source_pds`; per ADR-0021/MM-302 a full session is required to mint the source's `createAccount` service-auth token — HTTPS + account-match guards + email-2FA, password used once and never stored), `create_destination_account` (reserveSigningKey → getServiceAuth → deactivated `createAccount` → Bearer session; tolerates `DidAlreadyExists` for resume), `transfer_repo` (getRepo → importRepo), `transfer_blobs` (cursor-paginated `listMissingBlobs` drain), `transfer_preferences` (get→put), `verify_import` (`checkAccountStatus` completeness gate; returns `AccountStatus`), `arm_identity_leg` (populate `migrate::MigrationState.dest_oauth_client`, then run `migrate::build_migration_op_cmd`/`submit_migration_op_cmd`), `finalize_migration` (activate dest → deactivate source). Pure cores split out for testability (`ensure_phase_did` gate, `create_destination_account_impl`, `drain_missing_blobs`, `transfer_repo_impl`, `transfer_preferences_impl`, `import_reconciles`, `finalize_migration_impl`, and the `*_core` mutex-parameterized command cores). `MigrationError` (MIGRATION_NOT_READY, DESTINATION_UNREACHABLE, SOURCE_AUTH_FAILED, TWO_FACTOR_REQUIRED, ACCOUNT_MISMATCH, INSECURE_SOURCE_URL, RATE_LIMITED, SERVER_ERROR, SERVICE_AUTH_FAILED, ACCOUNT_CREATION_FAILED, DESTINATION_CONFLICT, REPO_TRANSFER_FAILED, BLOB_TRANSFER_FAILED, PREFERENCES_TRANSFER_FAILED, VERIFICATION_INCOMPLETE, ACTIVATION_FAILED, DEACTIVATION_FAILED, NETWORK_ERROR). Migration state is in-memory only (`AppState.orchestration_state`); an app kill restarts from `prepare_migration`. The orchestrator never POSTs plc.directory — the single PLC write is `migrate::submit_migration_op_cmd`
- `src/lib.rs::check_identity_status() -> Result<Vec<IdentityStatus>, MonitorError>` — Tauri IPC command (delegates to `PlcMonitor::check_all`)
- `src/lib.rs::list_identities() -> Result<Vec<String>, IdentityStoreError>` — Tauri IPC command: returns managed DIDs from Keychain via `IdentityStore::list_identities()`; returns empty list if no identities claimed
- `src/lib.rs::get_stored_did_doc(did: String) -> Result<Option<serde_json::Value>, IdentityStoreError>` — Tauri IPC command: retrieves stored DID document as parsed JSON for a claimed identity; returns None if not stored
- `src/lib.rs::get_device_key_id(did: String) -> Result<String, IdentityStoreError>` — Tauri IPC command: returns the device key's did:key URI for a claimed identity via `IdentityStore::get_or_create_device_key()`
- `src/lib.rs::register_created_identity(did: String, handle: String) -> Result<(), RegisterIdentityError>` — Tauri IPC command: registers a just-created identity in `IdentityStore` so it appears in `IdentityListHome` (the create flow otherwise writes only the OAuth session + legacy `"did"` Keychain item, which the home screen does not read). Calls `add_identity` (tolerating `IdentityAlreadyExists`), `adopt_global_device_key` (so the per-DID key matches the genesis rotation key), and stores a locally-built PLC-format DID document (handle + PDS + rotationKeys). Mirrors `claim::submit_claim`'s persistence step. `RegisterIdentityError` { KEYCHAIN_ERROR } serialized as `{ code: "SCREAMING_SNAKE_CASE" }`
- `src/lib.rs::get_pds_url() -> Option<String>` — Tauri IPC command: loads PDS base URL from Keychain, returns Some(url) if configured or None for first-launch
- `src/lib.rs::save_pds_url(url: String) -> Result<(), PdsConfigError>` — Tauri IPC command: validates URL format, pings `/xrpc/_health` on the PDS, saves to Keychain, initializes `AppState.custos_client` (runtime configuration)
- `src/lib.rs::get_appearance_preference() -> Option<String>` — Tauri IPC command: returns the saved appearance preference (`"system"` | `"light"` | `"dark"`) from the Keychain, or None if never set; a corrupt/unrecognized stored value reads as None (follow the system), never an error
- `src/lib.rs::set_appearance_preference(preference: String) -> Result<(), AppearanceError>` — Tauri IPC command: validates the value against the three-value allowlist and persists it to the Keychain. `AppearanceError` { INVALID_PREFERENCE, KEYCHAIN_ERROR } serialized as `{ code: "SCREAMING_SNAKE_CASE" }`

**Guarantees:**
- `crate-type = ["staticlib", "cdylib", "rlib"]` supports iOS (staticlib), Android (cdylib), and normal cargo builds (rlib)
- `src/main.rs` is the desktop entry point; `src/lib.rs::run()` is the iOS/Android entry point (via `#[cfg_attr(mobile, tauri::mobile_entry_point)]`)
- `tauri.conf.json` configures the bundle identifier, dev URL (`http://localhost:5173`), and frontend dist path (`../dist`)
- `create_account` maps PDS HTTP error codes to typed `CreateAccountError` variants (EXPIRED_CODE, REDEEMED_CODE, EMAIL_TAKEN, HANDLE_TAKEN, NETWORK_ERROR, UNKNOWN) serialized as `{ code: "SCREAMING_SNAKE" }` for the frontend
- `perform_did_ceremony` maps failures to typed `DIDCeremonyError` variants (KEY_NOT_FOUND, PDS_KEY_FETCH_FAILED, NO_PDS_SIGNING_KEY, SIGNING_FAILED, DID_CREATION_FAILED, KEYCHAIN_ERROR, NETWORK_ERROR) serialized as `{ code: "SCREAMING_SNAKE_CASE" }` for the frontend
- `load_home_data` always returns Ok -- partial failures (PDS unreachable, session expired) are encoded as `HomeData` fields (`pds_healthy: false`, `session: null`, `session_error: "NOT_AUTHENTICATED"`) so the UI can render whatever is available
- `log_out` always returns Ok -- Keychain delete errors are swallowed; the frontend unconditionally navigates to the welcome screen; device key and DPoP key are deliberately preserved (not deleted)
- `HomeData` and `SessionInfo` serialize with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ pdsHealthy, session, sessionError, share1InKeychain }` and `{ did, handle, email, emailConfirmed, didDoc }`
- `prepare_oauth_flow` / `complete_oauth_flow` map failures to typed `OAuthError` variants (DPOP_KEY_GEN_FAILED, DPOP_KEY_INVALID, DPOP_PROOF_FAILED, KEYCHAIN_ERROR, STATE_MISMATCH, CALLBACK_ABANDONED, PAR_FAILED, TOKEN_EXCHANGE_FAILED, TOKEN_REFRESH_FAILED, INVALID_GRANT, NOT_AUTHENTICATED) serialized as `{ code: "SCREAMING_SNAKE_CASE" }` for the frontend
- The OAuth callback is delivered by **`ASWebAuthenticationSession`** (via the vendored `tauri-plugin-auth-session`), **not** a deep link. The frontend calls `prepare_*` (Rust) for the authorize URL, then `plugin:auth-session|start` (which opens the in-app auth sheet and returns the `org.obsign.identitywallet:/oauth/callback?code=...&state=...` URL), then `complete_*` (Rust) to finish. The custom scheme `org.obsign.identitywallet` is registered in `src-tauri/Info.ios.plist` (`CFBundleURLTypes`, alongside the legacy `dev.malpercio.identitywallet` transition entry) because it is the session's `callbackURLScheme`. **Why not deep links:** iOS Safari will not auto-launch the app from a server-side redirect to a custom scheme, so the old `tauri-plugin-deep-link` + `on_open_url` + `handle_deep_link` flow silently failed; ASWebAuthenticationSession captures the callback itself
- On app startup, if OAuth tokens exist in Keychain, the session is restored into `AppState.oauth_session` and an `auth_ready` Tauri event is emitted after a 300ms delay (allows SvelteKit to boot and register its listener)
- `OAuthClient` transparently refreshes access tokens with <60s remaining before each request; retries once on `use_dpop_nonce` 400 responses from the server. A 400 that is NOT a `use_dpop_nonce` challenge (a genuine `InvalidRequest`/`InsufficientScope`/etc.) is buffered and handed back to the caller as an intact `reqwest::Response` (rebuilt via `http::Response` → `reqwest::Response::from`), NOT flattened into `NotAuthenticated` — so the caller's classifier (`pds_client::classify_xrpc_response`, MM-290) can surface the server's real status + body on the DPoP migration-source path. Non-400 statuses were already passed through untouched
- `DPoPKeypair` is idempotent: `get_or_create()` generates and persists to Keychain on first call, loads from Keychain on subsequent calls; the same key is used across all DPoP proofs and app sessions
- `device_key::get_or_create()` is idempotent -- returns the same key on every call for a given device
- `device_key::sign()` returns raw 64-byte r||s ECDSA signatures; low-S normalized on both paths (ATProto/PLC directory requires low-S); deterministic (RFC 6979) on simulator
- `DeviceKeyError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the `CreateAccountError` pattern
- Device key dispatch: `#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]` for software path, `#[cfg(all(target_os = "ios", not(target_env = "sim")))]` for Secure Enclave path
- `IdentityStore` is stateless (unit struct); all state lives in the Keychain. Methods take `&self` to allow future integration into `AppState`
- `IdentityStore::add_identity` does NOT eagerly generate a device key -- keys are lazily created on first `get_or_create_device_key` call
- `register_created_identity` registers the create-flow identity in `IdentityStore` (mirrors `claim::submit_claim`): `add_identity` (tolerating `IdentityAlreadyExists`) + `adopt_global_device_key` + a locally-built PLC DID doc. Without it, a PDS-OAuth (create-flow) identity never appears in `IdentityListHome`, which lists from `IdentityStore` alone. Best-effort on the frontend (never blocks reaching `home`); idempotent on the backend
- `IdentityStore::adopt_global_device_key` makes the per-DID device key resolve to the global `device_key.rs` key (the create flow's genesis op signs with the global key before the DID exists). This keeps the "root key" badge accurate AND prevents `plc_monitor` from flagging the user's own genesis/handle operations as unauthorized (the monitor verifies audit-log signatures against the per-DID key). Platform-agnostic: copies whichever global account exists (software private scalar, or SE pub + app-label)
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
- `claim::authenticate_source_pds` logs in to the source PDS with the account **password** (`createSession`) rather than OAuth: the claim flow's next steps (`requestPlcOperationSignature`/`signPlcOperation`) are PLC/identity ops that require a full session, which no OAuth `transition:generic` token can grant (ADR-0021/MM-289). It builds a full-session Bearer `OAuthClient` (`OAuthClient::new_bearer`) and stores it in `ClaimState.pds_oauth_client`; the password is used for one request and never persisted. (`PdsAuthScreen` collects the password and proceeds when the `authenticateSourcePds` promise resolves.)
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
- The wallet's OAuth identity lives in `pds_client.rs`: `CANONICAL_CLIENT_ID` (`https://identitywallet.obsign.org/oauth/client-metadata.json`), `REDIRECT_URI` (`org.obsign.identitywallet:/oauth/callback`), and `CALLBACK_SCHEME`. `client_id_for_pds(custos_base_url)` returns the fixed canonical URL — the OAuth client is the wallet app, so its identity never varies with the configured Custos — except for a loopback base (local dev), where it derives `{base}/oauth/client-metadata.json`. The redirect scheme is the canonical client_id host in **reverse-FQDN order**, which the atproto OAuth spec requires for a native client's private-use redirect and third-party AS's (bsky.social) enforce. Must stay in sync with the Custos client-metadata route and the V042-seeded `oauth_clients` row
- Per-DID Keychain accounts use `"{did}:suffix"` format (e.g. `"did:plc:abc123:device-key"`) -- the colon separator is part of the naming convention

**Expects:**
- `tauri.conf.json` exists in `src-tauri/` before `cargo build` runs — the config is read at compile time by `generate_context!()`
- `cargo-tauri` is in PATH (provided by the Nix dev shell)
- Xcode and iOS Simulator are installed on the developer's macOS machine
- PDS must be running at the configured URL (set via `PdsConfigScreen` on first launch, or the compile-time default) for `create_account` to succeed at runtime

## Dependencies

- Frontend -> Rust backend (via Tauri IPC -- `@tauri-apps/api/core` `invoke()`)
- Rust backend -> Cargo workspace (inherits `version`, `edition`, `publish` from root `Cargo.toml`)
- Rust backend -> `crates/crypto` (workspace dep: P-256 key generation in simulator/macOS software path)
- Rust backend -> `p256` (workspace dep: key reconstruction, signature types in both paths)
- Rust backend -> `multibase` (workspace dep: base58btc encoding for multibase/did:key output)
- Rust backend -> PDS `/v1/accounts/mobile` endpoint (via `reqwest` HTTP at runtime)
- Rust backend -> PDS `GET /v1/pds/keys` endpoint (public, no auth; fetches active signing key for DID ceremony)
- Rust backend -> PDS `POST /v1/dids` endpoint (Bearer token auth; submits signed genesis op for DID promotion)
- Rust backend -> PDS `POST /oauth/par` endpoint (PAR: push authorization request with PKCE challenge + DPoP proof)
- Rust backend -> PDS `GET /oauth/authorize` endpoint (opened in Safari; user authenticates via browser)
- Rust backend -> PDS `POST /oauth/token` endpoint (exchanges authorization code + PKCE verifier for DPoP-bound tokens)
- Rust backend -> PDS `GET /xrpc/_health` endpoint (public, no auth; home screen PDS health check)
- Rust backend -> PDS `GET /xrpc/com.atproto.server.getSession` endpoint (DPoP-authenticated via OAuthClient; fetches session info for home screen)
- Rust backend / frontend -> `tauri-plugin-auth-session` (**vendored** in `vendor/tauri-plugin-auth-session/`; ASWebAuthenticationSession for the in-app OAuth session — replaced `tauri-plugin-deep-link` + `tauri-plugin-opener`, both removed)
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

# 4. Finish + verify the generated project (swift-rs fork check + app icon + ios-check)
cd .. # back to workspace root
just ios-postinit
```

Note: `src-tauri/gen/` contains a machine-specific Xcode project. It is gitignored and must be re-generated on each developer machine. Do not commit it.

### After every `cargo tauri ios init`: run `just ios-postinit`

`cargo tauri ios init` regenerates the gitignored Xcode project at
`src-tauri/gen/apple/`. The Xcode-project workarounds are **not patched in
afterwards** — they come from the committed XcodeGen template
`scripts/ios/project.yml`, which the init renders into `gen/apple/project.yml`
on every run (via `bundle > iOS > template` in `tauri.conf.json`; the template
path is cwd-relative, so run the init from `apps/identity-wallet/`). The template
carries: `ENABLE_USER_SCRIPT_SANDBOXING: NO` (macOS 26 + Xcode sandbox blocks
Cargo's directory walk), the dev-env preamble in the "Build Rust Code" Run Script
phase (`EZPDS_IOS_BUILD=1` + PATH + `source scripts/ios-env.sh` — that phase does
not inherit the dev-shell environment), `CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION:
YES` (tolerates Xcode's spurious "entitlements modified during build" failure
caused by the per-build project sync), `OTHER_LDFLAGS` linking every framework in
`tauri.conf.json`'s `bundle > iOS > frameworks` (see Troubleshooting), and
`Externals → buildPhase: none` (keeps the Rust staticlib `libapp.a` out of the app
bundle — App Store rejects a loose `.a`; see Troubleshooting).

After every init, run (from the repo root):

```bash
just ios-postinit
```

It verifies the `swift-rs` `--disable-sandbox` fork is wired in the workspace
`Cargo.toml`, regenerates the AppIcon asset catalog from `app-icon.png`, and runs
the full `just ios-check`, which fails loudly if the template did not apply (e.g.
a stale pre-template `gen/apple`, or the `template` key dropped from
`tauri.conf.json`). Verify at any time with `just ios-check`.

### Why rustup instead of Nix-managed Rust

`languages.rust` in devenv uses Nix's `rust-default` package, which only ships stdlibs for standard host targets. iOS Simulator requires `aarch64-apple-ios-sim` stdlib. Nix doesn't package iOS cross-compilation stdlibs; `rustup` downloads them from the Rust release infrastructure. The dev shell is configured with project-local `RUSTUP_HOME` and `CARGO_HOME` (inside `.devenv/state/`) so the toolchain is isolated per project.

The Apple toolchain (clang/ar/SDKs/`DEVELOPER_DIR`) is resolved dynamically by
`scripts/ios-env.sh` via `xcrun`/`xcode-select` — there are no hardcoded Xcode
paths, so the build follows whatever Xcode `xcode-select` points at. `ios-env.sh`
is sourced by the devenv `enterShell` and by the patched Xcode Run Script phase.

One subtlety makes this work: Nix's Darwin stdenv exports `DEVELOPER_DIR`/`SDKROOT`
pointing at its apple-sdk **stub**, and both `xcode-select -p` and `xcrun` honor those
env vars *above* the system Xcode selection — so even calling them by absolute path
returns the Nix stub (→ Nix clang-wrapper → `ld: library not found for -liconv` on the
host-side proc-macro link). `ios-env.sh` therefore strips `DEVELOPER_DIR`/`SDKROOT`
**when (and only when) they point into `/nix/store`** before resolving, so the real
Apple toolchain wins; a genuine Xcode-provided value (e.g. the one Xcode injects into
its Run Script phase) is preserved.

The script is split into two tiers: iOS-target overrides (`CC_aarch64_apple_ios*`,
`AR_aarch64_apple_ios*`, the iOS linkers) are always exported — no server crate
targets iOS, so they never affect a host build — while the **host-target overrides**
(`CC_aarch64_apple_darwin`, the macOS-host linker + SDK `rustflags`) are gated behind
`EZPDS_IOS_BUILD=1`. Only the `just ios-dev`/`ios-build` recipes and the injected
Xcode Run Script set that variable, so a plain `cargo build --workspace` /
`cargo run -p PDS` inside the dev shell keeps using the unmodified Nix toolchain.
The host overrides exist solely so the iOS build's host-side proc-macros and
`security-framework` C build avoid the Nix cc-wrapper (`-mmacos-version-min`) and the
Nix apple-sdk stub (missing `/usr/lib` stubs like `libiconv.tbd`). `ios-env.sh` is
SOURCED, never executed (no `exit`, no `set -e`), so it is safe to source repeatedly
and is a no-op on non-Mac shells where `xcrun`/`xcode-select` are absent.

## Development Workflow

The primary iOS build commands are `just ios-dev` and `just ios-build`, run from the
workspace root:

```bash
# Enter the dev shell if not already active (MUST be run from the workspace root,
# not from apps/identity-wallet/ — CARGO_HOME resolves relative to devenv root)
nix develop --impure --accept-flake-config

# Launch the app in the iOS Simulator (starts pnpm dev + Rust compilation + Simulator).
# No arg: `cargo tauri ios dev` auto-selects a target and PREFERS a connected physical
# device (which then needs code signing). Pass a simulator name to force the Simulator:
just ios-dev                       # auto-select (a connected device wins)
just ios-dev "iPhone 17 Pro Max"   # force a specific simulator

# Build (Xcode project only; does not launch Simulator)
just ios-build
```

Both commands first run `just ios-check`, which fails fast if the Xcode project is missing a required patch — run `just ios-postinit` to apply them. Each recipe then **re-sources `ios-env.sh`** (with `EZPDS_IOS_BUILD=1`) before invoking `cargo tauri`, so the build's outer process starts from a freshly-resolved Apple toolchain even when the surrounding shell carries **stale** `CARGO_TARGET_*`/`CC_*`/`AR_*` from an earlier `ios-env.sh` sourcing (e.g. a long-lived dev shell entered before a fix). A stale outer env reaches the build through the shared `target/` even though the Xcode Run Script re-sources `ios-env.sh`, so correcting it at the recipe is what makes the build robust. The Apple toolchain env is thus applied at three points: the dev shell (`enterShell` sources `ios-env.sh`), the recipe re-source, and the `ios-env.sh` preamble the `scripts/ios/project.yml` template puts into the Xcode Run Script phase.

**Do not click Run in Xcode directly.** `just ios-dev` starts a JSON-RPC server that
Xcode's build phase connects to; bypassing it causes "Connection refused" in the build log.

For a non-iOS build (CI or any machine without Xcode):

```bash
# From workspace root — builds all workspace crates including src-tauri for the host platform
cargo build
```

## CI / TestFlight

The iOS app builds in **GitHub Actions** (the macOS lane — `cargo tauri ios build` needs
macOS + Xcode, which the Linux PDS lane lacks), on a free `macos-26` runner for the public
repo. `.github/workflows/ios-testflight.yml`
runs on every push to `main`: regenerate the gitignored Xcode project
(`cargo tauri ios init` + `just ios-postinit`), build a signed App Store IPA
(`just ios-ipa` stamps a unique, monotonic `bundle.iOS.bundleVersion` — UTC epoch
seconds — so CI and a local `just ios-release` share one scheme and never collide),
and upload to TestFlight. Signing is **explicit** — Tauri's
automatic iOS signing emits an "Apple Distribution: Tauri (unset)" placeholder that App
Store rejects (tauri#11092), so Tauri reads `IOS_CERTIFICATE` / `IOS_CERTIFICATE_PASSWORD`
/ `IOS_MOBILE_PROVISION` (an Apple Distribution cert + App Store profile); the App Store
Connect API key (`APPLE_API_*`) is used only for the `altool` upload.

The build/upload core is shared `just` recipes (workspace root) so CI and local runs are
identical: `just ios-ipa` (build signed IPA via `--export-method app-store-connect`),
`just ios-upload` (`xcrun altool` → TestFlight), `just ios-release` (both). Run
`just ios-release` locally once to validate signing before trusting CI. The workflow
never runs on `pull_request` (public repo — keeps the Apple key off fork PRs).

Full setup (mirror dual-push, App Store Connect, GitHub secrets) and gotchas:
**[docs/ios-cicd.md](../../docs/ios-cicd.md)**.

## Key Decisions

- **`adapter-static` + `ssr = false`**: Tauri WebViews load files from disk — there is no web server. SSR is meaningless and globally disabled.
- **`pages: 'dist'` in svelte.config.js**: Matches `tauri.conf.json`'s `frontendDist: "../dist"`.
- **`TAURI_DEV_HOST` for HMR**: Tauri v2 automatically sets this env var to the machine's LAN IP when running `cargo tauri ios dev`. The iOS simulator connects to the Vite dev server over LAN, not localhost.
- **`generate_context!()` is compile-time**: `tauri.conf.json` must exist when `src-tauri/` is compiled — the macro embeds the config at compile time and will fail to compile if the file is missing.
- **`src-tauri/gen/` is gitignored**: The Xcode project generated by `cargo tauri ios init` is machine-specific. Committing it causes merge conflicts and bloats the repo.
- **`tauri` and `tauri-build` declared locally**: These crates are not in `[workspace.dependencies]` because no other workspace crate uses them. `serde` and `serde_json` use `{ workspace = true }` per the standard workspace pattern.
- **Toolchain configuration via `ios-env.sh` (no hardcoded Xcode paths)**: `apps/identity-wallet/scripts/ios-env.sh` derives the Apple toolchain dynamically for cross-compiling to iOS — it resolves `DEVELOPER_DIR` via `/usr/bin/xcode-select -p` and sets `CC`/`AR`/linker overrides as environment variables rather than baking paths into a committed file. iOS-target overrides always apply; macOS-host overrides (needed only for the iOS build's host-side proc-macros and `security-framework`'s C build, which fail under Nix's cc-wrapper) are gated on `EZPDS_IOS_BUILD=1` so non-iOS workspace builds are untouched. The script is sourced by the devenv `enterShell` and by the Xcode "Build Rust Code" Run Script phase (rendered from the `scripts/ios/project.yml` template), so CLI and Xcode builds resolve the toolchain identically. `src-tauri/.cargo/config.toml` now holds only `RUST_TEST_THREADS=1`; all toolchain overrides moved to the shell script for de-Nix compliance. See the Troubleshooting section for the full explanation.
- **Runtime-configurable PDS URL**: `http.rs` provides a compile-time default via `#[cfg(debug_assertions)]` (`http://localhost:8080` debug, `https://obsign.org` release). At runtime, the user configures the PDS URL on first launch via `PdsConfigScreen`; the URL is persisted to Keychain and restored on subsequent launches via `AppState::set_custos_client()`. The compile-time default is used only as the pre-filled value in the configuration UI.
- **Device key module (`device_key.rs`) with `#[cfg]` dispatch**: Two compile-time paths share the same public API (`get_or_create`, `sign`). macOS and iOS Simulator use software P-256 via `crypto` crate with private key bytes in Keychain. Real iOS device uses Secure Enclave -- private key never leaves the SE; only the compressed public key and application_label (SE-assigned SHA1) are stored in regular Keychain for lookup.
- **Idempotent key lifecycle**: `get_or_create()` generates on first call, returns the same key on subsequent calls. `create_account` delegates to `device_key::get_or_create()` so the same device key is sent to the PDS on every attempt (retries are safe).
- **P-256 multicodec prefix duplicated**: `device_key.rs` duplicates the `[0x80, 0x24]` P-256 multicodec varint prefix from `crates/crypto/src/keys.rs` because the constant is `pub(crate)` there. This is intentional -- the identity-wallet crate should not depend on internal crypto crate layout.
- **Low-S normalization on both paths**: ATProto/PLC directory requires low-S ECDSA signatures (enforced by `@noble/curves` in strict mode). Both the SE path and the simulator path apply `normalize_s()` after signing. RFC 6979 only provides deterministic nonces — it does NOT guarantee low-S; that requires an explicit normalization step.
- **reqwest with rustls-tls**: Uses `default-features = false` + `rustls-tls` to avoid linking OpenSSL. On iOS, rustls handles TLS natively without additional system deps.
- **OAuth PKCE flow with DPoP**: The identity-wallet authenticates with the PDS using OAuth 2.0 Authorization Code + PKCE (RFC 7636) with DPoP-bound tokens (RFC 9449). The flow is split across two Rust commands with the in-app auth session between them: `prepare_*` does DPoP keygen + PKCE verifier + PAR -> returns the `/oauth/authorize` URL (parking the verifier + CSRF in `AppState`); the frontend calls `plugin:auth-session|start`, which opens the in-app ASWebAuthenticationSession and returns the custom-scheme callback URL with the authorization code; `complete_*` validates the CSRF state + does the token exchange (PKCE verifier + DPoP proof) -> stores tokens in Keychain. The verifier + CSRF state never leave the Rust backend.
- **DPoP keypair persisted in Keychain**: The same P-256 DPoP key is reused across all OAuth flows and app sessions. This allows the PDS to bind tokens to the key (via `jkt` thumbprint) and enables token refresh without re-authenticating.
- **In-app auth session for the OAuth callback**: Uses the **vendored** `tauri-plugin-auth-session` (ASWebAuthenticationSession on iOS/macOS) to open the authorize URL and capture the `org.obsign.identitywallet:/oauth/callback?code=...&state=...` redirect directly — no app relaunch. Replaced the `tauri-plugin-deep-link` approach: iOS Safari will not auto-launch the app from a server-side redirect to a custom scheme. The plugin is vendored (not a live git dep) because it sits in the auth path; see `vendor/tauri-plugin-auth-session/VENDORED.md`.
- **AppState with Mutex<Option>**: `pending_login` (create flow) holds the PKCE verifier + CSRF state between `prepare_oauth_flow` and `complete_oauth_flow` while the auth session runs; `oauth_session` holds the active tokens. Both use `Mutex<Option<T>>` so the state is cleanly empty before/after flows. (Both source logins — the claim flow and the outbound migration — are password-based `createSession` — `claim::authenticate_source_pds` / `migration_orchestrator::authenticate_migration_source` — so neither needs a pending-login slot.)
- **OAuthClient with lazy refresh**: `OAuthClient` checks token expiry before each request and refreshes if <60s remaining. Retries once on `use_dpop_nonce` 400 responses (server requires a nonce the client didn't have yet).
- **`load_home_data` always-Ok pattern**: `load_home_data` never returns Err -- partial failures (PDS down, session expired, OAuthClient construction failure) are encoded as HomeData fields (e.g. `pds_healthy: false`, `session: null`, `session_error: "NOT_AUTHENTICATED"`). This lets the UI render whatever data is available rather than showing a generic error screen.
- **`log_out` preserves device key and DPoP key**: `log_out` only deletes OAuth tokens (access + refresh) and the DID from Keychain. The device rotation key and DPoP keypair are deliberately preserved so re-authentication does not require re-enrollment.
- **DIDAvatar deterministic hue**: `DIDAvatar.svelte` derives a stable hue (0-359) from the DID string using a polynomial hash (`h = (h * 31 + charCode) & 0xffffff; hue = h % 360`). The same DID always produces the same color across renders and sessions.
- **Home screen data flow**: HomeScreen calls `loadHomeData()` on mount, stores the result in local state, and passes the full HomeData to child screens (DIDDocumentScreen, RecoveryInfoScreen) via the page-level state machine in `+page.svelte` rather than having children re-fetch.
- **Startup token restore**: On app launch, `lib.rs::run()` checks Keychain for persisted OAuth tokens. If found, restores them into `AppState.oauth_session` with `expires_at = 0` (forces immediate refresh on first use) and emits `auth_ready` after 300ms delay so SvelteKit has time to boot.
- **Per-DID Keychain namespacing (`identity_store.rs`)**: Multi-identity support uses DID-prefixed Keychain accounts (`"{did}:device-key"`, etc.) instead of the single-identity global accounts in `device_key.rs`. A top-level `"managed-dids"` JSON array index tracks all registered DIDs. Device keys are lazily generated on first `get_or_create_device_key` rather than at identity registration time. The module uses the same `#[cfg]` dispatch pattern as `device_key.rs` for software vs. SE key generation but with per-DID scoping.
- **PDS client separate from PDS client (`pds_client.rs`)**: `PdsClient` handles discovery and OAuth against arbitrary PDS endpoints (not just our PDS), while `CustosClient` (in `http.rs`) handles communication with the user's configured PDS. The separation exists because PDS discovery targets endpoints the wallet learns at runtime (plc.directory, user's PDS), whereas `CustosClient` targets a single configured PDS. `PdsClient` is stateless and uses `reqwest::Client` directly; `CustosClient` holds a runtime-configured base URL.
- **XRPC identity functions as module-level functions**: `request_plc_operation_signature`, `sign_plc_operation`, and `get_recommended_did_credentials` are standalone functions in `pds_client.rs` (not methods on `PdsClient`) because they require a DPoP-authenticated `OAuthClient` for the Authorization header, which `PdsClient`'s plain HTTP client cannot provide. This keeps `PdsClient` focused on unauthenticated discovery while XRPC calls use the existing `OAuthClient` infrastructure.
- **DNS resolution via hickory-resolver**: Handle resolution uses `hickory-resolver` for DNS TXT lookups (`_atproto.{handle}`), matching the same DNS library used by the PDS crate (`crates/pds/src/dns.rs`). Falls back to HTTP `/.well-known/atproto-did` when DNS fails.
- **Claim flow as multi-step state machine (`claim.rs`)**: The claim commands form a sequential pipeline: `resolve_identity` -> `authenticate_source_pds` -> `request_claim_verification` -> `sign_and_verify_claim` -> `submit_claim`. State is persisted in `AppState.claim_state` (tokio::sync::Mutex) across commands. Each command validates prerequisites (e.g. `authenticate_source_pds` requires `ClaimState` to exist, `request_claim_verification` requires `pds_oauth_client`). The `_impl` test helpers extract core logic away from Tauri's `State` wrapper.
- **Source logins are password-based, not OAuth (ADR-0021/MM-289/MM-302)**: both the claim flow and the outbound migration drive source-PDS operations a spec-strict PDS (bsky.social) gates behind a full session; the atproto OAuth ceiling for a third-party client is `transition:generic`, which is refused for them. The claim flow's next steps are PLC/identity ops; the outbound migration mints a `com.atproto.server.createAccount` service-auth token **from the source PDS** (MM-302). So `claim::authenticate_source_pds` and `migration_orchestrator::authenticate_migration_source` each do a one-shot password `createSession` → full-session Bearer client (`OAuthClient::new_bearer`), with HTTPS + account-match guards and email-2FA; the password is used once and never stored. Only the **create flow** (`oauth::prepare_oauth_flow`/`complete_oauth_flow`) still uses the in-app auth session (`plugin:auth-session|start`) — OAuth is fine for creating a fresh account. Only one auth session runs at a time.
- **PlcDidDocument and PlcService derive Clone**: Added to support cloning claim state data out of the tokio Mutex before releasing the lock for network calls. This pattern avoids holding the Mutex across `.await` points.
- **Mode selector as entry point**: The app starts at `mode_select` (not `pds_config`), offering two paths: "Create new identity" (original onboarding flow) and "Import existing identity" (claim flow). On mount, `+page.svelte` calls `listIdentities()` and skips directly to `home` if any identities exist. This identity-aware routing replaces the previous PDS-URL-based skip logic.
- **IdentityListHome replaces HomeScreen at `home` step**: The `home` state now renders `IdentityListHome` (multi-identity card list) instead of the single-identity `HomeScreen`. `IdentityListHome` shows all managed identities with handle, PDS URL, and rotation key status badges. Tapping an identity navigates to `identity_detail` (renders `DIDDocumentScreen`). The original `HomeScreen` component still exists for legacy PDS-authenticated sessions but is no longer wired into the state machine.
- **Create flow registers into `IdentityStore` (`register_created_identity`)**: The PDS-OAuth create flow writes only the OAuth session (`oauth_session` + `oauth-*-token` Keychain) and the legacy `"did"` Keychain item — none of which `IdentityListHome` reads. So after `handle_registration`, `finishCreateFlow()` calls `registerCreatedIdentity(did, handle)` to persist the identity to `IdentityStore`, exactly as the import flow does in `submit_claim`. Because a did:plc is the hash of its own genesis op, the create flow signs with the *global* `device_key.rs` key before the DID exists; `adopt_global_device_key` then aliases the per-DID key to it so the "root key" badge and PLC monitor stay correct. The DID doc is built locally (not fetched) to avoid plc.directory propagation timing right after creation. This is what makes the home screen show the new identity after OAuth login.
- **Identity store IPC commands are synchronous**: `list_identities`, `get_stored_did_doc`, and `get_device_key_id` are non-async Tauri commands (no `async fn`, no `State<>` parameter) -- they call `IdentityStore` methods directly since Keychain access is synchronous. This differs from most other Tauri commands which are async and take `State<AppState>`.
- **PLC monitoring: background timer + foreground check**: Two complementary mechanisms detect unauthorized PLC operations. (1) A background `tokio::time::interval` loop runs every 15 minutes, spawned once at app startup via `run_monitoring_loop`. (2) A `visibilitychange` listener in `+page.svelte` calls `checkIdentityStatus()` when the app returns to foreground. The timer uses `MissedTickBehavior::Delay` so iOS app suspension does not cause burst-fire of missed ticks.
- **PlcMonitor borrows PdsClient**: `PlcMonitor` takes `&PdsClient` (not owned) because `PdsClient` is a shared singleton on `AppState`. The monitor is constructed fresh on each cycle from the managed `AppState` reference, avoiding lifetime issues with long-lived borrows across async boundaries.
- **Graceful degradation on network errors**: `check_for_changes` returns `Ok(vec![])` when plc.directory is unreachable or audit log parsing fails, rather than surfacing errors to the UI. This prevents false alarms or error screens when the user has no network connectivity. Errors are logged via `tracing::warn` for diagnostics.
- **Signing key identification**: When an unauthorized change is detected, `identify_signing_key` attempts to identify the signer by trying each rotation key from the previous operation in the audit log. If no key matches, `signing_key` is `None`. This is best-effort -- the signer may have used a key not in the previous rotation key set.
- **Vitest for frontend unit tests**: `vitest` added as a dev dependency with `pnpm test` script (`vitest run`). Used for pure-logic utilities (e.g. `deadline.ts`) that do not require Tauri IPC mocking.
- **AlertDetailScreen countdown**: `AlertDetailScreen` updates `now` via a 60-second `setInterval`, which re-computes urgency and countdown display. The timer is cleaned up in `onDestroy` to prevent leaks if the component is unmounted.
- **Self-signed migration inverts the claim guard (`migrate.rs`)**: the self-signed migration path builds the DID-repointing PLC op locally (like `recovery.rs`) rather than verifying a PDS-signed op (like `claim.rs`). Its guard is the polar opposite of the claim guard: a claim must change *nothing* but insert the device key at `rotationKeys[0]`, whereas a migration *must* rewrite `services.atproto_pds`, `rotationKeys[1]`, and `verificationMethods.atproto` to the destination's values. The one preserved invariant — `rotationKeys[0]` == the wallet device key — is the entire "credible exit" guarantee (ADR-0002); an op the user didn't initiate is caught by `plc_monitor` and reversible via `recovery.rs`. The destination-PDS OAuth login is deliberately NOT owned by `migrate.rs`: it takes an already-authenticated `dest_oauth_client` supplied by the migration orchestrator, keeping the identity leg a pure, independently-testable unit.
- **Native migration is deferred, trigger-gated**: see ADR-0013 (`docs/architecture/decisions/0013-native-swiftui-shell-over-rust-core.md`). Migrate to a SwiftUI shell over the Rust core (UniFFI) only when background PLC monitoring becomes a hard requirement; port the shell, never the crypto.

## Invariants

- `src/lib/ipc.ts` is the only file that calls `invoke()` directly; page components import from `ipc.ts`
- `tauri.conf.json` bundle identifier `dev.malpercio.identitywallet` must match the iOS provisioning profile for physical device builds
- `src-tauri/gen/` is never committed -- regenerate with `cargo tauri ios init`
- `pnpm-lock.yaml` is committed and kept in sync with `package.json`
- Keychain service name is always `"ezpds-identity-wallet"` (constant `keychain::SERVICE`); changing it orphans previously stored credentials
- `CreateAccountError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `CreateAccountError.code` union must match exactly
- `DeviceKeyError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `DeviceKeyError.code` union must match exactly
- `DIDCeremonyError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `DIDCeremonyError.code` union must match exactly
- `PdsConfigError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `PdsConfigError.code` union must match exactly (INVALID_URL, UNREACHABLE, KEYCHAIN_ERROR)
- Keychain account `"relay-base-url"` stores the PDS's base URL (e.g. `https://obsign.org`); persisted by `save_pds_url` on first launch; `get_pds_url` returns null if not yet set
- Keychain account `"appearance-preference"` stores the in-app appearance override (`"system"` | `"light"` | `"dark"`); the localStorage key `appearance-preference` is its pre-paint mirror and must stay in sync with both `src/app.html`'s inline script and `APPEARANCE_STORAGE_KEY` in `src/lib/appearance.ts`
- `AppearanceError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `AppearanceError.code` union in `ipc.ts` must match exactly (INVALID_PREFERENCE, KEYCHAIN_ERROR)
- Keychain account `"device-rotation-key-priv"` stores the software P-256 private key (simulator/macOS path only); changing it orphans existing keys
- Keychain accounts `"device-rotation-key-pub"` and `"device-rotation-key-app-label"` store SE metadata (real iOS device path only); changing them orphans the SE key lookup
- Keychain account `"session-token"` stores the pending (pre-DID) or full (post-DID) session token; `perform_did_ceremony` reads the pending token and overwrites it with the upgraded token on success
- Keychain account `"did"` stores the user's did:plc after successful DID ceremony; persisted for use in subsequent app sessions
- Keychain account `"recovery-share-1"` stores Share 1 of the Shamir recovery split (base32, 52 chars); written by `perform_did_ceremony` immediately after DID promotion; never displayed to the user (iCloud Keychain automatic backup)
- Keychain account `"oauth-dpop-key-priv"` stores the P-256 DPoP private key scalar (32 bytes); generated once by `DPoPKeypair::get_or_create()`, reused across all app sessions; changing it invalidates all DPoP-bound tokens
- Keychain account `"oauth-access-token"` stores the OAuth access token; written by `complete_oauth_flow` on success and by `OAuthClient` on refresh
- Keychain account `"oauth-refresh-token"` stores the OAuth refresh token; written alongside the access token
- `OAuthError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `OAuthError.code` union must match exactly
- `PdsClientError` variant names serialize as SCREAMING_SNAKE_CASE -- the full Rust enum is HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR, RATE_LIMITED, UNAUTHORIZED, XRPC_ERROR, INVALID_RESPONSE, OAUTH_FAILED, DID_ALREADY_EXISTS, INVALID_CREDENTIALS, AUTH_FACTOR_TOKEN_REQUIRED, INSECURE_PDS_URL. HANDLE_NOT_FOUND / DID_NOT_FOUND / PDS_UNREACHABLE / NETWORK_ERROR / INVALID_RESPONSE / OAUTH_FAILED can reach the frontend directly (discovery/resolve paths); RATE_LIMITED / UNAUTHORIZED / XRPC_ERROR are the status-classified variants produced from any non-2xx XRPC response (MM-290) and are mapped into the command-specific error (e.g. `ClaimError::RateLimited`/`Unauthorized`/`ServerError`) before reaching the frontend; DID_ALREADY_EXISTS is migration-createAccount-internal; INVALID_CREDENTIALS / AUTH_FACTOR_TOKEN_REQUIRED / INSECURE_PDS_URL are claim-flow-internal — `authenticate_source_pds` maps them into `ClaimError` (SOURCE_AUTH_FAILED / TWO_FACTOR_REQUIRED / INSECURE_SOURCE_URL), so they are never surfaced as `PdsClientError` to the frontend
- `ResolveError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `ResolveError` union must match exactly (HANDLE_NOT_FOUND, DID_NOT_FOUND, PDS_UNREACHABLE, NETWORK_ERROR)
- `ClaimError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `ClaimError` union must match exactly (INVALID_TOKEN, VERIFICATION_FAILED, PLC_DIRECTORY_ERROR, UNAUTHORIZED, SOURCE_AUTH_FAILED, TWO_FACTOR_REQUIRED, ACCOUNT_MISMATCH, INSECURE_SOURCE_URL, INSUFFICIENT_SCOPE, RATE_LIMITED, SERVER_ERROR, NETWORK_ERROR). SOURCE_AUTH_FAILED is a rejected password `createSession` on the source PDS (wrong password / app-password used); TWO_FACTOR_REQUIRED means the source account has email 2FA — the PDS emailed a code and the UI prompts for it, re-invoking `authenticate_source_pds` with the `auth_factor_token`; ACCOUNT_MISMATCH means the entered credentials signed in to a different account than the one being claimed (`createSession`'s returned DID ≠ the claim DID — refused before any PLC op); INSECURE_SOURCE_URL means the source PDS endpoint (from the DID doc) isn't HTTPS, so the password is refused rather than sent in cleartext (loopback excepted); INSUFFICIENT_SCOPE is a PLC-op endpoint refusing the token for scope reasons, surfaced distinctly rather than masquerading as "failed to send verification email" (the MM-289 error-surfacing fix); RATE_LIMITED (carries `retryAfter`) and SERVER_ERROR (carries the server's own `message`) are the MM-290 status-classified surfaces — a 429/other non-2xx from a PLC-op or source login now names the real reason instead of the connectivity boilerplate. The claim screens format both via `src/lib/claim-errors.ts` (`formatRateLimitMessage`, `formatServerErrorMessage`)
- `IdentityStoreError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `IdentityStoreError.code` union must match exactly (IDENTITY_NOT_FOUND, IDENTITY_ALREADY_EXISTS, KEYCHAIN_ERROR, KEY_GENERATION_FAILED, SERIALIZATION_ERROR)
- `MonitorError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript consumer (if any) must match exactly (NETWORK_ERROR, IDENTITY_STORE_ERROR, PARSE_ERROR)
- `UnauthorizedChange` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ cid, createdAt, signingKey, operation }`; the TypeScript `UnauthorizedChange` type in `ipc.ts` must match exactly
- `IdentityStatus` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ did, alertCount, unauthorizedChanges }`; the TypeScript `IdentityStatus` type in `ipc.ts` must match exactly
- Tauri event `"plc_alert"` payload is `Vec<IdentityStatus>` (JSON array of identity statuses); the frontend `IdentityListHome` component listens for this event to update alert badges in real time
- PLC monitoring interval is 15 minutes (`MONITOR_INTERVAL_SECS = 900`); changing this constant alters battery/network impact
- Recovery deadline window is 72 hours (`RECOVERY_WINDOW_MS` in `deadline.ts`); this matches the PLC directory's 72-hour recovery window specification
- OAuth client_id is `pds_client::CANONICAL_CLIENT_ID` (`https://identitywallet.obsign.org/oauth/client-metadata.json`) against every non-loopback server; a loopback Custos (local dev) derives `{base}/oauth/client-metadata.json` instead -- must match the seeded row in PDS migration V042 and the Custos client-metadata route. The `tauri.conf.json` bundle identifier stays `dev.malpercio.identitywallet` (provisioning unchanged) and is deliberately NOT coupled to the client_id anymore
- OAuth redirect_uri is always `pds_client::REDIRECT_URI` (`org.obsign.identitywallet:/oauth/callback`) -- its scheme is the canonical client_id host in reverse-FQDN order (atproto OAuth requirement for private-use redirects) and must match the `CFBundleURLTypes` entry in `src-tauri/Info.ios.plist` and the seeded client_metadata redirect_uris in V042
- `DevicePublicKey` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ multibase, keyId }` (not `key_id`)
- `HomeData` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ pdsHealthy, session, sessionError, share1InKeychain }`; the TypeScript `HomeData` type in `ipc.ts` must match exactly
- `SessionInfo` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ did, handle, email, emailConfirmed, didDoc }`; the TypeScript `SessionInfo` type in `ipc.ts` must match exactly
- `log_out` deletes exactly three Keychain accounts: `"oauth-access-token"`, `"oauth-refresh-token"`, `"did"` -- adding or removing items from this list changes what data survives a logout
- Keychain account `"managed-dids"` stores a JSON array of all managed DID strings (e.g. `["did:plc:abc","did:plc:def"]`); the single source of truth for which identities are registered in `IdentityStore`
- Per-DID Keychain accounts follow the `"{did}:suffix"` pattern with six suffixes: `device-key` (P-256 private key scalar, software path only; not written on SE path), `device-key-pub` (compressed public key, SE path only), `device-key-app-label` (SE application_label, SE path only), `did-doc` (opaque DID document JSON), `plc-log` (opaque PLC audit log JSON), `oauth-tokens` (reserved for per-DID OAuth tokens)
- `IdentityStore` P-256 multicodec prefix `[0x80, 0x24]` is duplicated from `crates/crypto/src/keys.rs` (same rationale as `device_key.rs` -- `pub(crate)` constant cannot be imported cross-crate)
- `RecoveryError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `RecoveryError` union in `ipc.ts` must match exactly
- `SignedRecoveryOp` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ diff, signedOp }`
- Recovery window is 72 hours from the unauthorized operation's `created_at` timestamp; computed locally but enforced by plc.directory
- `RecoveryState` in `AppState` uses `tokio::sync::Mutex` (same as `ClaimState`) because recovery commands hold the lock across `.await` points
- `MigrateError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `MigrateError` union in `ipc.ts` must match exactly (WALLET_NOT_AUTHORIZED, GUARD_REJECTED, INVALID_RECOMMENDED_CREDENTIALS, INVALID_AUDIT_LOG, SIGNING_FAILED, PLC_DIRECTORY_ERROR, NETWORK_ERROR, IDENTITY_NOT_FOUND, MIGRATION_NOT_READY)
- `AgentsError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `AgentsError.code` union in `ipc.ts` must match exactly (NOT_AUTHENTICATED, CODE_NOT_FOUND, CODE_EXPIRED, ALREADY_CLAIMED, ACCESS_DENIED, AGENT_NOT_FOUND, RATE_LIMITED, NETWORK_ERROR, UNKNOWN); the agent IPC types (`AgentSummary`, `AgentAuditEvent`, `AgentAuditPage`, `AgentClaimPreview`, `AgentClaimConfirmation`) serialize with `#[serde(rename_all = "camelCase")]` and their `ipc.ts` counterparts must match exactly
- Home steps `my_agents` and `agent_approval` in `+page.svelte` render `MyAgentsScreen` (list + in-component detail with audit trail and biometric-gated revoke) and `AgentClaimApprovalScreen` (code entry → `previewAgentClaim` review → `authenticateBiometric` → `confirmAgentClaim`); the biometric prompt precedes the confirm network call, so a rejected gate grants nothing
- `SignedMigrationOp` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ diff, signedOp }`
- `MigrationState` in `AppState` uses `tokio::sync::Mutex` (same as `RecoveryState`) because migration commands hold the lock across `.await` points; it is populated by the migration orchestrator, not by `migrate.rs` itself
- `migrate::guard_migration_op` enforces a STRICT allowlist before signing: (1) `rotationKeys[0]` == device key, (2) device key is in the DID's current rotationKeys (else `WalletNotAuthorized` → orchestrator falls back to the interop path), (3) every other proposed rotation key was recommended by the destination, (4) alsoKnownAs preserved, (5) only the `atproto_pds` service is touched. This is the inverse of `claim.rs`'s guard, which forbids the very key/service changes a migration requires

## Key Files

- `src-tauri/tauri.conf.json` -- Tauri config: bundle ID, devUrl, frontendDist, window settings
- `src-tauri/src/lib.rs` -- Tauri IPC commands (`get_pds_url`, `save_pds_url`, `get_appearance_preference`, `set_appearance_preference`, `create_account`, `get_or_create_device_key`, `sign_with_device_key`, `perform_did_ceremony`, `oauth::prepare_oauth_flow`, `oauth::complete_oauth_flow`, `home::load_home_data`, `home::log_out`, `claim::resolve_identity`, `claim::authenticate_source_pds`, `claim::request_claim_verification`, `claim::sign_and_verify_claim`, `claim::submit_claim`, `list_identities`, `get_stored_did_doc`, `get_device_key_id`, `register_created_identity`, `plc_monitor::check_identity_status`, `recovery::build_recovery_override_cmd`, `recovery::submit_recovery_override_cmd`, `migrate::build_migration_op_cmd`, `migrate::submit_migration_op_cmd`), `run()` (mobile entry point), auth-session plugin setup, startup token restore, PLC monitoring loop spawn
- `src-tauri/src/home.rs` -- Home screen Tauri commands: `load_home_data` (concurrent PDS health + getSession), `log_out` (Keychain wipe + session clear); output types: HomeData, SessionInfo
- `src-tauri/src/device_key.rs` -- P-256 device key module: `#[cfg]`-dispatched `get_or_create()` and `sign()` (simulator software path vs. Secure Enclave)
- `src-tauri/src/identity_store.rs` -- Multi-identity Keychain management: IdentityStore (add/remove/list identities, per-DID device key generation, DID doc + PLC log persistence)
- `src-tauri/src/claim.rs` -- PLC rotation key claim flow: 5 Tauri IPC commands (resolve_identity, authenticate_source_pds, request_claim_verification, sign_and_verify_claim, submit_claim); types (IdentityInfo, VerifiedClaimOp, OpDiff, ServiceChange, ClaimResult, ClaimState); error enums (ResolveError, ClaimError)
- `src-tauri/src/plc_monitor.rs` -- PLC monitoring: PlcMonitor (check_all, check_for_changes), run_monitoring_loop (15-min background timer), check_identity_status (IPC command); types (UnauthorizedChange, IdentityStatus, MonitorError)
- `src-tauri/src/recovery.rs` -- Recovery override: build_recovery_override_cmd, submit_recovery_override_cmd; fork-point identification, per-DID signing, recovery window check
- `src-tauri/src/migrate.rs` -- Self-signed migration identity leg: build_migration_op_cmd, submit_migration_op_cmd; strict pre-sign guard (guard_migration_op), RecommendedCredentials→typed-map converters, current-state extraction, migration diff, per-DID device-key signing; types SignedMigrationOp, MigrationState, MigrateError
- `src-tauri/src/pds_client.rs` -- PDS discovery and OAuth to arbitrary PDS: PdsClient (resolve_handle, discover_pds, discover_auth_server, pds_par, pds_token_exchange, build_pds_authorize_url, fetch_audit_log, post_plc_operation, create_session); XRPC identity functions (request_plc_operation_signature, sign_plc_operation, get_recommended_did_credentials)
- `src-tauri/src/main.rs` -- Desktop entry point (calls `lib::run()`)
- `src-tauri/src/oauth.rs` -- OAuth PKCE module: AppState, DPoPKeypair, OAuthSession, OAuthPrepared, PKCE utilities, prepare_oauth_flow/complete_oauth_flow commands, parse_callback_url
- `vendor/tauri-plugin-auth-session/` -- vendored Tauri plugin (ASWebAuthenticationSession); path dep of src-tauri, excluded from the workspace; see VENDORED.md for provenance + audit
- `src-tauri/src/oauth_client.rs` -- OAuthClient: authenticated HTTP client with DPoP proofs and lazy token refresh
- `src-tauri/src/keychain.rs` -- iOS Keychain abstraction (store_item, get_item, delete_item); PDS URL helpers (store_pds_url, load_pds_url); OAuth helpers (store_dpop_key, load_dpop_key, store_oauth_tokens, load_oauth_tokens)
- `src-tauri/src/http.rs` -- CustosClient with runtime-configurable base URL; OAuth methods (par, token_exchange)
- `src-tauri/.cargo/config.toml` -- Cargo configuration: `RUST_TEST_THREADS=1` (prevent test race conditions)
- `apps/identity-wallet/scripts/ios-env.sh` -- thin sourcing wrapper over the SHARED implementation `scripts/ios/ios-env.sh` (repo root; one copy for both app lanes): Apple toolchain derivation for iOS cross-compilation — resolves `DEVELOPER_DIR` via `/usr/bin/xcode-select -p`, exports iOS-target `CC`/`AR`/linker overrides unconditionally and macOS-host overrides only under `EZPDS_IOS_BUILD=1`. Sourced (never executed) by devenv `enterShell` and the patched Xcode Run Script phase
- `scripts/ios/project.yml` (repo root) -- the SHARED forked XcodeGen project template for BOTH iOS apps, rendered into `gen/apple/project.yml` by every `cargo tauri ios init` (via `bundle > iOS > template` in `tauri.conf.json`). Carries every Xcode-project workaround declaratively: `ENABLE_USER_SCRIPT_SANDBOXING: NO`, the dev-env preamble in the "Build Rust Code" phase (`EZPDS_IOS_BUILD=1` + PATH + `source ios-env.sh`, all `$SRCROOT`-derived — no machine paths), `CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION: YES`, `OTHER_LDFLAGS` rendered from `bundle > iOS > frameworks` (this app: SystemConfiguration for the `system-configuration` crate + AuthenticationServices for the vendored `tauri-plugin-auth-session`), and `Externals → buildPhase: none` (no loose `libapp.a` in the bundle). Forked from tauri-cli's built-in template; the pristine copy sits next to it as `upstream-project.yml`, and `just ios-template-check` (Linux, part of `just ci`) keeps the fork in lockstep with the workflows' tauri-cli pin
- `apps/identity-wallet/scripts/ios-postinit.sh` -- thin wrapper over the SHARED `scripts/ios/ios-postinit.sh` (repo root), pinning this app's dir and `ios` recipe prefix; run after every `cargo tauri ios init` (idempotent): verifies the swift-rs `[patch.crates-io]` entry, asserts the generated project.yml was rendered from the template, regenerates the AppIcon asset catalog from `app-icon.png` via `cargo tauri icon` (into the gitignored catalog + `src-tauri/icons-build/`), then runs the full ios-check
- `apps/identity-wallet/scripts/ios-check.sh` -- thin wrapper over the SHARED `scripts/ios/ios-check.sh` (repo root; same wrapper arguments as ios-postinit.sh); read-only verifier of the GENERATED project's end state: template sentinel in project.yml, every template-carried setting in the pbxproj (frameworks read from `tauri.conf.json`), the app-icon sha256 marker, and `plutil -lint`; gates `just ios-dev`/`ios-build`
- `apps/identity-wallet/app-icon.svg` -- the Obsign app icon's vector source of truth (the SealEmblem wax seal + shield-check; rationale in the root DESIGN.md §6); `app-icon.png` is its 1024×1024 render and the input `cargo tauri icon` consumes (Patch G regenerates the gitignored AppIcon asset catalog from it after every `cargo tauri ios init`). To change the icon: edit the SVG, re-render the PNG at 1024×1024 (e.g. resvg), commit both, re-run `just ios-postinit`
- `apps/identity-wallet/AppIcon.icon/` -- the layered Icon Composer document for the iOS 26 Liquid Glass icon: `icon.json` (fill gradient + one group: shield.svg over seal.svg, specular on, neutral shadow) + `Assets/*.svg` layers split from `app-icon.svg` with NO baked drop shadows (Liquid Glass supplies lighting/shadow). Referenced in place by the XcodeGen template (`scripts/ios/project.yml`, with a `fileTypes` mapping so the .icon package stays one file); Xcode 26 prefers it over the same-named appiconset, which remains the older-toolchain fallback. Compiled/validated by actool in `just ios-pr-check` (`just _icon-compile`); `just ios-check` verifies the rendered registration. Keep layer geometry in sync with the master SVG when the icon changes
- `src/lib/ipc.ts` -- Typed TypeScript wrappers for all Tauri IPC commands (getPdsUrl, savePdsUrl, createAccount, getOrCreateDeviceKey, signWithDeviceKey, performDIDCeremony, startOAuthFlow, loadHomeData, logOut, resolveIdentity, authenticateSourcePds, requestClaimVerification, signAndVerifyClaim, submitClaim, listIdentities, getStoredDidDoc, getDeviceKeyId, checkIdentityStatus, checkHandleResolution, buildRecoveryOverride, submitRecoveryOverride, buildMigrationOp, submitMigrationOp)
- `src/lib/components/onboarding/` -- Seventeen onboarding screen components (ModeSelectScreen, PdsConfigScreen, ClaimCodeScreen, EmailScreen, HandleScreen, PasswordScreen, LoadingScreen, DIDCeremonyScreen, DIDSuccessScreen, ShamirBackupScreen, HandleRegistrationScreen, AuthenticatingScreen, IdentityInputScreen, PdsAuthScreen, EmailVerificationScreen, ReviewOperationScreen, ClaimSuccessScreen)
- `src/lib/components/home/` -- Six home screen components (IdentityListHome, HomeScreen, DIDDocumentScreen, RecoveryInfoScreen, AlertDetailScreen, RecoveryOverrideScreen) plus DIDAvatar utility component
- `src/lib/utils/deadline.ts` -- PLC recovery deadline utilities (getDeadline, getUrgency, formatCountdown); tested by `deadline.test.ts`
- `src/routes/+page.svelte` -- Two-flow state machine starting at mode_select; Create flow: mode_select -> pds_config -> ... -> home; Import flow: mode_select -> identity_input -> pds_auth -> email_verification -> review_operation -> claim_success -> home; Home: home (IdentityListHome) -> identity_detail -> did_document / recovery_info / alert_detail -> recovery_override, plus home -> settings (SettingsScreen, appearance control); visibilitychange handler calls checkIdentityStatus() on foreground
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

The Nix devenv's Darwin setup hooks override `DEVELOPER_DIR` (and `SDKROOT`) to a Nix apple-sdk stub that has no runtime tools. The `xcbuild` xcrun shim in PATH delegates to `$DEVELOPER_DIR/usr/bin/xcrun` — if `DEVELOPER_DIR` points at a Nix stub, it fails.

**Fix:** Already resolved automatically. `devenv.nix`'s `enterShell` sources `apps/identity-wallet/scripts/ios-env.sh`. The catch: `/usr/bin/xcode-select -p` and `/usr/bin/xcrun` both **honor `DEVELOPER_DIR` above the system Xcode selection**, so calling them by absolute path is not enough — they echo the Nix stub straight back. `ios-env.sh` first **unsets `DEVELOPER_DIR` when it points into `/nix/store`**, so `xcode-select -p` falls through to the real Xcode selection; it then re-exports `DEVELOPER_DIR` to that real path. (A genuine Xcode-provided `DEVELOPER_DIR` — not under `/nix/store` — is left untouched, so the Xcode Run Script keeps Xcode's own value.)

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

**Fix:** Already resolved automatically. The `scripts/ios/project.yml` template sets `ENABLE_USER_SCRIPT_SANDBOXING: NO`, which every `cargo tauri ios init` renders into the generated project; `just ios-check` verifies the setting is in place.

---

### `Undefined symbols ... _SC*` / `_ASWebAuthenticationSession*` — an Apple framework not linked at `Ld`

The Rust code compiles, then Xcode's link step fails with `Undefined symbols for architecture arm64:` naming Apple framework symbols — e.g. `_SCDynamicStore...` / `_SCNetworkReachability...` (Apple's `SystemConfiguration.framework`, which the `system-configuration` crate needs — pulled in transitively by `hickory-resolver` for system DNS config and `reqwest` for system proxy detection), or `_ASWebAuthenticationSessionErrorDomain` (Apple's `AuthenticationServices.framework`, which the vendored `tauri-plugin-auth-session` needs via `objc2-authentication-services` / `ASWebAuthenticationSession`).

Host builds (`cargo test` / `cargo build`) link fine because **rustc** does the final link and honors the crate's `#[link(name = "...", kind = "framework")]`. On iOS the crate is built as a `staticlib` (`libapp.a`) and **Xcode** does the final link — it never sees that embedded directive, so the framework must be declared in the Xcode project or the symbols stay undefined. A `build.rs` `cargo:rustc-link-lib=framework=...` does NOT help (same staticlib → Xcode gap).

**Fix:** Already resolved automatically. The `scripts/ios/project.yml` template renders `OTHER_LDFLAGS = "$(inherited) -framework SystemConfiguration -framework AuthenticationServices"` from `bundle > iOS > frameworks` in `tauri.conf.json` (the same list also produces xcodegen `sdk:` link dependencies), and `just ios-check` verifies every listed framework. The historical footgun this design removes: `bundle.iOS.frameworks` used to seed only a FRESH project.yml, because `cargo tauri ios init` preserves an existing one — with the custom template, project.yml is re-rendered from config on every init, so the config is now the enforced mechanism. To link another Apple framework a new Rust dep requires, **add it to `bundle > iOS > frameworks` in `tauri.conf.json`** and re-run `cargo tauri ios init` + `just ios-postinit` — never hand-edit `OTHER_LDFLAGS` in the generated project (a second `OTHER_LDFLAGS` assignment for the same build config shadows, not appends to, the first, silently dropping a framework — `just ios-check` detects that state).

---

### `libapp.a ... is not permitted` / `Invalid bundle structure` on TestFlight upload

`cargo tauri ios build` succeeds and `xcrun altool` then rejects the upload (HTTP 409): *"The 'Obsign.app/libapp.a' binary file is not permitted. Your app cannot contain standalone executables or libraries."* (tauri#13578.)

cargo-mobile2 lists the `Externals` directory (which holds the Rust staticlib `libapp.a`) as a project source with **no explicit `buildPhase`**, so XcodeGen infers `resources` and copies the raw `.a` into the `.app` — which App Store validation forbids. The library is also (correctly) **linked** via the separate `framework: libapp.a` entry + `LIBRARY_SEARCH_PATHS`, so excluding it from resources is safe.

**Fix:** Already resolved automatically. The `scripts/ios/project.yml` template sets `Externals → buildPhase: none`, so xcodegen never emits a `libapp.a in Resources` entry (the `framework: libapp.a` link dependency is kept). `just ios-check` verifies both layers.

---

### `base64: invalid option -- 'o'` during `cargo tauri ios build` signing

The build reads `IOS_CERTIFICATE` and fails decoding it: `base64: invalid option -- 'o'`. In the Nix dev shell, GNU coreutils `base64` shadows macOS's BSD `base64` in `PATH`, but Tauri's cert decode uses BSD-only flags (`-i`/`-o`). (CI is unaffected — the runner has no Nix.)

**Fix:** Already resolved automatically. `scripts/ios-env.sh` (under `EZPDS_IOS_BUILD=1`) shims `/usr/bin/base64` ahead of the Nix one via a tiny symlink dir on `PATH` — surgical (only `base64`), leaving every other Nix tool untouched.
