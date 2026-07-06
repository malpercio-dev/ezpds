# Wallet Outbound Migration — Phase 3: Orchestrator module — state, setup, and auth

**Goal:** Stand up the `migration_orchestrator.rs` state machine with its front half — the state/error types, `AppState` wiring, command registration, and the first three commands: `prepare_migration` (resolve destination + source), the `prepare_source_auth`/`complete_source_auth` OAuth pair, and `create_destination_account` (reserve key → service-auth → deactivated account → Bearer session, tolerating `DidAlreadyExists`).

**Architecture:** A new module mirroring `claim.rs`: a single `OutboundMigrationState` parked in `AppState.orchestration_state` behind a `tokio::sync::Mutex<Option<...>>`, plus `pending_source_login: Mutex<Option<PendingSourceLogin>>` for the OAuth prepare/complete split. Each command validates its prerequisite phase and the `did` argument, clones `Arc<OAuthClient>` out of the lock before network calls, and is a thin `#[tauri::command]` wrapper over a pure `_impl` that takes explicit dependencies (following `migrate.rs`'s `build_migration_op_cmd` → `build_migration_op`).

**Tech Stack:** Rust, Tauri v2 commands, `tokio::sync::Mutex`, `std::sync::Arc`, `httpmock` for the network `#[ignore]` tests, `serde` SCREAMING_SNAKE_CASE error enum.

**Scope:** Phase 3 of 7.

**Codebase verified:** 2026-07-05.

---

## Acceptance Criteria Coverage

This phase implements and tests (auth/setup portion of AC1; establishes the error contract for AC10):

### wallet-outbound-migration.AC1: A wallet-authorized outbound migration drives to completion
- **wallet-outbound-migration.AC1.3 Failure:** Any command invoked out of phase order (e.g. `transfer_repo` before `create_destination_account`) returns `MIGRATION_NOT_READY` without performing network side effects.
- **wallet-outbound-migration.AC1.4 Failure:** A command whose `did` argument does not match `OutboundMigrationState.did` returns `MIGRATION_NOT_READY` (defense-in-depth against a concurrent flow).
- **wallet-outbound-migration.AC1.5 Failure:** `prepare_migration` against an unreachable destination PDS returns `DESTINATION_UNREACHABLE`.

### wallet-outbound-migration.AC5: Partial failure is resumable and leaves a coherent state
- **wallet-outbound-migration.AC5.1 Success:** Re-running `create_destination_account` after the account already exists tolerates `DidAlreadyExists` and re-establishes the destination Bearer session.

### wallet-outbound-migration.AC10: Cross-cutting behaviors
- **wallet-outbound-migration.AC10.1:** `MigrationError` serializes as `{ "code": "SCREAMING_SNAKE_CASE" }`, matching the wallet's established error contract.
- **wallet-outbound-migration.AC10.3:** Migration state lives only in `AppState` (in-memory); an app kill loses it and the flow restarts from `prepare_migration`.

---

## Verified codebase facts

- `claim.rs` is the exact template. `ClaimState { did, pds_url, did_doc: PlcDidDocument, pds_oauth_client: Option<Arc<OAuthClient>>, verified_signed_op: Option<Value> }`. `ClaimError` uses `#[derive(Debug, Serialize, thiserror::Error)] #[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]`.
- `PendingPdsLogin { did, pds_url, pkce_verifier, csrf_state, metadata: AuthServerMetadata, client_id, oauth_client_pds_url }` (claim.rs 129–149).
- `claim::prepare_pds_auth(state, pds_url) -> Result<OAuthPrepared, ClaimError>` (346–446): gate on `ClaimState`, `pds_client.discover_auth_server`, generate PKCE+CSRF, `DPoPKeypair::get_or_create`, `pds_par` with nonce retry, park `PendingPdsLogin`, return `OAuthPrepared { auth_url, callback_scheme }`.
- `claim::complete_pds_auth(app, state, callback_url) -> Result<(), ClaimError>` (454–544): take+clear `pending_pds_login`, `oauth::parse_callback_url` + CSRF check, DPoP keypair, `pds_token_exchange` with nonce retry, build `OAuthClient` via `OAuthClient::new`, store `Arc::new(oauth_client)` into state, emit an event.
- Gating pattern: `let Some(claim) = claim_state.as_ref() else { return Err(...) }; if claim.pds_url != pds_url { return Err(...) }`.
- `AppState` (oauth.rs 21–53) fields incl. `pending_pds_login: Mutex<Option<PendingPdsLogin>>` (29), `pds_client: PdsClient` (38), `claim_state: tokio::sync::Mutex<Option<ClaimState>>` (43), `migration_state: tokio::sync::Mutex<Option<MigrationState>>` (52). `AppState::new()` (56–67) initializes each with `Mutex::new(None)` / `tokio::sync::Mutex::new(None)`.
- `oauth::parse_callback_url(&str) -> Result<(String, String), OAuthError>` returns `(code, state)`; `OAuthPrepared { auth_url, callback_scheme }`.
- `lib.rs`: module decls at lines 1–12 (alphabetical); `tauri::generate_handler![...]` at 913–942 lists claim/migrate/recovery commands.
- `PdsClient::discover_pds(did) -> (String, PlcDidDocument)` resolves the SOURCE PDS URL + DID doc (`also_known_as` holds `at://handle`); it also HEAD-checks PDS reachability.
- `OAuthClient::new(session, base_url)` builds a DPoP client; `OAuthClient::new_bearer(access_jwt, refresh_jwt, base_url)` (Phase 1) builds a Bearer client.

---

## Design decisions locked (from verification)

1. **`OutboundMigrationState` carries `source_pds_url`** (not in the design's sketch but required by source auth — it is resolved by `prepare_migration` via `discover_pds`) and a `dest_password`-free create (the migration account is OAuth-only; the server stores NULL password).
2. **Every command takes a `did` argument** validated against `OutboundMigrationState.did` (uniform AC1.4 defense-in-depth), including `prepare_source_auth(did)` / `complete_source_auth(did, callback_url)`. This is a small, deliberate divergence from the design's arg sketch that makes AC1.4 uniform.
3. **`create_destination_account(did, email, invite_code)`** takes `email` (server-required) and an optional `invite_code`. It calls **`reserveSigningKey` first** (server-required), then `getServiceAuth`, then `createAccount`.
4. **`DidAlreadyExists` handling / resume (AC5.1):** `create_destination_account` is idempotent within a live app session. If `dest_client` is already present (phase ≥ `DestCreated`), it returns early (re-establishes = returns the cached still-valid session). If `createAccount` returns `DidAlreadyExists` while a `dest_client` is held, it is tolerated (kept). If the account exists but **no** `dest_client` is held (only possible after an app kill wiped in-memory state), it returns `DESTINATION_CONFLICT` — consistent with **AC10.3** (app kill restarts the flow; cross-kill session recovery would require persistence, which is explicitly out of the in-memory design). Document this at the call site.
5. **The gating helper `ensure_phase_did` is a pure function** (no `.await`, no network) so AC1.3/AC1.4 are unit-testable inline and side-effect-free.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Module scaffold — state, phase, error types, PendingSourceLogin, gating helper

**Verifies:** wallet-outbound-migration.AC1.3, wallet-outbound-migration.AC1.4, wallet-outbound-migration.AC10.1

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`

**Implementation:**
```rust
use std::sync::Arc;
use crate::oauth_client::OAuthClient;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum MigrationPhase {
    Resolved, SourceAuthed, DestCreated, RepoTransferred,
    BlobsTransferred, PreferencesTransferred, Verified, IdentityArmed, Finalized,
}

pub struct OutboundMigrationState {
    pub did: String,
    pub source_pds_url: String,       // resolved in prepare_migration (discover_pds)
    pub dest_pds_url: String,
    pub dest_did: String,             // getServiceAuth `aud`, from dest describeServer
    pub handle: String,               // preserved into createAccount
    pub source_client: Option<Arc<OAuthClient>>,  // DPoP, old PDS
    pub dest_client: Option<Arc<OAuthClient>>,    // Bearer, new PDS
    pub phase: MigrationPhase,
}

#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationError {
    #[error("migration not ready: {message}")]
    MigrationNotReady { message: String },
    #[error("destination unreachable: {message}")]
    DestinationUnreachable { message: String },
    #[error("source auth failed: {message}")]
    SourceAuthFailed { message: String },
    #[error("service auth failed: {message}")]
    ServiceAuthFailed { message: String },
    #[error("account creation failed: {message}")]
    AccountCreationFailed { message: String },
    #[error("destination conflict: {message}")]
    DestinationConflict { message: String },
    #[error("repo transfer failed: {message}")]
    RepoTransferFailed { message: String },
    #[error("blob transfer failed: {message}")]
    BlobTransferFailed { message: String },
    #[error("preferences transfer failed: {message}")]
    PreferencesTransferFailed { message: String },
    #[error("verification incomplete")]
    VerificationIncomplete { imported: u64, expected: u64 },
    #[error("activation failed: {message}")]
    ActivationFailed { message: String },
    #[error("deactivation failed: {message}")]
    DeactivationFailed { message: String },
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// Pending source-PDS OAuth login, parked between prepare_source_auth and complete_source_auth
/// (twin of claim::PendingPdsLogin). Defined here in Task 1 so AppState (Task 2) can reference it.
pub struct PendingSourceLogin {
    pub did: String,
    pub source_pds_url: String,
    pub pkce_verifier: String,
    pub csrf_state: String,
    pub metadata: crate::pds_client::AuthServerMetadata,
    pub client_id: String,
    pub oauth_client_pds_url: String,
}

/// Pure prerequisite gate: state present, DID matches, and phase is at least `required`.
/// No network, no side effects — this is what makes AC1.3/AC1.4 hold "without side effects".
pub(crate) fn ensure_phase_did<'a>(
    state: &'a Option<OutboundMigrationState>,
    did: &str,
    required: MigrationPhase,
) -> Result<&'a OutboundMigrationState, MigrationError> {
    let Some(s) = state.as_ref() else {
        return Err(MigrationError::MigrationNotReady { message: "no migration in progress".into() });
    };
    if s.did != did {
        return Err(MigrationError::MigrationNotReady { message: "did does not match active migration".into() });
    }
    if s.phase < required {
        return Err(MigrationError::MigrationNotReady {
            message: format!("expected phase >= {:?}, found {:?}", required, s.phase),
        });
    }
    Ok(s)
}
```

**Testing (inline `#[test]`, no network — this is the pure core):**
Tests must verify:
- AC1.3: `ensure_phase_did(&Some(state_at_SourceAuthed), &did, MigrationPhase::RepoTransferred)` returns `MigrationNotReady`.
- AC1.4: `ensure_phase_did(&Some(state_with_did_A), "did:plc:B", MigrationPhase::Resolved)` returns `MigrationNotReady`.
- `ensure_phase_did(&None, ...)` returns `MigrationNotReady`.
- AC10.1: `serde_json::to_value(MigrationError::MigrationNotReady{message:"x".into()})` produces `{"code":"MIGRATION_NOT_READY","message":"x"}`; `VerificationIncomplete{imported:1,expected:2}` produces `{"code":"VERIFICATION_INCOMPLETE","imported":1,"expected":2}`. (Assert the `code` casing for a couple more variants.)

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```
Expected: gating + serialization tests pass.

**Commit:** `feat(wallet): migration_orchestrator scaffold (state, phase, error, gate)`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `AppState` wiring + module registration

**Verifies:** wallet-outbound-migration.AC10.3 (state lives only in AppState, in-memory)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs` (`AppState` struct 21–53; `AppState::new` 56–67)
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (module decl 1–12; handler list 913–942)

**Implementation:**
- In `AppState`, add (near `migration_state`):
  ```rust
  /// Outbound-migration orchestration state (in-memory only; an app kill restarts from
  /// prepare_migration). tokio::sync::Mutex because commands hold the lock across .await.
  pub orchestration_state: tokio::sync::Mutex<Option<crate::migration_orchestrator::OutboundMigrationState>>,
  /// Pending source-PDS OAuth login, parked between prepare_source_auth and complete_source_auth
  /// (twin of pending_pds_login).
  pub pending_source_login: Mutex<Option<crate::migration_orchestrator::PendingSourceLogin>>,
  ```
- In `AppState::new`, initialize both: `orchestration_state: tokio::sync::Mutex::new(None)`, `pending_source_login: Mutex::new(None)`.
- In `lib.rs`, add `pub mod migration_orchestrator;` alphabetically (after `pub mod migrate;`).
- **Do NOT add any `generate_handler!` entries in this task.** The four Phase 3 commands do not exist yet (they land in Tasks 4–6), and referencing a non-existent command in `generate_handler!` fails to compile. The handler entries are all added in **Task 6** once every command exists.

Both `AppState` fields compile now because both types they reference — `OutboundMigrationState` and `PendingSourceLogin` — are defined in Task 1. `pub mod migration_orchestrator;` referencing a module that currently holds only types (no commands) also compiles.

**Testing:** None (wiring; the compiler verifies registration once Task 6 adds the handler entries — a bad command signature fails `generate_handler!`).

**Verification:**
```
cargo build -p identity-wallet
```
Expected: compiles. The `mod` declaration + the two `AppState` fields (referencing Task 1's types) build cleanly; no `generate_handler!` change happens here (deferred to Task 6).

**Commit:** `feat(wallet): register migration_orchestrator + AppState orchestration fields`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `PdsClient::describe_server`

**Verifies:** supports AC1.5 (describe_server reachability)

(`PendingSourceLogin` is already defined in Task 1's scaffold — it lives in `migration_orchestrator.rs` so `AppState` can reference it in Task 2. Nothing to add for it here.)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs` (add `describe_server` + `DescribeServerResponse`)

**Implementation:**
- `PdsClient::describe_server`:
  ```rust
  #[derive(Debug, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct DescribeServerResponse {
      pub did: String,
      #[serde(default)]
      pub available_user_domains: Vec<String>,
  }

  /// GET com.atproto.server.describeServer (auth: none). Also serves as the destination
  /// reachability probe for prepare_migration.
  pub async fn describe_server(&self, pds_url: &str) -> Result<DescribeServerResponse, PdsClientError> {
      // GET {pds_url}/xrpc/com.atproto.server.describeServer
      // connection error / non-2xx -> PdsClientError::PdsUnreachable { reason } (so prepare_migration
      // can map it to DESTINATION_UNREACHABLE); parse -> DescribeServerResponse
  }
  ```
  Use a short connect timeout (reuse the existing 30s client, or the reachability idiom from `discover_pds`). Map a connection failure to `PdsClientError::PdsUnreachable { reason }`.

**Testing (inline `httpmock` in `pds_client.rs`):**
- `describe_server` against a mock returning `{"did":"did:web:dest","availableUserDomains":[".dest"]}` parses `did`.
- (Reachability) `describe_server` against a closed/unreachable URL returns `PdsClientError::PdsUnreachable` — mark this test `#[ignore] // Requires socket binding; ignore in sandboxed environments` if it binds/connects a socket.

**Verification:**
```
cargo test -p identity-wallet --lib pds_client
```
Expected: describe_server parse test passes.

**Commit:** `feat(wallet): PdsClient::describe_server (dest reachability + dest_did)`
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 4-6) -->

<!-- START_TASK_4 -->
### Task 4: `prepare_migration` command

**Verifies:** wallet-outbound-migration.AC1.5, wallet-outbound-migration.AC10.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`

**Implementation:**
```rust
#[tauri::command]
pub async fn prepare_migration(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    dest_pds_url: String,
) -> Result<(), MigrationError> {
    let pds_client = state.pds_client();  // confirm accessor name in oauth.rs (pds_client field is private w/ getter)
    // 1. discover source: (source_pds_url, plc_doc) = pds_client.discover_pds(&did).await
    //    map err -> MigrationError::NetworkError / a resolve failure message.
    //    handle = plc_doc.also_known_as.first() stripped of "at://"  (error if none)
    // 2. describe dest: dest = pds_client.describe_server(&dest_pds_url).await
    //    map PdsUnreachable -> MigrationError::DestinationUnreachable { message }
    //    map other err -> DestinationUnreachable or NetworkError as appropriate
    // 3. store fresh state:
    //    *state.orchestration_state.lock().await = Some(OutboundMigrationState {
    //        did, source_pds_url, dest_pds_url, dest_did: dest.did, handle,
    //        source_client: None, dest_client: None, phase: MigrationPhase::Resolved });
    Ok(())
}
```
Confirm the `PdsClient` accessor on `AppState` (investigation shows `pds_client` is a field with a getter used by claim commands, e.g. `state.pds_client()` — verify the exact method/field visibility and use whatever `claim.rs` uses).

**Testing:**
- AC1.5: `prepare_migration` with a `dest_pds_url` pointing at an unreachable host returns `DESTINATION_UNREACHABLE`. This needs `discover_pds` to succeed first — structure the test so the source resolves (mock plc.directory + source) but the dest describeServer is unreachable, OR test `describe_server`'s unreachable mapping in isolation (Task 3) and here assert the mapping `PdsUnreachable -> DestinationUnreachable`. Prefer an `_impl` split so the mapping is unit-testable without real sockets; mark any socket-binding variant `#[ignore]`.
- AC10.3 (documentation-level): assert that after `prepare_migration`, the state is present in `orchestration_state`, and that there is no disk/Keychain write (state is in-memory only). A direct assertion is the presence in the mutex; add a `// in-memory only; app kill restarts from prepare_migration` comment.

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```

**Commit:** `feat(wallet): prepare_migration (resolve dest describeServer + source)`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Source-PDS OAuth — `prepare_source_auth` / `complete_source_auth`

**Verifies:** wallet-outbound-migration.AC1.4 (did gate on these commands)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`

**Implementation:** Mirror `claim::prepare_pds_auth` / `claim::complete_pds_auth` almost verbatim, substituting the orchestration state + `pending_source_login`, and reading the source PDS URL from `OutboundMigrationState.source_pds_url` (not a parameter).
```rust
#[tauri::command]
pub async fn prepare_source_auth(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<crate::oauth::OAuthPrepared, MigrationError> {
    // gate: ensure_phase_did(&*orchestration_state.lock().await, &did, MigrationPhase::Resolved)
    //       and read source_pds_url out; drop lock.
    // then follow claim::prepare_pds_auth: discover_auth_server(source_pds_url), PKCE+CSRF,
    //   DPoPKeypair::get_or_create, pds_par (+ nonce retry), park PendingSourceLogin,
    //   return OAuthPrepared { auth_url, callback_scheme }.
}

#[tauri::command]
pub async fn complete_source_auth(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    callback_url: String,
) -> Result<(), MigrationError> {
    // take+clear pending_source_login; validate did matches; parse_callback_url + CSRF check;
    // DPoP keypair; pds_token_exchange (+ nonce retry); build OAuthClient::new(session, source_pds_url);
    // store Arc::new(client) into orchestration_state.source_client; advance phase -> SourceAuthed.
}
```
Reuse `claim.rs`'s helpers where they are shared (`oauth::parse_callback_url`, `OAuthPrepared`, `pds_par`, `pds_token_exchange`). Map `ClaimError`/`OAuthError`/`PdsClientError` into `MigrationError::SourceAuthFailed { message }` (or `NetworkError`).

**Testing:**
- AC1.4: `prepare_source_auth("did:plc:OTHER")` when the active state's did differs returns `MIGRATION_NOT_READY`.
- Gating before `Resolved`: `prepare_source_auth` with no active state returns `MIGRATION_NOT_READY`.
- The happy-path OAuth exchange is exercised end-to-end by the Phase 5 full-pipeline integration test (it needs a mock auth server + token endpoint); a focused `#[ignore]` mock test here is optional. Do NOT duplicate the whole `claim.rs` OAuth test surface — assert the gate and that a successful completion advances the phase to `SourceAuthed` and stores a `source_client`.

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
```

**Commit:** `feat(wallet): source-PDS OAuth prepare/complete (mirrors claim flow)`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: `create_destination_account` + wire the four handlers

**Verifies:** wallet-outbound-migration.AC5.1, wallet-outbound-migration.AC1.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (add the four handler entries from Task 2)

**Implementation:** Split into a pure `_impl` (testable with mock servers) and the `#[tauri::command]` wrapper.
```rust
/// Pure core: reserve key, mint service-auth, create the deactivated account, return the
/// destination Bearer client. Takes explicit deps so it is unit-testable.
async fn create_destination_account_impl(
    pds_client: &crate::pds_client::PdsClient,
    source_client: &OAuthClient,
    dest_pds_url: &str,
    dest_did: &str,
    did: &str,
    handle: &str,
    email: &str,
    invite_code: Option<String>,
    existing_dest_client: Option<Arc<OAuthClient>>,
) -> Result<Arc<OAuthClient>, MigrationError> {
    // 0. If existing_dest_client.is_some() -> return it (idempotent fast path).
    // 1. reserveSigningKey(dest): pds_client.reserve_signing_key(dest_pds_url, did).await
    //    err -> AccountCreationFailed
    // 2. serviceAuth: get_service_auth(source_client, dest_did, "com.atproto.server.createAccount").await
    //    err -> ServiceAuthFailed
    // 3. one-shot Bearer client carrying the service-auth token:
    //    let sa_client = OAuthClient::new_bearer(token.token, String::new(), dest_pds_url.into())?;
    // 4. createAccount(migration):
    //    let req = CreateAccountMigrationRequest { handle: handle.into(), email: email.into(),
    //                                              did: did.into(), invite_code };
    //    match create_account_migration(&sa_client, &req).await {
    //        Ok(resp) => Ok(Arc::new(OAuthClient::new_bearer(resp.access_jwt, resp.refresh_jwt, dest_pds_url.into())?)),
    //        Err(PdsClientError::DidAlreadyExists) => match existing_dest_client {
    //            Some(c) => Ok(c),                              // tolerate (AC5.1)
    //            None => Err(MigrationError::DestinationConflict {
    //                message: "account exists but session was lost (app kill); restart migration".into() }),
    //        },
    //        Err(e) => Err(MigrationError::AccountCreationFailed { message: e.to_string() }),
    //    }
}

#[tauri::command]
pub async fn create_destination_account(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    email: String,
    invite_code: Option<String>,
) -> Result<(), MigrationError> {
    // gate: ensure_phase_did(.., &did, MigrationPhase::SourceAuthed); clone source_client (Arc),
    //       read dest_pds_url/dest_did/handle, and read existing dest_client (Arc clone); drop lock.
    // call create_destination_account_impl(...); on Ok(dest_client):
    //   re-lock, re-validate did, set state.dest_client = Some(dest_client), phase = DestCreated.
}
```
Add the four handler entries to `generate_handler!` (deferred from Task 2) now that the commands exist.

**Testing (mock `httpmock`, `#[ignore] // Requires socket binding; ...`):**
- AC5.1: `create_destination_account_impl` with `existing_dest_client: Some(client)` returns that client without hitting the network (idempotent re-establish). Additionally, with `existing_dest_client: Some(client)` and a mock `createAccount` returning 409, it still returns Ok(client) (explicit `DidAlreadyExists` tolerance).
- With `existing_dest_client: None` and a mock returning 409, it returns `DESTINATION_CONFLICT`.
- Happy path: mock `reserveSigningKey` (200 `{signingKey}`), `getServiceAuth` (200 `{token}`), `createAccount` (200 session) → returns a Bearer client whose base_url is the mock dest and whose access token is the returned `accessJwt`.
- AC1.3: calling `create_destination_account` when phase is `Resolved` (before source auth) returns `MIGRATION_NOT_READY` (pure gate — no `#[ignore]` needed).

**Verification:**
```
cargo test -p identity-wallet --lib migration_orchestrator
cargo build -p identity-wallet    # confirms the four commands are registered in generate_handler!
```

**Commit:** `feat(wallet): create_destination_account (reserveKey→serviceAuth→createAccount)`
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 3 done when

- `migration_orchestrator.rs` exists with `OutboundMigrationState`, `MigrationPhase`, `MigrationError`, `PendingSourceLogin`, and the pure `ensure_phase_did` gate.
- `AppState` has `orchestration_state` + `pending_source_login`, initialized in `new()`.
- `prepare_migration`, `prepare_source_auth`, `complete_source_auth`, `create_destination_account` are implemented and registered in `generate_handler!`.
- `_impl` gating tests confirm phase/DID checks (AC1.3/AC1.4) and `DidAlreadyExists` tolerance (AC5.1); `MigrationError` serializes SCREAMING_SNAKE_CASE (AC10.1).
- `cargo build -p identity-wallet` and `cargo test -p identity-wallet --lib migration_orchestrator` pass (socket tests may need the sandbox disabled).
- Covers wallet-outbound-migration.AC1.3–AC1.5 (setup), AC5.1, AC10.1, AC10.3.
