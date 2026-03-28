# Relay URL Configuration — Phase 2: AppState Integration and Command Migration

**Goal:** Remove the `RELAY_CLIENT` global static and route all relay access through `AppState`, while keeping the app fully functional using the compile-time default URL.

**Architecture:** Add `relay_client: OnceLock<RelayClient>` to `AppState` (initialized to default until Phase 3 adds Keychain loading). Update all four commands that use `RELAY_CLIENT` to accept `state: tauri::State<'_, AppState>`. Update `start_oauth_flow` and `OAuthClient::new()` to get the URL from state. The app continues to work with the compile-time default URL throughout this phase.

**Tech Stack:** Rust (stable), no new dependencies

**Scope:** 2 of 4 phases

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

Infrastructure/refactor phase — no new ACs tested here.

**Verifies: None** — this phase is a mechanical refactor. Correctness is verified by `cargo build` succeeding, all existing tests passing, and no references to `RELAY_CLIENT` remaining.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Add `relay_client` to `AppState` in `oauth.rs` and add a `default_relay_url` helper in `http.rs`

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs`
- Modify: `apps/identity-wallet/src-tauri/src/http.rs`

**Step 1: Add the `relay_client` field and methods to `AppState` (`oauth.rs`)**

At the top of the file there should already be a `use std::sync::Mutex;` import. Add `OnceLock` to the import. Find the existing `use std::sync::Mutex;` import and change it to:

```rust
use std::sync::{Mutex, OnceLock};
```

Then update the `AppState` struct (currently at lines 17–28) to add the new field:

```rust
pub struct AppState {
    /// The pending OAuth flow waiting for the deep-link callback.
    /// Set by `start_oauth_flow` before opening Safari; cleared by `handle_deep_link`.
    pub pending_auth: Mutex<Option<PendingOAuthFlow>>,
    /// The active authenticated session after a successful token exchange.
    /// Set by `start_oauth_flow` on success; read by `OAuthClient` for every request.
    pub oauth_session: Mutex<Option<OAuthSession>>,
    /// Runtime relay client. Populated from Keychain on startup (Phase 3) or by
    /// `save_relay_url` on first launch. Falls back to the compile-time default if unset.
    relay_client: OnceLock<crate::http::RelayClient>,
}
```

Update `AppState::new()` (currently at lines 30–36) to initialize the new field:

```rust
impl AppState {
    pub fn new() -> Self {
        Self {
            pending_auth: Mutex::new(None),
            oauth_session: Mutex::new(None),
            relay_client: OnceLock::new(),
        }
    }

    /// Returns the configured relay client, or initializes with the compile-time
    /// default URL if none has been set yet.
    pub fn relay_client(&self) -> &crate::http::RelayClient {
        self.relay_client
            .get_or_init(crate::http::RelayClient::new)
    }

    /// Set the relay client from a runtime URL. Silently ignored if already set
    /// (OnceLock::set semantics — this is only called once on first launch).
    pub fn set_relay_client(&self, url: String) {
        self.relay_client
            .set(crate::http::RelayClient::new_with_url(url))
            .ok();
    }
}
```

The `Default` impl at lines 39–42 can remain unchanged (it calls `Self::new()`).

**Step 2: Add `pub fn default_relay_url()` to `http.rs`**

This free function is used by tests and will be used by the frontend default in Phase 3. Add it after the `RELAY_BASE_URL` constants (after line 15):

```rust
/// Returns the compile-time default relay base URL.
///
/// Used by integration tests and as the pre-filled default in the relay
/// configuration UI. The runtime URL (from Keychain or user input) takes
/// precedence during normal app operation.
pub fn default_relay_url() -> &'static str {
    RELAY_BASE_URL
}
```

**Step 3: Verify compilation**

```bash
cargo build --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1 | head -40
```

Expected: Compiles (with possible dead-code warnings for the new methods, which is fine).
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Remove `RELAY_CLIENT` static from `lib.rs` and update all four commands

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Remove the static declaration**

Delete these lines from `lib.rs` (currently lines 227–229):

```rust
// ── Static relay client ─────────────────────────────────────────────────────

static RELAY_CLIENT: LazyLock<http::RelayClient> = LazyLock::new(http::RelayClient::new);
```

Also remove the `LazyLock` import at the top of the file. Find and remove `LazyLock` from the `use std::sync::LazyLock;` import line (or remove the entire import if `LazyLock` is the only thing imported from it).

**Step 2: Update `create_account`**

Add `state: tauri::State<'_, oauth::AppState>` as the last parameter and replace the `RELAY_CLIENT` call:

Before (lines 247–252):
```rust
#[tauri::command]
async fn create_account(
    claim_code: String,
    email: String,
    handle: String,
) -> Result<CreateAccountResult, CreateAccountError> {
```

After:
```rust
#[tauri::command]
async fn create_account(
    claim_code: String,
    email: String,
    handle: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<CreateAccountResult, CreateAccountError> {
```

Replace `RELAY_CLIENT` at line 268:
```rust
    let resp = RELAY_CLIENT
        .post("/v1/accounts/mobile", &req)
```
becomes:
```rust
    let resp = state
        .relay_client()
        .post("/v1/accounts/mobile", &req)
```

**Step 3: Update `perform_did_ceremony`**

Add `state: tauri::State<'_, oauth::AppState>` as the last parameter:

Before (lines 332–336):
```rust
#[tauri::command]
async fn perform_did_ceremony(
    handle: String,
    password: String,
) -> Result<DIDCeremonyResult, DIDCeremonyError> {
```

After:
```rust
#[tauri::command]
async fn perform_did_ceremony(
    handle: String,
    password: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<DIDCeremonyResult, DIDCeremonyError> {
```

Replace `RELAY_CLIENT` at line 345:
```rust
    let resp =
        RELAY_CLIENT
            .get("/v1/relay/keys")
```
becomes:
```rust
    let resp =
        state
            .relay_client()
            .get("/v1/relay/keys")
```

Replace `http::RelayClient::base_url()` at line 379:
```rust
        http::RelayClient::base_url(),
```
becomes:
```rust
        state.relay_client().base_url_str(),
```

Replace `RELAY_CLIENT` at line 410:
```rust
    let resp = RELAY_CLIENT
        .post_with_bearer("/v1/dids", &create_did_req, &pending_token)
```
becomes:
```rust
    let resp = state
        .relay_client()
        .post_with_bearer("/v1/dids", &create_did_req, &pending_token)
```

**Step 4: Update `register_handle`**

Add `state: tauri::State<'_, oauth::AppState>` as the last parameter:

Before (lines 472–475):
```rust
#[tauri::command]
async fn register_handle(
    handle_label: String,
) -> Result<RegisterHandleResult, RegisterHandleError> {
```

After:
```rust
#[tauri::command]
async fn register_handle(
    handle_label: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<RegisterHandleResult, RegisterHandleError> {
```

Replace `RELAY_CLIENT` at line 477:
```rust
    let resp = RELAY_CLIENT
        .get("/xrpc/com.atproto.server.describeServer")
```
becomes:
```rust
    let resp = state
        .relay_client()
        .get("/xrpc/com.atproto.server.describeServer")
```

Replace `RELAY_CLIENT` at line 531:
```rust
    let resp = RELAY_CLIENT
        .post_with_bearer("/v1/handles", &req, &session_token)
```
becomes:
```rust
    let resp = state
        .relay_client()
        .post_with_bearer("/v1/handles", &req, &session_token)
```

**Step 5: Update `check_handle_resolution`**

Add `state: tauri::State<'_, oauth::AppState>` as the last parameter:

Before (line 585):
```rust
#[tauri::command]
async fn check_handle_resolution(handle: String, expected_did: String) -> bool {
```

After:
```rust
#[tauri::command]
async fn check_handle_resolution(
    handle: String,
    expected_did: String,
    state: tauri::State<'_, oauth::AppState>,
) -> bool {
```

Replace `RELAY_CLIENT` at line 589:
```rust
    let resp = match RELAY_CLIENT.get(&path).await {
```
becomes:
```rust
    let resp = match state.relay_client().get(&path).await {
```

**Step 6: Verify compilation**

```bash
cargo build --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1 | head -40
```

Expected: Compiles. If there are errors about `LazyLock` being unused or not found, double-check the import removal in Step 1.
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->
<!-- START_TASK_3 -->
### Task 3: Update `OAuthClient::new()` in `oauth_client.rs` and its call site in `home.rs`

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth_client.rs`
- Modify: `apps/identity-wallet/src-tauri/src/home.rs`

**Step 1: Add `base_url` parameter to `OAuthClient::new()` (`oauth_client.rs`)**

Current `new()` at lines 37–44:
```rust
pub fn new(session: Arc<Mutex<OAuthSession>>) -> Result<Self, OAuthError> {
    let dpop = DPoPKeypair::get_or_create()?;
    Ok(Self {
        inner: Client::new(),
        dpop,
        session,
        base_url: crate::http::RelayClient::base_url().to_string(),
    })
}
```

Replace with:
```rust
pub fn new(session: Arc<Mutex<OAuthSession>>, base_url: String) -> Result<Self, OAuthError> {
    let dpop = DPoPKeypair::get_or_create()?;
    Ok(Self {
        inner: Client::new(),
        dpop,
        session,
        base_url,
    })
}
```

**Step 2: Update the `OAuthClient::new()` call in `home.rs`**

In `home.rs` at line 83:
```rust
    let oauth_client = match crate::oauth_client::OAuthClient::new(session_arc.clone()) {
```
becomes:
```rust
    let oauth_client = match crate::oauth_client::OAuthClient::new(
        session_arc.clone(),
        state.relay_client().base_url_str().to_owned(),
    ) {
```

The same `state` parameter that `load_home_data` already receives (`state: tauri::State<'_, AppState>`) is used here.

**Step 3: Update the private `check_relay_health` helper in `home.rs`**

Rename `check_relay_health` to `ping_relay_health` (to avoid ambiguity with any future public IPC commands) and add a `relay_client` parameter.

Current at lines 165–171:
```rust
async fn check_relay_health() -> bool {
    crate::http::RelayClient::new()
        .get("/xrpc/_health")
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}
```

Replace with:
```rust
async fn ping_relay_health(relay_client: &crate::http::RelayClient) -> bool {
    relay_client
        .get("/xrpc/_health")
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}
```

Update the three call sites in `load_home_data` (lines 72, 88, 97):

- Line 72: `check_relay_health().await` → `ping_relay_health(state.relay_client()).await`
- Line 88: `check_relay_health().await` → `ping_relay_health(state.relay_client()).await`
- Line 97: `check_relay_health()` → `ping_relay_health(state.relay_client())`

**Step 4: Verify compilation**

```bash
cargo build --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1 | head -40
```

Expected: Compiles cleanly.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Update `start_oauth_flow` in `oauth.rs` and fix test static calls

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs`

**Step 1: Update `start_oauth_flow` to use `state.relay_client()`**

`start_oauth_flow` at line 384 creates a local `RelayClient`:
```rust
    let relay = crate::http::RelayClient::new();
```
Replace with:
```rust
    let relay = state.relay_client();
```

At line 394, replace:
```rust
    let par_htu = format!("{}/oauth/par", crate::http::RelayClient::base_url());
```
with:
```rust
    let par_htu = format!("{}/oauth/par", state.relay_client().base_url_str());
```

At line 421, replace:
```rust
        let base = crate::http::RelayClient::base_url();
```
with:
```rust
        let base = state.relay_client().base_url_str();
```

At line 449, replace:
```rust
    let token_htu = format!("{}/oauth/token", crate::http::RelayClient::base_url());
```
with:
```rust
    let token_htu = format!("{}/oauth/token", state.relay_client().base_url_str());
```

**Step 2: Fix the two test usages of `RelayClient::base_url()` (lines 786, 818)**

These are `#[ignore]` integration tests. They use `crate::http::RelayClient::base_url()` only to build URL strings for test requests. Replace them with the new `default_relay_url()` free function added in Task 1.

At line 786 (inside `par_integration_returns_201_with_request_uri`):
```rust
        let htu = format!("{}/oauth/par", crate::http::RelayClient::base_url());
```
becomes:
```rust
        let htu = format!("{}/oauth/par", crate::http::default_relay_url());
```

At lines 818–819 (inside `par_missing_code_challenge_returns_client_error`):
```rust
        let base_url = crate::http::RelayClient::base_url();
        let url = format!("{base_url}/oauth/par");
```
becomes:
```rust
        let base_url = crate::http::default_relay_url();
        let url = format!("{base_url}/oauth/par");
```

**Step 3: Remove the now-unused static `base_url()` method from `http.rs`**

In `http.rs`, delete the static `base_url()` method (currently lines 192–197):

```rust
    /// Returns the compile-time base URL for this relay client instance.
    ///
    /// Used as the `service_endpoint` parameter in DID ceremony genesis op construction.
    pub const fn base_url() -> &'static str {
        RELAY_BASE_URL
    }
```

Update the doc comment on `http.rs` at the top (lines 1–5) to remove the note about compile-time base URL, since it's now runtime-configurable.

**Step 4: Run all tests**

```bash
cargo test --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1
```

Expected: All non-ignored tests pass. The `#[ignore]` integration tests in `oauth.rs` are skipped (expected).

Verify zero references to `RELAY_CLIENT` remain:
```bash
grep -r "RELAY_CLIENT" apps/identity-wallet/src-tauri/src/
```
Expected: No output.

Verify zero references to `RelayClient::base_url()` as a static call remain:
```bash
grep -rn "RelayClient::base_url()" apps/identity-wallet/src-tauri/src/
```
Expected: No output.

**Step 5: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/
git commit -m "refactor: move RelayClient to AppState, remove RELAY_CLIENT static"
```
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_B -->
