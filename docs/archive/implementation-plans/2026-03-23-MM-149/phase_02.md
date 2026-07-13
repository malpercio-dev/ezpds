# MM-149 OAuth PKCE Client Implementation Plan

**Goal:** Wire up the deep-link plugin, register AppState, and establish the OAuth callback routing path so the deep-link callback can be verified end-to-end before adding cryptographic logic.

**Architecture:** Tauri's `.manage()` puts `AppState` into the app's DI container. The `tauri-plugin-deep-link` plugin injects a `CFBundleURLSchemes` entry into Info.plist at build time, routes incoming `dev.malpercio.identitywallet://` URLs to `on_open_url` at runtime, and that callback routes to `handle_deep_link` in `oauth.rs`. The opener plugin lets Rust open Safari. State is accessed from the callback via a cloned `AppHandle`.

**Tech Stack:** Rust/Tauri v2, `tauri-plugin-deep-link = "2"`, `tauri-plugin-opener = "2"`, `std::sync::Mutex`

**Scope:** 7 phases from original design (phase 2 of 7)

**Codebase verified:** 2026-03-23

---

## Acceptance Criteria Coverage

This phase implements and tests:

> This is an infrastructure phase. Done-when: the app builds for iOS and `xcrun simctl openurl` triggers the `on_open_url` handler (verified via tracing log). No AC cases are formally tested in this phase.

**Verifies:** None (infrastructure — verified operationally)

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add plugin dependencies to Cargo.toml

**Verifies:** None (infrastructure)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml`

These plugins are declared locally in the app's Cargo.toml (same pattern as `tauri` and `tauri-build`), not in workspace dependencies, because no other workspace crate uses them.

**Step 1: Add the two plugin crates to `[dependencies]`**

In `apps/identity-wallet/src-tauri/Cargo.toml`, after the `tauri = { version = "2", features = [] }` line, add:

```toml
tauri-plugin-deep-link = "2"
tauri-plugin-opener = "2"
```

The `[dependencies]` section should now include:

```toml
tauri = { version = "2", features = [] }
tauri-plugin-deep-link = "2"
tauri-plugin-opener = "2"
```

**Step 2: Verify the crates download**

```bash
cd apps/identity-wallet && cargo fetch
```

Expected: exits without error. This confirms the crate versions resolve.

**Step 3: Build to confirm no compile errors**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors (no new code yet, just new deps).

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add deep-link plugin config to tauri.conf.json

**Verifies:** None (infrastructure)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/tauri.conf.json`

The current file has no `plugins` section. Adding `plugins.deep-link.mobile` causes the build tool to inject a `CFBundleURLTypes` entry into the generated iOS Info.plist, registering `dev.malpercio.identitywallet` as a custom URL scheme. Only non-HTTPS schemes trigger this Info.plist path.

**Step 1: Add the `plugins` section**

The full updated `tauri.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Identity Wallet",
  "version": "0.1.0",
  "identifier": "dev.malpercio.identitywallet",
  "build": {
    "devUrl": "http://localhost:5173",
    "frontendDist": "../dist",
    "beforeDevCommand": "pnpm dev",
    "beforeBuildCommand": "pnpm build"
  },
  "app": {
    "windows": [
      {
        "title": "Identity Wallet",
        "width": 400,
        "height": 600,
        "resizable": true
      }
    ]
  },
  "bundle": {
    "active": true
  },
  "plugins": {
    "deep-link": {
      "mobile": [
        {
          "scheme": ["dev.malpercio.identitywallet"]
        }
      ]
    }
  }
}
```

**Step 2: Regenerate the Xcode project**

The Xcode project (`src-tauri/gen/apple/`) is machine-specific and gitignored. After any config change that affects the iOS build, regenerate it:

```bash
cd apps/identity-wallet && cargo tauri ios init
```

Then re-apply the two one-time Xcode patches from the AGENTS.md:

```bash
# Patch 1: Add Nix devenv PATH to the build phase
# Replace <project-root> with the absolute path to the workspace root (e.g. /Users/you/workspace/malpercio-dev/ezpds)
# Find the shellScript line in project.pbxproj and prepend the PATH export

# Patch 2: Disable user script sandboxing
sed -i '' 's/ENABLE_USER_SCRIPT_SANDBOXING = YES/ENABLE_USER_SCRIPT_SANDBOXING = NO/g' \
  src-tauri/gen/apple/identity-wallet.xcodeproj/project.pbxproj
```

<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Create oauth.rs with AppState, PendingOAuthFlow, CallbackParams, and handle_deep_link stub

**Verifies:** None (infrastructure stub — verified by tracing log in Task 5)

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/oauth.rs`

This file is the Functional Core for OAuth state types and the stub callback. `PendingOAuthFlow` is a placeholder for now; Phase 5 will add the `oneshot::Sender` and cryptographic state fields. The `Mutex` fields in `AppState` use `std::sync::Mutex` — it is never held across an `.await` point (it's always lock-set-drop or lock-take-drop), so it is safe in both the sync callback and the async command.

**Step 1: Create `apps/identity-wallet/src-tauri/src/oauth.rs`**

```rust
// pattern: Mixed (unavoidable)
//
// Types: AppState, PendingOAuthFlow, OAuthSession, CallbackParams (Functional Core)
// handle_deep_link: Imperative Shell (reads OS callback, routes to pending channel)

use std::sync::Mutex;
use tracing;

// ── Shared state ──────────────────────────────────────────────────────────────

/// App-wide OAuth state registered via `.manage()` in lib.rs.
///
/// Both fields are Option-wrapped so the state is cleanly empty before any
/// OAuth flow starts and after a flow completes.
pub struct AppState {
    /// The pending OAuth flow waiting for the deep-link callback.
    /// Set by `start_oauth_flow` before opening Safari; cleared by `handle_deep_link`.
    pub pending_auth: Mutex<Option<PendingOAuthFlow>>,
    /// The active authenticated session after a successful token exchange.
    /// Set by `start_oauth_flow` on success; read by `OAuthClient` for every request.
    pub oauth_session: Mutex<Option<OAuthSession>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            pending_auth: Mutex::new(None),
            oauth_session: Mutex::new(None),
        }
    }
}

// ── Pending flow (stub — filled out in Phase 5) ───────────────────────────────

/// State parked inside `AppState.pending_auth` while `start_oauth_flow` waits
/// for the deep-link callback.
///
/// Phase 5 adds: oneshot::Sender<CallbackParams>, pkce_verifier, csrf_state.
pub struct PendingOAuthFlow {
    /// The CSRF state parameter generated at the start of the flow.
    /// Used by `handle_deep_link` to validate the callback state.
    pub csrf_state: String,
}

// ── OAuth session (stub — filled out in Phase 5) ──────────────────────────────

/// Active OAuth session stored after a successful token exchange.
///
/// Phase 5 adds: access_token, refresh_token, expires_at, dpop_nonce.
pub struct OAuthSession {
    pub access_token: String,
    pub refresh_token: String,
}

// ── Callback params ───────────────────────────────────────────────────────────

/// Parameters extracted from the OAuth deep-link callback URL.
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

// ── Deep-link handler ─────────────────────────────────────────────────────────

/// Process URLs received from the deep-link plugin's `on_open_url` event.
///
/// Filters for the OAuth callback path and logs receipt. Phase 5 completes this
/// by extracting `code`+`state` and sending them on the pending `oneshot` channel.
pub fn handle_deep_link(urls: Vec<url::Url>, app_state: &AppState) {
    for url in &urls {
        let scheme = url.scheme();
        let path = url.path();

        if scheme == "dev.malpercio.identitywallet" && path == "/oauth/callback" {
            tracing::info!(url = %url, "OAuth deep-link callback received");

            // Phase 5: extract code+state, validate CSRF, send on oneshot channel.
            // For now, just log that the callback arrived.
            let _pending = app_state.pending_auth.lock().unwrap();
            tracing::info!("pending_auth slot present: {}", _pending.is_some());

            return;
        }

        tracing::debug!(url = %url, "ignoring non-OAuth deep-link");
    }
}
```

**Step 2: Add `url = "2"` to Cargo.toml**

Add to `[dependencies]` in `apps/identity-wallet/src-tauri/Cargo.toml`:

```toml
url = "2"
```

The `url` crate is a transitive dependency of `tauri-plugin-deep-link`, but declaring it explicitly makes the version requirement clear and ensures `url::Url` resolves unambiguously in all contexts.

**Step 3: Verify the file compiles**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors. The `url::Url` type resolves from the explicit `url = "2"` dependency.

<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Register plugins, AppState, and on_open_url in lib.rs

**Verifies:** None (infrastructure — verified operationally in Task 5)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Add the `oauth` module declaration at the top of lib.rs**

After the existing module declarations (lines 1-3), add:

```rust
pub mod oauth;
```

The top of lib.rs should now read:

```rust
pub mod device_key;
pub mod http;
pub mod keychain;
pub mod oauth;
```

**Step 2: Update the `run()` function**

The current `run()` function (lines 398-409) is:

```rust
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            create_account,
            get_or_create_device_key,
            sign_with_device_key,
            perform_did_ceremony,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

Replace it with:

```rust
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(oauth::AppState::new())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let app_handle = app.app_handle().clone();
            app.deep_link().on_open_url(move |event| {
                let state = app_handle.state::<oauth::AppState>();
                oauth::handle_deep_link(event.urls(), &state);
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_account,
            get_or_create_device_key,
            sign_with_device_key,
            perform_did_ceremony,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

**Step 3: Add the missing use import for Tauri Manager**

`app_handle.state::<T>()` requires the `tauri::Manager` trait in scope. Add it to the existing use imports at the top of lib.rs:

```rust
use tauri::Manager;
```

**Step 4: Build to verify no compile errors**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_TASK_5 -->
### Task 5: Verify deep-link callback fires end-to-end

**Verifies:** None (operational — confirms the plumbing works before Phase 5 adds logic)

This task verifies the Phase 2 Done-when criterion: the `on_open_url` handler fires when the iOS Simulator receives a custom URL scheme URL.

**Step 1: Launch the app in the iOS Simulator**

```bash
cd apps/identity-wallet
cargo tauri ios dev
```

Wait for the Simulator to open and the app to launch.

**Step 2: Trigger the deep-link callback**

In a separate terminal (while `cargo tauri ios dev` is running), run:

```bash
xcrun simctl openurl booted "dev.malpercio.identitywallet:/oauth/callback?code=test&state=abc"
```

**Step 3: Verify the handler fired**

In the `cargo tauri ios dev` terminal output, confirm you see:

```
INFO identity_wallet::oauth: OAuth deep-link callback received url=dev.malpercio.identitywallet:/oauth/callback?code=test&state=abc
INFO identity_wallet::oauth: pending_auth slot present: false
```

The `pending_auth slot present: false` is expected — no flow is in progress. The important thing is that the log appeared, proving the route landed.

**Step 4: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml
git add apps/identity-wallet/src-tauri/tauri.conf.json
git add apps/identity-wallet/src-tauri/src/lib.rs
git add apps/identity-wallet/src-tauri/src/oauth.rs
git commit -m "feat(identity-wallet): wire deep-link plugin and AppState for OAuth callback (MM-149 phase 2)"
```

<!-- END_TASK_5 -->
