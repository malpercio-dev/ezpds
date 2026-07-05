# Relay URL Configuration — Phase 3: IPC Commands and Startup Initialization

**Goal:** Expose relay URL configuration to the frontend and initialize the relay client from Keychain on startup.

**Architecture:** Add two new Tauri IPC commands (`get_relay_url`, `save_relay_url`) and two Keychain helpers (`store_relay_url`, `load_relay_url`). Update the `run()` setup block to read the relay URL from Keychain and initialize AppState before the app starts receiving commands. URL validation uses the `url` crate (already in `Cargo.toml`). `save_relay_url` handles validation, health check, Keychain persistence, and AppState initialization in one command. A separate `check_relay_health` command is not needed and is not added.

**Tech Stack:** Rust (stable), `url` crate (already in Cargo.toml), `reqwest` (already in Cargo.toml)

**Scope:** 3 of 4 phases

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

### relay-url-config.AC3: URL persists across restarts
- **relay-url-config.AC3.1 Success:** After saving a URL and relaunching the app, the relay config screen is not shown
- **relay-url-config.AC3.2 Success:** All relay IPC commands on subsequent launches use the saved URL

### relay-url-config.AC4: Relay reachability verified before saving
- **relay-url-config.AC4.1 Success:** A URL whose `/xrpc/_health` returns HTTP 200 is accepted
- **relay-url-config.AC4.2 Failure:** An unreachable host surfaces an `UNREACHABLE` inline error
- **relay-url-config.AC4.3 Failure:** A malformed URL (not `http`/`https`, empty host) surfaces an `INVALID_URL` error before any network call
- **relay-url-config.AC4.4 Edge:** A URL with a trailing slash is accepted and normalized (slash stripped) before saving

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->
### Task 1: Add Keychain helpers for relay URL in `keychain.rs`

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/keychain.rs`

**Step 1: Add the account name constant**

In `keychain.rs`, find the existing account name constants (they look like `const DPOP_KEY_PRIV_ACCOUNT: &str = "..."`). Add a new constant alongside them:

```rust
const RELAY_URL_ACCOUNT: &str = "relay-base-url";
```

**Step 2: Add `store_relay_url` and `load_relay_url` helpers**

Add these helper functions at the bottom of the public helper section (after the existing `store_oauth_tokens` / `load_oauth_tokens` functions):

```rust
/// Persist the user-configured relay base URL to the Keychain.
///
/// Overwrites any previously stored URL.
pub fn store_relay_url(url: &str) -> Result<(), KeychainError> {
    store_item(RELAY_URL_ACCOUNT, url.as_bytes())
}

/// Retrieve the user-configured relay base URL from the Keychain.
///
/// Returns `None` if no URL has been saved yet (first run or after logout).
pub fn load_relay_url() -> Option<String> {
    match get_item(RELAY_URL_ACCOUNT) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|e| {
                tracing::warn!(error = %e, "relay URL in Keychain is not valid UTF-8; treating as absent");
            })
            .ok(),
        Err(e) if is_not_found(&e) => None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading relay URL");
            None
        }
    }
}

/// Remove the relay URL from the Keychain. Test-only; used to reset state
/// between tests that share the Keychain mock store.
#[cfg(test)]
pub fn delete_relay_url_test_only() {
    let _ = delete_item(RELAY_URL_ACCOUNT);
}
```

**Step 3: Verify compilation**

```bash
cargo build --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1 | head -20
```

Expected: Compiles.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add `RelayConfigError` and the three IPC commands in `lib.rs`

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Add `RelayConfigError`**

Add this enum to `lib.rs` alongside the other error enums (e.g., after `CreateAccountError`). Follow the exact same derive pattern used by `CreateAccountError`:

```rust
/// Error returned by relay URL configuration commands.
///
/// Serializes as `{ "code": "INVALID_URL" | "UNREACHABLE" | "KEYCHAIN_ERROR" }` for the frontend.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelayConfigError {
    #[error("invalid relay URL: must be http or https with a non-empty host")]
    InvalidUrl,
    #[error("relay is unreachable or did not return a success response")]
    Unreachable,
    #[error("failed to save relay URL to device storage")]
    KeychainError,
}
```

**Step 2: Add URL validation helper**

Add a private helper function near the bottom of the helpers section (near `map_409_subcode`):

```rust
/// Validate a relay URL: must parse as http or https with a non-empty host.
/// Strips any trailing slash and returns the normalized URL string.
fn normalize_relay_url(url: &str) -> Result<String, RelayConfigError> {
    let parsed = url::Url::parse(url).map_err(|_| RelayConfigError::InvalidUrl)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(RelayConfigError::InvalidUrl),
    }
    if parsed.host().is_none() {
        return Err(RelayConfigError::InvalidUrl);
    }
    Ok(url.trim_end_matches('/').to_string())
}
```

**Step 3: Add the two IPC commands**

Add these two commands to `lib.rs`, grouped after the existing IPC commands (before `run()`):

```rust
/// Return the saved relay base URL, or `None` if not yet configured.
///
/// The frontend calls this on mount to decide whether to show the relay
/// configuration screen.
#[tauri::command]
fn get_relay_url() -> Option<String> {
    keychain::load_relay_url()
}

/// Validate `url`, confirm the relay is reachable, save to Keychain, and
/// initialize the runtime relay client.
///
/// After this call succeeds, all subsequent IPC commands that use the relay
/// will use the saved URL for the remainder of the app session and on all
/// future launches.
#[tauri::command]
async fn save_relay_url(
    url: String,
    state: tauri::State<'_, oauth::AppState>,
) -> Result<(), RelayConfigError> {
    let normalized = normalize_relay_url(&url)?;
    let resp = http::RelayClient::new_with_url(normalized.clone())
        .get("/xrpc/_health")
        .await
        .map_err(|_| RelayConfigError::Unreachable)?;
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            url = %normalized,
            "relay health check returned non-success status"
        );
        return Err(RelayConfigError::Unreachable);
    }
    keychain::store_relay_url(&normalized).map_err(|e| {
        tracing::error!(error = %e, "failed to save relay URL to Keychain");
        RelayConfigError::KeychainError
    })?;
    state.set_relay_client(normalized);
    Ok(())
}
```

**Step 4: Register the new commands in `invoke_handler`**

Update the `tauri::generate_handler!` macro in `run()`:

```rust
        .invoke_handler(tauri::generate_handler![
            create_account,
            get_or_create_device_key,
            sign_with_device_key,
            perform_did_ceremony,
            register_handle,
            check_handle_resolution,
            get_relay_url,
            save_relay_url,
            home::load_home_data,
            home::log_out,
            oauth::start_oauth_flow,
        ])
```

**Step 5: Verify compilation**

```bash
cargo build --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1 | head -40
```

Expected: Compiles cleanly.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Initialize relay client from Keychain on startup, write tests, and commit

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Add Keychain relay URL initialization to `run()` setup block**

In the `run()` function, in the `.setup(|app| { ... })` closure, add relay URL initialization **before** the existing OAuth token restore block:

```rust
        .setup(|app| {
            // Restore relay URL from Keychain if previously configured.
            if let Some(url) = keychain::load_relay_url() {
                app.state::<oauth::AppState>().set_relay_client(url);
            }

            let app_handle = app.app_handle().clone();
            app.deep_link().on_open_url(move |event| {
                // ... existing deep-link handler unchanged
            });

            // ... existing OAuth token restore block unchanged
```

This ensures the relay client is configured before any IPC commands can fire, on both first launch (where `load_relay_url()` returns `None` and the default is used) and subsequent launches (where it returns the saved URL).

**Step 2: Write tests**

Add tests to the existing `mod tests` block at the bottom of `lib.rs`. These tests use the Keychain test mock that the existing tests already rely on.

```rust
    // -- normalize_relay_url --

    #[test]
    fn normalize_relay_url_strips_trailing_slash() {
        assert_eq!(
            normalize_relay_url("https://relay.example.com/").unwrap(),
            "https://relay.example.com"
        );
    }

    #[test]
    fn normalize_relay_url_accepts_http_and_https() {
        assert!(normalize_relay_url("https://relay.example.com").is_ok());
        assert!(normalize_relay_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn normalize_relay_url_rejects_non_http_schemes() {
        assert!(matches!(
            normalize_relay_url("ftp://relay.example.com").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_relay_url("ws://relay.example.com").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
    }

    #[test]
    fn normalize_relay_url_rejects_malformed_input() {
        assert!(matches!(
            normalize_relay_url("not-a-url").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
        assert!(matches!(
            normalize_relay_url("").unwrap_err(),
            RelayConfigError::InvalidUrl
        ));
    }

    // -- get_relay_url / load_relay_url round-trip --

    #[test]
    fn get_relay_url_returns_none_before_save() {
        // The Keychain test mock starts empty in a fresh process; tests that
        // write to the store must clean up via delete_relay_url_test_only().
        assert!(get_relay_url().is_none());
    }

    #[test]
    fn relay_url_round_trips_through_keychain() {
        let url = "https://relay.example.com";
        keychain::store_relay_url(url).unwrap();
        let loaded = keychain::load_relay_url().unwrap();
        assert_eq!(loaded, url);
        // Clean up so this test doesn't affect others sharing the mock store.
        keychain::delete_relay_url_test_only();
    }
```

> Note: `save_relay_url` makes live HTTP calls and is not tested here. The URL validation path through `normalize_relay_url` is fully covered by the unit tests above. End-to-end behavior (reachability) is verified manually per the test plan.
>
> `delete_relay_url_test_only` is a `#[cfg(test)]` helper added in Task 1 alongside `store_relay_url` and `load_relay_url` — it calls `keychain::delete_item(RELAY_URL_ACCOUNT)` so round-trip tests can clean up after themselves without polluting other tests that expect an empty store.

**Step 3: Run tests**

```bash
cargo test --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1
```

Expected: All tests pass, including the new ones. Look for the test names `normalize_relay_url_*`, `get_relay_url_*`, `relay_url_round_trips_*` in the output.

**Step 4: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/keychain.rs \
        apps/identity-wallet/src-tauri/src/lib.rs
git commit -m "feat: add relay URL IPC commands and Keychain persistence"
```
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->
