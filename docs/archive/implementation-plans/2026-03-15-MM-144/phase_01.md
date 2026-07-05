# MM-144 Onboarding Flow — Implementation Plan

**Goal:** Add Rust dependencies and implement the Keychain abstraction (`keychain.rs`) and relay HTTP client (`http.rs`) for the identity-wallet Tauri backend.

**Architecture:** Infrastructure phase only — no IPC command, no frontend changes. Two new Rust modules are added to `src-tauri/src/`, new crate dependencies are added to `src-tauri/Cargo.toml`, and module declarations are added to `lib.rs`. Verification is `cargo build` success.

**Tech Stack:** Rust stable, Tauri v2, `security-framework` v3 (iOS Keychain), `reqwest` v0.12 (`rustls-tls`), `thiserror` v2 (workspace dep)

**Scope:** Phase 1 of 4

**Codebase verified:** 2026-03-15

---

## Acceptance Criteria Coverage

This infrastructure phase does not implement user-facing behavior. It creates the building blocks Phase 2 depends on.

**Verifies:** None — operational verification only (`cargo build`, `cargo clippy`, `cargo fmt --check`)

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Add Cargo dependencies

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml`

**Step 1: Add the new dependencies**

Open `apps/identity-wallet/src-tauri/Cargo.toml`. The current `[dependencies]` section is:

```toml
[dependencies]
tauri = { version = "2", features = [] }
serde = { workspace = true }
serde_json = { workspace = true }
```

Replace with:

```toml
[dependencies]
tauri = { version = "2", features = [] }
serde = { workspace = true }
serde_json = { workspace = true }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
security-framework = "3"
thiserror = { workspace = true }
```

**Why `default-features = false` on reqwest:** The default features include `default-tls` (OpenSSL). On iOS there is no OpenSSL; `rustls-tls` bundles its own TLS implementation.

**Why `thiserror = { workspace = true }`:** The root `Cargo.toml` has `thiserror = "2"` in `[workspace.dependencies]` (used by `crates/crypto`). The `keychain.rs` module uses it for `KeychainError`.

**Note:** `crypto = { workspace = true }` is NOT added here — it is only needed in Phase 2 when `create_account` calls `generate_p256_keypair`. Adding it now would create unused-dependency warnings.

**Step 2: Verify the change compiles**

```bash
cargo build -p identity-wallet
```

Expected: dependency resolution and download succeed; compilation may fail with "unused import" warnings until modules are created in later tasks — that is fine at this step. If resolution itself fails (e.g., `rustls-tls` feature not found), check reqwest version.

**Step 3: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml
git commit -m "chore(identity-wallet): add reqwest, security-framework, thiserror deps"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create `keychain.rs`

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/keychain.rs`

**Step 1: Create the file with the following content**

```rust
//! iOS Keychain storage for identity-wallet credentials.
//!
//! All items are stored as `kSecClassGenericPassword` under
//! service `"ezpds-identity-wallet"`. Use the `SERVICE` constant
//! to ensure consistency.

// Suppressed until Phase 2 wires up the IPC command that calls these functions.
#![allow(dead_code)]

use security_framework::passwords::{get_generic_password, set_generic_password};

pub const SERVICE: &str = "ezpds-identity-wallet";

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain error: {0}")]
    Security(#[from] security_framework::base::Error),
}

/// Store arbitrary bytes in the Keychain under the given account name.
///
/// Creates the entry if it doesn't exist, or updates it if it does.
pub fn store_item(account: &str, data: &[u8]) -> Result<(), KeychainError> {
    set_generic_password(SERVICE, account, data).map_err(KeychainError::Security)
}

/// Retrieve bytes from the Keychain for the given account name.
///
/// Returns `Err` with `errSecItemNotFound` if no entry exists.
pub fn get_item(account: &str) -> Result<Vec<u8>, KeychainError> {
    get_generic_password(SERVICE, account).map_err(KeychainError::Security)
}
```

**Why `thiserror`:** Already added to `Cargo.toml` in Task 1. It generates the `Error` impl and `From` conversion automatically.

**Why `#![allow(dead_code)]`:** `store_item` and `get_item` are not called until Phase 2's `create_account` command. Without this suppression, `cargo clippy --workspace -- -D warnings` would fail in Task 4. Remove this attribute in Phase 2 Task 1 once the functions are in use.

**Step 2: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/keychain.rs
git commit -m "feat(identity-wallet): add keychain module for iOS credential storage"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Create `http.rs`

**Files:**
- Create: `apps/identity-wallet/src-tauri/src/http.rs`

**Step 1: Create the file with the following content**

```rust
//! Relay HTTP client for identity-wallet.
//!
//! All relay API calls go through `RelayClient`. The base URL is
//! compile-time configured: `http://localhost:8080` in debug builds,
//! `https://relay.ezpds.com` in release builds.

// Suppressed until Phase 2 wires up the IPC command that calls this client.
#![allow(dead_code)]

use reqwest::{Client, Response};
use serde::Serialize;

#[cfg(debug_assertions)]
const RELAY_BASE_URL: &str = "http://localhost:8080";
#[cfg(not(debug_assertions))]
const RELAY_BASE_URL: &str = "https://relay.ezpds.com";

/// HTTP client for relay API requests.
pub struct RelayClient {
    client: Client,
    base_url: &'static str,
}

impl RelayClient {
    /// Create a new `RelayClient` with the compile-time base URL.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: RELAY_BASE_URL,
        }
    }

    /// POST JSON to `path` (relative, e.g. `"/v1/accounts/mobile"`).
    ///
    /// Returns the raw `Response` so callers can inspect the status code
    /// before attempting to deserialize the body.
    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.post(&url).json(body).send().await
    }
}

impl Default for RelayClient {
    fn default() -> Self {
        Self::new()
    }
}
```

**Why return raw `Response` instead of deserializing here:** The caller (`create_account` in Phase 2) needs to inspect the HTTP status code first to map error variants (`ExpiredCode`, `EmailTaken`, etc.) before deciding whether to deserialize the success body. If we deserialize here, the error information is lost.

**Step 2: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/http.rs
git commit -m "feat(identity-wallet): add relay HTTP client module"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Declare modules in `lib.rs` and verify build

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Add module declarations**

Open `apps/identity-wallet/src-tauri/src/lib.rs`. The current file begins directly with:

```rust
#[tauri::command]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}
```

Add the module declarations at the very top of the file, before the `#[tauri::command]` attribute:

```rust
pub mod http;
pub mod keychain;

#[tauri::command]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}
```

Leave the rest of the file unchanged (the `run()` function and `#[cfg(test)]` block stay as-is).

**Step 2: Verify the full build**

```bash
cargo build --workspace
```

Expected: build succeeds with zero errors. `keychain.rs` and `http.rs` have `#![allow(dead_code)]` so unused item warnings are suppressed.

**Step 3: Verify lints**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: passes. `keychain.rs` and `http.rs` already suppress dead_code warnings via `#![allow(dead_code)]`. These suppressions are removed in Phase 2 Task 1 when the functions are called from `create_account`.

**Step 4: Verify formatting**

```bash
cargo fmt --all --check
```

Expected: passes.

**Step 5: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/lib.rs
git commit -m "feat(identity-wallet): register keychain and http modules in lib.rs"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->
