# MM-144 Onboarding Flow — Phase 2: create_account IPC Command

**Goal:** Implement the `create_account` Tauri IPC command end-to-end: generate a P-256 keypair, store the private key in the iOS Keychain, POST to the relay, store returned tokens in the Keychain, and return a typed result or typed error.

**Architecture:** One new `#[tauri::command] async fn create_account` in `lib.rs`. Types declared in the same file. Error variants use `#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]` so they serialize as `{ "code": "EXPIRED_CODE" }` etc., which matches the TypeScript `CreateAccountError` union.

**Tech Stack:** Rust/Tauri v2 async commands, `crates/crypto` (P-256), `keychain` module from Phase 1, `http` module from Phase 1, `reqwest`, `security-framework`, `serde`

**Scope:** Phase 2 of 4

**Codebase verified:** 2026-03-15

---

## Acceptance Criteria Coverage

### MM-144.AC2: Account creation succeeds end-to-end
- **MM-144.AC2.1 Success:** Valid email, handle, and claim code submission invokes the `create_account` Rust command via Tauri IPC
- **MM-144.AC2.2 Success:** The Rust command POSTs to `POST /v1/accounts/mobile` with `email`, `handle`, `claimCode`, `devicePublicKey`, and `platform: "ios"`
- **MM-144.AC2.3 Success:** On 201 response, `device_token` and `session_token` are stored in the iOS Keychain
- **MM-144.AC2.4 Success:** The device P-256 private key is stored in the iOS Keychain before the HTTP request
- **MM-144.AC2.5 Success:** On success, the frontend receives `{ nextStep: "did_creation" }` and advances past the loading screen

### MM-144.AC3: Error handling
- **MM-144.AC3.1 Failure:** A relay 404 response (expired claim code) surfaces as `{ code: "EXPIRED_CODE" }` error
- **MM-144.AC3.2 Failure:** A relay 409/`CLAIM_CODE_REDEEMED` surfaces as `{ code: "REDEEMED_CODE" }` error
- **MM-144.AC3.3 Failure:** A relay 409/`ACCOUNT_EXISTS` surfaces as `{ code: "EMAIL_TAKEN" }` error
- **MM-144.AC3.4 Failure:** A relay 409/`HANDLE_TAKEN` surfaces as `{ code: "HANDLE_TAKEN" }` error
- **MM-144.AC3.5 Failure:** A network or server error surfaces as `{ code: "NETWORK_ERROR", message: "..." }` error

### MM-144.AC4: iOS Keychain storage
- **MM-144.AC4.1 Success:** `device_token` is stored in the iOS Keychain under account `"device-token"`
- **MM-144.AC4.2 Success:** `session_token` is stored in the iOS Keychain under account `"session-token"`
- **MM-144.AC4.3 Success:** Device P-256 private key bytes are stored in the iOS Keychain under account `"device-private-key"`

### MM-144.AC5: Build passes
- **MM-144.AC5.1 Success:** `cargo build --workspace` succeeds after adding the command

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Implement `create_account` in `lib.rs`

**Verifies:** MM-144.AC2.1, MM-144.AC2.2, MM-144.AC2.3, MM-144.AC2.4, MM-144.AC2.5, MM-144.AC3.1, MM-144.AC3.2, MM-144.AC3.3, MM-144.AC3.4, MM-144.AC3.5, MM-144.AC4.1, MM-144.AC4.2, MM-144.AC4.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml`
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Step 1: Add the `crypto` workspace dependency to `Cargo.toml`**

Open `apps/identity-wallet/src-tauri/Cargo.toml`. After Phase 1, the `[dependencies]` section ends with `thiserror = { workspace = true }`. Add:

```toml
crypto = { workspace = true }
```

The root `Cargo.toml` already has `crypto = { path = "crates/crypto" }` in `[workspace.dependencies]`.

Also remove the `#![allow(dead_code)]` line from the top of both `src/keychain.rs` and `src/http.rs` — these functions are now in use.

**Step 2: Add all new types and the `create_account` command to `lib.rs`**

After Phase 1, `lib.rs` begins with:
```rust
pub mod http;
pub mod keychain;

#[tauri::command]
fn greet(name: String) -> String { ... }
```

Add the following block between the `pub mod keychain;` declaration and the `#[tauri::command] fn greet` line:

```rust
use crypto::generate_p256_keypair;
use serde::{Deserialize, Serialize};

// ── Request / response types ────────────────────────────────────────────────

/// JSON body sent to POST /v1/accounts/mobile.
/// Field names match the relay's camelCase deserialization.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountRequest {
    email: String,
    handle: String,
    device_public_key: String,
    platform: String,
    claim_code: String,
}

/// Successful 201 response from the relay.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountResponse {
    device_token: String,
    session_token: String,
    next_step: String,
}

/// Relay error envelope: { "error": { "code": "...", "message": "..." } }
#[derive(Deserialize)]
struct RelayErrorEnvelope {
    error: RelayErrorBody,
}

#[derive(Deserialize)]
struct RelayErrorBody {
    code: String,
}

// ── IPC result / error types (returned to the frontend) ─────────────────────

/// Successful result returned to the Svelte frontend.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResult {
    pub next_step: String,
}

/// Typed error returned to the Svelte frontend as a rejected Promise.
///
/// Serializes as `{ "code": "EXPIRED_CODE" }` (SCREAMING_SNAKE_CASE) so
/// the TypeScript catch block can switch on `error.code`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CreateAccountError {
    #[error("claim code has expired")]
    ExpiredCode,
    #[error("claim code already redeemed")]
    RedeemedCode,
    #[error("email already taken")]
    EmailTaken,
    #[error("handle already taken")]
    HandleTaken,
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("unknown error: {message}")]
    Unknown { message: String },
}

// ── IPC command ─────────────────────────────────────────────────────────────

#[tauri::command]
async fn create_account(
    claim_code: String,
    email: String,
    handle: String,
) -> Result<CreateAccountResult, CreateAccountError> {
    // 1. Generate P-256 device keypair.
    let keypair = generate_p256_keypair()
        .map_err(|e| CreateAccountError::Unknown { message: e.to_string() })?;

    // 2. Store private key bytes in Keychain before any network call.
    //    private_key_bytes is Zeroizing<[u8; 32]>; deref to &[u8] via AsRef.
    keychain::store_item("device-private-key", keypair.private_key_bytes.as_ref())
        .map_err(|e| CreateAccountError::Unknown { message: e.to_string() })?;

    // 3. POST to relay.
    let req = CreateMobileAccountRequest {
        email,
        handle,
        device_public_key: keypair.public_key,
        platform: "ios".to_string(),
        claim_code,
    };

    let resp = http::RelayClient::new()
        .post("/v1/accounts/mobile", &req)
        .await
        .map_err(|e| CreateAccountError::NetworkError { message: e.to_string() })?;

    let status = resp.status();

    if status.is_success() {
        // 4. Deserialize success body.
        let body: CreateMobileAccountResponse = resp
            .json()
            .await
            .map_err(|e| CreateAccountError::Unknown { message: e.to_string() })?;

        // 5. Store tokens in Keychain.
        keychain::store_item("device-token", body.device_token.as_bytes())
            .map_err(|e| CreateAccountError::Unknown { message: e.to_string() })?;
        keychain::store_item("session-token", body.session_token.as_bytes())
            .map_err(|e| CreateAccountError::Unknown { message: e.to_string() })?;

        Ok(CreateAccountResult { next_step: body.next_step })
    } else {
        // 6. Map relay error codes to typed variants.
        match status.as_u16() {
            404 => Err(CreateAccountError::ExpiredCode),
            409 => {
                let envelope: RelayErrorEnvelope = resp
                    .json()
                    .await
                    .map_err(|e| CreateAccountError::Unknown { message: e.to_string() })?;
                match envelope.error.code.as_str() {
                    "CLAIM_CODE_REDEEMED" => Err(CreateAccountError::RedeemedCode),
                    "ACCOUNT_EXISTS" => Err(CreateAccountError::EmailTaken),
                    "HANDLE_TAKEN" => Err(CreateAccountError::HandleTaken),
                    other => Err(CreateAccountError::Unknown {
                        message: format!("409: {other}"),
                    }),
                }
            }
            _ => Err(CreateAccountError::NetworkError {
                message: format!("HTTP {}", status.as_u16()),
            }),
        }
    }
}
```

**Step 3: Register `create_account` in `generate_handler!`**

In the `run()` function, change:

```rust
.invoke_handler(tauri::generate_handler![greet])
```

to:

```rust
.invoke_handler(tauri::generate_handler![greet, create_account])
```

**Step 4: Verify build**

```bash
cargo build --workspace
```

Expected: build succeeds. The `#![allow(dead_code)]` suppressions were removed from `keychain.rs` and `http.rs` in Step 1 — their functions are now called from `create_account`. If `unused_imports` fires, ensure `use serde::{Deserialize, Serialize};` and `use crypto::generate_p256_keypair;` are only declared once (not duplicated with existing imports).

**Step 5: Verify lints**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: passes.

**Step 6: Verify formatting**

```bash
cargo fmt --all --check
```

Expected: passes.

**Step 7: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml apps/identity-wallet/src-tauri/src/lib.rs apps/identity-wallet/src-tauri/src/keychain.rs apps/identity-wallet/src-tauri/src/http.rs
git commit -m "feat(identity-wallet): implement create_account IPC command"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Verify command is reachable from TypeScript (smoke check)

This task is a build-level verification only — end-to-end HTTP testing requires a running relay and iOS simulator, which is manual.

**Files:** No changes.

**Step 1: Confirm the command name matches what ipc.ts will use**

The Tauri command name for `create_account` (snake_case function) becomes `"create_account"` when called via `invoke()`. Verify this is consistent with the TypeScript wrapper being written in Phase 4 (`invoke('create_account', { claimCode, email, handle })`).

Tauri v2 maps `claim_code` (Rust parameter) → `claimCode` (JavaScript argument) automatically when the parameter is passed as a camelCase object key. This is the default Tauri v2 behavior for argument deserialization.

No code change needed — this is a documentation checkpoint.

**Step 2: Verify the full workspace build one more time**

```bash
cargo build --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all --check
```

Expected: all three commands pass with zero errors.

**Step 3: Commit (if any minor adjustments were made)**

If any `#[allow(dead_code)]` attributes were removed or other minor cleanups done:

```bash
git add -p
git commit -m "chore(identity-wallet): clean up dead_code suppression after Phase 2"
```

Skip if no changes were needed.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->
