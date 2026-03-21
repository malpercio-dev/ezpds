# MM-146 DID Ceremony Implementation Plan

**Goal:** Implement the `perform_did_ceremony` Tauri command that orchestrates the full 7-step DID ceremony: get device key, fetch relay signing key, build signed genesis op, retrieve pending session token, POST to relay, persist DID and new session token, return result.

**Architecture:** Imperative Shell in `src-tauri/src/lib.rs` + HTTP client extension in `src-tauri/src/http.rs`. The crypto crate (Functional Core, Phase 2) is wired in via the `sign` callback. All I/O (Keychain, network) is in the Tauri command; no I/O in the crypto crate.

**Tech Stack:** Rust, Tauri v2, reqwest, crypto crate (build_did_plc_genesis_op_with_external_signer), keychain module, device_key module

**Scope:** Phase 3 of 4 from the MM-146 design plan.

**Codebase verified:** 2026-03-20

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-146.AC3: perform_did_ceremony completes the full ceremony
- **MM-146.AC3.1 Success:** Given a valid pending session token and provisioned relay key, returns `DIDCeremonyResult { did }` with a valid `did:plc` identifier
- **MM-146.AC3.2 Success:** Keychain `"session-token"` is overwritten with the full session token from `POST /v1/dids` response
- **MM-146.AC3.3 Success:** Keychain `"did"` is populated with the resulting DID
- **MM-146.AC3.4 Failure:** Returns `DIDCeremonyError::NoRelaySigningKey` (serializes as `{ code: "NO_RELAY_SIGNING_KEY" }`) when relay has no key
- **MM-146.AC3.5 Failure:** Returns `DIDCeremonyError::RelayKeyFetchFailed` when `GET /v1/relay/keys` is unreachable
- **MM-146.AC3.6 Failure:** Returns `DIDCeremonyError::SigningFailed` when SE signing fails
- **MM-146.AC3.7 Failure:** Returns `DIDCeremonyError::DidCreationFailed` when `POST /v1/dids` returns non-2xx

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Extend RelayClient with get() and post_with_bearer() methods and base_url() accessor

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/http.rs`

**Implementation:**

Add three new items to the `RelayClient` impl block, after the existing `post()` method:

```rust
    /// GET `path` (relative, e.g. `"/v1/relay/keys"`).
    ///
    /// Returns the raw `Response` so callers can inspect the status code
    /// before attempting to deserialize the body.
    pub async fn get(&self, path: &str) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.get(&url).send().await
    }

    /// POST JSON to `path` with a Bearer token in the Authorization header.
    ///
    /// Used for authenticated relay endpoints (e.g. `POST /v1/dids` which
    /// requires the pending session token).
    pub async fn post_with_bearer<T: Serialize>(
        &self,
        path: &str,
        body: &T,
        bearer_token: &str,
    ) -> reqwest::Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .bearer_auth(bearer_token)
            .json(body)
            .send()
            .await
    }

    /// Returns the compile-time base URL for this relay client instance.
    ///
    /// Used as the `service_endpoint` parameter in DID ceremony genesis op construction.
    pub const fn base_url() -> &'static str {
        RELAY_BASE_URL
    }
```

**Verification:**

Run: `cargo build -p identity-wallet`
Expected: Compiles without errors or warnings.
<!-- END_TASK_1 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 2-4) -->

<!-- START_TASK_2 -->
### Task 2: Add types and the perform_did_ceremony command to lib.rs

**Verifies:** MM-146.AC3.1, MM-146.AC3.2, MM-146.AC3.3, MM-146.AC3.4, MM-146.AC3.5, MM-146.AC3.6, MM-146.AC3.7

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`

**Implementation:**

**Step 1:** Add imports after the existing `use serde::{Deserialize, Serialize};` import block at the top:

```rust
use crypto::{build_did_plc_genesis_op_with_external_signer, CryptoError, DidKeyUri};
```

Also add `tracing` to `apps/identity-wallet/src-tauri/Cargo.toml` if it is not already listed as a dependency (check with `cargo build -p identity-wallet` after adding — it compiles if present, or add `tracing = { workspace = true }` if the macro is not found):

```toml
tracing = { workspace = true }
```

**Step 2:** Add the relay API types after the existing `CreateMobileAccountResponse` struct (around line 33), before the `RelayErrorEnvelope` struct:

```rust
/// Response from GET /v1/relay/keys — the relay's active signing key.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelaySigningKey {
    key_id: String,
    public_key: String,
    algorithm: String,
}

/// Request body for POST /v1/dids — submit the signed genesis op for DID promotion.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateDidRequest {
    rotation_key_public: String,
    signed_creation_op: String,
}

/// Response from POST /v1/dids — the promoted DID and upgraded session token.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDidResponse {
    did: String,
    session_token: String,
}
```

**Step 3:** Add the IPC result and error types in the IPC types section (after `CreateAccountError`):

```rust
/// Successful result returned to the Svelte frontend after DID ceremony completes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDCeremonyResult {
    pub did: String,
}

/// Typed error returned to the Svelte frontend as a rejected Promise.
///
/// Serializes as `{ "code": "NO_RELAY_SIGNING_KEY" }` (SCREAMING_SNAKE_CASE) so
/// the TypeScript catch block can switch on `error.code`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DIDCeremonyError {
    #[error("device key not found; call get_or_create before ceremony")]
    KeyNotFound,
    #[error("failed to fetch relay signing key")]
    RelayKeyFetchFailed,
    #[error("relay has no signing key provisioned")]
    NoRelaySigningKey,
    #[error("device signing failed")]
    SigningFailed,
    #[error("DID creation request failed")]
    DidCreationFailed,
    #[error("keychain operation failed")]
    KeychainError,
    #[error("network error: {message}")]
    NetworkError { message: String },
}
```

**Step 4:** Add the `perform_did_ceremony` command after the `sign_with_device_key` command (before the `#[cfg_attr(mobile, tauri::mobile_entry_point)]` pub fn run()):

```rust
#[tauri::command]
async fn perform_did_ceremony(handle: String) -> Result<DIDCeremonyResult, DIDCeremonyError> {
    // Step 1: Get or create the device's P-256 key (serves as rotation key).
    let device_key = device_key::get_or_create().map_err(|e| {
        tracing::warn!(error = %e, "device key creation failed during DID ceremony");
        DIDCeremonyError::KeyNotFound
    })?;

    // Step 2: Fetch the relay's active signing key (public, no auth required).
    let resp = RELAY_CLIENT
        .get("/v1/relay/keys")
        .await
        .map_err(|e| DIDCeremonyError::NetworkError {
            message: e.to_string(),
        })?;

    if resp.status().as_u16() == 503 {
        return Err(DIDCeremonyError::NoRelaySigningKey);
    }
    if !resp.status().is_success() {
        return Err(DIDCeremonyError::RelayKeyFetchFailed);
    }

    let relay_key: RelaySigningKey = resp
        .json()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "failed to deserialize relay signing key response");
            DIDCeremonyError::RelayKeyFetchFailed
        })?;

    // Step 3: Build signed genesis op — device key as rotation key, relay key as signing key.
    // The sign callback calls device_key::sign() so the private key never leaves the SE.
    let rotation_key = DidKeyUri(device_key.key_id.clone());
    let signing_key = DidKeyUri(relay_key.key_id.clone());

    let genesis_op = build_did_plc_genesis_op_with_external_signer(
        &rotation_key,
        &signing_key,
        &handle,
        http::RelayClient::base_url(),
        |data| {
            device_key::sign(data)
                .map_err(|e| CryptoError::PlcOperation(format!("device signing failed: {e}")))
        },
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "genesis op signing failed during DID ceremony");
        DIDCeremonyError::SigningFailed
    })?;

    // Step 4: Retrieve the pending session token from Keychain.
    let token_bytes = keychain::get_item("session-token").map_err(|e| {
        tracing::warn!(error = %e, "failed to retrieve session-token from keychain");
        DIDCeremonyError::KeychainError
    })?;
    let pending_token = String::from_utf8(token_bytes).map_err(|e| {
        tracing::warn!(error = %e, "session-token bytes are not valid UTF-8");
        DIDCeremonyError::KeychainError
    })?;

    // Step 5: POST the signed genesis op to the relay to promote the account to a full DID.
    let create_did_req = CreateDidRequest {
        rotation_key_public: device_key.multibase,
        signed_creation_op: genesis_op.signed_op_json,
    };

    let resp = RELAY_CLIENT
        .post_with_bearer("/v1/dids", &create_did_req, &pending_token)
        .await
        .map_err(|e| DIDCeremonyError::NetworkError {
            message: e.to_string(),
        })?;

    if !resp.status().is_success() {
        return Err(DIDCeremonyError::DidCreationFailed);
    }

    let create_did_resp: CreateDidResponse = resp
        .json()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "failed to deserialize POST /v1/dids response");
            DIDCeremonyError::DidCreationFailed
        })?;

    // Step 6: Overwrite session-token with the upgraded full session token.
    keychain::store_item(
        "session-token",
        create_did_resp.session_token.as_bytes(),
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "failed to persist upgraded session-token to keychain");
        DIDCeremonyError::KeychainError
    })?;

    // Step 7: Persist the DID for use in subsequent app sessions.
    keychain::store_item("did", create_did_resp.did.as_bytes()).map_err(|e| {
        tracing::warn!(error = %e, "failed to persist DID to keychain");
        DIDCeremonyError::KeychainError
    })?;

    Ok(DIDCeremonyResult {
        did: create_did_resp.did,
    })
}
```

**Step 5:** Register `perform_did_ceremony` in `tauri::generate_handler![]` (around line 194-198):

```rust
.invoke_handler(tauri::generate_handler![
    create_account,
    get_or_create_device_key,
    sign_with_device_key,
    perform_did_ceremony,
])
```

**Verification:**

Run: `cargo build -p identity-wallet`
Expected: Compiles without errors or warnings.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Unit tests for DIDCeremonyResult and DIDCeremonyError serialization

**Verifies:** MM-146.AC3.4, MM-146.AC3.5, MM-146.AC3.6, MM-146.AC3.7 (via serde serialization contracts)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` — add to the existing `#[cfg(test)] mod tests` block

**Testing:**

Tests must verify the serde serialization contracts that the TypeScript frontend depends on. Append these test functions to the existing `mod tests` block in `lib.rs`:

```rust
    // -- DIDCeremonyResult serialization --
    #[test]
    fn did_ceremony_result_serializes_did_in_camel_case() {
        let result = DIDCeremonyResult {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["did"], "did:plc:abcdefghijklmnopqrstuvwx");
    }

    // -- DIDCeremonyError serialization (one test per variant) --
    #[test]
    fn did_ceremony_error_key_not_found_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::KeyNotFound).unwrap();
        assert_eq!(json["code"], "KEY_NOT_FOUND");
    }

    #[test]
    fn did_ceremony_error_relay_key_fetch_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::RelayKeyFetchFailed).unwrap();
        assert_eq!(json["code"], "RELAY_KEY_FETCH_FAILED");
    }

    #[test]
    fn did_ceremony_error_no_relay_signing_key_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::NoRelaySigningKey).unwrap();
        assert_eq!(json["code"], "NO_RELAY_SIGNING_KEY");
    }

    #[test]
    fn did_ceremony_error_signing_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::SigningFailed).unwrap();
        assert_eq!(json["code"], "SIGNING_FAILED");
    }

    #[test]
    fn did_ceremony_error_did_creation_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::DidCreationFailed).unwrap();
        assert_eq!(json["code"], "DID_CREATION_FAILED");
    }

    #[test]
    fn did_ceremony_error_keychain_error_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    #[test]
    fn did_ceremony_error_network_error_serializes_with_message() {
        let err = DIDCeremonyError::NetworkError {
            message: "Connection refused".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection refused");
    }
```

**Note on behavioral test coverage:** The `perform_did_ceremony` command orchestrates Keychain, Secure Enclave, and HTTP — none of which can be meaningfully mocked in a `cargo test` unit test environment on macOS/iOS. The 8 serde tests here cover the TypeScript-facing serialization contracts. Full behavioral coverage (ceremony runs end-to-end, keychain values are persisted, errors surface correctly) is verified via iOS Simulator manual testing described in the test-requirements document.

**Verification:**

Run: `cargo test -p identity-wallet`
Expected: All existing tests pass + 8 new serialization tests pass.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Commit

```bash
git add apps/identity-wallet/src-tauri/src/http.rs \
        apps/identity-wallet/src-tauri/src/lib.rs
git commit -m "feat(identity-wallet): add perform_did_ceremony Tauri command and relay client extensions"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->
