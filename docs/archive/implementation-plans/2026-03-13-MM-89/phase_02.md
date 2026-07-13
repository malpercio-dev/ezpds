# MM-89: DID Creation — did:plc via PLC Directory Proxy — Phase 2

**Goal:** Implement `POST /v1/dids` in the relay: DB migration, auth helper, route handler with pre-store retry resilience, and integration tests with a mocked plc.directory.

**Architecture:** Imperative Shell in `crates/relay/src/routes/create_did.rs`. Authenticates a `pending_session` Bearer token, calls Phase 1's pure `build_did_plc_genesis_op`, submits to plc.directory via `reqwest`, then atomically promotes the account in the DB.

**Tech Stack:** Rust stable; `axum` (routing, extractors), `reqwest` 0.12 (HTTP client), `sqlx` 0.8 (transactions), `wiremock` 0.6 (mock plc.directory in tests), `crypto::build_did_plc_genesis_op` (Phase 1)

**Scope:** Phase 2 of 2 from the original design. Depends on Phase 1 (`crypto::build_did_plc_genesis_op` must be on the branch).

**Codebase verified:** 2026-03-13

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-89.AC2: POST /v1/dids completes the DID ceremony and promotes the account
- **MM-89.AC2.1 Success:** Valid request with a live `pending_session` token returns `200 OK` with `{ "did": "did:plc:...", "status": "active" }`
- **MM-89.AC2.2 Success:** After success, `accounts` row exists with `did` as PK, correct `email`, and `password_hash` NULL
- **MM-89.AC2.3 Success:** After success, `did_documents` row exists for the DID with non-empty `document` JSON
- **MM-89.AC2.4 Success:** After success, `handles` row exists linking the handle to the DID
- **MM-89.AC2.5 Success:** After success, `pending_accounts` and `pending_sessions` rows for the account are deleted
- **MM-89.AC2.6 Success:** When `pending_did` is already set (client retry), handler skips the plc.directory HTTP call and completes DB promotion, returning 200
- **MM-89.AC2.7 Failure:** Missing `Authorization` header returns 401 `UNAUTHORIZED`
- **MM-89.AC2.8 Failure:** Expired `pending_session` token returns 401 `UNAUTHORIZED`
- **MM-89.AC2.9 Failure:** `signingKey` not present in `relay_signing_keys` returns 404 `NOT_FOUND`
- **MM-89.AC2.10 Failure:** Account already fully promoted (`accounts` row already exists) returns 409 `DID_ALREADY_EXISTS`
- **MM-89.AC2.11 Failure:** plc.directory returns non-2xx returns 502 `PLC_DIRECTORY_ERROR`

### MM-89.AC3: Schema migration and protocol correctness
- **MM-89.AC3.1:** V008 migration applies cleanly on top of V007; `accounts.password_hash` accepts NULL; `pending_accounts.pending_did` column exists

---

## External Dependency Research Findings

- ✓ **reqwest 0.12**: `Client::new()` returns a `Clone + Send + Sync` client safe for AppState. POST pre-serialized JSON: `.post(url).body(json_string).header("Content-Type", "application/json").send().await?`. Check success: `response.status().is_success()`. Path format for plc.directory: `POST /{did}` (e.g., `https://plc.directory/did:plc:xyz`).
- ✓ **wiremock 0.6**: `MockServer::start().await` on random port; `.uri()` for base URL. `Mock::given(method("POST")).and(path_regex(r"^/did:plc:[a-z2-7]+$")).respond_with(ResponseTemplate::new(200)).expect(1).mount(&server).await`. `.expect(0)` to assert NOT called. `MockServer` auto-verifies `.expect()` counts on drop.
- ✓ **Token hash pattern** (from create_mobile_account.rs): `Sha256::digest(raw_token_bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()`. SHA-256 of the raw bytes, NOT the base64url string. Bearer token sent to client is `URL_SAFE_NO_PAD.encode(raw_bytes)`.

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Add reqwest and wiremock Cargo.toml dependencies

**Verifies:** None (infrastructure)

**Files:**
- Modify: `Cargo.toml` (workspace root) — add reqwest
- Modify: `crates/relay/Cargo.toml` — add reqwest dep + wiremock dev-dep

**Step 1: Add reqwest to workspace Cargo.toml**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/Cargo.toml`, in the `[workspace.dependencies]` section, add after the existing entries:

```toml
reqwest = { version = "0.12", features = ["json"] }
```

**Step 2: Update crates/relay/Cargo.toml**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/Cargo.toml`, add to `[dependencies]`:

```toml
reqwest = { workspace = true }
serde_json = { workspace = true }
```

> **Note:** `serde_json` is already in the workspace root. It must appear in `[dependencies]` (not just `[dev-dependencies]`) because `create_did.rs` uses `serde_json::json!()` inside `build_did_document`, which is production code. Without this, `cargo build --release` (which does not include dev-deps) will fail.

Add to `[dev-dependencies]`:

```toml
wiremock = "0.6"
```

**Step 3: Verify deps resolve**

```bash
cargo check -p relay
```

Expected: resolves without errors.

**Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock crates/relay/Cargo.toml
git commit -m "chore(relay): add reqwest 0.12 and wiremock 0.6 deps for POST /v1/dids (MM-89)"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: V008 migration — nullable password_hash and pending_did column

**Verifies:** MM-89.AC3.1

**Files:**
- Create: `crates/relay/src/db/migrations/V008__did_promotion.sql`
- Modify: `crates/relay/src/db/mod.rs` (add V008 to MIGRATIONS)
- Modify: `crates/relay/src/db/AGENTS.md` (document V008)

**Step 1: Create the migration file**

Create `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/db/migrations/V008__did_promotion.sql`:

```sql
-- V008: DID promotion support
-- Applied in a single transaction by the migration runner.
--
-- 1. Rebuilds the accounts table with nullable password_hash.
--    Mobile-provisioned accounts (via POST /v1/dids) have no password;
--    only accounts created via POST /v1/accounts have a password_hash.
--    SQLite does not support ALTER COLUMN, so a full table rebuild is required.
--
-- 2. Adds pending_did to pending_accounts for retry-safe DID pre-storage.
--    Populated by POST /v1/dids before calling plc.directory (pre-store pattern).
--    If the promotion transaction fails after plc.directory accepts the op,
--    a client retry detects this non-NULL value and skips the directory call.

-- ── Rebuild accounts with nullable password_hash ─────────────────────────────

CREATE TABLE accounts_new (
    did                TEXT NOT NULL,
    email              TEXT NOT NULL,
    password_hash      TEXT,                -- NULL for mobile-provisioned accounts
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    email_confirmed_at TEXT,
    deactivated_at     TEXT,
    PRIMARY KEY (did)
);

INSERT INTO accounts_new
    SELECT did, email, password_hash, created_at, updated_at, email_confirmed_at, deactivated_at
    FROM accounts;

DROP TABLE accounts;

ALTER TABLE accounts_new RENAME TO accounts;

CREATE UNIQUE INDEX idx_accounts_email ON accounts (email);

-- ── Add pending_did to pending_accounts ──────────────────────────────────────

ALTER TABLE pending_accounts ADD COLUMN pending_did TEXT;
```

> **Note for executor:** The `DROP TABLE accounts` step works even with FK enforcement ON because SQLite FK checks are triggered on INSERT/UPDATE of child rows, not on DROP of a parent table. If for any reason the migration runner reports FK constraint issues, consult the db/mod.rs migration runner to see if PRAGMA foreign_keys = OFF is needed around the table rebuild section.

**Step 2: Add V008 to the MIGRATIONS array in db/mod.rs**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/db/mod.rs`, find the `MIGRATIONS` static array. Add the V008 entry after V007:

```rust
Migration { version: 8, sql: include_str!("migrations/V008__did_promotion.sql") },
```

The full array (after edit) should look like:

```rust
static MIGRATIONS: &[Migration] = &[
    Migration { version: 1, sql: include_str!("migrations/V001__init.sql") },
    Migration { version: 2, sql: include_str!("migrations/V002__auth_identity.sql") },
    Migration { version: 3, sql: include_str!("migrations/V003__relay_signing_keys.sql") },
    Migration { version: 4, sql: include_str!("migrations/V004__claim_codes_invite.sql") },
    Migration { version: 5, sql: include_str!("migrations/V005__pending_accounts.sql") },
    Migration { version: 6, sql: include_str!("migrations/V006__devices_v2.sql") },
    Migration { version: 7, sql: include_str!("migrations/V007__pending_sessions.sql") },
    Migration { version: 8, sql: include_str!("migrations/V008__did_promotion.sql") },
];
```

**Step 3: Update crates/relay/src/db/AGENTS.md**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/db/AGENTS.md`, update the "Last verified" date to `2026-03-13` and add to the Key Files section:

```
- `migrations/V008__did_promotion.sql` - Rebuilds accounts with nullable password_hash (mobile accounts have no password); adds pending_did column to pending_accounts for DID pre-store retry resilience
```

**Step 4: Verify migration applies cleanly**

```bash
cargo test -p relay db::tests
```

Expected: all DB tests pass including migration idempotence test with V008 applied.

**Step 5: Commit**

```bash
git add crates/relay/src/db/migrations/V008__did_promotion.sql crates/relay/src/db/mod.rs crates/relay/src/db/AGENTS.md
git commit -m "feat(relay): V008 migration — nullable accounts.password_hash, pending_did column (MM-89)"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Add plc_directory_url to Config and ErrorCode variants

**Verifies:** None (infrastructure — verified through route tests)

**Files:**
- Modify: `crates/common/src/config.rs` (add plc_directory_url field)
- Modify: `crates/common/src/error.rs` (add DID_ALREADY_EXISTS, PLC_DIRECTORY_ERROR)

**Step 1: Add plc_directory_url to Config struct**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/common/src/config.rs`:

**1a. Add to `Config` struct** (after `signing_key_master_key`):

```rust
pub plc_directory_url: String,
```

**1b. Add to `RawConfig` struct** (after `admin_token`, before `signing_key_master_key`):

```rust
pub(crate) plc_directory_url: Option<String>,
```

> **Note:** Unlike `signing_key_master_key`, this field is NOT security-sensitive, so it does NOT use `#[serde(skip)]` or a sentinel. Operators can set it via either TOML (`plc_directory_url = "https://..."`) or the env var `EZPDS_PLC_DIRECTORY_URL`.

**1c. Add env override in `apply_env_overrides`** (after the existing EZPDS_ env var handling block, following the same pattern):

```rust
if let Some(v) = env.get("EZPDS_PLC_DIRECTORY_URL") {
    raw.plc_directory_url = Some(v.clone());
}
```

**1d. Add to `validate_and_build`** (after the other field validations, before the final Config construction):

```rust
let plc_directory_url = raw
    .plc_directory_url
    .unwrap_or_else(|| "https://plc.directory".to_string());
```

**1e. Add to the Config constructor** in `validate_and_build` (add `plc_directory_url,` to the struct literal):

```rust
Ok(Config {
    // ... existing fields ...
    plc_directory_url,
})
```

**Step 2: Add ErrorCode variants**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/common/src/error.rs`, add to the `ErrorCode` enum (keeping the existing variants unchanged). Match the existing pattern — bare variants with doc comments, no `#[error(...)]` attribute (the enum derives `Serialize` for wire format, not `thiserror::Error`):

```rust
/// The DID has already been fully promoted to an active account.
DidAlreadyExists,
/// The external PLC directory returned a non-success response.
PlcDirectoryError,
```

Also add the HTTP status code mappings for these new variants. Find the `status_code()` method in `impl ErrorCode` and add:

```rust
ErrorCode::DidAlreadyExists => 409,
ErrorCode::PlcDirectoryError => 502,
```

> **Note for executor:** `status_code()` returns a plain `u16`, not `axum::http::StatusCode`. The common crate does not depend on axum. Match the existing pattern — e.g., `ErrorCode::AccountExists => 409,`.

**Step 2b: Update the `status_code_mapping` test**

In the same file (`crates/common/src/error.rs`), find the `status_code_mapping` test (in `#[cfg(test)] mod tests`). Add two entries to the `cases` array:

```rust
(ErrorCode::DidAlreadyExists, 409),
(ErrorCode::PlcDirectoryError, 502),
```

The test is exhaustive — it will fail at compile time if new variants are not covered. Add these entries at the end of the `cases` array, just before the closing `]`.

**Step 3: Verify build passes**

```bash
cargo check --workspace
```

Expected: no errors.

**Step 4: Commit**

```bash
git add crates/common/src/config.rs crates/common/src/error.rs
git commit -m "feat(common): add plc_directory_url to Config and DID error codes (MM-89)"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Add http_client to AppState and update test_state

**Verifies:** None (infrastructure — verified through route tests)

**Files:**
- Modify: `crates/relay/src/app.rs`

**Step 1: Add http_client field to AppState**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/app.rs`:

**1a. Add reqwest use import** (at the top of the file with other imports):

```rust
use reqwest::Client;
```

**1b. Add `http_client` field to `AppState`** struct:

```rust
pub struct AppState {
    pub config: Arc<Config>,
    pub db: sqlx::SqlitePool,
    pub http_client: Client,
}
```

**1c. Update the production AppState construction** in `main.rs` (find where `AppState { config, db }` is created and add `http_client: Client::new()`):

```rust
AppState {
    config: Arc::new(config),
    db,
    http_client: Client::new(),
}
```

> **Note for executor:** Find the AppState construction in `crates/relay/src/main.rs` (or wherever the production startup code lives) and add `http_client: Client::new()`.

**1d. Replace `test_state()` in app.rs and add `test_state_with_plc_url`** (in the `#[cfg(test)]` block):

Replace the existing `test_state()` function entirely with these two functions:

```rust
#[cfg(test)]
pub(crate) async fn test_state() -> AppState {
    test_state_with_plc_url("https://plc.directory".to_string()).await
}

#[cfg(test)]
pub async fn test_state_with_plc_url(plc_directory_url: String) -> AppState {
    use crate::db::{open_pool, run_migrations};
    use common::{BlobsConfig, IrohConfig, OAuthConfig, TelemetryConfig};
    use std::path::PathBuf;

    let db = open_pool("sqlite::memory:").await.expect("test pool");
    run_migrations(&db).await.expect("test migrations");

    AppState {
        config: Arc::new(Config {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            data_dir: PathBuf::from("/tmp"),
            database_url: "sqlite::memory:".to_string(),
            public_url: "https://test.example.com".to_string(),
            server_did: None,
            available_user_domains: vec!["test.example.com".to_string()],
            invite_code_required: true,
            links: common::ServerLinksConfig::default(),
            contact: common::ContactConfig::default(),
            blobs: BlobsConfig::default(),
            oauth: OAuthConfig::default(),
            iroh: IrohConfig::default(),
            telemetry: TelemetryConfig::default(),
            admin_token: None,
            signing_key_master_key: None,
            plc_directory_url,
        }),
        db,
        http_client: Client::new(),
    }
}
```

The `test_state()` function now delegates to `test_state_with_plc_url`, keeping a single source of truth for Config defaults. All existing tests that call `test_state()` continue to work unchanged.

**Step 2: Verify build passes**

```bash
cargo build -p relay
```

Expected: builds without errors.

**Step 3: Run existing tests to ensure no regressions**

```bash
cargo test -p relay
```

Expected: all existing tests pass.

**Step 4: Commit**

```bash
git add crates/relay/src/app.rs crates/relay/src/main.rs
git commit -m "feat(relay): add reqwest::Client to AppState for outbound HTTP (MM-89)"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 5-6) -->

<!-- START_TASK_5 -->
### Task 5: Add require_pending_session auth helper to auth.rs

**Verifies:** MM-89.AC2.7, MM-89.AC2.8

**Files:**
- Modify: `crates/relay/src/routes/auth.rs`

**Step 1: Read current auth.rs**

Before editing, read `crates/relay/src/routes/auth.rs` to understand the current imports and structure. The existing `require_admin_token` function is the pattern to follow.

**Step 2: Add PendingSessionInfo struct and require_pending_session function**

Add the following to `crates/relay/src/routes/auth.rs`:

```rust
/// Information about an authenticated pending session.
pub struct PendingSessionInfo {
    pub account_id: String,
    pub device_id: String,
}

/// Authenticate a `pending_session` Bearer token.
///
/// Extracts the Bearer token from the Authorization header, SHA-256 hashes the raw
/// decoded bytes (matching the storage format from `POST /v1/accounts/mobile`), and
/// queries `pending_sessions` for a matching, unexpired row.
///
/// # Errors
/// Returns `ApiError::Unauthorized` if:
/// - The Authorization header is missing
/// - The token is not valid base64url
/// - No unexpired session matches the token hash
pub async fn require_pending_session(
    headers: &axum::http::HeaderMap,
    db: &sqlx::SqlitePool,
) -> Result<PendingSessionInfo, ApiError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    // Extract Bearer token from Authorization header.
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unauthorized,
                "missing or invalid Authorization header",
            )
        })?;

    // Decode base64url → raw bytes, then SHA-256 hash → hex string.
    // Matches the storage format written by POST /v1/accounts/mobile.
    let token_bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| {
        ApiError::new(
            ErrorCode::Unauthorized,
            "invalid session token",
        )
    })?;
    let token_hash: String = Sha256::digest(&token_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Look up the session by hash, rejecting expired sessions.
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT account_id, device_id FROM pending_sessions \
         WHERE token_hash = ? AND expires_at > datetime('now')",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query pending session");
        ApiError::new(
            ErrorCode::InternalError,
            "session lookup failed",
        )
    })?;

    let (account_id, device_id) = row.ok_or_else(|| {
        ApiError::new(
            ErrorCode::Unauthorized,
            "invalid or expired session token",
        )
    })?;

    Ok(PendingSessionInfo { account_id, device_id })
}
```

**Step 3: Add necessary imports to auth.rs**

Ensure the top of auth.rs has the needed imports. The function uses:
- `axum::http::HeaderMap` — check if already imported
- `sqlx::SqlitePool` — check if already imported
- `base64`, `sha2` — these crates are already in `crates/relay/Cargo.toml`

**Step 4: Verify build**

```bash
cargo build -p relay
```

Expected: no errors.

**Step 5: Commit**

```bash
git add crates/relay/src/routes/auth.rs
git commit -m "feat(relay): add require_pending_session auth helper (MM-89)"
```
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Implement create_did.rs route, register it, and add integration tests

**Verifies:** MM-89.AC2.1, MM-89.AC2.2, MM-89.AC2.3, MM-89.AC2.4, MM-89.AC2.5, MM-89.AC2.6, MM-89.AC2.7, MM-89.AC2.8, MM-89.AC2.9, MM-89.AC2.10, MM-89.AC2.11, MM-89.AC3.1

**Files:**
- Create: `crates/relay/src/routes/create_did.rs` (new)
- Modify: `crates/relay/src/routes/mod.rs` (add module)
- Modify: `crates/relay/src/app.rs` (register route)
- Create: `bruno/create-did.bru` (new)

> **Pre-step for executor:** Before implementing, read `crates/relay/src/routes/test_utils.rs` to understand what test helpers are already available (e.g., helpers to insert claim codes, pending accounts, devices, sessions). Use existing helpers where possible rather than duplicating SQL setup. Also read the full current `test_state()` in app.rs before implementing `test_state_with_plc_url`.

---

**Step 1: Read crates/relay/src/routes/create_signing_key.rs**

Read the full file to understand the exact import pattern, master key access pattern (`state.config.signing_key_master_key.as_ref().map(|s| &*s.0)`), and error handling style.

---

**Step 2: Create crates/relay/src/routes/create_did.rs**

Create `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/routes/create_did.rs`:

```rust
// pattern: Imperative Shell
//
// POST /v1/dids — DID creation and account promotion
//
// Inputs:
//   - Authorization: Bearer <pending_session_token>
//   - JSON body: { "signingKey": "did:key:z...", "rotationKey": "did:key:z..." }
//
// Processing steps:
//   1. require_pending_session → PendingSessionInfo { account_id, device_id }
//   2. SELECT handle, pending_did FROM pending_accounts WHERE id = account_id
//   3. SELECT private_key_encrypted FROM relay_signing_keys WHERE id = signing_key
//   4. decrypt_private_key(encrypted, master_key)
//   5. build_did_plc_genesis_op(rotation_key, signing_key, private_key, handle, public_url)
//   6. If pending_did IS NULL: UPDATE pending_accounts SET pending_did = did (pre-store resilience)
//   7. If pending_did IS NOT NULL (retry): skip step 8
//   8. POST {plc_directory_url}/{did} with signed_op_json
//   9. Atomic transaction:
//        INSERT accounts (did, email, password_hash=NULL)
//        INSERT did_documents (did, document)
//        INSERT handles (handle, did)
//        DELETE pending_sessions WHERE account_id = ?
//        DELETE pending_accounts WHERE id = ?
//  10. Return { "did": "did:plc:...", "status": "active" }
//
// Outputs (success):  200 { "did": "did:plc:...", "status": "active" }
// Outputs (error):    401 UNAUTHORIZED, 404 NOT_FOUND, 409 DID_ALREADY_EXISTS,
//                     502 PLC_DIRECTORY_ERROR, 500 INTERNAL_ERROR

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::routes::auth::require_pending_session;
use common::{ApiError, ErrorCode};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequest {
    pub signing_key: String,
    pub rotation_key: String,
}

#[derive(Serialize)]
pub struct CreateDidResponse {
    pub did: String,
    pub status: &'static str,
}

pub async fn create_did_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateDidRequest>,
) -> Result<Json<CreateDidResponse>, ApiError> {
    // Step 1: Authenticate via pending_session Bearer token.
    let session = require_pending_session(&headers, &state.db).await?;

    // Step 2: Load pending account details.
    let (handle, pending_did, email): (String, Option<String>, String) = sqlx::query_as(
        "SELECT handle, pending_did, email FROM pending_accounts WHERE id = ?",
    )
    .bind(&session.account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query pending account");
        ApiError::new(ErrorCode::InternalError, "failed to load account")
    })?
    .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "account not found"))?;

    // Step 3: Look up signing key in relay_signing_keys.
    let (private_key_encrypted,): (String,) = sqlx::query_as(
        "SELECT private_key_encrypted FROM relay_signing_keys WHERE id = ?",
    )
    .bind(&payload.signing_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query relay signing key");
        ApiError::new(ErrorCode::InternalError, "key lookup failed")
    })?
    .ok_or_else(|| {
        ApiError::new(ErrorCode::NotFound, "signing key not found in relay_signing_keys")
    })?;

    // Step 4: Decrypt the private key using the master key from config.
    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(ErrorCode::InternalError, "signing key master key not configured")
        })?;

    let private_key_bytes = crypto::decrypt_private_key(&private_key_encrypted, master_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to decrypt signing key");
            ApiError::new(ErrorCode::InternalError, "failed to decrypt signing key")
        })?;

    // Step 5: Build the genesis operation and derive the DID.
    let rotation_key = crypto::DidKeyUri(payload.rotation_key.clone());
    let signing_key_uri = crypto::DidKeyUri(payload.signing_key.clone());

    let genesis = crypto::build_did_plc_genesis_op(
        &rotation_key,
        &signing_key_uri,
        &*private_key_bytes,
        &handle,
        &state.config.public_url,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to build genesis op");
        ApiError::new(ErrorCode::InternalError, "failed to build genesis operation")
    })?;

    let did = genesis.did.clone();
    let signed_op_json = genesis.signed_op_json;

    // Step 6: Pre-store the DID for retry resilience.
    // If pending_did is already set, we are on a retry path — skip the plc.directory call.
    let skip_plc_directory = if let Some(pre_stored_did) = &pending_did {
        // Retry: use the pre-stored DID (should match — same deterministic inputs).
        tracing::info!(did = %pre_stored_did, "retry detected: pending_did already set, skipping plc.directory");
        true
    } else {
        // First attempt: write the DID before calling plc.directory.
        sqlx::query(
            "UPDATE pending_accounts SET pending_did = ? WHERE id = ?",
        )
        .bind(&did)
        .bind(&session.account_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to pre-store pending_did");
            ApiError::new(ErrorCode::InternalError, "failed to store pending DID")
        })?;
        false
    };

    // Step 7: Check if the account is already fully promoted (idempotency guard for AC2.10).
    let already_promoted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE did = ?)")
        .bind(&did)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to check accounts existence");
            ApiError::new(ErrorCode::InternalError, "database error")
        })?;

    if already_promoted {
        return Err(ApiError::new(ErrorCode::DidAlreadyExists, "DID is already fully promoted"));
    }

    // Step 8: POST the genesis operation to plc.directory (skipped on retry).
    if !skip_plc_directory {
        let plc_url = format!("{}/{}", state.config.plc_directory_url, did);
        let response = state
            .http_client
            .post(&plc_url)
            .body(signed_op_json.clone())
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, plc_url = %plc_url, "failed to contact plc.directory");
                ApiError::new(ErrorCode::PlcDirectoryError, "failed to contact plc.directory")
            })?;

        if !response.status().is_success() {
            let status = response.status();
            tracing::error!(status = %status, "plc.directory rejected genesis operation");
            return Err(ApiError::new(
                ErrorCode::PlcDirectoryError,
                format!("plc.directory returned {status}"),
            ));
        }
    }

    // Step 9: Build the DID document for local storage.
    let did_document = build_did_document(&did, &handle, &payload.signing_key, &state.config.public_url);

    // Step 10: Atomically promote the account.
    let mut tx = state
        .db
        .begin()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to begin promotion transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to begin transaction"))?;

    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
         VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
    )
    .bind(&did)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| tracing::error!(error = %e, "failed to insert account"))
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to create account"))?;

    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now'))",
    )
    .bind(&did)
    .bind(&did_document)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| tracing::error!(error = %e, "failed to insert did_document"))
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to store DID document"))?;

    sqlx::query(
        "INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))",
    )
    .bind(&handle)
    .bind(&did)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| tracing::error!(error = %e, "failed to insert handle"))
    .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to register handle"))?;

    sqlx::query("DELETE FROM pending_sessions WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete pending sessions"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up sessions"))?;

    sqlx::query("DELETE FROM pending_accounts WHERE id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to delete pending account"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to clean up account"))?;

    tx.commit()
        .await
        .inspect_err(|e| tracing::error!(error = %e, "failed to commit promotion transaction"))
        .map_err(|_| ApiError::new(ErrorCode::InternalError, "failed to commit transaction"))?;

    Ok(Json(CreateDidResponse { did, status: "active" }))
}

/// Construct a minimal DID Core document from known fields.
///
/// No I/O — pure construction from parameters.
fn build_did_document(
    did: &str,
    handle: &str,
    signing_key_did: &str,
    service_endpoint: &str,
) -> String {
    // Extract the multibase-encoded public key from the did:key URI.
    // did:key:zAbcDef... → publicKeyMultibase = "zAbcDef..."
    let public_key_multibase = signing_key_did
        .strip_prefix("did:key:")
        .unwrap_or(signing_key_did);

    serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1"
        ],
        "id": did,
        "alsoKnownAs": [format!("at://{handle}")],
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": service_endpoint
        }]
    })
    .to_string()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state_with_plc_url;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand_core::{OsRng, RngCore};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt; // for `.oneshot()`
    use uuid::Uuid;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path_regex}};

    // ── Test setup helpers ────────────────────────────────────────────────────

    /// A test master key: 32 bytes of 0x01.
    const TEST_MASTER_KEY: [u8; 32] = [0x01u8; 32];

    /// All data needed to call POST /v1/dids in a test.
    struct TestSetup {
        session_token: String,
        signing_key_id: String,
        rotation_key_id: String,
        account_id: String,
        /// The handle stored in `pending_accounts`. Needed for AC2.10 to re-create
        /// a second pending account that derives the same DID (same keys + same handle).
        handle: String,
    }

    /// Insert all prerequisite rows for a DID-creation test.
    ///
    /// Inserts: relay_signing_key, pending_account (with claim code), device, pending_session.
    ///
    /// Pre-step: Read `crates/relay/src/routes/test_utils.rs` to see if helpers already
    /// exist for inserting claim codes, pending accounts, or pending sessions. Use them here
    /// if available. If not, use the raw SQL below.
    async fn insert_test_data(db: &sqlx::SqlitePool) -> TestSetup {
        use crypto::{encrypt_private_key, generate_p256_keypair};

        // Generate signing and rotation keypairs.
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");

        // Encrypt the signing private key with the test master key.
        let encrypted =
            encrypt_private_key(&signing_kp.private_key_bytes, &TEST_MASTER_KEY)
                .expect("encrypt key");

        // Insert relay_signing_key.
        sqlx::query(
            "INSERT INTO relay_signing_keys \
             (id, algorithm, public_key, private_key_encrypted, created_at) \
             VALUES (?, 'p256', ?, ?, datetime('now'))",
        )
        .bind(&signing_kp.key_id.0)
        .bind(&signing_kp.public_key)
        .bind(&encrypted)
        .execute(db)
        .await
        .expect("insert relay_signing_key");

        // Insert a claim_code row (required FK for pending_accounts).
        let claim_code = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code)
        .execute(db)
        .await
        .expect("insert claim_code");

        // Insert pending_account.
        let account_id = Uuid::new_v4().to_string();
        let handle = format!("alice{}.example.com", &account_id[..8]);
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id)
        .bind(format!("alice{}@example.com", &account_id[..8]))
        .bind(&handle)
        .bind(&claim_code)
        .execute(db)
        .await
        .expect("insert pending_account");

        // Insert a device (required FK for pending_sessions).
        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'test_pubkey', 'test_device_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id)
        .bind(&account_id)
        .execute(db)
        .await
        .expect("insert device");

        // Generate pending session token.
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let session_token = URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash: String = Sha256::digest(token_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        // Insert pending_session.
        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(&device_id)
        .bind(&token_hash)
        .execute(db)
        .await
        .expect("insert pending_session");

        TestSetup {
            session_token,
            signing_key_id: signing_kp.key_id.0,
            rotation_key_id: rotation_kp.key_id.0,
            account_id,
            handle,
        }
    }

    /// Create an AppState with TEST_MASTER_KEY set and plc_directory_url pointing to the mock.
    async fn test_state_for_did(plc_url: String) -> AppState {
        use crate::db::{open_pool, run_migrations};
        use common::{BlobsConfig, IrohConfig, OAuthConfig, Sensitive, TelemetryConfig};
        use reqwest::Client;
        use std::path::PathBuf;
        use std::sync::Arc;
        use zeroize::Zeroizing;

        let db = open_pool("sqlite::memory:").await.expect("test pool");
        run_migrations(&db).await.expect("test migrations");

        AppState {
            config: Arc::new(Config {
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
                data_dir: PathBuf::from("/tmp"),
                database_url: "sqlite::memory:".to_string(),
                public_url: "https://test.example.com".to_string(),
                server_did: None,
                available_user_domains: vec!["test.example.com".to_string()],
                invite_code_required: true,
                links: common::ServerLinksConfig::default(),
                contact: common::ContactConfig::default(),
                blobs: BlobsConfig::default(),
                oauth: OAuthConfig::default(),
                iroh: IrohConfig::default(),
                telemetry: TelemetryConfig::default(),
                admin_token: None,
                signing_key_master_key: Some(Sensitive(Zeroizing::new(TEST_MASTER_KEY))),
                plc_directory_url: plc_url,
            }),
            db,
            http_client: Client::new(),
        }
    }

    /// Build a POST /v1/dids request with the given session token and body.
    fn create_did_request(
        session_token: &str,
        signing_key: &str,
        rotation_key: &str,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "signingKey": signing_key,
            "rotationKey": rotation_key,
        });
        Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ── AC2.1: Valid request returns 200 with { did, status: "active" } ───────

    /// MM-89.AC2.1, AC2.2, AC2.3, AC2.4, AC2.5: Happy path — full promotion
    #[tokio::test]
    async fn happy_path_promotes_account_and_returns_did() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .named("plc.directory genesis op")
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        // AC2.1: 200 OK with did + status
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
        let did = body["did"].as_str().expect("did field");
        assert!(did.starts_with("did:plc:"), "did should start with did:plc:");
        assert_eq!(body["status"], "active");

        // AC2.2: accounts row with null password_hash
        let (stored_email, stored_hash): (String, Option<String>) =
            sqlx::query_as("SELECT email, password_hash FROM accounts WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .expect("accounts row should exist");
        assert!(stored_hash.is_none(), "password_hash should be NULL");
        assert!(stored_email.contains("alice"), "email should be set");

        // AC2.3: did_documents row with non-empty document
        let (doc,): (String,) =
            sqlx::query_as("SELECT document FROM did_documents WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .expect("did_documents row should exist");
        assert!(!doc.is_empty(), "did_document should be non-empty");

        // AC2.4: handles row
        let (handle_did,): (String,) =
            sqlx::query_as("SELECT did FROM handles WHERE did = ?")
                .bind(did)
                .fetch_one(&db)
                .await
                .expect("handles row should exist");
        assert_eq!(handle_did, did);

        // AC2.5: pending_accounts and pending_sessions deleted
        let pending_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_accounts WHERE id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(pending_count, 0, "pending_account should be deleted");

        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_sessions WHERE account_id = ?")
                .bind(&setup.account_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(session_count, 0, "pending_sessions should be deleted");
    }

    /// MM-89.AC2.6: Retry path — pending_did pre-set, plc.directory NOT called
    #[tokio::test]
    async fn retry_with_pending_did_skips_plc_directory() {
        let mock_server = MockServer::start().await;
        // Expect zero calls to plc.directory on a retry.
        // MockServer auto-verifies .expect(0) on drop — if plc.directory is called,
        // the mock panics and the test fails.
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:.*$"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0) // Must NOT be called
            .named("plc.directory (should not be called on retry)")
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        // Simulate a partial-failure retry: set pending_did to any non-null value.
        // The handler checks `pending_did.is_some()` as a boolean flag to skip
        // plc.directory. It does NOT use the stored value — it always re-derives
        // the DID from the crypto function (deterministic from key + handle inputs).
        // So any syntactically valid DID string works here.
        let any_did = "did:plc:abcdefghijklmnopqrstuvwx";
        sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind(any_did)
            .bind(&setup.account_id)
            .execute(&db)
            .await
            .expect("pre-store pending_did");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        // The route skips plc.directory (enforced by .expect(0) above) and proceeds
        // to promote the account using the crypto-derived DID. Returns 200.
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "retry should succeed with 200"
        );
    }

    /// MM-89.AC2.7: Missing Authorization header returns 401
    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let state = test_state_with_plc_url("https://plc.directory".to_string()).await;
        let app = crate::app::app(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/dids")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"signingKey":"did:key:z...","rotationKey":"did:key:z..."}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// MM-89.AC2.8: Expired session token returns 401
    #[tokio::test]
    async fn expired_session_returns_401() {
        let state = test_state_with_plc_url("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        // Manually expire the session.
        sqlx::query("UPDATE pending_sessions SET expires_at = datetime('now', '-1 hour') WHERE account_id = ?")
            .bind(&setup.account_id)
            .execute(&db)
            .await
            .expect("expire session");

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// MM-89.AC2.9: signingKey not in relay_signing_keys returns 404
    #[tokio::test]
    async fn unknown_signing_key_returns_404() {
        let state = test_state_for_did("https://plc.directory".to_string()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                "did:key:zNONEXISTENT",  // Not in relay_signing_keys
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// MM-89.AC2.10: Account already promoted returns 409 DID_ALREADY_EXISTS
    ///
    /// The DID is deterministic from (rotation_key, signing_key, handle, service_endpoint).
    /// To reliably trigger 409, we:
    ///   1. First call promotes setup's account (deletes pending_accounts + pending_sessions).
    ///   2. Create a NEW pending account+session using the SAME signing key, rotation key,
    ///      and handle as setup. Same inputs → same crypto-derived DID.
    ///   3. Second call: handler derives the same DID, finds the existing `accounts` row,
    ///      returns 409 DID_ALREADY_EXISTS.
    #[tokio::test]
    async fn already_promoted_account_returns_409() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:.*$"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        // First call: promotes setup's account (deletes pending_accounts + pending_sessions).
        let app1 = crate::app::app(state.clone());
        let resp1 = app1
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK, "first call should succeed");

        // setup's pending_accounts row is now deleted. Create a NEW pending account
        // with the SAME handle and signing key. Since pending_accounts.handle has no
        // unique constraint, we can reuse setup.handle here.
        let claim_code2 = format!("TEST-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(&claim_code2)
        .execute(&db)
        .await
        .expect("claim_code2");

        let account_id2 = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(&account_id2)
        .bind(format!("retry{}@example.com", &account_id2[..8]))
        .bind(&setup.handle) // same handle → same DID with same signing/rotation keys
        .bind(&claim_code2)
        .execute(&db)
        .await
        .expect("pending_account2");

        let device_id2 = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices \
             (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
             VALUES (?, ?, 'ios', 'retry_pubkey', 'retry_device_hash', datetime('now'), datetime('now'))",
        )
        .bind(&device_id2)
        .bind(&account_id2)
        .execute(&db)
        .await
        .expect("device2");

        let mut token_bytes2 = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes2);
        let session_token2 = URL_SAFE_NO_PAD.encode(token_bytes2);
        let token_hash2: String = Sha256::digest(token_bytes2)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sqlx::query(
            "INSERT INTO pending_sessions \
             (id, account_id, device_id, token_hash, created_at, expires_at) \
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id2)
        .bind(&device_id2)
        .bind(&token_hash2)
        .execute(&db)
        .await
        .expect("session2");

        // Second call: same signing_key + rotation_key + handle → same DID.
        // accounts table already has this DID → handler returns 409.
        let app2 = crate::app::app(state);
        let resp2 = app2
            .oneshot(create_did_request(
                &session_token2,
                &setup.signing_key_id,  // same signing key
                &setup.rotation_key_id, // same rotation key
            ))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::CONFLICT, "should return 409 DID_ALREADY_EXISTS");
    }

    /// MM-89.AC2.11: plc.directory returns non-2xx → 502 PLC_DIRECTORY_ERROR
    #[tokio::test]
    async fn plc_directory_error_returns_502() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/did:plc:.*$"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let state = test_state_for_did(mock_server.uri()).await;
        let db = state.db.clone();
        let setup = insert_test_data(&db).await;

        let app = crate::app::app(state);
        let response = app
            .oneshot(create_did_request(
                &setup.session_token,
                &setup.signing_key_id,
                &setup.rotation_key_id,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
```

---

**Step 3: Add create_did module to routes/mod.rs**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/routes/mod.rs`, add:

```rust
pub mod create_did;
```

Keep the existing module declarations; add this line in alphabetical order (after `claim_codes`, before `create_mobile_account`).

---

**Step 4: Register POST /v1/dids in app.rs router**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/app.rs`, in the `app(state: AppState)` function:

**4a. Add the import** at the top of the function body or via `use`:

```rust
use crate::routes::create_did::create_did_handler;
```

**4b. Add the route** to the `Router::new()` chain (after the existing `/v1/relay/keys` route):

```rust
.route("/v1/dids", post(create_did_handler))
```

---

**Step 5: Create bruno/create-did.bru**

Create `/Users/malpercio/workspace/malpercio-dev/ezpds/bruno/create-did.bru`:

```
meta {
  name: Create DID
  type: http
  seq: 8
}

post {
  url: {{baseUrl}}/v1/dids
  body: json
  auth: bearer
}

auth:bearer {
  token: {{pendingSessionToken}}
}

body:json {
  {
    "signingKey": "{{signingKeyId}}",
    "rotationKey": "{{rotationKeyId}}"
  }
}
```

---

**Step 6: Verify all tests pass**

```bash
cargo test -p relay
```

Expected: all tests pass including the new `create_did` integration tests.

**Step 7: Verify no clippy warnings**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: zero warnings.

**Step 8: Commit**

```bash
git add crates/relay/src/routes/create_did.rs crates/relay/src/routes/mod.rs crates/relay/src/app.rs bruno/create-did.bru
git commit -m "feat(relay): implement POST /v1/dids with pre-store retry resilience (MM-89)"
```
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase Completion Verification

After all tasks, verify the complete phase:

```bash
# All relay tests pass (existing 167+ tests + new create_did tests)
cargo test -p relay

# All crypto tests still pass
cargo test -p crypto

# No clippy warnings across workspace
cargo clippy --workspace -- -D warnings

# No formatting issues
cargo fmt --all --check
```

Expected: all tests pass, zero warnings, formatted correctly.
