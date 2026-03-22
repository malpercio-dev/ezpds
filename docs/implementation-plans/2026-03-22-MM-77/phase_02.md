# OAuth Token Endpoint — Phase 2: OAuth Signing Key Infrastructure

**Goal:** Load or generate the persistent ES256 signing keypair at startup and expose it via `AppState`.

**Architecture:** New `OAuthSigningKey` type in `auth/mod.rs`. DB functions for the `oauth_signing_key` table in `db/oauth.rs`. Startup function `load_or_create_oauth_signing_key` in `auth/mod.rs`. `AppState` gains `oauth_signing_keypair: OAuthSigningKey`. `main.rs` calls the startup function after migrations.

**Tech Stack:** `p256 0.13` (ecdsa + pkcs8 features), `jsonwebtoken 9` (ES256 EncodingKey), `crypto` crate (generate_p256_keypair, encrypt_private_key, decrypt_private_key), `sqlx` (oauth_signing_key table).

**Scope:** Phase 2 of 6

**Codebase verified:** 2026-03-22

---

## Acceptance Criteria Coverage

### MM-77.AC6: OAuth signing key persistence
- **MM-77.AC6.1 Success:** First startup generates P-256 keypair, stores encrypted in `oauth_signing_key`
- **MM-77.AC6.2 Success:** Subsequent restarts reload the same key (same `kid` in JWTs)

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add pkcs8 feature to p256 and move to production dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root, line 61)
- Modify: `crates/relay/Cargo.toml` (move p256 from dev-deps to deps)

The workspace p256 dependency currently only has `features = ["ecdsa"]`. The `pkcs8` feature is required for `SigningKey::to_pkcs8_der()`, which is needed to construct a `jsonwebtoken::EncodingKey`. Additionally, `p256` is currently only in relay's `[dev-dependencies]`; production code in `auth/mod.rs` will use it, so it must move to `[dependencies]`.

**Step 1: Edit workspace `Cargo.toml`**

Find this line (line 61):

```toml
p256 = { version = "0.13", features = ["ecdsa"] }
```

Replace with:

```toml
p256 = { version = "0.13", features = ["ecdsa", "pkcs8"] }
```

**Step 2: Edit `crates/relay/Cargo.toml`**

In `[dependencies]`, after the `jsonwebtoken` line, add:

```toml
p256 = { workspace = true }
```

The `p256` entry in `[dev-dependencies]` at the bottom of the file remains as-is (it's harmless to have it in both; dev-deps inherit from deps).

**Step 3: Verify compilation**

```bash
cargo build -p relay
```

Expected: compiles without errors. The `pkcs8` feature makes `p256::pkcs8::EncodePrivateKey` trait available.

**Step 4: Commit**

```bash
git add Cargo.toml crates/relay/Cargo.toml
git commit -m "build(relay): add p256 pkcs8 feature + move to production dependencies"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add DB functions for oauth_signing_key table

**Files:**
- Modify: `crates/relay/src/db/oauth.rs`

Add `OAuthSigningKeyRow`, `get_oauth_signing_key`, and `store_oauth_signing_key` to `db/oauth.rs`. Append them after the existing `get_single_account_did` function, before the `#[cfg(test)]` block.

**Step 1: Append to `crates/relay/src/db/oauth.rs`**

Find the line `pub async fn get_single_account_did...` block and append after it (before `#[cfg(test)]`):

```rust
/// A row from the `oauth_signing_key` table.
pub struct OAuthSigningKeyRow {
    pub id: String,
    pub public_key_jwk: String,
    pub private_key_encrypted: String,
}

/// Load the server's OAuth signing key row. Returns `None` if no key has been generated yet.
pub async fn get_oauth_signing_key(
    pool: &SqlitePool,
) -> Result<Option<OAuthSigningKeyRow>, sqlx::Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key_jwk, private_key_encrypted FROM oauth_signing_key LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(id, public_key_jwk, private_key_encrypted)| OAuthSigningKeyRow {
        id,
        public_key_jwk,
        private_key_encrypted,
    }))
}

/// Persist a newly generated OAuth signing key.
///
/// `id` is a UUID string. `public_key_jwk` is a JWK JSON string for the P-256 public key.
/// `private_key_encrypted` is the AES-256-GCM-encrypted private key (base64, 80 chars).
pub async fn store_oauth_signing_key(
    pool: &SqlitePool,
    id: &str,
    public_key_jwk: &str,
    private_key_encrypted: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_signing_key (id, public_key_jwk, private_key_encrypted, created_at) \
         VALUES (?, ?, ?, datetime('now'))",
    )
    .bind(id)
    .bind(public_key_jwk)
    .bind(private_key_encrypted)
    .execute(pool)
    .await?;
    Ok(())
}
```

**Step 2: Add tests for the new DB functions**

In the `#[cfg(test)]` block at the bottom of `db/oauth.rs`, add:

```rust
    #[tokio::test]
    async fn store_and_retrieve_oauth_signing_key() {
        let pool = test_pool().await;
        store_oauth_signing_key(
            &pool,
            "test-key-uuid-01",
            r#"{"kty":"EC","crv":"P-256","x":"abc","y":"def","kid":"test-key-uuid-01"}"#,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .await
        .unwrap();

        let row = get_oauth_signing_key(&pool)
            .await
            .unwrap()
            .expect("key should exist after storage");

        assert_eq!(row.id, "test-key-uuid-01");
        assert!(!row.public_key_jwk.is_empty());
        assert!(!row.private_key_encrypted.is_empty());
    }

    #[tokio::test]
    async fn get_oauth_signing_key_returns_none_when_empty() {
        let pool = test_pool().await;
        let result = get_oauth_signing_key(&pool).await.unwrap();
        assert!(result.is_none());
    }
```

**Step 3: Run tests**

```bash
cargo test -p relay db::oauth
```

Expected: all tests pass including the two new ones.

**Step 4: Commit**

```bash
git add crates/relay/src/db/oauth.rs
git commit -m "feat(db): add oauth_signing_key DB functions"
```
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-5) -->

<!-- START_TASK_3 -->
### Task 3: Add OAuthSigningKey type and load_or_create function

**Files:**
- Modify: `crates/relay/src/auth/mod.rs`

Add the `OAuthSigningKey` struct and `load_or_create_oauth_signing_key` function. Insert after the existing imports at the top of `auth/mod.rs` (after line 12: `use crate::app::AppState;`).

**Step 1: Add imports and type**

After the existing imports block in `auth/mod.rs`, add:

```rust
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use rand_core::RngCore;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

/// The server's persistent ES256 signing keypair, held in `AppState`.
///
/// `encoding_key` is derived from the P-256 private key in PKCS#8 DER format, as required by
/// `jsonwebtoken`. `key_id` is a UUID that appears as the `kid` header in issued access tokens.
#[derive(Clone)]
pub struct OAuthSigningKey {
    /// UUID identifier embedded in JWT `kid` header.
    pub key_id: String,
    /// PKCS#8 DER ES256 encoding key for JWT signing.
    pub encoding_key: jsonwebtoken::EncodingKey,
}

/// In-memory store for server-issued DPoP nonces.
///
/// Maps nonce string → expiry `Instant`. Protected by a `Mutex` so handlers can issue,
/// validate, and prune concurrently. Held in `AppState`.
pub type DpopNonceStore = Arc<Mutex<HashMap<String, Instant>>>;

/// Create an empty `DpopNonceStore`.
pub fn new_nonce_store() -> DpopNonceStore {
    Arc::new(Mutex::new(HashMap::new()))
}
```

**Step 2: Add load_or_create_oauth_signing_key**

After the `new_nonce_store` function, add:

```rust
/// Load the OAuth signing key from the database, or generate a new one on first boot.
///
/// If `master_key` is `None`, generates an ephemeral (non-persistent) key and logs a warning.
/// Ephemeral keys are not stored in the DB and invalidate all issued tokens on restart.
pub(crate) async fn load_or_create_oauth_signing_key(
    pool: &SqlitePool,
    master_key: Option<&[u8; 32]>,
) -> anyhow::Result<OAuthSigningKey> {
    use crate::db::oauth::{get_oauth_signing_key, store_oauth_signing_key};

    // Attempt to load an existing key.
    if let Some(row) = get_oauth_signing_key(pool).await? {
        let key = decode_oauth_signing_key(&row.id, &row.private_key_encrypted, master_key)?;
        tracing::info!(key_id = %row.id, "OAuth signing key loaded from database");
        return Ok(key);
    }

    // No key stored yet. Generate one.
    let keypair = crypto::generate_p256_keypair()
        .map_err(|e| anyhow::anyhow!("failed to generate P-256 keypair: {e}"))?;

    let key_id = Uuid::new_v4().to_string();

    // Build JWK for the public key (uncompressed EC point → x, y coordinates).
    let signing_key = p256::ecdsa::SigningKey::from_bytes(
        p256::FieldBytes::from_slice(keypair.private_key_bytes.as_ref()),
    )
    .map_err(|e| anyhow::anyhow!("invalid P-256 private key bytes: {e}"))?;

    let vk = signing_key.verifying_key();
    let point = vk.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate"));
    let public_key_jwk = serde_json::to_string(&serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": key_id,
    }))
    .map_err(|e| anyhow::anyhow!("JWK serialization failed: {e}"))?;

    match master_key {
        Some(key) => {
            let encrypted =
                crypto::encrypt_private_key(keypair.private_key_bytes.as_ref(), key)
                    .map_err(|e| anyhow::anyhow!("key encryption failed: {e}"))?;
            store_oauth_signing_key(pool, &key_id, &public_key_jwk, &encrypted).await?;
            tracing::info!(key_id = %key_id, "OAuth signing key generated and persisted");
        }
        None => {
            tracing::warn!(
                "signing_key_master_key not configured; \
                 OAuth signing key is ephemeral — tokens will be invalidated on restart"
            );
        }
    }

    let encoding_key = build_encoding_key(&signing_key)?;
    Ok(OAuthSigningKey { key_id, encoding_key })
}

/// Decode a stored OAuth signing key row into an `OAuthSigningKey`.
fn decode_oauth_signing_key(
    key_id: &str,
    private_key_encrypted: &str,
    master_key: Option<&[u8; 32]>,
) -> anyhow::Result<OAuthSigningKey> {
    let master_key = master_key.ok_or_else(|| {
        anyhow::anyhow!(
            "signing_key_master_key not configured but an OAuth signing key exists in the DB; \
             cannot decrypt it — set signing_key_master_key in config"
        )
    })?;

    let raw_bytes = crypto::decrypt_private_key(private_key_encrypted, master_key)
        .map_err(|e| anyhow::anyhow!("failed to decrypt OAuth signing key: {e}"))?;

    let signing_key = p256::ecdsa::SigningKey::from_bytes(
        p256::FieldBytes::from_slice(raw_bytes.as_ref()),
    )
    .map_err(|e| anyhow::anyhow!("invalid stored P-256 private key: {e}"))?;

    let encoding_key = build_encoding_key(&signing_key)?;
    Ok(OAuthSigningKey {
        key_id: key_id.to_string(),
        encoding_key,
    })
}

/// Convert a `p256::ecdsa::SigningKey` to a `jsonwebtoken::EncodingKey` via PKCS#8 DER.
fn build_encoding_key(
    signing_key: &p256::ecdsa::SigningKey,
) -> anyhow::Result<jsonwebtoken::EncodingKey> {
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| anyhow::anyhow!("PKCS#8 DER encoding failed: {e}"))?;
    jsonwebtoken::EncodingKey::from_ec_der(pkcs8_der.as_bytes())
        .map_err(|e| anyhow::anyhow!("jsonwebtoken EncodingKey construction failed: {e}"))
}
```

**Step 3: Run tests**

```bash
cargo test -p relay
```

Expected: compiles and all tests pass.

**Step 4: Commit**

```bash
git add crates/relay/src/auth/mod.rs
git commit -m "feat(auth): OAuthSigningKey type + load_or_create_oauth_signing_key"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Add oauth_signing_keypair to AppState and test_state

**Verifies:** MM-77.AC6.1, MM-77.AC6.2

**Files:**
- Modify: `crates/relay/src/app.rs`

Add `oauth_signing_keypair: OAuthSigningKey` and `dpop_nonces: DpopNonceStore` to `AppState`. Update `test_state_with_plc_url` to initialize both fields. Also import the new types.

**Step 1: Edit `AppState` struct in `app.rs`**

In the imports at the top of `app.rs`, add:

```rust
use crate::auth::{new_nonce_store, DpopNonceStore, OAuthSigningKey};
```

In the `AppState` struct (after the `jwt_secret` field), add:

```rust
    /// Persistent ES256 keypair for signing OAuth access tokens.
    /// Loaded at startup from `oauth_signing_key` table (or generated + stored on first boot).
    pub oauth_signing_keypair: OAuthSigningKey,
    /// In-memory store for server-issued DPoP nonces. Shared across all token endpoint requests.
    pub dpop_nonces: DpopNonceStore,
```

**Step 2: Update `test_state_with_plc_url`**

In the `#[cfg(test)]` section of `app.rs`, add to the imports at the top of `test_state_with_plc_url`:

```rust
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
```

And add this block before the `AppState { ... }` return:

```rust
    // Generate a fresh ephemeral P-256 keypair for tests (no DB persistence needed).
    let test_signing_key = {
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let pkcs8 = sk.to_pkcs8_der().expect("PKCS#8 encoding must succeed for test key");
        OAuthSigningKey {
            key_id: "test-oauth-key-01".to_string(),
            encoding_key: jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_bytes())
                .expect("EncodingKey from test PKCS#8 must succeed"),
        }
    };
    let dpop_nonces = new_nonce_store();
```

Add both to the `AppState { ... }` constructor:

```rust
        oauth_signing_keypair: test_signing_key,
        dpop_nonces,
```

**Step 3: Update `test_state_with_keys` in `create_signing_key.rs`**

The `test_state_with_keys` helper in `crates/relay/src/routes/create_signing_key.rs` constructs `AppState` directly. It will fail to compile until it includes the two new fields. Update it to pass the fields through from `base`:

Find the `AppState { ... }` block inside `test_state_with_keys` and add:

```rust
            oauth_signing_keypair: base.oauth_signing_keypair,
            dpop_nonces: base.dpop_nonces,
```

Do the same for the manual `AppState` construction in the `missing_master_key_returns_503` test in the same file.

**Step 4: Run tests**

```bash
cargo test -p relay
```

Expected: all tests compile and pass.

**Step 5: Commit**

```bash
git add crates/relay/src/app.rs crates/relay/src/routes/create_signing_key.rs
git commit -m "feat(app): add oauth_signing_keypair and dpop_nonces to AppState"
```
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Wire signing key loading into main.rs startup

**Verifies:** MM-77.AC6.1, MM-77.AC6.2

**Files:**
- Modify: `crates/relay/src/main.rs`

Call `auth::load_or_create_oauth_signing_key` after `run_migrations` and before constructing `AppState`.

**Step 1: Edit `main.rs` `run()` function**

After the `db::run_migrations(&pool)` block (around line 91–103 in `main.rs`), add:

```rust
    let oauth_signing_keypair =
        auth::load_or_create_oauth_signing_key(
            &pool,
            config.signing_key_master_key.as_ref().map(|s| &*s.0),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "fatal: failed to load OAuth signing key");
            e
        })
        .with_context(|| "failed to load or create OAuth signing keypair")?;
```

**Step 2: Update the `AppState { ... }` constructor**

Find the `let state = app::AppState { ... };` block (around line 132–140) and add the two new fields:

```rust
        oauth_signing_keypair,
        dpop_nonces: auth::new_nonce_store(),
```

**Step 3: Build the binary**

```bash
cargo build -p relay
```

Expected: compiles without errors or warnings.

**Step 4: Run all tests**

```bash
cargo test -p relay
```

Expected: all tests pass.

**Step 5: Commit**

```bash
git add crates/relay/src/main.rs
git commit -m "feat(relay): load OAuth signing key at startup and wire into AppState"
```
<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_B -->
