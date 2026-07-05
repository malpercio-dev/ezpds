# MM-146 DID Ceremony Implementation Plan

**Goal:** Expose the relay's active signing key as a public `GET /v1/relay/keys` endpoint.

**Architecture:** Single axum GET handler that queries `relay_signing_keys ORDER BY created_at DESC LIMIT 1`. Returns the most-recently-created key as `{ keyId, publicKey, algorithm }`, or 503 if no key is provisioned. No authentication required — this is a public endpoint.

**Tech Stack:** Rust, axum, sqlx (SQLite), serde_json, Bruno

**Scope:** Phase 1 of 4 from the MM-146 design plan.

**Codebase verified:** 2026-03-20

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-146.AC1: GET /v1/relay/keys returns active signing key
- **MM-146.AC1.1 Success:** Returns 200 with `{ keyId, publicKey, algorithm }` when a signing key is provisioned
- **MM-146.AC1.2 Success:** Returns the most recently created key when multiple keys exist
- **MM-146.AC1.3 Failure:** Returns 503 when no signing key is provisioned
- **MM-146.AC1.4 Success:** Endpoint requires no authentication (public, no Bearer token needed)

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Create get_relay_signing_key.rs handler

**Files:**
- Create: `crates/relay/src/routes/get_relay_signing_key.rs`

**Implementation:**

Create the file with the response struct and handler. The handler performs a single `SELECT ... ORDER BY created_at DESC LIMIT 1` query and returns 503 if no row exists.

```rust
// pattern: Imperative Shell
//
// Gathers: DB pool (via AppState)
// Processes: SELECT most recently created signing key
// Returns: JSON { keyId, publicKey, algorithm } on success; 503 if no key provisioned

use axum::{extract::State, response::Json};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;

// Response uses camelCase per JSON API convention (keyId, publicKey).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRelaySigningKeyResponse {
    key_id: String,
    public_key: String,
    algorithm: String,
}

pub async fn get_relay_signing_key(
    State(state): State<AppState>,
) -> Result<Json<GetRelaySigningKeyResponse>, ApiError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key, algorithm \
         FROM relay_signing_keys \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query relay signing key");
        ApiError::new(ErrorCode::InternalError, "failed to query signing key")
    })?;

    let (id, public_key, algorithm) = row.ok_or_else(|| {
        ApiError::new(ErrorCode::ServiceUnavailable, "no signing key provisioned")
    })?;

    Ok(Json(GetRelaySigningKeyResponse {
        key_id: id,
        public_key,
        algorithm,
    }))
}
```

**Note:** Do not add a `#[cfg(test)]` block yet — that comes in Task 3.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Wire module and route registration

**Files:**
- Modify: `crates/relay/src/routes/mod.rs` — add `pub mod get_relay_signing_key;` after line 7 (`pub mod create_signing_key;`)
- Modify: `crates/relay/src/app.rs` — add import + update route registration on line 122

**mod.rs change** — add one line after the `create_signing_key` module declaration:

```rust
pub mod create_signing_key;
pub mod get_relay_signing_key;  // add this line
```

**app.rs changes:**

Add a use import after line 21 (`use crate::routes::create_signing_key::create_signing_key;`):

```rust
use crate::routes::get_relay_signing_key::get_relay_signing_key;
```

Update line 122 — change the relay keys route from POST-only to GET+POST:

```rust
// Before:
.route("/v1/relay/keys", post(create_signing_key))

// After:
.route("/v1/relay/keys", get(get_relay_signing_key).post(create_signing_key))
```

**Verification:**

Run: `cargo build -p relay`
Expected: Compiles without errors or warnings.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Integration tests

**Verifies:** MM-146.AC1.1, MM-146.AC1.2, MM-146.AC1.3, MM-146.AC1.4

**Files:**
- Modify: `crates/relay/src/routes/get_relay_signing_key.rs` — append `#[cfg(test)] mod tests` block

**Testing:**

Tests must verify each AC listed above. All tests use `test_state()` from `crate::app` (in-memory SQLite DB). Add a `insert_test_key` helper and a `get_keys` request builder inside the test module.

Append to `get_relay_signing_key.rs`:

```rust
#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};

    /// Insert a signing key row directly into the test DB.
    /// `created_at` is an ISO 8601 UTC string, e.g. `"2026-01-01T00:00:00"`.
    ///
    /// `private_key_encrypted` is a NOT NULL column, but the GET handler never reads it,
    /// so any valid base64 value satisfies the constraint. The real format is
    /// base64(nonce(12) || ciphertext(32) || tag(16)) = 80 base64 chars. The 84-char
    /// placeholder below (60 zero-bytes base64-encoded + padding) is intentionally a
    /// dummy — replace with a correct 80-char value if a test ever needs to read
    /// private_key_encrypted back.
    async fn insert_test_key(db: &sqlx::SqlitePool, key_id: &str, created_at: &str) {
        sqlx::query(
            "INSERT INTO relay_signing_keys \
             (id, algorithm, public_key, private_key_encrypted, created_at) \
             VALUES (?, 'p256', 'zTestPublicKey123', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==', ?)",
        )
        .bind(key_id)
        .bind(created_at)
        .execute(db)
        .await
        .unwrap();
    }

    /// Build a GET /v1/relay/keys request with no Authorization header (public endpoint).
    fn get_keys() -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/v1/relay/keys")
            .body(Body::empty())
            .unwrap()
    }

    // MM-146.AC1.3: Returns 503 when no signing key is provisioned.
    #[tokio::test]
    async fn get_relay_keys_returns_503_when_no_key_provisioned() {
        let response = app(test_state().await)
            .oneshot(get_keys())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // MM-146.AC1.1: Returns 200 with { keyId, publicKey, algorithm } when a key is provisioned.
    #[tokio::test]
    async fn get_relay_keys_returns_200_with_active_key() {
        let state = test_state().await;
        insert_test_key(&state.db, "did:key:zTestKey1", "2026-01-01T00:00:00").await;

        let response = app(state).oneshot(get_keys()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["keyId"], "did:key:zTestKey1");
        assert_eq!(json["algorithm"], "p256");
        assert!(json["publicKey"].is_string(), "publicKey must be present");
    }

    // MM-146.AC1.2: Returns the most recently created key when multiple keys exist.
    #[tokio::test]
    async fn get_relay_keys_returns_most_recently_created_key() {
        let state = test_state().await;
        insert_test_key(&state.db, "did:key:zOlderKey", "2026-01-01T00:00:00").await;
        insert_test_key(&state.db, "did:key:zNewerKey", "2026-01-02T00:00:00").await;

        let response = app(state).oneshot(get_keys()).await.unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["keyId"], "did:key:zNewerKey",
            "must return the key with the most recent created_at"
        );
    }

    // MM-146.AC1.4: Endpoint requires no authentication.
    #[tokio::test]
    async fn get_relay_keys_requires_no_authentication() {
        // test_state() has no admin_token configured.
        // get_keys() sends no Authorization header.
        // If the endpoint incorrectly required auth, this would return 401 instead of 200.
        let state = test_state().await;
        insert_test_key(&state.db, "did:key:zPublicKey", "2026-01-01T00:00:00").await;

        let response = app(state).oneshot(get_keys()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
```

**Verification:**

Run: `cargo test -p relay get_relay`
Expected: All 4 tests pass.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Add Bruno file and commit

**Verifies:** None (documentation artifact)

**Files:**
- Create: `bruno/get_relay_keys.bru`

**Implementation:**

```
meta {
  name: Get Relay Keys
  type: http
  seq: 11
}

get {
  url: {{baseUrl}}/v1/relay/keys
  body: none
  auth: none
}
```

**Commit:**

```bash
git add crates/relay/src/routes/get_relay_signing_key.rs \
        crates/relay/src/routes/mod.rs \
        crates/relay/src/app.rs \
        bruno/get_relay_keys.bru
git commit -m "feat(relay): add GET /v1/relay/keys endpoint to expose active signing key"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->
