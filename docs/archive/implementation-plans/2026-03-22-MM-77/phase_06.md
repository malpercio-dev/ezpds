# OAuth Token Endpoint — Phase 6: Refresh Token Grant and Rotation

**Goal:** Implement the `refresh_token` grant with single-use rotation and DPoP key binding verification.

**Architecture:** New `RefreshTokenRow` struct and `consume_oauth_refresh_token` function in `db/oauth.rs`. New `handle_refresh_token` function in `routes/oauth_token.rs` replacing the Phase 4 stub. Integration tests covering AC4.1–AC4.5 appended to the existing test module from Phase 5.

**Tech Stack:** `sqlx` transactions (atomic token consume, same pattern as `consume_authorization_code`), `jsonwebtoken`/`sha2`/`base64` (already imported from Phase 5).

**Scope:** Phase 6 of 6

**Codebase verified:** 2026-03-22

---

## Acceptance Criteria Coverage

### MM-77.AC4: Refresh token rotation
- **MM-77.AC4.1 Success:** Valid refresh token + DPoP proof → 200 with new `access_token` and new `refresh_token`
- **MM-77.AC4.2 Success:** Old refresh token row deleted after rotation; second use → 400 `invalid_grant`
- **MM-77.AC4.3 Failure:** Expired refresh token (>24h) → 400 `invalid_grant`
- **MM-77.AC4.4 Failure:** DPoP key thumbprint mismatch → 400 `invalid_grant`
- **MM-77.AC4.5 Failure:** `client_id` mismatch on refresh → 400 `invalid_grant`

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: DB function — consume_oauth_refresh_token

**Files:**
- Modify: `crates/relay/src/db/oauth.rs`

**Step 1: Add RefreshTokenRow and consume_oauth_refresh_token**

Append to `db/oauth.rs` (before the `#[cfg(test)]` block):

```rust
/// A row read from `oauth_tokens` during refresh token rotation.
pub struct RefreshTokenRow {
    pub client_id: String,
    pub did: String,
    pub scope: String,
    /// DPoP key thumbprint bound to this refresh token. `None` for tokens
    /// issued before DPoP binding was enforced (not expected after V012).
    pub jkt: Option<String>,
}

/// Atomically consume a refresh token: SELECT + DELETE in one transaction.
///
/// Returns `None` if the token does not exist or has already expired
/// (`expires_at <= now`). Callers must treat `None` as `invalid_grant`.
///
/// The `id` column stores the SHA-256 hex hash of the raw token bytes.
/// Callers must hash the presented token before calling this function
/// using the same approach as `store_oauth_refresh_token`.
pub async fn consume_oauth_refresh_token(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT client_id, did, scope, jkt FROM oauth_tokens \
         WHERE id = ? AND expires_at > datetime('now')",
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;

    if row.is_some() {
        sqlx::query("DELETE FROM oauth_tokens WHERE id = ?")
            .bind(token_hash)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    Ok(row.map(|(client_id, did, scope, jkt)| RefreshTokenRow {
        client_id,
        did,
        scope,
        jkt,
    }))
}
```

**Step 2: Add DB tests**

In the `#[cfg(test)]` block of `db/oauth.rs`, append after the existing Phase 5 tests:

```rust
    #[tokio::test]
    async fn consume_oauth_refresh_token_returns_row_and_deletes_it() {
        // AC4.2: consumed token must not be found again.
        let pool = test_pool().await;
        register_oauth_client(
            &pool,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        store_oauth_refresh_token(
            &pool,
            "consume-test-token-hash",
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            "test-jkt-thumbprint",
        )
        .await
        .unwrap();

        let row = consume_oauth_refresh_token(&pool, "consume-test-token-hash")
            .await
            .unwrap()
            .expect("token must be found on first use");

        assert_eq!(row.client_id, "https://app.example.com/client-metadata.json");
        assert_eq!(row.scope, "com.atproto.refresh");
        assert_eq!(row.jkt.as_deref(), Some("test-jkt-thumbprint"));

        // Second consume must return None (already deleted) — AC4.2.
        let second = consume_oauth_refresh_token(&pool, "consume-test-token-hash")
            .await
            .unwrap();
        assert!(second.is_none(), "consumed token must not be found again (AC4.2)");
    }

    #[tokio::test]
    async fn consume_oauth_refresh_token_returns_none_for_expired_token() {
        // AC4.3: expired tokens are rejected.
        let pool = test_pool().await;
        register_oauth_client(
            &pool,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Insert an already-expired row directly (bypassing store_oauth_refresh_token's +24h default).
        sqlx::query(
            "INSERT INTO oauth_tokens (id, client_id, did, scope, jkt, expires_at, created_at) \
             VALUES (?, ?, ?, 'com.atproto.refresh', ?, datetime('now', '-1 seconds'), datetime('now'))",
        )
        .bind("expired-hash")
        .bind("https://app.example.com/client-metadata.json")
        .bind("did:plc:testaccount000000000000")
        .bind("test-jkt")
        .execute(&pool)
        .await
        .unwrap();

        let result = consume_oauth_refresh_token(&pool, "expired-hash")
            .await
            .unwrap();
        assert!(result.is_none(), "expired refresh token must return None (AC4.3)");
    }

    #[tokio::test]
    async fn consume_oauth_refresh_token_returns_none_for_unknown_token() {
        let pool = test_pool().await;
        let result = consume_oauth_refresh_token(&pool, "nonexistent-hash").await.unwrap();
        assert!(result.is_none());
    }
```

**Step 3: Run DB tests**

```bash
cargo test -p relay db::oauth
```

Expected: all tests pass including the three new `consume_oauth_refresh_token` tests.

**Step 4: Commit**

```bash
git add crates/relay/src/db/oauth.rs
git commit -m "feat(db): consume_oauth_refresh_token + RefreshTokenRow"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement refresh_token grant in handler

**Files:**
- Modify: `crates/relay/src/routes/oauth_token.rs`

**Step 1: Add consume_oauth_refresh_token to the db::oauth import**

In `oauth_token.rs`, find the existing import line:

```rust
use crate::db::oauth::{consume_authorization_code, store_oauth_refresh_token};
```

Replace with:

```rust
use crate::db::oauth::{
    consume_authorization_code, consume_oauth_refresh_token, store_oauth_refresh_token,
};
```

**Step 2: Add handle_refresh_token function**

Append after `handle_authorization_code` (before the `#[cfg(test)]` block):

```rust
async fn handle_refresh_token(
    state: &AppState,
    headers: &HeaderMap,
    form: TokenRequestForm,
) -> Response {
    // Prune stale nonces on every request.
    cleanup_expired_nonces(&state.dpop_nonces).await;

    // Required fields.
    let refresh_token_plaintext = match form.refresh_token.as_deref() {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: refresh_token")
                .into_response();
        }
    };
    let client_id = match form.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            return OAuthTokenError::new("invalid_request", "missing parameter: client_id")
                .into_response();
        }
    };

    // Validate DPoP proof — must be present, structurally valid, and carry a valid server nonce.
    let dpop_token = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => {
            return OAuthTokenError::new("invalid_dpop_proof", "DPoP header required")
                .into_response();
        }
    };

    let token_url = format!(
        "{}/oauth/token",
        state.config.public_url.trim_end_matches('/')
    );

    let jkt = match validate_dpop_for_token_endpoint(
        &dpop_token,
        "POST",
        &token_url,
        &state.dpop_nonces,
    )
    .await
    {
        Ok(jkt) => jkt,
        Err(DpopTokenEndpointError::MissingHeader) => {
            return OAuthTokenError::new("invalid_dpop_proof", "DPoP header required")
                .into_response();
        }
        Err(DpopTokenEndpointError::InvalidProof(msg)) => {
            return OAuthTokenError::new("invalid_dpop_proof", msg).into_response();
        }
        Err(DpopTokenEndpointError::UseNonce(fresh_nonce)) => {
            return OAuthTokenError::with_nonce(
                "use_dpop_nonce",
                "DPoP nonce required",
                fresh_nonce,
            )
            .into_response();
        }
    };

    // Hash the presented refresh token for DB lookup.
    let token_hash = crate::routes::token::sha256_hex(
        &URL_SAFE_NO_PAD
            .decode(refresh_token_plaintext.as_str())
            .unwrap_or_else(|_| refresh_token_plaintext.as_bytes().to_vec()),
    );

    // Atomically consume the refresh token (SELECT + DELETE).
    let stored = match consume_oauth_refresh_token(&state.db, &token_hash).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return OAuthTokenError::new("invalid_grant", "refresh token not found or expired")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to consume refresh token");
            return OAuthTokenError::new("server_error", "database error").into_response();
        }
    };

    // Verify client_id matches the stored value.
    if stored.client_id != client_id {
        return OAuthTokenError::new("invalid_grant", "client_id mismatch").into_response();
    }

    // DPoP binding check: if the refresh token was bound to a specific key, the same key must be used.
    if let Some(ref stored_jkt) = stored.jkt {
        if *stored_jkt != jkt {
            return OAuthTokenError::new("invalid_grant", "DPoP key mismatch").into_response();
        }
    }

    // Issue new ES256 access token.
    let access_token =
        match issue_access_token(&state.oauth_signing_keypair, &stored.did, &stored.scope, &jkt) {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };

    // Generate and store new refresh token (rotation: old token already deleted above).
    let new_refresh = generate_token();
    if let Err(e) = store_oauth_refresh_token(
        &state.db,
        &new_refresh.hash,
        &stored.client_id,
        &stored.did,
        &jkt,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store rotated refresh token");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    // Issue fresh DPoP nonce for the next request.
    let fresh_nonce = issue_nonce(&state.dpop_nonces).await;

    let mut response_headers = axum::http::HeaderMap::new();
    response_headers.insert("DPoP-Nonce", fresh_nonce.parse().unwrap());

    (
        StatusCode::OK,
        response_headers,
        Json(TokenResponse {
            access_token,
            token_type: "DPoP",
            expires_in: 300,
            refresh_token: new_refresh.plaintext,
            scope: stored.scope,
        }),
    )
        .into_response()
}
```

**Step 3: Replace the refresh_token stub arm in post_token**

Replace the `"refresh_token"` stub match arm:

```rust
        "refresh_token" => {
            handle_refresh_token(&state, &headers, form).await
        }
```

**Step 4: Compile**

```bash
cargo build -p relay
```

Expected: compiles without errors.

**Step 5: Commit**

```bash
git add crates/relay/src/routes/oauth_token.rs
git commit -m "feat(relay): refresh_token grant — rotation, DPoP binding check"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Integration tests for refresh_token grant

**Verifies:** MM-77.AC4.1, MM-77.AC4.2, MM-77.AC4.3, MM-77.AC4.4, MM-77.AC4.5

**Files:**
- Modify: `crates/relay/src/routes/oauth_token.rs` (`#[cfg(test)]` block)

The test module in `routes/oauth_token.rs` already contains all DPoP proof helpers (`dpop_key_to_jwk`, `dpop_thumbprint`, `make_dpop_proof`, `post_token_with_dpop`, `json_body`, `now_secs`) from Phase 5. This task appends helpers and tests for the refresh_token grant to the end of that module.

**Step 1: Add generate_token to the test module's imports**

Find the existing import block in the `mod tests { ... }` block:

```rust
    use crate::db::oauth::{register_oauth_client, store_authorization_code};
```

Replace with:

```rust
    use crate::db::oauth::{register_oauth_client, store_authorization_code, store_oauth_refresh_token};
    use crate::routes::token::generate_token;
```

**Step 2: Append seed helpers and AC4 tests inside the test module**

Append inside the `mod tests { ... }` block, after the last test:

```rust
    // ── AC4 — refresh_token grant ─────────────────────────────────────────────

    /// Seed the DB with a client + account + fresh refresh token bound to `jkt`.
    ///
    /// Returns the base64url plaintext of the seeded refresh token.
    async fn seed_refresh_token(state: &AppState, jkt: &str) -> String {
        register_oauth_client(
            &state.db,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let token = generate_token();
        store_oauth_refresh_token(
            &state.db,
            &token.hash,
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            jkt,
        )
        .await
        .unwrap();
        token.plaintext
    }

    /// Seed the DB with an already-expired refresh token (bypasses store_oauth_refresh_token's +24h).
    ///
    /// Returns the base64url plaintext.
    async fn seed_expired_refresh_token(state: &AppState, jkt: &str) -> String {
        register_oauth_client(
            &state.db,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let token = generate_token();
        sqlx::query(
            "INSERT INTO oauth_tokens (id, client_id, did, scope, jkt, expires_at, created_at) \
             VALUES (?, ?, ?, 'com.atproto.refresh', ?, datetime('now', '-1 seconds'), datetime('now'))",
        )
        .bind(&token.hash)
        .bind("https://app.example.com/client-metadata.json")
        .bind("did:plc:testaccount000000000000")
        .bind(jkt)
        .execute(&state.db)
        .await
        .unwrap();
        token.plaintext
    }

    #[tokio::test]
    async fn refresh_token_happy_path_returns_200_with_new_tokens() {
        // AC4.1 — valid rotation returns 200 with fresh token pair.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "valid rotation must return 200");
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "success response must include DPoP-Nonce header"
        );

        let json = json_body(resp).await;
        assert!(json["access_token"].is_string(), "access_token must be present");
        assert_eq!(json["token_type"], "DPoP");
        assert_eq!(json["expires_in"], 300);
        assert!(json["refresh_token"].is_string(), "rotated refresh_token must be present");

        // Rotated token must differ from the original.
        let new_rt = json["refresh_token"].as_str().unwrap();
        assert_ne!(
            new_rt, plaintext.as_str(),
            "rotated refresh token must differ from original"
        );
    }

    #[tokio::test]
    async fn refresh_token_second_use_returns_invalid_grant() {
        // AC4.2 — after rotation the original token is deleted; second use must fail.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;
        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        // First use: succeeds. Clone state so the second request shares the same DB.
        let nonce1 = issue_nonce(&state.dpop_nonces).await;
        let dpop1 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce1),
            now_secs(),
        );
        let first_resp = app(state.clone())
            .oneshot(post_token_with_dpop(&body, &dpop1))
            .await
            .unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK, "first use must succeed");

        // Second use of the same original token: must return invalid_grant.
        let nonce2 = issue_nonce(&state.dpop_nonces).await;
        let dpop2 = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce2),
            now_secs(),
        );
        let resp2 = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop2))
            .await
            .unwrap();

        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST, "second use must return 400");
        let json = json_body(resp2).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "second use of consumed token must return invalid_grant (AC4.2)"
        );
    }

    #[tokio::test]
    async fn refresh_token_expired_returns_invalid_grant() {
        // AC4.3 — expired refresh tokens are rejected.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_expired_refresh_token(&state, &jkt).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "expired refresh token must return invalid_grant (AC4.3)"
        );
    }

    #[tokio::test]
    async fn refresh_token_jkt_mismatch_returns_invalid_grant() {
        // AC4.4 — DPoP key in proof must match the thumbprint bound to the refresh token.
        let state = test_state().await;
        let stored_key = SigningKey::random(&mut OsRng);
        let stored_jkt = dpop_thumbprint(&stored_key);

        // Seed token bound to stored_key's thumbprint.
        let plaintext = seed_refresh_token(&state, &stored_jkt).await;

        // Build proof with a DIFFERENT key — thumbprint will not match stored_jkt.
        let different_key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &different_key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "DPoP key mismatch must return invalid_grant (AC4.4)"
        );
    }

    #[tokio::test]
    async fn refresh_token_client_id_mismatch_returns_invalid_grant() {
        // AC4.5 — client_id in the request must match the stored client_id.
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let jkt = dpop_thumbprint(&key);

        let plaintext = seed_refresh_token(&state, &jkt).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        // Wrong client_id — does not match stored "https://app.example.com/client-metadata.json".
        let body = format!(
            "grant_type=refresh_token\
             &refresh_token={plaintext}\
             &client_id=https%3A%2F%2Fother.example.com%2Fclient-metadata.json"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"], "invalid_grant",
            "client_id mismatch must return invalid_grant (AC4.5)"
        );
    }
```

**Step 3: Run refresh_token tests**

```bash
cargo test -p relay routes::oauth_token
```

Expected: all tests pass including the five new AC4 tests.

**Step 4: Run full test suite**

```bash
cargo test -p relay
```

Expected: all tests pass.

**Step 5: Commit**

```bash
git add crates/relay/src/routes/oauth_token.rs
git commit -m "test(relay): refresh_token grant integration tests (AC4.1–AC4.5)"
```
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
