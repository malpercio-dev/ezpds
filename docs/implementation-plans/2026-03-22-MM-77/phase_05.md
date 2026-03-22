# OAuth Token Endpoint — Phase 5: Authorization Code Exchange Grant

**Goal:** Implement the full `authorization_code` grant: DPoP validation with nonce, PKCE check, atomic code consumption, and ES256 JWT + refresh token issuance.

**Architecture:** New DB functions `consume_authorization_code` and `store_oauth_refresh_token` in `db/oauth.rs`. New `DpopTokenEndpointError` enum + `validate_dpop_for_token_endpoint` function + `nonce: Option<String>` field on `DPopClaims` in `auth/mod.rs`. Full `authorization_code` grant path in `routes/oauth_token.rs`.

**Tech Stack:** `sha2::Sha256` (PKCE S256), `base64::URL_SAFE_NO_PAD` (PKCE + JWK), `jsonwebtoken` (ES256 JWT), `sqlx` transactions (atomic code consume).

**Scope:** Phase 5 of 6

**Codebase verified:** 2026-03-22

---

## Acceptance Criteria Coverage

### MM-77.AC1: Authorization code exchange
- **MM-77.AC1.1 Success:** Valid code + code_verifier + DPoP proof with nonce → 200 with `access_token`, `token_type="DPoP"`, `expires_in=300`, `refresh_token`, `scope`
- **MM-77.AC1.2 Success:** Access token is ES256 JWT with `typ=at+jwt`, `cnf.jkt`, `exp=now+300s`
- **MM-77.AC1.3 Success:** Refresh token plaintext is 43-char base64url; stored row has `scope='com.atproto.refresh'`
- **MM-77.AC1.4 Failure:** Invalid `code_verifier` → 400 `invalid_grant`
- **MM-77.AC1.5 Failure:** Expired auth code (>60s) → 400 `invalid_grant`
- **MM-77.AC1.6 Failure:** Already-consumed code → 400 `invalid_grant`
- **MM-77.AC1.7 Failure:** `client_id` mismatch → 400 `invalid_grant`
- **MM-77.AC1.8 Failure:** `redirect_uri` mismatch → 400 `invalid_grant`

### MM-77.AC2: DPoP proof validation
- **MM-77.AC2.1 Success:** Valid DPoP proof accepted
- **MM-77.AC2.2 Success:** Access token `cnf.jkt` matches the DPoP proof's JWK thumbprint
- **MM-77.AC2.3 Failure:** Missing `DPoP:` header → 400 `invalid_dpop_proof`
- **MM-77.AC2.4 Failure:** Wrong `htm` → 400 `invalid_dpop_proof`
- **MM-77.AC2.5 Failure:** Wrong `htu` → 400 `invalid_dpop_proof`
- **MM-77.AC2.6 Failure:** Stale `iat` (>60s) → 400 `invalid_dpop_proof`

### MM-77.AC3: DPoP server nonces
- **MM-77.AC3.2 Failure:** No `nonce` claim → 400 `use_dpop_nonce` + `DPoP-Nonce:` header
- **MM-77.AC3.3 Failure:** Expired nonce → 400 `use_dpop_nonce` + fresh nonce header
- **MM-77.AC3.4 Failure:** Unknown nonce → 400 `use_dpop_nonce`
- **MM-77.AC3.5 Success:** Successful response includes fresh `DPoP-Nonce:` header

### MM-77.AC6: OAuth signing key
- **MM-77.AC6.3 Success:** Access tokens use ES256 signing, not HS256

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: DB functions — consume_authorization_code + store_oauth_refresh_token

**Files:**
- Modify: `crates/relay/src/db/oauth.rs`

**Step 1: Add AuthCodeRow struct and consume_authorization_code**

Append to `db/oauth.rs` (before the `#[cfg(test)]` block):

```rust
/// A row read from `oauth_authorization_codes` during code exchange.
pub struct AuthCodeRow {
    pub client_id: String,
    pub did: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub redirect_uri: String,
    pub scope: String,
}

/// Atomically consume an authorization code: SELECT + DELETE in one transaction.
///
/// Returns `None` if the code does not exist or has already expired (`expires_at <= now`).
/// Callers must treat `None` as `invalid_grant`.
///
/// The code column stores the SHA-256 hex hash of the raw code bytes. Callers must
/// hash the presented code before calling this function (use `routes::token::sha256_hex`).
pub async fn consume_authorization_code(
    pool: &SqlitePool,
    code_hash: &str,
) -> Result<Option<AuthCodeRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT client_id, did, code_challenge, code_challenge_method, redirect_uri, scope \
         FROM oauth_authorization_codes \
         WHERE code = ? AND expires_at > datetime('now')",
    )
    .bind(code_hash)
    .fetch_optional(&mut *tx)
    .await?;

    if row.is_some() {
        sqlx::query("DELETE FROM oauth_authorization_codes WHERE code = ?")
            .bind(code_hash)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    Ok(row.map(
        |(client_id, did, code_challenge, code_challenge_method, redirect_uri, scope)| {
            AuthCodeRow {
                client_id,
                did,
                code_challenge,
                code_challenge_method,
                redirect_uri,
                scope,
            }
        },
    ))
}

/// Store a new refresh token in `oauth_tokens`.
///
/// `token_hash` is used as the row's `id` (PRIMARY KEY). This follows the same
/// pattern as `oauth_authorization_codes` where `code` IS the hash.
/// `scope` is always `'com.atproto.refresh'` for OAuth refresh tokens.
/// `jkt` is the DPoP key thumbprint binding this token to the client's keypair.
/// Expires 24 hours after insertion.
pub async fn store_oauth_refresh_token(
    pool: &SqlitePool,
    token_hash: &str,
    client_id: &str,
    did: &str,
    jkt: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_tokens (id, client_id, did, scope, jkt, expires_at, created_at) \
         VALUES (?, ?, ?, 'com.atproto.refresh', ?, datetime('now', '+24 hours'), datetime('now'))",
    )
    .bind(token_hash)
    .bind(client_id)
    .bind(did)
    .bind(jkt)
    .execute(pool)
    .await?;
    Ok(())
}
```

**Step 2: Add DB tests**

In the `#[cfg(test)]` block of `db/oauth.rs`, add helper and tests:

```rust
    /// Insert an account row needed to satisfy oauth_tokens FK.
    async fn insert_test_account(pool: &SqlitePool) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:testaccount000000000000', 'test@example.com', NULL, \
             datetime('now'), datetime('now'))",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn consume_authorization_code_returns_row_and_deletes_it() {
        let pool = test_pool().await;
        register_oauth_client(
            &pool,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        insert_test_account(&pool).await;

        store_authorization_code(
            &pool,
            "hash-abc123",
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            "s256challenge",
            "S256",
            "https://app.example.com/callback",
            "atproto",
        )
        .await
        .unwrap();

        let row = consume_authorization_code(&pool, "hash-abc123")
            .await
            .unwrap()
            .expect("code should be found");

        assert_eq!(row.client_id, "https://app.example.com/client-metadata.json");
        assert_eq!(row.did, "did:plc:testaccount000000000000");

        // Second consume: must return None (already deleted).
        let second = consume_authorization_code(&pool, "hash-abc123").await.unwrap();
        assert!(second.is_none(), "consumed code must not be found again (AC1.6)");
    }

    #[tokio::test]
    async fn consume_authorization_code_returns_none_for_unknown_code() {
        let pool = test_pool().await;
        let result = consume_authorization_code(&pool, "nonexistent-hash").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn consume_authorization_code_returns_none_for_expired_code() {
        // AC1.5: expired auth codes (>60s) are rejected.
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

        // Insert an already-expired auth code directly (bypassing store_authorization_code's +60s default).
        sqlx::query(
            "INSERT INTO oauth_authorization_codes \
             (code, client_id, did, code_challenge, code_challenge_method, redirect_uri, scope, expires_at, created_at) \
             VALUES (?, ?, ?, ?, 'S256', ?, 'atproto', datetime('now', '-1 seconds'), datetime('now'))",
        )
        .bind("expired-code-hash")
        .bind("https://app.example.com/client-metadata.json")
        .bind("did:plc:testaccount000000000000")
        .bind("s256challenge")
        .bind("https://app.example.com/callback")
        .execute(&pool)
        .await
        .unwrap();

        let result = consume_authorization_code(&pool, "expired-code-hash")
            .await
            .unwrap();
        assert!(result.is_none(), "expired auth code must return None (AC1.5)");
    }

    #[tokio::test]
    async fn store_oauth_refresh_token_persists_row() {
        let pool = test_pool().await;
        register_oauth_client(
            &pool,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        insert_test_account(&pool).await;

        store_oauth_refresh_token(
            &pool,
            "refresh-token-hash-01",
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            "jkt-thumbprint",
        )
        .await
        .unwrap();

        let row: Option<(String, String, Option<String>)> =
            sqlx::query_as("SELECT id, scope, jkt FROM oauth_tokens WHERE id = ?")
                .bind("refresh-token-hash-01")
                .fetch_optional(&pool)
                .await
                .unwrap();

        let (id, scope, jkt) = row.expect("refresh token row must exist");
        assert_eq!(id, "refresh-token-hash-01");
        assert_eq!(scope, "com.atproto.refresh", "scope must be com.atproto.refresh (AC1.3)");
        assert_eq!(jkt.as_deref(), Some("jkt-thumbprint"));
    }
```

**Step 3: Run DB tests**

```bash
cargo test -p relay db::oauth
```

Expected: all tests pass.

**Step 4: Commit**

```bash
git add crates/relay/src/db/oauth.rs
git commit -m "feat(db): consume_authorization_code + store_oauth_refresh_token"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: DPoP validation for token endpoint

**Files:**
- Modify: `crates/relay/src/auth/mod.rs`

Add `nonce: Option<String>` to `DPopClaims` (backward-compatible — absent `nonce` deserializes to `None`). Add `DpopTokenEndpointError` enum. Add `validate_dpop_for_token_endpoint` function.

**Step 1: Add `nonce` to `DPopClaims`**

Find the `DPopClaims` struct (around line 88 in `auth/mod.rs`):

```rust
struct DPopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
}
```

Add the `nonce` field:

```rust
struct DPopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    /// Server-issued DPoP nonce (RFC 9449 §8). Required when the server has issued one.
    #[serde(default)]
    nonce: Option<String>,
}
```

**Step 2: Add DpopTokenEndpointError and validate_dpop_for_token_endpoint**

After the `build_encoding_key` function (added in Phase 2) and before the `#[cfg(test)]` block, add:

```rust
/// Error from DPoP validation at the token endpoint.
///
/// Converted to `OAuthTokenError` by the handler in `routes/oauth_token.rs`.
pub(crate) enum DpopTokenEndpointError {
    /// `DPoP:` header is absent.
    MissingHeader,
    /// DPoP proof is syntactically or semantically invalid.
    InvalidProof(&'static str),
    /// Nonce is missing, unknown, or expired — fresh nonce included for the response header.
    UseNonce(String),
}

/// Validate the DPoP proof at the token endpoint and return the JWK thumbprint.
///
/// This is a token-endpoint-specific variant of `validate_dpop`:
/// - Does NOT check `cnf.jkt` against an existing access token (no token yet).
/// - DOES validate the `nonce` claim against the nonce store.
/// - Returns the JWK thumbprint (jkt) so the handler can embed it in `cnf.jkt`.
///
/// `htm` must be `"POST"`. `htu` must be the token endpoint URL (e.g.
/// `"https://relay.example.com/oauth/token"`).
pub(crate) async fn validate_dpop_for_token_endpoint(
    dpop_token: &str,
    htm: &str,
    htu: &str,
    nonce_store: &DpopNonceStore,
) -> Result<String, DpopTokenEndpointError> {
    // Decode the DPoP proof header manually (same pattern as validate_dpop).
    let header_b64 = dpop_token
        .split('.')
        .next()
        .ok_or(DpopTokenEndpointError::InvalidProof("malformed DPoP JWT"))?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP header base64 invalid"))?;
    let dpop_header: DPopHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP header JSON malformed"))?;

    if dpop_header.typ != "dpop+jwt" {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP typ must be dpop+jwt"));
    }

    // Verify the signature against the embedded JWK.
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(dpop_header.jwk.clone())
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP JWK parse failed"))?;
    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP DecodingKey build failed"))?;
    let alg = dpop_alg_from_str(&dpop_header.alg)
        .ok_or(DpopTokenEndpointError::InvalidProof("DPoP unsupported alg"))?;

    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_aud = false;

    let dpop_data = decode::<DPopClaims>(dpop_token, &decoding_key, &validation)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("DPoP signature verification failed"))?;
    let claims = dpop_data.claims;

    // Validate htm (HTTP method).
    if claims.htm.to_uppercase() != htm.to_uppercase() {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP htm mismatch"));
    }

    // Validate htu (target URI).
    if claims.htu != htu {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP htu mismatch"));
    }

    // Validate jti (presence only — server nonce provides replay protection).
    if claims.jti.is_empty() {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP jti missing"));
    }

    // Freshness: reject proofs older than 60 seconds or from the future.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("system clock error"))?
        .as_secs() as i64;
    let diff = (now as i128) - (claims.iat as i128);
    if diff.unsigned_abs() > 60 {
        return Err(DpopTokenEndpointError::InvalidProof("DPoP proof stale"));
    }

    // Validate nonce claim.
    match claims.nonce.as_deref() {
        None | Some("") => {
            // No nonce — issue a fresh one for the client to retry with.
            let fresh = issue_nonce(nonce_store).await;
            return Err(DpopTokenEndpointError::UseNonce(fresh));
        }
        Some(nonce) => {
            if !validate_and_consume_nonce(nonce_store, nonce).await {
                // Unknown or expired nonce — issue a fresh one.
                let fresh = issue_nonce(nonce_store).await;
                return Err(DpopTokenEndpointError::UseNonce(fresh));
            }
        }
    }

    // Compute and return the JWK thumbprint.
    jwk_thumbprint(&dpop_header.jwk)
        .map_err(|_| DpopTokenEndpointError::InvalidProof("JWK thumbprint computation failed"))
}
```

**Step 3: Run tests**

```bash
cargo test -p relay
```

Expected: all existing tests still pass (adding `nonce` to `DPopClaims` is backward compatible via `#[serde(default)]`).

**Step 4: Commit**

```bash
git add crates/relay/src/auth/mod.rs
git commit -m "feat(auth): validate_dpop_for_token_endpoint + DpopTokenEndpointError"
```
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Implement authorization_code grant in handler

**Files:**
- Modify: `crates/relay/src/routes/oauth_token.rs`

Replace the `"authorization_code"` stub arm in `post_token` with the full grant implementation.

**Step 1: Add imports to `oauth_token.rs`**

At the top of `routes/oauth_token.rs`, add or extend the use declarations:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use crate::auth::{
    cleanup_expired_nonces, issue_nonce, validate_dpop_for_token_endpoint,
    DpopTokenEndpointError,
};
use crate::db::oauth::{consume_authorization_code, store_oauth_refresh_token};
use crate::routes::token::generate_token;
```

**Step 2: Add helper — issue_access_token**

Add a private helper function above `post_token`:

```rust
/// Claims for an OAuth 2.0 AT+JWT access token (RFC 9068).
#[derive(Serialize)]
struct AccessTokenClaims {
    sub: String,
    iat: u64,
    exp: u64,
    scope: String,
    /// DPoP confirmation claim (RFC 9449 §4.3): binds the token to the client's keypair.
    cnf: CnfClaim,
}

#[derive(Serialize)]
struct CnfClaim {
    jkt: String,
}

fn issue_access_token(
    signing_key: &crate::auth::OAuthSigningKey,
    did: &str,
    scope: &str,
    jkt: &str,
) -> Result<String, OAuthTokenError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthTokenError::new("server_error", "system clock error"))?
        .as_secs();

    let claims = AccessTokenClaims {
        sub: did.to_string(),
        iat: now,
        exp: now + 300,
        scope: scope.to_string(),
        cnf: CnfClaim {
            jkt: jkt.to_string(),
        },
    };

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(signing_key.key_id.clone());

    jsonwebtoken::encode(&header, &claims, &signing_key.encoding_key)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to sign access token");
            OAuthTokenError::new("server_error", "token signing failed")
        })
}

/// Verify the PKCE S256 code challenge.
fn verify_pkce_s256(code_verifier: &str, stored_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    // Constant-time comparison to prevent timing oracle.
    subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), stored_challenge.as_bytes()).into()
}
```

**Step 3: Replace the authorization_code stub arm in post_token**

Replace the `"authorization_code"` match arm:

```rust
        "authorization_code" => {
            handle_authorization_code(&state, &headers, form).await
        }
```

Add the full implementation as a separate async function after `post_token`:

```rust
async fn handle_authorization_code(
    state: &AppState,
    headers: &HeaderMap,
    form: TokenRequestForm,
) -> Response {
    // Prune stale nonces on every request.
    cleanup_expired_nonces(&state.dpop_nonces).await;

    // Required fields: code, redirect_uri, client_id, code_verifier.
    let code = match form.code.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => return OAuthTokenError::new("invalid_request", "missing parameter: code").into_response(),
    };
    let redirect_uri = match form.redirect_uri.as_deref() {
        Some(u) if !u.is_empty() => u,
        _ => return OAuthTokenError::new("invalid_request", "missing parameter: redirect_uri").into_response(),
    };
    let client_id = match form.client_id.as_deref() {
        Some(id) if !id.is_empty() => id,
        _ => return OAuthTokenError::new("invalid_request", "missing parameter: client_id").into_response(),
    };
    let code_verifier = match form.code_verifier.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => return OAuthTokenError::new("invalid_request", "missing parameter: code_verifier").into_response(),
    };

    // Validate DPoP proof.
    let dpop_token = match headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
    {
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

    // Hash the presented code for DB lookup.
    let code_hash = crate::routes::token::sha256_hex(
        &URL_SAFE_NO_PAD
            .decode(code)
            .unwrap_or_else(|_| code.as_bytes().to_vec()),
    );

    // Atomically consume the authorization code.
    let auth_code = match crate::db::oauth::consume_authorization_code(&state.db, &code_hash).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return OAuthTokenError::new("invalid_grant", "authorization code invalid or expired")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to consume authorization code");
            return OAuthTokenError::new("server_error", "database error").into_response();
        }
    };

    // Verify client_id matches.
    if auth_code.client_id != client_id {
        return OAuthTokenError::new("invalid_grant", "client_id mismatch").into_response();
    }

    // Verify redirect_uri matches.
    if auth_code.redirect_uri != redirect_uri {
        return OAuthTokenError::new("invalid_grant", "redirect_uri mismatch").into_response();
    }

    // Verify PKCE S256 challenge.
    if !verify_pkce_s256(code_verifier, &auth_code.code_challenge) {
        return OAuthTokenError::new("invalid_grant", "code_verifier does not match code_challenge")
            .into_response();
    }

    // Issue ES256 access token.
    let access_token =
        match issue_access_token(&state.oauth_signing_keypair, &auth_code.did, &auth_code.scope, &jkt)
        {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };

    // Generate and store refresh token.
    let refresh = generate_token();
    if let Err(e) = store_oauth_refresh_token(
        &state.db,
        &refresh.hash,
        &auth_code.client_id,
        &auth_code.did,
        &jkt,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store refresh token");
        return OAuthTokenError::new("server_error", "database error").into_response();
    }

    // Issue a fresh DPoP nonce for the next request.
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
            refresh_token: refresh.plaintext,
            scope: auth_code.scope,
        }),
    )
        .into_response()
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
git commit -m "feat(relay): authorization_code grant — DPoP, PKCE, ES256 JWT + refresh token"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Integration tests for authorization_code grant

**Verifies:** MM-77.AC1.1–AC1.8, MM-77.AC2.1–AC2.6, MM-77.AC3.2–AC3.5, MM-77.AC6.3

**Files:**
- Modify: `crates/relay/src/routes/oauth_token.rs` (`#[cfg(test)]` block)

The existing test helpers in `auth/mod.rs` (`make_dpop_proof`, `dpop_key_to_jwk`, `dpop_key_thumbprint`) are in `#[cfg(test)]` in that module. The tests below live in `routes/oauth_token.rs` and need their own local DPoP proof helpers or must call through `auth::` test utilities (not possible — they're private test-scope). Implement local equivalents in the test module.

**Step 1: Replace the existing test module in `oauth_token.rs`**

Replace the entire `#[cfg(test)] mod tests { ... }` block (from Phase 4) with this expanded version:

```rust
#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::app::{app, test_state, AppState};
    use crate::auth::issue_nonce;
    use crate::db::oauth::{register_oauth_client, store_authorization_code};

    // ── DPoP proof test helpers ───────────────────────────────────────────────

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn dpop_key_to_jwk(key: &SigningKey) -> serde_json::Value {
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })
    }

    fn dpop_thumbprint(key: &SigningKey) -> String {
        let jwk = dpop_key_to_jwk(key);
        let canonical = serde_json::to_string(&serde_json::json!({
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        }))
        .unwrap();
        let hash = Sha256::digest(canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    fn make_dpop_proof(
        key: &SigningKey,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        iat: i64,
    ) -> String {
        let jwk = dpop_key_to_jwk(key);
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
        let mut payload =
            serde_json::json!({ "htm": htm, "htu": htu, "iat": iat, "jti": Uuid::new_v4().to_string() });
        if let Some(n) = nonce {
            payload["nonce"] = serde_json::Value::String(n.to_string());
        }
        let hdr = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let pay = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let sig_input = format!("{hdr}.{pay}");
        let sig: Signature = key.sign(sig_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes().as_ref() as &[u8]);
        format!("{hdr}.{pay}.{sig_b64}")
    }

    /// Seed the DB with a test client + account + authorization code.
    async fn seed_auth_code(state: &AppState, code_hash: &str, code_challenge: &str) {
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

        store_authorization_code(
            &state.db,
            code_hash,
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            code_challenge,
            "S256",
            "https://app.example.com/callback",
            "atproto",
        )
        .await
        .unwrap();
    }

    fn post_token(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn post_token_with_dpop(body: &str, dpop: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("DPoP", dpop)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Phase 4 tests (retained) ──────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_grant_type_returns_400_unsupported() {
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=client_credentials"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn missing_grant_type_returns_400_invalid_request() {
        let resp = app(test_state().await)
            .oneshot(post_token("code=abc123"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn error_response_content_type_is_json() {
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=bad"))
            .await
            .unwrap();
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("application/json"));
    }

    #[tokio::test]
    async fn error_response_has_error_and_error_description_fields() {
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=bad"))
            .await
            .unwrap();
        let json = json_body(resp).await;
        assert!(json["error"].is_string());
        assert!(json["error_description"].is_string());
    }

    #[tokio::test]
    async fn get_token_endpoint_returns_405() {
        let resp = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth/token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // ── AC2 — DPoP proof validation ───────────────────────────────────────────

    #[tokio::test]
    async fn missing_dpop_header_returns_invalid_dpop_proof() {
        // AC2.3
        let resp = app(test_state().await)
            .oneshot(post_token("grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_wrong_htm_returns_invalid_dpop_proof() {
        // AC2.4
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "GET",  // wrong — must be POST
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof", "wrong htm must return invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_wrong_htu_returns_invalid_dpop_proof() {
        // AC2.5
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://wrong-url.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    #[tokio::test]
    async fn dpop_stale_iat_returns_invalid_dpop_proof() {
        // AC2.6
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs() - 120, // 2 minutes ago — stale
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_dpop_proof");
    }

    // ── AC3 — DPoP nonces ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn dpop_without_nonce_returns_use_dpop_nonce_with_header() {
        // AC3.2
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            None, // no nonce
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "use_dpop_nonce response must include DPoP-Nonce header"
        );
        let json = json_body(resp).await;
        assert_eq!(json["error"], "use_dpop_nonce");
    }

    #[tokio::test]
    async fn dpop_with_unknown_nonce_returns_use_dpop_nonce() {
        // AC3.4
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some("fabricated-nonce-that-was-never-issued"),
            now_secs(),
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                "grant_type=authorization_code&code=x&redirect_uri=x&client_id=x&code_verifier=x",
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "use_dpop_nonce");
    }

    // ── AC1 — authorization_code grant ───────────────────────────────────────

    #[tokio::test]
    async fn authorization_code_happy_path_returns_200_with_tokens() {
        // AC1.1, AC1.2, AC1.3, AC2.1, AC2.2, AC3.5, AC6.3
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

        // Build PKCE S256 challenge.
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnop";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        // Raw code (43-char base64url) and its SHA-256 hex hash for DB storage.
        let raw_code = "testauthorizationcode1234567890123456789012";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };

        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;

        let dpop = make_dpop_proof(
            &key,
            "POST",
            "https://test.example.com/oauth/token",
            Some(&nonce),
            now_secs(),
        );

        let body = format!(
            "grant_type=authorization_code\
             &code={raw_code}\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &code_verifier={code_verifier}"
        );

        let resp = app(state)
            .oneshot(post_token_with_dpop(&body, &dpop))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "happy path must return 200");

        // AC3.5 — DPoP-Nonce header in success response.
        assert!(
            resp.headers().contains_key("DPoP-Nonce"),
            "success response must include fresh DPoP-Nonce header"
        );

        let json = json_body(resp).await;

        // AC1.1 — TokenResponse fields.
        assert!(json["access_token"].is_string(), "access_token must be present");
        assert_eq!(json["token_type"], "DPoP", "token_type must be DPoP");
        assert_eq!(json["expires_in"], 300);
        assert!(json["refresh_token"].is_string(), "refresh_token must be present");
        assert!(json["scope"].is_string(), "scope must be present");

        // AC1.3 — refresh token is 43-char base64url.
        let rt = json["refresh_token"].as_str().unwrap();
        assert_eq!(rt.len(), 43, "refresh_token must be 43 chars (AC1.3)");

        // AC1.2 + AC6.3 — access token is ES256 JWT with typ=at+jwt.
        let at = json["access_token"].as_str().unwrap();
        let header_b64 = at.split('.').next().unwrap();
        let header_json = String::from_utf8(
            URL_SAFE_NO_PAD.decode(header_b64).unwrap(),
        )
        .unwrap();
        let header: serde_json::Value = serde_json::from_str(&header_json).unwrap();
        assert_eq!(header["typ"], "at+jwt", "access token typ must be at+jwt (AC1.2)");
        assert_eq!(header["alg"], "ES256", "access token alg must be ES256 (AC6.3)");

        // AC2.2 — cnf.jkt in access token matches DPoP key thumbprint.
        let payload_b64 = at.split('.').nth(1).unwrap();
        let payload_json = String::from_utf8(
            URL_SAFE_NO_PAD.decode(payload_b64).unwrap(),
        )
        .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        let cnf_jkt = payload["cnf"]["jkt"].as_str().unwrap();
        let expected_jkt = dpop_thumbprint(&key);
        assert_eq!(cnf_jkt, expected_jkt, "cnf.jkt must match DPoP key thumbprint (AC2.2)");
    }

    #[tokio::test]
    async fn wrong_code_verifier_returns_invalid_grant() {
        // AC1.4
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);

        let code_verifier = "correct-verifier-1234567890abcdefghijk";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "testauthorizationcode1234567890123456789012";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&key, "POST", "https://test.example.com/oauth/token", Some(&nonce), now_secs());

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                &format!(
                    "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json&code_verifier=wrong-verifier"
                ),
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_grant", "wrong code_verifier must return invalid_grant (AC1.4)");
    }

    #[tokio::test]
    async fn consumed_code_returns_invalid_grant() {
        // AC1.6
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnop";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "testauthorizationcode1234567890123456789012";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;

        let body = format!(
            "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json&code_verifier={code_verifier}"
        );

        // First use — should succeed.
        let nonce1 = issue_nonce(&state.dpop_nonces).await;
        let dpop1 = make_dpop_proof(&key, "POST", "https://test.example.com/oauth/token", Some(&nonce1), now_secs());
        let state_arc = std::sync::Arc::new(state);

        // Build the app twice using different oneshot calls on the same state.
        // Clone state so the DB pool is shared across both calls.
        let state1 = (*state_arc).clone();
        let resp1 = app(state1)
            .oneshot(post_token_with_dpop(&body, &dpop1))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK, "first use must succeed");

        // Second use — code was consumed.
        let state2 = (*state_arc).clone();
        let nonce2 = issue_nonce(&state2.dpop_nonces).await;
        let dpop2 = make_dpop_proof(&key, "POST", "https://test.example.com/oauth/token", Some(&nonce2), now_secs());
        let resp2 = app(state2)
            .oneshot(post_token_with_dpop(&body, &dpop2))
            .await
            .unwrap();
        let json2 = json_body(resp2).await;
        assert_eq!(json2["error"], "invalid_grant", "second use must return invalid_grant (AC1.6)");
    }

    #[tokio::test]
    async fn client_id_mismatch_returns_invalid_grant() {
        // AC1.7
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnop";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "testauthorizationcode1234567890123456789012";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&key, "POST", "https://test.example.com/oauth/token", Some(&nonce), now_secs());

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                &format!(
                    "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=https%3A%2F%2Fwrong-client.example.com%2F&code_verifier={code_verifier}"
                ),
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_grant", "client_id mismatch must return invalid_grant (AC1.7)");
    }

    #[tokio::test]
    async fn redirect_uri_mismatch_returns_invalid_grant() {
        // AC1.8
        let state = test_state().await;
        let key = SigningKey::random(&mut OsRng);
        let code_verifier = "testcodeverifier1234567890abcdefghijklmnop";
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let raw_code = "testauthorizationcode1234567890123456789012";
        let code_hash = {
            let bytes = URL_SAFE_NO_PAD.decode(raw_code).unwrap();
            let hash = Sha256::digest(&bytes);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        seed_auth_code(&state, &code_hash, &code_challenge).await;
        let nonce = issue_nonce(&state.dpop_nonces).await;
        let dpop = make_dpop_proof(&key, "POST", "https://test.example.com/oauth/token", Some(&nonce), now_secs());

        let resp = app(state)
            .oneshot(post_token_with_dpop(
                &format!(
                    "grant_type=authorization_code&code={raw_code}&redirect_uri=https%3A%2F%2Fwrong.example.com%2Fcallback&client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json&code_verifier={code_verifier}"
                ),
                &dpop,
            ))
            .await
            .unwrap();

        let json = json_body(resp).await;
        assert_eq!(json["error"], "invalid_grant", "redirect_uri mismatch must return invalid_grant (AC1.8)");
    }
}
```

**Step 2: Run tests**

```bash
cargo test -p relay routes::oauth_token
```

Expected: all tests pass.

**Step 3: Run full test suite**

```bash
cargo test -p relay
```

Expected: all tests pass.

**Step 4: Commit**

```bash
git add crates/relay/src/routes/oauth_token.rs
git commit -m "test(relay): authorization_code grant integration tests (AC1, AC2, AC3, AC6)"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->
