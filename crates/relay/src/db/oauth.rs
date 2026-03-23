// pattern: Imperative Shell
//
// Storage adapter for OAuth server-side state: client registry, authorization
// codes, and helpers for the authorization endpoint.

use sqlx::SqlitePool;

/// A registered OAuth client row from the `oauth_clients` table.
///
/// `client_metadata` is stored as a raw JSON string (RFC 7591 client metadata).
/// Callers are responsible for serializing/deserializing the JSON.
pub struct OAuthClientRow {
    pub client_id: String,
    pub client_metadata: String,
    // created_at is included for future handlers (admin listing, DCR);
    // not read by any handler yet.
    #[allow(dead_code)]
    pub created_at: String,
}

/// Register a new OAuth client.
///
/// `client_id` is an HTTPS URL (the client's metadata document URL per AT Protocol OAuth spec).
/// `client_metadata` is a JSON string conforming to RFC 7591 client metadata.
///
/// Returns `sqlx::Error` on failure. Callers should use `crate::db::is_unique_violation`
/// to detect duplicate `client_id` conflicts.
///
/// No HTTP handler calls this yet; a future dynamic client registration endpoint (RFC 7591)
/// will call it.
#[allow(dead_code)]
pub async fn register_oauth_client(
    pool: &SqlitePool,
    client_id: &str,
    client_metadata: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_metadata, created_at) \
         VALUES (?, ?, datetime('now'))",
    )
    .bind(client_id)
    .bind(client_metadata)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a registered OAuth client by `client_id`. Returns `None` if not found.
pub async fn get_oauth_client(
    pool: &SqlitePool,
    client_id: &str,
) -> Result<Option<OAuthClientRow>, sqlx::Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT client_id, client_metadata, created_at FROM oauth_clients WHERE client_id = ?",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;

    Ok(
        row.map(|(client_id, client_metadata, created_at)| OAuthClientRow {
            client_id,
            client_metadata,
            created_at,
        }),
    )
}

/// Store a newly generated authorization code.
///
/// `code` must be the SHA-256 hex hash of the raw token bytes — callers pass `token.hash`,
/// not `token.plaintext`. The token endpoint hashes the presented code before lookup,
/// consistent with the session and refresh-token patterns in this codebase.
///
/// The code expires 60 seconds after creation (single-use, short-lived per RFC 6749 §4.1.2).
#[allow(clippy::too_many_arguments)]
pub async fn store_authorization_code(
    pool: &SqlitePool,
    code: &str,
    client_id: &str,
    did: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    redirect_uri: &str,
    scope: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_authorization_codes \
         (code, client_id, did, code_challenge, code_challenge_method, redirect_uri, scope, \
          expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+60 seconds'), datetime('now'))",
    )
    .bind(code)
    .bind(client_id)
    .bind(did)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(redirect_uri)
    .bind(scope)
    .execute(pool)
    .await?;
    Ok(())
}

/// Return the DID of the first account on this single-user PDS.
///
/// `ORDER BY created_at ASC` makes selection deterministic if the single-account
/// invariant is ever violated. Returns `None` when no account row exists yet.
pub async fn get_single_account_did(pool: &SqlitePool) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT did FROM accounts ORDER BY created_at ASC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(did,)| did))
}

/// A row from the `oauth_signing_key` table.
#[allow(dead_code)]
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

    Ok(row.map(
        |(id, public_key_jwk, private_key_encrypted)| OAuthSigningKeyRow {
            id,
            public_key_jwk,
            private_key_encrypted,
        },
    ))
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

/// A row read from `oauth_authorization_codes` during code exchange.
pub struct AuthCodeRow {
    pub client_id: String,
    pub did: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub redirect_uri: String,
    #[allow(dead_code)]
    pub scope: String,
}

/// Retrieve an authorization code without consuming it.
///
/// Returns `None` if the code does not exist or has already expired (`expires_at <= now`).
/// Callers must treat `None` as `invalid_grant`.
///
/// The code column stores the SHA-256 hex hash of the raw code bytes. Callers must
/// hash the presented code before calling this function (use `routes::token::sha256_hex`).
///
/// Use this to retrieve the code for validation, then call `delete_authorization_code`
/// after all checks pass. The SELECT+DELETE are serialized due to `max_connections(1)`
/// on the pool, preventing TOCTOU races.
pub async fn get_authorization_code(
    pool: &SqlitePool,
    code_hash: &str,
) -> Result<Option<AuthCodeRow>, sqlx::Error> {
    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT client_id, did, code_challenge, code_challenge_method, redirect_uri, scope \
         FROM oauth_authorization_codes \
         WHERE code = ? AND expires_at > datetime('now')",
    )
    .bind(code_hash)
    .fetch_optional(pool)
    .await?;

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

/// Delete an authorization code after validation is complete.
///
/// The code column stores the SHA-256 hex hash of the raw code bytes.
///
/// The SELECT+DELETE sequence is safe from TOCTOU races because the relay's
/// connection pool uses `max_connections(1)`, making all DB operations serialized.
pub async fn delete_authorization_code(
    pool: &SqlitePool,
    code_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oauth_authorization_codes WHERE code = ?")
        .bind(code_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Atomically consume an authorization code: SELECT + DELETE in one transaction.
///
/// Deprecated: Use `get_authorization_code` followed by validation then `delete_authorization_code`.
/// This function is kept for backward compatibility with existing tests.
///
/// Returns `None` if the code does not exist or has already expired (`expires_at <= now`).
/// Callers must treat `None` as `invalid_grant`.
///
/// The code column stores the SHA-256 hex hash of the raw code bytes. Callers must
/// hash the presented code before calling this function (use `routes::token::sha256_hex`).
#[allow(dead_code)]
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

/// A row read from `oauth_tokens` during refresh token rotation.
pub struct RefreshTokenRow {
    pub client_id: String,
    pub did: String,
    #[allow(dead_code)]
    pub scope: String,
    /// DPoP key thumbprint bound to this refresh token. `None` for tokens
    /// issued before DPoP binding was enforced (not expected after V012).
    pub jkt: Option<String>,
}

/// Retrieve a refresh token without consuming it.
///
/// Returns `None` if the token does not exist or has already expired
/// (`expires_at <= now`). Callers must treat `None` as `invalid_grant`.
///
/// The `id` column stores the SHA-256 hex hash of the raw token bytes.
/// Callers must hash the presented token before calling this function
/// using the same approach as `store_oauth_refresh_token`.
///
/// Use this to retrieve the token for validation, then call `delete_oauth_refresh_token`
/// after all checks pass. The SELECT+DELETE are serialized due to `max_connections(1)`
/// on the pool, preventing TOCTOU races.
pub async fn get_oauth_refresh_token(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT client_id, did, scope, jkt FROM oauth_tokens \
         WHERE id = ? AND expires_at > datetime('now')",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(client_id, did, scope, jkt)| RefreshTokenRow {
        client_id,
        did,
        scope,
        jkt,
    }))
}

/// Delete a refresh token after validation is complete.
///
/// The `id` column stores the SHA-256 hex hash of the raw token bytes.
///
/// The SELECT+DELETE sequence is safe from TOCTOU races because the relay's
/// connection pool uses `max_connections(1)`, making all DB operations serialized.
pub async fn delete_oauth_refresh_token(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oauth_tokens WHERE id = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete all expired authorization codes from the database.
///
/// Call alongside `cleanup_expired_nonces` on every token request to prevent unbounded
/// DB growth from abandoned authorization flows.
pub async fn cleanup_expired_auth_codes(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oauth_authorization_codes WHERE expires_at <= datetime('now')")
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete all expired refresh tokens from the database.
///
/// Call alongside `cleanup_expired_nonces` on every token request to prevent unbounded
/// DB growth from expired sessions.
pub async fn cleanup_expired_refresh_tokens(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oauth_tokens WHERE expires_at <= datetime('now')")
        .execute(pool)
        .await?;
    Ok(())
}

/// Atomically consume a refresh token: SELECT + DELETE in one transaction.
///
/// Deprecated: Use `get_oauth_refresh_token` followed by validation then `delete_oauth_refresh_token`.
/// This function is kept for backward compatibility with existing tests.
///
/// Returns `None` if the token does not exist or has already expired
/// (`expires_at <= now`). Callers must treat `None` as `invalid_grant`.
///
/// The `id` column stores the SHA-256 hex hash of the raw token bytes.
/// Callers must hash the presented token before calling this function
/// using the same approach as `store_oauth_refresh_token`.
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{is_unique_violation, open_pool, run_migrations};

    async fn test_pool() -> SqlitePool {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn register_and_retrieve_oauth_client() {
        let pool = test_pool().await;
        let client_id = "https://app.example.com/client-metadata.json";
        let metadata = r#"{"redirect_uris":["https://app.example.com/callback"]}"#;

        register_oauth_client(&pool, client_id, metadata)
            .await
            .unwrap();

        let row = get_oauth_client(&pool, client_id)
            .await
            .unwrap()
            .expect("client should exist after registration");

        assert_eq!(row.client_id, client_id);
        assert_eq!(row.client_metadata, metadata);
        assert!(!row.created_at.is_empty());
    }

    #[tokio::test]
    async fn get_oauth_client_returns_none_for_unknown_client() {
        let pool = test_pool().await;
        let result = get_oauth_client(&pool, "https://unknown.example.com/client")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn register_duplicate_client_id_is_unique_violation() {
        let pool = test_pool().await;
        let client_id = "https://app.example.com/client-metadata.json";
        let metadata = r#"{"redirect_uris":["https://app.example.com/callback"]}"#;

        register_oauth_client(&pool, client_id, metadata)
            .await
            .unwrap();

        let err = register_oauth_client(&pool, client_id, metadata)
            .await
            .unwrap_err();

        assert!(
            is_unique_violation(&err),
            "duplicate client_id should be a unique violation"
        );
    }

    #[tokio::test]
    async fn store_and_retrieve_authorization_code_exists_in_db() {
        let pool = test_pool().await;

        // Register client and account (FK constraints).
        register_oauth_client(
            &pool,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind("did:plc:testaccount000000000000")
        .bind("test@example.com")
        .execute(&pool)
        .await
        .unwrap();

        store_authorization_code(
            &pool,
            "test-code-abc123",
            "https://app.example.com/client-metadata.json",
            "did:plc:testaccount000000000000",
            "e3b0c44298fc1c149afbf4c8996fb924",
            "S256",
            "https://app.example.com/callback",
            "atproto",
        )
        .await
        .unwrap();

        let row: Option<(String,)> =
            sqlx::query_as("SELECT code FROM oauth_authorization_codes WHERE code = ?")
                .bind("test-code-abc123")
                .fetch_optional(&pool)
                .await
                .unwrap();

        assert!(row.is_some(), "authorization code should be stored");
    }

    #[tokio::test]
    async fn get_single_account_did_returns_none_when_no_accounts() {
        let pool = test_pool().await;
        let result = get_single_account_did(&pool).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_single_account_did_returns_did_when_account_exists() {
        let pool = test_pool().await;
        let did = "did:plc:testaccount000000000000";

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind("test@example.com")
        .execute(&pool)
        .await
        .unwrap();

        let result = get_single_account_did(&pool).await.unwrap();
        assert_eq!(result.as_deref(), Some(did));
    }

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
        assert_eq!(
            row.public_key_jwk,
            r#"{"kty":"EC","crv":"P-256","x":"abc","y":"def","kid":"test-key-uuid-01"}"#
        );
        assert_eq!(
            row.private_key_encrypted,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }

    #[tokio::test]
    async fn get_oauth_signing_key_returns_none_when_empty() {
        let pool = test_pool().await;
        let result = get_oauth_signing_key(&pool).await.unwrap();
        assert!(result.is_none());
    }

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

        assert_eq!(
            row.client_id,
            "https://app.example.com/client-metadata.json"
        );
        assert_eq!(row.did, "did:plc:testaccount000000000000");

        // Second consume: must return None (already deleted).
        let second = consume_authorization_code(&pool, "hash-abc123")
            .await
            .unwrap();
        assert!(second.is_none(), "consumed code must not be found again");
    }

    #[tokio::test]
    async fn consume_authorization_code_returns_none_for_unknown_code() {
        let pool = test_pool().await;
        let result = consume_authorization_code(&pool, "nonexistent-hash")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn consume_authorization_code_returns_none_for_expired_code() {
        let pool = test_pool().await;
        register_oauth_client(
            &pool,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();

        insert_test_account(&pool).await;

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
        assert!(result.is_none(), "expired auth code must return None");
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
        assert_eq!(
            scope, "com.atproto.refresh",
            "scope must be com.atproto.refresh"
        );
        assert_eq!(jkt.as_deref(), Some("jkt-thumbprint"));
    }

    #[tokio::test]
    async fn consume_oauth_refresh_token_returns_row_and_deletes_it() {
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

        assert_eq!(
            row.client_id,
            "https://app.example.com/client-metadata.json"
        );
        assert_eq!(row.scope, "com.atproto.refresh");
        assert_eq!(row.jkt.as_deref(), Some("test-jkt-thumbprint"));
        assert_eq!(row.did, "did:plc:testaccount000000000000");

        // Second consume must return None (already deleted) — AC4.2.
        let second = consume_oauth_refresh_token(&pool, "consume-test-token-hash")
            .await
            .unwrap();
        assert!(second.is_none(), "consumed token must not be found again");
    }

    #[tokio::test]
    async fn consume_oauth_refresh_token_returns_none_for_expired_token() {
        let pool = test_pool().await;
        register_oauth_client(
            &pool,
            "https://app.example.com/client-metadata.json",
            r#"{"redirect_uris":["https://app.example.com/callback"]}"#,
        )
        .await
        .unwrap();
        insert_test_account(&pool).await;

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
        assert!(result.is_none(), "expired refresh token must return None");
    }

    #[tokio::test]
    async fn consume_oauth_refresh_token_returns_none_for_unknown_token() {
        let pool = test_pool().await;
        let result = consume_oauth_refresh_token(&pool, "nonexistent-hash")
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
