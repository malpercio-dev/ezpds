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
/// not `token.plaintext`. The token endpoint (not yet implemented) hashes the presented code
/// before lookup, consistent with the session and refresh-token patterns in this codebase.
///
/// The code expires 60 seconds after creation (single-use, short-lived per RFC 6749 §4.1.2).
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
        assert!(!row.public_key_jwk.is_empty());
        assert!(!row.private_key_encrypted.is_empty());
    }

    #[tokio::test]
    async fn get_oauth_signing_key_returns_none_when_empty() {
        let pool = test_pool().await;
        let result = get_oauth_signing_key(&pool).await.unwrap();
        assert!(result.is_none());
    }
}
