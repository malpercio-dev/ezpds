// pattern: Imperative Shell
//
// Storage adapter for OAuth server-side state in the `oauth_clients` table.
// Authorization code and token functions will be added when the full OAuth
// flow is implemented.

use sqlx::SqlitePool;

/// A registered OAuth client row from the `oauth_clients` table.
///
/// `client_metadata` is stored as a raw JSON string (RFC 7591 client metadata).
/// Callers are responsible for serializing/deserializing the JSON.
// Wired to handlers when the OAuth authorization flow is implemented.
#[allow(dead_code)]
pub struct OAuthClientRow {
    pub client_id: String,
    pub client_metadata: String,
    pub created_at: String,
}

/// Register a new OAuth client.
///
/// `client_id` is an HTTPS URL (the client's metadata document URL per AT Protocol OAuth spec).
/// `client_metadata` is a JSON string conforming to RFC 7591 client metadata.
///
/// Returns `sqlx::Error` on failure. Callers should use `crate::db::is_unique_violation`
/// to detect duplicate `client_id` conflicts.
// Wired to handlers when the OAuth authorization flow is implemented.
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
// Wired to handlers when the OAuth authorization flow is implemented.
#[allow(dead_code)]
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
}
