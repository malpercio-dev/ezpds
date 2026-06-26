// pattern: Imperative Shell

use sqlx::SqlitePool;

/// A row from the `iroh_identity` table.
#[allow(dead_code)]
pub struct IrohIdentityRow {
    pub id: String,
    pub secret_key_encrypted: String,
}

/// Load the relay's persistent Iroh node secret-key row.
///
/// Returns `None` if no identity has been generated yet (first boot).
pub async fn get_iroh_identity(pool: &SqlitePool) -> Result<Option<IrohIdentityRow>, sqlx::Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT id, secret_key_encrypted FROM iroh_identity LIMIT 1")
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(id, secret_key_encrypted)| IrohIdentityRow {
        id,
        secret_key_encrypted,
    }))
}

/// Persist a newly generated, AES-256-GCM-encrypted Iroh node secret key.
///
/// `id` is a UUID string. `secret_key_encrypted` is the encrypted 32-byte Ed25519
/// secret key (base64, 80 chars) produced by `crypto::encrypt_private_key`.
pub async fn store_iroh_identity(
    pool: &SqlitePool,
    id: &str,
    secret_key_encrypted: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO iroh_identity (id, secret_key_encrypted, created_at) \
         VALUES (?, ?, datetime('now'))",
    )
    .bind(id)
    .bind(secret_key_encrypted)
    .execute(pool)
    .await?;
    Ok(())
}
