// pattern: Imperative Shell

use sqlx::SqlitePool;

/// A row from the `jwt_signing_secret` table.
#[allow(dead_code)]
pub struct JwtSecretRow {
    pub id: String,
    pub secret_encrypted: String,
}

/// Load the server's persistent HS256 JWT signing secret row.
///
/// Returns `None` if no secret has been generated yet (first boot).
pub async fn get_jwt_secret(pool: &SqlitePool) -> Result<Option<JwtSecretRow>, sqlx::Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT id, secret_encrypted FROM jwt_signing_secret LIMIT 1")
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(id, secret_encrypted)| JwtSecretRow {
        id,
        secret_encrypted,
    }))
}

/// Persist a newly generated, AES-256-GCM-encrypted HS256 JWT signing secret.
///
/// `id` is a UUID string. `secret_encrypted` is the encrypted 32-byte secret
/// (base64, 80 chars) produced by `crypto::encrypt_private_key`.
pub async fn store_jwt_secret(
    pool: &SqlitePool,
    id: &str,
    secret_encrypted: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO jwt_signing_secret (id, secret_encrypted, created_at) \
         VALUES (?, ?, datetime('now'))",
    )
    .bind(id)
    .bind(secret_encrypted)
    .execute(pool)
    .await?;
    Ok(())
}
