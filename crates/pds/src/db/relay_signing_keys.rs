// pattern: Imperative Shell
//
// Operator-level PDS signing keys — the `relay_signing_keys` table (V003), not tied to any
// account DID. Backs the `/v1/pds/keys` endpoints (deprecated `/v1/relay/keys` aliases): read the
// current key and persist a freshly minted one. Returns plain data; no business logic.

use common::{ApiError, ErrorCode};

/// A stored operator signing key's public fields.
pub struct RelaySigningKey {
    pub id: String,
    pub public_key: String,
    pub algorithm: String,
}

/// The most recently created operator signing key, or `None` when none is provisioned.
pub async fn latest_signing_key(
    db: &sqlx::SqlitePool,
) -> Result<Option<RelaySigningKey>, ApiError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key, algorithm \
         FROM relay_signing_keys \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to query pds signing key");
        ApiError::new(ErrorCode::InternalError, "failed to query signing key")
    })?;

    Ok(row.map(|(id, public_key, algorithm)| RelaySigningKey {
        id,
        public_key,
        algorithm,
    }))
}

/// Persist a freshly generated operator signing key. `private_key_encrypted` is the encoded
/// AES-256-GCM ciphertext of the private key.
pub async fn insert_signing_key(
    db: &sqlx::SqlitePool,
    id: &str,
    algorithm: &str,
    public_key: &str,
    private_key_encrypted: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO relay_signing_keys \
         (id, algorithm, public_key, private_key_encrypted, created_at) \
         VALUES (?, ?, ?, ?, datetime('now'))",
    )
    .bind(id)
    .bind(algorithm)
    .bind(public_key)
    .bind(private_key_encrypted)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, key_id = %id, "failed to insert PDS signing key");
        ApiError::new(ErrorCode::InternalError, "failed to store signing key")
    })?;

    Ok(())
}
