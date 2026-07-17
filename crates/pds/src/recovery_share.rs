// pattern: Imperative Shell

//! KEK wrapping for the PDS-held Shamir recovery share.
//!
//! The wire representation is base32, but the decoded share is exactly 32
//! bytes, so it uses the same authenticated-encryption envelope as the other
//! secrets protected by `EZPDS_SIGNING_KEY_MASTER_KEY`.

use data_encoding::BASE32_NOPAD;
use sqlx::SqlitePool;
use zeroize::Zeroizing;

const PLAINTEXT_BASE32_LEN: usize = 52;

pub fn wrap(share: &str, master_key: &[u8; 32]) -> anyhow::Result<String> {
    let decoded = Zeroizing::new(
        BASE32_NOPAD
            .decode(share.as_bytes())
            .map_err(|_| anyhow::anyhow!("recovery share is not valid base32"))?,
    );
    if decoded.len() != 32 {
        anyhow::bail!("recovery share must decode to exactly 32 bytes");
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&decoded);
    crypto::encrypt_private_key(&bytes, master_key)
        .map_err(|e| anyhow::anyhow!("failed to wrap recovery share: {e}"))
}

pub fn unwrap(ciphertext: &str, master_key: &[u8; 32]) -> anyhow::Result<String> {
    let bytes = crypto::decrypt_private_key(ciphertext, master_key)
        .map_err(|e| anyhow::anyhow!("failed to unwrap recovery share: {e}"))?;
    Ok(BASE32_NOPAD.encode(bytes.as_slice()))
}

/// Idempotently wrap every legacy base32 row in one transaction.
///
/// The length predicate deliberately selects only the old representation. A
/// malformed legacy-looking value aborts the transaction, while already
/// wrapped rows remain untouched. This runs after schema migrations and before
/// the server starts accepting requests.
pub async fn migrate_plaintext_rows(
    pool: &SqlitePool,
    master_key: Option<&[u8; 32]>,
) -> anyhow::Result<u64> {
    let mut tx = pool.begin().await?;
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT did, recovery_share FROM accounts WHERE recovery_share IS NOT NULL")
            .fetch_all(&mut *tx)
            .await?;

    if rows.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }
    let master_key = master_key.ok_or_else(|| {
        anyhow::anyhow!("EZPDS_SIGNING_KEY_MASTER_KEY is required to wrap existing recovery shares")
    })?;

    let mut migrated = 0u64;
    for (did, share) in &rows {
        if share.len() != PLAINTEXT_BASE32_LEN {
            unwrap(share, master_key).map_err(|e| {
                anyhow::anyhow!("failed to validate wrapped recovery share for {did}: {e}")
            })?;
            continue;
        }
        let wrapped = wrap(share, master_key)
            .map_err(|e| anyhow::anyhow!("failed to migrate recovery share for {did}: {e}"))?;
        let result = sqlx::query(
            "UPDATE accounts SET recovery_share = ? \
             WHERE did = ? AND recovery_share = ?",
        )
        .bind(wrapped)
        .bind(did)
        .bind(share)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            anyhow::bail!("recovery share row changed during migration for {did}");
        }
        migrated += 1;
    }

    tx.commit().await?;
    Ok(migrated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    const KEY: [u8; 32] = [0x51; 32];

    #[test]
    fn wrap_unwrap_round_trip() {
        let share = BASE32_NOPAD.encode(&[0x2a; 32]);
        let ciphertext = wrap(&share, &KEY).unwrap();
        assert_eq!(ciphertext.len(), 80);
        assert_eq!(unwrap(&ciphertext, &KEY).unwrap(), share);
        assert!(unwrap(&ciphertext, &[0x52; 32]).is_err());
    }

    #[tokio::test]
    async fn migration_wraps_legacy_rows_without_touching_wrapped_rows() {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        let legacy = BASE32_NOPAD.encode(&[0x31; 32]);
        let already_wrapped = wrap(&BASE32_NOPAD.encode(&[0x32; 32]), &KEY).unwrap();
        for (did, email, share) in [
            ("did:plc:legacy", "legacy@example.com", legacy.as_str()),
            (
                "did:plc:wrapped",
                "wrapped@example.com",
                already_wrapped.as_str(),
            ),
        ] {
            sqlx::query(
                "INSERT INTO accounts \
                 (did, email, password_hash, recovery_share, created_at, updated_at) \
                 VALUES (?, ?, 'hash', ?, datetime('now'), datetime('now'))",
            )
            .bind(did)
            .bind(email)
            .bind(share)
            .execute(&pool)
            .await
            .unwrap();
        }

        assert_eq!(migrate_plaintext_rows(&pool, Some(&KEY)).await.unwrap(), 1);
        assert_eq!(migrate_plaintext_rows(&pool, Some(&KEY)).await.unwrap(), 0);

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT did, recovery_share FROM accounts ORDER BY did")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(unwrap(&rows[0].1, &KEY).unwrap(), legacy);
        assert_eq!(rows[1].1, already_wrapped);
    }

    #[tokio::test]
    async fn migration_without_key_does_not_modify_plaintext() {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        let legacy = BASE32_NOPAD.encode(&[0x33; 32]);
        sqlx::query(
            "INSERT INTO accounts \
             (did, email, password_hash, recovery_share, created_at, updated_at) \
             VALUES ('did:plc:no-key', 'no-key@example.com', 'hash', ?, \
                     datetime('now'), datetime('now'))",
        )
        .bind(&legacy)
        .execute(&pool)
        .await
        .unwrap();

        assert!(migrate_plaintext_rows(&pool, None).await.is_err());
        let (stored,): (String,) =
            sqlx::query_as("SELECT recovery_share FROM accounts WHERE did = 'did:plc:no-key'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, legacy);
    }
}
