// pattern: Imperative Shell

//! Per-account ATProto repo signing key queries.
//!
//! The key is generated during the DID ceremony and stored on the pending
//! account (`pending_accounts.repo_signing_*`), then copied into `signing_keys`
//! (DID-keyed) inside the promotion transaction. The private key is always
//! AES-256-GCM encrypted by the caller before it reaches these functions —
//! this module only moves opaque ciphertext, never plaintext key material.

#![allow(dead_code)]

use sqlx::{Sqlite, SqlitePool};

/// A repo signing key as stored: did:key id, multibase public key, and the
/// AES-256-GCM-encrypted private key (80-char base64, per `crypto::encrypt_private_key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSigningKey {
    pub key_id: String,
    pub public_key: String,
    pub private_key_encrypted: String,
}

/// Store the generated per-account repo signing key on the pending account.
/// Overwrites any existing key for the pending account (the ceremony endpoint
/// is idempotent and reuses the existing key, so this only writes once).
pub async fn set_pending_repo_key(
    pool: &SqlitePool,
    account_id: &str,
    key: &RepoSigningKey,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE pending_accounts \
         SET repo_signing_key_id = ?, repo_signing_public_key = ?, \
             repo_signing_private_key_encrypted = ? \
         WHERE id = ?",
    )
    .bind(&key.key_id)
    .bind(&key.public_key)
    .bind(&key.private_key_encrypted)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch the per-account repo signing key from the pending account.
/// Returns `None` if no key has been generated yet (all three columns NULL).
pub async fn get_pending_repo_key(
    pool: &SqlitePool,
    account_id: &str,
) -> Result<Option<RepoSigningKey>, sqlx::Error> {
    let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT repo_signing_key_id, repo_signing_public_key, \
                repo_signing_private_key_encrypted \
         FROM pending_accounts WHERE id = ?",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((Some(key_id), Some(public_key), Some(private_key_encrypted))) => {
            Some(RepoSigningKey {
                key_id,
                public_key,
                private_key_encrypted,
            })
        }
        _ => None,
    })
}

/// Insert the per-account signing key into `signing_keys` (DID-keyed).
/// Generic over the executor so it can run inside the promotion transaction.
pub async fn insert_did_signing_key<'e, E>(
    executor: E,
    did: &str,
    key: &RepoSigningKey,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO signing_keys \
         (id, did, key_type, public_key, private_key_encrypted, created_at) \
         VALUES (?, ?, 'p256', ?, ?, datetime('now'))",
    )
    .bind(&key.key_id)
    .bind(did)
    .bind(&key.public_key)
    .bind(&key.private_key_encrypted)
    .execute(executor)
    .await?;
    Ok(())
}

/// Store a standard account-migration signing-key reservation.
///
/// Returns `true` when this call inserted a fresh reservation. When `did` is
/// `Some`, the database enforces one reservation per DID; duplicate DID inserts
/// return `false` so callers can re-read and return the existing key.
pub async fn insert_reserved_repo_key(
    pool: &SqlitePool,
    did: Option<&str>,
    key: &RepoSigningKey,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO reserved_signing_keys \
         (id, did, key_type, public_key, private_key_encrypted, created_at) \
         VALUES (?, ?, 'p256', ?, ?, datetime('now')) \
         ON CONFLICT(did) DO NOTHING",
    )
    .bind(&key.key_id)
    .bind(did)
    .bind(&key.public_key)
    .bind(&key.private_key_encrypted)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Fetch a reserved account-migration signing key by migrating DID.
pub async fn get_reserved_repo_key_by_did(
    pool: &SqlitePool,
    did: &str,
) -> Result<Option<RepoSigningKey>, sqlx::Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key, private_key_encrypted FROM reserved_signing_keys \
         WHERE did = ? LIMIT 1",
    )
    .bind(did)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(key_id, public_key, private_key_encrypted)| RepoSigningKey {
            key_id,
            public_key,
            private_key_encrypted,
        },
    ))
}

/// Fetch a reserved account-migration signing key by did:key id.
pub async fn get_reserved_repo_key_by_id(
    pool: &SqlitePool,
    key_id: &str,
) -> Result<Option<RepoSigningKey>, sqlx::Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key, private_key_encrypted FROM reserved_signing_keys \
         WHERE id = ? LIMIT 1",
    )
    .bind(key_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(key_id, public_key, private_key_encrypted)| RepoSigningKey {
            key_id,
            public_key,
            private_key_encrypted,
        },
    ))
}

/// Fetch the per-account signing key for a promoted DID (used to sign commits).
///
/// Only `'active'` rows are visible here: a `'staged'` rotation key must never
/// sign a commit (or be advertised) before the DID document repoints at it.
pub async fn get_signing_key_by_did(
    pool: &SqlitePool,
    did: &str,
) -> Result<Option<RepoSigningKey>, sqlx::Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key, private_key_encrypted FROM signing_keys \
         WHERE did = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(did)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(key_id, public_key, private_key_encrypted)| RepoSigningKey {
            key_id,
            public_key,
            private_key_encrypted,
        },
    ))
}

/// Stage a freshly generated rotation key for `did`, replacing any prior staged
/// key. Always a fresh insert (never reuse): in a compromise scenario a key
/// staged before the rotation began must be assumed known to the attacker.
///
/// Single-table two-statement operation, so it owns its own transaction.
pub async fn stage_rotation_key(
    pool: &SqlitePool,
    did: &str,
    key: &RepoSigningKey,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM signing_keys WHERE did = ? AND status = 'staged'")
        .bind(did)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO signing_keys \
         (id, did, key_type, public_key, private_key_encrypted, created_at, status) \
         VALUES (?, ?, 'p256', ?, ?, datetime('now'), 'staged')",
    )
    .bind(&key.key_id)
    .bind(did)
    .bind(&key.public_key)
    .bind(&key.private_key_encrypted)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Fetch the staged rotation key for `did`, if a rotation is in progress.
pub async fn get_staged_signing_key(
    pool: &SqlitePool,
    did: &str,
) -> Result<Option<RepoSigningKey>, sqlx::Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key, private_key_encrypted FROM signing_keys \
         WHERE did = ? AND status = 'staged' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(did)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(key_id, public_key, private_key_encrypted)| RepoSigningKey {
            key_id,
            public_key,
            private_key_encrypted,
        },
    ))
}

/// Rotation cutover: promote the staged key to active and delete the retired
/// active rows in one transaction. Deleting (rather than tombstoning) the old
/// rows is deliberate — after a rotation the old private key is either
/// compromised or lost, and commit verification only ever needs the public
/// keys recorded in the DID document history.
///
/// Returns `false` when no staged row with `staged_key_id` exists (nothing is
/// deleted in that case).
pub async fn promote_staged_signing_key(
    pool: &SqlitePool,
    did: &str,
    staged_key_id: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let promoted = sqlx::query(
        "UPDATE signing_keys SET status = 'active' \
         WHERE did = ? AND id = ? AND status = 'staged'",
    )
    .bind(did)
    .bind(staged_key_id)
    .execute(&mut *tx)
    .await?;
    if promoted.rows_affected() != 1 {
        // Nothing staged under that id — roll back rather than deleting the
        // account's only active key.
        return Ok(false);
    }
    sqlx::query("DELETE FROM signing_keys WHERE did = ? AND status = 'active' AND id != ?")
        .bind(did)
        .bind(staged_key_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn test_pool() -> SqlitePool {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        pool
    }

    async fn insert_pending_account(pool: &SqlitePool, account_id: &str) {
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(format!("CODE-{account_id}"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(account_id)
        .bind(format!("{account_id}@example.com"))
        .bind(format!("{account_id}.example.com"))
        .bind(format!("CODE-{account_id}"))
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_account(pool: &SqlitePool, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(pool)
        .await
        .unwrap();
    }

    fn sample_key() -> RepoSigningKey {
        RepoSigningKey {
            key_id: "did:key:zSampleRepoKey".to_string(),
            public_key: "zSamplePublicKey".to_string(),
            private_key_encrypted: "ZW5jcnlwdGVkLXByaXZhdGUta2V5LWJhc2U2NA".to_string(),
        }
    }

    #[tokio::test]
    async fn set_then_get_pending_repo_key() {
        let pool = test_pool().await;
        insert_pending_account(&pool, "acct-1").await;

        let key = sample_key();
        set_pending_repo_key(&pool, "acct-1", &key).await.unwrap();

        let got = get_pending_repo_key(&pool, "acct-1").await.unwrap();
        assert_eq!(got, Some(key));
    }

    #[tokio::test]
    async fn get_pending_repo_key_none_when_unset() {
        let pool = test_pool().await;
        insert_pending_account(&pool, "acct-2").await;

        let got = get_pending_repo_key(&pool, "acct-2").await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn insert_reserved_repo_key_is_idempotent_by_did() {
        let pool = test_pool().await;
        let key = sample_key();
        assert!(
            insert_reserved_repo_key(&pool, Some("did:plc:migrating"), &key)
                .await
                .unwrap()
        );

        let other = RepoSigningKey {
            key_id: "did:key:zOtherReservedKey".to_string(),
            public_key: "zOtherPublicKey".to_string(),
            private_key_encrypted: "b3RoZXItZW5jcnlwdGVk".to_string(),
        };
        assert!(
            !insert_reserved_repo_key(&pool, Some("did:plc:migrating"), &other)
                .await
                .unwrap()
        );

        let got = get_reserved_repo_key_by_did(&pool, "did:plc:migrating")
            .await
            .unwrap();
        assert_eq!(got, Some(key));
    }

    #[tokio::test]
    async fn reserved_repo_key_can_be_fetched_by_id() {
        let pool = test_pool().await;
        let key = sample_key();
        insert_reserved_repo_key(&pool, None, &key).await.unwrap();

        let got = get_reserved_repo_key_by_id(&pool, &key.key_id)
            .await
            .unwrap();
        assert_eq!(got, Some(key));
    }

    #[tokio::test]
    async fn insert_and_get_signing_key_by_did() {
        let pool = test_pool().await;
        insert_account(&pool, "did:plc:keyowner").await;

        let key = sample_key();
        insert_did_signing_key(&pool, "did:plc:keyowner", &key)
            .await
            .unwrap();

        let got = get_signing_key_by_did(&pool, "did:plc:keyowner")
            .await
            .unwrap();
        assert_eq!(got, Some(key));
    }

    #[tokio::test]
    async fn get_signing_key_by_did_none_when_absent() {
        let pool = test_pool().await;
        let got = get_signing_key_by_did(&pool, "did:plc:nobody")
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    fn other_key(suffix: &str) -> RepoSigningKey {
        RepoSigningKey {
            key_id: format!("did:key:zStaged{suffix}"),
            public_key: format!("zStagedPublic{suffix}"),
            private_key_encrypted: format!("c3RhZ2VkLWVuY3J5cHRlZC{suffix}"),
        }
    }

    #[tokio::test]
    async fn staged_key_is_invisible_to_active_lookup() {
        let pool = test_pool().await;
        insert_account(&pool, "did:plc:rotator").await;
        let active = sample_key();
        insert_did_signing_key(&pool, "did:plc:rotator", &active)
            .await
            .unwrap();

        let staged = other_key("A");
        stage_rotation_key(&pool, "did:plc:rotator", &staged)
            .await
            .unwrap();

        // The commit-signing lookup still sees the active key even though the
        // staged row is newer.
        let got = get_signing_key_by_did(&pool, "did:plc:rotator")
            .await
            .unwrap();
        assert_eq!(got, Some(active));
        let got_staged = get_staged_signing_key(&pool, "did:plc:rotator")
            .await
            .unwrap();
        assert_eq!(got_staged, Some(staged));
    }

    #[tokio::test]
    async fn staging_again_replaces_the_prior_staged_key() {
        let pool = test_pool().await;
        insert_account(&pool, "did:plc:restager").await;
        insert_did_signing_key(&pool, "did:plc:restager", &sample_key())
            .await
            .unwrap();

        let first = other_key("B");
        stage_rotation_key(&pool, "did:plc:restager", &first)
            .await
            .unwrap();
        let second = other_key("C");
        stage_rotation_key(&pool, "did:plc:restager", &second)
            .await
            .unwrap();

        let got = get_staged_signing_key(&pool, "did:plc:restager")
            .await
            .unwrap();
        assert_eq!(got, Some(second));
        // Exactly one staged row survives.
        let staged_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM signing_keys WHERE did = ? AND status = 'staged'",
        )
        .bind("did:plc:restager")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(staged_count, 1);
    }

    #[tokio::test]
    async fn promote_flips_staged_to_active_and_retires_the_old_key() {
        let pool = test_pool().await;
        insert_account(&pool, "did:plc:cutover").await;
        insert_did_signing_key(&pool, "did:plc:cutover", &sample_key())
            .await
            .unwrap();
        let staged = other_key("D");
        stage_rotation_key(&pool, "did:plc:cutover", &staged)
            .await
            .unwrap();

        let promoted = promote_staged_signing_key(&pool, "did:plc:cutover", &staged.key_id)
            .await
            .unwrap();
        assert!(promoted);

        // The staged key is now the (only) active key; the old row is gone.
        let got = get_signing_key_by_did(&pool, "did:plc:cutover")
            .await
            .unwrap();
        assert_eq!(got, Some(staged));
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signing_keys WHERE did = ?")
            .bind("did:plc:cutover")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(
            get_staged_signing_key(&pool, "did:plc:cutover")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn promote_without_a_matching_staged_key_changes_nothing() {
        let pool = test_pool().await;
        insert_account(&pool, "did:plc:nostage").await;
        let active = sample_key();
        insert_did_signing_key(&pool, "did:plc:nostage", &active)
            .await
            .unwrap();

        let promoted = promote_staged_signing_key(&pool, "did:plc:nostage", "did:key:zNoSuchKey")
            .await
            .unwrap();
        assert!(!promoted);
        // The active key is untouched.
        let got = get_signing_key_by_did(&pool, "did:plc:nostage")
            .await
            .unwrap();
        assert_eq!(got, Some(active));
    }
}
