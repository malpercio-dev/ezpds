// pattern: Imperative Shell

//! Per-account KEM key queries (V080, ADR-0043).
//!
//! The KEM key is the account's `#atproto_kem` verification method. A syncer reading a space
//! record combines it with a throwaway key of its own to agree a MAC secret with this host; the
//! key never signs anything. It is stored exactly like the repo signing key (same three homes,
//! same master-key AES-256-GCM wrapping, same `'active'`/`'staged'` lifecycle) but in its own
//! tables, so [`crate::repo_keys::get_signing_key_by_did`] can never return it. The SQL is shared
//! with [`crate::repo_keys`] through its `KeyFamily`; this module is the KEM family's surface.
//!
//! The private key is always encrypted by the caller before it reaches these functions.

use sqlx::{Sqlite, SqlitePool};

use crate::repo_keys::{self, KeyFamily};

/// A KEM key as stored: did:key id, multibase public key, and the AES-256-GCM-wrapped private
/// key. The shape is identical to a repo signing key's.
pub type KemKey = repo_keys::RepoSigningKey;

/// Store the DID ceremony's KEM key on the pending account.
pub async fn set_pending_kem_key(
    pool: &SqlitePool,
    account_id: &str,
    key: &KemKey,
) -> Result<(), sqlx::Error> {
    repo_keys::set_pending_key(pool, KeyFamily::Kem, account_id, key).await
}

/// The pending account's KEM key, or `None` before one is issued.
pub async fn get_pending_kem_key(
    pool: &SqlitePool,
    account_id: &str,
) -> Result<Option<KemKey>, sqlx::Error> {
    repo_keys::get_pending_key(pool, KeyFamily::Kem, account_id).await
}

/// Insert `key` as the account's active KEM key. Generic over the executor so it can run inside
/// an account-creation transaction.
pub async fn insert_active_kem_key<'e, E>(
    executor: E,
    did: &str,
    key: &KemKey,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    repo_keys::insert_active_key(executor, KeyFamily::Kem, did, key).await
}

/// Store a `reserveKemKey` reservation. Returns `false` when `did` already holds one.
pub async fn insert_reserved_kem_key(
    pool: &SqlitePool,
    did: Option<&str>,
    key: &KemKey,
) -> Result<bool, sqlx::Error> {
    repo_keys::insert_reserved_key(pool, KeyFamily::Kem, did, key).await
}

/// The reservation filed under `did`.
pub async fn get_reserved_kem_key_by_did(
    pool: &SqlitePool,
    did: &str,
) -> Result<Option<KemKey>, sqlx::Error> {
    repo_keys::get_reserved_key(pool, KeyFamily::Kem, "did", did).await
}

/// The reservation whose did:key is `key_id`.
pub async fn get_reserved_kem_key_by_id(
    pool: &SqlitePool,
    key_id: &str,
) -> Result<Option<KemKey>, sqlx::Error> {
    repo_keys::get_reserved_key(pool, KeyFamily::Kem, "id", key_id).await
}

/// The KEM key the account's DID document should publish, if it has one. Generic over the
/// executor so a caller holding a transaction can read through it.
pub async fn get_active_kem_key<'e, E>(
    executor: E,
    did: &str,
) -> Result<Option<KemKey>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    repo_keys::get_key_by_status(executor, KeyFamily::Kem, did, "active").await
}

/// The replacement KEM key waiting to be published, if a ceremony is in progress.
pub async fn get_staged_kem_key(
    pool: &SqlitePool,
    did: &str,
) -> Result<Option<KemKey>, sqlx::Error> {
    repo_keys::get_key_by_status(pool, KeyFamily::Kem, did, "staged").await
}

/// Stage a fresh KEM key, replacing any key staged earlier.
pub async fn stage_kem_key(pool: &SqlitePool, did: &str, key: &KemKey) -> Result<(), sqlx::Error> {
    repo_keys::stage_key(pool, KeyFamily::Kem, did, key).await
}

/// Make the staged key active and delete the one it replaces. `false` when nothing is staged
/// under `staged_key_id`.
pub async fn promote_staged_kem_key(
    pool: &SqlitePool,
    did: &str,
    staged_key_id: &str,
) -> Result<bool, sqlx::Error> {
    repo_keys::promote_staged_key(pool, KeyFamily::Kem, did, staged_key_id).await
}

/// Delete every KEM key the account holds, active and staged. Run when the account is
/// deactivated after migrating to another host: the new host publishes its own key, and this
/// host must not keep a secret for an identity it no longer serves.
pub async fn delete_kem_keys(pool: &SqlitePool, did: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM kem_keys WHERE did = ?")
        .bind(did)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::insert_bare_account;
    use crate::test_pool;

    fn key(suffix: &str) -> KemKey {
        KemKey {
            key_id: format!("did:key:zKem{suffix}"),
            public_key: format!("zKemPublic{suffix}"),
            private_key_encrypted: format!("a2VtLWVuY3J5cHRlZC{suffix}"),
        }
    }

    #[tokio::test]
    async fn kem_key_is_invisible_to_the_commit_signer_lookup() {
        let pool = test_pool().await;
        insert_bare_account(&pool, "did:plc:kemowner").await;
        insert_active_kem_key(&pool, "did:plc:kemowner", &key("A"))
            .await
            .unwrap();

        assert_eq!(
            get_active_kem_key(&pool, "did:plc:kemowner").await.unwrap(),
            Some(key("A"))
        );
        assert_eq!(
            repo_keys::get_signing_key_by_did(&pool, "did:plc:kemowner")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn stage_then_promote_replaces_the_active_key() {
        let pool = test_pool().await;
        insert_bare_account(&pool, "did:plc:kemrotate").await;
        insert_active_kem_key(&pool, "did:plc:kemrotate", &key("A"))
            .await
            .unwrap();
        stage_kem_key(&pool, "did:plc:kemrotate", &key("B"))
            .await
            .unwrap();
        stage_kem_key(&pool, "did:plc:kemrotate", &key("C"))
            .await
            .unwrap();

        assert!(
            !promote_staged_kem_key(&pool, "did:plc:kemrotate", "did:key:zKemB")
                .await
                .unwrap()
        );
        assert!(
            promote_staged_kem_key(&pool, "did:plc:kemrotate", "did:key:zKemC")
                .await
                .unwrap()
        );

        assert_eq!(
            get_active_kem_key(&pool, "did:plc:kemrotate")
                .await
                .unwrap(),
            Some(key("C"))
        );
        assert_eq!(
            get_staged_kem_key(&pool, "did:plc:kemrotate")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            delete_kem_keys(&pool, "did:plc:kemrotate").await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn reservations_are_idempotent_by_did_and_found_by_id() {
        let pool = test_pool().await;
        assert!(
            insert_reserved_kem_key(&pool, Some("did:plc:incoming"), &key("A"))
                .await
                .unwrap()
        );
        assert!(
            !insert_reserved_kem_key(&pool, Some("did:plc:incoming"), &key("B"))
                .await
                .unwrap()
        );
        insert_reserved_kem_key(&pool, None, &key("C"))
            .await
            .unwrap();

        assert_eq!(
            get_reserved_kem_key_by_did(&pool, "did:plc:incoming")
                .await
                .unwrap(),
            Some(key("A"))
        );
        assert_eq!(
            get_reserved_kem_key_by_id(&pool, "did:key:zKemC")
                .await
                .unwrap(),
            Some(key("C"))
        );
    }
}
