// pattern: Imperative Shell

//! Offline master-key (KEK) re-wrap: decrypt every KEK-wrapped secret with the
//! old master key and re-encrypt it under a new one, in one transaction.
//!
//! This changes no underlying key material — the same P-256 repo keys, OAuth
//! key, JWT secret, Iroh identity, and recovery shares come back out; only the AES-256-GCM
//! envelope around each one is replaced. No PLC operation, no firehose event,
//! no network effect. It exists so the operator can rotate
//! `EZPDS_SIGNING_KEY_MASTER_KEY` (proactively, or after suspected exposure of
//! the key alone) without destroying the wrapped keys.
//!
//! Invoked by the `pds rewrap-master-key` subcommand (`main.rs`) while the
//! server is stopped — the single-connection pool means a running server and
//! this tool cannot share the DB anyway. Atomicity contract: any blob that
//! fails to decrypt with the old key (wrong key, foreign ciphertext) aborts
//! the whole transaction, so the DB is always uniformly under exactly one key.

use sqlx::SqlitePool;

use crate::db::kek::{
    get_kek_generation, list_wrapped_secrets, set_kek_generation, update_wrapped_secret,
    SecretFamily,
};

/// What one completed re-wrap did: per-table re-encrypted row counts plus the
/// KEK generation recorded in `server_metadata`.
#[derive(Debug)]
pub struct RewrapReport {
    /// `(table name, rows re-wrapped)` for every [`SecretFamily`], in sweep order.
    pub families: Vec<(&'static str, u64)>,
    /// The generation written by this run (previous value + 1).
    pub kek_generation: i64,
}

impl RewrapReport {
    /// Total rows re-encrypted across all families.
    pub fn total(&self) -> u64 {
        self.families.iter().map(|(_, n)| n).sum()
    }
}

/// Re-encrypt every KEK-wrapped secret from `old_key` to `new_key` in one
/// transaction.
///
/// Fails without writing anything if any stored blob does not decrypt under
/// `old_key`. When that happens because the blob already decrypts under
/// `new_key`, the error says so — the usual cause is re-running the tool after
/// a completed rotation.
pub async fn rewrap_master_key(
    pool: &SqlitePool,
    old_key: &[u8; 32],
    new_key: &[u8; 32],
) -> anyhow::Result<RewrapReport> {
    if old_key == new_key {
        anyhow::bail!("old and new master keys are identical; nothing to rotate");
    }

    let mut tx = pool.begin().await?;

    let mut families = Vec::with_capacity(SecretFamily::ALL.len());
    for family in SecretFamily::ALL {
        let rows = list_wrapped_secrets(&mut *tx, family).await?;
        let mut rewrapped = 0u64;
        for row in rows {
            // The generic-length decrypt/encrypt pair shares the fixed-length envelope, so
            // 32-byte key scalars and longer secrets (the 42-byte escrow share envelope)
            // re-wrap through one code path.
            let plaintext = match crypto::decrypt_secret_bytes(&row.ciphertext, old_key) {
                Ok(p) => p,
                Err(e) => {
                    // Distinguish "wrong old key" from "rotation already done":
                    // a blob that decrypts under the NEW key means a prior run
                    // committed and the operator is re-running with stale keys.
                    if crypto::decrypt_secret_bytes(&row.ciphertext, new_key).is_ok() {
                        anyhow::bail!(
                            "{} row {} is already encrypted under the NEW key — a previous \
                             rotation appears to have completed; no changes were made",
                            family.table(),
                            row.id
                        );
                    }
                    anyhow::bail!(
                        "failed to decrypt {} row {} with the OLD key ({e}); wrong old key? \
                         no changes were made",
                        family.table(),
                        row.id
                    );
                }
            };
            let reencrypted = crypto::encrypt_secret_bytes(&plaintext, new_key)
                .map_err(|e| anyhow::anyhow!("re-encryption failed: {e}"))?;
            update_wrapped_secret(&mut *tx, family, &row.id, &reencrypted).await?;
            rewrapped += 1;
        }
        families.push((family.table(), rewrapped));
    }

    let kek_generation = get_kek_generation(&mut *tx).await? + 1;
    set_kek_generation(&mut *tx, kek_generation).await?;

    tx.commit().await?;
    Ok(RewrapReport {
        families,
        kek_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    const OLD_KEY: [u8; 32] = [0x11; 32];
    const NEW_KEY: [u8; 32] = [0x22; 32];
    const WRONG_KEY: [u8; 32] = [0x33; 32];

    async fn test_pool() -> SqlitePool {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        pool
    }

    fn enc(plaintext: &[u8], key: &[u8; 32]) -> String {
        crypto::encrypt_secret_bytes(plaintext, key).unwrap()
    }

    /// Seed one row in every KEK-wrapped table, each wrapping a distinct
    /// plaintext under `key`. Returns the per-family plaintexts keyed by table.
    /// `recovery_escrow` gets a 42-byte plaintext (a share envelope's length)
    /// so the sweep's variable-length path is exercised; the key columns stay
    /// 32 bytes.
    async fn seed_all_families(pool: &SqlitePool, key: &[u8; 32]) -> Vec<(&'static str, Vec<u8>)> {
        let mut plaintexts = Vec::new();
        for (i, family) in SecretFamily::ALL.iter().enumerate() {
            let len = if *family == SecretFamily::RecoveryEscrow {
                42
            } else {
                32
            };
            let mut p = vec![0u8; len];
            p[0] = 0x40 + i as u8;
            plaintexts.push((family.table(), p));
        }
        let pt = |table: &str| {
            plaintexts
                .iter()
                .find(|(t, _)| *t == table)
                .map(|(_, p)| p.clone())
                .unwrap()
        };

        // signing_keys needs an accounts row (FK).
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:rewraptest', 'rewrap@example.com', 'hash', \
                     datetime('now'), datetime('now'))",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("UPDATE accounts SET recovery_share = ? WHERE did = 'did:plc:rewraptest'")
            .bind(enc(&pt("accounts.recovery_share"), key))
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO signing_keys \
             (id, did, key_type, public_key, private_key_encrypted, created_at) \
             VALUES ('did:key:zSigning', 'did:plc:rewraptest', 'p256', 'zPub1', ?, \
                     datetime('now'))",
        )
        .bind(enc(&pt("signing_keys"), key))
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO reserved_signing_keys \
             (id, did, key_type, public_key, private_key_encrypted, created_at) \
             VALUES ('did:key:zReserved', NULL, 'p256', 'zPub2', ?, datetime('now'))",
        )
        .bind(enc(&pt("reserved_signing_keys"), key))
        .execute(pool)
        .await
        .unwrap();

        // pending_accounts needs a claim_codes row (FK). Seed one row WITH a
        // repo key and one without (the NULL row must be left untouched).
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES ('REWRAP-CODE', datetime('now', '+1 hour'), datetime('now')), \
                    ('REWRAP-CODE-2', datetime('now', '+1 hour'), datetime('now'))",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pending_accounts \
             (id, email, handle, tier, claim_code, created_at, \
              repo_signing_key_id, repo_signing_public_key, \
              repo_signing_private_key_encrypted) \
             VALUES ('pending-1', 'p1@example.com', 'p1.example.com', 'free', \
                     'REWRAP-CODE', datetime('now'), 'did:key:zPending', 'zPub3', ?)",
        )
        .bind(enc(&pt("pending_accounts"), key))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES ('pending-2', 'p2@example.com', 'p2.example.com', 'free', \
                     'REWRAP-CODE-2', datetime('now'))",
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO relay_signing_keys \
             (id, algorithm, public_key, private_key_encrypted, created_at) \
             VALUES ('did:key:zRelay', 'p256', 'zPub4', ?, datetime('now'))",
        )
        .bind(enc(&pt("relay_signing_keys"), key))
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO oauth_signing_key \
             (id, public_key_jwk, private_key_encrypted, created_at) \
             VALUES ('oauth-key-1', '{}', ?, datetime('now'))",
        )
        .bind(enc(&pt("oauth_signing_key"), key))
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO jwt_signing_secret (id, secret_encrypted, created_at) \
             VALUES ('jwt-key-1', ?, datetime('now'))",
        )
        .bind(enc(&pt("jwt_signing_secret"), key))
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO iroh_identity (id, secret_key_encrypted, created_at) \
             VALUES ('iroh-key-1', ?, datetime('now'))",
        )
        .bind(enc(&pt("iroh_identity"), key))
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO recovery_escrow (did, share_encrypted, created_at) \
             VALUES ('did:plc:rewraptest', ?, datetime('now'))",
        )
        .bind(enc(&pt("recovery_escrow"), key))
        .execute(pool)
        .await
        .unwrap();

        plaintexts
    }

    /// Read back every wrapped blob and assert it decrypts to the seeded
    /// plaintext under `key` (and fails under `not_key`).
    async fn assert_all_under_key(
        pool: &SqlitePool,
        plaintexts: &[(&'static str, Vec<u8>)],
        key: &[u8; 32],
        not_key: &[u8; 32],
    ) {
        for family in SecretFamily::ALL {
            let rows = list_wrapped_secrets(pool, family).await.unwrap();
            assert_eq!(
                rows.len(),
                1,
                "{} should hold one wrapped row",
                family.table()
            );
            let expected = plaintexts
                .iter()
                .find(|(t, _)| *t == family.table())
                .map(|(_, p)| p.clone())
                .unwrap();
            let decrypted = crypto::decrypt_secret_bytes(&rows[0].ciphertext, key)
                .unwrap_or_else(|e| panic!("{} must decrypt under key: {e}", family.table()));
            assert_eq!(
                *decrypted,
                expected,
                "{} plaintext mismatch",
                family.table()
            );
            assert!(
                crypto::decrypt_secret_bytes(&rows[0].ciphertext, not_key).is_err(),
                "{} must not decrypt under the other key",
                family.table()
            );
        }
    }

    #[tokio::test]
    async fn rewrap_reencrypts_every_family_under_the_new_key() {
        let pool = test_pool().await;
        let plaintexts = seed_all_families(&pool, &OLD_KEY).await;

        let report = rewrap_master_key(&pool, &OLD_KEY, &NEW_KEY).await.unwrap();

        assert_eq!(report.total(), SecretFamily::ALL.len() as u64);
        for (table, count) in &report.families {
            assert_eq!(*count, 1, "{table} should report one re-wrapped row");
        }
        assert_eq!(report.kek_generation, 1);
        assert_all_under_key(&pool, &plaintexts, &NEW_KEY, &OLD_KEY).await;

        // The NULL pending row is untouched.
        let (null_key,): (Option<String>,) = sqlx::query_as(
            "SELECT repo_signing_private_key_encrypted FROM pending_accounts \
             WHERE id = 'pending-2'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(null_key, None);
    }

    #[tokio::test]
    async fn wrong_old_key_aborts_with_no_partial_writes() {
        let pool = test_pool().await;
        let plaintexts = seed_all_families(&pool, &OLD_KEY).await;

        let err = rewrap_master_key(&pool, &WRONG_KEY, &NEW_KEY)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("wrong old key"),
            "error should point at the old key: {err}"
        );

        // Everything still decrypts under the real old key, nothing under new.
        assert_all_under_key(&pool, &plaintexts, &OLD_KEY, &NEW_KEY).await;
        assert_eq!(get_kek_generation(&pool).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn rerun_after_completed_rotation_reports_already_rotated() {
        let pool = test_pool().await;
        seed_all_families(&pool, &OLD_KEY).await;
        rewrap_master_key(&pool, &OLD_KEY, &NEW_KEY).await.unwrap();

        let err = rewrap_master_key(&pool, &OLD_KEY, &NEW_KEY)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("already encrypted under the NEW key"),
            "re-run should be diagnosed as a completed rotation: {err}"
        );
        assert_eq!(get_kek_generation(&pool).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn identical_keys_are_rejected() {
        let pool = test_pool().await;
        let err = rewrap_master_key(&pool, &OLD_KEY, &OLD_KEY)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("identical"));
    }

    #[tokio::test]
    async fn empty_database_rewrap_succeeds_and_bumps_generation() {
        let pool = test_pool().await;
        let report = rewrap_master_key(&pool, &OLD_KEY, &NEW_KEY).await.unwrap();
        assert_eq!(report.total(), 0);
        assert_eq!(report.kek_generation, 1);

        let second = rewrap_master_key(&pool, &NEW_KEY, &OLD_KEY).await.unwrap();
        assert_eq!(second.kek_generation, 2);
    }

    /// The end-to-end acceptance shape: seed via the real load-or-create
    /// paths, rotate, and confirm the server-side loaders come back with the
    /// same secrets under the new key while the old key is refused.
    #[tokio::test]
    async fn server_loaders_round_trip_across_a_rotation() {
        use crate::auth::{load_or_create_iroh_secret_key, load_or_create_jwt_secret};

        let pool = test_pool().await;
        let jwt_before = load_or_create_jwt_secret(&pool, Some(&OLD_KEY))
            .await
            .unwrap();
        let iroh_before = load_or_create_iroh_secret_key(&pool, Some(&OLD_KEY))
            .await
            .unwrap();

        rewrap_master_key(&pool, &OLD_KEY, &NEW_KEY).await.unwrap();

        let jwt_after = load_or_create_jwt_secret(&pool, Some(&NEW_KEY))
            .await
            .unwrap();
        let iroh_after = load_or_create_iroh_secret_key(&pool, Some(&NEW_KEY))
            .await
            .unwrap();
        assert_eq!(
            jwt_before, jwt_after,
            "JWT secret must survive the rotation"
        );
        assert_eq!(
            iroh_before, iroh_after,
            "Iroh identity must survive the rotation"
        );

        assert!(
            load_or_create_jwt_secret(&pool, Some(&OLD_KEY))
                .await
                .is_err(),
            "old key must no longer decrypt the JWT secret"
        );
    }
}
