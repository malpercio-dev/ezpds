// pattern: Imperative Shell

//! DID-scoped replay prevention for sovereign-session signed requests.

use common::SOVEREIGN_TIMESTAMP_WINDOW_SECS;
use sqlx::{Sqlite, SqlitePool};

/// The full interval during which one captured request can remain timestamp-valid when first
/// accepted at the early edge of the server's symmetric freshness window.
#[allow(dead_code)] // Retention invariant consumed when the background nonce sweep is wired.
pub const REPLAY_ACCEPTANCE_SPAN_SECS: i64 = 2 * SOVEREIGN_TIMESTAMP_WINDOW_SECS;

/// Atomically record `(did, nonce)`. Returns `true` only for the first insertion.
pub async fn insert_nonce_if_absent<'e, E>(
    executor: E,
    did: &str,
    nonce: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "INSERT OR IGNORE INTO sovereign_session_nonces (did, nonce, seen_at) \
         VALUES (?, ?, datetime('now'))",
    )
    .bind(did)
    .bind(nonce)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Delete stale nonce rows while preserving every nonce that could still accompany an accepted
/// signed-request timestamp.
///
/// Retention must be strictly greater than the full replay-acceptance span. The boundary itself
/// is unsafe because the delete predicate is inclusive.
#[allow(dead_code)] // Foundation for the background nonce sweep; insertion is already live.
pub async fn sweep_stale_nonces(
    pool: &SqlitePool,
    max_age_seconds: i64,
) -> Result<u64, sqlx::Error> {
    if max_age_seconds <= REPLAY_ACCEPTANCE_SPAN_SECS {
        return Err(sqlx::Error::Protocol(format!(
            "max_age_seconds must exceed the {REPLAY_ACCEPTANCE_SPAN_SECS}-second sovereign request replay-acceptance span"
        )));
    }
    let modifier = format!("-{max_age_seconds} seconds");
    let result =
        sqlx::query("DELETE FROM sovereign_session_nonces WHERE seen_at <= datetime('now', ?)")
            .bind(&modifier)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_pool, run_migrations};

    async fn test_pool() -> SqlitePool {
        let pool = open_pool("sqlite::memory:").await.unwrap();
        run_migrations(&pool).await.unwrap();
        for did in ["did:plc:alice", "did:plc:bob"] {
            sqlx::query(
                "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
                 VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
            )
            .bind(did)
            .bind(format!("{did}@example.com"))
            .execute(&pool)
            .await
            .unwrap();
        }
        pool
    }

    #[tokio::test]
    async fn duplicate_nonce_is_rejected_atomically() {
        let pool = test_pool().await;
        let (first, second) = tokio::join!(
            insert_nonce_if_absent(&pool, "did:plc:alice", "same"),
            insert_nonce_if_absent(&pool, "did:plc:alice", "same")
        );
        assert_ne!(first.unwrap(), second.unwrap());

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sovereign_session_nonces \
             WHERE did = 'did:plc:alice' AND nonce = 'same'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn nonce_uniqueness_is_isolated_per_did() {
        let pool = test_pool().await;
        assert!(insert_nonce_if_absent(&pool, "did:plc:alice", "shared")
            .await
            .unwrap());
        assert!(insert_nonce_if_absent(&pool, "did:plc:bob", "shared")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn nonce_requires_a_hosted_account_did() {
        let pool = test_pool().await;
        assert!(insert_nonce_if_absent(&pool, "did:plc:unknown", "nonce")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn sweep_rejects_unsafe_retention_and_preserves_fresh_rows() {
        let pool = test_pool().await;
        for (nonce, age) in [
            ("accepted", REPLAY_ACCEPTANCE_SPAN_SECS),
            ("stale", REPLAY_ACCEPTANCE_SPAN_SECS + 2),
        ] {
            sqlx::query(
                "INSERT INTO sovereign_session_nonces (did, nonce, seen_at) \
                 VALUES ('did:plc:alice', ?, datetime('now', ?))",
            )
            .bind(nonce)
            .bind(format!("-{age} seconds"))
            .execute(&pool)
            .await
            .unwrap();
        }

        assert!(sweep_stale_nonces(&pool, REPLAY_ACCEPTANCE_SPAN_SECS)
            .await
            .is_err());
        assert_eq!(
            sweep_stale_nonces(&pool, REPLAY_ACCEPTANCE_SPAN_SECS + 1)
                .await
                .unwrap(),
            1
        );
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT nonce FROM sovereign_session_nonces ORDER BY nonce")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, vec!["accepted"]);
    }
}
