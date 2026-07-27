// pattern: Imperative Shell
//
// Enrollment grants. Status is derived from the timestamps at query time (the pds crate's
// claim_codes doctrine) and redemption is one guarded UPDATE (the `consume_pairing_code`
// shape): the WHERE clause carries the whole "unconsumed and unexpired" precondition, so
// two nodes racing on the same code cannot both win.

use sqlx::{Sqlite, SqlitePool};

/// Insert a freshly minted code valid for `ttl_secs`. Returns its expiry as stored.
pub async fn insert_code(
    db: &SqlitePool,
    code: &str,
    ttl_secs: i64,
) -> Result<String, sqlx::Error> {
    sqlx::query(
        "INSERT INTO enrollment_codes (code, created_at, expires_at) \
         VALUES (?, datetime('now'), datetime('now', ?))",
    )
    .bind(code)
    // SQLite's modifier takes an optional sign, so a negative TTL (tests exercising an
    // already-expired grant) formats as validly as a positive one.
    .bind(format!("{ttl_secs} seconds"))
    .execute(db)
    .await?;

    sqlx::query_scalar("SELECT expires_at FROM enrollment_codes WHERE code = ?")
        .bind(code)
        .fetch_one(db)
        .await
}

/// Atomically redeem `code` for `node_id`. Returns false when the code is unknown,
/// already consumed, or expired — the caller reports all three identically, so a probe
/// learns nothing about which codes exist.
///
/// Generic over the executor so redemption and the enrollment insert share one transaction.
pub async fn consume_code<'e, E>(
    executor: E,
    code: &str,
    node_id: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(
        "UPDATE enrollment_codes \
         SET consumed_at = datetime('now'), consumed_by_node = ? \
         WHERE code = ? AND consumed_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(node_id)
    .bind(code)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;

    #[tokio::test]
    async fn a_valid_code_is_consumed_exactly_once() {
        let pool = test_pool().await;
        insert_code(&pool, "GRANT-1", 3600).await.expect("mint");

        assert!(consume_code(&pool, "GRANT-1", "node-a")
            .await
            .expect("first redemption"));
        assert!(
            !consume_code(&pool, "GRANT-1", "node-b")
                .await
                .expect("second redemption"),
            "a consumed code must never redeem again"
        );

        let owner: Option<String> =
            sqlx::query_scalar("SELECT consumed_by_node FROM enrollment_codes WHERE code = ?")
                .bind("GRANT-1")
                .fetch_one(&pool)
                .await
                .expect("read");
        assert_eq!(owner.as_deref(), Some("node-a"));
    }

    #[tokio::test]
    async fn an_expired_code_is_refused() {
        let pool = test_pool().await;
        insert_code(&pool, "STALE", -60).await.expect("mint");
        assert!(!consume_code(&pool, "STALE", "node-a")
            .await
            .expect("redeem"));
    }

    #[tokio::test]
    async fn an_unknown_code_is_refused() {
        let pool = test_pool().await;
        assert!(!consume_code(&pool, "NEVER-MINTED", "node-a")
            .await
            .expect("redeem"));
    }
}
