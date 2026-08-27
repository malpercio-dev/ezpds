// pattern: Imperative Shell

//! Single-use `jti` replay protection for the spaces token surfaces — the
//! `space_jti_replay` table (V065).
//!
//! The `(scope, jti)` primary key is the replay defense: only the first insert
//! for a given scope reports `true`, and the writer stamps `expires_at` with
//! the token's own acceptance horizon (a delegation token's ~60 s validity, a
//! DPoP proof's `iat` recency window). The periodic sweep
//! (`space_jti_sweep.rs`) is storage reclamation only — a row is deleted only
//! once no token carrying its jti could still be accepted.

use sqlx::{Sqlite, SqlitePool};

/// Which token surface a jti was spent on. A jti spent on one surface is
/// independent of the same string on another (the table key is `(scope, jti)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceJtiScope {
    /// `getSpaceCredential`'s single-use delegation tokens.
    Delegation,
    /// Client attestation JWTs.
    Attestation,
    /// Per-request DPoP proofs on credential-authed sync calls.
    Dpop,
}

impl SpaceJtiScope {
    fn as_str(self) -> &'static str {
        match self {
            SpaceJtiScope::Delegation => "delegation",
            SpaceJtiScope::Attestation => "attestation",
            SpaceJtiScope::Dpop => "dpop",
        }
    }
}

/// Atomically record a spent jti, retained for `ttl_secs` (the token's
/// acceptance horizon). Returns `true` only for the first insertion — a
/// `false` is a replay and the caller must reject the request.
pub async fn insert_jti_if_absent<'e, E>(
    executor: E,
    scope: SpaceJtiScope,
    jti: &str,
    ttl_secs: i64,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let modifier = format!("+{ttl_secs} seconds");
    let result = sqlx::query(
        "INSERT INTO space_jti_replay (scope, jti, expires_at) \
         VALUES (?, ?, datetime('now', ?)) \
         ON CONFLICT DO NOTHING",
    )
    .bind(scope.as_str())
    .bind(jti)
    .bind(&modifier)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Delete rows whose acceptance horizon has passed. Safe at any time: a token
/// carrying a swept jti is already rejected on its own expiry before the
/// replay check matters.
pub async fn sweep_expired_jtis(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM space_jti_replay WHERE expires_at <= datetime('now')")
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
        pool
    }

    #[tokio::test]
    async fn duplicate_jti_rejected_per_scope_and_sweep_reclaims_expired() {
        let pool = test_pool().await;

        assert!(
            insert_jti_if_absent(&pool, SpaceJtiScope::Delegation, "jti-1", 60)
                .await
                .unwrap()
        );
        assert!(
            !insert_jti_if_absent(&pool, SpaceJtiScope::Delegation, "jti-1", 60)
                .await
                .unwrap(),
            "second spend of the same (scope, jti) must be a replay"
        );
        // The same string on a different surface is an independent jti.
        assert!(
            insert_jti_if_absent(&pool, SpaceJtiScope::Dpop, "jti-1", 60)
                .await
                .unwrap()
        );

        // An already-expired row is reclaimed; unexpired rows survive.
        sqlx::query(
            "INSERT INTO space_jti_replay (scope, jti, expires_at) \
             VALUES ('attestation', 'stale', datetime('now', '-1 seconds'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(sweep_expired_jtis(&pool).await.unwrap(), 1);
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM space_jti_replay")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 2);
    }
}
