// pattern: Imperative Shell
//
// Pool setup and the migration runner, mirroring the pds crate's `db/mod.rs`. Submodules
// own their tables' queries and never open transactions of their own unless the operation
// is single-table; the cross-table sequences (redeem a code *and* record the enrollment)
// live in `service.rs`.

pub mod enrollment_codes;
pub mod enrollments;
pub mod handles;
mod migrations;

use migrations::{Migration, MIGRATIONS};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

/// Errors from pool creation or migration execution.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("invalid database URL: {0}")]
    InvalidUrl(String),
    #[error("failed to open database pool: {0}")]
    Pool(sqlx::Error),
    #[error("failed to initialize migration infrastructure ({step}): {source}")]
    Setup {
        step: &'static str,
        source: sqlx::Error,
    },
    #[error("migration v{version} failed: {source}")]
    Migration { version: u32, source: sqlx::Error },
}

/// Open a WAL-mode SQLite pool with a single connection, the pds crate's posture.
pub async fn open_pool(url: &str) -> Result<SqlitePool, DbError> {
    let opts = SqliteConnectOptions::from_str(url)
        .map_err(|e| DbError::InvalidUrl(e.to_string()))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(DbError::Pool)
}

/// Apply every pending migration in one transaction. Safe to re-run.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), DbError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        ) WITHOUT ROWID",
    )
    .execute(pool)
    .await
    .map_err(|e| DbError::Setup {
        step: "create schema_migrations table",
        source: e,
    })?;

    let applied: Vec<(i64,)> = sqlx::query_as("SELECT version FROM schema_migrations")
        .fetch_all(pool)
        .await
        .map_err(|e| DbError::Setup {
            step: "fetch applied versions",
            source: e,
        })?;
    let applied_set: std::collections::HashSet<u32> = applied
        .into_iter()
        .map(|(v,)| {
            u32::try_from(v).map_err(|_| DbError::Setup {
                step: "parse migration version from schema_migrations",
                source: sqlx::Error::Protocol(format!("version {v} does not fit in u32")),
            })
        })
        .collect::<Result<_, _>>()?;

    let pending: Vec<&Migration> = MIGRATIONS
        .iter()
        .filter(|m| !applied_set.contains(&m.version))
        .collect();
    if pending.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await.map_err(|e| DbError::Setup {
        step: "begin transaction",
        source: e,
    })?;
    for migration in pending {
        tracing::info!(version = migration.version, "applying migration");
        // raw_sql (not query) so multi-statement SQL files execute fully.
        sqlx::raw_sql(migration.sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| DbError::Migration {
                version: migration.version,
                source: e,
            })?;
        sqlx::query(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, datetime('now'))",
        )
        .bind(i64::from(migration.version))
        .execute(&mut *tx)
        .await
        .map_err(|e| DbError::Migration {
            version: migration.version,
            source: e,
        })?;
    }
    tx.commit().await.map_err(|e| DbError::Setup {
        step: "commit transaction",
        source: e,
    })?;

    Ok(())
}

/// An in-memory, migrated pool for tests.
#[cfg(test)]
pub(crate) async fn test_pool() -> SqlitePool {
    let pool = open_pool("sqlite::memory:").await.expect("open test pool");
    run_migrations(&pool).await.expect("migrate test pool");
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_versions_are_sequential_from_one() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                migration.version,
                u32::try_from(index + 1).expect("small index"),
                "migration versions must be sequential positive integers starting at 1"
            );
        }
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let pool = test_pool().await;
        run_migrations(&pool).await.expect("re-running is a no-op");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(count, MIGRATIONS.len() as i64);
    }
}
