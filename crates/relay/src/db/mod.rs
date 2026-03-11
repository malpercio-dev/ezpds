// pattern: Imperative Shell
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

/// Errors from database pool creation or migration execution.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("failed to open database pool: {0}")]
    Pool(#[from] sqlx::Error),
    /// Errors in migration infrastructure (bootstrap table, transaction control).
    /// Distinct from `Migration` so operators know there is no version 0 to look for.
    #[error("failed to initialize migration infrastructure: {0}")]
    Setup(sqlx::Error),
    #[error("migration v{version} failed: {source}")]
    Migration { version: u32, source: sqlx::Error },
}

struct Migration {
    version: u32,
    sql: &'static str,
}

static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: include_str!("migrations/V001__init.sql"),
}];

/// Open a WAL-mode SQLite connection pool with a maximum of 1 connection.
///
/// Accepts any sqlx URL string (e.g. `"sqlite:relay.db"`, `"sqlite::memory:"`).
/// `create_if_missing` is enabled so the file is created on first run.
/// WAL journal mode is set via `SqliteConnectOptions` — not a raw PRAGMA — so
/// sqlx tracks the mode across the connection lifecycle.
pub async fn open_pool(url: &str) -> Result<SqlitePool, DbError> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);

    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .map_err(DbError::Pool)
}

/// Apply any pending migrations from `MIGRATIONS` to the given pool.
///
/// Creates `schema_migrations` if it does not exist, reads which versions
/// are already recorded, then applies all pending migrations in a single
/// transaction and records each applied version.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), DbError> {
    // Bootstrap the tracking table before any migration SQL runs.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        ) WITHOUT ROWID",
    )
    .execute(pool)
    .await
    .map_err(DbError::Setup)?;

    // Fetch already-applied versions.
    let applied: Vec<(i32,)> = sqlx::query_as("SELECT version FROM schema_migrations")
        .fetch_all(pool)
        .await
        .map_err(DbError::Setup)?;
    let applied_set: std::collections::HashSet<u32> =
        applied.into_iter().map(|(v,)| v as u32).collect();

    // Collect pending migrations in order.
    let pending: Vec<&Migration> = MIGRATIONS
        .iter()
        .filter(|m| !applied_set.contains(&m.version))
        .collect();

    if pending.is_empty() {
        return Ok(());
    }

    // Apply all pending migrations in one transaction.
    let mut tx = pool.begin().await.map_err(DbError::Setup)?;

    for migration in pending {
        // Use raw_sql (not query) so multi-statement SQL files execute fully.
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
        .bind(migration.version as i32)
        .execute(&mut *tx)
        .await
        .map_err(|e| DbError::Migration {
            version: migration.version,
            source: e,
        })?;
    }

    tx.commit().await.map_err(DbError::Setup)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Open a fresh in-memory pool for each test.
    /// Uses "sqlite::memory:" — no files created on disk.
    async fn in_memory_pool() -> SqlitePool {
        open_pool("sqlite::memory:")
            .await
            .expect("failed to open in-memory pool")
    }

    #[tokio::test]
    async fn select_one_succeeds() {
        let pool = in_memory_pool().await;
        let (n,): (i64,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn migrations_apply_on_first_run() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    /// MM-72.AC2.1: Running migrations twice leaves only one row in schema_migrations.
    #[tokio::test]
    async fn migrations_are_idempotent() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap(); // second call — must be a no-op

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "second run must not insert a duplicate migration row"
        );
    }

    /// MM-72.AC2.2: schema_migrations records version=1 with a non-null applied_at.
    #[tokio::test]
    async fn schema_migrations_records_version_and_timestamp() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let (version, applied_at): (i64, String) =
            sqlx::query_as("SELECT version, applied_at FROM schema_migrations WHERE version = 1")
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(version, 1);
        assert!(!applied_at.is_empty(), "applied_at must be non-empty");
    }

    #[tokio::test]
    async fn server_metadata_table_exists_and_accepts_inserts() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query("INSERT INTO server_metadata (key, value) VALUES ('test_key', 'test_value')")
            .execute(&pool)
            .await
            .unwrap();

        let (value,): (String,) =
            sqlx::query_as("SELECT value FROM server_metadata WHERE key = 'test_key'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(value, "test_value");
    }

    /// MM-72.AC4.1: WAL mode requires a real file — use tempfile here, not :memory:.
    /// In-memory SQLite reports journal_mode = "memory", not "wal".
    #[tokio::test]
    async fn wal_mode_enabled_on_file_pool() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_wal.db");
        let url = format!("sqlite:{}", db_path.display());

        let pool = open_pool(&url).await.unwrap();

        let (mode,): (String,) = sqlx::query_as("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(mode, "wal", "pool must use WAL journal mode");
    }
}
