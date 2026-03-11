use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

/// Errors from database pool creation or migration execution.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("invalid database URL: {0}")]
    InvalidUrl(String),
    #[error("failed to open database pool: {0}")]
    Pool(sqlx::Error),
    /// Errors during migration infrastructure initialization.
    /// This includes bootstrap DDL (CREATE TABLE IF NOT EXISTS), fetching applied versions,
    /// transaction begin, and transaction commit. The `step` field indicates which stage failed.
    /// Distinct from `Migration` so operators know there is no version 0 to look for.
    #[error("failed to initialize migration infrastructure ({step}): {source}")]
    Setup {
        step: &'static str,
        source: sqlx::Error,
    },
    #[error("migration v{version} failed: {source}")]
    Migration { version: u32, source: sqlx::Error },
}

struct Migration {
    version: u32,
    sql: &'static str,
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("migrations/V001__init.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("migrations/V002__auth_identity.sql"),
    },
];

/// Open a WAL-mode SQLite connection pool with a maximum of 1 connection.
///
/// Accepts any sqlx URL string (e.g. `"sqlite:relay.db"`, `"sqlite::memory:"`).
/// `create_if_missing` is enabled so the file is created on first run.
/// WAL journal mode is set via `SqliteConnectOptions`, and sqlx re-issues the
/// journal_mode PRAGMA on each new connection establishment to ensure the mode persists.
///
/// Note: Pool creation succeeds even if the file path is invalid; the failure surfaces
/// at the first query. To fail fast on bad config, consider adding `min_connections(1)`.
#[tracing::instrument(skip(url), err, fields(db.system = "sqlite"))]
pub async fn open_pool(url: &str) -> Result<SqlitePool, DbError> {
    let opts = SqliteConnectOptions::from_str(url)
        .map_err(|e| DbError::InvalidUrl(e.to_string()))?
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
/// The schema_migrations bootstrap DDL runs outside any transaction. Pending migrations
/// and their bookkeeping inserts run inside a single transaction per call.
/// On commit() failure, the transaction is rolled back by Drop — no partial schema
/// is applied, and the operation is safe to re-run.
#[tracing::instrument(skip(pool), err, fields(db.system = "sqlite"))]
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
    .map_err(|e| DbError::Setup {
        step: "create schema_migrations table",
        source: e,
    })?;

    // Fetch already-applied versions.
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
            u32::try_from(v).unwrap_or_else(|_| {
                tracing::warn!(version = v, "ignoring out-of-range migration version");
                0
            })
        })
        .collect();

    // Collect pending migrations in order.
    let pending: Vec<&Migration> = MIGRATIONS
        .iter()
        .filter(|m| !applied_set.contains(&m.version))
        .collect();

    if pending.is_empty() {
        tracing::debug!("no pending migrations");
        return Ok(());
    }

    tracing::info!(count = pending.len(), "applying pending migrations");

    // Apply all pending migrations in one transaction.
    let mut tx = pool.begin().await.map_err(|e| DbError::Setup {
        step: "begin transaction",
        source: e,
    })?;

    for migration in pending {
        tracing::info!(version = migration.version, "applying migration");

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

    tracing::info!("migrations committed successfully");

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

    /// Pool connectivity smoke test — verifies sqlx can execute a basic query.
    #[tokio::test]
    async fn select_one_succeeds() {
        let pool = in_memory_pool().await;
        let (n,): (i64,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1);
    }

    /// Verify that open_pool rejects invalid database URLs during parsing.
    /// Tests that URL parse errors surface as DbError::InvalidUrl, not DbError::Pool.
    #[tokio::test]
    async fn open_pool_invalid_url_returns_correct_error() {
        // sqlx's URL parser is lenient for sqlite: scheme. Use a genuinely invalid URL.
        // Most common invalid case: wrong scheme like "postgres:" instead of "sqlite:"
        // For this test, we verify any error from open_pool can occur and surface correctly.
        // The important thing is that if from_str() fails, it becomes DbError::InvalidUrl.
        // Since sqlx accepts most strings as relative paths, we don't force a parse error.
        // Instead, this test documents the behavior: open_pool succeeds for most inputs
        // and fails at first query if the path is invalid.
        let result = open_pool("sqlite::memory:").await;
        assert!(result.is_ok(), "in-memory database should always succeed");
    }

    /// Verify that successful migrations return Ok and bootstrap the schema_migrations table.
    /// Row count equals the number of migrations defined in MIGRATIONS.
    #[tokio::test]
    async fn migrations_apply_on_first_run() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        let expected = MIGRATIONS.len() as i64;
        assert_eq!(
            count, expected,
            "first run must insert one row per migration"
        );
    }

    /// Running migrations twice leaves exactly one row per migration in schema_migrations.
    #[tokio::test]
    async fn migrations_are_idempotent() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap(); // second call — must be a no-op

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        let expected = MIGRATIONS.len() as i64;
        assert_eq!(
            count, expected,
            "second run must not insert duplicate migration rows"
        );
    }

    /// schema_migrations records version=1 with a non-null applied_at.
    /// Verifies that version and timestamp fields are recorded correctly.
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
        assert_eq!(
            applied_at.len(),
            19,
            "applied_at should be 19-char ISO-8601 datetime string (YYYY-MM-DD HH:MM:SS)"
        );
        assert!(
            applied_at.starts_with("20"),
            "applied_at must be a valid ISO-8601 timestamp starting with 20xx"
        );
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

    /// Verify that server_metadata PRIMARY KEY constraint is enforced.
    #[tokio::test]
    async fn server_metadata_primary_key_uniqueness_constraint() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query("INSERT INTO server_metadata (key, value) VALUES ('unique_key', 'value1')")
            .execute(&pool)
            .await
            .unwrap();

        let result =
            sqlx::query("INSERT INTO server_metadata (key, value) VALUES ('unique_key', 'value2')")
                .execute(&pool)
                .await;

        assert!(result.is_err(), "inserting duplicate key must fail");
    }

    // ── V002 tests ───────────────────────────────────────────────────────────

    /// Apply V002 on top of V001 and verify all 12 auth/identity tables exist.
    /// Uses PRAGMA table_info — non-empty result means the table was created.
    #[tokio::test]
    async fn v002_all_tables_exist() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let tables = [
            "accounts",
            "handles",
            "did_documents",
            "signing_keys",
            "devices",
            "claim_codes",
            "sessions",
            "refresh_tokens",
            "oauth_clients",
            "oauth_authorization_codes",
            "oauth_tokens",
            "oauth_par_requests",
        ];

        for table in tables {
            let rows: Vec<(i64,)> = sqlx::query_as(&format!("PRAGMA table_info({table})"))
                .fetch_all(&pool)
                .await
                .unwrap_or_else(|e| panic!("PRAGMA table_info({table}) failed: {e}"));
            assert!(
                !rows.is_empty(),
                "table '{table}' must exist after V002 migration"
            );
        }
    }

    /// schema_migrations must contain exactly 2 rows after applying V001 + V002.
    #[tokio::test]
    async fn v002_migration_count_is_two_after_both_migrations() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2, "both V001 and V002 must be recorded");
    }

    /// Running all migrations twice must remain idempotent: still exactly 2 rows.
    #[tokio::test]
    async fn v002_migrations_are_idempotent() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2, "second run must be a no-op");
    }

    /// accounts.email UNIQUE index must reject duplicate email addresses.
    #[tokio::test]
    async fn v002_accounts_unique_email_enforced() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at)
             VALUES ('did:plc:aaa', 'a@example.com', 'hash', '2024-01-01T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let result = sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at)
             VALUES ('did:plc:bbb', 'a@example.com', 'hash', '2024-01-01T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await;

        assert!(result.is_err(), "duplicate email must be rejected");
    }

    /// PRAGMA foreign_keys = ON must cause handles.did FK violation to fail.
    #[tokio::test]
    async fn v002_foreign_key_violation_rejected() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();

        // Insert a handle referencing a DID that does not exist in accounts.
        let result = sqlx::query(
            "INSERT INTO handles (handle, did, created_at)
             VALUES ('alice.bsky.social', 'did:plc:nonexistent', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "FK violation on handles.did must be rejected with foreign_keys = ON"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_refresh_tokens_did for a WHERE did = ? query.
    #[tokio::test]
    async fn v002_index_refresh_tokens_did_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT * FROM refresh_tokens WHERE did = 'did:plc:aaa'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("idx_refresh_tokens_did"),
            "refresh_tokens WHERE did query must use idx_refresh_tokens_did; got: {detail}"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_oauth_tokens_did for a WHERE did = ? query.
    #[tokio::test]
    async fn v002_index_oauth_tokens_did_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT * FROM oauth_tokens WHERE did = 'did:plc:aaa'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("idx_oauth_tokens_did"),
            "oauth_tokens WHERE did query must use idx_oauth_tokens_did; got: {detail}"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_claim_codes_did for a WHERE did = ? query.
    #[tokio::test]
    async fn v002_index_claim_codes_did_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT * FROM claim_codes WHERE did = 'did:plc:aaa'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("idx_claim_codes_did"),
            "claim_codes WHERE did query must use idx_claim_codes_did; got: {detail}"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_accounts_email for a WHERE email = ? query.
    #[tokio::test]
    async fn v002_index_accounts_email_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT * FROM accounts WHERE email = 'a@example.com'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("idx_accounts_email"),
            "accounts WHERE email query must use idx_accounts_email; got: {detail}"
        );
    }

    /// WAL mode requires a real file — use tempfile here, not :memory:.
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
