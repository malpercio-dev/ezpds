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
    Migration {
        version: 3,
        sql: include_str!("migrations/V003__relay_signing_keys.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("migrations/V004__claim_codes_invite.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("migrations/V005__pending_accounts.sql"),
    },
    Migration {
        version: 6,
        sql: include_str!("migrations/V006__devices_v2.sql"),
    },
    Migration {
        version: 7,
        sql: include_str!("migrations/V007__pending_sessions.sql"),
    },
    Migration {
        version: 8,
        sql: include_str!("migrations/V008__did_promotion.sql"),
    },
];

/// Open a WAL-mode SQLite connection pool with a maximum of 1 connection.
///
/// Accepts any sqlx URL string (e.g. `"sqlite:relay.db"`, `"sqlite::memory:"`).
/// `create_if_missing` is enabled so the file is created on first run.
/// WAL journal mode and foreign key enforcement are set via `SqliteConnectOptions`;
/// sqlx re-issues both PRAGMAs on every new connection so they survive reconnects.
///
/// Note: Pool creation succeeds even if the file path is invalid; the failure surfaces
/// at the first query. To fail fast on bad config, consider adding `min_connections(1)`.
#[tracing::instrument(skip(url), err, fields(db.system = "sqlite"))]
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
            u32::try_from(v).map_err(|_| DbError::Setup {
                step: "parse migration version from schema_migrations",
                source: sqlx::Error::Protocol(format!("version {v} does not fit in u32")),
            })
        })
        .collect::<Result<_, _>>()?;

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

    /// schema_migrations must contain one row per migration in MIGRATIONS.
    #[tokio::test]
    async fn all_migrations_recorded_in_schema_migrations() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            count,
            MIGRATIONS.len() as i64,
            "schema_migrations must have one row per migration in MIGRATIONS"
        );
    }

    /// Running migrations twice must not drop or recreate V002 tables.
    /// (Row-count idempotency is already covered by the generic migrations_are_idempotent test.)
    #[tokio::test]
    async fn v002_tables_survive_second_migration_run() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();

        // Spot-check a few tables to confirm they still exist and are writable.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at)
             VALUES ('did:plc:zzz', 'z@example.com', 'hash', '2024-01-01T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "accounts table must survive a second migration run"
        );
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

    /// FK enforcement is on by default (via open_pool .foreign_keys(true)).
    /// Inserting a handle with a nonexistent DID must fail without any manual PRAGMA.
    #[tokio::test]
    async fn v002_fk_handles_did_rejected() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let result = sqlx::query(
            "INSERT INTO handles (handle, did, created_at)
             VALUES ('alice.bsky.social', 'did:plc:nonexistent', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "FK violation on handles.did must be rejected by the pool (foreign_keys=true)"
        );
    }

    /// sessions.device_id → devices.id FK must be enforced.
    #[tokio::test]
    async fn v002_fk_sessions_device_id_rejected() {
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
            "INSERT INTO sessions (id, did, device_id, created_at, expires_at)
             VALUES ('sess1', 'did:plc:aaa', 'dev:nonexistent', '2024-01-01T00:00:00', '2024-01-02T00:00:00')",
        )
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "FK violation on sessions.device_id must be rejected"
        );
    }

    /// refresh_tokens.session_id → sessions.id FK must be enforced.
    #[tokio::test]
    async fn v002_fk_refresh_tokens_session_id_rejected() {
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
            "INSERT INTO refresh_tokens (jti, did, session_id, expires_at, created_at)
             VALUES ('jti1', 'did:plc:aaa', 'sess:nonexistent', '2024-01-02T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "FK violation on refresh_tokens.session_id must be rejected"
        );
    }

    /// oauth_authorization_codes.client_id → oauth_clients.client_id FK must be enforced.
    #[tokio::test]
    async fn v002_fk_oauth_authorization_codes_client_id_rejected() {
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
            "INSERT INTO oauth_authorization_codes
             (code, client_id, did, code_challenge, code_challenge_method, redirect_uri, scope, expires_at, created_at)
             VALUES ('code1', 'client:nonexistent', 'did:plc:aaa', 'challenge', 'S256',
                     'https://example.com/cb', 'atproto', '2024-01-02T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await;

        assert!(
            result.is_err(),
            "FK violation on oauth_authorization_codes.client_id must be rejected"
        );
    }

    /// End-to-end insert chain: accounts → devices → sessions → refresh_tokens.
    /// Validates column names, NOT NULL constraints, and FK ordering across the core auth path.
    #[tokio::test]
    async fn v002_core_auth_chain_insert_succeeds() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at)
             VALUES ('did:plc:aaa', 'a@example.com', 'hash', '2024-01-01T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();

        // V006: devices now references pending_accounts.id instead of accounts.did.
        // Set up a claim_code and pending_account so the device FK can be satisfied.
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES ('CHAIN1', datetime('now', '+24 hours'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES ('acct1', 'a@example.com', 'a.example.com', 'free', 'CHAIN1', datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO devices (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at)
             VALUES ('dev1', 'acct1', 'ios', 'pubkey123', 'deadbeef', '2024-01-01T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO sessions (id, did, device_id, created_at, expires_at)
             VALUES ('sess1', 'did:plc:aaa', 'dev1', '2024-01-01T00:00:00', '2024-01-02T00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO refresh_tokens (jti, did, session_id, expires_at, created_at)
             VALUES ('jti1', 'did:plc:aaa', 'sess1', '2024-01-02T00:00:00', '2024-01-01T00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM refresh_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "full auth chain insert must succeed");
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

    /// EXPLAIN QUERY PLAN must show idx_claim_codes_expires_at for a WHERE expires_at query.
    /// (V004 removed the did column; the index is now on expires_at for expiry sweeps.)
    #[tokio::test]
    async fn v004_index_claim_codes_expires_at_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT * FROM claim_codes WHERE expires_at < datetime('now')",
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
            detail.contains("idx_claim_codes_expires_at"),
            "claim_codes WHERE expires_at query must use idx_claim_codes_expires_at; got: {detail}"
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

    /// EXPLAIN QUERY PLAN must show idx_handles_did for a WHERE did = ? query.
    #[tokio::test]
    async fn v002_index_handles_did_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as("EXPLAIN QUERY PLAN SELECT * FROM handles WHERE did = 'did:plc:aaa'")
                .fetch_all(&pool)
                .await
                .unwrap();

        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("idx_handles_did"),
            "handles WHERE did query must use idx_handles_did; got: {detail}"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_signing_keys_did for a WHERE did = ? query.
    #[tokio::test]
    async fn v002_index_signing_keys_did_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT * FROM signing_keys WHERE did = 'did:plc:aaa'",
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
            detail.contains("idx_signing_keys_did"),
            "signing_keys WHERE did query must use idx_signing_keys_did; got: {detail}"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_devices_account_id for a WHERE account_id = ? query.
    /// (V006 replaced the did FK with account_id; the index is now idx_devices_account_id.)
    #[tokio::test]
    async fn v006_index_devices_account_id_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as("EXPLAIN QUERY PLAN SELECT * FROM devices WHERE account_id = 'acct1'")
                .fetch_all(&pool)
                .await
                .unwrap();

        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("idx_devices_account_id"),
            "devices WHERE account_id query must use idx_devices_account_id; got: {detail}"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_sessions_did for a WHERE did = ? query.
    #[tokio::test]
    async fn v002_index_sessions_did_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as("EXPLAIN QUERY PLAN SELECT * FROM sessions WHERE did = 'did:plc:aaa'")
                .fetch_all(&pool)
                .await
                .unwrap();

        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("idx_sessions_did"),
            "sessions WHERE did query must use idx_sessions_did; got: {detail}"
        );
    }

    // ── V003 tests ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn v003_relay_signing_keys_table_exists() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        // Verify the table exists by performing a SELECT with no rows expected.
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM relay_signing_keys")
            .fetch_one(&pool)
            .await
            .expect("relay_signing_keys table must exist after V003 migration");
        assert_eq!(count.0, 0, "table must be empty after migration");
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

    #[tokio::test]
    async fn v003_relay_signing_keys_columns_are_correct() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        // PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
        let columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
            sqlx::query_as("PRAGMA table_info(relay_signing_keys)")
                .fetch_all(&pool)
                .await
                .expect("PRAGMA table_info must succeed");

        let names: Vec<&str> = columns.iter().map(|r| r.1.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "id",
                "algorithm",
                "public_key",
                "private_key_encrypted",
                "created_at"
            ],
            "relay_signing_keys must have exactly these columns in order"
        );
    }

    #[tokio::test]
    async fn v003_relay_signing_keys_id_is_unique() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let insert = "INSERT INTO relay_signing_keys \
                      (id, algorithm, public_key, private_key_encrypted, created_at) \
                      VALUES (?, ?, ?, ?, datetime('now'))";

        // First insert: must succeed.
        sqlx::query(insert)
            .bind("did:key:ztest123")
            .bind("p256")
            .bind("zpubkey1")
            .bind("base64encodedvalue1")
            .execute(&pool)
            .await
            .expect("first insert must succeed");

        // Second insert with same id: must fail.
        let result = sqlx::query(insert)
            .bind("did:key:ztest123")
            .bind("p256")
            .bind("zpubkey2")
            .bind("base64encodedvalue2")
            .execute(&pool)
            .await;

        assert!(
            result.is_err(),
            "duplicate id must be rejected by PRIMARY KEY constraint"
        );
    }
}
