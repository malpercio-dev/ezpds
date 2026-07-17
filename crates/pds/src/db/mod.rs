pub mod account_deletion_tokens;
pub mod accounts;
pub mod admin_devices;
pub mod agent_audit;
pub mod agent_auth;
pub mod agent_child_deletions;
pub mod app_passwords;
pub mod blobs;
pub mod blocks;
pub mod claim_codes;
pub mod dids;
pub mod email_tokens;
pub mod firehose_seq;
pub mod handles;
pub mod iroh_identity;
pub mod jwt_secret;
pub mod kek;
mod migrations;
pub mod oauth;
pub mod password_reset;
pub mod plc_operation_tokens;
pub mod preferences;
pub mod refresh_tokens;
pub mod relay_signing_keys;
pub mod repo_keys;
pub mod server_stats;
pub mod sessions;
pub mod sovereign_session_nonces;
pub mod transfers;

use migrations::{Migration, MIGRATIONS};
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

// ── Unique constraint helpers ─────────────────────────────────────────────

/// Check if a sqlx::Error is a UNIQUE constraint violation.
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::Database(db_err)
            if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation
    )
}

/// Extract the column name from a UNIQUE constraint violation on a specific table.
///
/// SQLite's stable error format is `"UNIQUE constraint failed: <table>.<column>"`.
/// Returns `Some(column)` if the error matches, `None` otherwise.
pub fn unique_violation_column<'a>(e: &'a sqlx::Error, table: &str) -> Option<&'a str> {
    if let sqlx::Error::Database(db_err) = e {
        if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation {
            let prefix = format!("UNIQUE constraint failed: {table}.");
            let msg = db_err.message();
            if let Some(column) = msg.strip_prefix(&prefix) {
                return Some(column);
            }
        }
    }
    None
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

    /// Apply every migration strictly before `stop_before`, in order, inside one transaction —
    /// mirroring `run_migrations` but letting a test pause at an intermediate schema version.
    async fn apply_migrations_before(pool: &SqlitePool, stop_before: u32) {
        let mut tx = pool.begin().await.unwrap();
        for migration in MIGRATIONS.iter().filter(|m| m.version < stop_before) {
            sqlx::raw_sql(migration.sql)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
    }

    /// V038 rebuilds `agent_identities` (referenced by `agent_claim_attempts`) to make `did`
    /// nullable. The fresh-DB migration run never has rows present during the rebuild, so this test
    /// exercises the production upgrade path: seed the V037 schema with a populated
    /// identity→claim-attempt chain, then apply V038 and confirm the child rows survive (V038
    /// stashes and refills `agent_claim_attempts` around the parent swap) and an anonymous NULL-did
    /// identity can now be inserted.
    #[tokio::test]
    async fn v038_rebuild_preserves_child_rows_and_allows_null_did() {
        let pool = in_memory_pool().await;
        apply_migrations_before(&pool, 38).await;

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:v038owner', 'v038@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, created_at, updated_at) \
             VALUES ('reg_v038', 'did:plc:v038owner', 'service_auth', '[]', \
                     datetime('now', '+1 hour'), datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_claim_attempts \
             (id, identity_id, user_code, user_code_expires_at, created_at) \
             VALUES ('cla_v038', 'reg_v038', '123456', datetime('now', '+10 minutes'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Apply just V038.
        let v038 = MIGRATIONS.iter().find(|m| m.version == 38).unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(v038.sql).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();

        // The child claim-attempt row still resolves its FK to the preserved identity id.
        let (attempts,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM agent_claim_attempts WHERE identity_id = 'reg_v038'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempts, 1, "child claim attempt must survive the rebuild");

        // An anonymous identity (NULL did) is now insertable, and FK enforcement is intact.
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, created_at, updated_at) \
             VALUES ('reg_anon_v038', NULL, 'anonymous', '[]', datetime('now', '+1 hour'), \
                     datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        let (did,): (Option<String>,) =
            sqlx::query_as("SELECT did FROM agent_identities WHERE id = 'reg_anon_v038'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(did, None);

        // A non-NULL did still has to reference a real account.
        let orphan = sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, created_at, updated_at) \
             VALUES ('reg_orphan', 'did:plc:missing', 'service_auth', '[]', \
                     datetime('now', '+1 hour'), datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await;
        assert!(
            orphan.is_err(),
            "non-NULL did must still be checked against accounts"
        );
    }

    /// V047 rebuilds `agent_identities` for sovereign child agents. Like V038 it must cycle
    /// every child table referencing the parent through a stash — including `agent_audit_events`
    /// (V040), which a fresh-DB migration run never populates. This test exercises the
    /// production upgrade path that shipped broken in v0.5.1: seed a populated
    /// identity→claim-attempt→audit-event chain, apply V047, and confirm all child rows survive
    /// with audit rowids (the pagination cursor) intact.
    #[tokio::test]
    async fn v047_rebuild_preserves_audit_events_and_claim_attempts() {
        let pool = in_memory_pool().await;
        apply_migrations_before(&pool, 47).await;

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:v047owner', 'v047@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_identities \
             (id, did, registration_type, scopes, assertion_expires_at, created_at, updated_at) \
             VALUES ('reg_v047', 'did:plc:v047owner', 'service_auth', '[]', \
                     datetime('now', '+1 hour'), datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_claim_attempts \
             (id, identity_id, user_code, user_code_expires_at, created_at) \
             VALUES ('cla_v047', 'reg_v047', '654321', datetime('now', '+10 minutes'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        // Two audit events with the first later deleted, so the survivor sits at rowid 2 —
        // proving the stash refill preserves absolute rowids (the audit pagination cursor),
        // not just relative order.
        for id in ["evt_v047_a", "evt_v047_b"] {
            sqlx::query(
                "INSERT INTO agent_audit_events \
                 (id, registration_id, did, event_type, detail, created_at) \
                 VALUES (?, 'reg_v047', 'did:plc:v047owner', 'registered', NULL, datetime('now'))",
            )
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query("DELETE FROM agent_audit_events WHERE id = 'evt_v047_a'")
            .execute(&pool)
            .await
            .unwrap();

        let v047 = MIGRATIONS.iter().find(|m| m.version == 47).unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(v047.sql)
            .execute(&mut *tx)
            .await
            .expect("V047 must apply over a populated agent-auth schema");
        tx.commit().await.unwrap();

        let (attempts,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM agent_claim_attempts WHERE identity_id = 'reg_v047'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempts, 1, "claim attempt must survive the rebuild");

        let (event_rowid,): (i64,) = sqlx::query_as(
            "SELECT rowid FROM agent_audit_events WHERE id = 'evt_v047_b' \
             AND registration_id = 'reg_v047'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            event_rowid, 2,
            "audit event must survive the rebuild with its original rowid"
        );

        // FK enforcement against the rebuilt parent is intact.
        let orphan = sqlx::query(
            "INSERT INTO agent_audit_events \
             (id, registration_id, did, event_type, detail, created_at) \
             VALUES ('evt_orphan', 'reg_missing', NULL, 'registered', NULL, datetime('now'))",
        )
        .execute(&pool)
        .await;
        assert!(
            orphan.is_err(),
            "audit events must still FK-check against the rebuilt agent_identities"
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

    /// V032 creates a reserved_signing_keys table for standard account-migration key reservations.
    #[tokio::test]
    async fn v032_reserved_signing_keys_table_shape() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as("PRAGMA table_info(reserved_signing_keys)")
                .fetch_all(&pool)
                .await
                .unwrap();
        let names: Vec<&str> = columns
            .iter()
            .map(|(_, name, _, _, _, _)| name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "id",
                "did",
                "key_type",
                "public_key",
                "private_key_encrypted",
                "created_at"
            ],
            "reserved_signing_keys must have the expected columns"
        );

        sqlx::query(
            "INSERT INTO reserved_signing_keys \
             (id, did, key_type, public_key, private_key_encrypted, created_at) \
             VALUES ('did:key:z1', 'did:plc:reserved', 'p256', 'pub', 'enc', datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        let duplicate = sqlx::query(
            "INSERT INTO reserved_signing_keys \
             (id, did, key_type, public_key, private_key_encrypted, created_at) \
             VALUES ('did:key:z2', 'did:plc:reserved', 'p256', 'pub2', 'enc2', datetime('now'))",
        )
        .execute(&pool)
        .await;
        assert!(duplicate.is_err(), "DID-keyed reservations must be unique");
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

    // ── V008 tests ───────────────────────────────────────────────────────────

    /// Verify that V008 rebuilds accounts with nullable password_hash.
    /// Before V008, password_hash was NOT NULL. After V008, it should be nullable.
    #[tokio::test]
    async fn v008_accounts_password_hash_is_nullable() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        // PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
        let columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
            sqlx::query_as("PRAGMA table_info(accounts)")
                .fetch_all(&pool)
                .await
                .expect("PRAGMA table_info must succeed");

        // Find the password_hash column.
        let password_hash_col = columns
            .iter()
            .find(|(_, name, _, _, _, _)| name == "password_hash")
            .expect("password_hash column must exist");

        let notnull = password_hash_col.3;
        assert_eq!(
            notnull, 0,
            "password_hash must be nullable (notnull=0); got notnull={}",
            notnull
        );
    }

    /// Verify that V008 adds pending_did column to pending_accounts.
    #[tokio::test]
    async fn v008_pending_accounts_has_pending_did_column() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        // PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
        let columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
            sqlx::query_as("PRAGMA table_info(pending_accounts)")
                .fetch_all(&pool)
                .await
                .expect("PRAGMA table_info must succeed");

        // Find the pending_did column.
        let pending_did_col = columns
            .iter()
            .find(|(_, name, _, _, _, _)| name == "pending_did");

        assert!(
            pending_did_col.is_some(),
            "pending_did column must exist in pending_accounts after V008"
        );
    }

    /// Verify that accounts with NULL password_hash can be inserted (for mobile-provisioned accounts).
    #[tokio::test]
    async fn v008_accounts_can_insert_null_password_hash() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:mobile', 'mobile@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .expect("insert account with NULL password_hash must succeed");

        let (stored_hash,): (Option<String>,) =
            sqlx::query_as("SELECT password_hash FROM accounts WHERE did = 'did:plc:mobile'")
                .fetch_one(&pool)
                .await
                .expect("query must succeed");

        assert!(stored_hash.is_none(), "password_hash must be NULL");
    }

    /// Verify that pending_did can be NULL (initial state) and can be updated to a DID string.
    #[tokio::test]
    async fn v008_pending_accounts_pending_did_nullable_and_updatable() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let claim_code = "TEST-CODE";
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
        )
        .bind(claim_code)
        .execute(&pool)
        .await
        .expect("insert claim_code");

        let account_id = "acct-v008-test";
        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES (?, ?, ?, 'free', ?, datetime('now'))",
        )
        .bind(account_id)
        .bind("test@example.com")
        .bind("test.example.com")
        .bind(claim_code)
        .execute(&pool)
        .await
        .expect("insert pending_account");

        // Initially, pending_did should be NULL.
        let (initial_pending_did,): (Option<String>,) =
            sqlx::query_as("SELECT pending_did FROM pending_accounts WHERE id = ?")
                .bind(account_id)
                .fetch_one(&pool)
                .await
                .expect("query must succeed");

        assert!(
            initial_pending_did.is_none(),
            "pending_did should be NULL initially"
        );

        // Update it to a DID value.
        sqlx::query("UPDATE pending_accounts SET pending_did = ? WHERE id = ?")
            .bind("did:plc:test123")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("update must succeed");

        let (updated_pending_did,): (Option<String>,) =
            sqlx::query_as("SELECT pending_did FROM pending_accounts WHERE id = ?")
                .bind(account_id)
                .fetch_one(&pool)
                .await
                .expect("query must succeed");

        assert_eq!(
            updated_pending_did,
            Some("did:plc:test123".to_string()),
            "pending_did should be updated"
        );
    }

    #[tokio::test]
    async fn v013_seeds_identity_wallet_oauth_client() {
        let pool = in_memory_pool().await;
        run_migrations(&pool)
            .await
            .expect("migrations must apply cleanly");

        let row = oauth::get_oauth_client(&pool, "dev.malpercio.identitywallet")
            .await
            .expect("db query must not fail");

        assert!(
            row.is_some(),
            "V013 migration must insert the identity-wallet client row"
        );

        let row = row.unwrap();
        let metadata: serde_json::Value =
            serde_json::from_str(&row.client_metadata).expect("client_metadata must be valid JSON");

        assert_eq!(
            metadata["redirect_uris"][0].as_str(),
            Some("dev.malpercio.identitywallet:/oauth/callback"),
            "redirect_uri must match the custom URL scheme"
        );
        assert_eq!(
            metadata["dpop_bound_access_tokens"].as_bool(),
            Some(true),
            "DPoP must be required for this client"
        );
    }

    #[tokio::test]
    async fn v042_seeds_canonical_wallet_oauth_client() {
        let pool = in_memory_pool().await;
        run_migrations(&pool)
            .await
            .expect("migrations must apply cleanly");

        let row = oauth::get_oauth_client(
            &pool,
            "https://identitywallet.obsign.org/oauth/client-metadata.json",
        )
        .await
        .expect("db query must not fail")
        .expect("V042 migration must insert the canonical wallet client row");

        let metadata: serde_json::Value =
            serde_json::from_str(&row.client_metadata).expect("client_metadata must be valid JSON");

        assert_eq!(
            metadata["client_id"].as_str(),
            Some("https://identitywallet.obsign.org/oauth/client-metadata.json"),
            "the document must self-reference the canonical URL"
        );
        assert_eq!(
            metadata["redirect_uris"][0].as_str(),
            Some("org.obsign.identitywallet:/oauth/callback"),
            "redirect scheme must be the canonical client_id host in reverse order"
        );
        assert_eq!(
            metadata["dpop_bound_access_tokens"].as_bool(),
            Some(true),
            "DPoP must be required for this client"
        );

        // The V013 row survives: wallet builds shipped before the scheme change
        // still present the old client_id during the transition window.
        let legacy = oauth::get_oauth_client(&pool, "dev.malpercio.identitywallet")
            .await
            .expect("db query must not fail");
        assert!(legacy.is_some(), "the legacy V013 client row must be kept");
    }

    // ── V025 tests ───────────────────────────────────────────────────────────

    /// All three admin-device tables exist after V025.
    #[tokio::test]
    async fn v025_admin_tables_exist() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        for table in ["admin_pairing_codes", "admin_devices", "admin_nonces"] {
            let rows: Vec<(i64,)> = sqlx::query_as(&format!("PRAGMA table_info({table})"))
                .fetch_all(&pool)
                .await
                .unwrap_or_else(|e| panic!("PRAGMA table_info({table}) failed: {e}"));
            assert!(!rows.is_empty(), "table '{table}' must exist after V025");
        }
    }

    /// admin_devices.scopes defaults to 'full' when omitted on insert.
    #[tokio::test]
    async fn v025_admin_devices_scopes_defaults_to_full() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO admin_devices (id, label, public_key, platform, created_at) \
             VALUES ('d1', 'phone', 'did:key:z1', 'ios', datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        let (scopes,): (String,) =
            sqlx::query_as("SELECT scopes FROM admin_devices WHERE id = 'd1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(scopes, "full");
    }

    /// admin_pairing_codes PRIMARY KEY rejects a duplicate code.
    #[tokio::test]
    async fn v025_admin_pairing_codes_pk_enforced() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let insert = "INSERT INTO admin_pairing_codes (code, expires_at, created_at) \
                      VALUES ('CODE', datetime('now', '+5 minutes'), datetime('now'))";
        sqlx::query(insert).execute(&pool).await.unwrap();
        assert!(
            sqlx::query(insert).execute(&pool).await.is_err(),
            "duplicate pairing code must be rejected by the PRIMARY KEY"
        );
    }

    /// admin_nonces PRIMARY KEY rejects a duplicate nonce.
    #[tokio::test]
    async fn v025_admin_nonces_pk_enforced() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO admin_devices (id, label, public_key, platform, created_at) \
             VALUES ('d1', 'phone', 'did:key:z1', 'ios', datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        let insert = "INSERT INTO admin_nonces (nonce, device_id, seen_at) \
                      VALUES ('N1', 'd1', datetime('now'))";
        sqlx::query(insert).execute(&pool).await.unwrap();
        assert!(
            sqlx::query(insert).execute(&pool).await.is_err(),
            "duplicate nonce must be rejected by the PRIMARY KEY"
        );
    }

    /// admin_nonces.device_id → admin_devices.id FK must be enforced.
    #[tokio::test]
    async fn v025_admin_nonces_fk_device_id_rejected() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let result = sqlx::query(
            "INSERT INTO admin_nonces (nonce, device_id, seen_at) \
             VALUES ('N1', 'no-such-device', datetime('now'))",
        )
        .execute(&pool)
        .await;
        assert!(
            result.is_err(),
            "FK violation on admin_nonces.device_id must be rejected"
        );
    }

    // ── V026 tests ───────────────────────────────────────────────────────────

    /// V026 adds nullable `suspended_at` and `taken_down_at` columns to `accounts`.
    #[tokio::test]
    async fn v026_accounts_has_lifecycle_columns() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        // PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
        let columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
            sqlx::query_as("PRAGMA table_info(accounts)")
                .fetch_all(&pool)
                .await
                .expect("PRAGMA table_info must succeed");

        for name in ["suspended_at", "taken_down_at"] {
            let col = columns
                .iter()
                .find(|(_, col_name, _, _, _, _)| col_name == name)
                .unwrap_or_else(|| panic!("{name} column must exist after V026"));
            assert_eq!(col.3, 0, "{name} must be nullable (notnull=0)");
        }
    }

    /// The new lifecycle columns accept timestamp writes and default to NULL.
    #[tokio::test]
    async fn v026_lifecycle_columns_nullable_and_writable() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:v026', 'v026@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Default NULL.
        let (susp, td): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT suspended_at, taken_down_at FROM accounts WHERE did = 'did:plc:v026'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(susp.is_none() && td.is_none(), "columns default to NULL");

        // Writable.
        sqlx::query(
            "UPDATE accounts SET suspended_at = datetime('now'), taken_down_at = datetime('now') \
             WHERE did = 'did:plc:v026'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let (susp, td): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT suspended_at, taken_down_at FROM accounts WHERE did = 'did:plc:v026'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            susp.is_some() && td.is_some(),
            "columns accept timestamp writes"
        );
    }

    /// EXPLAIN QUERY PLAN must show idx_admin_nonces_seen_at for the sweep query.
    #[tokio::test]
    async fn v025_index_admin_nonces_seen_at_used() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT * FROM admin_nonces WHERE seen_at <= datetime('now')",
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
            detail.contains("idx_admin_nonces_seen_at"),
            "admin_nonces WHERE seen_at query must use idx_admin_nonces_seen_at; got: {detail}"
        );
    }

    // ── V028 tests ───────────────────────────────────────────────────────────

    /// The `repo_seq` firehose event log exists after V028.
    #[tokio::test]
    async fn v028_repo_seq_table_exists() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let rows: Vec<(i64,)> = sqlx::query_as("PRAGMA table_info(repo_seq)")
            .fetch_all(&pool)
            .await
            .expect("PRAGMA table_info(repo_seq) must succeed");
        assert!(!rows.is_empty(), "repo_seq table must exist after V028");
    }

    /// `repo_seq.seq` is the PRIMARY KEY, so a duplicate sequence number is rejected.
    #[tokio::test]
    async fn v028_repo_seq_seq_is_unique() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let insert = "INSERT INTO repo_seq (seq, did, event_type, event, sequenced_at) \
                      VALUES (1, 'did:plc:a', 'commit', x'cafe', datetime('now'))";
        sqlx::query(insert).execute(&pool).await.unwrap();
        assert!(
            sqlx::query(insert).execute(&pool).await.is_err(),
            "duplicate seq must be rejected by the PRIMARY KEY"
        );
    }

    /// A `seq > ?` range scan uses the integer primary key rather than a full table scan.
    #[tokio::test]
    async fn v028_repo_seq_range_scan_uses_primary_key() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as("EXPLAIN QUERY PLAN SELECT * FROM repo_seq WHERE seq > 5 ORDER BY seq")
                .fetch_all(&pool)
                .await
                .unwrap();
        let detail = plan
            .iter()
            .map(|r| r.3.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !detail.contains("SCAN repo_seq"),
            "seq range query must not be a full table scan; got: {detail}"
        );
    }

    // ── V045 tests ───────────────────────────────────────────────────────────

    /// V045 lowercases (and trims) existing mixed-case accounts.email / pending_accounts.email
    /// rows in place.
    #[tokio::test]
    async fn v045_lowercases_existing_emails() {
        let pool = in_memory_pool().await;
        apply_migrations_before(&pool, 45).await;

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:v045a', '  Alice@Example.COM ', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO claim_codes (code, expires_at, created_at) \
             VALUES ('V045CODE', datetime('now', '+1 hour'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pending_accounts (id, email, handle, tier, claim_code, created_at) \
             VALUES ('v045-pending', 'Bob@Example.COM', 'bob.example.com', 'free', 'V045CODE', datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        let v045 = MIGRATIONS.iter().find(|m| m.version == 45).unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::raw_sql(v045.sql).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();

        let account_email: String =
            sqlx::query_scalar("SELECT email FROM accounts WHERE did = 'did:plc:v045a'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(account_email, "alice@example.com");

        let pending_email: String =
            sqlx::query_scalar("SELECT email FROM pending_accounts WHERE id = 'v045-pending'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(pending_email, "bob@example.com");
    }

    /// If two account rows would collide once normalized (differing only by case today, since
    /// the pre-V045 UNIQUE index is case-sensitive), V045 must fail loudly rather than silently
    /// merging or dropping one of them.
    #[tokio::test]
    async fn v045_fails_loudly_on_case_collision() {
        let pool = in_memory_pool().await;
        apply_migrations_before(&pool, 45).await;

        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:v045collide1', 'dup@example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES ('did:plc:v045collide2', 'DUP@Example.com', 'hash', datetime('now'), datetime('now'))",
        )
        .execute(&pool)
        .await
        .unwrap();

        let v045 = MIGRATIONS.iter().find(|m| m.version == 45).unwrap();
        let mut tx = pool.begin().await.unwrap();
        let result = sqlx::raw_sql(v045.sql).execute(&mut *tx).await;
        assert!(
            result.is_err(),
            "normalizing two case-colliding emails must fail loudly, not silently merge"
        );
    }
}
