# MM-72 SQLite Migration Infrastructure — Implementation Plan

**Goal:** Implement the `db/` module inside `crates/relay/src/` with pool factory, forward-only migration runner, Wave 1 schema (`V001__init.sql`), and unit tests using in-memory SQLite.

**Architecture:** `db/mod.rs` is the imperative shell for all database I/O. `DbError` mirrors the `ConfigError` thiserror pattern. `run_migrations` creates `schema_migrations` before any `.sql` file is executed. `MIGRATIONS` embeds `.sql` files at compile time via `include_str!`. Tests stay entirely in-memory — no disk files for the migration runner tests.

**Tech Stack:** Rust stable, sqlx 0.8 (`SqlitePool`, `SqlitePoolOptions`, `SqliteConnectOptions`, `SqliteJournalMode`), thiserror 2, tempfile 3 (dev only, for WAL mode test)

**Scope:** Phase 2 of 3 from the original design plan.

**Codebase verified:** 2026-03-10

---

## Acceptance Criteria Coverage

### MM-72.AC2: Migrations are idempotent
- **MM-72.AC2.1 Success:** Running the relay a second time does not re-apply V001 — row count in `schema_migrations` remains 1
- **MM-72.AC2.2 Success:** `schema_migrations` records `version = 1` with a non-null `applied_at` timestamp after first run

### MM-72.AC4: WAL mode enabled
- **MM-72.AC4.1 Success:** `PRAGMA journal_mode` queried on the pool returns `wal`

### MM-72.AC5: Unit tests use in-memory SQLite
- **MM-72.AC5.1 Success:** Migration runner unit tests use `":memory:"` — no `relay.db` or temp files created on disk during `cargo test`
- **MM-72.AC5.2 Success:** `cargo test --workspace` passes in a clean environment with no pre-existing `relay.db`

### MM-72.AC6: Toolchain checks pass
- **MM-72.AC6.1 Success:** `cargo clippy --workspace -- -D warnings` passes with no warnings
- **MM-72.AC6.2 Success:** `cargo fmt --all --check` passes

---

<!-- START_TASK_1 -->
### Task 1: Add thiserror and tempfile to relay Cargo.toml

**Verifies:** None — infrastructure task

**Files:**
- Modify: `crates/relay/Cargo.toml`

**Step 1: Add thiserror to [dependencies] and tempfile to [dev-dependencies]**

Open `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/Cargo.toml`.

After Phase 1, the file looks like:
```toml
[dependencies]
axum = { workspace = true }
common = { workspace = true, features = ["axum"] }
clap = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
tokio = { workspace = true }
tower-http = { workspace = true }
sqlx = { workspace = true }

[dev-dependencies]
tower = { workspace = true }
serde_json = { workspace = true }
```

Add `thiserror = { workspace = true }` to `[dependencies]` and `tempfile = { workspace = true }` to `[dev-dependencies]`:

```toml
[dependencies]
axum = { workspace = true }
common = { workspace = true, features = ["axum"] }
clap = { workspace = true }
anyhow = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
tokio = { workspace = true }
tower-http = { workspace = true }
sqlx = { workspace = true }

[dev-dependencies]
tower = { workspace = true }
serde_json = { workspace = true }
tempfile = { workspace = true }
```

**Step 2: Verify**

Run:
```bash
cargo build -p relay
```
Expected: compiles without errors.

**Step 3: Commit**

```bash
git add crates/relay/Cargo.toml
git commit -m "chore(deps): add thiserror + tempfile to relay crate"
```
<!-- END_TASK_1 -->

<!-- START_SUBCOMPONENT_A (tasks 2-4) -->

<!-- START_TASK_2 -->
### Task 2: Create the db/migrations directory and V001__init.sql

**Verifies:** None — infrastructure task (presence of this file is compile-time verified by `include_str!` in Task 3)

**Files:**
- Create: `crates/relay/src/db/migrations/V001__init.sql`

**Step 1: Create the directory and SQL file**

```bash
mkdir -p /Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/db/migrations
```

Create `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/db/migrations/V001__init.sql` with this exact content:

```sql
CREATE TABLE server_metadata (
    key   TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (key)
) WITHOUT ROWID;
```

Note: `schema_migrations` is NOT defined here. The migration runner creates it with `CREATE TABLE IF NOT EXISTS` before executing any `.sql` files. `V001__init.sql` only needs to create `server_metadata`.

**Step 2: Commit**

```bash
git add crates/relay/src/db/migrations/V001__init.sql
git commit -m "feat(db): add V001__init.sql Wave 1 schema (server_metadata)"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Create db/mod.rs — DbError, open_pool, run_migrations, unit tests

**Verifies:** MM-72.AC2.1, MM-72.AC2.2, MM-72.AC4.1, MM-72.AC5.1, MM-72.AC5.2

**Design note:** The Definition of Done in the design plan (line 11) describes `open_pool(path: &Path)`, but the Architecture section (line 89) specifies `open_pool(url: &str)`. This implementation follows the Architecture section — `&str` is correct because `SqliteConnectOptions::from_str` requires a URL string, not a `Path`. The DoD has a minor inconsistency that can be ignored.

**Files:**
- Create: `crates/relay/src/db/mod.rs`

**Step 1: Create the file with the following exact content**

Create `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/db/mod.rs`:

```rust
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
        open_pool("sqlite::memory:").await.expect("failed to open in-memory pool")
    }

    #[tokio::test]
    async fn select_one_succeeds() {
        let pool = in_memory_pool().await;
        let (n,): (i64,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn migrations_apply_on_first_run() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
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

        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1, "second run must not insert a duplicate migration row");
    }

    /// MM-72.AC2.2: schema_migrations records version=1 with a non-null applied_at.
    #[tokio::test]
    async fn schema_migrations_records_version_and_timestamp() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.unwrap();

        let (version, applied_at): (i64, String) = sqlx::query_as(
            "SELECT version, applied_at FROM schema_migrations WHERE version = 1",
        )
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

        sqlx::query(
            "INSERT INTO server_metadata (key, value) VALUES ('test_key', 'test_value')",
        )
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
```

**Step 2: Verify compilation**

Run:
```bash
cargo build -p relay
```
Expected: compiles without errors. The `include_str!("migrations/V001__init.sql")` macro is verified at compile time — if the file path is wrong, the build fails here.

**Step 3: Run unit tests**

Run:
```bash
cargo test -p relay db::
```
Expected: all 6 tests in `db::tests` pass. No `relay.db` or files created in the project directory.

**Step 4: Run full workspace tests**

Run:
```bash
cargo test --workspace
```
Expected: all tests pass, including the pre-existing 5 tests in `relay::app::tests`.

**Step 5: Commit**

```bash
git add crates/relay/src/db/mod.rs
git commit -m "feat(db): add db module with pool factory, migration runner, and unit tests"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Register db module in main.rs and verify toolchain checks

**Verifies:** MM-72.AC6.1, MM-72.AC6.2

**Files:**
- Modify: `crates/relay/src/main.rs` (line 5 — after `mod app;`)

**Step 1: Add mod db declaration**

Open `/Users/malpercio/workspace/malpercio-dev/ezpds/crates/relay/src/main.rs`.

After line 5 (`mod app;`), add:

```rust
mod app;
mod db;
```

The `db` module is declared here but not yet used in `run()` — that wiring happens in Phase 3. Declaring it here ensures the module compiles as part of the binary and the compiler checks for errors.

**Step 2: Suppress dead_code warning**

Because `db` is declared but not used in `run()` yet, cargo clippy will emit a warning. Add `#[allow(dead_code)]` to the module declaration to suppress it until Phase 3 wires it in:

```rust
mod app;
#[allow(dead_code)]
mod db;
```

**Step 3: Run clippy**

Run:
```bash
cargo clippy --workspace -- -D warnings
```
Expected: zero warnings, zero errors.

**Step 4: Run fmt check**

Run:
```bash
cargo fmt --all --check
```
Expected: no formatting differences. If differences are found, run `cargo fmt --all` to fix them, then re-run the check.

**Step 5: Run all workspace tests**

Run:
```bash
cargo test --workspace
```
Expected: all tests pass (11 relay tests: 5 existing app tests + 6 new db tests).

**Step 6: Commit**

```bash
git add crates/relay/src/main.rs
git commit -m "feat(relay): declare db module in main.rs"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->
