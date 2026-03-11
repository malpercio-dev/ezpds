# MM-72 SQLite Migration Infrastructure — Implementation Plan

**Goal:** Wire `open_pool` + `run_migrations` into `main.rs`, add `db: SqlitePool` to `AppState`, and update the test fixture — making the pool available to every Axum handler via Axum's `State` extractor.

**Architecture:** `main.rs` (imperative shell) calls `db::open_pool` and `db::run_migrations` after config load and before AppState construction. `AppState` gains a `db: SqlitePool` field — no `Arc` wrapping needed since `SqlitePool` is already Arc-backed. The `test_state()` fixture becomes `async` and opens an in-memory pool with migrations applied.

**Tech Stack:** Rust stable, sqlx 0.8 `SqlitePool`, axum 0.7 `State` extractor, anyhow `Context` trait

**Scope:** Phase 3 of 3 from the original design plan.

**Codebase verified:** 2026-03-10

---

## Acceptance Criteria Coverage

### MM-72.AC1: relay.db created on first start
- **MM-72.AC1.1 Success:** `cargo run --bin relay` (with a valid `relay.toml`) creates `relay.db` in the configured `data_dir`
- **MM-72.AC1.2 Success:** `schema_migrations` table exists in the produced database
- **MM-72.AC1.3 Success:** `server_metadata` table exists in the produced database

### MM-72.AC2: Migrations are idempotent
- **MM-72.AC2.1 Success:** Running the relay a second time does not re-apply V001 — row count in `schema_migrations` remains 1

### MM-72.AC3: Pool available in AppState
- **MM-72.AC3.1 Success:** Handler tests that extract `State<AppState>` compile and pass with the `db: SqlitePool` field present
- **MM-72.AC3.2 Success:** `sqlx::query("SELECT 1").execute(&state.db)` succeeds in tests using an in-memory pool

### MM-72.AC5: Unit tests use in-memory SQLite
- **MM-72.AC5.2 Success:** `cargo test --workspace` passes in a clean environment with no pre-existing `relay.db`

### MM-72.AC6: Toolchain checks pass
- **MM-72.AC6.1 Success:** `cargo clippy --workspace -- -D warnings` passes with no warnings
- **MM-72.AC6.2 Success:** `cargo fmt --all --check` passes

---

<!-- START_TASK_1 -->
### Task 1: Add db: SqlitePool to AppState and update test_state()

**Verifies:** MM-72.AC3.1, MM-72.AC3.2

**Files:**
- Modify: `crates/relay/src/app.rs`

**Step 1: Update AppState struct**

Open `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/relay/src/app.rs`.

The current `AppState` (lines 7–13):
```rust
/// Shared application state cloned into every request handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    // Read by handlers once XRPC endpoints are implemented; suppressed until then.
    #[allow(dead_code)]
    pub config: Arc<Config>,
}
```

Replace with:
```rust
/// Shared application state cloned into every request handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    // Read by handlers once XRPC endpoints are implemented; suppressed until then.
    #[allow(dead_code)]
    pub config: Arc<Config>,
    pub db: sqlx::SqlitePool,
}
```

`sqlx::SqlitePool` is Arc-backed internally — no `Arc<Mutex<>>` wrapper is needed. The `#[derive(Clone)]` on `AppState` works because `SqlitePool` implements `Clone` (cloning is cheap — it just clones the Arc reference to the shared pool).

**Step 2: Update the imports block**

The current imports at the top of `app.rs`:
```rust
use std::sync::Arc;

use axum::{extract::Path, routing::get, Router};
use common::{ApiError, Config, ErrorCode};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
```

No import changes are needed — `sqlx::SqlitePool` is referenced with its full path in the struct to avoid ambiguity with future imports.

**Step 3: Update test_state() to be async and open an in-memory pool**

The `#[cfg(test)]` block currently starts at line 38. The `test_state()` function (lines 49–62):

```rust
fn test_state() -> AppState {
    AppState {
        config: Arc::new(Config {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            data_dir: PathBuf::from("/tmp"),
            database_url: "/tmp/test.db".to_string(),
            public_url: "https://test.example.com".to_string(),
            blobs: BlobsConfig::default(),
            oauth: OAuthConfig::default(),
            iroh: IrohConfig::default(),
        }),
    }
}
```

Replace it with the async version:
```rust
async fn test_state() -> AppState {
    let pool = crate::db::open_pool("sqlite::memory:")
        .await
        .expect("failed to open test pool");
    crate::db::run_migrations(&pool)
        .await
        .expect("failed to run test migrations");
    AppState {
        config: Arc::new(Config {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            data_dir: PathBuf::from("/tmp"),
            database_url: "sqlite::memory:".to_string(),
            public_url: "https://test.example.com".to_string(),
            blobs: BlobsConfig::default(),
            oauth: OAuthConfig::default(),
            iroh: IrohConfig::default(),
        }),
        db: pool,
    }
}
```

**Step 4: Update all test_state() call sites**

Every existing test in `app.rs` calls `test_state()`. Since `test_state` is now async, each call must add `.await`:

Find all occurrences of `test_state()` in the test block (there are 5 tests, each calling it once) and change each to `test_state().await`:

```rust
// Before:
let response = app(test_state())

// After:
let response = app(test_state().await)
```

All 5 tests already use `#[tokio::test]` and are `async fn`, so `.await` is valid in each.

**Step 5: Add a test that exercises state.db (AC3.2)**

Add this test after the existing 5 tests in the `#[cfg(test)]` block:

```rust
#[tokio::test]
async fn appstate_db_pool_is_queryable() {
    let state = test_state().await;
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .expect("db pool in AppState must be queryable");
}
```

**Step 6: Verify compilation**

Run:
```bash
cargo build -p relay
```
Expected: compiles without errors.

**Step 7: Run relay tests**

Run:
```bash
cargo test -p relay
```
Expected: all 6 app tests pass (5 existing XRPC tests + 1 new db pool test), plus all 6 db module tests.

**Step 8: Commit**

```bash
git add crates/relay/src/app.rs
git commit -m "feat(relay): add db: SqlitePool to AppState and update test fixture"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Wire open_pool + run_migrations into main.rs

**Verifies:** MM-72.AC1.1, MM-72.AC1.2, MM-72.AC1.3, MM-72.AC2.1

**Files:**
- Modify: `crates/relay/src/main.rs`

**Step 1: Review current main.rs structure**

The relevant section of `run()` in `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/relay/src/main.rs` currently looks like this (lines 23–45):

```rust
async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))?;

    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("relay.toml"));

    let config = common::load_config(&config_path)
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;

    tracing::info!(
        bind_address = %config.bind_address,
        port = config.port,
        public_url = %config.public_url,
        "relay starting"
    );

    let addr = format!("{}:{}", config.bind_address, config.port);
    let state = app::AppState {
        config: Arc::new(config),
    };
    ...
```

**Step 2: Insert pool creation and migration wiring**

Between the `tracing::info!` log and the `let addr = ...` line, insert the pool creation and migration steps. The `config.database_url` is a plain path by default (e.g. `/var/pds/relay.db`); format it as a valid sqlx URL before passing to `open_pool`.

The updated `run()` function body, starting from `let addr`:

```rust
    let addr = format!("{}:{}", config.bind_address, config.port);

    // **Intentional deviation from design:** The design doc's startup sequence shows
    // `open_pool(&config.database_url)` directly. However, `config.database_url` defaults
    // to a plain filesystem path (e.g. `/var/pds/relay.db`) when not explicitly set, which
    // is not a valid sqlx URL. We format it here rather than changing Config or open_pool,
    // keeping both functions general-purpose.
    //
    // Plain absolute paths like "/var/pds/relay.db" become "sqlite:///var/pds/relay.db".
    // Already-formatted "sqlite://..." URLs pass through unchanged.
    let db_url = if config.database_url.starts_with("sqlite:") {
        config.database_url.clone()
    } else if config.database_url.starts_with('/') {
        format!("sqlite://{}", config.database_url)
    } else {
        format!("sqlite:{}", config.database_url)
    };

    let pool = db::open_pool(&db_url)
        .await
        .with_context(|| format!("failed to open database at {}", config.database_url))?;

    db::run_migrations(&pool)
        .await
        .with_context(|| "failed to run database migrations")?;

    let state = app::AppState {
        config: Arc::new(config),
        db: pool,
    };
```

**Why `.with_context()` works here:** `DbError` is derived via `thiserror`, which implements `std::error::Error`. `anyhow::Context` is implemented for `Result<T, E>` where `E: std::error::Error + Send + Sync + 'static` — so `.with_context(|| ...)` converts `DbError` into `anyhow::Error` automatically. No `.map_err` is needed.

**Step 3: Verify the module declaration**

Confirm that `mod db;` is present in main.rs (added in Phase 2, Task 4). The top of main.rs should read:

```rust
use anyhow::Context;
use clap::Parser;
use std::{path::PathBuf, sync::Arc};

mod app;
mod db;
```

If `mod db;` still has `#[allow(dead_code)]` from Phase 2 (Task 4 of Phase 2 added this as a temporary suppressor), remove the attribute now — `db` is actively used in `run()`.

**Step 4: Verify build**

Run:
```bash
cargo build --workspace
```
Expected: compiles without errors.

**Step 5: Run all tests**

Run:
```bash
cargo test --workspace
```
Expected: all tests pass. No `relay.db` file created in the project directory (tests use in-memory pools).

**Step 6: Run clippy and fmt**

Run:
```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all --check
```
Expected: zero warnings, zero errors, no formatting differences.

**Step 7: Commit**

```bash
git add crates/relay/src/main.rs
git commit -m "feat(relay): wire db pool and migrations into startup sequence"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Manual verification — relay.db created on first start

**Verifies:** MM-72.AC1.1, MM-72.AC1.2, MM-72.AC1.3, MM-72.AC2.1 (runtime)

**Note:** These acceptance criteria require running the actual binary and cannot be automated with `cargo test` alone. This task verifies them manually.

**Step 1: Ensure a valid relay.toml exists**

The project includes `relay.dev.toml`. Copy it or create `relay.toml` in the workspace root with at minimum:

```toml
data_dir = "/tmp/relay-test"
public_url = "https://test.example.com"
```

Create the data directory:
```bash
mkdir -p /tmp/relay-test
```

**Step 2: Run the relay binary**

Run:
```bash
cargo run --bin relay -- --config relay.toml
```

Expected startup output (tracing logs):
```
relay starting bind_address=0.0.0.0 port=8080 public_url=https://test.example.com
listening address=0.0.0.0:8080
```

Press Ctrl+C to stop after the server binds.

**Step 3: Verify relay.db was created**

Run:
```bash
ls -la /tmp/relay-test/relay.db
```
Expected: file exists.

**Step 4: Verify tables exist** (AC1.2, AC1.3)

Run:
```bash
sqlite3 /tmp/relay-test/relay.db ".tables"
```
Expected output includes: `schema_migrations  server_metadata`

**Step 5: Verify schema_migrations has one row** (AC2.2)

Run:
```bash
sqlite3 /tmp/relay-test/relay.db "SELECT version, applied_at FROM schema_migrations;"
```
Expected output:
```
1|<timestamp>
```

**Step 6: Run the binary a second time** (AC2.1)

Run:
```bash
cargo run --bin relay -- --config relay.toml
```
Stop with Ctrl+C after binding.

**Step 7: Verify migration was NOT re-applied**

Run:
```bash
sqlite3 /tmp/relay-test/relay.db "SELECT COUNT(*) FROM schema_migrations;"
```
Expected: `1` (still one row, not two).

**Step 8: Clean up**

```bash
rm -rf /tmp/relay-test relay.toml
```
<!-- END_TASK_3 -->
