# Test Requirements: MM-72 SQLite Migration Infrastructure (Wave 1 Schema)

Generated from test-analyst review of design plan `docs/design-plans/2026-03-10-MM-72.md`
and implementation plans `docs/implementation-plans/2026-03-10-MM-72/`.

**Automated coverage:** 11/16 acceptance criteria verified by unit/integration tests in `cargo test`.

**Human verification:** 5 criteria require running the relay binary against a real filesystem and
inspecting the produced database with `sqlite3`. These criteria are runtime-only by nature (file
creation, WAL persistence on disk, idempotent startup across process restarts).

---

## Conventions

- **AC identifiers** use the slugged form from the design plan: `MM-72.AC1.1`, `MM-72.AC2.1`, etc.
- **Test file paths** are relative to the workspace root.
- **In-memory vs. file-backed:** The design explicitly requires unit tests to use `":memory:"` (AC5.1).
  However, WAL mode cannot be verified on an in-memory database (SQLite reports `journal_mode = "memory"`
  for in-memory connections). The implementation plan resolves this by using `tempfile::tempdir()` for the
  WAL test only (phase_02.md Task 3, `wal_mode_enabled_on_file_pool`). This is consistent with AC5.1
  because the acceptance criterion scopes the in-memory requirement to "migration runner unit tests" --
  the WAL test exercises `open_pool`, not `run_migrations`.
- **AC1.x runtime verification:** The design plan's AC1 criteria ("relay.db created on first start")
  inherently require running the binary. The implementation plan documents this explicitly in
  phase_03.md Task 3 ("These acceptance criteria require running the actual binary and cannot be
  automated with `cargo test` alone"). They appear below under Human Verification.

---

## Automated Tests

### MM-72.AC2.1 -- Migrations are idempotent (row count)

| Field | Value |
|-------|-------|
| **Criterion** | Running the relay a second time does not re-apply V001 -- row count in `schema_migrations` remains 1 |
| **Test type** | Unit |
| **Test file** | `crates/relay/src/db/mod.rs` (`#[cfg(test)] mod tests`) |
| **Test name** | `migrations_are_idempotent` |
| **Asserts** | Calls `run_migrations` twice on the same in-memory pool. Queries `SELECT COUNT(*) FROM schema_migrations` and asserts the count is exactly 1. |
| **Implementation phase** | phase_02.md Task 3 |

---

### MM-72.AC2.2 -- schema_migrations records version and timestamp

| Field | Value |
|-------|-------|
| **Criterion** | `schema_migrations` records `version = 1` with a non-null `applied_at` timestamp after first run |
| **Test type** | Unit |
| **Test file** | `crates/relay/src/db/mod.rs` (`#[cfg(test)] mod tests`) |
| **Test name** | `schema_migrations_records_version_and_timestamp` |
| **Asserts** | After `run_migrations`, queries `SELECT version, applied_at FROM schema_migrations WHERE version = 1`. Asserts `version == 1` and `applied_at` is a non-empty string. |
| **Implementation phase** | phase_02.md Task 3 |

---

### MM-72.AC3.1 -- Handler tests compile with db field in AppState

| Field | Value |
|-------|-------|
| **Criterion** | Handler tests that extract `State<AppState>` compile and pass with the `db: SqlitePool` field present |
| **Test type** | Integration (compile-time + runtime) |
| **Test file** | `crates/relay/src/app.rs` (`#[cfg(test)] mod tests`) |
| **Test names** | All 5 existing XRPC handler tests: `xrpc_get_unknown_method_returns_501`, `xrpc_post_unknown_method_returns_501`, `xrpc_delete_returns_405`, `xrpc_response_has_json_content_type`, `xrpc_response_body_is_method_not_implemented` |
| **Asserts** | These tests construct `AppState` via `test_state().await`, which includes the `db: SqlitePool` field. If the field were missing or the type wrong, the tests would fail to compile. All tests pass at runtime, confirming the router accepts the updated state. |
| **Implementation phase** | phase_03.md Task 1 (Steps 3-4: `test_state()` becomes async, all call sites updated to `.await`) |

---

### MM-72.AC3.2 -- SELECT 1 succeeds on AppState pool

| Field | Value |
|-------|-------|
| **Criterion** | `sqlx::query("SELECT 1").execute(&state.db)` succeeds in tests using an in-memory pool |
| **Test type** | Integration |
| **Test file** | `crates/relay/src/app.rs` (`#[cfg(test)] mod tests`) |
| **Test name** | `appstate_db_pool_is_queryable` |
| **Asserts** | Constructs `AppState` via `test_state().await`, then executes `sqlx::query("SELECT 1").execute(&state.db)`. Asserts the query completes without error. |
| **Implementation phase** | phase_03.md Task 1 (Step 5) |

---

### MM-72.AC4.1 -- WAL mode enabled

| Field | Value |
|-------|-------|
| **Criterion** | `PRAGMA journal_mode` queried on the pool returns `wal` |
| **Test type** | Unit |
| **Test file** | `crates/relay/src/db/mod.rs` (`#[cfg(test)] mod tests`) |
| **Test name** | `wal_mode_enabled_on_file_pool` |
| **Asserts** | Creates a file-backed pool via `open_pool` using a `tempfile::tempdir()` path. Queries `PRAGMA journal_mode` and asserts the result is the string `"wal"`. |
| **Design rationale** | Uses a temp file instead of `":memory:"` because in-memory SQLite always reports `journal_mode = "memory"`, making WAL verification impossible. This is documented in the test's own doc comment and is consistent with AC5.1's scope (which applies to "migration runner unit tests", not pool factory tests). The temp directory is cleaned up automatically by `tempfile` on drop. |
| **Implementation phase** | phase_02.md Task 3 |

---

### MM-72.AC5.1 -- Migration runner tests use in-memory SQLite

| Field | Value |
|-------|-------|
| **Criterion** | Migration runner unit tests use `":memory:"` -- no `relay.db` or temp files created on disk during `cargo test` |
| **Test type** | Unit (structural / convention) |
| **Test file** | `crates/relay/src/db/mod.rs` (`#[cfg(test)] mod tests`) |
| **Test names** | `select_one_succeeds`, `migrations_apply_on_first_run`, `migrations_are_idempotent`, `schema_migrations_records_version_and_timestamp`, `server_metadata_table_exists_and_accepts_inserts` |
| **Asserts** | All five migration-related tests call `in_memory_pool()` which opens `"sqlite::memory:"`. No test in this group creates files on disk. The sole exception -- `wal_mode_enabled_on_file_pool` -- tests the pool factory, not the migration runner, and uses `tempfile` (cleaned up on drop). |
| **Verification method** | Code review of test source. Additionally, running `cargo test --workspace` in a clean checkout and confirming no `relay.db` file appears anywhere in the workspace tree. |
| **Implementation phase** | phase_02.md Task 3 |

---

### MM-72.AC5.2 -- cargo test passes in clean environment

| Field | Value |
|-------|-------|
| **Criterion** | `cargo test --workspace` passes in a clean environment with no pre-existing `relay.db` |
| **Test type** | Integration (CI gate) |
| **Test file** | Entire workspace |
| **Test name** | N/A -- full workspace test suite |
| **Asserts** | `cargo test --workspace` exits 0. No `relay.db` file exists before or after the run. |
| **Verification method** | CI pipeline runs `cargo test --workspace` on every push. Can be manually verified by cloning fresh and running the command. |
| **Implementation phase** | phase_02.md Task 3 (Step 4), phase_03.md Task 1 (Step 7) |

---

### MM-72.AC6.1 -- cargo clippy passes

| Field | Value |
|-------|-------|
| **Criterion** | `cargo clippy --workspace -- -D warnings` passes with no warnings |
| **Test type** | Lint (CI gate) |
| **Test file** | Entire workspace |
| **Asserts** | `cargo clippy --workspace -- -D warnings` exits 0 with no diagnostic output. |
| **Verification method** | CI pipeline. Manually: run the command and verify exit code. |
| **Implementation phase** | phase_02.md Task 4 (Step 3), phase_03.md Task 2 (Step 6) |

---

### MM-72.AC6.2 -- cargo fmt passes

| Field | Value |
|-------|-------|
| **Criterion** | `cargo fmt --all --check` passes |
| **Test type** | Format check (CI gate) |
| **Test file** | Entire workspace |
| **Asserts** | `cargo fmt --all --check` exits 0 with no diff output. |
| **Verification method** | CI pipeline. Manually: run the command and verify exit code. |
| **Implementation phase** | phase_02.md Task 4 (Step 4), phase_03.md Task 2 (Step 6) |

---

## Supplementary Automated Tests (no direct AC mapping)

These tests are defined in the implementation plan but do not map 1:1 to a named acceptance criterion.
They provide coverage for implicit requirements (pool connectivity, schema correctness) that support
multiple ACs.

| Test name | Test file | Asserts | Supports ACs |
|-----------|-----------|---------|--------------|
| `select_one_succeeds` | `crates/relay/src/db/mod.rs` | `SELECT 1` returns 1 on an in-memory pool -- confirms pool is functional | AC3.2, AC5.1 |
| `migrations_apply_on_first_run` | `crates/relay/src/db/mod.rs` | After first `run_migrations`, `schema_migrations` has exactly 1 row | AC2.1, AC2.2 |
| `server_metadata_table_exists_and_accepts_inserts` | `crates/relay/src/db/mod.rs` | After migrations, `INSERT INTO server_metadata` succeeds and value is retrievable | AC1.3 (in-memory equivalent) |

---

## Human Verification

### MM-72.AC1.1 -- relay.db created on first start

| Field | Value |
|-------|-------|
| **Criterion** | `cargo run --bin relay` (with a valid `relay.toml`) creates `relay.db` in the configured `data_dir` |
| **Why not automated** | Requires running the actual binary with a real config file and filesystem. `cargo test` cannot exercise the `main.rs` startup path that reads `relay.toml`, constructs the database URL, and calls `open_pool` with a real file path. The binary also binds a TCP listener, which makes it unsuitable for headless test automation without process management. |
| **Implementation reference** | phase_03.md Task 3 (Steps 1-3) |
| **Manual steps** | |

| Step | Action | Expected |
|------|--------|----------|
| 1 | Create a `relay.toml` with `data_dir = "/tmp/relay-test"` and `public_url = "https://test.example.com"`. Run `mkdir -p /tmp/relay-test`. | Directory exists. |
| 2 | Run `cargo run --bin relay -- --config relay.toml` | Relay starts, logs "relay starting" and "listening". |
| 3 | Press Ctrl+C to stop the relay. | Relay shuts down cleanly. |
| 4 | Run `ls -la /tmp/relay-test/relay.db` | File exists. |
| 5 | Clean up: `rm -rf /tmp/relay-test relay.toml` | -- |

---

### MM-72.AC1.2 -- schema_migrations table exists in produced database

| Field | Value |
|-------|-------|
| **Criterion** | `schema_migrations` table exists in the produced database |
| **Why not automated** | Same as AC1.1 -- requires the real binary to have produced the database file. The in-memory test (`migrations_apply_on_first_run`) proves the runner creates the table, but AC1.2 specifically requires verifying the on-disk artifact produced by the binary. |
| **Implementation reference** | phase_03.md Task 3 (Step 4) |
| **Manual steps** | |

| Step | Action | Expected |
|------|--------|----------|
| 1 | After completing AC1.1 steps 1-3 (database file exists at `/tmp/relay-test/relay.db`): | -- |
| 2 | Run `sqlite3 /tmp/relay-test/relay.db ".tables"` | Output includes `schema_migrations`. |

---

### MM-72.AC1.3 -- server_metadata table exists in produced database

| Field | Value |
|-------|-------|
| **Criterion** | `server_metadata` table exists in the produced database |
| **Why not automated** | Same rationale as AC1.2. The in-memory test (`server_metadata_table_exists_and_accepts_inserts`) proves the migration creates the table, but AC1.3 requires verifying the on-disk artifact. |
| **Implementation reference** | phase_03.md Task 3 (Step 4) |
| **Manual steps** | |

| Step | Action | Expected |
|------|--------|----------|
| 1 | After completing AC1.1 steps 1-3 (database file exists at `/tmp/relay-test/relay.db`): | -- |
| 2 | Run `sqlite3 /tmp/relay-test/relay.db ".tables"` | Output includes `server_metadata`. |

---

### MM-72.AC2.1 -- Idempotent across process restarts (runtime)

| Field | Value |
|-------|-------|
| **Criterion** | Running the relay a second time does not re-apply V001 -- row count in `schema_migrations` remains 1 |
| **Why not automated** | The unit test `migrations_are_idempotent` calls `run_migrations` twice on the same in-memory pool within a single process, which verifies the runner logic. However, AC2.1 as stated in phase_03.md Task 3 also requires verifying idempotency across separate binary invocations (process restart), which exercises the full startup path including URL formatting, file-backed pool reopening, and `schema_migrations` persistence on disk. |
| **Note** | This criterion has **dual coverage**: the automated unit test verifies the core logic, and the manual steps below verify the end-to-end runtime behavior. Both are required for full confidence. |
| **Implementation reference** | phase_03.md Task 3 (Steps 6-7) |
| **Manual steps** | |

| Step | Action | Expected |
|------|--------|----------|
| 1 | After completing AC1.1 steps 1-4 (relay has been started and stopped once, database file exists): | -- |
| 2 | Run `sqlite3 /tmp/relay-test/relay.db "SELECT COUNT(*) FROM schema_migrations;"` | Output: `1` |
| 3 | Run `cargo run --bin relay -- --config relay.toml` a second time. Press Ctrl+C after "listening" appears. | Relay starts and stops cleanly. |
| 4 | Run `sqlite3 /tmp/relay-test/relay.db "SELECT COUNT(*) FROM schema_migrations;"` | Output: still `1` (not `2`). |

---

### MM-72.AC4.1 -- WAL mode on production database (runtime)

| Field | Value |
|-------|-------|
| **Criterion** | `PRAGMA journal_mode` queried on the pool returns `wal` |
| **Why partially automated** | The automated test `wal_mode_enabled_on_file_pool` verifies that `open_pool` sets WAL mode on a temp file. This is sufficient to prove the pool factory works correctly. However, for completeness, operators may want to verify that the production database file produced by the binary is also in WAL mode. This is optional -- the automated test is the primary verification. |
| **Note** | This criterion has **primary automated coverage** via `wal_mode_enabled_on_file_pool`. The manual step below is supplementary. |
| **Implementation reference** | phase_02.md Task 3 (`wal_mode_enabled_on_file_pool` test) |
| **Manual steps (optional)** | |

| Step | Action | Expected |
|------|--------|----------|
| 1 | After completing AC1.1 steps 1-3 (database file exists at `/tmp/relay-test/relay.db`): | -- |
| 2 | Run `sqlite3 /tmp/relay-test/relay.db "PRAGMA journal_mode;"` | Output: `wal` |
| 3 | Run `ls /tmp/relay-test/relay.db-wal` | WAL file exists (created by SQLite when WAL mode is active). |

---

## Traceability Matrix

| Acceptance Criterion | Automated Test | Human Verification | Notes |
|----------------------|----------------|-------------------|-------|
| MM-72.AC1.1 (relay.db created) | -- | AC1.1 manual steps | Runtime-only; requires binary execution |
| MM-72.AC1.2 (schema_migrations exists) | `server_metadata_table_exists_and_accepts_inserts` (indirect) | AC1.2 manual steps | In-memory test proves runner logic; manual verifies on-disk artifact |
| MM-72.AC1.3 (server_metadata exists) | `server_metadata_table_exists_and_accepts_inserts` | AC1.3 manual steps | In-memory test proves runner logic; manual verifies on-disk artifact |
| MM-72.AC2.1 (idempotent) | `migrations_are_idempotent` | AC2.1 manual steps | Unit test covers logic; manual covers cross-process restart |
| MM-72.AC2.2 (version + timestamp) | `schema_migrations_records_version_and_timestamp` | -- | Fully automated |
| MM-72.AC3.1 (AppState compiles) | 5 existing XRPC handler tests | -- | Compilation is the test; runtime confirms router accepts state |
| MM-72.AC3.2 (SELECT 1 on state.db) | `appstate_db_pool_is_queryable` | -- | Fully automated |
| MM-72.AC4.1 (WAL mode) | `wal_mode_enabled_on_file_pool` | AC4.1 manual steps (optional) | Automated test is primary; manual is supplementary |
| MM-72.AC5.1 (in-memory tests) | Code review + 5 migration tests | -- | Structural: verify `in_memory_pool()` uses `"sqlite::memory:"` |
| MM-72.AC5.2 (clean cargo test) | `cargo test --workspace` | -- | CI gate; no relay.db created |
| MM-72.AC6.1 (clippy) | `cargo clippy --workspace -- -D warnings` | -- | CI gate |
| MM-72.AC6.2 (fmt) | `cargo fmt --all --check` | -- | CI gate |

---

## Prerequisites

- Development shell activated: `nix develop --impure --accept-flake-config`
- Branch rebased onto `main` (requires `AppState` from MM-71)
- All three implementation phases completed (phase_01, phase_02, phase_03)
- `cargo test --workspace` exits 0
- `cargo clippy --workspace -- -D warnings` exits 0
- `cargo fmt --all --check` exits 0
- `sqlite3` CLI available in shell (provided by devenv)

## Execution Order

1. Run `cargo test --workspace` -- covers all automated criteria (AC2.1, AC2.2, AC3.1, AC3.2, AC4.1, AC5.1, AC5.2)
2. Run `cargo clippy --workspace -- -D warnings` -- covers AC6.1
3. Run `cargo fmt --all --check` -- covers AC6.2
4. Execute human verification steps for AC1.1 through AC1.3 (single relay start)
5. Execute human verification steps for AC2.1 (second relay start)
6. Optionally execute human verification for AC4.1 (WAL mode on production file)
7. Clean up: `rm -rf /tmp/relay-test relay.toml`
