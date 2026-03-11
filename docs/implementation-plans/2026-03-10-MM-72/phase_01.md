# MM-72 SQLite Migration Infrastructure — Implementation Plan

**Goal:** Add `sqlx` to the workspace and verify the build is clean before any db module code is written.

**Architecture:** Infrastructure-only phase. Two Cargo.toml edits and a build check. No functional code, no tests.

**Tech Stack:** Rust stable, Cargo workspace, sqlx 0.8 (`runtime-tokio` + `sqlite` features)

**Scope:** Phase 1 of 3 from the original design plan.

**Codebase verified:** 2026-03-10

---

## Acceptance Criteria Coverage

This phase is infrastructure. It establishes the dependency but introduces no behaviour to test.

**Verifies: None** — Phase 1 is verified operationally (`cargo build` + `cargo clippy` passing).

---

<!-- START_TASK_1 -->
### Task 1: Add sqlx to workspace Cargo.toml

**Files:**
- Modify: `Cargo.toml` (workspace root — after the `axum` entry in `[workspace.dependencies]`)

**Step 1: Insert sqlx into [workspace.dependencies]**

Open `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/Cargo.toml`.

After the `axum = "0.7"` entry and its blank line, add a `# Database` section:

```toml
# Web framework (relay)
axum = "0.7"

# Database
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite"] }

# Serialization
```

The file should look like this around the insertion point:

```toml
# Web framework (relay)
axum = "0.7"

# Database
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite"] }

# Serialization
serde = { version = "1", features = ["derive"] }
```

**Step 2: Verify the edit**

Run:
```bash
grep -n "sqlx" Cargo.toml
```
Expected output: one line showing `sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite"] }`.

**Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "chore(deps): add sqlx 0.8 to workspace dependencies"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Opt relay crate into sqlx

**Files:**
- Modify: `crates/relay/Cargo.toml` — add `sqlx` to `[dependencies]`, after the `tower-http` entry and before `[dev-dependencies]`

**Step 1: Insert sqlx into relay [dependencies]**

Open `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/crates/relay/Cargo.toml`.

After the `tower-http = { workspace = true }` entry in `[dependencies]`, add:

```toml
tower-http = { workspace = true }
sqlx = { workspace = true }

[dev-dependencies]
```

The `[dependencies]` section should look like this after the edit:

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

**Step 2: Verify the edit**

Run:
```bash
grep -n "sqlx" crates/relay/Cargo.toml
```
Expected output: one line showing `sqlx = { workspace = true }`.

**Step 3: Verify build and lint pass**

Run:
```bash
cargo build --workspace
```
Expected: compiles successfully. On first run, cargo will download and compile sqlx and its dependencies including `libsqlite3-sys`. If `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set (devenv auto-sets it), sqlx links against the Nix-provided SQLite. If absent (CI/Docker), it compiles bundled SQLite — no action needed either way.

Run:
```bash
cargo clippy --workspace -- -D warnings
```
Expected: zero warnings, zero errors.

**Step 4: Commit**

```bash
git add crates/relay/Cargo.toml
git commit -m "chore(deps): opt relay into sqlx workspace dependency"
```
<!-- END_TASK_2 -->
