# Relay Containerization — Phase 1: Relay container-readiness

**Goal:** Make the relay build and run in a non-Nix container — TLS via rustls (no OpenSSL), SQLite bundled from source, and full configuration from environment variables including a `PORT` fallback and tolerating a missing config file.

**Architecture:** Small, behavior-preserving relay changes: switch `reqwest` to rustls (relay-local), add a `PORT`→port fallback and make a missing config file non-fatal in the config layer, and confirm `libsqlite3-sys` bundles SQLite when `LIBSQLITE3_SYS_USE_PKG_CONFIG` is unset.

**Tech Stack:** Rust, `reqwest` (rustls-tls), `sqlx`/`libsqlite3-sys` (bundled), the relay's `EZPDS_*` env config in `crates/common/src/config.rs`.

**Scope:** Phase 1 of 6 from `docs/design-plans/2026-06-20-relay-containerization.md`.

**Codebase verified:** 2026-06-20 (codebase-investigator).

> **Verified facts (do not re-derive):**
> - Config struct: `crates/common/src/config.rs:22-43`. Env parsing (`EZPDS_*`): `config.rs:188-254`. Defaults/validation: `config.rs:265-366`. Required fields: `data_dir`, `public_url` (must start `https://`), `available_user_domains` (non-empty).
> - Loader: `crates/relay/src/main.rs:35-56` — `--config <path>` or `EZPDS_CONFIG`, defaults to `relay.toml`; **errors if the file is absent**.
> - Port: read from `EZPDS_PORT` (`config.rs:195`), default 8080. **No `$PORT` support.**
> - `reqwest`: workspace dep `Cargo.toml:26` = `{ version = "0.12", features = ["json"] }` (native-tls default). **Only `crates/relay` depends on it** (`crates/relay/Cargo.toml:31`).
> - sqlx: runtime queries only (no `query!` macros, no `.sqlx/` cache) → no build-time `DATABASE_URL`. Migrations `include_str!`-embedded, auto-run on startup (`crates/relay/src/db/mod.rs:30-209`).
> - Health route: `GET /xrpc/_health` (`crates/relay/src/app.rs:162`).

> **Platform note:** Steps run on any machine with the Rust toolchain (the dev shell). No Docker needed in this phase.

---

## Acceptance Criteria Coverage

### relay-containerization.AC1: Container builds & runs the relay — no Nix, no OpenSSL, env-configured
- **relay-containerization.AC1.2 Success:** `cargo build --release -p relay` succeeds with `LIBSQLITE3_SYS_USE_PKG_CONFIG` unset (bundled SQLite compiled from source).
- **relay-containerization.AC1.3 Success:** the relay's `reqwest` uses rustls; the runtime image contains no `libssl`/OpenSSL. *(Image-level check lands in Phase 2; this phase removes the OpenSSL link.)*
- **relay-containerization.AC1.4 Success:** the relay starts from environment variables alone (no `--config` file) and binds the port given by `$PORT`.

### relay-containerization.AC6: No behavior/scope regression
- **relay-containerization.AC6.1 Success:** relay routes/behavior are unchanged — `cargo test --workspace` passes.

**Verifies (this phase):** AC1.2, AC1.4, AC6.1, and the relay-side half of AC1.3 (rustls swap; absence-of-libssl is confirmed on the image in Phase 2).

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Switch the relay's `reqwest` to rustls (drop OpenSSL)

**Files:**
- Modify: `crates/relay/Cargo.toml:31` (the `reqwest` line)

**Implementation:** Replace the workspace `reqwest` use in the relay with a relay-local dependency that disables default features and enables rustls — mirroring `apps/identity-wallet/src-tauri/Cargo.toml`. Change line 31 from:
```toml
reqwest = { workspace = true }
```
to:
```toml
# rustls (not native-tls): no system OpenSSL needed in the container image.
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```
Leave the workspace `Cargo.toml:26` line as-is (no other crate uses it; changing it is unnecessary and out of scope).

**Verification:**
Run: `cargo build -p relay`
Expected: builds. Then confirm no OpenSSL in the dependency graph:
Run: `cargo tree -p relay -i openssl-sys 2>&1 | head` and `cargo tree -p relay -e features | grep -i native-tls`
Expected: `openssl-sys` is **not** a dependency (cargo tree reports "package ID specification ... did not match any packages" or empty); no `native-tls` feature pulled. `rustls` appears in `cargo tree -p relay | grep rustls`.

**Commit:** `git commit -am "build(relay): use rustls-tls for reqwest (drop OpenSSL)"`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Env-only config — `PORT` fallback + tolerate a missing config file

**Verifies:** relay-containerization.AC1.4

**Files (verified against the FCIS layout — env is injected as a map into a pure core; `std::env`/file IO is the shell):**
- Modify: `crates/common/src/config.rs` — add the `PORT` fallback in the **pure** `apply_env_overrides` (the fn that maps the `EZPDS_*` env map onto config; port handling is around `:195`).
- Modify: `crates/common/src/config_loader.rs` — the actual file read that errors on a missing file is `std::fs::read_to_string(path)` here (~`:36`, surfaced as `ConfigError::Io`); `collect_ezpds_env` (~`:47`) builds the env map. Add a missing-file-tolerant load path here and capture bare `PORT` in `collect_ezpds_env`.
- Modify: `crates/relay/src/main.rs` (~`:53-55`) — only the **defaulted** path should tolerate absence (the path is `cli.config.unwrap_or_else(|| "relay.toml".into())`).
- Test: `crates/common` config tests — use the existing injectable seam `load_config_with_env(path, &env)` (~`config_loader.rs:32`).

**Implementation:**
1. **`PORT` fallback (Functional Core)** — in `config.rs::apply_env_overrides`, when resolving the port, if the `EZPDS_PORT` key is absent from the injected env map, fall back to a `PORT` key before the `8080` default. Precedence: `EZPDS_PORT` → `PORT` → `8080`. Keep parsing/validation identical. Ensure `collect_ezpds_env` (`config_loader.rs`) also collects a bare `PORT` so it reaches the core.
2. **Missing-config-file tolerance (Imperative Shell)** — in `main.rs`, branch on whether `cli.config`/`EZPDS_CONFIG` was explicitly set:
   - **Explicit** path missing → **still error** (don't mask misconfiguration).
   - **Default** `relay.toml` absent → load from defaults + env only (a `config_loader` entry point that parses an empty `RawConfig`, then `apply_env_overrides` + `validate_and_build`), instead of erroring on the missing file.

**Testing (use the `load_config_with_env(path, &env)` seam — no process-env mutation, no parallelism hazard):**
- **Env-only load (AC1.4):** missing file + an env map with `EZPDS_PUBLIC_URL`, `EZPDS_DATA_DIR`, `EZPDS_AVAILABLE_USER_DOMAINS` → loads OK; `Config` reflects the env values.
- **Port precedence:** `EZPDS_PORT` only → that; `PORT` only → that; both → `EZPDS_PORT` wins; neither → `8080`.
- **Explicit missing path still errors.**
The task-implementor writes the test code against the seam (this avoids touching shared `std::env`, so the `RUST_TEST_THREADS=1` serialization isn't needed for these tests).

**Verification:**
Run: `cargo test -p common`
Expected: new tests pass.

**Commit:** `git commit -am "feat(relay): env-only config — PORT fallback (pure), tolerate missing default config file"`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_3 -->
### Task 3: Confirm bundled SQLite builds with no system dependency

**Verifies:** relay-containerization.AC1.2

**Files:** none (verification; the workspace already declares `sqlx` with the `sqlite` feature).

**Implementation/notes:** `libsqlite3-sys` compiles vendored SQLite when `LIBSQLITE3_SYS_USE_PKG_CONFIG` is unset. The devenv shell sets that var (to link Nix's SQLite), so verify in a shell where it is unset — which is exactly the Docker build environment. If a future need arises to force bundling regardless of env, add `libsqlite3-sys = { version = "*", features = ["bundled"] }` is NOT needed because sqlx already enables bundling by default; do not add it unless Task verification shows otherwise.

**Verification:**
Run: `env -u LIBSQLITE3_SYS_USE_PKG_CONFIG cargo build --release -p relay`
Expected: builds successfully, compiling SQLite from source (you'll see `libsqlite3-sys` build script compiling C). This proves the relay needs no system `libsqlite3` — the precondition for the Dockerfile in Phase 2.

**Commit:** none (verification only). If a Cargo change was required, commit it: `git commit -am "build(relay): ensure bundled SQLite without pkg-config"`.
<!-- END_TASK_3 -->

---

## Phase 1 Done When

- `cargo build -p relay` uses rustls; `openssl-sys` is absent from the relay dep graph (AC1.3, relay side).
- `env -u LIBSQLITE3_SYS_USE_PKG_CONFIG cargo build --release -p relay` succeeds (AC1.2).
- The relay loads config from env with no config file, and `PORT` is honored when `EZPDS_PORT` is unset (AC1.4), verified by new tests.
- `cargo test --workspace` passes (AC6.1).
- Changes committed.
