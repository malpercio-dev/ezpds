# Phase 01 — Crate & build rename

**Goal:** Move `crates/relay/` → `crates/pds/` and rename the cargo package + binary from `relay` to `pds`, so the workspace builds under the new name. Foundation for everything else.

**Architecture:** Pure mechanical rename of the crate directory, package name, binary target, and workspace membership. No source logic changes. `git mv` preserves history; relative `include_bytes!` asset paths move with the directory and need no edits.

**Scope:** Phase 1 of 6.

**Codebase verified:** 2026-06-26.

**Verifies:** None (infrastructure refactor — verified operationally: `cargo build --workspace`).

> Read `00-overview.md` first — especially the "two senses of relay" keep-list. This phase touches only crate/build wiring, all Sense-A.

---

<!-- START_TASK_1 -->
### Task 1: Move the crate directory with git

**Files:**
- Rename: `crates/relay/` → `crates/pds/` (entire directory, including `src/`, `assets/`, `Cargo.toml`, `AGENTS.md`, `src/db/AGENTS.md`, all migrations)

**Step 1: Move the directory**

```bash
git mv crates/relay crates/pds
```

**Step 2: Verify the move**

```bash
git status        # expect: renamed: crates/relay/... -> crates/pds/...
ls crates/pds/src/main.rs crates/pds/Cargo.toml crates/pds/assets/fonts
```
Expected: all paths exist under `crates/pds/`.

**Note:** Do NOT touch `crates/pds/src/db/migrations/*.sql` contents or filenames — `V003__relay_signing_keys.sql` and the `relay_signing_keys` table name are immutable (see overview constraint 1). The file moves with the directory; its name stays `V003__relay_signing_keys.sql`.

**Note:** `crates/pds/src/routes/static_assets.rs` uses `include_bytes!("../../assets/fonts/...")` — relative paths, so they remain valid after the move. No edit needed; confirm in Task 4's build.

**Do not commit yet** — the workspace won't build until Tasks 2–3 land. Commit at Task 5.
<!-- END_TASK_1 -->

<!-- START_SUBCOMPONENT_A (tasks 2-3) -->
<!-- START_TASK_2 -->
### Task 2: Rename the package and binary in the crate's Cargo.toml

**Files:**
- Modify: `crates/pds/Cargo.toml:1-11`

**Implementation:** Change the package name and binary target name from `relay` to `pds`. Update the descriptive comment.

Current:
```toml
[package]
name = "relay"
version.workspace = true
edition.workspace = true
publish.workspace = true

# relay is the network-facing binary: Axum HTTP server, XRPC handlers,
# OAuth, provisioning API, blob storage.
[[bin]]
name = "relay"
path = "src/main.rs"
```

Change to:
```toml
[package]
name = "pds"
version.workspace = true
edition.workspace = true
publish.workspace = true

# pds is the network-facing binary (the Custos PDS): Axum HTTP server, XRPC
# handlers, OAuth, provisioning API, blob storage.
[[bin]]
name = "pds"
path = "src/main.rs"
```

**Verification:** `grep -n 'name = "relay"' crates/pds/Cargo.toml` → no matches.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update the workspace member path in root Cargo.toml

**Files:**
- Modify: `Cargo.toml:2-8` (workspace `members`)
- Modify: `Cargo.toml` dependency-group comments at lines ~22, ~25, ~37, ~78 (cosmetic: `(relay)` → `(pds)`)

**Implementation:** Change the member path `"crates/relay"` → `"crates/pds"`.

Current:
```toml
[workspace]
members = [
    "crates/relay",
    "crates/repo-engine",
    "crates/crypto",
    "crates/common",
    "apps/identity-wallet/src-tauri",
]
```

Change `"crates/relay"` to `"crates/pds"`.

Then update the cosmetic comments that label workspace deps as belonging to the relay (Sense-A):
```bash
# In root Cargo.toml only — review each hit; these are comments like "# Web framework (relay)"
grep -n '(relay' Cargo.toml
```
Replace `(relay` with `(pds` / `(pds auth` as appropriate in those comment lines. Also `crates/common/Cargo.toml` has a comment "# relay enables this; pure-logic crates do not" → change to "# pds enables this; pure-logic crates do not".

**Verification:** `grep -rn 'crates/relay' Cargo.toml` → no matches.
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_4 -->
### Task 4: Rename the telemetry service/tracer name

**Files:**
- Modify: `crates/common/src/config.rs:157` — `service_name: "ezpds-relay"` → `"ezpds-pds"`
- Modify: `crates/pds/src/telemetry.rs:77` — `provider.tracer("relay")` → `provider.tracer("pds")`

**Implementation:** These are the OpenTelemetry service identity strings for our component (Sense-A). Rename both. Confirm exact lines first:
```bash
grep -n 'ezpds-relay' crates/common/src/config.rs
grep -n 'tracer("relay")' crates/pds/src/telemetry.rs
```

**Verification:** `grep -rn 'ezpds-relay\|tracer("relay")' crates/` → no matches.
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Build, then commit

**Step 1: Build the whole workspace**

```bash
cargo build --workspace
```
Expected: builds cleanly. The binary is now `target/debug/pds`. If `include_bytes!` font paths fail, the directory move in Task 1 was incomplete — re-check `crates/pds/assets/fonts/`.

**Step 2: Sanity-check the binary name**

```bash
ls target/debug/pds
```
Expected: exists.

**Step 3: Commit**

```bash
git add -A
git commit -m "refactor(pds): rename relay crate to pds

The server is an AT Protocol PDS; 'relay' collided with atproto's
network-wide Relay (firehose aggregator). Crate, package, binary, and
telemetry names move to pds. Build wiring only; no behavior change."
```

> Deployment wiring (Dockerfile `-p relay`, justfile, CI) still references the old binary name and is fixed in Phase 02. The workspace `cargo build` is green; the Docker/CI gates are intentionally addressed next.
<!-- END_TASK_5 -->
