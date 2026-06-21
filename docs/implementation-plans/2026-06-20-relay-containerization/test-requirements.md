# Relay Containerization — Test Requirements

**Design:** `docs/design-plans/2026-06-20-relay-containerization.md`
**Phases:** `docs/implementation-plans/2026-06-20-relay-containerization/phase_01.md` … `phase_06.md`
**Created:** 2026-06-20

## How to read this document

This is an **infrastructure** plan (Dockerfile + Railway + NixOS `oci-containers` + flake cleanup + docs).
Verification is therefore **mostly operational** — shell/docker/grep assertions and human confirmation in
Railway/NixOS — **not** unit tests. The **one** exception is **Phase 1's config behavior** (the `PORT`
fallback and missing-config-file tolerance), which is a pure-function change in `crates/common` and **does**
get Rust unit tests through the existing injectable seam.

Each acceptance-criterion sub-item (`relay-containerization.AC1.1` … `AC6.2`) is mapped to **exactly one** of
three approaches:

- **Automated unit test** — Phase 1 config behavior only. Type `unit`, target `crates/common`, exercised via
  the `load_config_with_env(path, &env)` seam.
- **Automated / scriptable operational check** — an exact shell/docker/grep command that asserts the criterion.
  Tagged with the environment it requires.
- **Human / environment verification** — a person confirms state in Railway or on the NixOS lab host (e.g. a
  redeploy preserved data on a volume).

### Environment tags (used throughout)

| Tag | Meaning |
|---|---|
| `[any machine]` | Runs on any machine with the repo + Rust toolchain (the devenv dev shell). No Docker, no cloud. |
| `[requires Docker]` | Needs a local Docker daemon (Docker Desktop / colima / podman) on the dev Mac or any Linux host. |
| `[requires Railway account]` | Needs a Railway account + project; cannot run in this repo or on a bare dev machine. |
| `[requires NixOS lab host + Nix]` | Needs the NixOS lab host and/or a Nix install (`nix flake check` needs Nix; colmena deploy + on-host checks need the lab host). |

### Critical preconditions — read before relying on any "automated" item

- **There is NO CI in this repository.** Nothing runs automatically on push or PR. Every "automated/scriptable"
  command below is something a human (or executor agent) must run **manually** in the right environment and
  read the output of. "Automated" here means *scriptable and deterministic*, **not** *runs in CI*.
  (Phase 5 Task 1 even notes a publish GH Action is *optional* and out of scope — "there is no CI today.")
- **Railway steps need a Railway account.** AC3.1–AC3.3 cannot be verified without one. The plan explicitly
  marks these `[requires a Railway account/project]` and "cannot be verified in CI or on a bare dev machine."
- **NixOS steps need the lab host.** AC4.1/AC4.2 require a colmena deploy to the lab host. AC4.3's
  `nix flake check` needs a Nix install but not the lab host.
- **Docker steps need a local Docker daemon.** AC1.1, AC1.3 (image side), AC1.5, AC2.1, AC2.2, AC5.1 all
  require Docker to build/run/inspect the image.
- **Chicken-and-egg (Railway, AC3.x):** `EZPDS_PUBLIC_URL` must be the Railway-assigned domain, known only
  *after* you generate it. Generate the domain → set the variable → redeploy, then run the health check.
- **Required runtime env for any container run** (from `crates/common/src/config.rs` validation):
  `EZPDS_PUBLIC_URL` (**must** start `https://`), `EZPDS_AVAILABLE_USER_DOMAINS` (non-empty, comma-separated),
  `EZPDS_SIGNING_KEY_MASTER_KEY` (64-hex → 32 bytes), writable `EZPDS_DATA_DIR` (image default `/data`).
  `EZPDS_ADMIN_TOKEN` optional. A run that omits a required var fails validation and is **not** a valid
  health-check target — confirm these are set before asserting AC2.1/AC3.1/AC4.1.

---

## AC1 — Container builds & runs the relay (no Nix, no OpenSSL, env-configured)

### relay-containerization.AC1.1 — `docker build` produces a relay image with no Nix
- **Approach:** Automated/scriptable operational check — **[requires Docker]**
- **Source:** Phase 2, Task 4, Step 1.
- **Command:**
  ```bash
  docker build -t ezpds-relay:dev .
  ```
- **Assert:** Build completes successfully. The build-stage logs show `libsqlite3-sys` compiling SQLite from
  source and **no** Nix being pulled (the build uses `rust:bookworm` + Cargo only). Build context is governed
  by the `.dockerignore` from Phase 2 Task 1.

### relay-containerization.AC1.2 — `cargo build --release -p relay` with `LIBSQLITE3_SYS_USE_PKG_CONFIG` unset (bundled SQLite)
- **Approach:** Automated/scriptable operational check — **[any machine]**
- **Source:** Phase 1, Task 3.
- **Command:**
  ```bash
  env -u LIBSQLITE3_SYS_USE_PKG_CONFIG cargo build --release -p relay
  ```
- **Assert:** Builds successfully, compiling SQLite from vendored C source (the `libsqlite3-sys` build script
  runs the C compiler). Proves the relay needs no system `libsqlite3` — the precondition for the Dockerfile.
- **Note:** This is a build-success check, not a unit test. The devenv shell normally *sets*
  `LIBSQLITE3_SYS_USE_PKG_CONFIG`; `env -u` unsets it to mirror the Docker build environment.

### relay-containerization.AC1.3 — relay's `reqwest` uses rustls; runtime image contains no `libssl`/OpenSSL
This criterion has two halves verified in two phases; both are scriptable. **One approach overall: automated/scriptable operational check.**

- **Relay-side (dependency graph) — [any machine]** — Phase 1, Task 1:
  ```bash
  cargo build -p relay
  cargo tree -p relay -i openssl-sys 2>&1 | head
  cargo tree -p relay -e features | grep -i native-tls
  cargo tree -p relay | grep rustls
  ```
  **Assert:** `openssl-sys` is **not** in the graph (cargo reports "package ID specification … did not match
  any packages", or empty); no `native-tls` feature pulled; `rustls` is present.
- **Image-side (runtime image) — [requires Docker]** — Phase 2, Task 4, Step 2:
  ```bash
  docker run --rm --entrypoint /bin/sh ezpds-relay:dev -c "ldd /usr/local/bin/relay | grep -i ssl || echo NO_OPENSSL"
  docker run --rm --entrypoint /bin/sh ezpds-relay:dev -c "dpkg -l | grep -i openssl || echo NO_OPENSSL_PKG"
  ```
  **Assert:** prints `NO_OPENSSL` and `NO_OPENSSL_PKG` — the binary links no libssl and the slim image installs
  no openssl package.

### relay-containerization.AC1.4 — relay starts from environment variables alone (no `--config` file) and binds the port given by `$PORT`
This is the **only** AC with an automated **unit-test** mapping. It is verified at two levels; the *unit test* is the primary acceptance evidence for the config behavior, and the in-container run is corroborating.

- **PRIMARY — Automated unit test — [any machine]** — Phase 1, Task 2:
  - **Type:** `unit`
  - **Target file:** `crates/common` config tests — added next to the existing `#[cfg(test)]` blocks in
    `crates/common/src/config_loader.rs` (already host the seam tests at `:60-121`) and/or
    `crates/common/src/config.rs` (already host `apply_env_overrides` tests at `:440-885`).
  - **Seam:** `load_config_with_env(path, &env)` (`config_loader.rs:32`) — a `HashMap<String,String>` env map is
    injected into the pure core, so tests touch **no** process env and need no `RUST_TEST_THREADS=1`
    serialization. `apply_env_overrides` (`config.rs:188`) reads the port at `:195`.
  - **Cases this test must verify (each maps to the AC1.4 behavior):**
    1. **Env-only load (no config file):** a non-existent/empty path + an env map with `EZPDS_PUBLIC_URL`,
       `EZPDS_DATA_DIR`, `EZPDS_AVAILABLE_USER_DOMAINS` → loads OK and the resulting `Config` reflects the env
       values (proves "starts from env alone, no `--config` file").
    2. **Port precedence — `EZPDS_PORT` only:** resolves to that value.
    3. **Port precedence — `PORT` only (the `$PORT` fallback):** resolves to that value (proves Railway's
       injected `$PORT` is honored).
    4. **Port precedence — both set:** `EZPDS_PORT` wins.
    5. **Port precedence — neither set:** defaults to `8080`.
    6. **Explicit missing path still errors:** an *explicitly supplied* config path that is absent → returns an
       error (don't mask misconfiguration; only the *defaulted* `relay.toml` path tolerates absence).
  - **Command:** `cargo test -p common`
  - **Assert:** the new cases pass.
- **Corroborating — Automated/scriptable operational check — [requires Docker]** — Phase 3, Task 1, Step 2
  (runs the container with env only, `PORT=8080`, no config file mounted):
  ```bash
  curl -fsS http://localhost:8080/xrpc/_health && echo
  docker logs ezpds-relay 2>&1 | grep -iE "listening|migrat|config" | head
  ```
  **Assert:** health is 200; logs show the port bound and migrations run, with **no** error about a missing
  `relay.toml`. *(Mapped under AC1.4 here; AC2.1 owns the health-200 assertion itself.)*

### relay-containerization.AC1.5 — `EZPDS_SIGNING_KEY_MASTER_KEY` supplied at runtime; absent from image layers and git
- **Approach:** Automated/scriptable operational check — **[requires Docker]** (the git half also runs `[any machine]`)
- **Source:** Phase 3, Task 1, Step 3.
- **Command:**
  ```bash
  docker history --no-trunc ezpds-relay:dev | grep -i EZPDS_SIGNING_KEY_MASTER_KEY || echo NOT_IN_IMAGE
  git grep -nI "EZPDS_SIGNING_KEY_MASTER_KEY" -- Dockerfile docker-compose.yaml compose.yaml 2>/dev/null || echo NOT_IN_BUILD_FILES
  ```
- **Assert:** prints `NOT_IN_IMAGE` and `NOT_IN_BUILD_FILES` — the key arrives only via runtime `-e`/env, never
  baked into a layer or committed.

---

## AC2 — Stateful & healthy locally

### relay-containerization.AC2.1 — `docker run` with a volume at `EZPDS_DATA_DIR` → `/xrpc/_health` returns 200
- **Approach:** Automated/scriptable operational check — **[requires Docker]**
- **Source:** Phase 3, Task 1, Steps 1-2.
- **Setup + command:**
  ```bash
  docker volume create ezpds-data
  docker run -d --name ezpds-relay -p 8080:8080 \
    -v ezpds-data:/data \
    -e EZPDS_PUBLIC_URL="https://relay.local" \
    -e EZPDS_AVAILABLE_USER_DOMAINS="example.com" \
    -e EZPDS_SIGNING_KEY_MASTER_KEY="2a55ebbdb7c0a4864a3944a443765b13602c6fbbeda38c2d6afc57b96663810e" \
    -e EZPDS_ADMIN_TOKEN="local-admin-token" \
    -e PORT="8080" \
    ezpds-relay:dev
  sleep 2
  curl -fsS http://localhost:8080/xrpc/_health && echo
  ```
- **Assert:** `/xrpc/_health` returns HTTP 200 with JSON (e.g. `{"version":…,"db":"ok"}`). The volume is mounted
  at `/data` (the image's `EZPDS_DATA_DIR`). `curl -fsS` exits non-zero on any non-2xx, so a clean exit + JSON
  is the pass signal.

### relay-containerization.AC2.2 — data persists across a container restart (same volume reuses the SQLite DB; migrations idempotent, no data loss)
- **Approach:** Automated/scriptable operational check — **[requires Docker]**
- **Source:** Phase 3, Task 2, Steps 1-2.
- **Command:**
  ```bash
  docker exec ezpds-relay ls -la /data                  # DB file present after first run
  docker restart ezpds-relay
  sleep 2
  curl -fsS http://localhost:8080/xrpc/_health && echo
  docker logs ezpds-relay 2>&1 | tail -n 20 | grep -iE "migrat" || echo "no pending migrations on restart (expected)"
  ```
- **Assert:** a SQLite DB file (e.g. `relay.db`) exists on the volume; after restart health is 200 again and the
  second start applies **no** new migrations (idempotent — `schema_migrations` already records them), reusing
  the same DB file. No data loss.

---

## AC3 — Railway deployment

> All AC3 items **[require a Railway account]** and are verified operationally on Railway. There is no way to
> assert these in this repo, in CI (none exists), or on a bare dev machine.

### relay-containerization.AC3.1 — Railway builds the committed Dockerfile and deploys; public domain serves `/xrpc/_health` 200
- **Approach:** Human / environment verification (with a scriptable health probe) — **[requires Railway account]**
- **Source:** Phase 4, Tasks 1-3.
- **Human steps:** create a Railway service from the repo so it builds via the `Dockerfile` (forced by the
  committed `railway.toml` `builder = "DOCKERFILE"`); confirm in the Railway build logs the **Dockerfile**
  builder ran (not Nixpacks) and the deploy went healthy; generate the public domain.
- **Scriptable probe (after the domain exists):**
  ```bash
  curl -fsS https://<your-railway-domain>/xrpc/_health && echo
  ```
- **Assert:** HTTP 200 + JSON from the Railway public domain.

### relay-containerization.AC3.2 — a persistent Railway volume mounted at the data dir survives a redeploy
- **Approach:** Human / environment verification — **[requires Railway account]**
- **Source:** Phase 4, Task 2 Step 2 (attach volume at `/data`) + Task 3 Step 3.
- **Human steps:** confirm a persistent volume is attached at `/data`. Write/observe state (e.g. create an
  account), trigger a **redeploy** (no-op commit or dashboard redeploy), wait for healthy, then confirm the
  prior SQLite data is still present — e.g. the pre-redeploy account still resolves, or via a one-off
  `railway run ls -la /data` the DB file mtime predates the redeploy.
- **Assert:** data survived the redeploy because it lives on the volume, not the container filesystem.

### relay-containerization.AC3.3 — `public_url` and master key supplied via Railway variables; neither committed to git
- **Approach:** Automated/scriptable operational check (git side) + human confirmation (Railway side) — **[requires Railway account]** for the variable side; the grep is **[any machine]**
- **Source:** Phase 4, Task 2, Step 5.
- **Command (git side):**
  ```bash
  git grep -nI -E "EZPDS_SIGNING_KEY_MASTER_KEY|EZPDS_ADMIN_TOKEN" -- . ':!docs' && echo "FOUND (investigate)" || echo "OK — secrets only in Railway"
  ```
  **Assert:** prints `OK` — no real secret committed. (The throwaway dev key in `devenv.nix` is local-only and
  not a deploy secret; the grep excludes `docs/`.)
- **Human step (Railway side):** confirm `EZPDS_PUBLIC_URL` (the generated domain) and
  `EZPDS_SIGNING_KEY_MASTER_KEY` (sealed/secret) are set as Railway **service variables**, and that
  `EZPDS_PORT` is **not** set (Railway injects `PORT`, honored by the Phase 1 fallback).

---

## AC4 — NixOS via oci-containers (colmena still deploys) + flake cleanup

### relay-containerization.AC4.1 — `nix/module.nix` runs the relay as a `virtualisation.oci-containers` service; a colmena deploy to the lab host serves `/xrpc/_health`
- **Approach:** Human / environment verification (with a scriptable health probe) — **[requires NixOS lab host + Nix]**
- **Source:** Phase 5, Task 4, Steps 1-2.
- **Human steps:** point the host config at `nixosModules.default`, set `services.ezpds.image` to the GHCR
  digest ref, `publicUrl`, `availableUserDomains`, and `environmentFile`; enable a container backend
  (`virtualisation.oci-containers.backend = "podman"`, `virtualisation.podman.enable = true`); then
  `colmena apply --on <lab-host>`.
- **Scriptable probes:**
  ```bash
  curl -fsS https://<lab-relay-domain>/xrpc/_health && echo
  systemctl status podman-ezpds.service   # or docker-ezpds.service per backend
  ```
- **Assert:** HTTP 200 + JSON from the lab relay domain; the container systemd unit is active.

### relay-containerization.AC4.2 — secret injected via `environmentFiles` (agenix/sops-nix), not stored in the Nix store
- **Approach:** Automated/scriptable operational check, run **on the lab host** — **[requires NixOS lab host + Nix]**
- **Source:** Phase 5, Task 4, Step 3.
- **Command (on the host):**
  ```bash
  grep -rI "EZPDS_SIGNING_KEY_MASTER_KEY" /nix/store/ 2>/dev/null | head || echo "NOT_IN_STORE"
  ```
- **Assert:** prints `NOT_IN_STORE` — the master key's value lives only in the decrypted `environmentFile`
  (e.g. under `/run/secrets`), injected via the module's `environmentFiles`, never in the world-readable store.

### relay-containerization.AC4.3 — crane `relay` build and `docker-image`/`nix/docker.nix` removed/deprecated; `nix flake check` passes; `devShells` and `nixosModules.default` still evaluate
- **Approach:** Automated/scriptable operational check — **[requires NixOS lab host + Nix]** (Nix install; the lab host itself is not required for `nix flake check`)
- **Source:** Phase 5, Task 3, Step 4.
- **Command:**
  ```bash
  nix flake check --impure --accept-flake-config
  nix eval .#nixosModules.default --apply 'm: "ok"' --impure 2>/dev/null || nix flake show
  test ! -e nix/docker.nix && echo "docker.nix removed"
  ```
- **Assert:** `nix flake check` passes; `devShells.<system>.default` and `nixosModules.default` still resolve;
  `nix/docker.nix` is gone; no references remain to the removed `packages.relay`/`docker-image` outputs.
  (The repo-wide dangling-reference grep that backstops this lives under **AC5.2** / Phase 6 Task 4 Step 2.)
- **Note:** `just nix-check` runs the same `nix flake check --impure --accept-flake-config`.

---

## AC5 — Reproducibility & docs

### relay-containerization.AC5.1 — Dockerfile pins base images by digest, and the build uses the committed `Cargo.lock`
- **Approach:** Automated/scriptable operational check — **[any machine]** for the grep; **[requires Docker]** for resolving/confirming digests
- **Source:** Phase 2, Task 2 (`--locked` in the build command) + Task 3 (digest pinning).
- **Command:**
  ```bash
  # Both FROM lines are pinned by sha256 digest (not a bare mutable tag):
  grep -E '^FROM .*@sha256:[0-9a-f]{64}' Dockerfile
  test "$(grep -cE '^FROM ' Dockerfile)" -eq "$(grep -cE '^FROM .*@sha256:' Dockerfile)" && echo "ALL_FROM_DIGEST_PINNED"
  # The build uses the committed lockfile:
  grep -E 'cargo build .*--locked' Dockerfile && echo "USES_LOCKED"
  ```
- **Assert:** every `FROM` line carries an `@sha256:<64-hex>` digest (`ALL_FROM_DIGEST_PINNED`), and the build
  invokes `cargo build … --locked` (`USES_LOCKED`), which consumes the committed `Cargo.lock`.
- **Optional digest resolution check [requires Docker]** (from Phase 2 Task 3 Step 1):
  `docker buildx imagetools inspect rust:1-bookworm | grep -i digest | head -1` (and the debian image) to
  confirm the pinned digests match the intended tags.

### relay-containerization.AC5.2 — docs describe the Docker/Railway/oci-containers workflow; no doc presents removed Nix outputs as current; "Last verified" dates bumped
- **Approach:** Automated/scriptable operational check (grep) + human read-through — **[any machine]**
- **Source:** Phase 6, Tasks 1-3 (doc edits) + Task 4, Step 2 (dangling-reference grep).
- **Command (no dangling references to removed Nix outputs, excluding historical docs):**
  ```bash
  grep -rnI -E "\.#(relay|docker-image)|packages\.[^.]*\.(relay|docker-image)|nix/docker\.nix" \
    --exclude-dir=.git --exclude-dir=docs . ; echo "dangling-exit=$?"
  ```
  **Assert:** `dangling-exit=1` (no matches) — `justfile`, `tests/`, `nix/CLAUDE.md`, and root `CLAUDE.md` no
  longer reference the removed `.#relay`/`.#docker-image` outputs or the deleted `nix/docker.nix`. Historical
  mentions inside `docs/` are intentionally excluded.
- **Date-bump spot check (scriptable):**
  ```bash
  grep -RIl "Last verified: 2026-06-20" nix/CLAUDE.md CLAUDE.md crates/relay/CLAUDE.md
  test -f docs/deploy.md && echo "deploy.md exists"
  ```
  **Assert:** the three touched CLAUDE.md files carry the bumped `Last verified: 2026-06-20`; `docs/deploy.md`
  exists.
- **Human read-through:** confirm `docs/deploy.md` covers the runtime contract (`EZPDS_*` env, `/data` volume,
  `/xrpc/_health`), Railway setup, the colmena/oci-containers path (GHCR ref + agenix/sops `environmentFile` +
  backend enablement), the GHCR distribution choice, and the explicit reproducibility tradeoff; and that
  `nix/CLAUDE.md` + root `CLAUDE.md` describe the new workflow with no removed output shown as current. (Prose
  completeness is not fully assertable by grep — a human confirms it reads correctly.)

---

## AC6 — No behavior/scope regression

### relay-containerization.AC6.1 — relay routes/behavior are unchanged — `cargo test --workspace` (relay tests) pass
- **Approach:** Automated/scriptable operational check — **[any machine]**
- **Source:** Phase 1 ("Done When": `cargo test --workspace` passes), Task 2 (`cargo test -p common`).
- **Command:**
  ```bash
  cargo test --workspace
  ```
- **Assert:** the full workspace test suite passes, including pre-existing relay route/behavior tests and the
  new `crates/common` config tests from Phase 1 Task 2. No relay route or behavior regressed.
- **Note:** This runs the *existing* relay test suite plus the new config unit tests; the containerization plan
  adds no new relay-route tests because it changes no routes.

### relay-containerization.AC6.2 (negative) — SQLite single-instance model and schema unchanged; the devenv dev shell and the iOS app untouched
- **Approach:** Automated/scriptable operational check — **[any machine]**
- **Source:** Phase 6, Task 4, Step 1.
- **Command:**
  ```bash
  # No migration files added/changed by this plan:
  git diff --name-only main... -- crates/relay/src/db/migrations/ ; echo "migrations-changed-exit=$?"
  # devenv.nix + iOS app untouched by THIS plan's commits (spot check):
  git log --oneline main... -- devenv.nix apps/identity-wallet | head
  ```
- **Assert:** the migrations diff is **empty** (no schema change), and **no** relay-containerization commit
  touches `devenv.nix` or `apps/identity-wallet` (the iOS de-Nix work is a separate set of commits). The
  single-instance SQLite model is unchanged and is documented as such in `docs/deploy.md` (per Phase 6 Task 2).

---

## Coverage table

| AC sub-item | Approach | Environment | Where verified (phase/task) |
|---|---|---|---|
| **AC1.1** build, no Nix | Automated/scriptable op check | `[requires Docker]` | Phase 2, Task 4 Step 1 |
| **AC1.2** bundled SQLite build | Automated/scriptable op check | `[any machine]` | Phase 1, Task 3 |
| **AC1.3** rustls, no OpenSSL | Automated/scriptable op check | `[any machine]` (dep graph) + `[requires Docker]` (image) | Phase 1 Task 1 + Phase 2 Task 4 Step 2 |
| **AC1.4** env-only start + `$PORT` | **Automated unit test** (primary) + corroborating op check | `[any machine]` (unit) + `[requires Docker]` (run) | Phase 1, Task 2 (`crates/common` seam) + Phase 3 Task 1 |
| **AC1.5** secret not in image/git | Automated/scriptable op check | `[requires Docker]` + `[any machine]` (git) | Phase 3, Task 1 Step 3 |
| **AC2.1** volume + health 200 | Automated/scriptable op check | `[requires Docker]` | Phase 3, Task 1 Steps 1-2 |
| **AC2.2** persistence across restart | Automated/scriptable op check | `[requires Docker]` | Phase 3, Task 2 |
| **AC3.1** Railway build + health | Human/env verification (+ scriptable probe) | `[requires Railway account]` | Phase 4, Tasks 1-3 |
| **AC3.2** Railway volume survives redeploy | Human/env verification | `[requires Railway account]` | Phase 4, Task 2 Step 2 + Task 3 Step 3 |
| **AC3.3** secrets via Railway vars, not git | Automated/scriptable op check (git) + human (Railway) | `[any machine]` (git) + `[requires Railway account]` | Phase 4, Task 2 Step 5 |
| **AC4.1** oci-containers + colmena health | Human/env verification (+ scriptable probe) | `[requires NixOS lab host + Nix]` | Phase 5, Task 4 Steps 1-2 |
| **AC4.2** secret not in Nix store | Automated/scriptable op check (on host) | `[requires NixOS lab host + Nix]` | Phase 5, Task 4 Step 3 |
| **AC4.3** flake cleanup + `nix flake check` | Automated/scriptable op check | `[requires NixOS lab host + Nix]` (Nix install) | Phase 5, Task 3 Step 4 |
| **AC5.1** digest pinning + `--locked` | Automated/scriptable op check | `[any machine]` (grep) + `[requires Docker]` (digest resolve) | Phase 2, Task 2 + Task 3 |
| **AC5.2** docs updated, no stale Nix refs | Automated/scriptable op check (grep) + human read | `[any machine]` | Phase 6, Tasks 1-3 + Task 4 Step 2 |
| **AC6.1** workspace tests pass | Automated/scriptable op check | `[any machine]` | Phase 1 Done-When; Task 2 |
| **AC6.2** no schema/dev-shell/iOS change | Automated/scriptable op check | `[any machine]` | Phase 6, Task 4 Step 1 |

### Approach tally
- **Automated unit test:** 1 sub-item — **AC1.4** only (Phase 1 config behavior, `crates/common` via the
  `load_config_with_env(path, &env)` seam). AC1.4 also has a corroborating in-container op check.
- **Automated/scriptable operational check (primary approach):** AC1.1, AC1.2, AC1.3, AC1.5, AC2.1, AC2.2,
  AC3.3 (git side), AC4.2, AC4.3, AC5.1, AC5.2, AC6.1, AC6.2.
- **Human / environment verification (primary approach):** AC3.1, AC3.2, AC4.1 (each with a scriptable health
  probe where a public URL exists). AC3.3 and AC4.2/AC4.1 carry human-confirmed sub-steps in Railway/NixOS.

**Every AC sub-item (AC1.1 … AC6.2) is mapped to exactly one primary approach. None are left unmapped.**

### Environment reachability summary
- **On a bare dev machine / dev shell `[any machine]`:** AC1.2, AC1.3 (relay side), AC1.4 (unit test), AC5.1
  (grep), AC5.2 (grep + read), AC6.1, AC6.2 are fully verifiable.
- **Add a local Docker daemon `[requires Docker]`:** unlocks AC1.1, AC1.3 (image side), AC1.5, AC2.1, AC2.2,
  and the AC1.4 in-container corroboration.
- **`[requires Railway account]`:** AC3.1, AC3.2, AC3.3 (Railway side).
- **`[requires NixOS lab host + Nix]`:** AC4.1, AC4.2 (lab host); AC4.3 (Nix install, lab host not required).
- **Reminder:** none of these run automatically — **this repo has no CI**, so each command/verification is a
  manual step performed by a human or executor in the appropriate environment.
