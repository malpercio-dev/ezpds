# Human Test Plan: Relay Containerization
**Implementation plan:** `docs/implementation-plans/2026-06-20-relay-containerization/`
**HEAD SHA:** `2eae632d2b653e45617c9689d9f2dd2891659b6c`
**Generated:** 2026-06-21

---

## Automated Test Status

Run these before any manual steps:

```bash
env -u LIBSQLITE3_SYS_USE_PKG_CONFIG cargo test -p relay -p common -p repo-engine -p crypto
```

Expected: 509+ relay tests pass, 59+ common tests pass, 0 failures.

> **macOS + devenv note:** Running bare `cargo test` inside the devenv shell (where `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set) may fail with a linker error — Apple's system SQLite in the Xcode 26 SDK is found before the Nix-provided SQLite and strips `sqlite3_load_extension`/`sqlite3_unlock_notify`. The `env -u` prefix unsets the var, so `libsqlite3-sys` compiles bundled SQLite from source (same path the Dockerfile takes). This is a macOS + devenv interaction, not a code issue.
Do **not** use `cargo test --workspace` — `apps/identity-wallet` has pre-existing flaky tests (keychain/device-key/network) that are out of scope and untouched by this changeset.

| Criterion | Automated Tests | Status |
|-----------|----------------|--------|
| AC1.4 — env-only load | `config_loader.rs:144,186,206,126` + `config.rs:447,926,935,947` | Pass |
| AC6.1 — relay test suite | `cargo test -p relay -p common -p repo-engine -p crypto` | Pass |
| AC6.2 — no schema/iOS change | git range assertions | Pass |

---

## Prerequisites

- Repo checked out at HEAD `2eae632d2b653e45617c9689d9f2dd2891659b6c`; dev shell entered: `nix develop --impure --accept-flake-config`
- Throwaway 64-hex master key for runtime injection (dev-only, from `.env.local.example`):
  `2a55ebbdb7c0a4864a3944a443765b13602c6fbbeda38c2d6afc57b96663810e`
- Expected health response shape: HTTP **200** with JSON `{"version":"0.1.0","db":"ok"}`. On DB failure: **503** with `db:"error"`.

---

## Phase A — Any machine (dev shell, no Docker/cloud)

| Step | Criterion | Action | Expected |
|------|-----------|--------|----------|
| A1 | AC1.2 bundled SQLite | `env -u LIBSQLITE3_SYS_USE_PKG_CONFIG cargo build --release -p relay` | Build succeeds; logs show `libsqlite3-sys` compiling vendored SQLite C source |
| A2 | AC1.3 no OpenSSL (dep tree) | `cargo tree -p relay -i openssl-sys 2>&1 \| head` | Prints "did not match any packages" or empty |
| A3 | AC1.3 no native-tls | `cargo tree -p relay -e features \| grep -i native-tls` | No output |
| A4 | AC1.3 rustls present | `cargo tree -p relay \| grep rustls` | One or more `rustls` lines |
| A5 | AC1.4 unit tests | `cargo test -p common` | All 58+ pass, including `env_only_config_*`, `port_fallback_*`, `ezpds_port_takes_precedence_over_port`, `port_defaults_to_8080_when_both_absent`, `returns_error_for_missing_file` |
| A6 | AC1.5 secret not in git | `git grep -nI "EZPDS_SIGNING_KEY_MASTER_KEY" -- Dockerfile compose.yaml 2>/dev/null \|\| echo NOT_IN_BUILD_FILES` | `NOT_IN_BUILD_FILES` |
| A7 | AC3.3 git side | `git grep -nI -E "EZPDS_SIGNING_KEY_MASTER_KEY\|EZPDS_ADMIN_TOKEN" -- . ':!docs' && echo "FOUND" \|\| echo "OK"` | `OK` (the dev key in `.env.local.example` is a known throwaway; if it surfaces, confirm it is the dev value) |
| A8 | AC5.1 digest pinning | `grep -E '^FROM .*@sha256:[0-9a-f]{64}' Dockerfile` then `test "$(grep -cE '^FROM ' Dockerfile)" -eq "$(grep -cE '^FROM .*@sha256:' Dockerfile)" && echo ALL_PINNED` | Both `FROM` lines show `@sha256:<64-hex>`; prints `ALL_PINNED` |
| A9 | AC5.1 `--locked` | `grep -E 'cargo build .*--locked' Dockerfile && echo USES_LOCKED` | Prints the `cargo build --release --locked -p relay` line + `USES_LOCKED` |
| A10 | AC5.2 no stale refs | `grep -rnI -E "\.#(relay\|docker-image)\|packages\.[^.]*\.(relay\|docker-image)\|nix/docker\.nix" --exclude-dir=.git --exclude-dir=docs . ; echo "dangling-exit=$?"` | `dangling-exit=1` (no matches outside `docs/`) |
| A11 | AC5.2 dates | `grep -RIl "Last verified: 2026-06-21" nix/CLAUDE.md CLAUDE.md crates/relay/CLAUDE.md` and `test -f docs/deploy.md && echo "deploy.md exists"` | All three CLAUDE.md files listed; `deploy.md exists` |
| A12 | AC6.1 | `cargo test -p relay -p common -p repo-engine -p crypto` | All pass, 0 failures |
| A13 | AC6.2 | `git diff --name-only 4c6cbd4..HEAD -- crates/relay/src/db/migrations/` and `git log --oneline 4c6cbd4..HEAD -- devenv.nix apps/identity-wallet` | Both empty |

---

## Phase B — Requires Docker daemon (local)

Build tag: `ezpds-relay:dev`. (`just docker-build` produces `relay:latest`; retag or build with `:dev` explicitly for these steps.)

| Step | Criterion | Action | Expected |
|------|-----------|--------|----------|
| B1 | AC1.1 | `docker build -t ezpds-relay:dev .` | Build succeeds; logs show vendored SQLite compile and no Nix; `.dockerignore` excludes target/, node_modules/, docs/, .git |
| B2 | AC1.3 image — no libssl | `docker run --rm --entrypoint /bin/sh ezpds-relay:dev -c "ldd /usr/local/bin/relay \| grep -i ssl \|\| echo NO_OPENSSL"` | `NO_OPENSSL` |
| B3 | AC1.3 image — relay binary doesn't load libssl | `docker run --rm --entrypoint /bin/sh ezpds-relay:dev -c "ldd /usr/local/bin/relay \| grep -i ssl \|\| echo NO_SSL_LINK"` | `NO_SSL_LINK` — `libssl3` will be present in the image as a transitive dep of `ca-certificates` → `openssl` CLI, but the relay binary must not link it. B2 and B3 both assert this; B2 is sufficient. |
| B4 | AC1.5 secret not in image | `docker history --no-trunc ezpds-relay:dev \| grep -i EZPDS_SIGNING_KEY_MASTER_KEY \|\| echo NOT_IN_IMAGE` | `NOT_IN_IMAGE` |
| B5 | AC2.1 | `docker volume create ezpds-data && docker run -d --name ezpds-relay -p 8080:8080 -v ezpds-data:/data -e EZPDS_PUBLIC_URL=https://relay.local -e EZPDS_AVAILABLE_USER_DOMAINS=example.com -e EZPDS_SIGNING_KEY_MASTER_KEY=2a55ebbdb7c0a4864a3944a443765b13602c6fbbeda38c2d6afc57b96663810e -e EZPDS_ADMIN_TOKEN=local-admin-token -e PORT=8080 ezpds-relay:dev` | Container starts (exits 0) |
| B6 | AC2.1 | `sleep 2 && curl -fsS http://localhost:8080/xrpc/_health && echo` | HTTP 200, JSON `{"version":"0.1.0","db":"ok"}` |
| B7 | AC1.4 (in-container) | `docker logs ezpds-relay 2>&1 \| grep -iE "listening\|migrat\|config" \| head` | Logs show bound port + migrations; **no** error about missing `relay.toml` |
| B8 | AC2.2 | `docker exec ezpds-relay ls -la /data` | `relay.db` present on the volume |
| B9 | AC2.2 | `docker restart ezpds-relay && sleep 2 && curl -fsS http://localhost:8080/xrpc/_health && echo` | Health 200 after restart; same volume/DB reused |
| B10 | AC2.2 | `docker logs ezpds-relay 2>&1 \| tail -20 \| grep -iE "migrat" \|\| echo "no pending migrations (expected)"` | No new migrations applied (idempotent) |
| — | Cleanup | `docker rm -f ezpds-relay && docker volume rm ezpds-data` | — |

**Tip:** `compose.yaml` is an equivalent path for B5: copy `.env.local.example → .env.local`, then `docker compose up -d`. The compose file mounts the `ezpds-data` volume, sets `PORT=8080`, and reads env vars from `.env.local`.

### End-to-end persistence round-trip (AC1.4 + AC2.1 + AC2.2)

1. Build (B1), create volume, run container with env-only (B5).
2. Probe health → 200 `{"db":"ok"}` (B6). Confirm logs show no missing-config error (B7).
3. `docker exec … ls -la /data` — note the `relay.db` mtime (B8).
4. `docker restart ezpds-relay`; re-probe health → 200; confirm no new migrations in logs (B9–B10).
5. `docker exec … ls -la /data` again — same `relay.db`, mtime predates restart.

**Pass = data persisted, health green both times, no config-file error in logs.**

---

## Phase C — Requires Railway account

**Chicken-and-egg reminder:** `EZPDS_PUBLIC_URL` must be the Railway-assigned domain, known only after service creation. Order: create service → generate domain → set `EZPDS_PUBLIC_URL` → set `EZPDS_SIGNING_KEY_MASTER_KEY` (seal/secret) → ensure `EZPDS_PORT` is **unset** (Railway injects `PORT`, honored by the `PORT` fallback) → redeploy → probe.

| Criterion | Why manual | Steps |
|-----------|------------|-------|
| AC3.1 Railway build + health | Needs a Railway account/project | 1. Create Railway service from the repo. 2. Confirm build logs show **Dockerfile** builder (forced by `railway.toml`: `builder = "DOCKERFILE"`, `dockerfilePath = "Dockerfile"`). 3. Confirm deploy went healthy (Railway probes `healthcheckPath = "/xrpc/_health"`, 30s timeout per `railway.toml`). 4. Generate public domain. 5. `curl -fsS https://<railway-domain>/xrpc/_health && echo` → **200 + JSON**. |
| AC3.2 volume survives redeploy | Requires observing Railway state across a redeploy | 1. Confirm persistent volume attached at `/data`. 2. Write state (e.g. create an account). 3. Trigger redeploy (no-op commit or dashboard "Redeploy"); wait for healthy. 4. Confirm prior data survives — account still resolves, or `railway run ls -la /data` shows `relay.db` with mtime predating the redeploy. **Pass = data lives on the volume, not the container fs.** |
| AC3.3 secrets via Railway vars | Variable presence observable only in the Railway dashboard | Confirm `EZPDS_PUBLIC_URL` and `EZPDS_SIGNING_KEY_MASTER_KEY` are set as **service variables** (sealed), and `EZPDS_PORT` is **not** set. (Git side verified in A7.) |

---

## Phase D — Requires NixOS lab host + Nix

`nix flake check` (D3) needs only a Nix install; the lab host is required for D1/D2.

| Step | Criterion | Steps & Expected |
|------|-----------|------------------|
| D1 | AC4.1 oci-containers + colmena health | Point host config at `nixosModules.default`; set `services.ezpds.image` (GHCR digest ref), `publicUrl`, `availableUserDomains`, `environmentFile`; enable backend (`virtualisation.oci-containers.backend = "podman"`, `virtualisation.podman.enable = true`). Run `colmena apply --on <lab-host>`. Then `curl -fsS https://<lab-relay-domain>/xrpc/_health && echo` → **200 + JSON**, and `systemctl status podman-ezpds.service` → **active**. |
| D2 | AC4.2 secret not in Nix store | On the host after deploy: `grep -rI "EZPDS_SIGNING_KEY_MASTER_KEY" /nix/store/ 2>/dev/null \| head \|\| echo "NOT_IN_STORE"` → **`NOT_IN_STORE`**. The key lives only in the decrypted `environmentFile` (e.g. `/run/secrets`), injected via `environmentFiles` in `module.nix:61`, never in the world-readable store. |
| D3 | AC4.3 flake cleanup | `nix flake check --impure --accept-flake-config` → passes. `nix eval .#nixosModules.default --apply 'm: "ok"' --impure` → resolves. `test ! -e nix/docker.nix && echo "docker.nix removed"` → confirms deleted. No references to `packages.relay`/`docker-image` remain. (`just nix-check` runs the same flake check.) |

---

## Phase E — Human read-through: docs/deploy.md (AC5.2)

Open `docs/deploy.md` and confirm it covers:
- Runtime contract: `EZPDS_*` env vars (including `EZPDS_DATA_DIR`), `/data` volume, `/xrpc/_health` endpoint.
- `EZPDS_SIGNING_KEY_MASTER_KEY` described as **64-character hex string**, with `openssl rand -hex 32` generation example.
- Railway setup: Dockerfile builder, domain assignment, variables, `PORT` injection (not `EZPDS_PORT`).
- Colmena/oci-containers path: GHCR image digest ref, `environmentFile` for agenix/sops, backend enablement.
- GHCR distribution and the explicit reproducibility tradeoff.
- `nix/CLAUDE.md` and root `CLAUDE.md` describe the new OCI-container workflow with **no** deleted Nix outputs presented as current.

---

## Traceability

| Acceptance Criterion | Automated | Manual Step |
|----------------------|-----------|-------------|
| AC1.1 build, no Nix | — | B1 |
| AC1.2 bundled SQLite | — | A1 |
| AC1.3 rustls / no OpenSSL | — | A2–A4, B2–B3 |
| **AC1.4 env-only + PORT** | `config_loader.rs:144,186,206,126` + `config.rs:447,926,935,947` | A5, B6–B7 |
| AC1.5 secret not in build | — | A6, B4 |
| AC2.1 health 200 | — | B5–B6 |
| AC2.2 persistence | — | B8–B10, E2E round-trip |
| AC3.1 Railway build + health | — | C |
| AC3.2 Railway volume | — | C |
| AC3.3 secrets via vars | — | A7, C |
| AC4.1 oci-containers health | — | D1 |
| AC4.2 secret not in store | — | D2 |
| AC4.3 flake cleanup | — | D3 |
| AC5.1 digest pinning | — | A8–A9 |
| AC5.2 docs updated | — | A10–A11, E |
| **AC6.1 relay tests pass** | `cargo test -p relay -p common -p repo-engine -p crypto` | A12 |
| **AC6.2 no schema/iOS change** | git range assertions | A13 |
