# Relay Containerization — Phase 3: Local container verification

**Goal:** Prove the container is a correct, stateful relay locally — healthy, env-configured, and persisting SQLite to a mounted volume across restarts — before any cloud deploy.

**Architecture:** Run the Phase 2 image with a volume at `EZPDS_DATA_DIR` and the full required runtime env, then verify health and persistence.

**Tech Stack:** Docker, the relay's `EZPDS_*` config.

**Scope:** Phase 3 of 6.

**Codebase verified:** 2026-06-20.

> **Required runtime env (from `crates/common/src/config.rs` validation):** `EZPDS_PUBLIC_URL` (**must** start `https://`), `EZPDS_AVAILABLE_USER_DOMAINS` (non-empty, comma-separated), `EZPDS_SIGNING_KEY_MASTER_KEY` (64-hex → 32 bytes), and a writable `EZPDS_DATA_DIR` (image default `/data`). `EZPDS_ADMIN_TOKEN` is optional (needed for admin endpoints). Port: `EZPDS_PORT`/`PORT` (default 8080).
>
> **Platform note:** all steps are **[requires Docker]**. Health route is `GET /xrpc/_health` (returns 200 + JSON when the DB responds, 503 otherwise).

---

## Acceptance Criteria Coverage

### relay-containerization.AC1
- **relay-containerization.AC1.4 Success:** the relay starts from environment variables alone (no `--config` file) and binds the port given by `$PORT`.
- **relay-containerization.AC1.5 Edge:** `EZPDS_SIGNING_KEY_MASTER_KEY` is supplied at runtime and is absent from both the image layers and git.

### relay-containerization.AC2
- **relay-containerization.AC2.1 Success:** `docker run` with a volume at `EZPDS_DATA_DIR` → `/xrpc/_health` returns 200.
- **relay-containerization.AC2.2 Success:** data persists across a container restart (same volume reuses the SQLite DB; migrations idempotent, no data loss).

**Verifies (this phase):** AC1.4 (in-container), AC1.5, AC2.1, AC2.2. Infrastructure — verified operationally.

---

<!-- START_TASK_1 -->
### Task 1: Run the container env-only with a volume; verify health (AC1.4, AC2.1) [requires Docker]

**Files:** none (verification; optionally add a `compose.yaml` — see Task 3).

**Step 1: Run with a named volume and env (no config file mounted):**
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
```
(The master key above is the throwaway dev key from `devenv.nix` — fine for local only.)

**Step 2: Verify health (AC2.1) and env-only start (AC1.4):**
```bash
sleep 2
curl -fsS http://localhost:8080/xrpc/_health && echo
docker logs ezpds-relay 2>&1 | grep -iE "listening|migrat|config" | head
```
Expected: `/xrpc/_health` returns HTTP 200 with JSON (`{"version":...,"db":"ok"}`); logs show it bound the port and ran migrations, with **no error about a missing `relay.toml`** (proving env-only operation).

**Step 3: Verify the secret isn't baked into the image (AC1.5):**
```bash
docker history --no-trunc ezpds-relay:dev | grep -i EZPDS_SIGNING_KEY_MASTER_KEY || echo NOT_IN_IMAGE
git grep -nI "EZPDS_SIGNING_KEY_MASTER_KEY" -- Dockerfile docker-compose.yaml compose.yaml 2>/dev/null || echo NOT_IN_BUILD_FILES
```
Expected: `NOT_IN_IMAGE` and `NOT_IN_BUILD_FILES` — the key only ever arrives via runtime `-e`.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Verify persistence + idempotent migrations across restart (AC2.2) [requires Docker]

**Files:** none.

**Step 1: Confirm the DB file exists on the volume after first run:**
```bash
docker exec ezpds-relay ls -la /data
```
Expected: a SQLite DB file (e.g. `relay.db`) present.

**Step 2: Restart and confirm reuse (no re-migration, no data loss):**
```bash
docker restart ezpds-relay
sleep 2
curl -fsS http://localhost:8080/xrpc/_health && echo
docker logs ezpds-relay 2>&1 | tail -n 20 | grep -iE "migrat" || echo "no pending migrations on restart (expected)"
```
Expected: health is 200 again; the second start applies **no** new migrations (the `schema_migrations` table already records them — idempotent), and the same DB file is reused.

**Step 3: Cleanup:**
```bash
docker rm -f ezpds-relay
# keep or remove the volume:  docker volume rm ezpds-data
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: (Optional) commit a `compose.yaml` for repeatable local runs

**Files:**
- Create (optional): `compose.yaml` at repo root

**Step 1:** If useful, add a `compose.yaml` that encodes the Task 1 run (build context `.`, volume `ezpds-data:/data`, env via `env_file: .env.local` which is gitignored). Do **not** commit real secrets; reference an env file. Add `.env.local` to `.gitignore`.

**Step 2: Commit (only the compose + gitignore, never secrets):**
```bash
git add compose.yaml .gitignore
git commit -m "build: add compose.yaml for local relay container runs"
```
<!-- END_TASK_3 -->

---

## Phase 3 Done When

- The container starts from env alone and `/xrpc/_health` returns 200 (AC1.4, AC2.1) **[requires Docker]**.
- The master key is absent from image layers and build files (AC1.5).
- Data persists across `docker restart`; restart triggers no re-migration (AC2.2).
