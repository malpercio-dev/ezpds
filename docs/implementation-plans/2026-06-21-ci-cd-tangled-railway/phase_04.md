# Phase 4: Production database backup (Litestream)

**Goal:** Continuously replicate the production SQLite DB to object storage with restore-on-boot, giving a point-in-time restore point — without touching the query layer.

**Architecture:** Add the `litestream` binary to the runtime image. The entrypoint, after the existing root `chown /data`, conditionally runs the relay **under Litestream supervision** (`litestream replicate -exec`) when a replica URL is configured, restoring the DB first if absent. When unconfigured (staging/local), it falls back to today's behavior — so this change is backward-compatible and only production opts in.

**Scope:** Phase 4 of 6. Independent of Phases 1–3; sequence before Phase 5 (production promote relies on this restore point).

**Codebase verified:** 2026-06-21.
- `Dockerfile` runtime stage: `debian:bookworm-slim`, installs `ca-certificates tzdata gosu`, creates user `relay` (uid 10001), copies the binary + `docker-entrypoint.sh`, `ENTRYPOINT` is the entrypoint script.
- `docker-entrypoint.sh`: `chown relay:relay /data` then `exec gosu relay /usr/local/bin/relay`.
- ✓ The relay already runs SQLite in **WAL mode** (`PRAGMA journal_mode=WAL`) — Litestream requires WAL.

## External dependency findings (Litestream, verified 2026-06-21)
- ✓ `litestream replicate -exec "<cmd>"` runs the app as a child and replicates while it runs; `litestream restore` restores on boot. Requires WAL. Targets: S3, S3-compatible (MinIO, Tigris), Backblaze B2, GCS, Azure.
- **Confirm at execution:** exact CLI flag forms (`-config`, `-if-db-not-exists`, `-if-replica-exists`, arg order), the current release asset URL/version, and Litestream's checkpoint guidance for an app that also has the DB open (litestream.io guides: replicate/restore reference + Docker guide).

## Acceptance Criteria Coverage
### ci-cd-tangled-railway.AC5: Data safety
- **ci-cd-tangled-railway.AC5.1 Success:** After a promote, the production restore point is present and retrievable from the backup target.

**Verification is operational** (replicate to a test bucket, confirm objects, restore reproduces the DB) — no unit tests for the image/entrypoint.

## Tasks

<!-- START_TASK_1 -->
### Task 1: Add the litestream binary to the runtime image
**Files:** Modify `Dockerfile` (runtime stage).

**Implementation:** Add `curl` to the runtime `apt-get install` line and install a pinned `litestream`:
```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata gosu curl \
 && rm -rf /var/lib/apt/lists/*

ARG LITESTREAM_VERSION=0.3.13
RUN curl -fsSL "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-amd64.tar.gz" \
    | tar -xz -C /usr/local/bin litestream
```
(Pin/confirm the version and asset name at execution; Railway builds linux-amd64.)

**Verification:** `docker build -t relay:litestream .` succeeds; `docker run --rm relay:litestream litestream version` prints a version.

**Commit:** `build: add litestream to the relay runtime image`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add the Litestream config
**Files:** Create `litestream.yml`; `COPY` it into the image (Dockerfile runtime stage, e.g. to `/etc/litestream.yml`).

**Implementation:** One DB, one replica driven by env so credentials/target stay out of git:
```yaml
dbs:
  - path: /data/relay.db
    replicas:
      - url: ${LITESTREAM_REPLICA_URL}
```
Add `COPY litestream.yml /etc/litestream.yml` to the Dockerfile. Litestream reads `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY` (and endpoint for S3-compatible) from the environment — set only in the `production` Railway environment.

**Verification:** `litestream.yml` present in the image; `docker run` with the env unset still boots (Task 3 fallback).

**Commit:** `build: add litestream config (env-driven replica)`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Run the relay under Litestream supervision (conditional)
**Verifies:** ci-cd-tangled-railway.AC5.1

**Files:** Modify `docker-entrypoint.sh`.

**Implementation:** Keep the root `chown`, then branch on `LITESTREAM_REPLICA_URL`:
```sh
#!/bin/sh
set -e
# Railway volumes mount root:root on first use; fix ownership before dropping privs.
chown relay:relay /data
if [ -n "${LITESTREAM_REPLICA_URL:-}" ]; then
  # Restore the DB from the replica if it's missing, then run the relay under
  # Litestream so the WAL is streamed continuously to object storage.
  gosu relay litestream restore -if-db-not-exists -if-replica-exists -config /etc/litestream.yml /data/relay.db
  exec gosu relay litestream replicate -config /etc/litestream.yml -exec "/usr/local/bin/relay"
else
  # No replica configured (staging/local): today's behavior, unchanged.
  exec gosu relay /usr/local/bin/relay
fi
```
(Confirm the exact restore/replicate flag forms at execution.)

**Verification (operational):**
- With `LITESTREAM_REPLICA_URL` unset: `docker run` boots the relay exactly as before; `/xrpc/_health` → 200.
- With it set to a test target (e.g. local MinIO or a Railway test bucket) + credentials: the relay boots, objects appear at the replica, and `litestream restore` into a fresh dir reproduces `relay.db`. This is the AC5.1 restore point.

**Commit:** `feat: run relay under litestream when a replica is configured`
<!-- END_TASK_3 -->
