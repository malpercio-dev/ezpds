# Relay Containerization — Phase 4: Railway deployment

**Goal:** Deploy the relay to Railway from the committed `Dockerfile`, with a persistent volume and config/secrets supplied as Railway variables.

**Architecture:** Railway builds the repo `Dockerfile`, mounts a persistent volume at `EZPDS_DATA_DIR`, injects `$PORT` (honored via the Phase 1 fallback), and supplies the public URL, allowed domains, and the sealed master key as service variables.

**Tech Stack:** Railway (Dockerfile builder, volumes, variables), the relay container from Phases 1-2.

**Scope:** Phase 4 of 6.

**Codebase verified:** 2026-06-20.

> **Platform note:** **[requires a Railway account/project]** — this is environment-specific and cannot be verified in CI or on a bare dev machine. Railway's dashboard/CLI specifics may differ from the snapshot below; confirm against current Railway docs while executing.
>
> **Chicken-and-egg:** `EZPDS_PUBLIC_URL` must be the Railway-assigned domain, which you only know **after** generating it. Generate the domain first (or set a custom domain), then set `EZPDS_PUBLIC_URL`, then redeploy.

---

## Acceptance Criteria Coverage

### relay-containerization.AC3
- **relay-containerization.AC3.1 Success:** Railway builds the committed Dockerfile and deploys; the public domain serves `/xrpc/_health` 200.
- **relay-containerization.AC3.2 Success:** a persistent Railway volume mounted at the data dir survives a redeploy.
- **relay-containerization.AC3.3 Success:** `public_url` and the master key are supplied via Railway variables; neither is committed to git.

**Verifies (this phase):** AC3.1, AC3.2, AC3.3. Verified operationally on Railway.

---

<!-- START_TASK_1 -->
### Task 1: Tell Railway to build the Dockerfile

**Files:**
- Create: `railway.toml` (repo root)

**Step 1:** Add `railway.toml` to force the Dockerfile builder (Railway also auto-detects a root `Dockerfile`, but being explicit avoids Nixpacks surprises):
```toml
[build]
builder = "DOCKERFILE"
dockerfilePath = "Dockerfile"

[deploy]
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 3
# Railway sends platform health checks to this path; the relay returns 200 when the DB is up.
healthcheckPath = "/xrpc/_health"
healthcheckTimeout = 30
```

**Step 2: Commit**
```bash
git add railway.toml
git commit -m "build: configure Railway to build the relay Dockerfile"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create the service, volume, and variables [Railway]

**Files:** none (Railway dashboard/CLI).

**Step 1:** In a Railway project, create a service from this GitHub repo (or `railway up` from the repo). Railway builds the `Dockerfile`.

**Step 2: Attach a persistent volume** mounted at **`/data`** (matches the image's `EZPDS_DATA_DIR=/data`). This is what makes SQLite survive redeploys.

**Step 3: Set service variables** (Variables tab or `railway variables set`):
- `EZPDS_PUBLIC_URL` = the Railway domain (e.g. `https://<service>.up.railway.app`) — set after generating the domain (see Step 4).
- `EZPDS_AVAILABLE_USER_DOMAINS` = your handle domain(s), comma-separated.
- `EZPDS_SIGNING_KEY_MASTER_KEY` = a real 64-hex master key (sealed; **not** the dev key). Mark as secret.
- `EZPDS_ADMIN_TOKEN` = a strong admin token (if you'll use admin endpoints).
- `EZPDS_DATA_DIR` = `/data` (or rely on the image default).
- Do **not** set `EZPDS_PORT` — Railway injects `PORT`, which the Phase 1 fallback honors.

**Step 4: Generate the public domain** (Settings → Networking → Generate Domain), then set `EZPDS_PUBLIC_URL` to it and redeploy.

**Step 5: Verify none of these are in git:**
```bash
git grep -nI -E "EZPDS_SIGNING_KEY_MASTER_KEY|EZPDS_ADMIN_TOKEN" -- . ':!docs' && echo "FOUND (investigate)" || echo "OK — secrets only in Railway"
```
Expected: `OK` (secrets live only in Railway variables; the dev key in `devenv.nix` is local-only and not a deploy secret).
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Deploy and smoke-test (AC3.1, AC3.2) [Railway]

**Files:** none.

**Step 1: Deploy** (push to the connected branch, or `railway up`). Watch the build use the Dockerfile (not Nixpacks) and the deploy go healthy.

**Step 2: Health (AC3.1):**
```bash
curl -fsS https://<your-railway-domain>/xrpc/_health && echo
```
Expected: HTTP 200 + JSON.

**Step 3: Persistence across redeploy (AC3.2):** trigger a redeploy (e.g. push a no-op commit or redeploy in the dashboard); after it's healthy, confirm the data dir still holds the prior SQLite DB (e.g. an account created before the redeploy still resolves, or the DB file mtime predates the redeploy via a one-off `railway run ls -la /data`). Expected: data survived — the volume, not the container filesystem, holds it.

**Step 4: No commit** (deploy + verification only).
<!-- END_TASK_3 -->

---

## Phase 4 Done When

- Railway builds the committed Dockerfile and the public domain serves `/xrpc/_health` 200 (AC3.1) **[Railway]**.
- A persistent volume at `/data` survives a redeploy (AC3.2).
- `public_url` + secrets come only from Railway variables, not git (AC3.3).
- `railway.toml` committed.
