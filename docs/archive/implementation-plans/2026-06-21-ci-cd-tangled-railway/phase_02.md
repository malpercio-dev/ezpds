# Phase 2: Railway staging environment provisioning

**Goal:** Stand up an isolated `staging` environment that mirrors production's service config, and mint the environment-scoped tokens the pipeline will use.

**Scope:** Phase 2 of 6. **Human-executed** — these steps touch the Railway account and secrets (signing master key, admin token), so they are run by the operator in the Railway dashboard/CLI, not by an automated task.

**Codebase verified:** 2026-06-21. Production runs at `ezpds-production.up.railway.app`, deployed today by a manual `railway up`. `railway.toml` (Dockerfile builder, `/xrpc/_health`, restart policy) applies to all environments.

## Acceptance Criteria Coverage
### ci-cd-tangled-railway.AC2: Staging CD (partial — environment exists)
- **ci-cd-tangled-railway.AC2.2 Success:** The staging deploy serves on `ezpds-staging.up.railway.app` and uses staging-scoped credentials.
### ci-cd-tangled-railway.AC4: Secret isolation
- **ci-cd-tangled-railway.AC4.2:** `staging` and `production` use distinct `EZPDS_SIGNING_KEY_MASTER_KEY` and `EZPDS_ADMIN_TOKEN`.
- **ci-cd-tangled-railway.AC4.3:** `staging` and `production` use distinct `EZPDS_AVAILABLE_USER_DOMAINS`.

**Verification is operational** (environment boots, health 200, secrets confirmed distinct) — no automated tests.

## Tasks

<!-- START_TASK_1 -->
### Task 1: Fork `production` into a `staging` environment
**Files:** None (Railway dashboard).

**Steps:** Dashboard → project → **New Environment** → fork from `production`, name `staging`. Forking duplicates the `ezpds` service and its config (Dockerfile builder, healthcheck, restart policy).

**Verification:** `staging` appears as an environment containing the `ezpds` service.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Override staging variables and secrets
**Verifies:** ci-cd-tangled-railway.AC4.2, AC4.3

**Steps:** In `staging`, replace the values copied from production:
- `EZPDS_SIGNING_KEY_MASTER_KEY` — a **fresh** key: `openssl rand -hex 32` (never reuse production's — a shared key lets staging forge signatures valid for production DIDs).
- `EZPDS_ADMIN_TOKEN` — a new random token: `openssl rand -hex 32`.
- `EZPDS_AVAILABLE_USER_DOMAINS` — staging-only domain(s), distinct from production's namespace.
- `EZPDS_PUBLIC_URL` — set in Task 4 once the domain exists.
- Leave `PORT` and `EZPDS_DATA_DIR` unset (Railway injects `PORT`; the Dockerfile sets `EZPDS_DATA_DIR=/data`).

**Verification:** Staging's `EZPDS_SIGNING_KEY_MASTER_KEY`, `EZPDS_ADMIN_TOKEN`, and `EZPDS_AVAILABLE_USER_DOMAINS` differ from production's.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Attach a volume and enable serverless
**Steps:**
- Attach a volume to the staging `ezpds` service mounted at `/data` (a service has at most one volume). Forking does not clone production's data — staging gets its own empty volume; migrations run fresh on first boot.
- Enable **Serverless / App Sleeping** on the staging service (Settings) — idle >10 min sleeps to zero compute; first request after sleep may return a one-off `502` during cold boot (acceptable for staging).

**Verification:** The staging service shows a `/data` volume and Serverless enabled.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Generate the staging domain and verify first deploy
**Verifies:** ci-cd-tangled-railway.AC2.2

**Steps:**
- staging → `ezpds` service → Settings → Networking → **Generate Domain**; confirm `ezpds-staging.up.railway.app`. Set `EZPDS_PUBLIC_URL=https://ezpds-staging.up.railway.app` (Task 2).
- Manual first deploy from the repo root:
```bash
RAILWAY_TOKEN=<staging-token> railway up --service ezpds --environment staging
curl -fsS https://ezpds-staging.up.railway.app/xrpc/_health   # expect HTTP 200
```

**Verification:** `/xrpc/_health` returns 200 on the staging domain.
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Mint environment-scoped tokens → tangled secrets
**Verifies:** ci-cd-tangled-railway.AC4.4 (enables it)

**Steps:**
- Dashboard → project → Settings → **Tokens** → create a project token scoped to `staging`, and another scoped to `production` (select the environment when creating each).
- In **tangled** → repo → Settings → pipeline **Secrets**, add:
  - `RAILWAY_TOKEN_STAGING` = the staging-scoped token
  - `RAILWAY_TOKEN_PRODUCTION` = the production-scoped token

**Verification:** Both secrets exist in tangled repo settings. **Confirm at execution:** that tangled injects repo secrets into pipeline steps as environment variables (the mechanism the Phase 3/5 deploy steps rely on), and that a project token is environment-scoped at creation.
<!-- END_TASK_5 -->
