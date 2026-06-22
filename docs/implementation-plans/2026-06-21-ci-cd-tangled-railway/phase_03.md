# Phase 3: Staging continuous deployment

**Goal:** Auto-deploy `main` to `staging` after the test gate, with a reliable failure signal when a deploy is unhealthy.

**Architecture:** The spindle `staging.yaml` runs `just ci`, then (only if green) installs the Railway CLI, runs `railway up` to `staging`, and polls deployment status until healthy. The health poll is a committed helper script reused by Phase 5 (production).

**Scope:** Phase 3 of 6. Depends on Phase 1 (workflow skeletons) and Phase 2 (staging env + `RAILWAY_TOKEN_STAGING`).

**Codebase verified:** 2026-06-21. `staging.yaml` exists with a placeholder deploy step (Phase 1, Task 2).

## External dependency findings (Railway CLI, verified 2026-06-21)
- ✓ `railway up --ci` "streams only build logs and exits when the build completes" — it does **not** wait for deploy health. A separate status poll is required.
- ✓ Flags: `-s`/`--service`, `-e`/`--environment`. `RAILWAY_TOKEN=… railway up` runs non-interactively.
- ✓ use-railway execution rule: poll `railway deployment list --json` until newest status is `SUCCESS` (deployed) or `FAILED`/`CRASHED` (fail).
- **Confirm at execution:** the `railway deployment list --json` shape (`.[0].status` and the status enum values), the CLI install mechanism/PATH in a nixery step, and that an env-scoped token narrows `deployment list` to that environment.

## Acceptance Criteria Coverage
### ci-cd-tangled-railway.AC2: Staging CD on merge to main
- **ci-cd-tangled-railway.AC2.1 Success:** A push to `main` that passes `just ci` deploys the relay to the `staging` environment via the Railway CLI.
- **ci-cd-tangled-railway.AC2.3 Failure:** A staging deploy whose image build fails, or whose `/xrpc/_health` check does not pass within the timeout, fails the pipeline (non-zero, visible).
- **ci-cd-tangled-railway.AC2.4 Edge:** A push to `main` that fails `just ci` does not execute the staging deploy step.

**Verification is operational** (observe a real deploy gate), not unit tests.

## Tasks

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Add the deploy-health poll helper
**Verifies:** ci-cd-tangled-railway.AC2.3 (provides the failure signal)

**Files:** Create `scripts/ci/railway-wait-healthy.sh` (POSIX sh, executable).

**Implementation:** Poll the newest Railway deployment until it reaches `SUCCESS`; fail on `FAILED`/`CRASHED` or timeout. Reused by Phase 5. Requires `RAILWAY_TOKEN` set and `jq`.
```sh
#!/bin/sh
set -eu
# Wait for the newest Railway deployment (in the token-scoped environment) to
# reach SUCCESS. Exit non-zero on FAILED/CRASHED or timeout so CI fails loudly.
# Requires: railway CLI authenticated via RAILWAY_TOKEN, jq.
timeout_s="${HEALTH_TIMEOUT_S:-300}"
deadline=$(( $(date +%s) + timeout_s ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  status="$(railway deployment list --json | jq -r '.[0].status')"
  case "$status" in
    SUCCESS)        echo "deploy healthy"; exit 0 ;;
    FAILED|CRASHED) echo "deploy status: $status"; exit 1 ;;
    *)              echo "deploy status: $status; waiting..."; sleep 10 ;;
  esac
done
echo "timed out after ${timeout_s}s waiting for a healthy deploy"; exit 1
```

**Verification:** `sh -n scripts/ci/railway-wait-healthy.sh` parses clean; `chmod +x` set. (Behavior is exercised end-to-end by Task 2's deploy.)

**Commit:** `ci: add railway deploy-health poll helper`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Wire the staging deploy step
**Verifies:** ci-cd-tangled-railway.AC2.1, AC2.3, AC2.4

**Files:** Modify `.tangled/workflows/staging.yaml` (replace the Phase 1 placeholder deploy step; add `curl` and `jq` to deps).

**Implementation:** After `just ci`, install the Railway CLI, deploy to `staging` with the staging token, then run the health poll.
```yaml
when:
  - event: ["push", "manual"]
    branch: ["main"]

engine: nixery

dependencies:
  nixpkgs:
    - rustc
    - cargo
    - clippy
    - rustfmt
    - sqlite
    - just
    - cargo-audit
    - curl
    - jq

steps:
  - name: CI (fmt, clippy, test, audit)
    run: just ci
  - name: Install Railway CLI
    run: curl -fsSL https://railway.com/install.sh | sh
  - name: Deploy to staging
    run: RAILWAY_TOKEN="$RAILWAY_TOKEN_STAGING" railway up --service ezpds --environment staging --ci
  - name: Verify staging deploy healthy
    run: RAILWAY_TOKEN="$RAILWAY_TOKEN_STAGING" sh scripts/ci/railway-wait-healthy.sh
```
If `railway` is packaged in nixpkgs, prefer adding it to `dependencies.nixpkgs` and dropping the install step (confirm the attribute name at execution).

**Verification:**
- AC2.1: a push to `main` builds and deploys to `staging`; `https://ezpds-staging.up.railway.app/xrpc/_health` returns 200.
- AC2.3: a deploy that fails to build or never goes healthy makes the poll step exit non-zero → pipeline fails.
- AC2.4: a commit with a failing check aborts at `just ci`; the deploy steps never run.

**Commit:** `ci: deploy main to staging via Railway CLI`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->
