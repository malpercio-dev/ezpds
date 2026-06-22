# Phase 5: Production promote on tag

**Goal:** Promote a tagged commit to `production`, gated by the test gate and backed by Litestream's continuous restore point.

**Architecture:** `release.yaml` (triggered by a `v*` tag, push-only) runs `just ci`, then deploys that exact commit to `production` with the production token, then polls health with the Phase 3 helper. The "backup before promote" requirement is satisfied by Phase 4: Litestream replicates continuously, so the pre-promote DB state is already in object storage before the new deployment takes over.

**Scope:** Phase 5 of 6. Depends on Phase 1 (release.yaml skeleton + tag trigger), Phase 3 (CLI install + `railway-wait-healthy.sh`), Phase 4 (Litestream restore point).

**Codebase verified:** 2026-06-21. `release.yaml` exists with a placeholder promote step and a `v*` tag trigger (Phase 1, Task 3). `scripts/ci/railway-wait-healthy.sh` exists (Phase 3, Task 1).

> **Execution note (2026-06-21):** like staging (Phase 3), `release.yaml` declares `railway`, `jq`, and `coreutils` as nixpkgs deps and reuses `scripts/ci/railway-wait-healthy.sh` — no CLI install step.

## Acceptance Criteria Coverage
### ci-cd-tangled-railway.AC3: Production promote on tag
- **ci-cd-tangled-railway.AC3.1 Success:** Pushing a `v*` tag that passes `just ci` deploys that exact tagged commit to `production`.
- **ci-cd-tangled-railway.AC3.2 Success:** A retrievable restore point of the production DB exists before the new release takes traffic (Litestream continuous replication, Phase 4).
- **ci-cd-tangled-railway.AC3.3 Failure:** A push that is not a `v*` tag does not trigger a production deploy (enforced by the `tag: ["v*"]` trigger, Phase 1).
- **ci-cd-tangled-railway.AC3.4 Failure:** An unhealthy production deploy fails the pipeline visibly.
### ci-cd-tangled-railway.AC4: Secret isolation
- **ci-cd-tangled-railway.AC4.4:** The production leg uses `RAILWAY_TOKEN_PRODUCTION` (production-scoped); it cannot deploy staging and vice versa.

**Verification is operational** (push a tag, observe the gated deploy), not unit tests.

## Tasks

<!-- START_TASK_1 -->
### Task 1: Wire the production promote step
**Verifies:** ci-cd-tangled-railway.AC3.1, AC3.2, AC3.4, AC4.4

**Files:** Modify `.tangled/workflows/release.yaml` (replace the Phase 1 placeholder; add `curl` and `jq` to deps).

**Implementation:** Mirror the staging deploy with the production token and environment, reusing the health helper.
```yaml
when:
  - event: ["push"]
    tag: ["v*"]

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
  - name: Promote to production
    run: RAILWAY_TOKEN="$RAILWAY_TOKEN_PRODUCTION" railway up --service ezpds --environment production --ci
  - name: Verify production deploy healthy
    run: RAILWAY_TOKEN="$RAILWAY_TOKEN_PRODUCTION" sh scripts/ci/railway-wait-healthy.sh
```

**Verification:**
- AC3.1: pushing `v0.1.0` (after `just ci` passes) deploys that commit to production; `https://ezpds-production.up.railway.app/xrpc/_health` → 200.
- AC3.2: Litestream has a current replica of the production DB before the new container takes over (objects present at the replica target). Rollback = `litestream restore` to a pre-promote timestamp.
- AC3.3: a push to a branch or a non-`v*` tag does not run this workflow.
- AC3.4: an unhealthy production deploy makes `railway-wait-healthy.sh` exit non-zero → pipeline fails.

**Commit:** `ci: promote v* tags to production via Railway CLI`
<!-- END_TASK_1 -->
