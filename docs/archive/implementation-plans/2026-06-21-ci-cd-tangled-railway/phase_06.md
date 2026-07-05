# Phase 6: Documentation reconciliation

**Goal:** Make the deploy docs match the tangled→Railway reality and document the rollback procedure.

**Scope:** Phase 6 of 6. Documents the system built in Phases 1–5.

**Codebase verified:** 2026-06-21.
- `docs/deploy.md` still says "Connect to the GitHub repo" (Railway setup) and describes GitHub Actions / GHCR as the CI/CD and distribution path (Image Distribution section). The repo is on tangled; there is no GitHub remote.
- `AGENTS.md` "Commands" lists local build/test/lint but does not describe the tangled CI workflows or deploy flow.

## Acceptance Criteria Coverage
### ci-cd-tangled-railway.AC5: Data safety
- **ci-cd-tangled-railway.AC5.2 Documentation:** The rollback procedure is documented — redeploying a previous `v*` tag is valid only when the schema change was backward-compatible (expand-contract); otherwise rollback means restoring from the Litestream backup.

**Verification is operational** (docs read true, links resolve) — no automated tests.

## Tasks

<!-- START_TASK_1 -->
### Task 1: Rewrite the Railway + Image Distribution sections of deploy.md
**Verifies:** ci-cd-tangled-railway.AC5.2

**Files:** Modify `docs/deploy.md`.

**Implementation:** Replace the GitHub-oriented content with the tangled→Railway reality:
- **Remove** the "Connect to the GitHub repo" step and the GitHub-Actions/GHCR-as-primary framing.
- **Add** a CI/CD overview: three tangled spindle workflows — `pr.yaml` (test gate on PRs), `staging.yaml` (push to `main` → `just ci` → deploy to the standing `staging` environment), `release.yaml` (`v*` tag → `just ci` → promote to `production`). Railway builds the Dockerfile from the context the spindle uploads via `railway up`; **no registry is required** for the Railway path.
- **Document the two environments**: `production` (`ezpds-production.up.railway.app`, warm) and `staging` (`ezpds-staging.up.railway.app`, serverless sleep), each with isolated secrets and its own `/data` volume.
- **Document backup + rollback** (AC5.2): Litestream replicates `/data/relay.db` continuously to object storage (production only, gated on `LITESTREAM_REPLICA_URL`). Rollback: redeploy the previous `v*` tag **only if the schema change was backward-compatible** (expand-contract); migrations are forward-only, so otherwise restore the DB with `litestream restore`.
- **Reframe** the GHCR / colmena-NixOS path as the **secondary** self-host option (Railway is primary). Update "Last verified" to 2026-06-21.

**Verification:** `docs/deploy.md` contains no "connect the GitHub repo" / GitHub-Actions-as-primary language; the three workflows, two environments, and rollback procedure are documented; internal links resolve.

**Commit:** `docs: reconcile deploy.md to tangled→Railway CI/CD`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Document the CI/CD flow in AGENTS.md
**Files:** Modify `AGENTS.md`.

**Implementation:** Add a short CI/CD subsection (near "Commands"): the three `.tangled/workflows/` files and their triggers, that all three run `just ci` first, and that production is promoted by pushing a `v*` tag (not by merging to `main`). Update the "Last verified" date.

**Verification:** `AGENTS.md` describes `just ci` + the pr/staging/release workflows + tag-promote; date updated.

**Commit:** `docs: document tangled CI/CD workflows in AGENTS.md`
<!-- END_TASK_2 -->
