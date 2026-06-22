# Test Requirements — CI/CD: Tangled → Railway

**Generated:** 2026-06-21
**Design:** `docs/design-plans/2026-06-21-ci-cd-tangled-railway.md`

## Nature of verification

This change is infrastructure / CI-CD + ops: spindle workflow files, a Railway environment, the runtime image entrypoint, a CI shell helper, and docs. Per the project and skill convention, **infrastructure is verified operationally** — the pipeline runs and gates, the service boots and reports healthy, the restore drill reproduces the DB — not through new unit tests.

The relay's existing automated suite (`cargo test --workspace`, run by `just ci`) is **unchanged** and continues to gate every workflow. No application behavior is added that warrants new unit tests; the only new code is CI glue (`scripts/ci/railway-wait-healthy.sh`) and the container entrypoint branch, both verified operationally. Writing unit tests for workflow YAML or the deploy shell wiring would test implementation, not behavior.

> Note: generated directly (not via the usual opus subagent) because the subagent classifier was overloaded (HTTP 529) during this session.

## AC → verification map

| AC | What is verified | Type | Where / how |
|---|---|---|---|
| **AC1.1** | `just ci` runs fmt-check, clippy (`-D warnings`), test, audit; exits 0 only if all pass | Automated (existing suite) | `pr.yaml` run; locally `just ci` |
| **AC1.2** | A failing check aborts `just ci`; the same-file deploy step does not run | Operational | seed a fmt violation on a branch; observe abort |
| **AC1.3** | PR pipeline runs only `just ci`; no deploy step, no token | Static + operational | inspect `.tangled/workflows/pr.yaml`; PR run |
| **AC2.1** | Push to `main` builds + deploys to `staging` | Operational | `staging.yaml` run; `curl …staging…/xrpc/_health` → 200 |
| **AC2.2** | Staging serves on `ezpds-staging.up.railway.app` with staging-scoped creds | Operational | Railway dashboard + curl |
| **AC2.3** | Failed build / unhealthy deploy → `railway-wait-healthy.sh` exits non-zero → pipeline fails | Operational | induce an unhealthy deploy; observe pipeline failure |
| **AC2.4** | Failing `just ci` on `main` skips the deploy step | Operational | seed a failure on `main` |
| **AC3.1** | `v*` tag deploys that exact commit to `production` | Operational | `release.yaml` run; curl prod health |
| **AC3.2** | A restore point exists before the new release takes traffic | Operational (restore drill) | replica objects present; `litestream restore` reproduces |
| **AC3.3** | A non-`v*` push does not trigger a production deploy | Operational | branch push; confirm no `release.yaml` run |
| **AC3.4** | Unhealthy production deploy fails the pipeline | Operational | induce; observe |
| **AC4.1** | PR pipelines reference no Railway token | Static | inspect `pr.yaml` |
| **AC4.2** | Distinct `EZPDS_SIGNING_KEY_MASTER_KEY` + `EZPDS_ADMIN_TOKEN` (staging vs prod) | Operational | dashboard inspection |
| **AC4.3** | Distinct `EZPDS_AVAILABLE_USER_DOMAINS` (staging vs prod) | Operational | dashboard inspection |
| **AC4.4** | Env-scoped tokens; staging token cannot deploy production | Operational | attempt a cross-env deploy → denied |
| **AC5.1** | Production restore point retrievable from the backup target | Operational (restore drill) | `litestream restore` reproduces `relay.db` |
| **AC5.2** | Rollback procedure documented (expand-contract, else restore) | Documentation review | `docs/deploy.md` |

## Human verification drills

Because there is no GitHub-style hosted CI sandbox and these ACs require a real Railway account + secrets, verification is performed by the operator:

1. **Gate drill** — seed a failing check on a branch/PR; confirm the pipeline aborts before any deploy step. *(AC1.2, AC2.4)*
2. **Staging deploy + health-fail drill** — confirm a green `main` deploys to staging (AC2.1); then induce an unhealthy deploy and confirm the pipeline fails (AC2.3).
3. **Promote drill** — push a `v0.x.y` tag; confirm production deploys (AC3.1) and that a normal branch push does not (AC3.3); induce an unhealthy prod deploy and confirm failure (AC3.4).
4. **Restore drill** — confirm the production replica holds objects and `litestream restore` reproduces `relay.db` into a fresh directory. *(AC3.2, AC5.1)*
5. **Isolation check** — confirm staging/prod secrets and user-domain lists differ (AC4.2, AC4.3) and the staging token cannot deploy production (AC4.4).
6. **Docs review** — confirm `docs/deploy.md` documents the rollback procedure and carries no GitHub-connect assumption. *(AC5.2)*

## Automated coverage

- `just ci` (fmt-check, clippy `-D warnings`, `cargo test --workspace`, `cargo audit`) — the existing suite, unchanged, gating all three workflows. This is the only automated layer; it covers AC1.1 and is the precondition every deploy AC depends on.
