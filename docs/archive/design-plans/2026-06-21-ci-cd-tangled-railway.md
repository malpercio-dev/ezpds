# CI/CD: Tangled Spindle → Railway Design

**Last verified:** 2026-06-21

## Summary

The relay containerization refactor produced a deployable artifact (Dockerfile, entrypoint, `railway.toml`, healthcheck) but no delivery pipeline — the relay is deployed by running `railway up` by hand, and CI ([.tangled/workflows/ci.yaml](../../.tangled/workflows/ci.yaml)) only lints and tests. This design turns the tangled spindle pipeline into the delivery mechanism.

The approach treats the spindle pipeline as the *imperative shell* for deploys: it authenticates to Railway with a scoped token and drives the existing `railway up` flow, letting Railway build the Dockerfile (no registry, no image-building in CI — which tangled spindles cannot do). Pull requests run only the test gate. A merge to `main` deploys to a standing `staging` environment. A `v*` git tag backs up the production database and promotes that exact commit to `production`. Railway's existing healthcheck makes a deploy's health the pass/fail signal, and deploy credentials exist only in pipelines triggered by repository writes — never in PR pipelines — so leaving GitHub for tangled costs us nothing on security.

## Definition of Done

- A merge to `main` runs the test gate and, if green, deploys the relay to a standing `staging` Railway environment.
- Pushing a `v*` git tag runs the test gate and, if green, captures a production database restore point and deploys that exact commit to `production`.
- Pull requests run the full test gate (`just ci`) with no deploy step and no Railway credentials in scope.
- Railway deploy credentials exist only in pipelines triggered by repository writes (pushes to `main`, `v*` tag pushes), never in PR-triggered pipelines.
- `staging` and `production` each have isolated secrets (distinct signing master key, admin token, user-domain list) and their own persistent `/data` volume.
- A failed image build or an unhealthy deploy fails the corresponding pipeline visibly; `production` is never deployed except via an explicit `v*` tag.
- Deployment docs reflect the tangled→Railway reality (no GitHub-connect / GitHub Actions assumption).

## Acceptance Criteria

### ci-cd-tangled-railway.AC1: Test gate runs and gates correctly
- **ci-cd-tangled-railway.AC1.1 Success:** `just ci` runs `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, and `cargo audit`; the recipe exits 0 only when all pass.
- **ci-cd-tangled-railway.AC1.2 Failure:** When any check fails, `just ci` exits non-zero and the deploy step in the same workflow file does not run (step ordering gates the deploy).
- **ci-cd-tangled-railway.AC1.3 Success:** A `pull_request`-triggered pipeline runs `just ci` and only `just ci` — no deploy step, no Railway token referenced.

### ci-cd-tangled-railway.AC2: Staging CD on merge to main
- **ci-cd-tangled-railway.AC2.1 Success:** A push to `main` that passes `just ci` deploys the relay to the `staging` environment via the Railway CLI.
- **ci-cd-tangled-railway.AC2.2 Success:** The staging deploy serves on `ezpds-staging.up.railway.app` and uses staging-scoped credentials.
- **ci-cd-tangled-railway.AC2.3 Failure:** A staging deploy whose image build fails, or whose `/xrpc/_health` check does not pass within the timeout, fails the pipeline (non-zero, visible).
- **ci-cd-tangled-railway.AC2.4 Edge:** A push to `main` that fails `just ci` does not execute the staging deploy step.

### ci-cd-tangled-railway.AC3: Production promote on tag
- **ci-cd-tangled-railway.AC3.1 Success:** Pushing a `v*` tag that passes `just ci` deploys that exact tagged commit to `production`.
- **ci-cd-tangled-railway.AC3.2 Success:** A retrievable restore point of the production SQLite database is captured before the new release takes traffic.
- **ci-cd-tangled-railway.AC3.3 Failure:** A push that is not a `v*` tag (feature branch, non-version tag) does not trigger a production deploy.
- **ci-cd-tangled-railway.AC3.4 Failure:** An unhealthy production deploy fails the pipeline visibly.

### ci-cd-tangled-railway.AC4: Secret isolation & least privilege
- **ci-cd-tangled-railway.AC4.1:** PR-triggered pipelines have no Railway token available or referenced.
- **ci-cd-tangled-railway.AC4.2:** `staging` and `production` use distinct `EZPDS_SIGNING_KEY_MASTER_KEY` and `EZPDS_ADMIN_TOKEN` values.
- **ci-cd-tangled-railway.AC4.3:** `staging` and `production` use distinct `EZPDS_AVAILABLE_USER_DOMAINS` — staging cannot mint handles in the production namespace.
- **ci-cd-tangled-railway.AC4.4:** Each deploy leg uses an environment-scoped Railway token; the staging token cannot deploy production and vice versa.

### ci-cd-tangled-railway.AC5: Data safety
- **ci-cd-tangled-railway.AC5.1 Success:** After a promote, the production restore point is present and retrievable from the backup target.
- **ci-cd-tangled-railway.AC5.2 Documentation:** The rollback procedure is documented: redeploying a previous `v*` tag is valid only when the schema change was backward-compatible (expand-contract); otherwise rollback means restoring from the backup.

## Glossary

- **tangled / knot:** AT Protocol-based decentralized git forge. This repo lives on a self-hosted knot (`knot.malpercio.dev`); there is no GitHub remote.
- **spindle / pipeline:** tangled's CI runner (spindle) and its workflow definition (pipeline). Workflows live in `.tangled/workflows/*.yaml`, triggered by a `when` block (events `push`/`pull_request`/`manual`, with branch and tag globs).
- **nixery engine:** The spindle execution engine; each step runs in a fresh, unprivileged container whose image is built on the fly from declared `nixpkgs` dependencies. Cannot build or run nested container images.
- **Railway environment:** An isolated copy of a project's services with its own variables, secrets, and volumes. This design uses two standing environments: `production` and `staging`.
- **Railway volume:** Persistent storage mounted into a service (here at `/data`, holding `relay.db`). Per-environment; ephemeral environments get empty volumes.
- **project token vs API token:** A Railway project token (`RAILWAY_TOKEN`) authenticates non-interactive CLI deploys and is scoped to a project/environment; an account/workspace token (`RAILWAY_API_TOKEN`) is broader. This design uses environment-scoped project tokens.
- **healthcheck:** Railway polls `healthcheckPath` (`/xrpc/_health`) after a deploy; the relay returns 200 once the DB is up. A deploy is "healthy" only when this passes.
- **forward-only migration:** The relay's custom migration runner applies migrations forward with no down-path (tracked in `schema_migrations`). Implies code rollback does not roll back schema.
- **expand-contract:** A migration discipline (additive changes first, remove later) that keeps a newer schema readable by the previous binary, making tag-based code rollback safe.
- **Litestream:** A sidecar that continuously streams a SQLite WAL to S3-compatible object storage and restores it on boot, giving point-in-time recovery. Requires WAL mode (the relay already uses WAL).
- **serverless sleep:** Railway feature that sleeps a service after a period of inactivity (zero compute while asleep, cold start on next request).
- **gosu:** A privilege-drop helper used by the relay entrypoint to `chown /data` as root, then exec the relay as a non-root user.
- **RPO (recovery point objective):** The maximum acceptable data loss window; continuous replication (Litestream) yields a far smaller RPO than per-deploy snapshots.

## Architecture

The spindle pipeline drives Railway through the Railway CLI; Railway builds the Dockerfile from the uploaded context (no registry, no in-CI image build — spindle steps are unprivileged and cannot build images). One workflow file per trigger context, because spindle has no cross-workflow "needs" dependency; the only reliable gate is step ordering within a single file (a failed step aborts the run).

```
.tangled/workflows/
  pr.yaml        when: pull_request → main     steps: [just ci]
  staging.yaml   when: push        → main      steps: [just ci, deploy → staging]
  release.yaml   when: push tag    v*          steps: [just ci, backup, deploy → production]
```

**Environments (Railway, one project, two standing environments):**

| Environment | Lifetime | `/data` volume | Domain | Sleep |
|---|---|---|---|---|
| `production` | standing, warm | persistent | `ezpds-production.up.railway.app` | no |
| `staging` | standing | persistent | `ezpds-staging.up.railway.app` | serverless sleep |

**Deploy contract (pipeline ↔ Railway).** Each deploy leg is the existing `railway up` flow, authenticated by an environment-scoped token instead of an interactive login:

```
staging      RAILWAY_TOKEN=$STAGING_TOKEN     railway up --service ezpds --environment staging --ci
production   RAILWAY_TOKEN=$PRODUCTION_TOKEN  railway up --service ezpds --environment production --ci
```

**Smoke = deploy health.** [railway.toml](../../../railway.toml) already sets `healthcheckPath = "/xrpc/_health"` (30s timeout), so a deploy goes healthy only when the image builds, the binary boots, migrations run, and the DB comes up. The packaging-bug class (entrypoint, `gosu`, `useradd`, `/data` chown, `VOLUME` rejection) surfaces on the `staging` deploy — the staging deploy is the de facto packaging gate, and because `production` is gated behind a manual `v*` tag, a packaging regression cannot silently reach production.

**Secret split.** CI holds only deploy credentials; the app's runtime secrets never touch tangled.

| Location | Holds |
|---|---|
| tangled repo secrets | `RAILWAY_TOKEN_STAGING`, `RAILWAY_TOKEN_PRODUCTION` (each environment-scoped) |
| Railway dashboard, per-env | `EZPDS_PUBLIC_URL`, `EZPDS_AVAILABLE_USER_DOMAINS`, `EZPDS_SIGNING_KEY_MASTER_KEY`, `EZPDS_ADMIN_TOKEN` |
| `railway.toml` (git) | builder, healthcheck, restart policy — env-agnostic, no secrets |

**Data-safety chain for production:** `staging` runs each migration first (canary — a broken migration fails there) → a manual `v*` tag gates production → a restore point is captured before the new release takes traffic. Rollback of code via an older tag is safe only under expand-contract migrations; otherwise rollback is a restore from backup.

## Existing Patterns

- **Test steps already exist** in [.tangled/workflows/ci.yaml](../../.tangled/workflows/ci.yaml) (fmt → clippy → test → audit on push/PR/manual to `main`). This design folds them into a single `just ci` recipe so the gate is defined once and reused by all three workflow files. The `just` task runner is the established command surface ([justfile](../../../justfile) currently holds `docker-build`).
- **Railway config-as-code is already in place** — [railway.toml](../../../railway.toml) sets the Dockerfile builder, `/xrpc/_health` healthcheck, and restart policy. This design adds per-environment behavior (and a pre-deploy backup hook for production) without changing that contract.
- **Container contract is documented** in [docs/deploy.md](../../deploy.md): required `EZPDS_*` env vars, the `/data` volume, the non-root `gosu` entrypoint that chowns `/data`. The deploy doc's GitHub-connect / GitHub Actions / GHCR sections are stale (the repo is on tangled) and are reconciled in Phase 6.
- **Functional Core / Imperative Shell.** The relay is the project's sole imperative shell. Making the spindle pipeline the *deploy-time* imperative shell — pure config in git, side-effecting `railway up` confined to push/tag-triggered steps — mirrors that separation.
- **No deploy automation exists today.** Production runs at `ezpds-production.up.railway.app`, deployed by a manual local `railway up`. This design automates that exact flow; it does not introduce a new deploy mechanism.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Test-gate consolidation & workflow split
**Goal:** Define the test gate once and restructure tangled workflows by trigger context, with no deploy behavior yet.

**Components:**
- `just ci` recipe in [justfile](../../../justfile) — runs `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo audit`.
- `.tangled/workflows/pr.yaml` — `when: pull_request → main`, steps: `just ci`.
- `.tangled/workflows/staging.yaml` and `.tangled/workflows/release.yaml` — created with the `just ci` step and a placeholder/no-op deploy step (real deploy added in later phases); triggers `push → main` and `push tag v*` respectively.
- Remove or repurpose [.tangled/workflows/ci.yaml](../../.tangled/workflows/ci.yaml) (its steps now live in `just ci`; optionally keep a `manual` entry).

**Dependencies:** None.

**Done when:** `just ci` passes locally; the PR pipeline runs `just ci` and nothing else; pushes to `main` and `v*` tags trigger their workflows and run `just ci`. Covers ci-cd-tangled-railway.AC1.1, AC1.2 (via a deliberately failing check aborting the run), AC1.3, AC4.1.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Railway staging environment provisioning
**Goal:** Stand up an isolated `staging` environment that mirrors production's service config.

**Components (Railway-side, one-time):**
- New `staging` environment in the existing Railway project (clone service config from `production`).
- Distinct `EZPDS_*` values: `EZPDS_PUBLIC_URL=https://ezpds-staging.up.railway.app`, a freshly generated `EZPDS_SIGNING_KEY_MASTER_KEY` (`openssl rand -hex 32`), a distinct `EZPDS_ADMIN_TOKEN`, and a staging-only `EZPDS_AVAILABLE_USER_DOMAINS`.
- A `/data` volume mounted to the staging service; serverless sleep enabled.
- An environment-scoped project token stored as `RAILWAY_TOKEN_STAGING` in tangled repo secrets.

**Dependencies:** None (parallelizable with Phase 1).

**Done when:** A manual `railway up` to `staging` builds and reaches healthy; `https://ezpds-staging.up.railway.app/xrpc/_health` returns 200; staging secrets are distinct from production. Operational verification; sets up ci-cd-tangled-railway.AC2.2, AC4.2, AC4.3.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Staging continuous deployment
**Goal:** Auto-deploy `main` to `staging` after the test gate, with a reliable failure signal.

**Components:**
- Deploy step in `.tangled/workflows/staging.yaml`: Railway CLI (via `nixpkgs` dependency if available, else `npm i -g @railway/cli`), then `railway up` to `staging` using `RAILWAY_TOKEN_STAGING`.
- A health/status confirmation appended to the deploy step so the pipeline fails on an unhealthy deploy (see Additional Considerations — `railway up --ci` exits at build completion and does not wait for deploy health, so a `railway status` / deployment-status poll provides the pass/fail signal).

**Dependencies:** Phase 1 (workflow + `just ci`), Phase 2 (staging env + token).

**Done when:** A green push to `main` deploys to staging; a failing build or unhealthy deploy fails the pipeline; a red `just ci` skips the deploy. Covers ci-cd-tangled-railway.AC2.1, AC2.3, AC2.4.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Production database backup mechanism
**Goal:** Produce a retrievable restore point of the production SQLite database, as the prerequisite for safe promotes.

**Components (choose one — see Additional Considerations):**
- **Litestream (recommended):** add the `litestream` binary to the runtime image; entrypoint restores on boot if the DB is absent, then `litestream replicate -exec` supervises the relay, streaming the WAL to S3-compatible storage. Restructures [docker-entrypoint.sh](../../../docker-entrypoint.sh) (still root-chowns `/data` first).
- **Pre-deploy snapshot:** a `preDeployCommand` (production only, via `[environments.production]` in `railway.toml`) runs a WAL-safe `sqlite3 relay.db ".backup"` and uploads to a bucket; requires adding `sqlite3` and an object-storage client to the `debian-bookworm-slim` runtime image.
- Backup target: a Railway bucket or external S3-compatible store (Backblaze B2 / Tigris); credentials live in the `production` environment only.

**Dependencies:** Phase 2 (environment model established).

**Done when:** A production deploy (or boot) produces a restore point that is present and retrievable from the backup target, and a documented restore reproduces the DB. Covers ci-cd-tangled-railway.AC5.1.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Production promote on tag
**Goal:** Promote a tagged commit to `production`, gated by the test gate and preceded by a backup.

**Components:**
- Deploy step in `.tangled/workflows/release.yaml` (`when: push tag v*`): `just ci`, then ensure the backup/restore point (Phase 4), then `railway up` to `production` using `RAILWAY_TOKEN_PRODUCTION`, then the same health confirmation as staging.
- An environment-scoped `RAILWAY_TOKEN_PRODUCTION` in tangled repo secrets (production-only scope).

**Dependencies:** Phase 3 (deploy + health-signal pattern), Phase 4 (backup).

**Done when:** Pushing a `v*` tag deploys that exact commit to production after a restore point is captured; non-`v*` pushes never deploy production; an unhealthy production deploy fails the pipeline. Covers ci-cd-tangled-railway.AC3.1, AC3.2, AC3.3, AC3.4, AC4.4.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Documentation reconciliation
**Goal:** Make the deploy docs match the tangled→Railway reality.

**Components:**
- Rewrite the Railway and Image Distribution sections of [docs/deploy.md](../../deploy.md): remove "connect the GitHub repo" / GitHub Actions / GHCR-as-primary; document the two-environment topology, the `railway up`-from-spindle flow, tag-based promote, backup-before-promote, and the forward-only-migration rollback caveat. Mark the colmena/NixOS path as secondary.
- Update the CI/Commands section of [AGENTS.md](../../../AGENTS.md) to describe `just ci` and the three workflows.

**Dependencies:** Phases 1–5 (documents the implemented system).

**Done when:** [docs/deploy.md](../../deploy.md) and [AGENTS.md](../../../AGENTS.md) describe the implemented pipeline with no GitHub-connect assumption; internal links resolve. Covers the docs Definition-of-Done item and ci-cd-tangled-railway.AC5.2 (documented rollback procedure).
<!-- END_PHASE_6 -->

## Additional Considerations

**Platform behavior (verified against Railway/Litestream docs, 2026-06-21):**
- **`railway up` health signal.** `railway up --ci` streams only build logs and exits when the *build* completes — it does **not** wait for the deployment to become healthy. Each deploy step therefore follows `railway up --ci` with a deployment-status check (`railway status`, or a deployment-status query) and fails the step if the new deployment is not healthy. The `-s`/`--service` and `-e`/`--environment` flags target the deploy; `--environment` is passed explicitly.
- **Tokens.** `RAILWAY_TOKEN` authorizes project-level actions (non-interactive `RAILWAY_TOKEN=… railway up`); `RAILWAY_API_TOKEN` is account-level. The design uses a separate token per environment and passes `--environment` explicitly so the staging and production legs cannot cross over. Still to confirm at implementation: whether a project token is strictly environment-scoped at creation, and whether `railway link` is needed under a token.
- **`railway.toml`.** `preDeployCommand` is an array under `[deploy]` ("the command to run before starting the container"); per-environment overrides nest under `[environments.<name>.deploy]`, and config-as-code overrides dashboard values.
- **Railway CLI install.** Package attribute in nixpkgs unconfirmed (the search UI is JS-rendered); fall back to `npm i -g @railway/cli` (Node 22 is in the dev shell) or the install script.

**Backup approach trade-off.** Litestream gives continuous replication (small RPO) and restore-on-boot but supervises the process and adds a binary + restructured entrypoint; a `preDeployCommand` snapshot is simpler but only captures per-deploy points (larger RPO) and adds image dependencies. A decisive caveat favors Litestream: `preDeployCommand` runs *before the container starts*, and Railway mounts volumes at container start — so it may not have `/data` mounted and thus cannot read `relay.db`. If so, the backup must run inside the main container's entrypoint, which is exactly the Litestream pattern. Litestream targets S3, S3-compatible (MinIO, Tigris), Backblaze B2, GCS, and Azure, and requires WAL mode (the relay already uses WAL). Verify the volume-mount timing and finalize the exact `litestream.yml` during implementation. Recommendation: Litestream.

**Rollback caveat.** Migrations are forward-only. Tag-based code rollback is safe only under expand-contract migrations; otherwise rollback is a restore from the Phase 4 backup. This constrains how migrations are authored, not just how deploys run.

**Security posture.** No Railway token is present in PR-triggered pipelines; deploy tokens live only in pipelines that require repository write access (push to `main`, `v*` tag). This is the main reason the PR preview environment was dropped from scope.

**Cost.** `production` stays warm; `staging` uses serverless sleep — a service idle >10 min sleeps (zero compute; volume storage still billed), and the first request after sleep wakes it, possibly returning a one-off `502` during cold boot (fine for staging dogfooding). No ephemeral environments means no per-PR cost.

**Scope note.** Per-PR live preview environments were considered and deliberately excluded: tangled has no `pull_request_closed`/`merged` event for teardown, spindle cannot build images, and putting a Railway token in PR pipelines inverts least privilege.

**Considered & deferred — Turso / libSQL.** Evaluated as an alternative to the volume + Litestream: it removes the volume entirely, ships point-in-time restore on every tier (subsuming the backup mechanism), and its database-per-tenant model fits the planned per-user-SQLite architecture; it is MIT-licensed, the `sqld` server is self-hostable, and it preserves the standard SQLite file format, so the data-portability/sovereignty story survives. Deferred because adoption is a full data-layer migration — libSQL exposes its own `Builder`/`Connection` API with no `sqlx` backend and no compile-time-checked queries, so all ~560 `sqlx` query sites plus the custom migration runner would be rewritten. The natural trigger to revisit is the per-user-DB wave (Wave 3), when the data layer is already being reshaped; until then Litestream is the zero-code-change choice. Adopting it would also diverge from the Bluesky reference PDS, which uses local per-user SQLite files.
