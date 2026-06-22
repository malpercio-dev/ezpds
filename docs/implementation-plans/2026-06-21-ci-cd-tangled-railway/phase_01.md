# CI/CD: Tangled → Railway Implementation Plan — Phase 1: Test-gate & workflow split

**Goal:** Restructure the tangled spindle workflows by trigger context (PR / main / tag), each running the existing `just ci` gate; retire the monolithic `ci.yaml`.

**Architecture:** One workflow file per trigger. Spindle has no cross-workflow "needs" dependency, so the only reliable gate is step ordering within a single file — a failed step aborts the run, so a later deploy step runs only if `just ci` passed.

**Tech Stack:** tangled spindle (nixery engine), `just`, cargo (fmt/clippy/test), cargo-audit.

**Scope:** Phase 1 of 6. Design: `docs/design-plans/2026-06-21-ci-cd-tangled-railway.md`.

**Codebase verified:** 2026-06-21 (direct read this session; subagent verification skipped due to the classifier outage — all referenced files were read firsthand).

## Codebase verification findings
- ✓ **`just ci` already exists** (`justfile:28`): `ci: fmt-check clippy test` then `cargo audit`. **No recipe change needed** — Phase 1 is purely the workflow split. (Design assumed we'd create it.)
- ✓ Current gate `.tangled/workflows/ci.yaml` runs fmt/clippy/test/audit as explicit steps on `push`+`pull_request`+`manual` to `main`; `engine: nixery`; deps `rustc, cargo, clippy, rustfmt, sqlite`.
- ✗ **Correction (post-merge, 2026-06-21):** the documented step key is **`command:`** (shown verbatim in the tangled docs); the pre-existing `ci.yaml` used `run:`, which is undocumented and the likely reason CI never executed. All workflows use `command:`.
- ✗ **Correction (post-merge, 2026-06-21):** the Nixery CI image needs a C toolchain (`gcc`, `binutils`, `pkg-config`) — Rust build scripts and C deps (bundled SQLite, `ring`) require `cc`/`ar`. And `--workspace` pulls in the `identity-wallet` Tauri crate (GTK/WebKit), unbuildable in Linux CI, so the workflows run **`just ci-relay`** (`--workspace --exclude identity-wallet`); `just ci` stays the full macOS-local gate.
- + The current `ci.yaml` runs `cargo audit` but does **not** declare `cargo-audit` in deps. The new workflows add `just` and `cargo-audit` to `dependencies.nixpkgs`. **Confirm at execution** that `cargo audit` actually resolves in CI today (possible latent gap).

## Acceptance Criteria Coverage
### ci-cd-tangled-railway.AC1: Test gate runs and gates correctly
- **ci-cd-tangled-railway.AC1.1 Success:** `just ci` runs `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, and `cargo audit`; the recipe exits 0 only when all pass.
- **ci-cd-tangled-railway.AC1.2 Failure:** When any check fails, `just ci` exits non-zero and the deploy step in the same workflow file does not run (step ordering gates the deploy).
- **ci-cd-tangled-railway.AC1.3 Success:** A `pull_request`-triggered pipeline runs `just ci` and only `just ci` — no deploy step, no Railway token referenced.
### ci-cd-tangled-railway.AC4: Secret isolation (partial)
- **ci-cd-tangled-railway.AC4.1:** PR-triggered pipelines have no Railway token available or referenced.

**Verification is operational** (run the pipeline / `just ci`), not unit tests — these are CI config files.

## Tasks

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->
<!-- START_TASK_1 -->
### Task 1: Add PR test-gate workflow
**Verifies:** ci-cd-tangled-railway.AC1.1, AC1.3, AC4.1

**Files:** Create `.tangled/workflows/pr.yaml`

**Implementation:** Triggered on `pull_request` → `main`. Single step runs `just ci`. No deploy step, no secret referenced.
```yaml
when:
  - event: ["pull_request"]
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

steps:
  - name: CI (fmt, clippy, test, audit)
    run: just ci
```

**Verification:** Valid YAML. Locally, `just ci` exits 0 on a clean tree. Opening a PR to `main` triggers this pipeline and runs `just ci`.

**Commit:** `ci: add PR test-gate workflow`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add staging workflow (gate + placeholder deploy)
**Verifies:** ci-cd-tangled-railway.AC1.2 (gate ordering)

**Files:** Create `.tangled/workflows/staging.yaml`

**Implementation:** Triggered on `push` (+ `manual`) → `main`. Runs `just ci`, then a placeholder deploy step (the real `railway up` is wired in Phase 3). The placeholder keeps the file valid and proves step ordering now.
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

steps:
  - name: CI (fmt, clippy, test, audit)
    run: just ci
  - name: Deploy to staging (wired in Phase 3)
    run: echo "staging deploy added in Phase 3"
```

**Verification:** Pushing to `main` runs `just ci` then the placeholder. To confirm AC1.2: a commit that fails a check (e.g. a deliberate fmt violation) aborts at `just ci`, and the placeholder step does not run.

**Commit:** `ci: add staging workflow skeleton`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Add release workflow (gate + placeholder promote)
**Verifies:** ci-cd-tangled-railway.AC1.2 (gate ordering), AC3.3 (tag-only trigger)

**Files:** Create `.tangled/workflows/release.yaml`

**Implementation:** Triggered on `push` with a `v*` tag (push-only per tangled tag-glob support). Runs `just ci`, then a placeholder promote step (the real `railway up` to production is wired in Phase 5).
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

steps:
  - name: CI (fmt, clippy, test, audit)
    run: just ci
  - name: Promote to production (wired in Phase 5)
    run: echo "production promote added in Phase 5"
```

**Verification:** Pushing a tag like `v0.0.0-test` triggers this pipeline; a normal branch push does not. **Confirm at execution** that the `tag:` glob form is accepted by the spindle (the repo has not used tag triggers before).

**Commit:** `ci: add release workflow skeleton`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Retire the monolithic ci.yaml
**Verifies:** ci-cd-tangled-railway.AC1.3 (no duplicate PR runs)

**Files:** Delete `.tangled/workflows/ci.yaml`

**Implementation:** `pr.yaml` (pull_request) and `staging.yaml` (push + manual to main) now cover everything `ci.yaml` did. Remove it to avoid duplicate runs.

**Verification:** `.tangled/workflows/` contains exactly `pr.yaml`, `staging.yaml`, `release.yaml`. A PR to `main` runs only `pr.yaml`; a push to `main` runs only `staging.yaml`.

**Commit:** `ci: retire monolithic ci.yaml (split into pr/staging/release)`
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_A -->
