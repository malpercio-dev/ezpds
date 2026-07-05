# ADR-0015: Host CI on GitHub Actions (leaving the tangled spindle)

- **Status:** Accepted
- **Date:** 2026-07-05 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0009](0009-deploy-via-railway-github-integration.md) · [`../../ios-cicd.md`](../../ios-cicd.md) · [superseded design plan](../../archive/design-plans/2026-06-21-ci-cd-tangled-railway.md) · `.github/workflows/`

## Context

CI originally ran on a **tangled spindle** (the AT Protocol-based git forge's
CI runner), with the repo on a self-hosted knot and no GitHub remote — see the
superseded 2026-06-21 CI/CD design plan. Spindle pipelines run each step in a
fresh unprivileged Nix container: they cannot build or run nested container
images, and offer **no macOS runners**, so the iOS TestFlight lanes
(xcodebuild, code signing) were impossible there. Separately, Railway's native
GitHub integration — the deploy mechanism we wanted (ADR-0009) — requires the
repo to live on GitHub.

## Decision

We will host the repository on GitHub and run CI on **GitHub Actions**, split
into a Linux **PDS** lane (`ci.yml`, running `just ci-pds`) and macOS **iOS**
lanes (`ios-testflight.yml`, `admin-testflight.yml`, `ios-pr-check.yml` on
free public-repo `macos-26` runners). CI gates; Railway deploys (ADR-0009).

## Consequences

- macOS + Xcode runners make the TestFlight lanes and the secret-free iOS PR
  gate possible at all — the capability that forced the move.
- "Wait for CI" on Railway turns the green check into the deploy gate with no
  deploy credentials in CI.
- We give up forge sovereignty (the tangled knot) for CI capability and deploy
  integration; the repo's canonical home is now GitHub.
- Workflow definitions are GitHub-specific; the shared `just` recipes keep the
  build/test/upload logic portable if we ever move again.

## Alternatives considered

- **Stay on the tangled spindle** — no macOS runners and no image builds; the
  iOS apps could never ship from CI, and Railway's GitHub integration would be
  unavailable.
- **Self-hosted runners on the knot** — maintaining a macOS runner fleet for a
  solo project costs more than it buys; free public-repo GitHub macOS runners
  cost nothing.
