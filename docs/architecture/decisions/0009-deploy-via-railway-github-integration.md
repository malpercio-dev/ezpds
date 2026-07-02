# ADR-0009: Deploy via Railway's native GitHub integration; CI gates, it doesn't deploy

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0008](0008-pds-as-oci-image-not-nix-built.md) · [`../../deploy.md`](../../deploy.md) · [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)

## Context

We need continuous deployment for staging and production. The common approach is
a **CI-driven deploy**: a workflow step runs `railway up` (or equivalent) with a
deploy token stored as a CI secret. That puts a privileged deploy credential in
CI and on the fork-PR attack surface.

Railway also offers a **native GitHub integration**: Railway watches the repo,
builds the `Dockerfile` itself (ADR-0008), and deploys — with a "Wait for CI"
gate so it only ships green commits.

## Decision

Use **Railway's native GitHub integration**. **CI is the gate, not the
deployer** — there is no `railway up` step and **no Railway token in CI**. Both
environments use "Wait for CI", so the green check is the deploy gate:

- **staging** — Railway watches `main`; merging a PR deploys staging.
- **production** — Railway watches the `production` branch; a release advances
  `production` to a `vX.Y.Z` tag (`just deploy-production <tag>`), never a `main`
  merge. A `verify-release` job refuses any `production` tip whose tag doesn't
  match the workspace version.

## Consequences

- **No deploy secrets in CI** and none exposed to fork PRs; the deploy credential
  lives only in Railway's GitHub app.
- **The CI green check *is* the deploy gate** — CI correctness directly gates what
  ships.
- **Release = branch/tag advancement**, not a merge: `set-version` → merge →
  `release` (tag) → `deploy-production` (advance `production`). Litestream backs
  up the production SQLite DB.
- **Coupling to Railway** as the platform; migrating platforms means re-doing the
  watch/gate wiring (but not CI secrets, since there are none).

## Alternatives considered

- **CI-driven deploy (`railway up` + token in CI).** More explicit control over
  when/what deploys, but requires a privileged deploy secret in CI and on the
  fork-PR surface. Rejected for secret hygiene; the "Wait for CI" gate gives
  equivalent control without the token.
