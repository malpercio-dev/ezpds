#!/usr/bin/env bash
# deploy-production.sh — promote a release tag to production. Entry point:
# `just deploy-production [tag]`.
#
# Railway watches the `production` branch and deploys its tip (gated on the CI
# workflow + the verify-release-tag backstop), so "deploying production" means moving
# `production` to a vX.Y.Z tag:
#   scripts/release/deploy-production.sh v0.3.1   # promote a specific tag
#   scripts/release/deploy-production.sh          # promote the highest vX.Y.Z tag
# A normal promote must fast-forward (production never holds commits the tag lacks).
# Rolling back to an OLDER tag is a non-fast-forward; pass FORCE=1 to allow it —
# production is a deploy pointer, not a work branch, so rewinding it is safe.
set -euo pipefail

tag="${1:-}"
# Resolve tags against origin, not a possibly-stale local clone — otherwise the default
# "latest" pick (or an explicit tag this clone hasn't fetched) could promote the wrong
# release, or an outdated one, to production.
git fetch --quiet --tags origin
if [ -z "$tag" ]; then
  tag="$(git tag --list --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"
  if [ -z "$tag" ]; then echo "✗ no vX.Y.Z tag exists — cut one with 'just release'" >&2; exit 1; fi
  echo "→ no tag given; using latest: ${tag}"
fi
if ! printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "✗ tag must be vX.Y.Z (got '$tag')" >&2; exit 1
fi
# Only ever promote an origin-published tag. The fetch above brought origin's tags local for
# resolution, but the local namespace can also hold a local-only tag (auto-selected as
# "latest" or passed explicitly); refuse anything origin doesn't have, so an unpushed commit
# can never reach production. (A divergent same-name tag is additionally caught by the
# production-branch verify-release CI job before Railway deploys.)
if ! git ls-remote --exit-code --tags --refs origin "refs/tags/${tag}" >/dev/null 2>&1; then
  echo "✗ tag ${tag} is not on origin — push it (e.g. with 'just release') before promoting" >&2; exit 1
fi
if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  echo "✗ tag ${tag} does not exist locally — fetch it or cut it with 'just release'" >&2; exit 1
fi
target="$(git rev-parse "${tag}^{commit}")"
# Compare against the current remote production tip to classify the move.
if git fetch --quiet origin production 2>/dev/null; then
  current="$(git rev-parse FETCH_HEAD)"
  if [ "$current" = "$target" ]; then
    echo "✓ production already at ${tag} ($(git rev-parse --short "$target")) — nothing to do"; exit 0
  fi
  if ! git merge-base --is-ancestor "$current" "$target"; then
    if [ "${FORCE:-}" != "1" ]; then
      echo "✗ ${tag} is behind/diverged from current production ($(git rev-parse --short "$current")) — this is a rollback." >&2
      echo "  Re-run with FORCE=1 to rewind production to ${tag}." >&2
      exit 1
    fi
    echo "→ FORCE=1: rewinding production to ${tag}"
    git push --force origin "${target}:refs/heads/production"
    echo "✓ production → ${tag}; Railway will deploy once CI is green"
    exit 0
  fi
else
  echo "→ production branch does not exist yet — creating it at ${tag}"
fi
echo "→ pushing ${tag} ($(git rev-parse --short "$target")) → production…"
git push origin "${target}:refs/heads/production"
echo "✓ production → ${tag}; Railway will deploy once CI is green"
