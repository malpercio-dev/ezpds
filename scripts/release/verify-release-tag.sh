#!/usr/bin/env bash
# verify-release-tag.sh — verify the commit at HEAD is a valid production release
# point. Entry point: `just verify-release-tag`. Used by the CI workflow on the
# `production` branch, and runnable locally.
#
# Every v-prefixed tag on HEAD must be semver vX.Y.Z, at least one such tag must
# exist, and it must equal the workspace version the binary reports
# (env!("CARGO_PKG_VERSION")). The production branch is advanced to a v* tag to deploy
# and Railway gates the deploy on CI, so this is the backstop against shipping a tip
# whose tag/version disagree.
set -euo pipefail

# The branch may carry any v-prefixed tag; reject a non-semver one (e.g. `vfoo`) outright so it
# can never slip past the version check below.
release_tags="$(git tag --points-at HEAD | grep -E '^v' || true)"
non_semver="$(printf '%s\n' "$release_tags" | grep -Ev '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
if [ -n "$non_semver" ]; then
  echo "✗ non-semver release tag(s) point at HEAD:" >&2
  printf '    %s\n' "$non_semver" >&2
  exit 1
fi
tags="$(printf '%s\n' "$release_tags" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
if [ -z "$tags" ]; then
  echo "✗ no vX.Y.Z tag points at HEAD — the production branch must be advanced to a release tag" >&2
  echo "  (cut one with 'just release', then 'just deploy-production <tag>')." >&2
  exit 1
fi
version="v$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | select(.name=="pds") | .version')"
mismatched="$(printf '%s\n' "$tags" | grep -vxF "$version" || true)"
if [ -n "$mismatched" ]; then
  echo "✗ release tag(s) do not match workspace version '$version' (Cargo.toml):" >&2
  printf '    %s\n' "$mismatched" >&2
  echo "  Bump [workspace.package].version to the intended tag and re-tag, or remove the mismatched tag." >&2
  exit 1
fi
echo "✓ all vX.Y.Z tag(s) on HEAD match workspace version '$version'"
