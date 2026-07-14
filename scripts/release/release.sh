#!/usr/bin/env bash
# release.sh — cut a release: create the annotated tag v{workspace version} and push
# it to origin. Entry point: `just release`.
#
# The tag is the release anchor — it always matches the reported PDS version (derived
# from Cargo.toml). Tagging does NOT deploy: promoting a tag to production is a
# separate, explicit step (`just deploy-production <tag>`, which advances the
# `production` branch Railway watches). Run from a clean `main`.
set -euo pipefail

version="$(awk '/^\[workspace\.package\]/{p=1} p&&/^version *=/{if(match($0,/"[^"]+"/)){print substr($0,RSTART+1,RLENGTH-2);exit}}' Cargo.toml)"
if [ -z "$version" ]; then echo "✗ could not read [workspace.package] version from Cargo.toml" >&2; exit 1; fi
tag="v${version}"
if [ -n "$(git status --porcelain)" ]; then echo "✗ working tree not clean — commit/stash first" >&2; exit 1; fi
if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
  echo "✗ release from 'main' only (you are on $(git rev-parse --abbrev-ref HEAD))" >&2; exit 1
fi
# Tag the merged, pushed main — not a local-only or stale commit — so the tag (and the
# production branch later advanced to it) carries real merged-main provenance.
git fetch --quiet origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  echo "✗ release requires HEAD == origin/main — push/pull main first" >&2; exit 1
fi
# Check origin too: a stale clone may lack a tag that already exists on the remote, which
# would otherwise only surface as a confusing push rejection after the local tag is created.
if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null \
  || git ls-remote --exit-code --tags --refs origin "refs/tags/${tag}" >/dev/null 2>&1; then
  echo "✗ tag ${tag} already exists (locally or on origin) — bump the version with 'just set-version' first" >&2; exit 1
fi
echo "→ tagging ${tag} at $(git rev-parse --short HEAD)…"
git tag -a "${tag}" -m "Release ${tag}"
echo "→ pushing ${tag} → origin…"
git push origin "${tag}"
echo "✓ released ${tag} — promote it with 'just deploy-production ${tag}'"
