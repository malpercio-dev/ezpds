#!/usr/bin/env bash
# set-version.sh — bump the workspace version and resync Cargo.lock.
# Entry point: `just set-version X.Y.Z`.
#
# The workspace version (Cargo.toml [workspace.package].version) is the single
# source of truth: every crate inherits it, and the PDS reports it at
# _health/describeServer via env!("CARGO_PKG_VERSION"). This script bumps it;
# `just release` derives the git tag from it, so the tag and the reported version
# can never drift. Run in a reviewed PR, then `just release` from main after merge.
#
# Usage: scripts/release/set-version.sh X.Y.Z
set -euo pipefail

version="${1:-}"
if [ -z "$version" ]; then
  echo "usage: $(basename "$0") X.Y.Z" >&2
  exit 2
fi
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "✗ version must be X.Y.Z (got '$version')" >&2
  exit 1
fi
# Rewrite only the [workspace.package] version line (not dependency versions below it):
# scope strictly to that section (reset on any other section header) and fail if no version
# line was found, so a missing/renamed field can never silently rewrite a later `version`.
awk -v v="$version" '
  /^\[workspace\.package\]$/ {p=1; print; next}
  /^\[/ {p=0}
  p && /^version[[:space:]]*=/ && !done {print "version = \"" v "\""; done=1; next}
  {print}
  END { if (!done) { print "✗ could not rewrite [workspace.package].version" > "/dev/stderr"; exit 1 } }
' Cargo.toml > Cargo.toml.tmp
mv Cargo.toml.tmp Cargo.toml
# Resync the lockfile so the new workspace-crate versions land in Cargo.lock and
# `just lock-check` stays green (cargo metadata resolves without upgrading other deps).
cargo metadata --format-version 1 >/dev/null
echo "✓ workspace version set to $version — commit Cargo.toml + Cargo.lock, open a PR,"
echo "  then run 'just release' from main once it's merged."
