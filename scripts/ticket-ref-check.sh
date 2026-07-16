#!/usr/bin/env bash
# Fail if Rust source carries a Linear ticket / acceptance-criteria reference in a comment.
#
# AGENTS.md hard rule: "No ticket or AC references in source code" — traceability belongs in
# docs/design-plans/ and docs/test-plans/, not in `.rs`. The refs read as noise the moment the
# PR merges, and they rot. #227 swept the codebase clean of these; #266 reintroduced sixteen a
# day later. This guard is the forcing function so that class of regression can't recur silently.
#
# Scope is Rust source, where the #266 regression landed. The written AGENTS.md rule also covers
# AGENTS.md files (and frontend .ts/.svelte source is arguably in its spirit though not named), but
# those still carry historical refs — extending this guard to them is a separate decision that
# needs them cleaned up first.
#
# Portable bash + git grep only (Linux ci-pds + macOS ci + Nix shell). Date/time format strings
# such as `YYYY-MM-DD` never match `MM-[0-9]` (no digit follows `MM-`).
set -euo pipefail

cd "$(dirname "$0")/.."

pattern='(MM-[0-9]+|AC[0-9]+\.[0-9]+)'
hits="$(git grep -nIE "$pattern" -- '*.rs' ':(exclude)wt/' || true)"

if [ -n "$hits" ]; then
  echo "✗ ticket/AC references found in Rust source — move traceability to docs/:" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi

echo "✓ no ticket/AC references in Rust source"
