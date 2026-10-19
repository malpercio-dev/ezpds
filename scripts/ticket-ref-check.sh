#!/usr/bin/env bash
# Fail if Rust source or AGENTS.md carries a Linear ticket / acceptance-criteria reference.
#
# AGENTS.md hard rule: "No ticket or AC references in source code" — traceability belongs in
# ADRs, docs/design-plans/, and docs/test-plans/, not in `.rs` or AGENTS.md. The refs read as
# noise the moment the PR merges, and they rot. This guard is the forcing function so that class
# of regression can't recur silently.
#
# Scope is Rust source and every AGENTS.md file. Frontend .ts/.svelte source remains deliberately
# out of scope: the written rule does not name it, even though excluding ticket refs there is in
# the rule's spirit.
#
# Portable bash + git grep only (Linux ci-pds + macOS ci + Nix shell). Date/time format strings
# such as `YYYY-MM-DD` never match `MM-[0-9]` (no digit follows `MM-`).
set -euo pipefail

cd "$(dirname "$0")/.."

pattern='([Mm][Mm]-[0-9]+|AC[0-9]+\.[0-9]+)'
hits="$(git grep -nIE "$pattern" -- '*.rs' '*AGENTS.md' ':(exclude)wt/' || true)"

if [ -n "$hits" ]; then
  echo "✗ ticket/AC references found in Rust source or AGENTS.md — move traceability to an ADR or design/test plan under docs/:" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi

echo "✓ no ticket/AC references in Rust source or AGENTS.md"
