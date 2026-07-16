#!/usr/bin/env bash
# Prove scripts/gc.sh never targets the real main working tree for pruning — even when invoked
# from a secondary worktree (the normal agent workflow, `.claude/worktrees/*`). Regression guard
# for MM-390: gc.sh once derived "the main checkout" from cwd, so run from a secondary worktree it
# would mark git's actual main checkout as PRUNE (git's own refusal was the only thing preventing
# deletion). This drives gc.sh in dry-run from a throwaway secondary worktree and asserts the main
# working tree is never in the prune set.
#
# Portable bash + git + awk. Creates and cleans up one throwaway worktree/branch.
set -euo pipefail

cd "$(dirname "$0")/.."

main_wt="$(git worktree list --porcelain | awk '/^worktree /{print substr($0, 10); exit}')"
gc_script="$(pwd)/scripts/gc.sh"

tmp="$(mktemp -d)"
wt="$tmp/gc-guard-wt"
branch="gc-guard-selftest-$$"

cleanup() {
  git worktree remove --force "$wt" >/dev/null 2>&1 || true
  git branch -D "$branch" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

git worktree add -q -b "$branch" "$wt" HEAD

# Run gc.sh (dry-run — no --apply) FROM the secondary worktree; that is the buggy invocation.
out="$(cd "$wt" && bash "$gc_script" 2>/dev/null || true)"

# A correct gc.sh SKIPS the main working tree — it emits no KEEP/PRUNE line for it at all. The bug
# is that it evaluates main like any other worktree; whether that surfaces as PRUNE or (on a dirty
# main) KEEP depends on main's incidental state, so asserting on PRUNE alone would miss the bug on
# a dirty checkout. Instead assert main's EXACT path appears in NO KEEP/PRUNE line. Exact path-field
# match, not substring: the main path is a prefix of every nested worktree path under it.
offender="$(printf '%s\n' "$out" | awk -v m="$main_wt" '
  function pathfield(s) {
    sub(/^[[:space:]]*(KEEP|PRUNE)[[:space:]]+[^[:space:]]+[[:space:]]+/, "", s)   # strip "VERB <size> "
    if (match(s, / \[/))              s = substr(s, 1, RSTART - 1)                  # " [label] …"
    else if (match(s, / \(detached/)) s = substr(s, 1, RSTART - 1)                  # " (detached x) …"
    else if (match(s, / — /))         s = substr(s, 1, RSTART - 1)                  # bare " — reason"
    return s
  }
  /^[[:space:]]*(KEEP|PRUNE)[[:space:]]/ { if (pathfield($0) == m) print }
')"

if [ -n "$offender" ]; then
  echo "✗ gc.sh evaluated the real main working tree instead of skipping it (MM-390 regression):" >&2
  echo "    main working tree: $main_wt" >&2
  printf '    %s\n' "$offender" >&2
  exit 1
fi

echo "✓ gc.sh skips the main working tree when run from a secondary worktree"
