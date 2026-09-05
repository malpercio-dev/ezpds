#!/usr/bin/env bash
# Fail if any ADR-NNNN citation points at a superseded ADR, or at an ADR number with no file.
#
# ADRs are immutable historical records (docs/architecture/decisions/README.md): once one is
# superseded, code and docs elsewhere should cite whichever ADR replaced it, not the retired one —
# a stale citation reads as still-governing rationale to the next reader. This guard is the
# forcing function so that class of drift can't recur silently.
#
# Scope: crates/, apps/*/src-tauri, apps/*/src, tools/, docs/ — excluding
# docs/architecture/decisions/ itself (ADRs legitimately cite each other's history) and
# docs/archive/ (frozen historical record; a superseded citation there is accurate to the time).
# CHANGELOG* is excluded defensively (dated release notes, not living rationale) even though it
# currently falls outside every included path.
#
# Escape hatch: a citing line that also contains the word "superseded" is deliberately discussing
# history ("ADR-0003 was superseded by ADR-0022") rather than treating the old ADR as current
# rationale, so it is allowed through unchanged.
set -euo pipefail

cd "$(dirname "$0")/.."

adr_dir="docs/architecture/decisions"

hits="$(git grep -nIE 'ADR-[0-9]{4}' -- \
  'crates/**' 'apps/*/src-tauri/**' 'apps/*/src/**' 'tools/**' 'docs/**' \
  ":(exclude)$adr_dir/**" ':(exclude)docs/archive/**' ':(exclude)CHANGELOG*' \
  2>/dev/null || true)"

fail=0

while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  text="${rest#*:}"

  # Escape hatch: the line itself names the supersession, so the old number is prose, not a
  # governing citation.
  if printf '%s' "$text" | grep -qi 'superseded'; then
    continue
  fi

  for num in $(printf '%s' "$text" | grep -oE 'ADR-[0-9]{4}' | sed 's/ADR-//' | sort -u); do
    adr_file="$(ls "$adr_dir/$num"-*.md 2>/dev/null | head -1 || true)"
    if [ -z "$adr_file" ]; then
      echo "✗ $file:$lineno cites ADR-$num, which has no file under $adr_dir/" >&2
      fail=1
      continue
    fi
    # The status *value* is the first word after "**Status:**" (Proposed / Accepted / Deferred /
    # Deprecated / Superseded) — a status line can go on to prose an in-part nuance ("Accepted —
    # the ordering is superseded in part by ADR-0027"), so matching "superseded" anywhere on the
    # line would false-fail on a still-Accepted ADR.
    status_line="$(grep -m1 -E '\*\*Status:\*\*' "$adr_file" || true)"
    status_value="$(printf '%s' "$status_line" | sed -E 's/.*\*\*Status:\*\*[[:space:]]*([A-Za-z]+).*/\1/')"
    if printf '%s' "$status_value" | grep -qi '^superseded$'; then
      echo "✗ $file:$lineno cites ADR-$num, which is superseded ($status_line) — repoint to the current ADR" >&2
      fail=1
    fi
  done
done <<<"$hits"

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "✓ no citations of a superseded or missing ADR"
