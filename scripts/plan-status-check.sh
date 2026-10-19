#!/usr/bin/env bash
# Fail if a live design/implementation/test plan declares itself shipped, landed, superseded, or
# complete — that plan's design/test/implementation triad belongs in docs/archive/, moved
# together, per docs/archive/README.md. Plans still in flight stay in docs/{design,test,
# implementation}-plans/ (AGENTS.md Project Structure).
#
# Scope: docs/design-plans/, docs/implementation-plans/, docs/test-plans/ — whichever of the
# three exist. docs/archive/ is exempt: that's where a plan goes once it's actually done.
#
# A partially-shipped plan is legitimately still live ("mostly shipped", "partially landed", "in
# progress" all describe open work), so a completion word only counts when it isn't qualified:
# the check looks at the status clause up to the first dash/paren/period after "Status:", and a
# qualifier word (mostly/partially/largely/nearly/almost/in part/in progress) immediately before
# the completion word exempts the line even inside that clause.
set -euo pipefail

cd "$(dirname "$0")/.."

dirs=()
for d in docs/design-plans docs/implementation-plans docs/test-plans; do
  [ -d "$d" ] && dirs+=("$d")
done

if [ "${#dirs[@]}" -eq 0 ]; then
  echo "✓ no live plan directories to check"
  exit 0
fi

hits="$(grep -rniE 'status:.*\b(shipped|superseded|landed|complete(d)?)\b' "${dirs[@]}" 2>/dev/null || true)"

fail=0

while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  text="${rest#*:}"

  # The status *value* is the clause right after "Status:", up to the first dash/paren/period —
  # later prose (a cross-reference, an example that itself shipped) doesn't count.
  clause="$(printf '%s' "$text" | sed -E 's/.*[Ss]tatus:[[:space:]]*\*{0,2}//; s/[—–(.].*//')"

  # Exempt a qualified completion: still legitimately live.
  if printf '%s' "$clause" | grep -qiE '\b(mostly|partially|largely|nearly|almost|in part|in progress)\b'; then
    continue
  fi

  if printf '%s' "$clause" | grep -qiE '\b(shipped|superseded|landed|complete(d)?)\b'; then
    echo "✗ $file:$lineno declares itself done ($text) — move this plan's design/test/implementation triad to docs/archive/ (docs/archive/README.md)" >&2
    fail=1
  fi
done <<<"$hits"

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "✓ no live plan declares itself shipped/landed/superseded/complete"
