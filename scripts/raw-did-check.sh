#!/usr/bin/env bash
# Fail on a new raw-string DID parameter or field in the PDS's auth/ and routes/ trees.
#
# DIDs cross these boundaries as `common::Did`, which can only be built by the syntax
# validator. A `did: &str` / `did: String` (or `user_did`, `authority_did`, ...) lets a handle
# or an unchecked string through where a DID is meant.
#
# Both trees are migrating file by file. Each file's current count lives in
# scripts/raw-did-baseline.txt; a file may not exceed it (a file not listed allows zero), and a
# count that drops must be lowered in the baseline in the same change, so the ratchet only
# tightens. Regenerate the baseline with --print-counts after a migration slice.
#
# Test code is exempt: `*_test.rs` / test-support files, and any `#[cfg(test)]` item (tracked to
# the end of its brace block). `let` bindings are not parameters and are ignored.
#
# Usage: scripts/raw-did-check.sh [--print-counts]
set -euo pipefail

cd "$(dirname "$0")/.."

baseline=scripts/raw-did-baseline.txt

count_file() {
  awk '
    /#\[cfg\(test\)\]/ { skip = 1; depth = 0; opened = 0; next }
    skip {
      n = gsub(/\{/, "{"); c = gsub(/\}/, "}")
      depth += n - c
      if (n > 0) opened = 1
      if ((opened && depth <= 0) || (!opened && /;[[:space:]]*$/)) skip = 0
      next
    }
    /^[[:space:]]*\/\// { next }
    /(^|[^a-z_])let / { next }
    /[a-z_]*did: &?('"'"'[a-z]+ )?(str|String)([^A-Za-z0-9_]|$)/ { hits++ }
    END { print hits + 0 }
  ' "$1"
}

list_files() {
  git ls-files 'crates/pds/src/auth/*.rs' 'crates/pds/src/routes/*.rs' 'crates/pds/src/routes/**/*.rs' |
    grep -vE '(_test|_tests|test_utils|_test_support)\.rs$' | sort -u
}

if [ "${1:-}" = "--print-counts" ]; then
  for f in $(list_files); do
    n="$(count_file "$f")"
    [ "$n" -gt 0 ] && printf '%s %s\n' "$f" "$n"
  done
  exit 0
fi

fail=0
for f in $(list_files); do
  n="$(count_file "$f")"
  allowed="$(awk -v f="$f" '$1 == f { print $2 }' "$baseline")"
  allowed="${allowed:-0}"
  if [ "$n" -gt "$allowed" ]; then
    echo "✗ $f: $n raw-string DID parameter(s)/field(s), $allowed allowed — use common::Did" >&2
    fail=1
  elif [ "$n" -lt "$allowed" ]; then
    echo "✗ $f: down to $n raw-string DID(s) from $allowed — lower its line in $baseline" >&2
    fail=1
  fi
done

while read -r f _; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || { echo "✗ $baseline lists $f, which no longer exists — remove the line" >&2; fail=1; }
done < "$baseline"

[ "$fail" -eq 0 ] || exit 1
echo "✓ no new raw-string DID parameters in crates/pds/src/{auth,routes}"
