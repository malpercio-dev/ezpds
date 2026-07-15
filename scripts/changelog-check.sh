#!/usr/bin/env bash
# Require a valid changelog fragment when a PR changes a shipped surface.
# CHANGELOG_BASE_REF is set to the PR base SHA in CI; an explicit first argument is
# convenient for local checks. With neither, fragment validity is still checked but
# presence is not required because there is no trustworthy comparison range.
set -euo pipefail

cd "$(dirname "$0")/.."

base_ref="${1:-${CHANGELOG_BASE_REF:-}}"
fragment_dir="changelog.d"
fragment_re='^[a-z0-9][a-z0-9-]*\.(added|changed|fixed|removed|security)\.md$'

fail=0
fragment_count=0
while IFS= read -r fragment; do
  name="${fragment##*/}"
  if ! [[ "$name" =~ $fragment_re ]]; then
    echo "✗ invalid changelog fragment '$fragment' — expected <id>.<added|changed|fixed|removed|security>.md" >&2
    fail=1
    continue
  fi
  if ! grep -q '[^[:space:]]' "$fragment"; then
    echo "✗ changelog fragment '$fragment' is empty" >&2
    fail=1
    continue
  fi
  fragment_count=$((fragment_count + 1))
done < <(find "$fragment_dir" -maxdepth 1 -type f -name '*.md' ! -name README.md | sort)

if [ "$fail" -ne 0 ]; then
  exit 1
fi

if [ -z "$base_ref" ]; then
  echo "✓ $fragment_count valid changelog fragment(s); no base ref supplied, so presence was not evaluated"
  exit 0
fi

if ! git rev-parse --verify "${base_ref}^{commit}" >/dev/null 2>&1; then
  echo "✗ changelog base ref '$base_ref' is not available — fetch the PR base before running this check" >&2
  exit 1
fi

changed_files="$(git diff --name-only "${base_ref}...HEAD")"
shipped_files="$(printf '%s\n' "$changed_files" | awk '
  /^Cargo\.toml$/ || /^Cargo\.lock$/ || /^Dockerfile$/ || /^railway\.toml$/ { print; next }
  /^nix\/module\.nix$/ { print; next }
  /^sites\/marketing\// { print; next }
  /^crates\/[^\/]+\/src\// || /^crates\/pds\/assets\// { print; next }
  /^apps\/[^\/]+\/src\// || /^apps\/[^\/]+\/src-tauri\/src\// { print; next }
  /^apps\/[^\/]+\/static\// || /^apps\/[^\/]+\/tauri\.conf\.json$/ { print; next }
')"

# A release roll-up (`just set-version`) legitimately consumes every fragment while it bumps
# the workspace version and touches Cargo.toml/Cargo.lock — so it changes shipped surfaces
# yet cannot carry a fragment. Recognize that exact shape (the [workspace.package] version
# line changed AND a new dated release heading was added to CHANGELOG.md) and waive the
# presence requirement. Both signals are required, so a plain CHANGELOG.md edit can never
# be used to smuggle a real feature past the gate.
is_release_rollup() {
  git diff "${base_ref}...HEAD" -- Cargo.toml \
    | grep -qE '^\+version = "[0-9]+\.[0-9]+\.[0-9]+"$' || return 1
  git diff "${base_ref}...HEAD" -- CHANGELOG.md \
    | grep -qE '^\+## \[[0-9]+\.[0-9]+\.[0-9]+\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$' || return 1
}

if [ -n "$shipped_files" ] && [ "$fragment_count" -eq 0 ]; then
  if is_release_rollup; then
    echo "✓ release roll-up detected (workspace version bump + new CHANGELOG.md section); fragment presence not required"
    exit 0
  fi
  echo "✗ this change touches shipped surfaces but has no changelog.d/<id>.<type>.md fragment:" >&2
  while IFS= read -r shipped_file; do
    printf '  %s\n' "$shipped_file" >&2
  done <<< "$shipped_files"
  echo "  See changelog.d/README.md for the format and scoped exemptions." >&2
  exit 1
fi

if [ -n "$shipped_files" ]; then
  shipped_count="$(printf '%s\n' "$shipped_files" | wc -l | tr -d ' ')"
  echo "✓ $fragment_count valid changelog fragment(s) cover $shipped_count changed shipped file(s)"
else
  echo "✓ no shipped surfaces changed; $fragment_count valid changelog fragment(s)"
fi
