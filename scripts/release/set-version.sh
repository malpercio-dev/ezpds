#!/usr/bin/env bash
# set-version.sh — bump the workspace version, roll changelog fragments, and resync Cargo.lock.
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

release_date="${CHANGELOG_DATE:-$(date +%F)}"
if ! printf '%s' "$release_date" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
  echo "✗ CHANGELOG_DATE must be YYYY-MM-DD (got '$release_date')" >&2
  exit 1
fi

fragment_dir="changelog.d"
changelog="CHANGELOG.md"
fragment_re='^[a-z0-9][a-z0-9-]*\.(added|changed|fixed|removed|security)\.md$'
fragments=()
while IFS= read -r fragment; do
  name="${fragment##*/}"
  if ! [[ "$name" =~ $fragment_re ]]; then
    echo "✗ invalid changelog fragment '$fragment' — run 'just changelog-check' for details" >&2
    exit 1
  fi
  if ! grep -q '[^[:space:]]' "$fragment"; then
    echo "✗ changelog fragment '$fragment' is empty" >&2
    exit 1
  fi
  fragments+=("$fragment")
done < <(find "$fragment_dir" -maxdepth 1 -type f -name '*.md' ! -name README.md | sort)

if [ "${#fragments[@]}" -eq 0 ]; then
  echo "✗ no changelog fragments to roll up from $fragment_dir/" >&2
  exit 1
fi
if grep -q "^## \[$version\]" "$changelog"; then
  echo "✗ CHANGELOG.md already contains a release section for $version" >&2
  exit 1
fi

section_file="$(mktemp)"
changelog_tmp="$(mktemp)"
trap 'rm -f "$section_file" "$changelog_tmp" Cargo.toml.tmp' EXIT
printf '## [%s] - %s\n' "$version" "$release_date" > "$section_file"
for type in added changed fixed removed security; do
  case "$type" in
    added) heading="Added" ;;
    changed) heading="Changed" ;;
    fixed) heading="Fixed" ;;
    removed) heading="Removed" ;;
    security) heading="Security" ;;
  esac
  type_count=0
  for fragment in "${fragments[@]}"; do
    [[ "$fragment" == *."$type".md ]] || continue
    if [ "$type_count" -eq 0 ]; then
      printf '\n### %s\n\n' "$heading" >> "$section_file"
    fi
    sed '1s/^/- /; 2,$s/^/  /' "$fragment" >> "$section_file"
    printf '\n' >> "$section_file"
    type_count=$((type_count + 1))
  done
done
printf '\n' >> "$section_file"

# Insert the new release before the first historical release heading. CHANGELOG.md has no
# Unreleased block, so this is the only shared section touched during a release roll-up.
awk -v section="$section_file" '
  !inserted && /^## \[/ {
    while ((getline line < section) > 0) print line
    close(section)
    inserted=1
  }
  {print}
  END {
    if (!inserted) {
      print "✗ CHANGELOG.md has no existing release heading" > "/dev/stderr"
      exit 1
    }
  }
' "$changelog" > "$changelog_tmp"
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
mv "$changelog_tmp" "$changelog"
rm "${fragments[@]}"
echo "✓ workspace version set to $version and ${#fragments[@]} changelog fragment(s) rolled up —"
echo "  commit Cargo.toml + Cargo.lock + CHANGELOG.md + changelog.d/, open a PR,"
echo "  then run 'just release' from main once it's merged."
