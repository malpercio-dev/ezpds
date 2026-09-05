#!/usr/bin/env bash
# Freeze the workspace-dependency table as the single source of shared versions.
#
# AGENTS.md: "Workspace-level dependency versions in root Cargo.toml; crates use
# { workspace = true }." A member manifest that pins its own version/features for a
# crate other members also use is exactly the copy-a-sibling drift AGENTS.md's
# "Extend the shared helper; never copy a sibling" rule targets — it silently
# reintroduces the two-copies-of-the-same-thing bug the workspace table exists to
# prevent (a duplicate-major dependency, or a version that quietly drifts crate to
# crate). This guard fails on any [dependencies]/[dev-dependencies]/
# [build-dependencies]/[target.'...'.dependencies] entry in a member manifest that
# is neither `workspace = true` nor a `path =` dependency (vendored/local crates are
# exempt — they have no workspace-table entry to share).
#
# Portable bash + awk only (Linux ci-pds + macOS ci + Nix shell); no TOML parser.
# Assumes single-line dependency entries (true of every manifest in this repo as of
# writing) — a multi-line inline table would not be scanned correctly.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

for manifest in crates/*/Cargo.toml apps/*/src-tauri/Cargo.toml; do
  offenders="$(awk '
    /^\[/ {
      insec = ($0 == "[dependencies]" || $0 == "[dev-dependencies]" || $0 == "[build-dependencies]")
      if ($0 ~ /^\[target\..*\.dependencies\]$/) insec = 1
      next
    }
    insec && /^[A-Za-z0-9_-]+[[:space:]]*=/ {
      if ($0 !~ /workspace[[:space:]]*=[[:space:]]*true/ && $0 !~ /path[[:space:]]*=/) {
        print NR": "$0
      }
    }
  ' "$manifest")"

  if [ -n "$offenders" ]; then
    echo "✗ $manifest bypasses the workspace dependency table:" >&2
    printf '%s\n' "$offenders" | sed 's/^/    /' >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "  Move the version/features into [workspace.dependencies] in root Cargo.toml and switch" >&2
  echo "  the member to { workspace = true } (+ features/optional locally if needed)." >&2
  exit 1
fi

echo "✓ every member dependency is workspace = true or a path dependency"
