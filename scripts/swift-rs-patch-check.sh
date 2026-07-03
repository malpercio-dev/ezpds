#!/usr/bin/env bash
# Verify the swift-rs --disable-sandbox fork is (a) DECLARED and (b) ACTUALLY APPLIED.
#
# The fork (apps/identity-wallet/swift-rs-patch, adds --disable-sandbox to `swift build`
# for the macOS 26 sandbox_apply EPERM bug) is wired via [patch.crates-io] in the root
# Cargo.toml. Cargo only applies a [patch] while the resolved version stays semver-
# compatible with the fork's own version — if a future tauri/cargo-mobile2 bump requires
# a newer swift-rs major/minor, cargo prints a "patch not used" warning, resolves the
# crate FROM THE REGISTRY, and the sandbox fix silently vanishes (the build then fails
# with EPERM on macOS 26, far from the cause). Checking the declaration line alone
# cannot catch that, so this script also asserts the applied state in Cargo.lock:
# a path-patched package has NO `source = "registry+…"` line; an unpatched registry
# resolution does. Runs anywhere cargo resolves the workspace (Linux CI included) —
# it reads Cargo.toml/Cargo.lock, never the Apple toolchain.
set -euo pipefail

cd "$(dirname "$0")/.."

# (a) The [patch.crates-io] declaration exists in the root manifest.
if ! awk '
  /^\[patch\.crates-io\]/ { in_patch = 1; next }
  /^\[/ { in_patch = 0 }
  in_patch && /^[[:space:]]*swift-rs[[:space:]]*=[[:space:]]*\{[^}]*path[[:space:]]*=[[:space:]]*"apps\/identity-wallet\/swift-rs-patch"/ { found = 1 }
  END { exit(found ? 0 : 1) }
' Cargo.toml; then
  echo "✗ swift-rs-patch-check: [patch.crates-io] swift-rs = { path = \"apps/identity-wallet/swift-rs-patch\" }" >&2
  echo "  is missing from Cargo.toml — the macOS 26 swift-build sandbox workaround is not wired." >&2
  exit 1
fi

# (b) The patch was applied at resolution: every swift-rs package entry in Cargo.lock
# must be source-less (a path dep). Extract each [[package]] block named swift-rs and
# look for a source line inside it.
lock_state="$(awk '
  /^\[\[package\]\]/ { in_pkg = 0 }
  /^name = "swift-rs"$/ { in_pkg = 1; count++ }
  in_pkg && /^source = / { registry++ }
  END { printf "%d %d", count + 0, registry + 0 }
' Cargo.lock)"
count="${lock_state% *}"
registry="${lock_state#* }"

if [ "$count" -eq 0 ]; then
  echo "✗ swift-rs-patch-check: no swift-rs package in Cargo.lock — did the dependency tree change?" >&2
  echo "  If swift-rs is genuinely gone, remove the [patch.crates-io] entry and this check together." >&2
  exit 1
fi
if [ "$registry" -ne 0 ]; then
  echo "✗ swift-rs-patch-check: Cargo.lock resolves swift-rs from the registry — the" >&2
  echo "  [patch.crates-io] fork is DECLARED but NOT APPLIED (cargo only applies a patch" >&2
  echo "  while the required version stays semver-compatible with the fork's 1.0.x)." >&2
  echo "  Rebase apps/identity-wallet/swift-rs-patch onto the newly required swift-rs" >&2
  echo "  version, or drop the patch if upstream shipped the --disable-sandbox fix." >&2
  exit 1
fi

echo "✓ swift-rs-patch-check: fork declared in Cargo.toml and applied in Cargo.lock (${count} path entry)"
