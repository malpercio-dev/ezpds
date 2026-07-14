#!/usr/bin/env bash
# lib.sh — helpers shared by the iOS toolchain scripts. Sourced, never executed
# directly (no `set -e`/`main` here — the callers own their shell options).
#
# sha256_file <path> — print the lowercase hex SHA-256 of a file. Used to stamp
# and later verify the AppIcon marker: ios-postinit.sh WRITES the hash and
# ios-check.sh RE-DERIVES it, so the two must hash identically. A copy in each
# script could drift (different flags, different tool) and make postinit and check
# silently disagree — the exact failure these scripts exist to prevent — so the
# definition lives here once.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; fi
}
