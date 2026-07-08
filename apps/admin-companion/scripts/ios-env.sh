#!/usr/bin/env bash
# Thin wrapper — the shared implementation lives in scripts/ios/ios-env.sh (single
# source of truth for both app lanes). This per-app path is kept because the just
# recipes and the Xcode "Build Rust Code" Run Script (rendered from the
# scripts/ios/project.yml template) source
# apps/admin-companion/scripts/ios-env.sh.
#
# SOURCED, never executed (same contract as the shared script: no `exit`, no `set -e`).
# All sourcing contexts are bash (devenv enterShell, just's sh on macOS, Xcode's
# Run Script shell), so BASH_SOURCE is available; $0 is a best-effort fallback.
. "$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/../../../scripts/ios/ios-env.sh"
