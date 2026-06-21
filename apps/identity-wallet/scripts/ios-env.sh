#!/usr/bin/env bash
# ios-env.sh — derive the Apple toolchain for cross-compiling identity-wallet's
# Rust code to iOS, with ZERO hardcoded paths.
#
# Sourced by:
#   1. devenv.nix `enterShell` (CLI `cargo tauri ios dev`/`build`), and
#   2. the Xcode "Build Rust Code" Run Script phase (patched by ios-postinit.sh in
#      Phase 2) — that phase does NOT inherit the calling shell's environment.
#
# Everything is resolved via `xcrun`/`xcode-select`, so the build follows whatever
# Xcode `xcode-select` points at (survives Xcode moves, updates, beta switches).
#
# This file is SOURCED, never executed: it must not call `exit` and must not enable
# `set -e` (that would leak into the caller). Safe to source repeatedly.

# If Apple tools are missing (e.g. a non-mac shell), do nothing — never break the
# caller's shell just because it was sourced somewhere without Xcode.
if ! command -v xcrun >/dev/null 2>&1 || ! command -v xcode-select >/dev/null 2>&1; then
  return 0 2>/dev/null || true
fi

# Active Xcode developer dir (Nix's Darwin hooks otherwise point this at a stub SDK).
# Use /usr/bin/xcode-select explicitly to bypass any Nix shim in PATH.
_ezpds_dev_dir="$(/usr/bin/xcode-select -p 2>/dev/null || true)"
if [ -n "${_ezpds_dev_dir}" ]; then
  export DEVELOPER_DIR="${_ezpds_dev_dir}"
fi

# Unwrapped Apple clang/ar — bypasses the Nix cc-wrapper, which injects
# -mmacos-version-min and the wrong sysroot for iOS targets.
# xcrun will now read the corrected DEVELOPER_DIR above.
_ezpds_clang="$(xcrun -f clang 2>/dev/null || true)"
_ezpds_ar="$(xcrun -f ar 2>/dev/null || true)"

if [ -n "${_ezpds_clang}" ]; then
  # iOS TARGET overrides — always safe to export: no server crate targets iOS, so
  # these never affect a relay / `cargo build --workspace` host build.
  export CC_aarch64_apple_ios_sim="${_ezpds_clang}"
  export CC_aarch64_apple_ios="${_ezpds_clang}"
  export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER="${_ezpds_clang}"
  export CARGO_TARGET_AARCH64_APPLE_IOS_LINKER="${_ezpds_clang}"
fi
if [ -n "${_ezpds_ar}" ]; then
  export AR_aarch64_apple_ios_sim="${_ezpds_ar}"
  export AR_aarch64_apple_ios="${_ezpds_ar}"
fi

# HOST (aarch64-apple-darwin) overrides are needed ONLY while cross-building the iOS
# app — its host-side proc-macros and security-framework C build otherwise hit the Nix
# cc-wrapper (-mmacos-version-min) and the Nix apple-sdk stub (missing /usr/lib stubs
# like libiconv.tbd). They are GATED on EZPDS_IOS_BUILD so ordinary in-shell builds
# (`cargo build --workspace`, `cargo run -p relay`) keep using the Nix toolchain exactly
# as before — this is what makes AC2 (server build intact) true BY CONSTRUCTION. The iOS
# build entry points set EZPDS_IOS_BUILD=1: the `just ios-dev`/`ios-build` recipes and
# the injected Xcode "Build Rust Code" Run Script block (both in Phase 2).
if [ -n "${EZPDS_IOS_BUILD:-}" ]; then
  if [ -n "${_ezpds_clang}" ]; then
    export CC_aarch64_apple_darwin="${_ezpds_clang}"
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="${_ezpds_clang}"
  fi
  if [ -n "${_ezpds_ar}" ]; then
    export AR_aarch64_apple_darwin="${_ezpds_ar}"
  fi
  _ezpds_macos_sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
  if [ -n "${_ezpds_macos_sdk}" ]; then
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-L ${_ezpds_macos_sdk}/usr/lib"
  fi
fi

unset _ezpds_dev_dir _ezpds_clang _ezpds_ar _ezpds_macos_sdk
