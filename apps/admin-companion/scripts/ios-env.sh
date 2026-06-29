#!/usr/bin/env bash
# ios-env.sh — derive the Apple toolchain for cross-compiling admin-companion's
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
if [ ! -x /usr/bin/xcrun ] || [ ! -x /usr/bin/xcode-select ]; then
  return 0 2>/dev/null || true
fi

# Nix's Darwin stdenv exports DEVELOPER_DIR pointing into its apple-sdk STUB (under
# /nix/store). BOTH /usr/bin/xcode-select and /usr/bin/xcrun honor DEVELOPER_DIR ABOVE
# the system Xcode selection, so even called by absolute path they would resolve
# clang/ar/SDK to the Nix clang-wrapper + stub SDK — which lacks the macOS SDK link
# stubs (e.g. libiconv.tbd) and yields `ld: library not found for -liconv` on the
# host-side proc-macro link. Clear it WHEN (and only when) it points into /nix/store, so
# the real Apple toolchain resolves from the persistent `xcode-select` selection. A
# genuine Xcode DEVELOPER_DIR — the one Xcode injects into its Run Script phase, or a
# hand-picked beta Xcode — is NOT under /nix/store, so it is left untouched.
case "${DEVELOPER_DIR:-}" in
  /nix/store/*) unset DEVELOPER_DIR ;;
esac

# Active Xcode developer dir, resolved from the (now un-polluted) system selection.
_ezpds_dev_dir="$(/usr/bin/xcode-select -p 2>/dev/null || true)"
if [ -n "${_ezpds_dev_dir}" ]; then
  export DEVELOPER_DIR="${_ezpds_dev_dir}"
fi

# Unwrapped Apple clang/ar. With DEVELOPER_DIR corrected above and /usr/bin/xcrun called
# by absolute path (bypassing any Nix xcrun shim in PATH), these resolve to the real
# Apple toolchain rather than the Nix clang-wrapper.
_ezpds_clang="$(/usr/bin/xcrun -f clang 2>/dev/null || true)"
_ezpds_ar="$(/usr/bin/xcrun -f ar 2>/dev/null || true)"

if [ -n "${_ezpds_clang}" ]; then
  # iOS TARGET overrides — always safe to export: no server crate targets iOS, so
  # these never affect a pds / `cargo build --workspace` host build.
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
# (`cargo build --workspace`, `cargo run -p pds`) keep using the Nix toolchain exactly
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
  # Same Nix pollution as DEVELOPER_DIR above: a /nix/store SDKROOT would make the macOS
  # SDK below resolve to the Nix stub. Strip it only when it points into /nix/store, and
  # only inside this iOS-build gate so a plain `cargo build` keeps the Nix SDKROOT it
  # expects. A real Xcode SDKROOT (the iOS SDK Xcode sets in its Run Script — needed by
  # the `cargo tauri ios xcode-script --sdk-root ${SDKROOT}` invocation) is not under
  # /nix/store, so it is preserved.
  case "${SDKROOT:-}" in
    /nix/store/*) unset SDKROOT ;;
  esac
  _ezpds_macos_sdk="$(/usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
  if [ -n "${_ezpds_macos_sdk}" ]; then
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-L ${_ezpds_macos_sdk}/usr/lib"
  fi

  # Tauri's iOS signing decodes IOS_CERTIFICATE / IOS_MOBILE_PROVISION by shelling out to
  # `base64` with BSD flags (-i/-o). The Nix coreutils `base64` (GNU) earlier in PATH rejects
  # them ("invalid option -- 'o'"). Shim the system BSD base64 ahead of it — surgical (only
  # `base64`, only under EZPDS_IOS_BUILD), so other Nix tools are untouched. No-op on CI
  # (the runner's base64 is already /usr/bin's).
  if [ -x /usr/bin/base64 ]; then
    _ezpds_shim="${TMPDIR:-/tmp}/ezpds-ios-shims.$(id -u 2>/dev/null || echo 0)"
    # Prepend the shim to PATH only if the directory is trustworthy: a per-uid name, not a
    # symlink, created private (700), and owned by us. A predictable, world-writable shim dir
    # ahead of cargo/Xcode would let another local user hijack the `base64` the signing step
    # runs. The `if` also keeps a failed mkdir/ln from aborting a caller sourcing this under `set -e`.
    if [ ! -L "${_ezpds_shim}" ] \
       && { [ -d "${_ezpds_shim}" ] || mkdir -m 700 "${_ezpds_shim}" 2>/dev/null; } \
       && [ -O "${_ezpds_shim}" ] \
       && ln -sf /usr/bin/base64 "${_ezpds_shim}/base64" 2>/dev/null; then
      case ":${PATH}:" in
        *":${_ezpds_shim}:"*) : ;;
        *) export PATH="${_ezpds_shim}:${PATH}" ;;
      esac
    fi
    unset _ezpds_shim
  fi
fi

unset _ezpds_dev_dir _ezpds_clang _ezpds_ar _ezpds_macos_sdk
