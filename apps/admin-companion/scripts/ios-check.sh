#!/usr/bin/env bash
# ios-check.sh — fail (non-zero) if the gitignored Xcode project is missing any of
# the patches ios-postinit.sh applies. Run before an iOS build, or in CI later.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${APP_DIR}/../.." && pwd)"

PBXPROJ="$(ls "${APP_DIR}"/src-tauri/gen/apple/*.xcodeproj/project.pbxproj 2>/dev/null | head -n1 || true)"
if [ -z "${PBXPROJ}" ]; then
  echo "ios-check: FAIL — no project.pbxproj (run 'cargo tauri ios init' then 'just admin-postinit')" >&2
  exit 1
fi

fail=0

if ! grep -q 'swift-rs-patch' "${REPO_ROOT}/Cargo.toml"; then
  echo "ios-check: FAIL — swift-rs [patch.crates-io] override missing from Cargo.toml" >&2
  fail=1
fi

if grep -q 'ENABLE_USER_SCRIPT_SANDBOXING = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — ENABLE_USER_SCRIPT_SANDBOXING still YES (run 'just admin-postinit')" >&2
  fail=1
fi

if ! grep -q '# >>> ezpds-ios-env >>>' "${PBXPROJ}"; then
  echo "ios-check: FAIL — Run Script phase missing ios-env injection (run 'just admin-postinit')" >&2
  fail=1
fi

if grep -q 'CODE_SIGN_ENTITLEMENTS = ' "${PBXPROJ}" && ! grep -q 'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION missing (run 'just admin-postinit')" >&2
  fail=1
fi

# SystemConfiguration.framework must be linked: hickory-resolver + reqwest pull in the
# `system-configuration` crate, whose `_SC*` symbols are otherwise undefined at Xcode link time.
if ! grep -q 'SystemConfiguration' "${PBXPROJ}"; then
  echo "ios-check: FAIL — SystemConfiguration.framework not linked (run 'just admin-postinit')" >&2
  fail=1
fi

# The Rust staticlib must NOT be copied into the bundle — App Store upload rejects a
# standalone `libapp.a` ("Invalid bundle structure"). Patch F excludes it at both layers:
# project.yml (Externals -> buildPhase: none) and the live pbxproj (no `in Resources`).
if grep -q 'libapp\.a in Resources' "${PBXPROJ}"; then
  echo "ios-check: FAIL — libapp.a still in Copy Bundle Resources, pbxproj (run 'just admin-postinit')" >&2
  fail=1
fi
PROJYML="$(dirname "${PBXPROJ}")/../project.yml"
if [ -f "${PROJYML}" ] && grep -qE '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" \
   && ! grep -A1 -E '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" | grep -q 'buildPhase: none'; then
  echo "ios-check: FAIL — project.yml Externals lacks 'buildPhase: none'; libapp.a would be re-bundled (run 'just admin-postinit')" >&2
  fail=1
fi

# Structural guard: a sentinel-present-but-corrupt pbxproj must still fail the check.
if command -v plutil >/dev/null 2>&1 && ! plutil -lint "${PBXPROJ}" >/dev/null 2>&1; then
  echo "ios-check: FAIL — project.pbxproj does not parse (plutil -lint); patching may have corrupted it" >&2
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  exit 1
fi
echo "ios-check: OK — all patches present"
