#!/usr/bin/env bash
# ios-check.sh — fail (non-zero) if the gitignored Xcode project is missing any of
# the patches ios-postinit.sh applies. Run before an iOS build, or in CI later.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${APP_DIR}/../.." && pwd)"

PBXPROJ="$(ls "${APP_DIR}"/src-tauri/gen/apple/*.xcodeproj/project.pbxproj 2>/dev/null | head -n1 || true)"
if [ -z "${PBXPROJ}" ]; then
  echo "ios-check: FAIL — no project.pbxproj (run 'cargo tauri ios init' then 'just ios-postinit')" >&2
  exit 1
fi

fail=0

if ! grep -q 'swift-rs-patch' "${REPO_ROOT}/Cargo.toml"; then
  echo "ios-check: FAIL — swift-rs [patch.crates-io] override missing from Cargo.toml" >&2
  fail=1
fi

if grep -q 'ENABLE_USER_SCRIPT_SANDBOXING = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — ENABLE_USER_SCRIPT_SANDBOXING still YES (run 'just ios-postinit')" >&2
  fail=1
fi

if ! grep -q '# >>> ezpds-ios-env >>>' "${PBXPROJ}"; then
  echo "ios-check: FAIL — Run Script phase missing ios-env injection (run 'just ios-postinit')" >&2
  fail=1
fi

if grep -q 'CODE_SIGN_ENTITLEMENTS = ' "${PBXPROJ}" && ! grep -q 'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION missing (run 'just ios-postinit')" >&2
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
