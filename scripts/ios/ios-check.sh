#!/usr/bin/env bash
# ios-check.sh — fail (non-zero) if the gitignored Xcode project is missing any of
# the patches ios-postinit.sh applies. Run before an iOS build, or in CI.
#
# SINGLE shared implementation for both app lanes; each app keeps a thin wrapper at
# apps/<app>/scripts/ios-check.sh that pins its app dir, recipe prefix, and Patch E
# framework list (the same wrapper arguments as ios-postinit.sh).
#
# Usage: ios-check.sh <app-dir> <recipe-prefix> <framework>...
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $(basename "$0") <app-dir> <recipe-prefix> <framework>..." >&2
  exit 2
fi
APP_DIR="$(cd "$1" && pwd)"
RECIPE="$2"
shift 2
FRAMEWORKS=("$@")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PBXPROJ="$(ls "${APP_DIR}"/src-tauri/gen/apple/*.xcodeproj/project.pbxproj 2>/dev/null | head -n1 || true)"
if [ -z "${PBXPROJ}" ]; then
  echo "ios-check: FAIL — no project.pbxproj (run 'cargo tauri ios init' then 'just ${RECIPE}-postinit')" >&2
  exit 1
fi

fail=0

# Patch A: the swift-rs fork must be declared in Cargo.toml AND applied in Cargo.lock.
if ! "${REPO_ROOT}/scripts/swift-rs-patch-check.sh"; then
  echo "ios-check: FAIL — swift-rs [patch.crates-io] override missing or not applied (see above)" >&2
  fail=1
fi

if grep -q 'ENABLE_USER_SCRIPT_SANDBOXING = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — ENABLE_USER_SCRIPT_SANDBOXING still YES (run 'just ${RECIPE}-postinit')" >&2
  fail=1
fi

if ! grep -q '# >>> ezpds-ios-env >>>' "${PBXPROJ}"; then
  echo "ios-check: FAIL — Run Script phase missing ios-env injection (run 'just ${RECIPE}-postinit')" >&2
  fail=1
fi

if grep -q 'CODE_SIGN_ENTITLEMENTS = ' "${PBXPROJ}" && ! grep -q 'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION missing (run 'just ${RECIPE}-postinit')" >&2
  fail=1
fi

# Patch E: every required Apple framework must be linked on ONE shared OTHER_LDFLAGS line.
# A bare-string grep is insufficient: a split or duplicated OTHER_LDFLAGS (two assignments
# for the same build config) would still contain every name while the later one SHADOWS the
# earlier, silently dropping a framework — the exact failure Patch E exists to prevent. So
# validate the EFFECTIVE state: at least one OTHER_LDFLAGS line links all of them (in the
# canonical order Patch E writes), and NO OTHER_LDFLAGS line links only a subset. (`|| true`:
# grep -c exits 1 on zero matches, which would trip `set -e`.)
canon_re="OTHER_LDFLAGS = "
for fw in "${FRAMEWORKS[@]}"; do
  canon_re="${canon_re}.*-framework ${fw}"
done
ldflags_all=$(grep -cE "${canon_re}" "${PBXPROJ}" || true)
if [ "${ldflags_all}" -lt 1 ]; then
  echo "ios-check: FAIL — no OTHER_LDFLAGS line links all of: ${FRAMEWORKS[*]} (run 'just ${RECIPE}-postinit')" >&2
  fail=1
else
  for fw in "${FRAMEWORKS[@]}"; do
    ldflags_fw=$(grep -cE "OTHER_LDFLAGS = .*-framework ${fw}" "${PBXPROJ}" || true)
    if [ "${ldflags_fw}" -ne "${ldflags_all}" ]; then
      echo "ios-check: FAIL — a partial/split OTHER_LDFLAGS links ${fw} separately; a shadowed assignment drops frameworks (run 'just ${RECIPE}-postinit')" >&2
      fail=1
    fi
  done
fi

# The Rust staticlib must NOT be copied into the bundle — App Store upload rejects a
# standalone `libapp.a` ("Invalid bundle structure"). Patch F excludes it at both layers:
# project.yml (Externals -> buildPhase: none) and the live pbxproj (no `in Resources`).
if grep -q 'libapp\.a in Resources' "${PBXPROJ}"; then
  echo "ios-check: FAIL — libapp.a still in Copy Bundle Resources, pbxproj (run 'just ${RECIPE}-postinit')" >&2
  fail=1
fi
PROJYML="$(dirname "${PBXPROJ}")/../project.yml"
if [ -f "${PROJYML}" ] && grep -qE '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" \
   && ! grep -A1 -E '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" | grep -q 'buildPhase: none'; then
  echo "ios-check: FAIL — project.yml Externals lacks 'buildPhase: none'; libapp.a would be re-bundled (run 'just ${RECIPE}-postinit')" >&2
  fail=1
fi

# Patch G: when the app ships a brand icon (apps/<app>/app-icon.png), the regenerated
# asset catalog must have been built from exactly that file — postinit stamps its
# sha256 into the catalog (resampled PNGs can't be byte-compared to the source).
if [ -f "${APP_DIR}/app-icon.png" ]; then
  sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; fi
  }
  marker="$(dirname "${PBXPROJ}")/../Assets.xcassets/AppIcon.appiconset/.ezpds-app-icon.sha256"
  if [ ! -f "${marker}" ] || [ "$(cat "${marker}")" != "$(sha256_file "${APP_DIR}/app-icon.png")" ]; then
    echo "ios-check: FAIL — AppIcon.appiconset not regenerated from app-icon.png (run 'just ${RECIPE}-postinit')" >&2
    fail=1
  fi
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
