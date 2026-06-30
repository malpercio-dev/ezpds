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

if ! awk '
  /^\[patch\.crates-io\]/ { in_patch = 1; next }
  /^\[/ { in_patch = 0 }
  in_patch && /^[[:space:]]*swift-rs[[:space:]]*=[[:space:]]*\{[^}]*path[[:space:]]*=[[:space:]]*"apps\/identity-wallet\/swift-rs-patch"/ { found = 1 }
  END { exit(found ? 0 : 1) }
' "${REPO_ROOT}/Cargo.toml"; then
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

# Both Apple frameworks must be linked on ONE shared OTHER_LDFLAGS line (Patch E):
#   - SystemConfiguration: hickory-resolver + reqwest (`system-configuration` crate; `_SC*`).
#   - AuthenticationServices: vendored tauri-plugin-auth-session (ASWebAuthenticationSession;
#     `_ASWebAuthenticationSessionErrorDomain`).
# A bare-string grep is insufficient: a split or duplicated OTHER_LDFLAGS (two assignments for
# the same build config) would still contain both names while the later one SHADOWS the earlier,
# silently dropping a framework — the exact failure Patch E exists to prevent. So validate the
# EFFECTIVE state: at least one OTHER_LDFLAGS line links both (in the canonical order Patch E
# writes), and NO OTHER_LDFLAGS line links only one of them. (`|| true`: grep -c exits 1 on zero
# matches, which would trip `set -e`.)
ldflags_both=$(grep -cE 'OTHER_LDFLAGS = .*-framework SystemConfiguration -framework AuthenticationServices' "${PBXPROJ}" || true)
ldflags_sc=$(grep -cE 'OTHER_LDFLAGS = .*-framework SystemConfiguration' "${PBXPROJ}" || true)
ldflags_as=$(grep -cE 'OTHER_LDFLAGS = .*-framework AuthenticationServices' "${PBXPROJ}" || true)
if [ "${ldflags_both}" -lt 1 ]; then
  echo "ios-check: FAIL — no OTHER_LDFLAGS line links both SystemConfiguration + AuthenticationServices (run 'just ios-postinit')" >&2
  fail=1
elif [ "${ldflags_both}" -ne "${ldflags_sc}" ] || [ "${ldflags_both}" -ne "${ldflags_as}" ]; then
  echo "ios-check: FAIL — a partial/split OTHER_LDFLAGS links only one framework; the other is shadowed (run 'just ios-postinit')" >&2
  fail=1
fi

# The Rust staticlib must NOT be copied into the bundle — App Store upload rejects a
# standalone `libapp.a` ("Invalid bundle structure"). Patch F excludes it at both layers:
# project.yml (Externals -> buildPhase: none) and the live pbxproj (no `in Resources`).
if grep -q 'libapp\.a in Resources' "${PBXPROJ}"; then
  echo "ios-check: FAIL — libapp.a still in Copy Bundle Resources, pbxproj (run 'just ios-postinit')" >&2
  fail=1
fi
PROJYML="$(dirname "${PBXPROJ}")/../project.yml"
if [ -f "${PROJYML}" ] && grep -qE '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" \
   && ! grep -A1 -E '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" | grep -q 'buildPhase: none'; then
  echo "ios-check: FAIL — project.yml Externals lacks 'buildPhase: none'; libapp.a would be re-bundled (run 'just ios-postinit')" >&2
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
