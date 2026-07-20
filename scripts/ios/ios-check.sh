#!/usr/bin/env bash
# ios-check.sh — fail (non-zero) if the gitignored Xcode project is missing any of
# the required workarounds. Run before an iOS build, or in CI.
#
# The workarounds are no longer patched into the generated project by script — they
# come from the committed XcodeGen template scripts/ios/project.yml, rendered by
# `cargo tauri ios init` (via `bundle > iOS > template` in tauri.conf.json). This
# checker verifies the END STATE of the generated project, so it catches every way
# the template can fail to apply: a dropped `template` config key, a tauri-cli
# behavior change, or a stale gen/apple from before the template era. On failure,
# the fix is always: re-run `cargo tauri ios init` (from apps/<app>) then
# `just <recipe>-postinit`.
#
# SINGLE shared implementation for both app lanes; each app keeps a thin wrapper at
# apps/<app>/scripts/ios-check.sh that pins its app dir and recipe prefix. The
# framework list is read from the app's tauri.conf.json (bundle > iOS > frameworks)
# — the same source the template renders OTHER_LDFLAGS from — so there is no second
# copy to drift.
#
# Usage: ios-check.sh <app-dir> <recipe-prefix>
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $(basename "$0") <app-dir> <recipe-prefix>" >&2
  exit 2
fi
APP_DIR="$(cd "$1" && pwd)"
RECIPE="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REINIT_HINT="(re-run 'cargo tauri ios init' from ${APP_DIR}, then 'just ${RECIPE}-postinit')"

# shellcheck source=scripts/ios/lib.sh
. "${SCRIPT_DIR}/lib.sh"

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

# The generated project.yml must come from OUR template (its header carries the
# sentinel comment). A stock project.yml means `bundle > iOS > template` did not
# apply — none of the workarounds below can be trusted to be present.
PROJYML="$(dirname "${PBXPROJ}")/../project.yml"
if [ ! -f "${PROJYML}" ] || ! grep -q 'ezpds-ios-template' "${PROJYML}"; then
  echo "ios-check: FAIL — gen/apple/project.yml not rendered from scripts/ios/project.yml; check bundle > iOS > template in tauri.conf.json ${REINIT_HINT}" >&2
  fail=1
fi

# macOS 26's Run Script sandbox blocks Cargo's readdir (docs/ios-upstream-bugs.md
# Bug 2). The template forces the setting off; require the explicit NO (a missing
# setting would fall back to Xcode's default, which is YES on Xcode 14+).
if ! grep -q 'ENABLE_USER_SCRIPT_SANDBOXING = NO' "${PBXPROJ}" || grep -q 'ENABLE_USER_SCRIPT_SANDBOXING = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — ENABLE_USER_SCRIPT_SANDBOXING is not forced to NO ${REINIT_HINT}" >&2
  fail=1
fi

# The Build Rust Code phase must carry the dev-env preamble from the template —
# Xcode runs it in a clean shell that inherits neither the devenv PATH nor the
# ios-env.sh toolchain overrides.
if ! grep -q '# >>> ezpds-ios-env >>>' "${PBXPROJ}"; then
  echo "ios-check: FAIL — Build Rust Code phase missing the ezpds-ios-env preamble ${REINIT_HINT}" >&2
  fail=1
fi

# Tolerates Xcode's spurious "entitlements modified during build" caused by the
# per-build project restamp (docs/ios-upstream-bugs.md Bug 3).
if ! grep -q 'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION = YES' "${PBXPROJ}"; then
  echo "ios-check: FAIL — CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION missing ${REINIT_HINT}" >&2
  fail=1
fi

# The signed entitlements must come from the TRACKED per-app file (template change
# 5) — a stock path means the app signs with the empty generated entitlements and
# the wallet's iCloud blob-backup container silently disappears from the build.
if ! grep -qE 'CODE_SIGN_ENTITLEMENTS = "?\.\./\.\./Entitlements\.ios\.plist"?;' "${PBXPROJ}"; then
  echo "ios-check: FAIL — CODE_SIGN_ENTITLEMENTS does not point at the tracked src-tauri/Entitlements.ios.plist ${REINIT_HINT}" >&2
  fail=1
fi
if [ ! -f "${APP_DIR}/src-tauri/Entitlements.ios.plist" ]; then
  echo "ios-check: FAIL — ${APP_DIR}/src-tauri/Entitlements.ios.plist missing (the template's entitlements path references it)" >&2
  fail=1
fi

# Every Apple framework the Rust staticlib needs (bundle > iOS > frameworks in
# tauri.conf.json) must be linked on ONE shared OTHER_LDFLAGS line. A bare-string
# grep is insufficient: a split or duplicated OTHER_LDFLAGS (two assignments for
# the same build config) would still contain every name while the later one SHADOWS
# the earlier, silently dropping a framework. So validate the EFFECTIVE state: at
# least one OTHER_LDFLAGS line links all of them (in tauri.conf.json order, which is
# the order the template renders), and NO OTHER_LDFLAGS line links only a subset.
# (`|| true`: grep -c exits 1 on zero matches, which would trip `set -e`.)
CONF="${APP_DIR}/src-tauri/tauri.conf.json"
# python3 ships with Xcode's CLT (dev Macs) and the GitHub macOS runners.
# `read -a` (not mapfile: absent from the bash 3.2 on dev Macs) splits the
# space-separated names without the glob expansion an unquoted $() would risk.
IFS=' ' read -r -a FRAMEWORKS <<< "$(python3 -c "
import json
conf = json.load(open('${CONF}'))
print(' '.join(conf.get('bundle', {}).get('iOS', {}).get('frameworks', [])))
")"
if [ "${#FRAMEWORKS[@]}" -eq 0 ]; then
  echo "ios-check: FAIL — no bundle > iOS > frameworks in ${CONF} (SystemConfiguration is required by the system-configuration crate)" >&2
  fail=1
else
  canon_re="OTHER_LDFLAGS = "
  for fw in "${FRAMEWORKS[@]}"; do
    canon_re="${canon_re}.*-framework ${fw}"
  done
  ldflags_all=$(grep -cE "${canon_re}" "${PBXPROJ}" || true)
  if [ "${ldflags_all}" -lt 1 ]; then
    echo "ios-check: FAIL — no OTHER_LDFLAGS line links all of: ${FRAMEWORKS[*]} ${REINIT_HINT}" >&2
    fail=1
  else
    for fw in "${FRAMEWORKS[@]}"; do
      ldflags_fw=$(grep -cE "OTHER_LDFLAGS = .*-framework ${fw}" "${PBXPROJ}" || true)
      if [ "${ldflags_fw}" -ne "${ldflags_all}" ]; then
        echo "ios-check: FAIL — a partial/split OTHER_LDFLAGS links ${fw} separately; a shadowed assignment drops frameworks ${REINIT_HINT}" >&2
        fail=1
      fi
    done
  fi
fi

# The Rust staticlib must NOT be copied into the bundle — App Store upload rejects a
# standalone `libapp.a` ("Invalid bundle structure", tauri#13578). The template
# excludes it at the source (Externals -> buildPhase: none); verify both layers.
if grep -q 'libapp\.a in Resources' "${PBXPROJ}"; then
  echo "ios-check: FAIL — libapp.a still in Copy Bundle Resources, pbxproj ${REINIT_HINT}" >&2
  fail=1
fi
if [ -f "${PROJYML}" ] && grep -qE '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" \
   && ! grep -A1 -E '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" | grep -q 'buildPhase: none'; then
  echo "ios-check: FAIL — project.yml Externals lacks 'buildPhase: none'; libapp.a would be re-bundled ${REINIT_HINT}" >&2
  fail=1
fi

# Patch G: when the app ships a brand icon (apps/<app>/app-icon.png), the regenerated
# asset catalog must have been built from exactly that file — postinit stamps its
# sha256 into the catalog (resampled PNGs can't be byte-compared to the source).
if [ -f "${APP_DIR}/app-icon.png" ]; then
  # sha256_file: from lib.sh (sourced above) — the same hasher ios-postinit stamps with.
  marker="$(dirname "${PBXPROJ}")/../Assets.xcassets/AppIcon.appiconset/.ezpds-app-icon.sha256"
  if [ ! -f "${marker}" ] || [ "$(cat "${marker}")" != "$(sha256_file "${APP_DIR}/app-icon.png")" ]; then
    echo "ios-check: FAIL — AppIcon.appiconset not regenerated from app-icon.png (run 'just ${RECIPE}-postinit')" >&2
    fail=1
  fi
fi

# The layered Icon Composer document (apps/<app>/AppIcon.icon, the iOS 26 Liquid
# Glass icon) must be registered by the template: referenced in place in project.yml
# (with the fileTypes .icon=file mapping, else XcodeGen explodes the package into
# loose resources — XcodeGen#1556) and linked into the pbxproj Resources phase.
# Two pbxproj occurrences required: the PBXBuildFile definition AND the
# Resources-phase files entry both carry the "AppIcon.icon in Resources" comment —
# a bare -q would be satisfied by the definition alone.
if [ -d "${APP_DIR}/AppIcon.icon" ]; then
  if [ -f "${PROJYML}" ]; then
    if ! grep -A2 -E '^[[:space:]]*fileTypes:' "${PROJYML}" | grep -q 'icon:' \
       || ! grep -qE '^[[:space:]]*-[[:space:]]*path:[[:space:]]*\.\./\.\./\.\./AppIcon\.icon[[:space:]]*$' "${PROJYML}"; then
      echo "ios-check: FAIL — project.yml missing the AppIcon.icon resource or the fileTypes .icon=file mapping ${REINIT_HINT}" >&2
      fail=1
    fi
  fi
  icon_res_count=$(grep -c 'AppIcon\.icon in Resources' "${PBXPROJ}" || true)
  if [ "${icon_res_count}" -lt 2 ]; then
    echo "ios-check: FAIL — pbxproj does not link AppIcon.icon into the Resources phase ${REINIT_HINT}" >&2
    fail=1
  fi
fi

# Structural guard: a sentinel-present-but-corrupt pbxproj must still fail the check.
if command -v plutil >/dev/null 2>&1 && ! plutil -lint "${PBXPROJ}" >/dev/null 2>&1; then
  echo "ios-check: FAIL — project.pbxproj does not parse (plutil -lint)" >&2
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  exit 1
fi
echo "ios-check: OK — template-rendered project carries every workaround"
