#!/usr/bin/env bash
# ios-postinit.sh — finish setting up the gitignored Xcode project that
# `cargo tauri ios init` regenerates. Run after EVERY `cargo tauri ios init`.
# Idempotent.
#
# Most of the historical patch work here is GONE: the Xcode-project workarounds
# (script sandbox off, entitlements-modification allowance, framework linking,
# libapp.a bundle exclusion, dev-env injection into the Build Rust Code phase)
# now live declaratively in the committed XcodeGen template scripts/ios/project.yml,
# which `cargo tauri ios init` renders into gen/apple/project.yml on every init via
# `bundle > iOS > template` in each app's tauri.conf.json. What remains here is the
# work a template cannot express:
#   - Patch A: verify the swift-rs --disable-sandbox fork is declared AND applied
#   - Patch G: regenerate the AppIcon asset catalog from the checked-in brand icon
# followed by the full drift check (ios-check.sh), so "init + postinit" still fails
# loudly if the template was not applied (e.g. the `template` key was dropped from
# tauri.conf.json, or tauri-cli changed behavior).
#
# SINGLE shared implementation for both app lanes; each app keeps a thin wrapper at
# apps/<app>/scripts/ios-postinit.sh that pins its app dir and recipe prefix. See
# apps/identity-wallet/AGENTS.md and docs/ios-upstream-bugs.md for why each
# workaround exists.
#
# Usage: ios-postinit.sh <app-dir> <recipe-prefix>
#   app-dir        absolute path to apps/<app>
#   recipe-prefix  the just-recipe family for error hints (ios | admin)
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $(basename "$0") <app-dir> <recipe-prefix>" >&2
  exit 2
fi
APP_DIR="$(cd "$1" && pwd)"
RECIPE="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PBXPROJ="$(ls "${APP_DIR}"/src-tauri/gen/apple/*.xcodeproj/project.pbxproj 2>/dev/null | head -n1 || true)"
if [ -z "${PBXPROJ}" ]; then
  echo "error: no project.pbxproj under ${APP_DIR}/src-tauri/gen/apple/. Run 'cargo tauri ios init' first." >&2
  exit 1
fi

# --- Patch A: swift-rs --disable-sandbox fork must be declared AND applied ---
# (macOS 26 sandbox_apply EPERM). Delegates to the shared checker, which also asserts
# the applied state in Cargo.lock — a declared-but-unapplied patch (semver drift after
# a tauri bump) would otherwise fail much later, deep inside the Xcode build.
if ! "${REPO_ROOT}/scripts/swift-rs-patch-check.sh"; then
  echo "error: the swift-rs sandbox workaround is not active (see above)." >&2
  exit 1
fi

# The custom template must actually have been rendered. A gen/apple produced before
# the template era (or with the `template` key missing from tauri.conf.json) carries
# the stock project.yml — re-running `cargo tauri ios init` rewrites it from
# scripts/ios/project.yml unconditionally.
PROJYML="$(dirname "${PBXPROJ}")/../project.yml"
if [ ! -f "${PROJYML}" ] || ! grep -q 'ezpds-ios-template' "${PROJYML}"; then
  echo "error: ${PROJYML} was not rendered from scripts/ios/project.yml." >&2
  echo "       Check that tauri.conf.json still sets bundle > iOS > template, then" >&2
  echo "       re-run 'cargo tauri ios init' (from ${APP_DIR}) and 'just ${RECIPE}-postinit'." >&2
  exit 1
fi

# --- Patch G: populate the AppIcon asset catalog from the checked-in brand icon ---
# `cargo tauri ios init` regenerates gen/apple with Tauri's default placeholder icons.
# When the app ships a brand icon (apps/<app>/app-icon.png, 1024x1024 — its SVG source
# of truth sits next to it), regenerate the full icon set. `-o src-tauri/icons-build`
# (gitignored) keeps the desktop/android outputs out of the tracked tree; tauri-cli
# still writes the iOS set into gen/apple/Assets.xcassets/AppIcon.appiconset because
# it derives that path from the output dir's PARENT (src-tauri/) and only falls back
# to the -o dir when the catalog is missing. --ios-color flattens any transparency
# onto Console Slate rather than tauri's white default. The sha256 marker written at
# the end is what ios-check verifies (catalog contents can't be byte-compared to the
# source, since every size is a resample).
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; fi
}
APP_ICON="${APP_DIR}/app-icon.png"
APPICONSET="$(dirname "${PBXPROJ}")/../Assets.xcassets/AppIcon.appiconset"
if [ ! -f "${APP_ICON}" ]; then
  echo "ios-postinit: no app-icon.png in ${APP_DIR}; keeping template icons"
else
  if [ ! -d "${APPICONSET}" ]; then
    echo "error: ${APPICONSET} not found — cannot install the app icon (Patch G)." >&2
    echo "       Tauri's generated template may have moved the asset catalog;" >&2
    echo "       adjust APPICONSET in $(basename "$0")." >&2
    exit 1
  fi
  if ! cargo tauri icon --help >/dev/null 2>&1; then
    echo "error: 'cargo tauri' unavailable — cannot regenerate the app icon (Patch G)." >&2
    echo "       Enter the dev shell (nix develop) or install tauri-cli." >&2
    exit 1
  fi
  (cd "${APP_DIR}" && cargo tauri icon app-icon.png -o src-tauri/icons-build --ios-color '#0e1217')
  if [ ! -f "${APPICONSET}/AppIcon-512@2x.png" ]; then
    echo "error: 'cargo tauri icon' did not write the 1024px marketing icon into" >&2
    echo "       ${APPICONSET} (Patch G). tauri-cli's icon output layout may have" >&2
    echo "       changed; adjust Patch G in $(basename "$0")." >&2
    exit 1
  fi
  sha256_file "${APP_ICON}" > "${APPICONSET}/.ezpds-app-icon.sha256"
  echo "ios-postinit: regenerated AppIcon.appiconset from app-icon.png"
fi

# Full verification — everything the template should have put into the generated
# project, plus the checks above. This is what makes the CI "init + postinit" step
# fail loudly when the template and the generated project drift apart.
exec "${SCRIPT_DIR}/ios-check.sh" "${APP_DIR}" "${RECIPE}"
