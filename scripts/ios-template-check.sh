#!/usr/bin/env bash
# ios-template-check.sh — keep the forked XcodeGen template in lockstep with the
# pinned tauri-cli. Linux-runnable; part of `just ci` / `just ci-pds`.
#
# scripts/ios/project.yml is a fork of tauri-cli's built-in iOS project template
# (rendered into gen/apple/project.yml on every `cargo tauri ios init` via
# `bundle > iOS > template`). Replacing upstream's template wholesale means upstream
# changes to it — new build settings, search-path fixes — no longer reach us
# automatically. This gate closes that hole at the only moment drift can enter:
# when someone bumps the tauri-cli pin in the workflows without re-merging the
# upstream template, the versions disagree and CI fails with instructions.
#
# It also asserts the structural invariants the macOS-side ios-check verifies in
# the *generated* project — here checked in the *source* template, so a Linux PR
# that breaks the template fails before it ever reaches the macOS lanes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE="${REPO_ROOT}/scripts/ios/project.yml"
PRISTINE="${REPO_ROOT}/scripts/ios/upstream-project.yml"

fail=0

if [ ! -f "${TEMPLATE}" ]; then
  echo "ios-template-check: FAIL — ${TEMPLATE} missing" >&2
  exit 1
fi
if [ ! -f "${PRISTINE}" ]; then
  echo "ios-template-check: FAIL — ${PRISTINE} missing (the pristine upstream copy used to diff the fork)" >&2
  fail=1
fi

# --- Version lockstep: template stamp == every workflow's tauri-cli pin ---
stamped="$(sed -n 's/^# upstream-version: tauri-cli \([0-9][0-9.]*\)$/\1/p' "${TEMPLATE}")"
if [ -z "${stamped}" ]; then
  echo "ios-template-check: FAIL — no '# upstream-version: tauri-cli X.Y.Z' line in ${TEMPLATE}" >&2
  fail=1
else
  pins_found=0
  for wf in "${REPO_ROOT}"/.github/workflows/*.yml; do
    pin="$(sed -n "s/.*cargo binstall -y --locked tauri-cli --version '\([0-9][0-9.]*\)'.*/\1/p" "${wf}")"
    [ -z "${pin}" ] && continue
    pins_found=$((pins_found + 1))
    if [ "${pin}" != "${stamped}" ]; then
      echo "ios-template-check: FAIL — $(basename "${wf}") pins tauri-cli ${pin}, but scripts/ios/project.yml is forked from ${stamped}." >&2
      echo "  To bump: fetch the new tag's crates/tauri-cli/templates/mobile/ios/project.yml into" >&2
      echo "  scripts/ios/upstream-project.yml, re-merge upstream's changes into scripts/ios/project.yml" >&2
      echo "  (the ezpds changes are marked with 'ezpds:' comments), and update its upstream-version line." >&2
      fail=1
    fi
  done
  if [ "${pins_found}" -eq 0 ]; then
    echo "ios-template-check: FAIL — no tauri-cli binstall pin found in .github/workflows/*.yml (did the pin format change? update this script's sed)" >&2
    fail=1
  fi
fi

# --- Structural invariants of the fork (source-side mirror of ios-check.sh) ---
require() {
  local pattern="$1" why="$2"
  # -F: the "patterns" are literal template text full of regex metacharacters
  # ($(inherited), {{#each ...}}) — fixed-string matching keeps a future edit
  # from accidentally forming a valid regex with different semantics.
  if ! grep -qF -- "${pattern}" "${TEMPLATE}"; then
    echo "ios-template-check: FAIL — template lost '${pattern}' (${why})" >&2
    fail=1
  fi
}
require 'ezpds-ios-template' "the sentinel ios-check greps in the rendered project.yml"
require 'ENABLE_USER_SCRIPT_SANDBOXING: "NO"' "macOS 26 Run Script sandbox blocks Cargo (Bug 2)"
require 'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION: "YES"' "spurious entitlements-modified failure (Bug 3)"
require 'OTHER_LDFLAGS: $(inherited){{#each ios-frameworks}} -framework {{this}}{{/each}}' "staticlib framework linking from bundle > iOS > frameworks"
require '# >>> ezpds-ios-env >>>' "dev-env preamble in the Build Rust Code phase"
if ! grep -A1 -E '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${TEMPLATE}" | grep -q 'buildPhase: none'; then
  echo "ios-template-check: FAIL — template's Externals source lost 'buildPhase: none' (libapp.a would be bundled; tauri#13578)" >&2
  fail=1
fi

# --- Both apps must actually point at the template ---
for app in identity-wallet admin-companion; do
  conf="${REPO_ROOT}/apps/${app}/src-tauri/tauri.conf.json"
  if ! grep -q '"template": "../../scripts/ios/project.yml"' "${conf}"; then
    echo "ios-template-check: FAIL — ${conf} does not set bundle > iOS > template to ../../scripts/ios/project.yml" >&2
    fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  exit 1
fi
echo "ios-template-check: OK — template in lockstep with tauri-cli ${stamped}"
