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
  # The tauri-cli pin now lives in the shared runner-preamble composite action
  # (.github/actions/ios-setup/action.yml) — one home for all iOS lanes. Scan it
  # alongside the workflow files so a pin lingering in either location is still caught.
  for wf in "${REPO_ROOT}"/.github/workflows/*.yml "${REPO_ROOT}"/.github/actions/ios-setup/action.yml; do
    [ -f "${wf}" ] || continue
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
    echo "ios-template-check: FAIL — no tauri-cli binstall pin found in .github/workflows/*.yml or .github/actions/ios-setup/action.yml (did the pin format or location change? update this script's sed)" >&2
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
require '- path: ../../../AppIcon.icon' "the layered Icon Composer document (iOS 26 Liquid Glass icon), referenced in place"
# The fileTypes mapping must keep .icon packages single-file (XcodeGen#1556 —
# without it the package is exploded into loose resources Xcode won't use).
if ! grep -A2 -E '^[[:space:]]*fileTypes:' "${TEMPLATE}" | grep -q 'icon:'; then
  echo "ios-template-check: FAIL — template lost the fileTypes .icon=file mapping (XcodeGen would explode the AppIcon.icon package; XcodeGen#1556)" >&2
  fail=1
fi
# Both apps must actually ship the document the template references for every app.
for app in identity-wallet admin-companion; do
  if [ ! -f "${REPO_ROOT}/apps/${app}/AppIcon.icon/icon.json" ]; then
    echo "ios-template-check: FAIL — apps/${app}/AppIcon.icon/icon.json missing (the template references ../../../AppIcon.icon for every app)" >&2
    fail=1
  fi
done

# --- Entitlements: tauri's default path in the template, content via Patch H ---
# The template MUST keep tauri-cli's default entitlements path: tauri's build-time
# codesign reads that exact path regardless of the template, so a repoint leaves it
# fileless and signing dies with "cannot read entitlement data". The tracked per-app
# src-tauri/Entitlements.ios.plist is the source of truth; ios-postinit's Patch H
# copies it into the generated default file (verified by ios-check's sha marker).
require 'path: {{app.name}}_iOS/{{app.name}}_iOS.entitlements' "tauri's default entitlements path (do NOT repoint — breaks build-time codesign)"
for app in identity-wallet admin-companion; do
  if [ ! -f "${REPO_ROOT}/apps/${app}/src-tauri/Entitlements.ios.plist" ]; then
    echo "ios-template-check: FAIL — apps/${app}/src-tauri/Entitlements.ios.plist missing (Patch H installs it into every app's generated project)" >&2
    fail=1
  fi
done
# The wallet's blob backup needs the iCloud ubiquity container; the container id
# must also be declared to the Files app in Info.ios.plist (NSUbiquitousContainers).
WALLET_ENT="${REPO_ROOT}/apps/identity-wallet/src-tauri/Entitlements.ios.plist"
WALLET_CONTAINER='iCloud.dev.malpercio.identitywallet'
if [ -f "${WALLET_ENT}" ]; then
  # The container is matched in its <string> form: the file's explanatory comments quote the
  # bare id, so a plain substring match would be satisfied by prose alone and keep passing after
  # the real entitlement was deleted. `just bundle-identity-check` validates the same contract
  # against the parsed nodes.
  for key in 'com.apple.developer.ubiquity-container-identifiers' 'com.apple.developer.icloud-services' "<string>${WALLET_CONTAINER}</string>"; do
    if ! grep -qF -- "${key}" "${WALLET_ENT}"; then
      echo "ios-template-check: FAIL — wallet Entitlements.ios.plist lost '${key}' (the iCloud Drive blob backup mirror needs it)" >&2
      fail=1
    fi
  done
fi
if ! grep -qF -- "${WALLET_CONTAINER}" "${REPO_ROOT}/apps/identity-wallet/src-tauri/Info.ios.plist"; then
  echo "ios-template-check: FAIL — wallet Info.ios.plist lost the NSUbiquitousContainers entry for ${WALLET_CONTAINER} (the backup mirror would be invisible in the Files app)" >&2
  fail=1
fi
# Least privilege: the operator console must NOT grow iCloud entitlements — only
# the wallet's blob backup is entitled to a ubiquity container. Case-insensitive,
# and 'ubiquity' included: the ubiquity-container key has no "icloud" substring,
# and container values are conventionally capitalized ("iCloud.…").
if grep -qiE 'icloud|ubiquity' "${REPO_ROOT}/apps/admin-companion/src-tauri/Entitlements.ios.plist"; then
  echo "ios-template-check: FAIL — admin-companion Entitlements.ios.plist declares an iCloud entitlement (least privilege: only the wallet's blob backup needs one)" >&2
  fail=1
fi

# --- The Notification Service Extension (ezpds change 5) ---
# The extension is what makes an end-to-end-encrypted push readable: it HPKE-opens the sealed
# payload with the per-device notification key the wallet stores in the shared keychain group. Every
# piece below is load-
# bearing in a way that fails SILENTLY if dropped — a re-rendered template missing the target
# leaves the app installing happily and showing "couldn't verify" for every notification
# forever, with nothing in any log to say the extension was never built.
require 'type: app-extension' "the NSE target (a sealed push renders as the unverified notice without it)"
require 'NSExtensionPointIdentifier: com.apple.usernotifications.service' "the NSE's extension point (iOS would not route pushes to it)"
# Both halves of the principal class, and the line that joins them. Checking only the halves
# would pass a project that named a class iOS cannot find — which presents as a push that never
# arrived, with nothing in any log distinguishing it from one that was never sent.
require 'NSExtensionPrincipalClass: $(PRODUCT_MODULE_NAME).NotificationService' "the NSE's principal class (iOS cannot instantiate the extension without it)"
require 'PRODUCT_MODULE_NAME: NotificationService' "half of NSExtensionPrincipalClass — a drift here means iOS cannot instantiate the extension"
require '- path: ../../../../../ios/NotificationService' "the shared Swift sources, referenced in place"
require 'CODE_SIGN_ENTITLEMENTS: ../../Entitlements.NSE.plist' "the NSE's shared-keychain entitlement (without it every Keychain read finds nothing)"
# The embed dependency, not the target definition, is what puts the extension in the archive.
if ! grep -qF -- '- target: {{app.name}}_NSE' "${TEMPLATE}"; then
  echo "ios-template-check: FAIL — the app target no longer embeds {{app.name}}_NSE; the extension would be built but never shipped" >&2
  fail=1
fi
# The gate is what keeps admin-companion from needing a second App ID + profile + secret for
# an extension it cannot use (see the template's comment). If it is ever removed,
# it must be removed deliberately, alongside the console's shared keychain group.
if ! grep -qF -- '{{#if (eq app.identifier "dev.malpercio.identitywallet")}}' "${TEMPLATE}"; then
  echo "ios-template-check: FAIL — the NSE is no longer gated to the wallet's bundle id; admin-companion would need its own extension App ID and provisioning profile before either TestFlight lane could sign a build" >&2
  fail=1
fi
# The interop test's fixture is referenced in place, so there is no copy to drift from the
# crate that generates it.
require '- path: ../../../../../crates/crypto/tests/fixtures/notify/hpke-notify-v1.json' "the Rust golden HPKE vectors the CryptoKit cross-check opens"
for source in ios/NotificationService/NotificationService.swift \
              ios/NotificationService/NotifyCrypto.swift \
              ios/NotificationService/NotifyEnvelope.swift \
              ios/NotificationService/NotifyKeychain.swift \
              ios/NotificationService/NotifyBreadcrumbs.swift \
              ios/NotificationServiceTests/NotifyFixtureTests.swift \
              ios/NotificationServiceTests/NotifyResolverTests.swift; do
  # No CI lane compiles Swift, so this loop is the ONLY automated signal that one of these
  # files went missing — including the test files, whose absence would otherwise just look
  # like a suite that quietly got smaller.
  if [ ! -f "${REPO_ROOT}/${source}" ]; then
    echo "ios-template-check: FAIL — ${source} missing (the template compiles the whole ios/NotificationService tree)" >&2
    fail=1
  fi
done
# The extension's entitlements are its ONLY reach into the app's Keychain, and the ORDER is
# the mechanism: neither process names an access group in its queries, so iOS files an
# unqualified write into the FIRST entitled group. If org.obsign.shared is not first in BOTH
# files, the breadcrumbs the extension writes land where the app cannot read them.
NSE_ENT="${REPO_ROOT}/apps/identity-wallet/src-tauri/Entitlements.NSE.plist"
if [ ! -f "${NSE_ENT}" ]; then
  echo "ios-template-check: FAIL — ${NSE_ENT} missing (the NSE target's CODE_SIGN_ENTITLEMENTS points at it)" >&2
  fail=1
elif ! command -v python3 >/dev/null 2>&1; then
  echo "ios-template-check: WARN — python3 unavailable; skipping the NSE keychain-group order check" >&2
else
  # Both assertions read the PARSED nodes, never the raw text: this file's explanatory comments
  # name `aps-environment` and iCloud precisely to say why they are absent, so a grep would be
  # satisfied by prose and would fail on a correct file (the same trap the wallet container
  # check above documents).
  nse_verdict="$(python3 - "${NSE_ENT}" <<'PY'
import plistlib, sys

with open(sys.argv[1], "rb") as handle:
    entitlements = plistlib.load(handle)

groups = entitlements.get("keychain-access-groups", [])
if not groups or groups[0] != "$(AppIdentifierPrefix)org.obsign.shared":
    print("order")
# Least privilege: the extension only ever needs the shared keychain group. `aps-environment`
# is an APP entitlement (the app obtains the device token; the extension only decrypts), and a
# stray iCloud grant would widen the reach of the one process that runs on a locked screen.
elif set(entitlements) != {"keychain-access-groups"}:
    print("extra:" + ",".join(sorted(set(entitlements) - {"keychain-access-groups"})))
else:
    print("ok")
PY
)"
  case "${nse_verdict}" in
    ok) ;;
    order)
      echo "ios-template-check: FAIL — the NSE entitlements must list \$(AppIdentifierPrefix)org.obsign.shared FIRST; an unqualified write otherwise lands in a group the app cannot read (ADR-0030)" >&2
      fail=1
      ;;
    extra:*)
      echo "ios-template-check: FAIL — the NSE entitlements declare more than the shared keychain group (${nse_verdict#extra:}); least privilege: the extension obtains no push token and touches no backup" >&2
      fail=1
      ;;
    *)
      echo "ios-template-check: FAIL — could not parse ${NSE_ENT}" >&2
      fail=1
      ;;
  esac
fi

# --- Cross-bundle document versions: Swift and Rust must agree ---
# The app and the extension are separate bundles that share two JSON documents through the
# Keychain — the pinned sender-key set (app writes, extension reads) and the failure log
# (extension writes, app reads). Each carries a version tag, and each side refuses a document
# whose tag it does not recognise.
#
# So the two constants ARE the contract, and nothing at compile time relates them: they live in
# different languages, in different bundles, built by different toolchains. Bumping one alone
# does not fail anything — it makes the other side silently discard every document, which
# presents as notifications that stop being verifiable, or a Settings screen that goes blank
# exactly when it is needed. A Rust test asserting its own constant equals a literal cannot
# catch it either; only comparing the two files can.
if command -v python3 >/dev/null 2>&1; then
  version_verdict="$(python3 - "${REPO_ROOT}" <<'PY'
import pathlib, re, sys

root = pathlib.Path(sys.argv[1])
rust = (root / "apps/identity-wallet/src-tauri/src/notifications.rs").read_text()

# (label, swift file, swift type, rust constant)
contracts = [
    ("failure log", "NotifyBreadcrumbs.swift", "NotifyFailureLog", "FAILURE_LOG_VERSION"),
    ("sender-key pin document", "NotifyKeychain.swift", "PinnedSenderKeys", "PIN_DOCUMENT_VERSION"),
]

problems = []
for label, filename, swift_type, rust_const in contracts:
    source = (root / "ios/NotificationService" / filename).read_text()
    # The declaration sits inside its type, and each of these files declares exactly one.
    swift = re.search(r"struct\s+" + swift_type + r"\b.*?static let supportedVersion\s*=\s*(\d+)",
                      source, re.S)
    rust_match = re.search(r"const\s+" + rust_const + r"\s*:\s*u8\s*=\s*(\d+)\s*;", rust)
    if not swift:
        problems.append(f"{label}: no `supportedVersion` on Swift `{swift_type}` in {filename}")
    elif not rust_match:
        problems.append(f"{label}: no `{rust_const}` in notifications.rs")
    elif swift.group(1) != rust_match.group(1):
        problems.append(
            f"{label}: Swift {swift_type}.supportedVersion = {swift.group(1)} but Rust "
            f"{rust_const} = {rust_match.group(1)} — one side would discard every document "
            f"the other writes")

print("\n".join(problems) if problems else "ok")
PY
)"
  if [ "${version_verdict}" != "ok" ]; then
    echo "ios-template-check: FAIL — the app and the extension disagree on a shared document version:" >&2
    echo "${version_verdict}" | sed 's/^/  /' >&2
    fail=1
  fi
else
  echo "ios-template-check: WARN — python3 unavailable; skipping the Swift/Rust document-version check" >&2
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
