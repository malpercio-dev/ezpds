#!/usr/bin/env bash
# ios-postinit.sh — re-apply the surviving Tauri/macOS workarounds to the gitignored
# Xcode project that `cargo tauri ios init` regenerates. Run after EVERY
# `cargo tauri ios init`. Idempotent. See apps/identity-wallet/CLAUDE.md and
# docs/ios-upstream-bugs.md for why each patch exists.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"        # apps/identity-wallet
REPO_ROOT="$(cd "${APP_DIR}/../.." && pwd)"      # repo root

PBXPROJ="$(ls "${APP_DIR}"/src-tauri/gen/apple/*.xcodeproj/project.pbxproj 2>/dev/null | head -n1 || true)"
if [ -z "${PBXPROJ}" ]; then
  echo "error: no project.pbxproj under src-tauri/gen/apple/. Run 'cargo tauri ios init' first." >&2
  exit 1
fi
echo "ios-postinit: patching ${PBXPROJ}"

# --- Patch A: swift-rs --disable-sandbox override must be wired (macOS 26 EPERM) ---
if ! grep -q 'swift-rs-patch' "${REPO_ROOT}/Cargo.toml"; then
  echo "error: [patch.crates-io] swift-rs = { path = \"apps/identity-wallet/swift-rs-patch\" } is missing" >&2
  echo "       from ${REPO_ROOT}/Cargo.toml. The swift-rs sandbox workaround is not active." >&2
  exit 1
fi

# --- Patch B: disable Xcode user-script sandbox (macOS 26 blocks cargo's readdir) ---
# Idempotent: YES->NO twice is a no-op.
/usr/bin/sed -i '' 's/ENABLE_USER_SCRIPT_SANDBOXING = YES/ENABLE_USER_SCRIPT_SANDBOXING = NO/g' "${PBXPROJ}"

# --- Patch C: inject PATH + `source ios-env.sh` into the "Build Rust Code" phase ---
# That Run Script runs `cargo tauri ios xcode-script` in a clean shell that inherits
# neither the devenv PATH nor our env vars. Inject both at the top of its shellScript.
# Guarded by a sentinel so re-runs are no-ops.
SENTINEL='# >>> ezpds-ios-env >>>'
if grep -q "${SENTINEL}" "${PBXPROJ}"; then
  echo "ios-postinit: Run Script already patched (sentinel present)"
else
  CARGO_BIN="${CARGO_HOME:-$HOME/.cargo}/bin"
  DEVENV_BIN="${REPO_ROOT}/.devenv/profile/bin"
  ENVSH="${APP_DIR}/scripts/ios-env.sh"
  export CARGO_BIN DEVENV_BIN ENVSH SENTINEL
  # The injected lines are QUOTE-FREE on purpose: in pbxproj the shellScript is itself a
  # double-quoted string, so a literal " would terminate it early and corrupt the file.
  # The paths here contain no spaces (repo root + CARGO_HOME under $HOME). `\$PATH` stays
  # literal (the shell expands it at build time); `.` is the POSIX form of `source`.
  /usr/bin/perl -0pi -e '
    my $inject =
      "$ENV{SENTINEL}\n" .
      "export EZPDS_IOS_BUILD=1\n" .
      "export PATH=$ENV{CARGO_BIN}:$ENV{DEVENV_BIN}:\$PATH\n" .
      "[ -f $ENV{ENVSH} ] && . $ENV{ENVSH}\n" .
      "# <<< ezpds-ios-env <<<\n";
    $inject =~ s/\n/\\n/g;   # encode newlines the way pbxproj stores them (\n in-quote)
    s/(shellScript = ")((?:[^"\\]|\\.)*?tauri(?:[^"\\]|\\.)*?xcode-script(?:[^"\\]|\\.)*?")/$1$inject$2/s;
  ' "${PBXPROJ}"
  if ! grep -q "${SENTINEL}" "${PBXPROJ}"; then
    echo "error: could not inject ios-env into the Build Rust Code Run Script phase." >&2
    echo "       Tauri's generated template may differ. Open ${PBXPROJ}, find the" >&2
    echo "       PBXShellScriptBuildPhase whose shellScript runs 'cargo tauri ios" >&2
    echo "       xcode-script', and adjust the shellScript regex in $(basename "$0")." >&2
    exit 1
  fi
  echo "ios-postinit: injected EZPDS_IOS_BUILD + PATH + ios-env.sh into Run Script phase"
fi

# --- Patch D: tolerate Xcode's spurious "entitlements modified during build" ---
# `cargo tauri ios build` re-runs its project sync (synchronize_project_config) on EVERY
# invocation, restamping the pbxproj. That per-build churn makes Xcode's incremental
# packaging racily report the (empty, never-actually-modified) entitlements file as
# "modified during the build" and fail — intermittently. The entitlements is `<dict/>`,
# so permitting the modification cannot produce incorrect entitlements (nothing to get
# wrong). CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION=YES is Xcode's documented switch for
# exactly this. It survives the per-build sync (which preserves existing buildSettings).
# Idempotent; skips cleanly if a future Tauri template ships no entitlements.
if grep -q 'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION' "${PBXPROJ}"; then
  echo "ios-postinit: entitlements-modification allowance already present"
elif grep -q 'CODE_SIGN_ENTITLEMENTS = ' "${PBXPROJ}"; then
  # Append the allowance after each CODE_SIGN_ENTITLEMENTS line, matching its indentation.
  /usr/bin/perl -0pi -e 's/^([ \t]*)CODE_SIGN_ENTITLEMENTS = ([^\n]*);$/$1CODE_SIGN_ENTITLEMENTS = $2;\n$1CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION = YES;/mg' "${PBXPROJ}"
  if ! grep -q 'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION = YES' "${PBXPROJ}"; then
    echo "error: could not add CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION to the pbxproj." >&2
    echo "       Expected a CODE_SIGN_ENTITLEMENTS build setting to anchor it; Tauri's" >&2
    echo "       generated template may differ. Adjust the regex in $(basename "$0")." >&2
    exit 1
  fi
  echo "ios-postinit: added CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION=YES"
else
  echo "ios-postinit: no CODE_SIGN_ENTITLEMENTS in pbxproj; skipping entitlements allowance"
fi

# Structural guard: the patched project MUST still parse. Catches quoting/encoding
# corruption that a sentinel-only check would miss (plutil reads the pbxproj format).
if command -v plutil >/dev/null 2>&1; then
  if ! plutil -lint "${PBXPROJ}" >/dev/null 2>&1; then
    echo "error: ${PBXPROJ} no longer parses after patching (plutil -lint failed)." >&2
    echo "       The Run Script injection likely broke the file's quoting/encoding." >&2
    echo "       Inspect it and fix the inject/regex in $(basename "$0"); do not leave" >&2
    echo "       a corrupted project file in place." >&2
    exit 1
  fi
fi

echo "ios-postinit: OK"
