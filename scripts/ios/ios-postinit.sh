#!/usr/bin/env bash
# ios-postinit.sh — re-apply the surviving Tauri/macOS workarounds to the gitignored
# Xcode project that `cargo tauri ios init` regenerates. Run after EVERY
# `cargo tauri ios init`. Idempotent.
#
# SINGLE shared implementation for both app lanes; each app keeps a thin wrapper at
# apps/<app>/scripts/ios-postinit.sh that pins its app dir, recipe prefix, and Patch E
# framework list. See apps/identity-wallet/CLAUDE.md and docs/ios-upstream-bugs.md for
# why each patch exists.
#
# Usage: ios-postinit.sh <app-dir> <recipe-prefix> <framework>...
#   app-dir        absolute path to apps/<app>
#   recipe-prefix  the just-recipe family for error hints (ios | admin)
#   framework...   Apple frameworks Patch E must link via OTHER_LDFLAGS, in canonical
#                  order; the FIRST one anchors the extend-in-place branch.
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
  echo "error: no project.pbxproj under ${APP_DIR}/src-tauri/gen/apple/. Run 'cargo tauri ios init' first." >&2
  exit 1
fi
echo "ios-postinit: patching ${PBXPROJ}"

# --- Patch A: swift-rs --disable-sandbox fork must be declared AND applied ---
# (macOS 26 sandbox_apply EPERM). Delegates to the shared checker, which also asserts
# the applied state in Cargo.lock — a declared-but-unapplied patch (semver drift after
# a tauri bump) would otherwise fail much later, deep inside the Xcode build.
if ! "${REPO_ROOT}/scripts/swift-rs-patch-check.sh"; then
  echo "error: the swift-rs sandbox workaround is not active (see above)." >&2
  exit 1
fi

# --- Patch B: disable Xcode user-script sandbox (macOS 26 blocks cargo's readdir) ---
# Idempotent: YES->NO twice is a no-op. (perl -pi, not `sed -i ''`: works with both
# BSD and GNU userlands, so the script is smoke-testable off-mac.)
/usr/bin/perl -pi -e 's/ENABLE_USER_SCRIPT_SANDBOXING = YES/ENABLE_USER_SCRIPT_SANDBOXING = NO/g' "${PBXPROJ}"

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
  # The PATH/source values are wrapped in ESCAPED quotes (\") so a repo or CARGO_HOME path
  # containing a space survives — \" is a valid escape INSIDE the pbxproj double-quoted
  # shellScript string and does not terminate it (a *literal* " would). `\$PATH` stays
  # literal (the shell expands it at build time); `.` is the POSIX form of `source`.
  /usr/bin/perl -0pi -e '
    my $inject =
      "$ENV{SENTINEL}\n" .
      "export EZPDS_IOS_BUILD=1\n" .
      "export PATH=\\\"$ENV{CARGO_BIN}:$ENV{DEVENV_BIN}:\$PATH\\\"\n" .
      "[ -f \\\"$ENV{ENVSH}\\\" ] && . \\\"$ENV{ENVSH}\\\"\n" .
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

# --- Patch E: link the Apple frameworks this app's staticlib deps need (OTHER_LDFLAGS) ---
# Rust deps reference Apple framework symbols that rustc would auto-link via
# `#[link(kind="framework")]` on a host build, but on iOS the crate compiles into the
# `libapp.a` staticlib that Xcode links — and Xcode never sees those directives, so each
# framework must be declared in the Xcode project or the link fails with `Undefined symbols`.
# The per-app list comes from the wrapper:
#   - SystemConfiguration (both apps): `system-configuration` crate (hickory-resolver system
#     DNS config, reqwest system-proxy detection) → otherwise `_SC*` undefined.
#   - AuthenticationServices (identity-wallet): vendored `tauri-plugin-auth-session` →
#     `objc2-authentication-services` (ASWebAuthenticationSession, the in-app OAuth flow)
#     → otherwise `_ASWebAuthenticationSessionErrorDomain` undefined.
# `bundle.iOS.frameworks` in tauri.conf.json only seeds a FRESH project.yml; cargo-mobile2
# preserves an existing project.yml, so it does not retroactively apply — we enforce the link
# on the generated pbxproj here. ALL frameworks MUST share ONE OTHER_LDFLAGS line: a second
# OTHER_LDFLAGS assignment for the same build config shadows (not appends to) the first, which
# would silently drop a framework. The branches below keep this idempotent across a fresh init,
# an older partially-patched tree (extend in place), and an already-current tree.
canon_flags=""
canon_re="OTHER_LDFLAGS = "
for fw in "${FRAMEWORKS[@]}"; do
  canon_flags="${canon_flags} -framework ${fw}"
  canon_re="${canon_re}.*-framework ${fw}"
done
anchor_fw="${FRAMEWORKS[0]}"
if grep -qE "${canon_re}" "${PBXPROJ}"; then
  # Skip ONLY when a fully-patched line carries every framework (in canonical order) — not
  # on a bare name match, which a split/partial OTHER_LDFLAGS could satisfy while still
  # shadowing a framework. A partial state falls through to the repair branches below.
  echo "ios-postinit: OTHER_LDFLAGS already links:${canon_flags}"
elif grep -q "OTHER_LDFLAGS = .*-framework ${anchor_fw}" "${PBXPROJ}"; then
  # A patched line exists but lacks some frameworks — append each missing one in place
  # (before the closing quote of the anchored line) rather than adding a second assignment.
  for fw in "${FRAMEWORKS[@]}"; do
    if ! grep -qE "OTHER_LDFLAGS = .*-framework ${fw}" "${PBXPROJ}"; then
      # Braced ${a}/${f} interpolation: a bare $ENV{...} followed by `[` would parse as
      # a perl array subscript, not a regex character class.
      EZPDS_ANCHOR_FW="${anchor_fw}" EZPDS_ADD_FW="${fw}" /usr/bin/perl -0pi -e '
        my $a = quotemeta($ENV{EZPDS_ANCHOR_FW});
        my $f = $ENV{EZPDS_ADD_FW};
        s/(OTHER_LDFLAGS = "[^"\n]*-framework ${a}[^"\n]*)("[^\n]*;)/$1 -framework ${f}$2/mg;
      ' "${PBXPROJ}"
      if ! grep -qE "OTHER_LDFLAGS = .*-framework ${fw}" "${PBXPROJ}"; then
        echo "error: could not extend the existing OTHER_LDFLAGS line with ${fw}." >&2
        echo "       Inspect ${PBXPROJ} and adjust the regex in $(basename "$0")." >&2
        exit 1
      fi
      echo "ios-postinit: added ${fw}.framework to the existing OTHER_LDFLAGS line"
    fi
  done
else
  # Fresh project: add one OTHER_LDFLAGS line linking ALL frameworks after each target's
  # PRODUCT_BUNDLE_IDENTIFIER (its two build configs), reusing that line's indentation.
  # `\$(inherited)` stays literal (Xcode expands it).
  EZPDS_LDFLAGS="\$(inherited)${canon_flags}" /usr/bin/perl -0pi -e \
    's/^([ \t]*)PRODUCT_BUNDLE_IDENTIFIER = ([^\n]*);$/$1PRODUCT_BUNDLE_IDENTIFIER = $2;\n$1OTHER_LDFLAGS = "$ENV{EZPDS_LDFLAGS}";/mg' \
    "${PBXPROJ}"
  if ! grep -qE "${canon_re}" "${PBXPROJ}"; then
    echo "error: could not inject OTHER_LDFLAGS for the required frameworks into the pbxproj." >&2
    echo "       Expected a PRODUCT_BUNDLE_IDENTIFIER build setting to anchor it; Tauri's" >&2
    echo "       generated template may differ. Adjust the regex in $(basename "$0")." >&2
    exit 1
  fi
  echo "ios-postinit: linked${canon_flags} via OTHER_LDFLAGS"
fi

# --- Patch F: don't ship the Rust staticlib inside the .app (App Store rejects it) ---
# cargo-mobile2 lists the `Externals` dir (which holds `libapp.a`) as a project source with
# no explicit buildPhase, so XcodeGen infers `resources` and copies the raw `.a` into the
# .app — which App Store upload rejects ("libapp.a ... is not permitted / Invalid bundle
# structure", tauri#13578). The staticlib is still LINKED via the separate `framework:
# libapp.a` entry + LIBRARY_SEARCH_PATHS, so keeping it out of resources is safe. Fix at
# both layers: project.yml (the source the build re-syncs from) and the live pbxproj.
PROJYML="$(dirname "${PBXPROJ}")/../project.yml"
if [ -f "${PROJYML}" ]; then
  if grep -A1 -E '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}" | grep -q 'buildPhase: none'; then
    echo "ios-postinit: project.yml Externals already buildPhase:none"
  elif grep -qE '^[[:space:]]*-[[:space:]]*path:[[:space:]]*Externals[[:space:]]*$' "${PROJYML}"; then
    /usr/bin/perl -0pi -e 's/^([ \t]*)- path: Externals[ \t]*\n/$1- path: Externals\n$1  buildPhase: none\n/m' "${PROJYML}"
    echo "ios-postinit: set project.yml Externals buildPhase:none (keeps libapp.a out of the bundle)"
  else
    echo "ios-postinit: WARN — 'path: Externals' not found in project.yml; skipping (template changed?)" >&2
  fi
fi
# Strip the already-generated `libapp.a in Resources` entries from the live pbxproj (IDs are
# random per init, so match cargo-mobile2's stable comment). The `in Frameworks` link is kept.
if grep -q 'libapp\.a in Resources' "${PBXPROJ}"; then
  /usr/bin/perl -ni -e 'print unless m{/\* libapp\.a in Resources \*/}' "${PBXPROJ}"
  if grep -q 'libapp\.a in Resources' "${PBXPROJ}"; then
    echo "error: could not strip 'libapp.a in Resources' from the pbxproj (Patch F)." >&2
    exit 1
  fi
  echo "ios-postinit: stripped libapp.a from Copy Bundle Resources (pbxproj)"
else
  echo "ios-postinit: libapp.a already absent from pbxproj Resources phase"
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

echo "ios-postinit: OK (verify any time with 'just ${RECIPE}-check')"
