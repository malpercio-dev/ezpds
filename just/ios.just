# --- iOS lanes (identity-wallet + admin-companion) --------------------------------
# Imported by the root justfile. Run from the repo root; requires macOS + Xcode.
# The two apps share one toolchain seam: the per-app scripts under
# apps/<app>/scripts/ are thin wrappers over the ONE shared implementation in
# scripts/ios/. The public per-app recipes here are likewise thin delegates over
# private parameterized recipes (`_dev`, `_build`, `_pr-check`, `_upload`, `_ipa`,
# `_icon-compile`), so an identity-wallet ⇄ admin-companion pair can't drift.
#
# Both build recipes `export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh` before
# `cargo tauri` so the OUTER process re-resolves the Apple toolchain, overriding any
# stale CARGO_TARGET_*/CC_*/AR_* a long-lived dev shell may carry from a pre-fix
# ios-env.sh sourcing (see apps/identity-wallet/AGENTS.md "Development Workflow").

# --- Shared private recipes (parameterized over the app) ---

# Launch an app on the iOS Simulator. With no device, `cargo tauri ios dev`
# auto-selects a target and PREFERS a connected physical device (which needs code
# signing); pass a simulator name to force the Simulator even with a device plugged in.
_dev app_dir device:
    cd {{app_dir}} && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && if [ -n "{{device}}" ]; then cargo tauri ios dev "{{device}}"; else cargo tauri ios dev; fi

# Build an app for the Simulator.
_build app_dir:
    cd {{app_dir}} && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios build --debug

# PR-time iOS gate body (no signing, no secrets, no xcodebuild archive): build the
# frontend (tauri's codegen embeds ../dist at compile time), cross-compile the app's
# staticlib for the iOS device target, then run the app's Rust unit tests on the macOS
# host target (the only CI lane that can compile these crates — the Linux ci-pds gate
# excludes them). The host test run deliberately does NOT set EZPDS_IOS_BUILD (that
# would clobber CC/AR with iOS toolchain overrides). The `<app>-check` +
# `_icon-compile` dependencies (which exercise the whole Apple/Rust seam) are declared
# on the public delegates so each app runs its own check.
_pr-check app_dir crate:
    cd {{app_dir}} && pnpm build
    cd {{app_dir}} && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo build --locked --lib --target aarch64-apple-ios -p {{crate}}
    cargo test --locked -p {{crate}}

# Upload the most recently built IPA to App Store Connect / TestFlight via altool.
# Requires APPLE_API_KEY (key id) + APPLE_API_ISSUER (issuer id) in the environment
# and the matching AuthKey_<key id>.p8 in ~/.appstoreconnect/private_keys/.
_upload app_dir ipa_recipe:
    #!/usr/bin/env bash
    set -euo pipefail
    # Newest .ipa by mtime — `ls -t` picks the freshest build, not the alphabetically
    # first (which could be a stale pre-rename artifact). `|| true` tolerates no match.
    ipa="$(ls -t {{app_dir}}/src-tauri/gen/apple/build/arm64/*.ipa 2>/dev/null | head -n1 || true)"
    if [ -z "$ipa" ]; then
      echo "no .ipa found - run 'just {{ipa_recipe}}' first" >&2
      exit 1
    fi
    echo "uploading $ipa to TestFlight..."
    xcrun altool --upload-app --type ios --file "$ipa" --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"

# --- iOS release signing (shared by both apps) ---
# CI runs the release recipes on a GitHub macOS runner (.github/workflows/
# ios-testflight.yml, admin-testflight.yml); they double as the local
# `just ios-release`/`admin-release` escape hatch.
# SIGNING is explicit (Tauri's automatic iOS signing is unreliable — it emits an
# "Apple Distribution: Tauri (unset)" placeholder that App Store Connect rejects):
#   IOS_CERTIFICATE (base64 .p12) + IOS_CERTIFICATE_PASSWORD + IOS_MOBILE_PROVISION
#   (base64 App Store .mobileprovision; admin-companion uses its own bundle-id-bound
#   profile, IOS_MOBILE_PROVISION_ADMIN, in its workflow).
# UPLOAD uses the App Store Connect API key: APPLE_API_KEY + APPLE_API_ISSUER and the
# matching AuthKey_<id>.p8 in ~/.appstoreconnect/private_keys/. See docs/ios-cicd.md.

# Shared implementation behind `ios-ipa`/`admin-ipa`: stamp a unique, monotonic
# CFBundleVersion into the app's tauri.conf.json, build the signed App Store IPA, and
# restore the config afterwards.
#
# BUILD NUMBER: TestFlight rejects duplicate CFBundleVersions and requires them to
# increase, so CI and the local escape hatch must share ONE stamping scheme — stamping
# only in the workflow (the old design) made a second local `just ios-release` collide
# on the committed placeholder value. Default is UTC epoch seconds: unique, strictly
# increasing across CI and local runs alike, immune to the reset a workflow-file rename
# inflicts on GITHUB_RUN_NUMBER, and larger than any run number already uploaded (so
# the changeover is monotonic).
#
# RESTORE is `git checkout` of the committed file, not a backup copy: a SIGKILL skips
# the EXIT trap, and with a copy-based restore the next run would back up the
# already-stamped file as its new "original", losing the committed value for good.
# Because the git restore discards local edits to the file, the guard refuses to run
# while tauri.conf.json has uncommitted changes.
_ipa app_dir build_number:
    #!/usr/bin/env bash
    set -euo pipefail
    # Drop any stale .ipa first (e.g. a pre-rename artifact) so the upload recipes can't pick it up.
    rm -f {{app_dir}}/src-tauri/gen/apple/build/arm64/*.ipa
    conf="$(pwd)/{{app_dir}}/src-tauri/tauri.conf.json"
    if ! git diff --quiet -- "$conf"; then
      echo "✗ $conf has uncommitted changes — commit or stash them first" >&2
      echo "  (the post-build restore is 'git checkout -- <conf>', which would discard them)" >&2
      exit 1
    fi
    bv="{{build_number}}"
    [ -n "$bv" ] || bv="$(date -u +%s)"
    trap 'git checkout -- "$conf"' EXIT
    tmp="$(mktemp)"
    jq --arg bv "$bv" '.bundle.iOS.bundleVersion = $bv' "$conf" > "$tmp" && mv "$tmp" "$conf"
    echo "CFBundleVersion -> $bv"
    cd {{app_dir}} && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios build --export-method app-store-connect

# Compile the app's Icon Composer document (AppIcon.icon, referenced in place by
# the scripts/ios/project.yml template) with actool — the same compiler Xcode's
# build invokes — so a malformed icon.json or a layer SVG the Apple toolchain
# can't parse fails the PR gate instead of the post-merge TestFlight archive.
# macOS-only (xcrun); the callers are the macOS pr-check recipes. actool's exit
# code alone is not trustworthy, so the recipe also requires an Assets.car and
# greps the tool output for errors. A MISSING bundle fails too: both apps ship
# one, so absence in this gate means a miswired path, not an icon-less app.
_icon-compile app_dir:
    #!/usr/bin/env bash
    set -euo pipefail
    icon="{{app_dir}}/AppIcon.icon"
    if [ ! -d "$icon" ]; then
      echo "✗ missing AppIcon.icon in {{app_dir}} — both apps ship one; a missing bundle here means a miswired path" >&2
      exit 1
    fi
    out="$(mktemp -d)"
    log="$(xcrun actool "$icon" --compile "$out" \
      --platform iphoneos --minimum-deployment-target 14.0 \
      --app-icon AppIcon --output-partial-info-plist "$out/AppIcon-partial.plist" \
      --output-format human-readable-text --notices --warnings 2>&1)" || { echo "$log" >&2; exit 1; }
    echo "$log"
    if echo "$log" | grep -qi ': error:'; then
      echo "✗ actool reported errors compiling $icon" >&2
      exit 1
    fi
    if [ ! -f "$out/Assets.car" ]; then
      echo "✗ actool produced no Assets.car from $icon" >&2
      exit 1
    fi
    echo "✓ actool compiled $icon"

# --- identity-wallet (Obsign) ---

# Finish setting up the generated Xcode project (swift-rs fork check + app icon), then
# verify it. The Xcode-project workarounds themselves come from the committed template
# scripts/ios/project.yml, rendered on every `cargo tauri ios init`. Run once after
# every init. Idempotent.
ios-postinit:
    apps/identity-wallet/scripts/ios-postinit.sh

# Fail if the generated Xcode project is missing any required workaround (i.e. the
# scripts/ios/project.yml template did not apply, or gen/apple predates it).
ios-check:
    apps/identity-wallet/scripts/ios-check.sh

# Launch the app on the iOS Simulator (verifies patches first). Pass a simulator name
# to force the Simulator even while a device is plugged in, e.g.
# `just ios-dev "iPhone 17 Pro Max"`.
ios-dev device="": ios-check
    just _dev apps/identity-wallet "{{device}}"

# Build the iOS app for the Simulator (verifies patches first).
ios-build: ios-check
    just _build apps/identity-wallet

# PR-time iOS gate (.github/workflows/ios-pr-check.yml) — no signing, no secrets, no
# xcodebuild archive. See `_pr-check`. Via the ios-check + _icon-compile dependencies
# this exercises the whole Apple/Rust seam a PR can break: the scripts/ios/project.yml
# template rendering, the swift-rs fork (vendored plugin Swift compilation), and the
# shared workspace crates on aarch64-apple-ios.
# Assumes the Xcode project exists: run `cargo tauri ios init` + `just ios-postinit` first.
ios-pr-check: ios-check (_icon-compile "apps/identity-wallet")
    just _pr-check apps/identity-wallet identity-wallet

# Build a signed, App Store-method IPA (for TestFlight or the App Store). Assumes the
# Xcode project exists: run `cargo tauri ios init` + `just ios-postinit` once first
# (CI does both every run). NOTE: the --export-method token tracks Xcode's names
# (`app-store-connect` on Xcode 15+); confirm once with `cargo tauri ios build --help`.
# Build-number stamping: see `_ipa`. Override the default: `just ios-ipa 12345`.
ios-ipa build_number="": ios-check
    just _ipa apps/identity-wallet "{{build_number}}"

# Upload the most recently built identity-wallet IPA to TestFlight. See `_upload`.
ios-upload:
    just _upload apps/identity-wallet ios-ipa

# Full local release lane: build the signed IPA, then upload to TestFlight.
ios-release: ios-ipa ios-upload

# --- admin-companion (the operator console, "Brass Console") ---
# A second iOS app. Same toolchain seam as identity-wallet; the scripts are
# path-relative so they patch this app's own generated Xcode project. Its App Store
# profile is bound to admin-companion's own bundle id (dev.malpercio.admincompanion) —
# see docs/ios-cicd.md.

# Finish setting up admin-companion's generated Xcode project (swift-rs fork check +
# app icon), then verify it — the workarounds come from the scripts/ios/project.yml
# template. Run once after every `cargo tauri ios init`. Idempotent.
admin-postinit:
    apps/admin-companion/scripts/ios-postinit.sh

# Fail if admin-companion's generated Xcode project is missing any required workaround
# (i.e. the scripts/ios/project.yml template did not apply, or gen/apple predates it).
admin-check:
    apps/admin-companion/scripts/ios-check.sh

# Launch the admin console on the iOS Simulator (verifies patches first).
# Pass a simulator name to force the Simulator, e.g. `just admin-dev "iPhone 17 Pro Max"`.
admin-dev device="": admin-check
    just _dev apps/admin-companion "{{device}}"

# Build the admin console for the Simulator (verifies patches first).
admin-build: admin-check
    just _build apps/admin-companion

# PR-time iOS gate for the admin console — same shape as `just ios-pr-check`. See `_pr-check`.
# Assumes the Xcode project exists: `cargo tauri ios init` + `just admin-postinit` first.
admin-pr-check: admin-check (_icon-compile "apps/admin-companion")
    just _pr-check apps/admin-companion admin-companion

# Build a signed, App Store-method IPA for the admin console. Assumes the Xcode
# project exists: run `cargo tauri ios init` + `just admin-postinit` once first
# (CI does both every run). Build-number stamping: see `_ipa`; override:
# `just admin-ipa 12345`.
admin-ipa build_number="": admin-check
    just _ipa apps/admin-companion "{{build_number}}"

# Upload the most recently built admin-companion IPA to TestFlight. See `_upload`.
admin-upload:
    just _upload apps/admin-companion admin-ipa

# Full local release lane: build the signed IPA, then upload to TestFlight.
admin-release: admin-ipa admin-upload
