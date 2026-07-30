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
# staticlib for the iOS device target, then run the app's Rust unit tests and clippy on
# the macOS host target (the only CI lane that can compile these crates — the Linux
# ci-pds gate excludes them, so without the clippy step here nothing gates lints for
# these two crates and findings silently accumulate). The host test/clippy runs
# deliberately do NOT set EZPDS_IOS_BUILD (that would clobber CC/AR with iOS toolchain
# overrides). The `<app>-check` +
# `_icon-compile` dependencies (which exercise the whole Apple/Rust seam) are declared
# on the public delegates so each app runs its own check.
_pr-check app_dir crate:
    cd {{app_dir}} && pnpm build
    cd {{app_dir}} && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo build --locked --lib --target aarch64-apple-ios -p {{crate}}
    cargo test --locked -p {{crate}}
    cargo clippy --locked -p {{crate}} --all-targets -- -D warnings

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
    # Pre-flight the signing environment BEFORE the ~10-minute build.
    #
    # tauri's `signing_from_env()` reads exactly these three and silently returns "no signing"
    # if any is missing — it does not error. The build then runs to completion under AUTOMATIC
    # signing, mints the placeholder cert `Apple Distribution: Tauri (unset)` (tauri#11092), and
    # dies at the very end with `No signing certificate "iOS Distribution" found`, which names
    # neither the real cause nor the variable to set. One forgotten `export` in a fresh shell
    # therefore costs a full build and produces a misleading error; this costs a second.
    missing=()
    [ -n "${IOS_CERTIFICATE:-}" ] || missing+=("IOS_CERTIFICATE")
    # Set-but-empty is legitimate for a .p12 exported without a password, so test for the
    # variable's existence rather than its content.
    [ -n "${IOS_CERTIFICATE_PASSWORD+x}" ] || missing+=("IOS_CERTIFICATE_PASSWORD")
    [ -n "${IOS_MOBILE_PROVISION:-}" ] || missing+=("IOS_MOBILE_PROVISION")
    # An app that embeds an extension needs a SECOND profile, for the extension's own bundle id.
    # Keyed on the tracked entitlements file rather than a hardcoded app name: it is the same
    # marker the template gate and ios-check use, so an app gains this requirement in the change
    # that gives it an extension. Without it the build archives for minutes and only then fails
    # in `_reexport-embedded-extensions`.
    if [ -f "{{app_dir}}/src-tauri/Entitlements.NSE.plist" ]; then
      [ -n "${IOS_MOBILE_PROVISION_NSE:-}" ] || missing+=("IOS_MOBILE_PROVISION_NSE")
    fi
    if [ "${#missing[@]}" -gt 0 ]; then
      echo "✗ signing is not configured — missing: ${missing[*]}" >&2
      echo "  This lane signs EXPLICITLY; tauri's automatic signing produces an" >&2
      echo "  \"Apple Distribution: Tauri (unset)\" placeholder that App Store Connect rejects." >&2
      echo "  With these unset the build would run to completion and only then fail." >&2
      echo >&2
      echo "  export IOS_CERTIFICATE=\"\$(base64 -i Distribution.p12)\"" >&2
      echo "  export IOS_CERTIFICATE_PASSWORD='…'" >&2
      echo "  export IOS_MOBILE_PROVISION=\"\$(base64 -i <app>.mobileprovision)\"" >&2
      echo "  export IOS_MOBILE_PROVISION_NSE=\"\$(base64 -i <extension>.mobileprovision)\"  # apps embedding an extension" >&2
      echo >&2
      echo "  See docs/ios-cicd.md → \"GitHub repo secrets\"." >&2
      exit 1
    fi
    bv="{{build_number}}"
    [ -n "$bv" ] || bv="$(date -u +%s)"
    trap 'git checkout -- "$conf"' EXIT
    tmp="$(mktemp)"
    jq --arg bv "$bv" '.bundle.iOS.bundleVersion = $bv' "$conf" > "$tmp" && mv "$tmp" "$conf"
    echo "CFBundleVersion -> $bv"
    cd {{app_dir}} && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh
    # Report the signing environment as a CHILD PROCESS will see it — `env`, not shell
    # expansion, because that is exactly what tauri's `var_os` reads, and the two differ for a
    # variable that was assigned but never exported. Lengths only: a value here is a private
    # key or a password and must never reach a terminal scrollback or a CI transcript.
    #
    # This exists because "tauri fell back to automatic signing" and "you forgot an export" are
    # indistinguishable from tauri's own output — it prints the same placeholder cert either
    # way, minutes later, naming neither cause. Several builds were spent on that ambiguity.
    echo "signing environment visible to the build:"
    for _v in IOS_CERTIFICATE IOS_CERTIFICATE_PASSWORD IOS_MOBILE_PROVISION IOS_MOBILE_PROVISION_NSE APPLE_DEVELOPMENT_TEAM; do
      # Exportedness from `env` (a child's view); LENGTH from the shell's own copy. Not from
      # `env` output — base64 is commonly wrapped at 76 columns (openssl does it by default,
      # and tauri strips whitespace before decoding, so a wrapped value is perfectly valid),
      # and a line-oriented read of `env` reports only the first line. That misreads an
      # 18 KB certificate as "76 bytes", which looks exactly like someone passed a file path.
      if env | grep -q "^${_v}="; then
        _val="${!_v-}"
        _note=""
        # A .p12 and a .mobileprovision are kilobytes; anything tiny is a path, a truncated
        # paste, or a filename — all of which decode to garbage rather than failing cleanly.
        case "$_v" in
          IOS_CERTIFICATE|IOS_MOBILE_PROVISION|IOS_MOBILE_PROVISION_NSE)
            [ "${#_val}" -lt 1000 ] && _note="  ⚠ implausibly short for base64 — a file path?" ;;
        esac
        printf '  %-26s exported (%s bytes)%s\n' "$_v" "${#_val}" "$_note"
      else
        printf '  %-26s NOT EXPORTED\n' "$_v"
      fi
    done
    unset _v _val _note

    # REGENERATE the Xcode project before building. This is not hygiene — it is required for
    # correctness on any machine that builds twice.
    #
    # `cargo tauri ios build` writes CODE_SIGN_IDENTITY / DEVELOPMENT_TEAM /
    # PROVISIONING_PROFILE_SPECIFIER into project.pbxproj at line numbers its parser recorded.
    # Those numbers go stale as earlier insertions shift the file, so a project it has ALREADY
    # stamped comes back with settings written after a closing brace — or after
    # `/* End XCBuildConfiguration section */` entirely. Its own parser then derails, finds no
    # `_iOS` build-configuration list, and quietly skips every signing setting AND the
    # `provisioningProfiles`/`signingStyle` half of the ExportOptions. The build runs to
    # completion, signs with a self-signed "Apple Distribution: Tauri (unset)" placeholder, and
    # fails at the export blaming a missing "iOS Distribution" certificate.
    #
    # Xcode and `plutil -lint` both accept the mangled file, so nothing else notices. CI never
    # hit this because it regenerates gen/ on every run; only repeated LOCAL builds accumulate
    # the damage — one build is enough to break the next.
    #
    # Regenerating costs seconds and makes the local lane identical to CI's init → postinit →
    # build. It comes after the version stamp so the generated Info.plist carries it.
    echo "regenerating the Xcode project (tauri's pbxproj writes are not idempotent)..."
    # Output is captured rather than discarded, and replayed on failure. `cargo tauri ios init`
    # reports the actual reason on STDOUT — xcodegen's "Couldn't find current username", a
    # template render error, a missing dependency — so `>/dev/null` turns any of them into a
    # bare "exited with code 1" with the explanation thrown away.
    _initlog="$(mktemp)"
    if ! { cargo tauri ios init && "$(git rev-parse --show-toplevel)/{{app_dir}}/scripts/ios-postinit.sh"; } >"$_initlog" 2>&1; then
      echo "✗ could not regenerate the Xcode project:" >&2
      cat "$_initlog" >&2
      rm -f "$_initlog"
      exit 1
    fi
    rm -f "$_initlog"
    # Post-condition: confirm tauri can actually find what it needs to sign. Cheap, and it
    # converts the silent fallback above into an immediate, named failure.
    python3 "$(git rev-parse --show-toplevel)/scripts/ios/pbxproj-parseable.py" \
      src-tauri/gen/apple/*.xcodeproj/project.pbxproj

    # SwiftPM manifest compilation for the vendored swift-rs fork occasionally crashes the
    # Apple toolchain non-deterministically: `clang` dies with `Segmentation fault: 11`
    # while linking the throwaway Package.swift manifest executable, panicking swift-rs's
    # build script ("Failed to compile swift package Tauri") and failing the whole lane.
    # It is a transient toolchain crash, not a build defect — the identical build passes on
    # retry and passed on the sibling app's lane for the same commit. Retry ONLY that
    # signature (a clang crash-by-signal); any other failure — a real Rust/Swift compile
    # error or a signing failure — still fails fast on the first attempt.
    # See docs/ios-upstream-bugs.md Bug 4.
    transient_re='Segmentation fault: 11|linker command failed due to signal|unable to execute command: (Segmentation fault|Killed)'
    attempts=3
    for attempt in $(seq 1 "$attempts"); do
      buildlog="$(mktemp)"
      if cargo tauri ios build --export-method app-store-connect 2>&1 | tee "$buildlog"; then
        rm -f "$buildlog"
        break
      fi
      status="${PIPESTATUS[0]}"
      if [ "$attempt" -lt "$attempts" ] && grep -qE "$transient_re" "$buildlog"; then
        echo "⚠ transient Apple-toolchain crash during swift-rs manifest compile (attempt $attempt/$attempts) — retrying" >&2
        rm -f "$buildlog"
        continue
      fi
      rm -f "$buildlog"
      exit "$status"
    done
    # Only a successful build reaches here — every failure path above exits. `just` runs from
    # the justfile directory regardless of the cd above, so these need no path fixup.
    just _reexport-embedded-extensions {{app_dir}}
    just _verify-signed-ipa {{app_dir}}

# Re-export the archive with an ExportOptions that names a provisioning profile for EVERY
# embedded bundle, not just the app.
#
# WHY THIS EXISTS. `cargo tauri ios build` archives and exports in one step, and its generated
# ExportOptions carries exactly one provisioning-profile entry:
#
#     provisioning_profiles.insert(config.app().identifier().to_string(), profile_uuid.into());
#
# — the app's bundle id. It also only stamps signing settings onto build-configuration lists
# whose comment contains `_iOS`, so an extension target is left entirely unsigned in the
# archive. `xcodebuild -exportArchive` then re-signs the extension with the distribution
# identity but, having no profile for its bundle id, gives it EMPTY entitlements and no
# embedded.mobileprovision. Nothing fails: the archive succeeds, the export succeeds, a
# plausible-looking .ipa lands on disk, and the first thing that objects is App Store Connect
# ("Missing Code Signing Entitlements. No entitlements found in bundle ...") after a full
# build-and-upload round trip.
#
# The obvious escape hatch is closed: tauri merges a user-supplied gen/apple/ExportOptions.plist,
# but `merge_plist` is a shallow later-wins merge, so its own single-entry `provisioningProfiles`
# overwrites ours wholesale. And there is no archive-only mode to hook between.
#
# So we let tauri produce its (broken) .ipa and simply export the archive AGAIN with a complete
# ExportOptions, overwriting it. `-exportArchive` re-signs every bundle from scratch, so the
# archive — which tauri leaves ad-hoc signed anyway — is a perfectly good input, and the second
# export costs seconds. This keeps the fix inside one recipe instead of forking the whole
# release lane away from tauri.
#
# No-ops for an app with no embedded extensions (admin-companion today), so both lanes share it.
_reexport-embedded-extensions app_dir:
    #!/usr/bin/env bash
    set -euo pipefail
    gen="{{app_dir}}/src-tauri/gen/apple"
    archive="$(ls -td "$gen"/build/*.xcarchive 2>/dev/null | head -n1 || true)"
    if [ -z "$archive" ]; then
      echo "✗ no .xcarchive under $gen/build — did the build actually run?" >&2
      exit 1
    fi
    app="$(ls -d "$archive"/Products/Applications/*.app 2>/dev/null | head -n1 || true)"
    if [ -z "$app" ]; then
      echo "✗ no .app inside $archive" >&2
      exit 1
    fi

    # Enumerate embedded bundles that need their own profile. Read from the archive rather than
    # assuming a name, so this keeps working if a second extension is ever added.
    appexes=()
    while IFS= read -r a; do [ -n "$a" ] && appexes+=("$a"); done < <(ls -d "$app"/PlugIns/*.appex 2>/dev/null || true)
    if [ "${#appexes[@]}" -eq 0 ]; then
      echo "✓ no embedded extensions in $(basename "$app") — tauri's own export is complete"
      exit 0
    fi

    if [ -z "${IOS_MOBILE_PROVISION_NSE:-}" ]; then
      echo "✗ IOS_MOBILE_PROVISION_NSE is not set, but $(basename "$app") embeds an extension." >&2
      echo "  An app extension is a separate bundle and needs its OWN App Store provisioning" >&2
      echo "  profile, bound to its own App ID. Without it the extension ships with empty" >&2
      echo "  entitlements and App Store Connect rejects the upload." >&2
      echo "  Set it to the base64 of that .mobileprovision:" >&2
      echo "    export IOS_MOBILE_PROVISION_NSE=\"\$(base64 -i <profile>.mobileprovision)\"" >&2
      echo "  See docs/ios-cicd.md → \"Push notifications: three artifacts\"." >&2
      exit 1
    fi

    # Install the extension's profile where Xcode looks — the same folder and the same UUID
    # lookup tauri_macos_sign uses for the app's, so both are discoverable identically.
    profiles_dir="$HOME/Library/MobileDevice/Provisioning Profiles"
    mkdir -p "$profiles_dir"
    nse_profile="$(mktemp)"
    # `-d`, not `--decode`: both spellings work on the BSD base64 and the Nix GNU one this
    # repo can put ahead of it, but `-d` is the common denominator across older BSDs too.
    echo "$IOS_MOBILE_PROVISION_NSE" | base64 -d > "$nse_profile"
    nse_plist="$(security cms -D -i "$nse_profile" 2>/dev/null)" || {
      echo "✗ IOS_MOBILE_PROVISION_NSE is not a decodable .mobileprovision" >&2; exit 1; }
    nse_uuid="$(plutil -extract UUID raw - <<<"$nse_plist")"
    team="$(plutil -extract TeamIdentifier.0 raw - <<<"$nse_plist")"
    cp "$nse_profile" "$profiles_dir/$nse_uuid.mobileprovision"
    rm -f "$nse_profile"

    # The app's profile UUID: read what tauri actually archived with, straight out of the
    # pbxproj it just stamped. Deriving it from the env var again would risk exporting with a
    # different profile than the archive was built against.
    pbxproj="$(ls "$gen"/*.xcodeproj/project.pbxproj | head -n1)"
    app_uuid="$(grep -oE 'PROVISIONING_PROFILE_SPECIFIER = "[^"]+"' "$pbxproj" | head -n1 | sed -E 's/.*"(.*)"/\1/' || true)"
    if [ -z "$app_uuid" ]; then
      echo "✗ no PROVISIONING_PROFILE_SPECIFIER in $pbxproj — signing env (IOS_CERTIFICATE / IOS_MOBILE_PROVISION) was not set for the build" >&2
      exit 1
    fi

    app_id="$(plutil -extract CFBundleIdentifier raw -o - "$app/Info.plist")"
    export EXPORT_TEAM="$team" EXPORT_APP_ID="$app_id" EXPORT_APP_UUID="$app_uuid" EXPORT_NSE_UUID="$nse_uuid"
    # `mktemp -d` then a fixed name inside it: `mktemp -t NAME` is BSD syntax, and the Nix
    # coreutils mktemp that ios-env.sh leaves ahead of /usr/bin is GNU, which reads -t
    # differently and demands XXXXXX in the template ("too few X's").
    options="$(mktemp -d)/ExportOptions.plist"
    profiles_json="$(for a in "${appexes[@]}"; do
      plutil -extract CFBundleIdentifier raw -o - "$a/Info.plist"
    done | paste -sd, -)"
    EXPORT_APPEX_IDS="$profiles_json" python3 - "$options" <<'PY'
    import os, plistlib, sys

    profiles = {os.environ["EXPORT_APP_ID"]: os.environ["EXPORT_APP_UUID"]}
    for bundle_id in filter(None, os.environ["EXPORT_APPEX_IDS"].split(",")):
        # Every extension shares one profile today (there is exactly one). A second extension
        # would need its own entry here and its own secret — the loop is where that lands.
        profiles[bundle_id] = os.environ["EXPORT_NSE_UUID"]

    options = {
        "method": "app-store-connect",
        "signingStyle": "manual",
        "teamID": os.environ["EXPORT_TEAM"],
        # The generic identity name, resolved by Xcode against the keychain — the same shape
        # tauri writes, and stable across cert renewals.
        "signingCertificate": "Apple Distribution",
        "provisioningProfiles": profiles,
    }
    with open(sys.argv[1], "wb") as handle:
        plistlib.dump(options, handle)
    print("  ExportOptions provisioningProfiles:")
    for bundle_id, uuid in profiles.items():
        print(f"    {bundle_id} -> {uuid}")
    PY

    # Make the distribution identity findable for THIS export. tauri imports IOS_CERTIFICATE
    # into an ephemeral keychain that is deleted the moment `cargo tauri ios build` exits, so
    # by the time this recipe runs, a fresh CI runner holds no signing identity at all and
    # `-exportArchive` fails with `No signing certificate "iOS Distribution" found`. A
    # developer Mac hides this: the login keychain carries the same identity permanently,
    # which is why the lane can be red while the identical local build is green. Import into
    # our own temporary keychain, prepend it to the search list, and restore everything on
    # exit — the same lifecycle tauri gives its keychain, held open a recipe longer.
    # Skipped when IOS_CERTIFICATE is unset: that is a developer Mac running the recipe
    # standalone, where the login keychain already holds the identity.
    if [ -n "${IOS_CERTIFICATE:-}" ]; then
      reexport_keychain="$(mktemp -d)/reexport.keychain-db"
      cert_file="$(mktemp)"
      echo "$IOS_CERTIFICATE" | base64 -d > "$cert_file"
      prior_keychains=()
      while IFS= read -r k; do
        k="${k#"${k%%[![:space:]]*}"}"; k="${k%\"}"; k="${k#\"}"
        [ -n "$k" ] && prior_keychains+=("$k")
      done < <(security list-keychains -d user)
      restore_keychains() {
        security list-keychains -d user -s "${prior_keychains[@]}" 2>/dev/null || true
        security delete-keychain "$reexport_keychain" 2>/dev/null || true
      }
      trap restore_keychains EXIT
      security create-keychain -p "" "$reexport_keychain"
      security set-keychain-settings "$reexport_keychain"
      security unlock-keychain -p "" "$reexport_keychain"
      security import "$cert_file" -k "$reexport_keychain" \
        -P "${IOS_CERTIFICATE_PASSWORD:-}" -T /usr/bin/codesign -T /usr/bin/security
      rm -f "$cert_file"
      # Without this, codesign under xcodebuild stalls on a keychain ACL prompt no CI can answer.
      security set-key-partition-list -S apple-tool:,apple: -k "" "$reexport_keychain" >/dev/null
      security list-keychains -d user -s "$reexport_keychain" "${prior_keychains[@]}"
    fi

    echo "re-exporting $(basename "$archive") with profiles for every embedded bundle..."
    rm -f "$gen"/build/arm64/*.ipa
    xcodebuild -exportArchive \
      -archivePath "$archive" \
      -exportPath "$gen/build/arm64" \
      -exportOptionsPlist "$options" \
      -allowProvisioningUpdates >/dev/null
    rm -f "$options"
    echo "✓ re-exported with ${#appexes[@]} embedded extension(s) signed"

# Assert the exported .ipa is actually shippable: every bundle in it — the app and each
# embedded extension — must carry non-empty entitlements and its own embedded.mobileprovision.
#
# This is the check whose absence cost a full build-and-upload round trip. The failure it
# catches is completely silent locally: the archive succeeds, the export succeeds, the .ipa
# looks normal, and only App Store Connect objects, minutes later, with a 409. Two seconds of
# `codesign -d` turns that into an immediate local failure.
_verify-signed-ipa app_dir:
    #!/usr/bin/env bash
    set -euo pipefail
    ipa="$(ls -t "{{app_dir}}"/src-tauri/gen/apple/build/arm64/*.ipa 2>/dev/null | head -n1 || true)"
    if [ -z "$ipa" ]; then
      echo "✗ no .ipa to verify under {{app_dir}}/src-tauri/gen/apple/build/arm64/" >&2
      exit 1
    fi
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    unzip -q "$ipa" -d "$work"
    app="$(ls -d "$work"/Payload/*.app | head -n1)"

    fail=0
    check() { # <bundle> <label>
      local bundle="$1" label="$2" ents
      if [ ! -f "$bundle/embedded.mobileprovision" ]; then
        echo "✗ $label has no embedded.mobileprovision — it was signed without a provisioning profile" >&2
        fail=1
      fi
      # `codesign -d --entitlements -` prints nothing (or an empty dict) when the bundle was
      # signed with none, which is exactly the state App Store Connect rejects.
      ents="$(codesign -d --entitlements - --xml "$bundle" 2>/dev/null || true)"
      if ! python3 -c '
    import plistlib, sys
    raw = sys.stdin.buffer.read()
    start = raw.find(b"<?xml")
    sys.exit(0 if start >= 0 and plistlib.loads(raw[start:]) else 1)
    ' <<<"$ents"; then
        echo "✗ $label has no code-signing entitlements (App Store Connect rejects this with a 409)" >&2
        fail=1
      else
        echo "  ✓ $label — entitlements present, profile embedded"
      fi
    }

    check "$app" "$(basename "$app")"
    for appex in "$app"/PlugIns/*.appex; do
      [ -d "$appex" ] || continue
      check "$appex" "PlugIns/$(basename "$appex")"
    done

    [ "$fail" -eq 0 ] || { echo "✗ $(basename "$ipa") is not shippable — see above" >&2; exit 1; }
    echo "✓ $(basename "$ipa") signing verified"

# Typecheck the Notification Service Extension's Swift against the real iOS SDK — the
# extension's sources alone, then the test bundle exactly as the XcodeGen template composes
# it (extension sources compiled INTO the test target, since an app extension has no module
# to import).
#
# This exists because no other lane compiles Swift at all: `_pr-check` cross-compiles the
# Rust staticlib and stops, and the archive that would surface a Swift error only runs on
# push to main, holding signing secrets. Without this, a compile error in ~800 lines of
# security-critical Swift reaches TestFlight before anything objects — and the
# file-existence loop in ios-template-check would have to stand in for a compiler.
#
# `-typecheck`, not a build: it needs no simulator, no signing, and no generated Xcode
# project, so it runs on a bare checkout in seconds. macOS-only (xcrun); the caller is the
# macOS pr-check.
_nse-typecheck:
    #!/usr/bin/env bash
    set -euo pipefail
    sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
    platform="$(xcrun --sdk iphonesimulator --show-sdk-platform-path)"
    # The deployment target is pinned to the same 17.0 both apps declare: CryptoKit's HPKE
    # auth-mode initializer does not exist before it, so a lower target here would let a
    # regression that raises the real minimum pass unnoticed.
    common=(-typecheck -sdk "$sdk" -target arm64-apple-ios17.0-simulator)
    xcrun swiftc "${common[@]}" ios/NotificationService/*.swift
    echo "✓ NSE sources typecheck"
    # XCTest's Swift overlay lives beside the framework, not inside it; without the -I the
    # C macros are found instead and every assertion reads as an unknown identifier.
    xcrun swiftc "${common[@]}" \
      -F "$platform/Developer/Library/Frameworks" \
      -I "$platform/Developer/usr/lib" \
      ios/NotificationService/*.swift ios/NotificationServiceTests/*.swift
    echo "✓ NSE test bundle typechecks"

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
# `_nse-typecheck` is on THIS app's gate only: the Notification Service Extension target is
# gated to the wallet's bundle id in scripts/ios/project.yml, so admin-companion's project
# compiles none of that Swift (its adoption is where both move).
ios-pr-check: ios-check _nse-typecheck (_icon-compile "apps/identity-wallet")
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
