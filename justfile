check:
    cargo check --workspace

build:
    cargo build --workspace

test:
    cargo test --workspace

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# Lint all crates; all warnings (Clippy and rustc) are treated as errors
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

run-pds:
    cargo run -p pds

# Build the Docker image locally (requires Docker)
docker-build:
    docker build -t pds:latest .

# Security audit against the RustSec advisory database. Accepted/ignored advisories
# and their rationale live in .cargo/audit.toml (read automatically by cargo audit).
audit:
    cargo audit

# Dependency license + supply-chain gate (cargo-deny; policy in deny.toml). Checks the license
# allowlist, the duplicate-major version guard-bans, and crate sources. Advisories are NOT checked
# here — `just audit` (cargo-audit) owns the RustSec scan, so we don't double-report the same CVEs.
deny:
    cargo deny check licenses bans sources

# Verify Cargo.lock is in sync with the Cargo.toml manifests. `--locked` makes cargo
# error instead of silently regenerating the lockfile, so accidental dependency drift
# (an edited manifest with a stale lock) fails CI instead of being merged. `metadata`
# resolves the whole workspace — including the iOS app that the Linux ci-pds build
# excludes — so the lockfile is verified end-to-end even where it cannot be compiled.
lock-check:
    cargo metadata --locked --format-version 1 > /dev/null

# Verify route ⇄ Bruno parity: every route registered in crates/pds/src/app.rs has a
# matching request in bruno/, and no .bru targets a route that no longer exists. This
# is the automated backstop for the "Mandatory" rule in AGENTS.md (Bruno API Collection).
bruno-check:
    scripts/bruno-parity.sh

# Verify parity across the four vendored font copies (identity-wallet, admin-companion,
# PDS assets, marketing site): a font file bundled under the same name in more than one
# copy must be byte-identical everywhere, so a re-fetch or re-optimization of one copy
# cannot silently fork the brand type. Each copy may bundle a subset of the families.
font-check:
    scripts/font-parity.sh

# Verify the Tauri IPC capability allowlists stay minimal (no core:default), reference the
# mobile schema, and keep withGlobalTauri off. The static minimality-lock half of the
# least-privilege IPC boundary in docs/security/tauri-ipc-boundary.md (Tauri v2 has no runtime
# ACL-denial test); fails if an edit re-widens the surface. Runs on Linux — parses JSON only.
cap-check:
    scripts/capability-check.sh

# Verify the iOS workflows' `paths:` trigger filters match the apps' real dependency
# graph (cargo metadata), both directions: every in-repo crate an app links is watched
# (a new workspace-crate dependency can't ship without widening the filters), and no
# entry is broader than the graph (pure-PDS changes can't re-acquire the macOS lanes
# through a re-widened crates/** or scripts/**). Runs on Linux — reads metadata + YAML.
ios-paths-check:
    scripts/ios-paths-check.sh

# Verify the swift-rs --disable-sandbox fork ([patch.crates-io] in Cargo.toml) is both
# DECLARED and ACTUALLY APPLIED (Cargo.lock resolves swift-rs from the path, not the
# registry). Cargo silently stops applying a [patch] when a dependency bump requires a
# semver-incompatible swift-rs — this reads only Cargo.toml/Cargo.lock, so the Linux PR
# gate catches that before it breaks the macOS build with an EPERM far from the cause.
swift-rs-check:
    scripts/swift-rs-patch-check.sh

# Verify the forked XcodeGen iOS project template (scripts/ios/project.yml, wired via
# bundle > iOS > template in both apps' tauri.conf.json) is in lockstep with the
# tauri-cli version the workflows pin, still carries every required workaround, and is
# still referenced by both apps. Runs on Linux — greps only; the macOS-side
# `just ios-check`/`admin-check` verifies the same invariants in the GENERATED project.
ios-template-check:
    scripts/ios-template-check.sh

# Install dependencies for the interop CLI (tools/interop) — one-time setup.
interop-setup:
    cd tools/interop && pnpm install

# Run the interop CLI against a live deployment (default: staging). Exercises account
# provisioning, identity, sync, firehose, and scoped network interactions — see
# tools/interop/README.md for the runbook and the safety ground rules.
interop *args:
    tools/interop/bin/interop {{args}}

# Run the full CI pipeline locally (all crates; use on macOS where the iOS app builds)
ci: fmt-check lock-check bruno-check font-check cap-check ios-paths-check swift-rs-check ios-template-check clippy test audit deny

# CI gate for the Linux pds pipeline (GitHub Actions, .github/workflows/ci.yml). Excludes the
# iOS apps (identity-wallet, admin-companion), which need the Apple toolchain (security-framework)
# absent in CI; the mobile apps are built and checked via `just ios-*` / `just admin-*` on macOS.
ci-pds: fmt-check
    just lock-check
    just bruno-check
    just font-check
    just cap-check
    just ios-paths-check
    just swift-rs-check
    just ios-template-check
    cargo clippy --workspace --exclude identity-wallet --exclude admin-companion --all-targets -- -D warnings
    cargo test --workspace --exclude identity-wallet --exclude admin-companion
    just audit
    just deny

# Validate that the flake evaluates correctly (devShells + nixosModules).
nix-check:
    nix flake check --impure --accept-flake-config

# --- Release versioning ---------------------------------------------------------
# The workspace version (Cargo.toml [workspace.package].version) is the single source of
# truth: every crate inherits it, and the PDS reports it at _health/describeServer via
# env!("CARGO_PKG_VERSION"). `set-version` bumps it; `release` derives the git tag from it,
# so the tag and the reported version can never drift. The release CI re-asserts the match.

# Bump the workspace version and resync Cargo.lock. Run in a reviewed PR, then `just release`
# from main after it merges. Usage: just set-version 0.3.1
set-version version:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! printf '%s' "{{version}}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
      echo "✗ version must be X.Y.Z (got '{{version}}')" >&2; exit 1
    fi
    # Rewrite only the [workspace.package] version line (not dependency versions below it):
    # scope strictly to that section (reset on any other section header) and fail if no version
    # line was found, so a missing/renamed field can never silently rewrite a later `version`.
    awk -v v="{{version}}" '
      /^\[workspace\.package\]$/ {p=1; print; next}
      /^\[/ {p=0}
      p && /^version[[:space:]]*=/ && !done {print "version = \"" v "\""; done=1; next}
      {print}
      END { if (!done) { print "✗ could not rewrite [workspace.package].version" > "/dev/stderr"; exit 1 } }
    ' Cargo.toml > Cargo.toml.tmp
    mv Cargo.toml.tmp Cargo.toml
    # Resync the lockfile so the new workspace-crate versions land in Cargo.lock and
    # `just lock-check` stays green (cargo metadata resolves without upgrading other deps).
    cargo metadata --format-version 1 >/dev/null
    echo "✓ workspace version set to {{version}} — commit Cargo.toml + Cargo.lock, open a PR,"
    echo "  then run 'just release' from main once it's merged."

# Cut a release: create the annotated tag v{workspace version} and push it to origin. The tag
# is the release anchor — it always matches the reported PDS version (derived from Cargo.toml).
# Tagging does NOT deploy: promoting a tag to production is a separate, explicit step
# (`just deploy-production <tag>`, which advances the `production` branch Railway watches).
# Run from a clean `main`.
release:
    #!/usr/bin/env bash
    set -euo pipefail
    version="$(awk '/^\[workspace\.package\]/{p=1} p&&/^version *=/{if(match($0,/"[^"]+"/)){print substr($0,RSTART+1,RLENGTH-2);exit}}' Cargo.toml)"
    if [ -z "$version" ]; then echo "✗ could not read [workspace.package] version from Cargo.toml" >&2; exit 1; fi
    tag="v${version}"
    if [ -n "$(git status --porcelain)" ]; then echo "✗ working tree not clean — commit/stash first" >&2; exit 1; fi
    if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
      echo "✗ release from 'main' only (you are on $(git rev-parse --abbrev-ref HEAD))" >&2; exit 1
    fi
    # Tag the merged, pushed main — not a local-only or stale commit — so the tag (and the
    # production branch later advanced to it) carries real merged-main provenance.
    git fetch --quiet origin main
    if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
      echo "✗ release requires HEAD == origin/main — push/pull main first" >&2; exit 1
    fi
    # Check origin too: a stale clone may lack a tag that already exists on the remote, which
    # would otherwise only surface as a confusing push rejection after the local tag is created.
    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null \
      || git ls-remote --exit-code --tags --refs origin "refs/tags/${tag}" >/dev/null 2>&1; then
      echo "✗ tag ${tag} already exists (locally or on origin) — bump the version with 'just set-version' first" >&2; exit 1
    fi
    echo "→ tagging ${tag} at $(git rev-parse --short HEAD)…"
    git tag -a "${tag}" -m "Release ${tag}"
    echo "→ pushing ${tag} → origin…"
    git push origin "${tag}"
    echo "✓ released ${tag} — promote it with 'just deploy-production ${tag}'"

# Promote a release tag to production. Railway watches the `production` branch and deploys its
# tip (gated on the CI workflow + the verify-release-tag backstop), so "deploying production"
# means moving `production` to a vX.Y.Z tag:
#   just deploy-production v0.3.1   # promote a specific tag
#   just deploy-production          # promote the highest vX.Y.Z tag
# A normal promote must fast-forward (production never holds commits the tag lacks). Rolling
# back to an OLDER tag is a non-fast-forward; pass FORCE=1 to allow it — production is a deploy
# pointer, not a work branch, so rewinding it is safe.
deploy-production tag="":
    #!/usr/bin/env bash
    set -euo pipefail
    tag="{{tag}}"
    # Resolve tags against origin, not a possibly-stale local clone — otherwise the default
    # "latest" pick (or an explicit tag this clone hasn't fetched) could promote the wrong
    # release, or an outdated one, to production.
    git fetch --quiet --tags origin
    if [ -z "$tag" ]; then
      tag="$(git tag --list --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"
      if [ -z "$tag" ]; then echo "✗ no vX.Y.Z tag exists — cut one with 'just release'" >&2; exit 1; fi
      echo "→ no tag given; using latest: ${tag}"
    fi
    if ! printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
      echo "✗ tag must be vX.Y.Z (got '$tag')" >&2; exit 1
    fi
    # Only ever promote an origin-published tag. The fetch above brought origin's tags local for
    # resolution, but the local namespace can also hold a local-only tag (auto-selected as
    # "latest" or passed explicitly); refuse anything origin doesn't have, so an unpushed commit
    # can never reach production. (A divergent same-name tag is additionally caught by the
    # production-branch verify-release CI job before Railway deploys.)
    if ! git ls-remote --exit-code --tags --refs origin "refs/tags/${tag}" >/dev/null 2>&1; then
      echo "✗ tag ${tag} is not on origin — push it (e.g. with 'just release') before promoting" >&2; exit 1
    fi
    if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
      echo "✗ tag ${tag} does not exist locally — fetch it or cut it with 'just release'" >&2; exit 1
    fi
    target="$(git rev-parse "${tag}^{commit}")"
    # Compare against the current remote production tip to classify the move.
    if git fetch --quiet origin production 2>/dev/null; then
      current="$(git rev-parse FETCH_HEAD)"
      if [ "$current" = "$target" ]; then
        echo "✓ production already at ${tag} ($(git rev-parse --short "$target")) — nothing to do"; exit 0
      fi
      if ! git merge-base --is-ancestor "$current" "$target"; then
        if [ "${FORCE:-}" != "1" ]; then
          echo "✗ ${tag} is behind/diverged from current production ($(git rev-parse --short "$current")) — this is a rollback." >&2
          echo "  Re-run with FORCE=1 to rewind production to ${tag}." >&2
          exit 1
        fi
        echo "→ FORCE=1: rewinding production to ${tag}"
        git push --force origin "${target}:refs/heads/production"
        echo "✓ production → ${tag}; Railway will deploy once CI is green"
        exit 0
      fi
    else
      echo "→ production branch does not exist yet — creating it at ${tag}"
    fi
    echo "→ pushing ${tag} ($(git rev-parse --short "$target")) → production…"
    git push origin "${target}:refs/heads/production"
    echo "✓ production → ${tag}; Railway will deploy once CI is green"

# Verify the commit at HEAD is a valid production release point — used by the CI workflow on the
# `production` branch, and runnable locally. Every v-prefixed tag on HEAD must be semver vX.Y.Z,
# at least one such tag must exist, and it must equal the workspace version the binary reports
# (env!("CARGO_PKG_VERSION")). The production branch is advanced to a v* tag to deploy and Railway
# gates the deploy on CI, so this is the backstop against shipping a tip whose tag/version disagree.
verify-release-tag:
    #!/usr/bin/env bash
    set -euo pipefail
    # The branch may carry any v-prefixed tag; reject a non-semver one (e.g. `vfoo`) outright so it
    # can never slip past the version check below.
    release_tags="$(git tag --points-at HEAD | grep -E '^v' || true)"
    non_semver="$(printf '%s\n' "$release_tags" | grep -Ev '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
    if [ -n "$non_semver" ]; then
      echo "✗ non-semver release tag(s) point at HEAD:" >&2
      printf '    %s\n' "$non_semver" >&2
      exit 1
    fi
    tags="$(printf '%s\n' "$release_tags" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
    if [ -z "$tags" ]; then
      echo "✗ no vX.Y.Z tag points at HEAD — the production branch must be advanced to a release tag" >&2
      echo "  (cut one with 'just release', then 'just deploy-production <tag>')." >&2
      exit 1
    fi
    version="v$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | select(.name=="pds") | .version')"
    mismatched="$(printf '%s\n' "$tags" | grep -vxF "$version" || true)"
    if [ -n "$mismatched" ]; then
      echo "✗ release tag(s) do not match workspace version '$version' (Cargo.toml):" >&2
      printf '    %s\n' "$mismatched" >&2
      echo "  Bump [workspace.package].version to the intended tag and re-tag, or remove the mismatched tag." >&2
      exit 1
    fi
    echo "✓ all vX.Y.Z tag(s) on HEAD match workspace version '$version'"

# --- iOS (identity-wallet) — run from repo root; requires macOS + Xcode ---

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

# Both iOS recipes `export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh` before `cargo tauri`
# so the OUTER process re-resolves the Apple toolchain, overriding any stale
# CARGO_TARGET_*/CC_*/AR_* a long-lived dev shell may carry from a pre-fix ios-env.sh
# sourcing (see apps/identity-wallet/CLAUDE.md "Development Workflow").

# Launch the app on the iOS Simulator (verifies patches first). With no argument,
# `cargo tauri ios dev` auto-selects a target and PREFERS a connected physical
# device (which needs code signing). Pass a simulator name to force the Simulator
# even while a device is plugged in, e.g. `just ios-dev "iPhone 17 Pro Max"`.
ios-dev device="": ios-check
    cd apps/identity-wallet && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && if [ -n "{{device}}" ]; then cargo tauri ios dev "{{device}}"; else cargo tauri ios dev; fi

# Build the iOS app for the Simulator (verifies patches first).
ios-build: ios-check
    cd apps/identity-wallet && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios build --debug

# PR-time iOS gate (.github/workflows/ios-pr-check.yml) — no signing, no secrets, no
# xcodebuild archive. Builds the frontend (tauri's codegen embeds ../dist at compile
# time), cross-compiles the app's staticlib for the iOS device target, then runs the
# app's Rust unit tests on the macOS host target (the only CI lane that can compile
# this crate — the Linux ci-pds gate excludes it). Via the ios-check dependency this
# exercises the whole Apple/Rust seam a PR can break: the scripts/ios/project.yml
# template rendering, the swift-rs fork (vendored plugin Swift compilation), and the
# shared workspace crates on aarch64-apple-ios. The host test run deliberately does
# NOT set EZPDS_IOS_BUILD (that would clobber CC/AR with iOS toolchain overrides).
# Assumes the Xcode project exists: run `cargo tauri ios init` + `just ios-postinit` first.
ios-pr-check: ios-check (_icon-compile "apps/identity-wallet")
    cd apps/identity-wallet && pnpm build
    cd apps/identity-wallet && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo build --locked --lib --target aarch64-apple-ios -p identity-wallet
    cargo test --locked -p identity-wallet

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

# --- iOS release -> TestFlight (macOS + Xcode) ---
# CI runs these on a GitHub macOS runner (.github/workflows/ios-testflight.yml);
# they double as the local `just ios-release` escape hatch.
# SIGNING is explicit (Tauri's automatic iOS signing is unreliable — it emits an
# "Apple Distribution: Tauri (unset)" placeholder that App Store Connect rejects):
#   IOS_CERTIFICATE (base64 .p12) + IOS_CERTIFICATE_PASSWORD + IOS_MOBILE_PROVISION
#   (base64 App Store .mobileprovision).
# UPLOAD uses the App Store Connect API key: APPLE_API_KEY + APPLE_API_ISSUER and the
# matching AuthKey_<id>.p8 in ~/.appstoreconnect/private_keys/. See docs/ios-cicd.md.

# Shared implementation behind `ios-ipa`/`admin-ipa` (private): stamp a unique,
# monotonic CFBundleVersion into the app's tauri.conf.json, build the signed App
# Store IPA, and restore the config afterwards.
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

# Build a signed, App Store-method IPA (for TestFlight or the App Store). Assumes the
# Xcode project exists: run `cargo tauri ios init` + `just ios-postinit` once first
# (CI does both every run). NOTE: the --export-method token tracks Xcode's names
# (`app-store-connect` on Xcode 15+); confirm once with `cargo tauri ios build --help`.
# Build-number stamping: see `_ipa`. Override the default: `just ios-ipa 12345`.
ios-ipa build_number="": ios-check
    just _ipa apps/identity-wallet "{{build_number}}"

# Upload the most recently built IPA to App Store Connect / TestFlight via altool.
# Requires APPLE_API_KEY (key id) + APPLE_API_ISSUER (issuer id) in the environment
# and the matching AuthKey_<key id>.p8 in ~/.appstoreconnect/private_keys/.
ios-upload:
    #!/usr/bin/env bash
    set -euo pipefail
    # Newest .ipa by mtime — `ls -t` picks the freshest build, not the alphabetically
    # first (which could be a stale pre-rename artifact). `|| true` tolerates no match.
    ipa="$(ls -t apps/identity-wallet/src-tauri/gen/apple/build/arm64/*.ipa 2>/dev/null | head -n1 || true)"
    if [ -z "$ipa" ]; then
      echo "no .ipa found - run 'just ios-ipa' first" >&2
      exit 1
    fi
    echo "uploading $ipa to TestFlight..."
    xcrun altool --upload-app --type ios --file "$ipa" --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"

# Full local release lane: build the signed IPA, then upload to TestFlight.
ios-release: ios-ipa ios-upload

# --- iOS (admin-companion) — run from repo root; requires macOS + Xcode ---
# The operator console, a second iOS app. Same toolchain seam as identity-wallet;
# the scripts are path-relative so they patch this app's own generated Xcode project.

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
    cd apps/admin-companion && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && if [ -n "{{device}}" ]; then cargo tauri ios dev "{{device}}"; else cargo tauri ios dev; fi

# Build the admin console for the Simulator (verifies patches first).
admin-build: admin-check
    cd apps/admin-companion && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios build --debug

# PR-time iOS gate for the admin console — same shape as `just ios-pr-check` (no
# signing/secrets; frontend build + staticlib cross-compile for aarch64-apple-ios +
# host-target Rust unit tests, which no other CI lane can compile).
# Assumes the Xcode project exists: `cargo tauri ios init` + `just admin-postinit` first.
admin-pr-check: admin-check (_icon-compile "apps/admin-companion")
    cd apps/admin-companion && pnpm build
    cd apps/admin-companion && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo build --locked --lib --target aarch64-apple-ios -p admin-companion
    cargo test --locked -p admin-companion

# --- admin-companion release -> TestFlight (macOS + Xcode) ---
# CI runs these on a GitHub macOS runner (.github/workflows/admin-testflight.yml);
# they double as the local `just admin-release` escape hatch. Same signing model as
# identity-wallet (see the iOS release block above), but the App Store profile is
# bound to admin-companion's own bundle id (dev.malpercio.admincompanion) — set
# IOS_MOBILE_PROVISION to that profile's base64. The Apple Distribution cert
# (IOS_CERTIFICATE/_PASSWORD) and the API key (APPLE_API_KEY/_ISSUER) are team-wide
# and shared with the identity-wallet lane. See docs/ios-cicd.md.

# Build a signed, App Store-method IPA for the admin console. Assumes the Xcode
# project exists: run `cargo tauri ios init` + `just admin-postinit` once first
# (CI does both every run). Build-number stamping: see `_ipa`; override:
# `just admin-ipa 12345`.
admin-ipa build_number="": admin-check
    just _ipa apps/admin-companion "{{build_number}}"

# Upload the most recently built admin-companion IPA to App Store Connect / TestFlight
# via altool. Requires APPLE_API_KEY (key id) + APPLE_API_ISSUER (issuer id) in the
# environment and the matching AuthKey_<key id>.p8 in ~/.appstoreconnect/private_keys/.
admin-upload:
    #!/usr/bin/env bash
    set -euo pipefail
    # Newest .ipa by mtime — `ls -t` picks the freshest build, not the alphabetically first.
    ipa="$(ls -t apps/admin-companion/src-tauri/gen/apple/build/arm64/*.ipa 2>/dev/null | head -n1 || true)"
    if [ -z "$ipa" ]; then
      echo "no .ipa found - run 'just admin-ipa' first" >&2
      exit 1
    fi
    echo "uploading $ipa to TestFlight..."
    xcrun altool --upload-app --type ios --file "$ipa" --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"

# Full local release lane: build the signed IPA, then upload to TestFlight.
admin-release: admin-ipa admin-upload
