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

run-relay:
    cargo run -p relay

# Build the Docker image locally (requires Docker)
docker-build:
    docker build -t relay:latest .

# Security audit. RUSTSEC-2023-0071 (rsa Marvin attack) has no fixed release and is
# pulled only transitively by sqlx-macros' compile-time MySQL backend; the relay is
# sqlite-only, so rsa is never exercised at runtime. Revisit when a fix ships.
audit:
    cargo audit --ignore RUSTSEC-2023-0071

# Run the full CI pipeline locally (all crates; use on macOS where the iOS app builds)
ci: fmt-check clippy test audit

# CI gate for the Linux relay pipeline (tangled spindles). Excludes the iOS app
# (identity-wallet), which needs the Apple/GTK toolchain absent in CI; the mobile
# app is built and checked via `just ios-*` on macOS.
ci-relay: fmt-check
    cargo clippy --workspace --exclude identity-wallet --all-targets -- -D warnings
    cargo test --workspace --exclude identity-wallet
    just audit

# Validate that the flake evaluates correctly (devShells + nixosModules).
nix-check:
    nix flake check --impure --accept-flake-config

# Sync GitHub `main` (canonical) -> tangled `main`. PRs are merged on GitHub; tangled
# `main` does not auto-update, so it drifts and needs periodic syncing. This refuses
# anything that is not a clean fast-forward, so it can never clobber tangled history.
# NOTE: pushing tangled `main` triggers the staging deploy (just ci-relay -> Railway).
# Pre-validate first with `just ci-relay` if the relay changed.
sync-tangled-main:
    #!/usr/bin/env bash
    set -euo pipefail

    # Derive both push URLs from origin (no hardcoded SSH aliases): origin push-mirrors
    # to BOTH the GitHub mirror (URL contains "github") and the tangled knot (does not).
    github_url="$(git remote get-url --push --all origin | grep -i github | head -n1 || true)"
    tangled_url="$(git remote get-url --push --all origin | grep -iv github | head -n1 || true)"
    if [ -z "$github_url" ] || [ -z "$tangled_url" ]; then
      echo "✗ origin must push-mirror to both GitHub and tangled; found:" >&2
      git remote get-url --push --all origin >&2
      exit 1
    fi

    # Fast-forwarding local main touches the working tree — require it clean.
    if [ -n "$(git status --porcelain)" ]; then
      echo "✗ working tree not clean — commit or stash before syncing" >&2
      exit 1
    fi

    echo "→ fetching tangled main…"
    git fetch origin main
    tangled="$(git rev-parse FETCH_HEAD)"
    echo "→ fetching github main…"
    git fetch "$github_url" main
    github="$(git rev-parse FETCH_HEAD)"

    echo
    echo "tangled main: $(git rev-parse --short "$tangled")"
    echo "github  main: $(git rev-parse --short "$github")"

    if [ "$tangled" = "$github" ]; then
      echo "✓ already in sync — nothing to push"
      exit 0
    fi

    echo
    echo "incoming (on GitHub, not yet on tangled):"
    git log --oneline --graph "$tangled".."$github"

    # Refuse a non-fast-forward: tangled must hold no commits GitHub lacks.
    if ! git merge-base --is-ancestor "$tangled" "$github"; then
      echo >&2
      echo "✗ tangled main has commits not on GitHub main — NOT a clean fast-forward." >&2
      echo "  Refusing to push; reconcile the divergence manually." >&2
      exit 1
    fi

    # Fast-forward local main, push the tangled URL ONLY (origin would also push to
    # GitHub — harmless but redundant), then restore the branch you started on.
    start_branch="$(git rev-parse --abbrev-ref HEAD)"
    git checkout main
    git merge --ff-only "$github"
    echo
    echo "→ pushing main → tangled (this triggers the staging deploy)…"
    git push "$tangled_url" main
    [ "$start_branch" != "main" ] && git checkout "$start_branch" || true

    git fetch origin main
    if [ "$(git rev-parse FETCH_HEAD)" = "$github" ]; then
      echo "✓ tangled main == github main ($(git rev-parse --short "$github"))"
    else
      echo "✗ post-push verification failed — tangled does not match GitHub" >&2
      exit 1
    fi

# --- iOS (identity-wallet) — run from repo root; requires macOS + Xcode ---

# Re-apply the surviving Tauri/macOS patches to the generated Xcode project.
# Run once after every `cargo tauri ios init`. Idempotent.
ios-postinit:
    apps/identity-wallet/scripts/ios-postinit.sh

# Fail if the generated Xcode project is missing any required patch.
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

# --- iOS release -> TestFlight (macOS + Xcode) ---
# CI runs these on a GitHub macOS runner (.github/workflows/ios-testflight.yml);
# they double as the local `just ios-release` escape hatch.
# SIGNING is explicit (Tauri's automatic iOS signing is unreliable — it emits an
# "Apple Distribution: Tauri (unset)" placeholder that App Store Connect rejects):
#   IOS_CERTIFICATE (base64 .p12) + IOS_CERTIFICATE_PASSWORD + IOS_MOBILE_PROVISION
#   (base64 App Store .mobileprovision).
# UPLOAD uses the App Store Connect API key: APPLE_API_KEY + APPLE_API_ISSUER and the
# matching AuthKey_<id>.p8 in ~/.appstoreconnect/private_keys/. See docs/ios-cicd.md.

# Build a signed, App Store-method IPA (for TestFlight or the App Store). Assumes the
# Xcode project exists: run `cargo tauri ios init` + `just ios-postinit` once first
# (CI does both every run). NOTE: the --export-method token tracks Xcode's names
# (`app-store-connect` on Xcode 15+); confirm once with `cargo tauri ios build --help`.
ios-ipa: ios-check
    # Drop any stale .ipa first (e.g. a pre-rename artifact) so `ios-upload` can't pick it up.
    rm -f apps/identity-wallet/src-tauri/gen/apple/build/arm64/*.ipa
    cd apps/identity-wallet && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios build --export-method app-store-connect

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
