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

# Verify Cargo.lock is in sync with the Cargo.toml manifests. `--locked` makes cargo
# error instead of silently regenerating the lockfile, so accidental dependency drift
# (an edited manifest with a stale lock) fails CI instead of being merged. `metadata`
# resolves the whole workspace — including the iOS app that the Linux ci-pds build
# excludes — so the lockfile is verified end-to-end even where it cannot be compiled.
lock-check:
    cargo metadata --locked --format-version 1 > /dev/null

# Run the full CI pipeline locally (all crates; use on macOS where the iOS app builds)
ci: fmt-check lock-check clippy test audit

# CI gate for the Linux pds pipeline (tangled spindles). Excludes the iOS apps
# (identity-wallet, admin-companion), which need the Apple toolchain (security-framework)
# absent in CI; the mobile apps are built and checked via `just ios-*` / `just admin-*` on macOS.
ci-pds: fmt-check
    just lock-check
    cargo clippy --workspace --exclude identity-wallet --exclude admin-companion --all-targets -- -D warnings
    cargo test --workspace --exclude identity-wallet --exclude admin-companion
    just audit

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

# Cut a release: create the annotated tag v{workspace version} and push it to both remotes.
# The tangled push triggers release.yaml -> production. Derives the tag from Cargo.toml, so it
# always matches the reported PDS version. Run from a clean, synced `main` (see sync-tangled-main).
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
    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
      echo "✗ tag ${tag} already exists — bump the version with 'just set-version' first" >&2; exit 1
    fi
    github_url="$(git remote get-url --push --all origin | grep -i github | head -n1)"
    tangled_url="$(git remote get-url --push --all origin | grep -iv github | head -n1)"
    echo "→ tagging ${tag} at $(git rev-parse --short HEAD)…"
    git tag -a "${tag}" -m "Release ${tag}"
    echo "→ pushing ${tag} → tangled (triggers production deploy)…"
    git push "${tangled_url}" "${tag}"
    echo "→ pushing ${tag} → github (record)…"
    git push "${github_url}" "${tag}"
    echo "✓ released ${tag}"

# Sync GitHub `main` (canonical) -> tangled `main`. PRs are merged on GitHub; tangled
# `main` does not auto-update, so it drifts and needs periodic syncing. This refuses
# anything that is not a clean fast-forward, so it can never clobber tangled history.
# NOTE: pushing tangled `main` triggers the staging deploy (just ci-pds -> Railway).
# Pre-validate first with `just ci-pds` if the pds changed.
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

    # Fetch each SHA from its resolved push URL, NOT from `origin` — `git fetch origin`
    # uses origin's *fetch* URL, which may be GitHub. Reading the "tangled" SHA from there
    # would make it equal the GitHub SHA, so the equality check below would falsely report
    # "already in sync" and never push.
    echo "→ fetching tangled main…"
    git fetch "$tangled_url" main
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

    # Fast-forward local main, then push the tangled URL ONLY (origin would also push to
    # GitHub — harmless but redundant). An EXIT trap restores the branch you started on for
    # EVERY exit path: if the ff merge or push fails, `set -e` aborts mid-flight and would
    # otherwise strand you on `main`. A failed restore warns loudly rather than silently
    # swallowing the error, so a wrong-branch end state is never hidden.
    start_branch="$(git rev-parse --abbrev-ref HEAD)"
    restore_branch() {
      if [ "$start_branch" != "main" ] && [ "$(git rev-parse --abbrev-ref HEAD)" != "$start_branch" ]; then
        git checkout "$start_branch" \
          || echo "⚠ could not restore branch '$start_branch' — you are on $(git rev-parse --abbrev-ref HEAD)" >&2
      fi
    }
    trap restore_branch EXIT

    git checkout main
    git merge --ff-only "$github"
    echo
    echo "→ pushing main → tangled (this triggers the staging deploy)…"
    git push "$tangled_url" main

    # Verify against the tangled URL directly (same reason as the fetch above).
    echo "→ verifying tangled main…"
    git fetch "$tangled_url" main
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

# --- iOS (admin-companion) — run from repo root; requires macOS + Xcode ---
# The operator console, a second iOS app. Same toolchain seam as identity-wallet;
# the scripts are path-relative so they patch this app's own generated Xcode project.

# Re-apply the surviving Tauri/macOS patches to admin-companion's generated Xcode
# project. Run once after every `cargo tauri ios init`. Idempotent.
admin-postinit:
    apps/admin-companion/scripts/ios-postinit.sh

# Fail if admin-companion's generated Xcode project is missing any required patch.
admin-check:
    apps/admin-companion/scripts/ios-check.sh

# Launch the admin console on the iOS Simulator (verifies patches first).
# Pass a simulator name to force the Simulator, e.g. `just admin-dev "iPhone 17 Pro Max"`.
admin-dev device="": admin-check
    cd apps/admin-companion && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && if [ -n "{{device}}" ]; then cargo tauri ios dev "{{device}}"; else cargo tauri ios dev; fi

# Build the admin console for the Simulator (verifies patches first).
admin-build: admin-check
    cd apps/admin-companion && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios build --debug
