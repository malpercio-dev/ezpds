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
