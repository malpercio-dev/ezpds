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
    cargo clippy --workspace -- -D warnings

run-relay:
    cargo run -p relay

# Build the Docker image locally (requires Docker)
docker-build:
    docker build -t relay:latest .

# Run the full CI pipeline locally
ci: fmt-check clippy test
    cargo audit

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

# Launch the app in the iOS Simulator (verifies patches first).
ios-dev: ios-check
    cd apps/identity-wallet && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios dev

# Build the iOS app for the Simulator (verifies patches first).
ios-build: ios-check
    cd apps/identity-wallet && export EZPDS_IOS_BUILD=1 && . scripts/ios-env.sh && cargo tauri ios build --debug
