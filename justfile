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

# Build the relay binary via Nix
nix-build:
    nix build .#relay --accept-flake-config

# Build the Docker image via Nix (Linux only; on macOS use a remote Linux builder or CI)
docker-build:
    nix build .#docker-image --accept-flake-config

# Run the full CI pipeline locally
ci: fmt-check clippy test
    cargo audit

# Validate NixOS module evaluation (flake structure check).
# For full smoke tests (ExecStart composition, option enforcement, configFile
# escape hatch), run the nix eval commands in phase_03.md Tasks 2-5 manually.
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

# Launch the app in the iOS Simulator (verifies patches first).
ios-dev: ios-check
    cd apps/identity-wallet && EZPDS_IOS_BUILD=1 cargo tauri ios dev

# Build the iOS app for the Simulator (verifies patches first).
ios-build: ios-check
    cd apps/identity-wallet && EZPDS_IOS_BUILD=1 cargo tauri ios build --debug
