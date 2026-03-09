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
