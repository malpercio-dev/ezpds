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
