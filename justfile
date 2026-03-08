# Check all crates for errors without producing binaries
check:
    cargo check --workspace

# Build all crates
build:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Format all code
fmt:
    cargo fmt --all

# Check formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# Lint with warnings as errors
clippy:
    cargo clippy --workspace -- -D warnings

# Run the relay server
run-relay:
    cargo run -p relay

# Build the relay binary via Nix
nix-build:
    nix build .#relay --accept-flake-config

# Build the Docker image via Nix (Linux only)
docker-build:
    nix build .#docker-image --accept-flake-config

# Run the full CI pipeline locally
ci: fmt-check clippy test
    cargo audit
