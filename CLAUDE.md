# ezpds

Last verified: 2026-03-11

## Tech Stack
- Language: Rust (stable channel via rust-toolchain.toml)
- Build: Cargo workspace (resolver v2)
- Database: SQLite via sqlx 0.8 (runtime-tokio + sqlite features)
- Dev Environment: Nix flake + devenv (direnv integration via .envrc)
- Task Runner: just

## Commands
- `nix develop --impure --accept-flake-config` - Enter dev shell (flags required; --impure for devenv CWD detection, --accept-flake-config activates the Cachix binary cache in nixConfig — without it, a cold build takes 20+ minutes)
- `nix build .#relay --accept-flake-config` - Build relay binary (output at ./result/bin/relay)
- `nix build .#docker-image --accept-flake-config` - Build Docker image tarball (Linux only; output at `./result`; load with `docker load < result`; `docker-image` is not exposed on macOS — use a remote Linux builder or CI)
- `just nix-check` / `nix flake check --impure --accept-flake-config` - Validate NixOS module evaluation and flake structure
- `cargo build` - Build all crates
- `cargo test` - Run all tests
- `cargo clippy --workspace -- -D warnings` - Lint (warnings as errors)
- `cargo fmt --all --check` - Check formatting

## Dev Environment
- Managed entirely by Nix flake + devenv; do not install tools globally
- direnv auto-activates via `.envrc` (`use flake . --impure --accept-flake-config`)
- Rust toolchain pinned in `rust-toolchain.toml` (stable, with rustfmt + clippy + rust-analyzer)
- Shell provides: just, cargo-audit, sqlite (runtime binary + dev headers/library for sqlx's libsqlite3-sys), pkg-config
- `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set automatically by devenv (links sqlx against Nix-provided SQLite instead of bundled)
- Binary cache: devenv.cachix.org (activated by `--accept-flake-config`); speeds up cold shell builds significantly
- nixpkgs pin: `cachix/devenv-nixpkgs/rolling` (devenv's own nixpkgs fork — package versions may differ from upstream nixpkgs.search.dev)

## Project Structure
- `crates/relay/` - Web relay (axum-based)
- `crates/repo-engine/` - ATProto repo engine
- `crates/crypto/` - Cryptographic operations
- `crates/common/` - Shared types and utilities
- `nix/` - Nix packaging and deployment (docker.nix: container image; module.nix: NixOS module)
- `docs/` - Specs, design plans, implementation plans

## Flake Outputs
- `packages.<system>.relay` - Relay binary
- `packages.<system>.docker-image` - Docker image tarball (Linux only)
- `nixosModules.default` - NixOS module exposing `services.ezpds` options (see `nix/CLAUDE.md`)
- `devShells.<system>.default` - Development shell via devenv

## Conventions
- Workspace-level dependency versions in root Cargo.toml; crates use `{ workspace = true }`
- All crates share version (0.1.0) and edition (2021) via workspace.package
- publish = false (not intended for crates.io)

## Boundaries
- Never edit: `flake.lock` by hand (managed by `nix flake update`)
- Never edit: `devenv.local.nix` is gitignored for local overrides only
