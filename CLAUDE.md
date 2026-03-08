# ezpds

Last verified: 2026-03-07

## Tech Stack
- Language: Rust (stable channel via rust-toolchain.toml)
- Build: Cargo workspace (resolver v2)
- Dev Environment: Nix flake + devenv (direnv integration via .envrc)
- Task Runner: just

## Commands
- `nix develop --impure --accept-flake-config` - Enter dev shell (flags required; devenv needs --impure for CWD detection)
- `cargo build` - Build all crates
- `cargo test` - Run all tests
- `cargo clippy` - Lint
- `cargo fmt --check` - Check formatting

## Dev Environment
- Managed entirely by Nix flake + devenv; do not install tools globally
- direnv auto-activates via `.envrc` (`use flake`)
- Rust toolchain pinned in `rust-toolchain.toml` (stable, with rustfmt + clippy + rust-analyzer)
- Shell provides: just, cargo-audit, sqlite, pkg-config
- `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set automatically by devenv

## Project Structure
- `crates/relay/` - Web relay (axum-based)
- `crates/repo-engine/` - ATProto repo engine
- `crates/crypto/` - Cryptographic operations
- `crates/common/` - Shared types and utilities
- `docs/` - Specs, design plans, implementation plans

## Conventions
- Workspace-level dependency versions in root Cargo.toml; crates use `{ workspace = true }`
- All crates share version (0.1.0) and edition (2021) via workspace.package
- publish = false (not intended for crates.io)

## Boundaries
- Never edit: `flake.lock` by hand (managed by `nix flake update`)
- Never edit: `devenv.local.nix` is gitignored for local overrides only
