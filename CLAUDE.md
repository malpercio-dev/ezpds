# ezpds

Last verified: 2026-03-14

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
- **Always run `nix develop` from the workspace root**, not from a subdirectory — `CARGO_HOME` and `RUSTUP_HOME` resolve relative to devenv root
- Rust toolchain managed by **rustup** (not Nix's `rust-default`); pinned in `rust-toolchain.toml` (stable, with rustfmt + clippy + rust-analyzer + iOS targets). On first shell entry, `enterShell` runs `rustup toolchain install` automatically.
- Shell provides: just, cargo-audit, sqlite (runtime binary + dev headers/library for sqlx's libsqlite3-sys), pkg-config, cargo-tauri, node (22.x), pnpm, rustup
- `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set automatically by devenv (links sqlx against Nix-provided SQLite instead of bundled)
- `DEVELOPER_DIR` is set to `/Applications/Xcode.app/Contents/Developer` in `enterShell` — Nix's Darwin hooks override it to a stub SDK; the re-export restores real Xcode for iOS tooling (xcrun, simctl, xcodebuild)
- Binary cache: devenv.cachix.org (activated by `--accept-flake-config`); speeds up cold shell builds significantly
- nixpkgs pin: `cachix/devenv-nixpkgs/rolling` (devenv's own nixpkgs fork — package versions may differ from upstream nixpkgs.search.dev)

## Project Structure
- `apps/identity-wallet/` - Tauri v2 mobile app (iOS)
- `crates/relay/` - Web relay (axum-based)
- `crates/repo-engine/` - ATProto repo engine
- `crates/crypto/` - Cryptographic operations (P-256 key generation, did:key derivation, AES-256-GCM encryption, did:plc genesis ops and verification)
- `crates/common/` - Shared types and utilities
- `nix/` - Nix packaging and deployment (docker.nix: container image; module.nix: NixOS module)
- `docs/` - Specs, design plans, implementation plans

## Mobile

- `apps/identity-wallet/` — Tauri v2 iOS app (SvelteKit 2 + Svelte 5 frontend, Rust backend)
- Developer setup and iOS workstation guide: see [`apps/identity-wallet/CLAUDE.md`](apps/identity-wallet/CLAUDE.md)

## Flake Outputs
- `packages.<system>.relay` - Relay binary
- `packages.<system>.docker-image` - Docker image tarball (Linux only)
- `nixosModules.default` - NixOS module exposing `services.ezpds` options (see `nix/CLAUDE.md`)
- `devShells.<system>.default` - Development shell via devenv

## Bruno API Collection
- `bruno/` - Bruno HTTP client collection for all relay endpoints
- Open in Bruno desktop app; select the `local` environment and set `adminToken` to your relay admin token
- **Mandatory:** When adding, removing, or changing any route (path, method, request body, response shape, auth), update the corresponding `.bru` file in `bruno/`. New routes get a new `.bru` file with the next `seq` number.

## Conventions
- Workspace-level dependency versions in root Cargo.toml; crates use `{ workspace = true }`
- All crates share version (0.1.0) and edition (2021) via workspace.package
- publish = false (not intended for crates.io)
- **No ticket or AC references in source code.** Do not add comments like `// MM-123`, `// AC2.1:`, or `// MM-84.AC3: description` to `.rs` files or CLAUDE.md files. Design plans and test plans in `docs/` are the right home for ticket traceability. Source code comments should describe *why* in terms of the system, not which ticket required it.

## Boundaries
- Never edit: `flake.lock` by hand (managed by `nix flake update`)
- Never edit: `devenv.local.nix` is gitignored for local overrides only
- `flake.nix` `buildDepsOnly` is scoped to relay-related crates (`relay`, `repo-engine`, `crypto`, `common`). Adding a workspace crate with native dependencies not in `commonArgs.buildInputs` (e.g. Tauri's webkit2gtk/Apple frameworks) requires either adding the crate to the scope list or adding its build inputs to `commonArgs`.
