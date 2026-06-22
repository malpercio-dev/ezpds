# ezpds

Last verified: 2026-06-21

## Tech Stack
- Language: Rust (stable channel via rust-toolchain.toml)
- Build: Cargo workspace (resolver v2)
- Database: SQLite via sqlx 0.8 (runtime-tokio + sqlite features)
- Dev Environment: Nix flake + devenv (direnv integration via .envrc)
- Task Runner: just

## Commands
- `nix develop --impure --accept-flake-config` - Enter dev shell (flags required; --impure for devenv CWD detection, --accept-flake-config activates the Cachix binary cache in nixConfig — without it, a cold build takes 20+ minutes)
- `docker build -t relay .` / `just docker-build` - Build relay OCI image
- `just nix-check` / `nix flake check --impure --accept-flake-config` - Validate NixOS module evaluation and flake structure
- `cargo build` - Build all crates
- `cargo test` - Run all tests
- `cargo clippy --workspace -- -D warnings` - Lint (warnings as errors)
- `cargo fmt --all --check` - Check formatting
- `just ci` - Full local gate (fmt-check, clippy, test, audit) — the same checks CI runs

## CI/CD
CI runs on **tangled spindles** (`.tangled/workflows/`), not GitHub Actions. Three workflows, each running `just ci` first:
- `pr.yaml` — test gate on PRs to `main` (no deploy, no Railway token)
- `staging.yaml` — push to `main` → deploy to the Railway **staging** environment
- `release.yaml` — push a `v*` tag → promote to **production**

Deploys use the Railway CLI (nixpkgs dep) with environment-scoped tokens held as tangled repo secrets; production is reached only via a `v*` tag, never by merging to `main`. Litestream backs up the production SQLite DB. See [docs/deploy.md](docs/deploy.md).

## Dev Environment
- Managed entirely by Nix flake + devenv; do not install tools globally
- direnv auto-activates via `.envrc` (`use flake . --impure --accept-flake-config`)
- **Always run `nix develop` from the workspace root**, not from a subdirectory — `CARGO_HOME` and `RUSTUP_HOME` resolve relative to devenv root
- Rust toolchain managed by **rustup** (not Nix's `rust-default`); pinned in `rust-toolchain.toml` (stable, with rustfmt + clippy + rust-analyzer + iOS targets). On first shell entry, `enterShell` runs `rustup toolchain install` automatically.
- Shell provides: just, cargo-audit, sqlite (runtime binary + dev headers/library for sqlx's libsqlite3-sys), pkg-config, cargo-tauri, node (22.x), pnpm, rustup, shellcheck
- `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set automatically by devenv (links sqlx against Nix-provided SQLite instead of bundled)
- `DEVELOPER_DIR` and the Apple iOS toolchain are resolved dynamically (no hardcoded Xcode paths): `enterShell` sources `apps/identity-wallet/scripts/ios-env.sh`, which runs `/usr/bin/xcode-select -p` to point `DEVELOPER_DIR` at the active Xcode (Nix's Darwin hooks otherwise clobber it to a stub SDK). The same script is sourced by the patched Xcode Run Script phase, so CLI and Xcode builds resolve the toolchain identically. iOS-host `CC`/`AR`/linker overrides are gated on `EZPDS_IOS_BUILD=1` (set only by the `just ios-*` recipes and the Xcode Run Script), so a plain `cargo build --workspace` / `cargo run -p relay` is unaffected.
- Binary cache: devenv.cachix.org (activated by `--accept-flake-config`); speeds up cold shell builds significantly
- nixpkgs pin: `cachix/devenv-nixpkgs/rolling` (devenv's own nixpkgs fork — package versions may differ from upstream nixpkgs.search.dev)

## Project Structure
- `apps/identity-wallet/` - Tauri v2 mobile app (iOS)
- `crates/relay/` - Web relay (axum-based)
- `crates/repo-engine/` - ATProto repo engine
- `crates/crypto/` - Cryptographic operations (P-256 key generation, did:key derivation, AES-256-GCM encryption, did:plc genesis ops and verification)
- `crates/common/` - Shared types and utilities
- `nix/` - Nix deployment (module.nix: NixOS module for OCI container)
- `docs/` - Specs, design plans, implementation plans

## Mobile

- `apps/identity-wallet/` — Tauri v2 iOS app (SvelteKit 2 + Svelte 5 frontend, Rust backend)
- Developer setup and iOS workstation guide: see [`apps/identity-wallet/CLAUDE.md`](apps/identity-wallet/CLAUDE.md)
- iOS build commands: `just ios-dev` / `just ios-build` (run from repo root; macOS + Xcode required). Toolchain resolved by `apps/identity-wallet/scripts/ios-env.sh`; patches re-applied via `just ios-postinit` after `cargo tauri ios init`.

## Flake Outputs
- `nixosModules.default` - NixOS module for relay OCI container deployment (see `nix/CLAUDE.md`)
- `devShells.<system>.default` - Development shell via devenv

## Bruno API Collection
- `bruno/` - Bruno HTTP client collection for all relay endpoints
- Open in Bruno desktop app; select the `local` environment and set `adminToken` to your relay admin token
- **Mandatory:** When adding, removing, or changing any route (path, method, request body, response shape, auth), update the corresponding `.bru` file in `bruno/`. New routes get a new `.bru` file with the next `seq` number.

## Relay Architecture
See [`crates/relay/CLAUDE.md`](crates/relay/CLAUDE.md) for relay-specific module structure,
hard rules (route isolation, pattern comments, DB ownership), and step-by-step guides for
adding routes and DB queries.

## Conventions
- Workspace-level dependency versions in root Cargo.toml; crates use `{ workspace = true }`
- All crates share version (0.1.0) and edition (2021) via workspace.package
- publish = false (not intended for crates.io)
- **No ticket or AC references in source code.** Do not add comments like `// MM-123`, `// AC2.1:`, or `// MM-84.AC3: description` to `.rs` files or CLAUDE.md files. Design plans and test plans in `docs/` are the right home for ticket traceability. Source code comments should describe *why* in terms of the system, not which ticket required it.

## Boundaries
- Never edit: `flake.lock` by hand (managed by `nix flake update`)
- Never edit: `devenv.local.nix` is gitignored for local overrides only
- `flake.nix` is intentionally minimal: it exposes only the devenv `devShells.<system>.default` and `nixosModules.default` (no crane/rust-overlay inputs, no `packages.<system>.*` build outputs). The relay binary is built via the root `Dockerfile` (`cargo build --release --locked -p relay`), not by Nix — deploy as an OCI image, not a Nix-built binary. See `docs/deploy.md`.
