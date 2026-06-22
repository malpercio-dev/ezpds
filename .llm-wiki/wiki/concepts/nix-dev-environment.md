---
type: concept
domain: engineering
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-001]
---

# Nix Dev Environment

The development environment for the [[concepts/ezpds-workspace|ezpds workspace]], managed entirely by Nix flake + devenv. Developers must not install tools globally.

## Setup

```bash
# Enter dev shell (--impure for devenv CWD detection, --accept-flake-config for Cachix binary cache)
nix develop --impure --accept-flake-config

# Or use direnv (auto-activates on cd)
direnv allow
```

## What's Provided

- just (task runner)
- cargo-audit
- sqlite (runtime binary + dev headers/library for sqlx)
- pkg-config
- cargo-tauri
- node (22.x)
- pnpm
- rustup (manages Rust toolchain, not Nix's `rust-default`)
- shellcheck

## Key Details

- **Rust via rustup**: Pinned in `rust-toolchain.toml` (stable, with rustfmt + clippy + rust-analyzer + iOS targets). `enterShell` runs `rustup toolchain install` automatically on first entry.
- **Always from workspace root**: `CARGO_HOME` and `RUSTUP_HOME` resolve relative to devenv root. Running `nix develop` from a subdirectory breaks the toolchain.
- **Binary cache**: `devenv.cachix.org` activated by `--accept-flake-config`. Speeds up cold shell builds significantly.
- **`LIBSQLITE3_SYS_USE_PKG_CONFIG=1`**: Set automatically by devenv. Links sqlx against Nix-provided SQLite instead of bundled.
- **nixpkgs pin**: `cachix/devenv-nixpkgs/rolling` (devenv's own fork — package versions may differ from upstream nixpkgs).

## Boundaries

- **Never edit `flake.lock` by hand** — managed by `nix flake update`
- **Never edit `devenv.local.nix`** — gitignored for local overrides only
- **`flake.nix` is intentionally minimal** — only exposes `devShells.<system>.default` and `nixosModules.default`

## Related

- [[concepts/ios-toolchain-resolution|iOS Toolchain Resolution]]
- [[concepts/ezpds-workspace|ezpds Workspace]]
- [[sources/SRC-2026-06-22-001]] — Full dev environment docs
