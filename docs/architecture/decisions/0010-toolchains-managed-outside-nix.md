# ADR-0010: Manage the compiler toolchains outside Nix (rustup + dynamic Apple toolchain)

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [`AGENTS.md`](../../../AGENTS.md) · [`apps/identity-wallet/AGENTS.md`](../../../apps/identity-wallet/AGENTS.md) · [`apps/identity-wallet/scripts/ios-env.sh`](../../../apps/identity-wallet/scripts/ios-env.sh) · [`docs/archive/design-plans/2026-06-20-denix-ios-build.md`](../../archive/design-plans/2026-06-20-denix-ios-build.md)

## Context

The dev environment is a devenv flake, so the natural default is to let Nix
manage the Rust compiler too (`languages.rust` → Nix's `rust-default`). Two
problems make that unworkable for this project:

- **iOS cross-compilation.** `rust-default` ships stdlibs only for standard host
  targets. The iOS Simulator needs `aarch64-apple-ios-sim` stdlib, which Nix
  doesn't package. A moving `stable` channel would also drift local vs CI on
  rustfmt/clippy.
- **The Apple toolchain.** Nix's Darwin stdenv exports `DEVELOPER_DIR`/`SDKROOT`
  pointing at an apple-sdk **stub**, and both `xcode-select -p` and `xcrun` honor
  those env vars *above* the system Xcode — so even calling them by absolute path
  returns the stub, breaking `simctl` and the iOS link step.

## Decision

Manage the compiler toolchains **outside Nix**:

- **Rust via `rustup`**, pinned to an **exact** version in `rust-toolchain.toml`
  (with the iOS targets), installed on first shell entry. Project-local
  `RUSTUP_HOME`/`CARGO_HOME` keep it isolated.
- **The Apple toolchain resolved dynamically** by `scripts/ios-env.sh`
  (`xcode-select`/`xcrun`) with **no hardcoded Xcode paths**. It strips
  `DEVELOPER_DIR`/`SDKROOT` *only when they point into `/nix/store`*, so the real
  Xcode wins. Host-target `CC`/`AR`/linker overrides are gated on
  `EZPDS_IOS_BUILD=1`, so a plain `cargo build --workspace` / `cargo run -p pds`
  is untouched by the iOS overrides.

## Consequences

- **iOS builds work** (Simulator stdlibs present) and **local == CI** on
  rustfmt/clippy because the version is pinned, not tracking a channel.
- **No hardcoded Xcode paths** — the build follows whatever `xcode-select`
  points at; the same `ios-env.sh` is sourced by the dev shell and the Xcode Run
  Script phase, so CLI and Xcode builds resolve identically.
- **Complexity lives in `ios-env.sh`** (the `/nix/store` stripping, the
  `EZPDS_IOS_BUILD` gating). This is load-bearing and documented in the wallet
  AGENTS.md Troubleshooting section.
- Nix remains responsible for the *shell* (tools, headers, caches), just not the
  compilers.

## Alternatives considered

- **Nix-managed Rust (`rust-default`).** Rejected: no iOS stdlibs, and a moving
  channel diverges local/CI on lint/format.
- **Hardcoded Xcode/SDK paths in a committed config.** Rejected: brittle across
  machines and Xcode versions; dynamic resolution via `xcrun` is portable.
