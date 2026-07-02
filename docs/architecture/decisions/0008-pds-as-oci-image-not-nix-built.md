# ADR-0008: Ship the PDS as an OCI image built by the Dockerfile; keep the flake minimal

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0009](0009-deploy-via-railway-github-integration.md) · [`../../deploy.md`](../../deploy.md) · [`flake.nix`](../../../flake.nix) · [`Dockerfile`](../../../Dockerfile)

## Context

The repo already uses Nix (a devenv flake) for the dev shell. The obvious next
step would be to also *build* the release binary with Nix (crane / rust-overlay)
and deploy a Nix-built artifact — reproducible, one toolchain. But that couples
the deploy to Nix, adds crane/rust-overlay inputs, and cold builds are slow
without a populated Nix build cache.

## Decision

Build the PDS binary via the root **`Dockerfile`** (`cargo build --release
--locked -p pds`) and deploy it as an **OCI image**. Keep **`flake.nix`
intentionally minimal**: it exposes only `devShells.<system>.default` and
`nixosModules.default` — no crane/rust-overlay inputs, no `packages.<system>.*`
build outputs. The NixOS module consumes the OCI image; it does not build the
binary.

## Consequences

- **Standard container deploy.** Railway (ADR-0009) builds the Dockerfile
  directly; any OCI host can run the image.
- **Nix stays scoped to what it's good at here** — the reproducible dev shell and
  the NixOS deployment module — without owning the release build.
- **`--locked`** ties the release build to `Cargo.lock`, consistent with the
  CI lock-check.
- **Boundary to maintain:** don't add `packages.*` build outputs to the flake;
  the Dockerfile is the build path.

## Alternatives considered

- **Nix-built binary (crane/rust-overlay).** Reproducible and single-toolchain,
  but heavyweight, slow on cold caches, and couples deployment to Nix. Rejected.
- **Deploy a bare binary (no container).** Rejected: an OCI image is the portable,
  host-agnostic unit and is what the deploy platform consumes.
