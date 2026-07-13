# Relay Containerization (Docker + Railway, NixOS-compatible) Design

## Summary

The relay's build and deploy story is being migrated from a single Nix-native path (crane + `nix/docker.nix`) to an OCI image as the universal deployment substrate, while leaving everything else — the dev shell, the iOS app, relay behavior, and the NixOS colmena workflow itself — completely untouched. The approach is strictly additive: a multi-stage `Dockerfile` builds a self-contained `relay` binary (bundled SQLite via `libsqlite3-sys`, no system OpenSSL, TLS via rustls) and produces a minimal runtime image configured entirely from environment variables. That same image then serves double duty — Railway builds and runs it directly from the committed `Dockerfile`, while the NixOS lab host runs it through `virtualisation.oci-containers`, preserving the existing colmena-based deploy workflow. The only thing that actually disappears is the Nix-native build (crane package + `nix/docker.nix`), which is the sole hard coupling between the relay and the Nix world.

The config and secrets story is unified across all three environments by the relay's existing `EZPDS_*` env-var convention: Railway injects `$PORT` and seals secrets as service variables; the NixOS module injects them via `environmentFiles` from agenix/sops-nix; local runs use `--env-file`. Reproducibility is preserved at the pinned-base-image-digest + `Cargo.lock` level — an explicit, accepted step down from flake-locked builds, documented as a deliberate tradeoff rather than an omission. The Railway deployment requires a persistent volume mounted at `EZPDS_DATA_DIR` to preserve the SQLite database across redeploys; horizontal scaling is explicitly out of scope until the future per-user-DB story.

## Definition of Done

- A committed multi-stage `Dockerfile` builds the `relay` binary and produces a small runtime image that runs with **no Nix and no system OpenSSL**, configured entirely from environment variables (12-factor): HTTP port (including Railway's injected `$PORT`), `public_url`, `data_dir`, and the signing-key master secret — the secret is injected at runtime and **never baked into the image**.
- The relay runs healthy in a local container (`/xrpc/_health` returns 200) with its SQLite data persisted to a mounted volume across container restarts.
- The relay deploys to **Railway** from the committed `Dockerfile`, with a persistent volume mounted at the data dir and config/secrets supplied via Railway variables; the public URL resolves and `/xrpc/_health` is green.
- The **NixOS lab host continues to deploy via colmena**, now running the *same* container image through `virtualisation.oci-containers`. `services.ezpds` is reworked (or wrapped) accordingly; the crane relay build (`flake.nix`) and `nix/docker.nix` are retired or explicitly deprecated.
- Reproducibility is preserved at the **pinned-base-image-digest + `Cargo.lock`** level, documented as an explicit, accepted downgrade from flake-locked builds.
- Docs (`nix/AGENTS.md`, root `AGENTS.md` commands, deploy notes) describe the Docker/Railway workflow and the retained NixOS-via-`oci-containers` path. The Bruno collection and health endpoints are unchanged.
- No relay behavior change beyond config/TLS wiring. The single-instance SQLite model is unchanged and documented (Railway = one instance + volume; no horizontal scale until the per-user-DB/Postgres story lands).

## Acceptance Criteria

### relay-containerization.AC1: Container builds & runs the relay — no Nix, no OpenSSL, env-configured
- **relay-containerization.AC1.1 Success:** `docker build` from the committed Dockerfile produces a relay image with no Nix involved.
- **relay-containerization.AC1.2 Success:** `cargo build --release -p relay` succeeds with `LIBSQLITE3_SYS_USE_PKG_CONFIG` unset (bundled SQLite compiled from source).
- **relay-containerization.AC1.3 Success:** the relay's `reqwest` uses rustls; the runtime image contains no `libssl`/OpenSSL.
- **relay-containerization.AC1.4 Success:** the relay starts from environment variables alone (no `--config` file) and binds the port given by `$PORT`.
- **relay-containerization.AC1.5 Edge:** `EZPDS_SIGNING_KEY_MASTER_KEY` is supplied at runtime and is absent from both the image layers and git.

### relay-containerization.AC2: Stateful & healthy locally
- **relay-containerization.AC2.1 Success:** `docker run` with a volume mounted at `EZPDS_DATA_DIR` → `/xrpc/_health` returns 200.
- **relay-containerization.AC2.2 Success:** data persists across a container restart (same volume reuses the SQLite DB; migrations idempotent, no data loss).

### relay-containerization.AC3: Railway deployment
- **relay-containerization.AC3.1 Success:** Railway builds the committed Dockerfile and deploys; the public domain serves `/xrpc/_health` 200.
- **relay-containerization.AC3.2 Success:** a persistent Railway volume mounted at the data dir survives a redeploy.
- **relay-containerization.AC3.3 Success:** `public_url` and the master key are supplied via Railway variables; neither is committed to git.

### relay-containerization.AC4: NixOS via oci-containers (colmena still deploys) + flake cleanup
- **relay-containerization.AC4.1 Success:** `nix/module.nix` runs the relay as a `virtualisation.oci-containers` service; a colmena deploy to the lab host serves `/xrpc/_health`.
- **relay-containerization.AC4.2 Success:** the secret is injected via `environmentFiles` (agenix/sops-nix), not stored in the Nix store.
- **relay-containerization.AC4.3 Success:** the crane `relay` build and the `docker-image`/`nix/docker.nix` output are removed or deprecated; `nix flake check` passes; `devShells` and `nixosModules.default` still evaluate.

### relay-containerization.AC5: Reproducibility & docs
- **relay-containerization.AC5.1 Success:** the Dockerfile pins base images **by digest**, and the build uses the committed `Cargo.lock`.
- **relay-containerization.AC5.2 Success:** `nix/AGENTS.md`, root `AGENTS.md` (Commands + Flake Outputs), and a deploy note describe the Docker/Railway/oci-containers workflow; no doc presents the removed Nix build outputs as current; "Last verified" dates are bumped.

### relay-containerization.AC6: No behavior/scope regression
- **relay-containerization.AC6.1 Success:** relay routes/behavior are unchanged — `cargo test --workspace` (relay tests) pass.
- **relay-containerization.AC6.2 Success (negative):** the SQLite single-instance model and schema are unchanged; the devenv dev shell and the iOS app are untouched by this plan.

## Glossary

- **Railway**: a PaaS that builds and deploys containers from a `Dockerfile` committed to the repo, injects a dynamic `$PORT` env var, and provides persistent volumes and sealed service variables for secrets. No registry or build machine needed — Railway itself is the builder.
- **colmena**: a NixOS deployment tool (similar in role to NixOps or morph) used here to push the updated `nixosModules.default` configuration to the lab host. This plan keeps colmena as the deploy mechanism; only what the module runs changes (OCI container instead of the Nix-built binary).
- **`virtualisation.oci-containers` (NixOS)**: a NixOS module that runs OCI-compatible container images (Docker/Podman) as systemd services, configured declaratively. Lets NixOS host containers without giving up its reproducible system model.
- **multi-stage Docker build**: a `Dockerfile` technique where a heavyweight stage (here: a Rust toolchain image) compiles the binary, and a final lightweight stage copies only the resulting artifact into a minimal runtime image, discarding the compiler and build-time tooling.
- **distroless / debian-slim**: minimal container base images for runtime stages. `debian:<tag>-slim` is a stripped Debian with just the C library and essentials; distroless goes further and omits even a shell. Both shrink attack surface and image size.
- **rustls vs. native-tls / OpenSSL**: `rustls` is a pure-Rust TLS implementation; `native-tls` delegates to system OpenSSL. Using rustls means no `libssl` dependency at runtime — the binary is self-contained for TLS and the image needs no OpenSSL package.
- **`libsqlite3-sys` bundled**: when `LIBSQLITE3_SYS_USE_PKG_CONFIG` is unset, `libsqlite3-sys` compiles SQLite from vendored C source directly into the binary, eliminating any dependency on a system `libsqlite3.so`. The devenv shell sets the variable to link Nix's SQLite; the Dockerfile simply leaves it unset.
- **12-factor config**: the twelve-factor app methodology's config rule — all configuration comes from environment variables, not files baked into the image — so the same image runs in any environment without rebuilding.
- **GHCR (GitHub Container Registry)**: `ghcr.io`, GitHub's OCI image registry. The recommended distribution path (Option A) `docker push`es the built image here so both Railway and the NixOS host can pull the same pinned-by-digest artifact.
- **`$PORT` (Railway)**: Railway injects a dynamic `PORT` env var specifying which port the container must listen on. The relay must bind `0.0.0.0:$PORT` rather than a hardcoded port.
- **persistent volume (Railway)**: a Railway storage primitive that survives container redeploys. Required because the relay's SQLite database must not be lost when the container restarts or a new image deploys.
- **crane (Nix)**: a Nix library for building Rust artifacts (and, with `dockerTools`, images) from Nix derivations. Used in the current `flake.nix` to build the relay; this plan retires it in favor of the standard `Dockerfile`.
- **agenix / sops-nix**: NixOS secret-management tools that decrypt secrets at activation time and expose them as files on the host (e.g. `/run/secrets/relay-master-key`). The `oci-containers` module's `environmentFiles` points at such a file to inject `EZPDS_SIGNING_KEY_MASTER_KEY` without storing it in the Nix store or image.
- **image digest pinning**: referencing a base image by its content-addressable SHA-256 digest (`FROM rust@sha256:…`) rather than a mutable tag like `latest`, so the build is reproducible even if the upstream tag moves.

## Architecture

### Goal

Make a portable OCI image the **universal deployment substrate** for the relay, so infrastructure can be experimented with on Railway (and any container host) **without losing the existing colmena/NixOS path**. A `Dockerfile`-built image runs on Railway *and* on the NixOS lab host via `virtualisation.oci-containers` — so this is additive optionality, not a migration away from NixOS. The only thing fundamentally retired is the Nix-native *build* of the relay (crane + `nix/docker.nix`), which is the sole hard coupling to the Nix world.

### Runtime contract (the container's interface)

The image is configured exclusively through environment variables so the same artifact runs on Railway, locally, and under `oci-containers`:

```
PORT / EZPDS_PORT          HTTP listen port. Must honor Railway's injected $PORT.
EZPDS_PUBLIC_URL           Public URL the relay advertises (e.g. https://relay.up.railway.app).
EZPDS_DATA_DIR             SQLite data directory; MUST be a mounted volume for persistence.
EZPDS_SIGNING_KEY_MASTER_KEY   Secret; injected at runtime only. Never in the image or git.
RUST_LOG                   Log level (default info).
```

- Listens on `0.0.0.0:$PORT`. Exposes `/xrpc/_health` for platform health checks.
- The exact env-var names/precedence are confirmed during implementation against the relay's config loader (`crates/relay/src/main.rs` / `app.rs`); if the loader doesn't yet map `$PORT`, that wiring is added in Phase 1.

### Image shape

Multi-stage build, pinned by digest for reproducibility:
1. **Build stage** — `rust:<pinned>` (or `cargo-chef` for dep caching): `cargo build --release -p relay`. SQLite is compiled from source via `libsqlite3-sys` bundled (achieved simply by **not** setting `LIBSQLITE3_SYS_USE_PKG_CONFIG`).
2. **Runtime stage** — minimal base (`debian:<pinned>-slim` or distroless): the `relay` binary, `ca-certificates`, `tzdata`, a non-root user, `EXPOSE`, `ENTRYPOINT ["/usr/local/bin/relay"]`. No OpenSSL (see TLS), no Nix, no build toolchain.

### TLS simplification

The relay currently uses `reqwest` with workspace default features = **native-tls (OpenSSL)**. Switching the relay to **rustls** (mirroring `apps/identity-wallet`, which already uses `rustls-tls`) removes the runtime OpenSSL dependency, shrinking the image and avoiding `libssl` version drift. Fallback if rustls causes any issue: keep native-tls and install `libssl` + `ca-certificates` in the runtime stage. Recommended: rustls.

### Image distribution (the one real sub-decision)

Railway builds the image directly from the repo `Dockerfile` — no registry needed there. The NixOS host's `oci-containers` needs the *same* image from somewhere:
- **Option A (recommended): publish to GHCR**, NixOS pulls `ghcr.io/<owner>/relay:<tag>` by digest. Clean separation of build and run; both Railway and the lab host consume a known artifact. Adds a publish step (manual `docker push` or a tiny GH Action).
- **Option B: build locally on the lab host** from the same `Dockerfile` (or a thin Nix derivation wrapping `docker build`). No registry, but the host needs build tooling and rebuilds itself.

This is flagged as a decision in the implementation plan's Phase 5; default to Option A unless you'd rather avoid a registry.

### Secrets per target

`EZPDS_SIGNING_KEY_MASTER_KEY` (and any future secrets) are injected at runtime, never in the image:
- **Railway**: service variable (sealed).
- **NixOS/oci-containers**: `environmentFiles` sourced from agenix/sops-nix — consistent with the existing module's agenix/sops escape-hatch philosophy (`nix/module.nix` `configFile`).
- **Local**: `--env-file` / `-e`.

### What is retired vs. kept

| Retired / deprecated | Kept / gained |
|---|---|
| `flake.nix` crane `relay` package build | `flake.nix` dev shell (`devShells`) — optional, unaffected |
| `nix/docker.nix` (Nix-built image) | colmena deploys to the NixOS lab host (now an `oci-containers` service) |
| Flake-locked bit-reproducible relay build | Reproducible-enough: pinned base digest + `Cargo.lock` |
| | **New: Railway (and any container host) deploys from the same image** |

> The devenv dev shell is a *separate* axis and is out of scope here — keep it or drop it independently. This plan changes only the relay's **build + deploy**, not local development.

## Existing Patterns

- **Config precedence already env-aware**: `devenv.nix` sets `EZPDS_CONFIG`, `EZPDS_DATA_DIR`, `EZPDS_PUBLIC_URL`, `EZPDS_SIGNING_KEY_MASTER_KEY`, `RUST_LOG`, implying the relay reads `EZPDS_*` env vars (verified further in implementation). The container leans on this rather than inventing new config.
- **NixOS module already isolates config + secrets**: `nix/module.nix` generates a TOML config and supports a `configFile` escape hatch for agenix/sops. The `oci-containers` rework preserves the secret-injection philosophy via `environmentFiles`.
- **rustls precedent**: `apps/identity-wallet/src-tauri/Cargo.toml` already uses `reqwest` with `default-features = false` + `rustls-tls` for the same "no OpenSSL" reason — the relay follows the established in-repo pattern.
- **SQLite single-instance model**: per [MEMORY] and `crates/relay` design, the server DB uses a single connection pool; the container keeps this — one instance + a volume, no horizontal scale.
- **`nix/docker.nix` runtime contents** (`relay`, `sqlite.out`, `cacert`, `tzdata`, `SSL_CERT_FILE`, `TZDIR`) are the reference for what the Dockerfile runtime stage must provide (CA certs, tzdata), minus the Nix specifics.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Relay container-readiness (rustls, bundled sqlite, 12-factor config)
**Goal:** Make the relay build and run cleanly in a non-Nix container, configured fully from env (including Railway's `$PORT`), with no OpenSSL.

**Components:**
- `crates/relay` (and/or workspace `Cargo.toml`): switch `reqwest` to `rustls-tls` (no default OpenSSL TLS).
- Relay config loader (`crates/relay/src/main.rs` / `app.rs`): confirm/extend env mapping so `EZPDS_PORT`/`$PORT`, `EZPDS_PUBLIC_URL`, `EZPDS_DATA_DIR`, `EZPDS_SIGNING_KEY_MASTER_KEY` configure a running instance with no `--config` file required. Add `$PORT` support if missing.
- Confirm `sqlx`/`libsqlite3-sys` compiles bundled SQLite when `LIBSQLITE3_SYS_USE_PKG_CONFIG` is unset.

**Dependencies:** None.

**Done when:** `cargo build --release -p relay` succeeds without `LIBSQLITE3_SYS_USE_PKG_CONFIG`; the relay starts from env vars alone (no config file) and binds the port given by `$PORT`; existing relay tests pass.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Multi-stage Dockerfile
**Goal:** A reproducible, small image that runs the relay with no Nix.

**Components:**
- `Dockerfile` (repo root or `docker/`): pinned-by-digest build stage (`cargo build --release -p relay`) + minimal runtime stage (binary, `ca-certificates`, `tzdata`, non-root user, `EXPOSE`, `ENTRYPOINT`).
- `.dockerignore` excluding build artifacts and the SvelteKit frontend (`target/`, `.devenv/`, `.git/`, `result`, `**/node_modules`, `apps/identity-wallet/{.svelte-kit,build,static,dist,src-tauri/gen}`). It must **keep** all Cargo manifests, `crates/`, `Cargo.lock`, `rust-toolchain.toml`, and `apps/identity-wallet/{src-tauri,swift-rs-patch}` — Cargo resolves the whole workspace and the `swift-rs` `[patch.crates-io]` path even for `-p relay`.

**Dependencies:** Phase 1.

**Done when:** `docker build` produces an image; `docker run` with the runtime env vars starts the relay; image contains no OpenSSL/Nix/build toolchain.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Local container verification (volume + health)
**Goal:** Prove the container is a correct, stateful relay locally before any cloud deploy.

**Components:**
- A documented `docker run` invocation (or `compose.yaml`) mounting a volume at `EZPDS_DATA_DIR` and passing config/secret via env.

**Dependencies:** Phase 2.

**Done when:** `/xrpc/_health` returns 200; data written to the volume survives a container restart; a second run against the same volume reuses the existing SQLite DB (migrations idempotent).
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Railway deployment
**Goal:** Deploy the relay to Railway from the committed Dockerfile.

**Components:**
- Railway service config (`railway.json`/`railway.toml` and/or dashboard): Dockerfile build, a **persistent volume** mounted at `EZPDS_DATA_DIR`, variables for `EZPDS_PUBLIC_URL` (the Railway domain), `EZPDS_SIGNING_KEY_MASTER_KEY` (sealed), and `$PORT` wiring.

**Dependencies:** Phase 3. **Requires a Railway account/project (environment-specific verification).**

**Done when:** Railway builds and deploys the image; the public domain serves `/xrpc/_health` 200; data persists across redeploys on the attached volume.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: NixOS deploy via oci-containers (keep colmena) + flake cleanup
**Goal:** The lab host runs the same image through `virtualisation.oci-containers`, colmena still deploys, and the Nix-native relay build is retired.

**Components:**
- Rework `nix/module.nix` (or add a sibling module) so `services.ezpds` runs the OCI image via `virtualisation.oci-containers.containers.ezpds` (image ref per the distribution decision; volume for data dir; `environmentFiles` for the secret via agenix/sops; port mapping). Preserve the hardening intent where applicable.
- `flake.nix`: remove/deprecate the crane `relay` package and the `docker-image` output (and `nix/docker.nix`). Keep `devShells` and `nixosModules.default`.
- Decide image distribution (GHCR publish vs. local build) per the Architecture section.

**Dependencies:** Phase 2 (image exists). **Requires the NixOS lab host + colmena (environment-specific verification).**

**Done when:** A colmena deploy brings up the relay container on the lab host serving `/xrpc/_health`; `nix flake check` passes with the reworked outputs; no dangling references to the removed crane/docker.nix outputs.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Documentation + reproducibility note
**Goal:** Docs reflect the Docker/Railway/oci-containers reality.

**Components:**
- `nix/AGENTS.md`: rewrite to describe the `oci-containers` module and the retired crane/docker.nix outputs.
- Root `AGENTS.md`: update the Commands/Flake-Outputs sections (Docker build is now `docker build`, not `nix build .#docker-image`); note Railway as a deploy target.
- A short deploy/README note: the container runtime contract, the Railway setup, the colmena/oci path, the image-distribution choice, and the explicit reproducibility tradeoff. Bump "Last verified" dates.

**Dependencies:** Phases 1-5.

**Done when:** A reader can build the image, deploy to Railway, and deploy to the lab host from docs alone; no doc references the removed Nix build outputs as current.
<!-- END_PHASE_6 -->

## Additional Considerations

**Stateful single instance.** The relay uses one SQLite DB / single connection pool. On Railway that means **one instance + a persistent volume**; horizontal scaling is not available until a future Postgres/per-user-DB story. Documented, not solved here.

**Reproducibility downgrade is intentional.** Flake-locked → pinned base-image digest + `Cargo.lock`. Acceptable for a solo/experimental relay; called out so it's a choice, not an accident.

**Environment-specific verification.** Phase 4 needs a Railway account; Phase 5 needs the NixOS lab host + colmena. These cannot be verified in this repo's (nonexistent) CI or on a bare dev machine — the executor runs them in those environments and reports results, mirroring how the iOS plan marks `[developer-machine only]` steps.

**Scope boundary.** This plan changes the relay's build + deploy and minimal config/TLS wiring only. It does not change relay routes/behavior, the SQLite schema, the dev shell (devenv), or the iOS app.
