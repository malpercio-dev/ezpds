# Relay Containerization — Phase 2: Multi-stage Dockerfile

**Goal:** A reproducible, small image that builds and runs the relay with no Nix and no system OpenSSL.

**Architecture:** Multi-stage build — a Rust toolchain stage compiles `cargo build --release -p relay` (bundled SQLite, rustls), and a minimal Debian-slim runtime stage carries only the binary, CA certs, tzdata, and a non-root user. Base images pinned by digest.

**Tech Stack:** Docker (BuildKit), `rust:bookworm` build image, `debian:bookworm-slim` runtime.

**Scope:** Phase 2 of 6.

**Codebase verified:** 2026-06-20.

> **Workspace-coupling gotcha (critical for the build context):** the relay is a Cargo **workspace member**, and the root `Cargo.toml` has `[patch.crates-io] swift-rs = { path = "apps/identity-wallet/swift-rs-patch" }`. Cargo resolves the **whole workspace** even for `cargo build -p relay`, so the build context must still contain every member's `Cargo.toml` **and** the `swift-rs-patch` path, or resolution fails with "failed to load manifest / patch points to non-existent path." The `.dockerignore` therefore keeps all Cargo manifests + Rust sources and excludes only build artifacts and the SvelteKit frontend. `cargo build -p relay` will **not** compile Tauri/the wallet — it only builds relay's subgraph — so this costs build context size, not build time.

> **Platform note:** all build/run steps are **[requires Docker]** (Docker Desktop / colima / podman on the dev Mac, or any Linux Docker host).

---

## Acceptance Criteria Coverage

### relay-containerization.AC1
- **relay-containerization.AC1.1 Success:** `docker build` from the committed Dockerfile produces a relay image with no Nix involved.
- **relay-containerization.AC1.3 Success:** the runtime image contains no `libssl`/OpenSSL.

### relay-containerization.AC5
- **relay-containerization.AC5.1 Success:** the Dockerfile pins base images **by digest**, and the build uses the committed `Cargo.lock`.

**Verifies (this phase):** AC1.1, AC1.3 (image side), AC5.1. Infrastructure — verified operationally.

---

<!-- START_TASK_1 -->
### Task 1: Create `.dockerignore`

**Files:**
- Create: `.dockerignore` (repo root)

**Step 1:** Create `.dockerignore` with:
```gitignore
# Build artifacts / caches (huge, never needed in the image build)
target
**/target
.devenv
result
.git
.direnv

# Frontend + node (the relay build needs none of this)
**/node_modules
apps/identity-wallet/.svelte-kit
apps/identity-wallet/build
apps/identity-wallet/static
apps/identity-wallet/dist

# Generated iOS project
apps/identity-wallet/src-tauri/gen

# Docs / tooling not needed to compile the relay
docs
bruno

# IMPORTANT: do NOT ignore Cargo manifests, crates/, rust-toolchain.toml, or
# apps/identity-wallet/{src-tauri,swift-rs-patch} — cargo resolves the whole
# workspace (incl. the swift-rs [patch.crates-io] path) even for `-p relay`.
```

**Step 2: Commit**
```bash
git add .dockerignore
git commit -m "build: add .dockerignore for relay container build context"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create the multi-stage `Dockerfile`

**Files:**
- Create: `Dockerfile` (repo root)

**Step 1:** Create `Dockerfile` with this content (base-image digests are pinned in Task 3 — tags shown here for readability):
```dockerfile
# syntax=docker/dockerfile:1

# ---- build stage ----
FROM rust:1-bookworm AS build
WORKDIR /src
# Whole (ignore-trimmed) workspace — needed because cargo resolves all members
# and the swift-rs [patch.crates-io] path even for `-p relay`.
COPY . .
# Bundled SQLite: LIBSQLITE3_SYS_USE_PKG_CONFIG is intentionally NOT set, so
# libsqlite3-sys compiles SQLite from source. rustls means no OpenSSL needed.
# --locked uses the committed Cargo.lock for reproducibility.
RUN cargo build --release --locked -p relay

# ---- runtime stage ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*
# Non-root runtime user; /data is the default data dir (mount a volume here).
RUN useradd --system --uid 10001 --user-group --create-home --home-dir /data relay
COPY --from=build /src/target/release/relay /usr/local/bin/relay
ENV EZPDS_DATA_DIR=/data \
    RUST_LOG=info
VOLUME ["/data"]
# Documentation only; the actual listen port comes from EZPDS_PORT/$PORT at runtime.
EXPOSE 8080
USER relay
ENTRYPOINT ["/usr/local/bin/relay"]
```

Notes embedded for the executor:
- **No in-image `HEALTHCHECK`** — debian-slim has no `curl`, and platforms (Railway) health-check the URL externally. Local verification in Phase 3 curls `/xrpc/_health` from the host. Do not add `curl` just for a HEALTHCHECK.
- `public_url`, `available_user_domains`, and the master key are **runtime env** (deploy-specific) — never set in the image.
- **C compiler for bundled SQLite:** the `rust:bookworm` build image is Debian-based and ships `gcc`/`build-essential` (via buildpack-deps), which `libsqlite3-sys`'s vendored C build needs. The `debian:bookworm-slim` runtime stage has no compiler — correct, since compilation happens only in the build stage.
- **`rust-toolchain.toml` triggers a rustup install in the build stage.** The build context keeps `rust-toolchain.toml` (Cargo needs it adjacent to the workspace), and it pins `channel = "stable"` with extra components (clippy/rustfmt/rust-analyzer) and **6 targets including iOS**. When `cargo` runs in `/src`, the image's rustup will download/install that toolchain + components + targets before building — expect extra build time and a larger build layer. This is *expected and accounted for*. If you want a leaner/faster image build and accept that the image's bundled toolchain (not the pinned `stable`) compiles the binary, you may add `rust-toolchain.toml` to `.dockerignore` for the build context — call this out explicitly if you do, since it changes which toolchain builds the release binary.

**Step 2: Commit**
```bash
git add Dockerfile
git commit -m "build: add multi-stage Dockerfile for the relay (rustls, bundled sqlite)"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Pin both base images by digest (AC5.1)

**Files:**
- Modify: `Dockerfile` (the two `FROM` lines)

**Step 1: Resolve current digests** [requires Docker]:
```bash
docker buildx imagetools inspect rust:1-bookworm   | grep -i digest | head -1
docker buildx imagetools inspect debian:bookworm-slim | grep -i digest | head -1
```

**Step 2:** Replace the tags with `name@sha256:...` digests, keeping the human tag in a comment, e.g.:
```dockerfile
FROM rust:1-bookworm@sha256:<resolved> AS build
...
FROM debian:bookworm-slim@sha256:<resolved> AS runtime
```

**Step 3: Commit**
```bash
git add Dockerfile
git commit -m "build: pin Dockerfile base images by digest"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Build the image and confirm no OpenSSL (AC1.1, AC1.3) [requires Docker]

**Files:** none (verification).

**Step 1: Build**
```bash
docker build -t ezpds-relay:dev .
```
Expected: completes; the build stage compiles `libsqlite3-sys` from source (visible in logs) and does **not** pull Nix.

**Step 2: Confirm no OpenSSL in the runtime image**
```bash
docker run --rm --entrypoint /bin/sh ezpds-relay:dev -c "ldd /usr/local/bin/relay | grep -i ssl || echo NO_OPENSSL"
docker run --rm --entrypoint /bin/sh ezpds-relay:dev -c "dpkg -l | grep -i openssl || echo NO_OPENSSL_PKG"
```
Expected: both print `NO_OPENSSL` / `NO_OPENSSL_PKG` (rustls means the binary links no libssl, and the slim image installs no openssl package).

**Step 3: No commit** (verification only).
<!-- END_TASK_4 -->

---

## Phase 2 Done When

- `docker build -t ezpds-relay:dev .` succeeds with no Nix (AC1.1).
- Both `FROM` lines are digest-pinned and the build uses `--locked` (AC5.1).
- The runtime binary links no OpenSSL and the image has no openssl package (AC1.3).
- `Dockerfile` + `.dockerignore` committed.
