# MM-66 Test Requirements

## Overview

MM-66 is a Nix/Docker packaging ticket. There is no Rust application logic under test -- the implementation consists entirely of Nix derivation files (`nix/docker.nix` and a `flake.nix` extension). Consequently, there are no Rust unit tests or integration tests in scope. All verification is operational: checking that Nix flake outputs exist, that the built Docker image loads and runs correctly, and that the image meets size and content constraints.

Verification splits into two categories:

1. **Automated (CI-able on Linux):** Checks that can be scripted and run in a Linux CI environment with Nix and Docker installed. These are shell commands with deterministic expected output.
2. **Human verification (Linux required):** Checks that require a running Docker daemon on a Linux system. These cannot be run on macOS (where the current development happens) because `docker-image` is intentionally not exposed for Darwin targets. A developer must either use a Linux machine, a remote Linux builder, or a Linux CI runner.

In practice, every AC in this ticket requires Linux for full verification. The distinction below separates checks that are purely Nix evaluation (can run without Docker) from checks that require both Nix and a Docker daemon.

## Automated Tests

These checks can be scripted in CI. They verify Nix flake structure and file tracking -- no Docker daemon required.

| AC ID | Test Type | Verification Command | What It Verifies |
|---|---|---|---|
| AC1.3 | Nix flake evaluation (macOS or Linux) | `nix flake show --accept-flake-config 2>/dev/null \| grep docker-image` | `docker-image` appears only under `aarch64-linux` and `x86_64-linux` -- never under `aarch64-darwin` or `x86_64-darwin`. Verifiable on any platform because `nix flake show` evaluates all systems. |
| AC3.4 | Git file tracking | `git ls-files nix/docker.nix` | `nix/docker.nix` exists and is tracked by git (output is `nix/docker.nix`). |

**Notes:**
- AC1.3 is the only acceptance criterion fully verifiable on macOS. The `nix flake show` output lists all systems regardless of the host platform, so a grep for `docker-image` under Darwin systems can confirm absence.
- AC3.4 is a simple git check with no platform dependency.

## Human Verification (Linux Required)

All remaining ACs require a Linux system with both Nix and Docker installed. The commands below are taken directly from Phase 2, Task 2 of the implementation plan.

### AC1: docker-image outputs exist in the flake

| AC ID | Verification Command | Expected Result | Justification for Human Verification |
|---|---|---|---|
| AC1.1 | `nix flake show --accept-flake-config 2>/dev/null \| grep docker-image` | Output includes `packages.x86_64-linux.docker-image` (or the tree-formatted equivalent showing `docker-image: package 'docker-image.tar.gz'` under `x86_64-linux`) | While `nix flake show` works on any platform, confirming the output is correct on an actual Linux system validates that the conditional evaluation produces the expected attribute. Can be automated in Linux CI. |
| AC1.2 | `nix flake show --accept-flake-config 2>/dev/null \| grep docker-image` | Output includes `packages.aarch64-linux.docker-image` (or the tree-formatted equivalent showing `docker-image: package 'docker-image.tar.gz'` under `aarch64-linux`) | Same as AC1.1. Both architectures must appear. |

### AC2: Image builds and loads

| AC ID | Verification Command | Expected Result | Justification for Human Verification |
|---|---|---|---|
| AC2.1 | `nix build .#docker-image --accept-flake-config` | Exits 0. A `result` symlink appears pointing to a `.tar.gz` in the Nix store. | Requires Linux -- `docker-image` is not a valid flake output on Darwin. The Nix build actually compiles the image derivation. |
| AC2.2 | `nix build .#packages.aarch64-linux.docker-image --accept-flake-config` | Exits 0. A `result` symlink appears for the aarch64 image. | Requires Linux (or cross-compilation with binfmt_misc QEMU support). May need to be verified via CI if no aarch64 system is available. |
| AC2.3 | `docker load < result` | Output contains `Loaded image: relay:latest`. | Requires Docker daemon on Linux. |
| AC2.4 | `docker images relay` | At least one row showing `relay` / `latest`. | Requires Docker daemon on Linux. |

### AC3: Image contents

| AC ID | Verification Command | Expected Result | Justification for Human Verification |
|---|---|---|---|
| AC3.1 | `docker run --rm relay:latest` | Container exits without `no such file or directory` or `error while loading shared libraries: libsqlite3.so` errors. Non-zero exit code is acceptable (relay is a stub). | Requires Docker daemon on Linux. Validates that the relay binary and libsqlite3.so are present in the image closure. |
| AC3.2 | `docker inspect relay:latest \| grep -E 'SSL_CERT_FILE'` | Output shows `SSL_CERT_FILE=/nix/store/...-nss-ca-cert-.../etc/ssl/certs/ca-bundle.crt` (exact store hash varies). | Requires Docker daemon on Linux. Validates the cacert environment variable is set in the image config. |
| AC3.3 | `docker inspect relay:latest \| grep -E 'TZDIR'` | Output shows `TZDIR=/nix/store/...-tzdata-.../share/zoneinfo` (exact store hash varies). | Requires Docker daemon on Linux. Validates the tzdata environment variable is set in the image config. |

### AC4: Image size

| AC ID | Verification Command | Expected Result | Justification for Human Verification |
|---|---|---|---|
| AC4.1 | `docker images relay --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"` | SIZE column shows a value under 50 MB. | Requires Docker daemon on Linux. Image must be loaded first (AC2.3). |

### AC5: Scope boundaries

| AC ID | Verification Command | Expected Result | Justification for Human Verification |
|---|---|---|---|
| AC5.1 | `docker run --rm relay:latest` | Container exits (same command as AC3.1). The relay does not attempt to start an HTTP server or listen on a port. No health check endpoint is tested. | Requires Docker daemon on Linux. Confirms the relay is a stub -- packaging only, no HTTP functionality in this ticket. |

## AC Coverage Summary

| AC ID | Description | Category | Phase | Verification Platform |
|---|---|---|---|---|
| AC1.1 | `nix flake show` lists `packages.x86_64-linux.docker-image` | Human (CI-automatable on Linux) | Phase 2, Step 8 | Linux |
| AC1.2 | `nix flake show` lists `packages.aarch64-linux.docker-image` | Human (CI-automatable on Linux) | Phase 2, Step 8 | Linux |
| AC1.3 | `docker-image` absent for Darwin systems | Automated | Phase 1, Task 3 / Phase 2, Step 7 | Any (macOS or Linux) |
| AC2.1 | `nix build .#docker-image` succeeds on x86_64-linux | Human | Phase 2, Step 1 | x86_64-linux |
| AC2.2 | `nix build .#packages.aarch64-linux.docker-image` succeeds | Human | Phase 2, Step 2 | aarch64-linux (or x86_64-linux with binfmt) |
| AC2.3 | `docker load < result` succeeds | Human | Phase 2, Step 3 | Linux (Docker daemon) |
| AC2.4 | `docker images` shows `relay:latest` | Human | Phase 2, Step 3 | Linux (Docker daemon) |
| AC3.1 | `docker run --rm relay:latest` exits without linker errors | Human | Phase 2, Step 4 | Linux (Docker daemon) |
| AC3.2 | `docker inspect` shows `SSL_CERT_FILE` env var | Human | Phase 2, Step 5 | Linux (Docker daemon) |
| AC3.3 | `docker inspect` shows `TZDIR` env var | Human | Phase 2, Step 5 | Linux (Docker daemon) |
| AC3.4 | `nix/docker.nix` tracked by git | Automated | Phase 1, Task 3 | Any |
| AC4.1 | Image size under 50 MB | Human | Phase 2, Step 6 | Linux (Docker daemon) |
| AC5.1 | Relay is a stub; no HTTP server required | Human | Phase 2, Step 4 | Linux (Docker daemon) |
