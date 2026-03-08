# MM-66 Docker Image Implementation Plan — Phase 2

**Goal:** Update CLAUDE.md with the `docker-image` Linux-only caveat, then verify the image builds, loads, runs, and meets size constraints on a Linux system.

**Architecture:** No new Nix code. This phase has one code change (CLAUDE.md), and the remaining work is operational verification that must be executed on an x86_64-linux or aarch64-linux system (or via CI). All acceptance criteria in this phase require a Linux Docker daemon.

**Tech Stack:** Nix CLI, Docker CLI (Linux only)

**Scope:** Phase 2 of 2. Phase 1 created `nix/docker.nix` and extended `flake.nix`.

**Codebase verified:** 2026-03-08

---

## Acceptance Criteria Coverage

This phase verifies:

### MM-66.AC2: Image builds and loads
- **MM-66.AC2.1 Success:** `nix build .#docker-image --accept-flake-config` completes without error on x86_64-linux
- **MM-66.AC2.2 Success:** `nix build .#packages.aarch64-linux.docker-image --accept-flake-config` completes without error on an aarch64-linux or x86_64-linux system
- **MM-66.AC2.3 Success:** `docker load < result` completes without error
- **MM-66.AC2.4 Success:** `docker images` shows `relay:latest` after loading

### MM-66.AC3: Image contents
- **MM-66.AC3.1 Success:** `docker run --rm relay:latest` exits without a "no such file" or dynamic linker error (relay binary and libsqlite3.so are present)
- **MM-66.AC3.2 Success:** `docker inspect relay:latest` shows `SSL_CERT_FILE` env var pointing to a cacert store path
- **MM-66.AC3.3 Success:** `docker inspect relay:latest` shows `TZDIR` env var pointing to a tzdata store path

### MM-66.AC4: Image size
- **MM-66.AC4.1 Success:** `docker images relay` shows image size under 50 MB

### MM-66.AC5: Scope boundaries
- **MM-66.AC5.1 Negative:** `docker run relay:latest` does not require a running HTTP server to start (relay is a stub; no HTTP health check in this ticket)

---

> **All verification in this phase requires a Linux system with Docker installed.**
> On macOS, `docker-image` is not exposed (by design). Use a Linux CI runner or a remote Linux builder.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Update CLAUDE.md with `docker-image` Linux-only note

**Files:**
- Modify: `CLAUDE.md:13` (after the `nix build .#relay` line)

**Current content at line 13:**

```
- `nix build .#relay --accept-flake-config` - Build relay binary (output at ./result/bin/relay)
```

**Add the following line immediately after line 13:**

```
- `nix build .#docker-image --accept-flake-config` - Build Docker image tarball (Linux only; `docker-image` is not exposed on macOS — use a remote Linux builder or CI)
```

The full Commands section should read:

```markdown
## Commands
- `nix develop --impure --accept-flake-config` - Enter dev shell (flags required; --impure for devenv CWD detection, --accept-flake-config activates the Cachix binary cache in nixConfig — without it, a cold build takes 20+ minutes)
- `nix build .#relay --accept-flake-config` - Build relay binary (output at ./result/bin/relay)
- `nix build .#docker-image --accept-flake-config` - Build Docker image tarball (Linux only; `docker-image` is not exposed on macOS — use a remote Linux builder or CI)
- `cargo build` - Build all crates
- `cargo test` - Run all tests
- `cargo clippy` - Lint
- `cargo fmt --check` - Check formatting
```

**Verification:**

```bash
grep "docker-image" CLAUDE.md
```

Expected: One line mentioning `nix build .#docker-image` and noting it is Linux-only.

**Commit:**

```bash
git add CLAUDE.md
git commit -m "docs(MM-66): note docker-image is Linux-only in CLAUDE.md"
```

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Verify image on Linux (human verification checklist)

> **Run these steps on an x86_64-linux or aarch64-linux system with Docker installed.**
> This task documents acceptance-criteria verification — it is not automated.

---

**Step 1: Build x86_64-linux image (verifies MM-66.AC2.1)**

```bash
nix build .#docker-image --accept-flake-config
```

Expected: Exits 0. A `result` symlink appears pointing to a `.tar.gz` in the Nix store.

If it fails with an eval error, ensure Phase 1 commit is present and re-check `nix/docker.nix` and `flake.nix`.

---

**Step 2: Build aarch64-linux image (verifies MM-66.AC2.2)**

On an x86_64-linux host (cross-compilation):

```bash
nix build .#packages.aarch64-linux.docker-image --accept-flake-config
```

Expected: Exits 0. A `result` symlink appears for the aarch64 image.

> Cross-compilation for aarch64 requires binfmt\_misc QEMU support or a configured remote builder. If unavailable, skip this step and mark it verified via CI.

---

**Step 3: Load image into Docker (verifies MM-66.AC2.3 and MM-66.AC2.4)**

First rebuild the x86_64 image if `result` is from the aarch64 build:

```bash
nix build .#docker-image --accept-flake-config
```

Then load:

```bash
docker load < result
```

Expected output contains:
```
Loaded image: relay:latest
```

Verify the image appears:

```bash
docker images relay
```

Expected: At least one row showing `relay` / `latest`.

---

**Step 4: Run the relay stub (verifies MM-66.AC3.1 and MM-66.AC5.1)**

```bash
docker run --rm relay:latest
```

Expected: The container exits. There must be **no** `no such file or directory` or `error while loading shared libraries: libsqlite3.so` error.

The relay is currently a stub and may exit with a non-zero code — that is acceptable. The absence of linker errors confirms `relay` binary and `libsqlite3.so` are present in the image closure.

---

**Step 5: Inspect environment variables (verifies MM-66.AC3.2 and MM-66.AC3.3)**

```bash
docker inspect relay:latest | grep -E 'SSL_CERT_FILE|TZDIR'
```

Expected output (store hash will differ):

```
"SSL_CERT_FILE=/nix/store/...-nss-ca-cert-.../etc/ssl/certs/ca-bundle.crt",
"TZDIR=/nix/store/...-tzdata-.../share/zoneinfo"
```

Both variables must be present. If either is missing, `nix/docker.nix` is missing the `Env` config — re-check Task 1 of Phase 1.

---

**Step 6: Check image size (verifies MM-66.AC4.1)**

```bash
docker images relay --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
```

Expected: The `SIZE` column shows a value under 50 MB (e.g., `42.3MB`).

If the size exceeds 50 MB, check `contents` in `nix/docker.nix` for unnecessary packages and remove them. The expected closure is: relay binary + libsqlite3.so + CA bundle + tzdata. No shell, no libc extras.

---

**Step 7: Verify `docker-image` is absent on Darwin (verifies MM-66.AC1.3)**

From your macOS machine:

```bash
nix flake show --accept-flake-config 2>/dev/null | grep docker-image
```

Expected: Lines for `aarch64-linux` and `x86_64-linux` only. No `aarch64-darwin` or `x86_64-darwin` lines appear.

---

**Step 8: Verify flake show on Linux lists both outputs (verifies MM-66.AC1.1 and MM-66.AC1.2)**

On the Linux system:

```bash
nix flake show --accept-flake-config 2>/dev/null | grep docker-image
```

Expected output includes:
```
│   ├───aarch64-linux
│   │   ├───docker-image: package 'docker-image.tar.gz'
│   ...
│   ├───x86_64-linux
│   │   ├───docker-image: package 'docker-image.tar.gz'
```

Both `aarch64-linux` and `x86_64-linux` must show `docker-image`.

<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->
