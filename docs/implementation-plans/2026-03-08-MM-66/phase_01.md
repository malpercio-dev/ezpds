# MM-66 Docker Image Implementation Plan — Phase 1

**Goal:** Create `nix/docker.nix` and extend `flake.nix` so `docker-image` is exposed as a flake package on Linux targets only.

**Architecture:** A new file `nix/docker.nix` holds the `buildLayeredImage` derivation as a standalone Nix function `{ pkgs, relay }:`. `flake.nix` merges this into the existing `forEachSystem` lambda return value using `pkgs.lib.optionalAttrs pkgs.stdenv.isLinux { ... }`, which evaluates to `{}` on Darwin and `{ docker-image = ...; }` on Linux — making the conditional a zero-cost no-op on macOS.

**Tech Stack:** Nix flakes, nixpkgs `dockerTools.buildLayeredImage`, crane (relay binary already built by MM-65)

**Scope:** Phase 1 of 2 from the original design. Phase 2 covers build verification and CLAUDE.md update.

**Codebase verified:** 2026-03-08

---

## Acceptance Criteria Coverage

This phase implements:

### MM-66.AC1: docker-image outputs exist in the flake
- **MM-66.AC1.1 Success:** `nix flake show --accept-flake-config` (on Linux) lists `packages.x86_64-linux.docker-image`
- **MM-66.AC1.2 Success:** `nix flake show --accept-flake-config` (on Linux) lists `packages.aarch64-linux.docker-image`
- **MM-66.AC1.3 Negative:** `packages.aarch64-darwin.docker-image` and `packages.x86_64-darwin.docker-image` are not present in `nix flake show` output

### MM-66.AC3: Image contents
- **MM-66.AC3.4 Success:** `nix/docker.nix` exists and is tracked by git (`git ls-files nix/docker.nix` returns it)

> **Note on AC1.1 / AC1.2:** These require a Linux system to verify. On macOS, `nix flake show` will not list `docker-image` (AC1.3 is verifiable now; AC1.1 and AC1.2 are verified in Phase 2 on a Linux system or CI).

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->

<!-- START_TASK_1 -->
### Task 1: Create `nix/docker.nix`

**Files:**
- Create: `nix/docker.nix`

**Step 1: Create the `nix/` directory and write the derivation**

```bash
mkdir nix
```

Then create `nix/docker.nix` with exactly this content:

```nix
{ pkgs, relay }:
pkgs.dockerTools.buildLayeredImage {
  name = "relay";
  tag = "latest";
  contents = [ relay pkgs.sqlite.out pkgs.cacert pkgs.tzdata ];
  config = {
    Entrypoint = [ "${relay}/bin/relay" ];
    Env = [
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      "TZDIR=${pkgs.tzdata}/share/zoneinfo"
    ];
  };
}
```

**Explanation of each field:**
- `name = "relay"`: The Docker image name that appears in `docker images`.
- `tag = "latest"`: Placeholder tag; can be wired to `self.shortRev` later.
- `contents`: List of derivations whose closure becomes the image filesystem. `pkgs.sqlite.out` is the runtime-library output of sqlite (carries `libsqlite3.so`); `.dev` (headers) is omitted.
- `Entrypoint`: Uses Nix string interpolation — `${relay}` expands to the relay's `/nix/store/...` path at evaluation time, so the entrypoint is always tied to the exact derivation.
- `SSL_CERT_FILE` / `TZDIR`: Point into the Nix store paths of `cacert` and `tzdata` so TLS and timezone lookups work inside the container.

**Step 2: No operational verification yet** — verification happens after flake.nix is updated in Task 2.

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Extend `flake.nix` to expose `docker-image` on Linux

**Files:**
- Modify: `flake.nix:48-51`

**Current content at lines 48–51:**

```nix
      in {
        inherit relay;
        default = relay;
      }
```

**Replace with:**

```nix
      in {
        inherit relay;
        default = relay;
      } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
        docker-image = import ./nix/docker.nix { inherit pkgs relay; };
      }
```

**Why `pkgs.lib.optionalAttrs`:** Returns the attribute set when the condition is true, and `{}` otherwise. On Darwin, the merge is `{ inherit relay; default = relay; } // {} = { inherit relay; default = relay; }`. On Linux, the `docker-image` attribute is added. This keeps Darwin package outputs unchanged while adding the Linux-only output.

**Why `import ./nix/docker.nix { inherit pkgs relay; }`:** Calls the function in `nix/docker.nix` with the current `pkgs` (for the target system) and the crane-built `relay` derivation. This is the standard nixpkgs package-expression calling convention.

**Step 2: Verify the flake evaluates (catches Nix syntax errors)**

```bash
nix flake show --accept-flake-config
```

Expected on macOS (aarch64-darwin): Output shows `packages.aarch64-darwin` with `relay` and `default`, but **no** `docker-image`. This is correct — `pkgs.stdenv.isLinux` is `false` on Darwin.

Example output (macOS):
```
git+file:///path/to/ezpds
├───devShells
│   ├───aarch64-darwin
│   │   └───default: development environment 'devenv-shell'
│   ...
└───packages
    ├───aarch64-darwin
    │   ├───default: package 'relay-0.1.0'
    │   └───relay: package 'relay-0.1.0'
    ├───aarch64-linux
    │   ├───default: package 'relay-0.1.0'
    │   ├───docker-image: package 'docker-image.tar.gz'
    │   └───relay: package 'relay-0.1.0'
    ...
```

If the command errors with a Nix eval error, fix it before proceeding to Task 3.

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Track files in git and commit

**Files:**
- `nix/docker.nix` (new)
- `flake.nix` (modified)

**Step 1: Stage both files**

```bash
git add nix/docker.nix flake.nix
```

**Step 2: Verify AC3.4 — `nix/docker.nix` is tracked by git**

```bash
git ls-files nix/docker.nix
```

Expected output:
```
nix/docker.nix
```

If empty, the file is not staged/tracked. Re-run `git add nix/docker.nix`.

**Step 3: Verify AC1.3 (negative) on macOS — `docker-image` is NOT present for Darwin**

```bash
nix flake show --accept-flake-config 2>/dev/null | grep docker-image
```

Expected: Lines for `aarch64-linux` and `x86_64-linux` only. No `aarch64-darwin` or `x86_64-darwin` lines. If `docker-image` appears under a Darwin system, the `optionalAttrs` condition is wrong — re-check Task 2.

**Step 4: Commit**

```bash
git commit -m "feat(MM-66): add nix/docker.nix and expose docker-image on Linux"
```

<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_A -->
