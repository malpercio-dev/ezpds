# MM-64 Implementation Plan — Phase 1

**Goal:** Produce all static configuration files for the Nix flake + devenv dev shell.

**Architecture:** Minimal Nix flake (flake.nix) wires devenv as the sole output. A separate devenv.nix module configures the Rust toolchain and packages. rust-toolchain.toml is the single source of truth for the toolchain version, readable by both devenv (via rust-overlay) and rustup.

**Tech Stack:** Nix flakes, devenv (cachix/devenv), nix-systems, rust-overlay (used internally by devenv)

**Scope:** 2 phases total (Phase 1 of 2)

**Codebase verified:** 2026-03-07

---

## Acceptance Criteria Coverage

**Verifies: None** — This is an infrastructure phase that creates configuration files. All acceptance criteria (MM-64.AC1–MM-64.AC6) are verified operationally in Phase 2 by running `nix develop`.

---

<!-- START_SUBCOMPONENT_A (tasks 1-5) -->

<!-- START_TASK_1 -->
### Task 1: Create `flake.nix`

**Files:**
- Create: `flake.nix`

**Step 1: Create the file with the following exact contents**

```nix
{
  description = "ezpds development shell";

  nixConfig = {
    extra-substituters = "https://devenv.cachix.org";
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
  };

  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    devenv.url = "github:cachix/devenv";
    systems.url = "github:nix-systems/default";
  };

  outputs = { self, nixpkgs, devenv, systems, ... } @ inputs:
  let
    forEachSystem = f: nixpkgs.lib.genAttrs (import systems) f;
  in {
    devShells = forEachSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        default = devenv.lib.mkShell {
          inherit inputs pkgs;
          modules = [ ./devenv.nix ];
        };
      }
    );
  };
}
```

**Step 2: Verify file exists**

Run: `ls -la flake.nix`
Expected: file listed

**Step 3: Verify scope boundaries (no packages or nixosModules outputs)**

Run:
```bash
grep -E "^\s*packages\s*=" flake.nix && echo "FAIL: packages output found" || echo "OK: no packages output"
grep "nixosModules" flake.nix && echo "FAIL: nixosModules found" || echo "OK: no nixosModules"
```
Expected: both lines print "OK"
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create `devenv.nix`

**Files:**
- Create: `devenv.nix`

**Step 1: Create the file with the following exact contents**

```nix
{ pkgs, lib, config, ... }:
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = [
    pkgs.just
    pkgs.cargo-audit
    pkgs.sqlite
    pkgs.pkg-config
  ];

  env.LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
}
```

Notes:
- `languages.rust.toolchainFile` requires `enable = true` to be set alongside it — devenv does not auto-detect rust-toolchain.toml.
- `pkgs.pkg-config` must be explicit — `languages.rust` does not include it automatically.
- `pkgs.sqlite` includes both the runtime binary and dev headers (the `.dev` output is propagated by nixpkgs).
- `LIBSQLITE3_SYS_USE_PKG_CONFIG = "1"` tells `libsqlite3-sys` (used by `rusqlite`) to find sqlite via pkg-config instead of attempting to bundle it.

**Step 2: Verify file exists**

Run: `ls -la devenv.nix`
Expected: file listed
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Create `rust-toolchain.toml`

**Files:**
- Create: `rust-toolchain.toml`

**Step 1: Create the file with the following exact contents**

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy", "rust-analyzer"]
targets = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]
```

Notes:
- `channel = "stable"` satisfies MM-64.AC2.1 (stable release, not nightly or beta).
- The host platform target is always included automatically by rustup/rust-overlay; the listed targets enable cross-compilation from any platform to the others.
- devenv reads this file via `rust-overlay`'s `fromRustupToolchainFile`. rustup reads it natively on machines without Nix.
- `rust-analyzer` as a component satisfies MM-64.AC2.3.
- `clippy` as a component satisfies MM-64.AC2.4.
- `rustfmt` as a component satisfies MM-64.AC2.5.

**Step 2: Verify file exists**

Run: `ls -la rust-toolchain.toml`
Expected: file listed
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Create `.envrc`

**Files:**
- Create: `.envrc`

**Step 1: Create the file with the following exact contents (single line)**

```
use flake
```

Notes:
- `use flake` is the direnv hook that activates the Nix devShell automatically on `cd`.
- This satisfies MM-64.AC4.1 (`.envrc` contains `use flake` and is tracked by git — it will be tracked once committed in Task 6).

**Step 2: Verify file contents**

Run: `cat .envrc`
Expected: `use flake`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Update `.gitignore`

**Files:**
- Modify: `.gitignore` (append to end)

**Step 1: Append the following block to the end of `.gitignore`**

The current `.gitignore` ends after the `# Environment files` section. Append:

```
# Nix / devenv
.devenv/
.direnv/
devenv.local.nix
```

**Step 2: Verify entries are present**

Run:
```bash
grep -E "\.devenv/|\.direnv/|devenv\.local\.nix" .gitignore
```
Expected: all three lines printed
<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_6 -->
### Task 6: Commit all configuration files

**Step 1: Stage exactly the five files**

```bash
git add flake.nix devenv.nix rust-toolchain.toml .envrc .gitignore
```

**Step 2: Verify staging — confirm only expected files are staged**

Run: `git status`
Expected:
- `flake.nix` — new file
- `devenv.nix` — new file
- `rust-toolchain.toml` — new file
- `.envrc` — new file
- `.gitignore` — modified

**Step 3: Commit**

```bash
git commit -m "$(cat <<'EOF'
chore(MM-64): add Nix flake + devenv dev shell configuration

Adds flake.nix, devenv.nix, rust-toolchain.toml, .envrc. Phase 2 will
run nix develop to generate flake.lock and verify the shell.
EOF
)"
```

Expected: commit message displayed, branch `MM-64` advanced by one commit.
<!-- END_TASK_6 -->
