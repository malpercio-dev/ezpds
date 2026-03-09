# MM-135 NixOS Module — Phase 3: Validate Module Evaluation

**Goal:** Confirm the module evaluates correctly across all acceptance criteria using `nix eval` smoke tests — without a live NixOS system. Tests run cross-platform on macOS (aarch64-darwin) by evaluating for `x86_64-linux`.

**Architecture:** Inline `nix eval --expr` commands use `builtins.getFlake` to reference the local flake and construct minimal `nixosSystem` configurations. Two complementary approaches:
1. Full `nixpkgs.lib.nixosSystem` eval — tests option enforcement and ExecStart composition.
2. Direct `lib.filterAttrs` eval — tests TOML key inclusion/exclusion logic isolated from the module system.

**Tech Stack:** `nix eval`, `nixpkgs.lib.nixosSystem`, `builtins.getFlake`, `nix flake check`.

**Scope:** Phase 3 of 3. Requires Phases 1 and 2 to be complete.

**Codebase verified:** 2026-03-09

---

## Important: nixpkgs Selection for Smoke Tests

The project's nixpkgs pin (`cachix/devenv-nixpkgs/rolling`) is a fork of nixpkgs optimized for devenv and **does not export `lib.nixosSystem`**. Tasks 2, 3, and 5 below require evaluating `nixosSystem` configurations to test module behavior.

**Workaround:** Use `builtins.getFlake "nixpkgs"` to access the system nixpkgs registry (which includes `lib.nixosSystem`), instead of `flake.inputs.nixpkgs`. This is documented in the smoke test commands below as `evalNixpkgs`.

---

## Acceptance Criteria Coverage

### MM-135.AC1: Module options are correctly declared
- **MM-135.AC1.4 Failure:** Nix evaluation fails with a missing-option error when `services.ezpds.settings.public_url` is not set
- **MM-135.AC1.5 Failure:** Nix evaluation fails when `services.ezpds.package` is not set and the bare module (not the flake wrapper) is used

### MM-135.AC2: TOML config generation
- **MM-135.AC2.1 Success:** Generated `relay.toml` contains `bind_address`, `port`, `data_dir`, and `public_url` when all are set
- **MM-135.AC2.2 Success:** When `settings.database_url` is `null`, the generated TOML does not contain a `database_url` key
- **MM-135.AC2.3 Success:** When `settings.database_url` is set to a string, the generated TOML contains that `database_url` key
- **MM-135.AC2.4 Success:** The relay `ExecStart` line uses `--config <path>` pointing to the generated TOML derivation

### MM-135.AC3: `configFile` escape hatch
- **MM-135.AC3.1 Success:** When `services.ezpds.configFile` is set to a path, `ExecStart` uses that path instead of the generated TOML
- **MM-135.AC3.2 Success:** When `configFile` is set, changes to `settings.*` do not affect the `ExecStart` command

### MM-135.AC5: `nixosModules.default` flake output
- **MM-135.AC5.1 Success:** `nix flake show --accept-flake-config` lists `nixosModules.default`
- **MM-135.AC5.2 Success:** When imported via `nixosModules.default`, `services.ezpds.package` defaults to the flake's `relay` build for the current system
- **MM-135.AC5.3 Success:** The bare `nix/module.nix` is importable directly as `imports = [ ./nix/module.nix ]` without the flake wrapper, provided the user sets `services.ezpds.package`

---

<!-- START_TASK_1 -->
### Task 1: Run nix flake check

**Verifies:** MM-135.AC5.1 (nixosModules.default listed), overall flake validity

**Files:** None (read-only validation)

**Step 1: Run flake check**

```bash
nix flake check --impure --accept-flake-config
```

`--impure` is required because devenv's CWD detection uses impure operations. `--accept-flake-config` activates the Cachix binary cache.

Expected: exits with code 0, no errors. You will see warnings about omitted incompatible systems (e.g., `aarch64-linux`) — this is normal on macOS.

**Step 2: Confirm nixosModules.default is listed**

```bash
nix flake show --accept-flake-config --allow-import-from-derivation
```

Expected output includes:

```
├── nixosModules
│   └── default: NixOS module
```

*Note:* If `--allow-import-from-derivation` is not available in your nix version, use the attribute name check in Step 3 instead, which does not require IFD.

**Step 3: Confirm attribute name**

```bash
nix eval .#nixosModules --apply builtins.attrNames --accept-flake-config
```

Expected: `[ "default" ]`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Smoke test — minimal valid configuration

**Verifies:** MM-135.AC2.4 (ExecStart uses --config), MM-135.AC5.2 (package defaults to flake's relay)

**Files:** None (read-only validation)

All `nix eval` commands below must be run from the repo root (`/Users/jacob.zweifel/workspace/malpercio-dev/ezpds`).

**Step 1: Verify ExecStart with minimal config**

```bash
nix eval --impure --accept-flake-config --raw --expr '
let
  flake = builtins.getFlake (builtins.toString ./.);
  # devenv-nixpkgs fork lacks lib.nixosSystem; use system nixpkgs from registry
  evalNixpkgs = builtins.getFlake "nixpkgs";
  sys = evalNixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      {
        services.ezpds.enable = true;
        services.ezpds.settings.public_url = "https://relay.example.com";
      }
    ];
  };
in sys.config.systemd.services.ezpds.serviceConfig.ExecStart
'
```

Expected: a string like `/nix/store/...-relay-0.1.0/bin/relay --config /nix/store/...-relay.toml`

Confirm:
- It starts with a Nix store path ending in `/bin/relay`
- It contains `--config /nix/store/` (generated TOML in store, not a custom path)

**Step 2: Verify user declaration**

```bash
nix eval --impure --accept-flake-config --json --expr '
let
  flake = builtins.getFlake (builtins.toString ./.);
  # devenv-nixpkgs fork lacks lib.nixosSystem; use system nixpkgs from registry
  evalNixpkgs = builtins.getFlake "nixpkgs";
  sys = evalNixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      {
        services.ezpds.enable = true;
        services.ezpds.settings.public_url = "https://relay.example.com";
      }
    ];
  };
  u = sys.config.users.users.ezpds;
in { isSystemUser = u.isSystemUser; group = u.group; }
'
```

Expected: `{"group":"ezpds","isSystemUser":true}`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Smoke test — missing required option fails eval

**Verifies:** MM-135.AC1.4 (missing public_url causes eval error), MM-135.AC1.5 (missing package causes eval error with bare module)

**Files:** None (read-only validation)

**Step 1: Missing public_url must fail**

```bash
nix eval --impure --accept-flake-config --raw --expr '
let
  flake = builtins.getFlake (builtins.toString ./.);
  # devenv-nixpkgs fork lacks lib.nixosSystem; use system nixpkgs from registry
  evalNixpkgs = builtins.getFlake "nixpkgs";
  sys = evalNixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      {
        services.ezpds.enable = true;
        # public_url intentionally not set
      }
    ];
  };
in sys.config.systemd.services.ezpds.serviceConfig.ExecStart
'
echo "Exit code: $?"
```

Expected: exits with non-zero code. The error message should reference `services.ezpds.settings.public_url` as undefined or missing.

**Step 2: Missing package must fail when using bare module**

```bash
nix eval --impure --accept-flake-config --raw --expr '
let
  # devenv-nixpkgs fork lacks lib.nixosSystem; use system nixpkgs from registry
  evalNixpkgs = builtins.getFlake "nixpkgs";
  sys = evalNixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      (import ./nix/module.nix)   # bare module, no flake wrapper
      {
        services.ezpds.enable = true;
        services.ezpds.settings.public_url = "https://relay.example.com";
        # package intentionally not set
      }
    ];
  };
in sys.config.systemd.services.ezpds.serviceConfig.ExecStart
'
echo "Exit code: $?"
```

Expected: exits with non-zero code. The error should reference `services.ezpds.package` as undefined.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Smoke test — TOML key inclusion/exclusion

**Verifies:** MM-135.AC2.1 (expected keys present), MM-135.AC2.2 (database_url absent when null), MM-135.AC2.3 (database_url present when set)

**Files:** None (read-only validation)

These tests verify the `lib.filterAttrs` filtering pattern that the module uses for TOML generation — they test the filtering logic directly using `nixpkgs.lib`, not through the full module. This is the practical approach on macOS because reading the actual generated TOML file requires Import from Derivation (IFD), which requires building the derivation, which requires a Linux builder.

**Limitation:** These tests verify that `lib.filterAttrs (_: v: v != null)` correctly excludes/includes keys given the same attrset the module constructs. If the module's `settingsToml` let binding were to use a different set of keys (e.g., a typo in a field name), these tests would not catch the regression since they duplicate the logic inline. Task 2 Step 1 (ExecStart eval through the full nixosSystem) provides integration coverage of the generated path existing.

**On Linux:** The generated TOML file contents can be read directly after building. To read the actual file on a Linux system or CI with a Linux builder:
```bash
nix eval --impure --accept-flake-config --raw --expr '
let
  flake = builtins.getFlake (builtins.toString ./.);
  nixpkgs = flake.inputs.nixpkgs;
  sys = nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      { services.ezpds.enable = true; services.ezpds.settings.public_url = "https://relay.example.com"; }
    ];
  };
  execStart = sys.config.systemd.services.ezpds.serviceConfig.ExecStart;
  # Extract the --config path from ExecStart: "... --config /nix/store/...-relay.toml"
  configPath = builtins.elemAt (builtins.match ".* --config (.*)" execStart) 0;
in builtins.readFile configPath
'
# Then confirm presence/absence of keys in the output
```

**Step 1: Verify database_url is excluded when null**

```bash
nix eval --impure --accept-flake-config --expr '
let
  lib = (builtins.getFlake (builtins.toString ./.)).inputs.nixpkgs.lib;
  settingsToml = lib.filterAttrs (_: v: v != null) {
    bind_address = "0.0.0.0";
    port = 8080;
    data_dir = "/var/lib/ezpds";
    public_url = "https://relay.example.com";
    database_url = null;
  };
in lib.hasAttr "database_url" settingsToml
'
```

Expected: `false`

**Step 2: Verify all expected keys are present**

```bash
nix eval --impure --accept-flake-config --expr '
let
  lib = (builtins.getFlake (builtins.toString ./.)).inputs.nixpkgs.lib;
  settingsToml = lib.filterAttrs (_: v: v != null) {
    bind_address = "0.0.0.0";
    port = 8080;
    data_dir = "/var/lib/ezpds";
    public_url = "https://relay.example.com";
    database_url = null;
  };
  keys = builtins.attrNames settingsToml;
in builtins.all (k: builtins.elem k keys) [ "bind_address" "port" "data_dir" "public_url" ]
'
```

Expected: `true`

**Step 3: Verify database_url is included when set**

```bash
nix eval --impure --accept-flake-config --expr '
let
  lib = (builtins.getFlake (builtins.toString ./.)).inputs.nixpkgs.lib;
  settingsToml = lib.filterAttrs (_: v: v != null) {
    bind_address = "0.0.0.0";
    port = 8080;
    data_dir = "/var/lib/ezpds";
    public_url = "https://relay.example.com";
    database_url = "sqlite:///var/lib/ezpds/custom.db";
  };
in lib.hasAttr "database_url" settingsToml
'
```

Expected: `true`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Smoke test — configFile escape hatch

**Verifies:** MM-135.AC3.1 (ExecStart uses configFile path), MM-135.AC3.2 (settings changes don't affect ExecStart when configFile set)

**Files:** None (read-only validation)

**Step 1: Verify ExecStart uses configFile when set**

```bash
nix eval --impure --accept-flake-config --raw --expr '
let
  flake = builtins.getFlake (builtins.toString ./.);
  # devenv-nixpkgs fork lacks lib.nixosSystem; use system nixpkgs from registry
  evalNixpkgs = builtins.getFlake "nixpkgs";
  sys = evalNixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      {
        services.ezpds.enable = true;
        services.ezpds.configFile = "/run/secrets/relay.toml";
        services.ezpds.settings.public_url = "https://relay.example.com";
      }
    ];
  };
in sys.config.systemd.services.ezpds.serviceConfig.ExecStart
'
```

Expected: `.../bin/relay --config /run/secrets/relay.toml`

The path must be `/run/secrets/relay.toml` (the configFile value), not a `/nix/store/...` path.

**Step 2: Verify settings changes don't affect ExecStart when configFile is set**

Run the same eval twice with different `settings.public_url` values — the ExecStart must be identical:

```bash
nix eval --impure --accept-flake-config --raw --expr '
let
  flake = builtins.getFlake (builtins.toString ./.);
  # devenv-nixpkgs fork lacks lib.nixosSystem; use system nixpkgs from registry
  evalNixpkgs = builtins.getFlake "nixpkgs";
  mkSys = url: evalNixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      flake.nixosModules.default
      {
        services.ezpds.enable = true;
        services.ezpds.configFile = "/run/secrets/relay.toml";
        services.ezpds.settings.public_url = url;
      }
    ];
  };
  execA = (mkSys "https://relay-a.example.com").config.systemd.services.ezpds.serviceConfig.ExecStart;
  execB = (mkSys "https://relay-b.example.com").config.systemd.services.ezpds.serviceConfig.ExecStart;
in if execA == execB then "PASS: settings changes do not affect ExecStart" else "FAIL: ExecStart changed"
'
```

Expected: `PASS: settings changes do not affect ExecStart`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Add nix-check recipe to justfile

**Verifies:** Operationalizes the smoke tests for ongoing use

**Files:**
- Modify: `justfile`

**Step 1: Add nix-check recipe**

Append to `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/justfile`:

```just
# Validate NixOS module evaluation (flake structure check).
# For full smoke tests (ExecStart composition, option enforcement, configFile
# escape hatch), run the nix eval commands in phase_03.md Tasks 2-5 manually.
nix-check:
    nix flake check --impure --accept-flake-config
```

**Step 2: Verify it runs**

```bash
just nix-check
```

Expected: exits 0.

**Step 3: Commit**

```bash
git add justfile
git commit -m "chore(MM-135): add nix-check recipe to justfile"
```
<!-- END_TASK_6 -->
