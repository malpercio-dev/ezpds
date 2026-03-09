# MM-135 NixOS Module — Phase 1: Write nix/module.nix

**Goal:** Create the complete NixOS module at `nix/module.nix` with option declarations, TOML config generation, user/group creation, and a hardened systemd service definition.

**Architecture:** A standalone NixOS module using the `{ lib, pkgs, config, ... }:` module calling convention. It declares the `services.ezpds` option tree and wires it into systemd, users, and groups. Config generation uses `pkgs.formats.toml {}`. The `configFile` escape hatch bypasses generated config for operators using agenix or sops-nix.

**Tech Stack:** Nix language, NixOS module system (`lib.mkOption`, `lib.mkIf`, `lib.filterAttrs`), `pkgs.formats.toml`, systemd service options.

**Scope:** Phase 1 of 3. Creates `nix/module.nix`. Phase 2 exposes it as a flake output. Phase 3 validates eval correctness end-to-end.

**Codebase verified:** 2026-03-09

---

## Acceptance Criteria Coverage

This phase creates the module. Eval-based verification (AC1.4, AC1.5, AC2.1–AC2.3, AC3.x) happens in Phase 3.

### MM-135.AC1: Module options are correctly declared
- **MM-135.AC1.1 Success:** `nix/module.nix` exists and is tracked by git (`git ls-files nix/module.nix` returns it)
- **MM-135.AC1.2 Success:** `services.ezpds.enable`, `services.ezpds.package`, `services.ezpds.configFile`, and all five `services.ezpds.settings.*` fields are defined as NixOS options
- **MM-135.AC1.3 Success:** Default values match relay.toml defaults — `bind_address = "0.0.0.0"`, `port = 8080`, `data_dir = "/var/lib/ezpds"`, `database_url = null`

### MM-135.AC2: TOML config generation
- **MM-135.AC2.4 Success:** The relay `ExecStart` line uses `--config <path>` pointing to the generated TOML derivation

### MM-135.AC3: `configFile` escape hatch
- **MM-135.AC3.1 Success:** When `services.ezpds.configFile` is set to a path, `ExecStart` uses that path instead of the generated TOML
- **MM-135.AC3.2 Success:** When `configFile` is set, changes to `settings.*` do not affect the `ExecStart` command

### MM-135.AC4: User/group and state directory
- **MM-135.AC4.1 Success:** `users.users.ezpds` is defined as a system user with `group = "ezpds"` and `isSystemUser = true`
- **MM-135.AC4.2 Success:** `users.groups.ezpds` is defined
- **MM-135.AC4.3 Success:** `systemd.services.ezpds.serviceConfig.StateDirectory = "ezpds"` — systemd creates `/var/lib/ezpds` owned by `ezpds:ezpds` on first activation

### MM-135.AC6: Scope boundaries
- **MM-135.AC6.1 Negative:** `nix/module.nix` defines no options for `[blobs]`, `[oauth]`, or `[iroh]` relay.toml sections (deferred to later milestones)

---

## Design Deviations

**`configFile` type: `lib.types.nullOr lib.types.str` instead of `lib.types.nullOr lib.types.path`**

The design plan option table (line 86) lists `configFile` as `nullOr path`. This implementation uses `nullOr str` instead. Reason: `lib.types.path` coerces string literals into Nix store paths at evaluation time — e.g., setting `configFile = "/run/secrets/relay.toml"` with a `path` type would produce a store path like `/nix/store/...-relay.toml` that does NOT point to the operator's secret file. This defeats the entire purpose of the escape hatch for agenix/sops-nix secret injection. Using `lib.types.str` preserves the value verbatim, matching the same rationale as `data_dir` (also `str`). The implementation is more correct than the design document on this point.

---

<!-- START_TASK_1 -->
### Task 1: Create nix/module.nix

**Verifies:** MM-135.AC1.1, MM-135.AC1.2, MM-135.AC1.3, MM-135.AC2.4, MM-135.AC3.1, MM-135.AC3.2, MM-135.AC4.1, MM-135.AC4.2, MM-135.AC4.3, MM-135.AC6.1

**Files:**
- Create: `nix/module.nix`

**Step 1: Create nix/module.nix**

Create `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/nix/module.nix` with the following contents:

```nix
{ lib, pkgs, config, ... }:

let
  cfg = config.services.ezpds;

  # Build the TOML attrset, omitting database_url when null.
  # When null, the relay binary derives the database path from data_dir.
  settingsToml = lib.filterAttrs (_: v: v != null) {
    inherit (cfg.settings) bind_address port data_dir public_url database_url;
  };

  generatedConfigFile = (pkgs.formats.toml { }).generate "relay.toml" settingsToml;

  # When configFile is set, bypass the Nix-store-generated TOML entirely.
  # This is the escape hatch for secret injection via agenix or sops-nix.
  activeConfigFile =
    if cfg.configFile != null then cfg.configFile else generatedConfigFile;

in
{
  options.services.ezpds = {
    enable = lib.mkEnableOption "ezpds relay server";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The ezpds relay package to use.";
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path to a relay.toml configuration file.
        When set, all settings.* options are ignored and this path is
        passed directly to --config. Use with agenix or sops-nix to
        keep secrets outside the world-readable Nix store.
      '';
    };

    settings = {
      bind_address = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0";
        description = "IP address to bind the relay HTTP server to.";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 8080;
        description = "TCP port to bind the relay HTTP server to.";
      };

      data_dir = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/ezpds";
        description = ''
          Path to the relay data directory. Must be writable by the ezpds user.
          Uses lib.types.str (not lib.types.path) to preserve the value as a
          literal string and avoid Nix store coercion of runtime paths.
        '';
      };

      public_url = lib.mkOption {
        type = lib.types.str;
        description = ''
          Public URL where this relay is reachable (e.g. https://relay.example.com).
          Required — Nix evaluation fails if this option is not set.
        '';
      };

      database_url = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          SQLite database URL. When null (the default), the relay derives
          the database path from data_dir. Omitted from the generated
          relay.toml when null.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.ezpds = {
      isSystemUser = true;
      group = "ezpds";
      description = "ezpds relay service user";
    };

    users.groups.ezpds = { };

    systemd.services.ezpds = {
      description = "ezpds relay server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        User = "ezpds";
        Group = "ezpds";
        ExecStart = "${cfg.package}/bin/relay --config ${activeConfigFile}";
        StateDirectory = "ezpds";
        StateDirectoryMode = "0750";
        Restart = "on-failure";
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = true;
      };
    };
  };
}
```

**Step 2: Verify the file is a valid Nix function**

```bash
nix eval --impure --expr 'builtins.typeOf (import ./nix/module.nix)'
```

Expected output: `"lambda"`

This confirms the file is a well-formed Nix function expression (the module calling convention).

**Step 3: Stage and verify git tracking**

```bash
git add nix/module.nix
git ls-files nix/module.nix
```

Expected output: `nix/module.nix`

**Step 4: Commit**

```bash
git commit -m "feat(MM-135): add NixOS module nix/module.nix"
```
<!-- END_TASK_1 -->
