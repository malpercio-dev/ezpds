# MM-135 Test Requirements

## Automated Tests

### MM-135.AC1: Module options are correctly declared

| Criterion | Description | Test Location | Command / Assertion | Expected Result |
|-----------|-------------|---------------|---------------------|-----------------|
| MM-135.AC1.1 | `nix/module.nix` exists and is tracked by git | Phase 1 Task 1, Step 3 | `git ls-files nix/module.nix` | Returns `nix/module.nix` |
| MM-135.AC1.2 | All option fields are defined (`enable`, `package`, `configFile`, five `settings.*` fields) | Phase 1 Task 1, Step 2 | `nix eval --impure --expr 'builtins.typeOf (import ./nix/module.nix)'` | Returns `"lambda"` (confirms valid module function). Full option presence is structurally verified by Phase 3 Task 2 Step 1 (ExecStart eval succeeds only if all options resolve) and Phase 3 Task 3 (missing required options fail eval). |
| MM-135.AC1.3 | Default values match relay.toml defaults (`bind_address = "0.0.0.0"`, `port = 8080`, `data_dir = "/var/lib/ezpds"`, `database_url = null`) | Phase 3 Task 2 Step 1 + Phase 3 Task 4 Steps 1-2 | Task 2 Step 1: eval a minimal config (only `public_url` set) and extract `ExecStart` — succeeds only if defaults are valid. Task 4 Steps 1-2: verify `database_url` is excluded when null (confirming the null default) and that `bind_address`, `port`, `data_dir`, `public_url` are all present with defaults. | Task 2: ExecStart string contains `/bin/relay --config /nix/store/...-relay.toml`. Task 4 Step 1: `false` (database_url absent). Task 4 Step 2: `true` (all four non-null keys present). |
| MM-135.AC1.4 | Eval fails when `public_url` is not set | Phase 3 Task 3, Step 1 | `nix eval --impure --accept-flake-config --raw --expr '...'` (nixosSystem with `enable = true` but no `public_url`) | Non-zero exit code. Error references `services.ezpds.settings.public_url` as undefined/missing. |
| MM-135.AC1.5 | Eval fails when `package` is not set and bare module (not flake wrapper) is used | Phase 3 Task 3, Step 2 | `nix eval --impure --accept-flake-config --raw --expr '...'` (nixosSystem importing bare `./nix/module.nix` with `public_url` set but no `package`) | Non-zero exit code. Error references `services.ezpds.package` as undefined. |

### MM-135.AC2: TOML config generation

| Criterion | Description | Test Location | Command / Assertion | Expected Result |
|-----------|-------------|---------------|---------------------|-----------------|
| MM-135.AC2.1 | Generated TOML contains `bind_address`, `port`, `data_dir`, and `public_url` when all are set | Phase 3 Task 4, Step 2 | `nix eval --impure --accept-flake-config --expr '... builtins.all (k: builtins.elem k keys) [ "bind_address" "port" "data_dir" "public_url" ]'` | `true` |
| MM-135.AC2.2 | When `database_url` is null, the generated TOML does not contain a `database_url` key | Phase 3 Task 4, Step 1 | `nix eval --impure --accept-flake-config --expr '... lib.hasAttr "database_url" settingsToml'` (with `database_url = null`) | `false` |
| MM-135.AC2.3 | When `database_url` is set, the generated TOML contains the key | Phase 3 Task 4, Step 3 | `nix eval --impure --accept-flake-config --expr '... lib.hasAttr "database_url" settingsToml'` (with `database_url = "sqlite:///var/lib/ezpds/custom.db"`) | `true` |
| MM-135.AC2.4 | `ExecStart` uses `--config <path>` pointing to generated TOML | Phase 3 Task 2, Step 1 | `nix eval --impure --accept-flake-config --raw --expr '... sys.config.systemd.services.ezpds.serviceConfig.ExecStart'` | String matching `/nix/store/...-relay-0.1.0/bin/relay --config /nix/store/...-relay.toml` |

### MM-135.AC3: `configFile` escape hatch

| Criterion | Description | Test Location | Command / Assertion | Expected Result |
|-----------|-------------|---------------|---------------------|-----------------|
| MM-135.AC3.1 | When `configFile` is set, `ExecStart` uses that path instead of generated TOML | Phase 3 Task 5, Step 1 | `nix eval --impure --accept-flake-config --raw --expr '...'` (with `configFile = "/run/secrets/relay.toml"`) | String ends with `--config /run/secrets/relay.toml` (not a `/nix/store/...` path) |
| MM-135.AC3.2 | When `configFile` is set, changes to `settings.*` do not affect `ExecStart` | Phase 3 Task 5, Step 2 | `nix eval --impure --accept-flake-config --raw --expr '...'` (evaluates two configs with different `public_url` values but same `configFile`, compares ExecStart strings) | `PASS: settings changes do not affect ExecStart` |

### MM-135.AC4: User/group and state directory

| Criterion | Description | Test Location | Command / Assertion | Expected Result |
|-----------|-------------|---------------|---------------------|-----------------|
| MM-135.AC4.1 | `users.users.ezpds` is a system user with `group = "ezpds"` and `isSystemUser = true` | Phase 3 Task 2, Step 2 | `nix eval --impure --accept-flake-config --json --expr '... { isSystemUser = u.isSystemUser; group = u.group; }'` | `{"group":"ezpds","isSystemUser":true}` |
| MM-135.AC4.2 | `users.groups.ezpds` is defined | Phase 1 Task 1 (code review) | Structural: `nix/module.nix` contains `users.groups.ezpds = { };` in the `config` block | Group definition present in source. See Human Verification section for eval-level confirmation. |
| MM-135.AC4.3 | `systemd.services.ezpds.serviceConfig.StateDirectory = "ezpds"` | Phase 1 Task 1 (code review) | Structural: `nix/module.nix` contains `StateDirectory = "ezpds";` in `serviceConfig` | StateDirectory present in source. See Human Verification section for eval-level confirmation. |

### MM-135.AC5: `nixosModules.default` flake output

| Criterion | Description | Test Location | Command / Assertion | Expected Result |
|-----------|-------------|---------------|---------------------|-----------------|
| MM-135.AC5.1 | `nix flake show` lists `nixosModules.default` | Phase 2 Task 1 Step 2 + Phase 3 Task 1 Steps 2-3 | `nix flake show --accept-flake-config` and `nix eval .#nixosModules --apply builtins.attrNames --accept-flake-config` | Output includes `nixosModules` / `default: NixOS module`. Attribute names return `[ "default" ]`. |
| MM-135.AC5.2 | When imported via `nixosModules.default`, `services.ezpds.package` defaults to the flake's relay build | Phase 3 Task 2, Step 1 | `nix eval --impure --accept-flake-config --raw --expr '...'` (minimal config via `nixosModules.default` without setting `package`) | ExecStart contains a Nix store path to the relay binary (package was auto-injected). |
| MM-135.AC5.3 | Bare `nix/module.nix` is importable directly if `package` is set | Phase 3 Task 3, Step 2 (inverse) | The bare-module test (Step 2) fails only because `package` is missing. This confirms the bare module is syntactically importable — the failure is about the missing required option, not an import failure. | Non-zero exit referencing `services.ezpds.package`, not a syntax or import error. |

### MM-135.AC6: Scope boundaries

| Criterion | Description | Test Location | Command / Assertion | Expected Result |
|-----------|-------------|---------------|---------------------|-----------------|
| MM-135.AC6.1 | Module defines no options for `[blobs]`, `[oauth]`, or `[iroh]` sections | Phase 1 Task 1 (code review) | Structural: verify that `nix/module.nix` source contains no `blobs`, `oauth`, or `iroh` option declarations | No such options exist in the file. See Human Verification section. |

---

## Human Verification

### Criteria requiring manual verification

| Criterion | Reason | Verification Approach |
|-----------|--------|-----------------------|
| MM-135.AC2.1 (full TOML content) | Phase 3 Task 4 tests the `filterAttrs` logic in isolation, not the actual generated TOML file. Reading the generated TOML requires IFD (Import from Derivation), which requires a Linux builder. | **On Linux / CI:** Run the IFD-based command from Phase 3 Task 4 "On Linux" block: extract the `--config` path from ExecStart and `builtins.readFile` it, then confirm `bind_address`, `port`, `data_dir`, and `public_url` keys are present. |
| MM-135.AC4.2 (group eval) | Phase 3 tests verify the user but do not explicitly eval `users.groups.ezpds`. | **Manual eval:** `nix eval --impure --accept-flake-config --json --expr '... builtins.hasAttr "ezpds" sys.config.users.groups'` where `sys` is a minimal nixosSystem with the module enabled. Expected: `true`. |
| MM-135.AC4.3 (StateDirectory eval) | Phase 3 tests verify ExecStart but do not explicitly eval `StateDirectory`. | **Manual eval:** `nix eval --impure --accept-flake-config --raw --expr '... sys.config.systemd.services.ezpds.serviceConfig.StateDirectory'`. Expected: `"ezpds"`. |
| MM-135.AC6.1 (no stub sections) | Negative criterion — automated tests verify what exists, not what is absent. | **Code review:** `grep -E 'blobs\|oauth\|iroh' nix/module.nix` must produce zero matches. |
| MM-135.AC5.3 (bare module success path) | Phase 3 Task 3 Step 2 proves the bare module is importable by showing the failure is a missing required option, not an import error. But no test demonstrates a successful eval with `package` set explicitly. | **Manual eval:** Run the bare-module eval with `services.ezpds.package = pkgs.hello` (any derivation as stand-in) and `public_url` set. Confirm eval succeeds and ExecStart contains the provided package path. |
| Runtime behavior | All tests are eval-time (Nix expression evaluation). No test confirms the relay binary actually starts under systemd with the generated config. | **NixOS VM or deployment:** Use `nixos-rebuild build-vm` or deploy to a NixOS test system. Run `systemctl status ezpds` and verify the service starts, runs as `ezpds:ezpds`, and writes to `/var/lib/ezpds`. |
| Systemd hardening | Directives (`ProtectSystem = "strict"`, `PrivateTmp`, `NoNewPrivileges`, `StateDirectoryMode = "0750"`) are set in source but not eval-tested. | **Code review + runtime:** Inspect `nix/module.nix` for the hardening directives. On a live NixOS system, run `systemd-analyze security ezpds` to verify the security score. |

---

## Notes

1. **macOS vs Linux limitation:** All Phase 3 smoke tests evaluate for `system = "x86_64-linux"` on a macOS host. This works for pure Nix option evaluation but cannot build derivations or read generated file contents (IFD). Full TOML content verification (AC2.1 complete) requires a Linux builder.

2. **Phase 3 Task 4 test fidelity:** The TOML key inclusion/exclusion tests duplicate the `lib.filterAttrs` logic inline rather than evaluating through the module. If the module's `settingsToml` binding diverged from the tested pattern, these tests would not catch the regression. This is a known limitation documented in Phase 3 Task 4.

3. **`nix flake check` coverage:** Validates overall flake structure (outputs schema, module syntax) but does not evaluate NixOS configurations. The individual `nix eval` smoke tests in Phase 3 Tasks 2-5 provide the deeper option-resolution coverage.

4. **`configFile` type deviation:** The implementation uses `lib.types.nullOr lib.types.str` for `configFile` (not `path` as in the design table). This is intentional — `path` type coerces values into Nix store paths, defeating the escape hatch. Tests in Phase 3 Task 5 validate the `str` behavior by confirming the literal path appears in ExecStart.
