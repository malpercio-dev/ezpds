# MM-135 NixOS Module — Phase 2: Extend flake.nix with nixosModules.default

**Goal:** Expose `nix/module.nix` as a flake output so consumers can import it via `inputs.ezpds.nixosModules.default`. The wrapper injects the flake's own relay build as the default package.

**Architecture:** Add a `nixosModules.default` top-level output (outside `forEachSystem` — modules are not per-system). The wrapper module captures `self` via closure from the `outputs` function and uses `lib.mkDefault` so the operator can still override the package.

**Tech Stack:** Nix flake outputs, NixOS module system, `lib.mkDefault`.

**Scope:** Phase 2 of 3. Requires Phase 1 (`nix/module.nix`) to be complete. Phase 3 validates end-to-end eval.

**Codebase verified:** 2026-03-09

---

## Acceptance Criteria Coverage

### MM-135.AC5: `nixosModules.default` flake output
- **MM-135.AC5.1 Success:** `nix flake show --accept-flake-config` lists `nixosModules.default`
- **MM-135.AC5.2 Success:** When imported via `nixosModules.default`, `services.ezpds.package` defaults to the flake's `relay` build for the current system
- **MM-135.AC5.3 Success:** The bare `nix/module.nix` is importable directly as `imports = [ ./nix/module.nix ]` without the flake wrapper, provided the user sets `services.ezpds.package`

---

<!-- START_TASK_1 -->
### Task 1: Add nixosModules.default to flake.nix

**Verifies:** MM-135.AC5.1, MM-135.AC5.2, MM-135.AC5.3

**Files:**
- Modify: `flake.nix` (insert before the closing `};` of the outputs let block, after `devShells`)

Note: use the context code blocks below to locate the insertion point — do not rely on line numbers, which may shift if other changes land first.

**Step 1: Edit flake.nix**

In `/Users/malpercio/workspace/malpercio-dev/ezpds/flake.nix`, insert the `nixosModules.default` output after the closing `);` of the `devShells` output and before the `};` that closes the outputs let block.

The current end of the outputs block is:

```nix
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
  };                          # ← line 66: closing of outputs let block
}
```

After editing, it should look like:

```nix
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

    # nixosModules is not per-system — placed outside forEachSystem.
    # self is captured from the outputs function closure.
    nixosModules.default = { lib, pkgs, ... }: {
      imports = [ ./nix/module.nix ];
      config.services.ezpds.package =
        lib.mkDefault self.packages.${pkgs.system}.relay;
    };
  };
}
```

**Step 2: Verify the flake shows nixosModules.default**

```bash
nix flake show --accept-flake-config --allow-import-from-derivation
```

Expected output includes a line like:

```
├── nixosModules
│   └── default: NixOS module
```

*Note:* If `--allow-import-from-derivation` is not available in your nix version, use Step 3 instead, which does not require IFD.

**Step 3: Verify nixosModules attribute names**

```bash
nix eval .#nixosModules --apply builtins.attrNames --accept-flake-config
```

Expected output: `[ "default" ]`

**Step 4: Commit**

```bash
git add flake.nix
git commit -m "feat(MM-135): expose nixosModules.default in flake.nix"
```
<!-- END_TASK_1 -->
