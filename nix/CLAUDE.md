# Nix Packaging and Deployment

Last verified: 2026-03-09

## Purpose
Provides Nix-native build outputs (binary, container image) and a NixOS module
for declarative relay deployment. Keeps all Nix packaging logic out of the
top-level flake.nix.

## Contracts

### module.nix (NixOS module)
- **Exposes**: `services.ezpds` option namespace (enable, package, configFile, settings.*)
- **Guarantees**:
  - `settings.*` options generate a Nix-store TOML config passed via `--config`
  - `configFile` overrides all `settings.*` — when set, generated TOML is not used (escape hatch for agenix/sops-nix secret injection)
  - `database_url = null` is omitted from generated TOML (relay derives path from data_dir)
  - `public_url` is required; evaluation fails if unset
  - Dedicated `ezpds` system user/group created automatically
  - systemd service runs with hardening: ProtectSystem=strict, ProtectHome, NoNewPrivileges, PrivateTmp
  - StateDirectory "ezpds" managed by systemd (mode 0750)
  - ReadWritePaths always includes cfg.settings.data_dir — required when data_dir is not /var/lib/ezpds, since ProtectSystem=strict blocks writes elsewhere
- **Expects**: Caller provides `services.ezpds.settings.public_url` (or a complete `configFile`)

### docker.nix
- **Exposes**: Called by flake.nix to produce `packages.<system>.docker-image`
- **Guarantees**: Produces an OCI image tarball loadable via `docker load`
- **Expects**: Linux builder (not exposed on macOS)

## Dependencies
- **Uses**: `crates/relay/` binary (via `packages.<system>.relay`)
- **Used by**: flake.nix (imports module.nix, calls docker.nix)

## Key Decisions
- `lib.types.str` for paths (data_dir, configFile): avoids Nix store coercion of runtime paths
- configFile escape hatch: secrets must not land in world-readable Nix store
- systemd hardening on by default: defense-in-depth for a network-facing service

## Invariants
- module.nix must remain a standalone NixOS module importable without the flake
- ExecStart always passes `--config <path>` (never bare invocation)

## Key Files
- `module.nix` - NixOS module for relay deployment
- `docker.nix` - Docker image builder
