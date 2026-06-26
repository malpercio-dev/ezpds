# Nix Packaging and Deployment

Last verified: 2026-06-26

## Purpose
Provides a NixOS module (`module.nix`) for declarative PDS deployment via OCI containers
(podman/Docker). The PDS image is built externally (via `docker build` or CI/CD)
and referenced by digest in the module.

## Contracts

### module.nix (NixOS module)
- **Exposes**: `services.ezpds` option namespace
  - `enable` - Enable/disable the PDS service
  - `image` (required) - OCI image reference, ideally digest-pinned (e.g., `ghcr.io/owner/pds@sha256:...`)
  - `port` (default 8080) - Host port to publish
  - `dataDir` (default `/var/lib/ezpds`) - Host directory bind-mounted to container's `/data`
  - `publicUrl` (required) - Public https URL of the PDS
  - `availableUserDomains` (required) - Allowed handle domains (list of strings)
  - `environmentFile` (optional) - Path to env file from agenix/sops-nix holding secrets (e.g., EZPDS_SIGNING_KEY_MASTER_KEY, EZPDS_ADMIN_TOKEN)

- **Guarantees**:
  - Creates OCI container configuration via `virtualisation.oci-containers.containers.ezpds`
  - Binds `dataDir` to container's `/data` mount point
  - Passes environment variables to container (publicUrl, availableUserDomains, dataDir path, port)
  - Secrets from `environmentFile` are injected at container start, kept out of Nix store
  - systemd.tmpfiles creates `dataDir` with mode 0750
  - NoNewPrivileges=true enforced on generated podman/docker systemd unit
  - Container runs non-root (relay uid 10001, baked into OCI image)

- **Expects**: 
  - Caller has enabled a container backend (e.g., `virtualisation.oci-containers.backend = "podman"`)
  - Caller provides `services.ezpds.image` (digest-pinned OCI image reference)
  - Caller provides `services.ezpds.publicUrl` and `services.ezpds.availableUserDomains`

## Dependencies
- **Uses**: OCI image (built externally, not by Nix)
- **Used by**: NixOS configurations importing `nixosModules.default` from the flake

## Key Decisions
- Container-based deployment (not binary package) allows runtime secrets via environmentFile
- `lib.types.str` for paths: avoids Nix store coercion of runtime paths
- environmentFile escape hatch: secrets must not land in world-readable Nix store
- Non-root container (uid 10001) + NoNewPrivileges: defense-in-depth for network-facing service
- Digest-pinned image references: ensures reproducibility and prevents accidental image rollbacks

## Invariants
- module.nix must remain a standalone NixOS module importable without the flake
- `services.ezpds.image` is mandatory — evaluation fails if unset
- Container image is built and distributed externally (not via `nix build`)

## Key Files
- `module.nix` - NixOS module for PDS OCI container deployment
