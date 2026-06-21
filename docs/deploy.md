# Relay Deployment

**Last verified:** 2026-06-20

## Overview

The relay is deployed as an OCI container (Docker/Podman) running on Railway (or any Linux host with a container runtime). Secrets are injected at container start via `environmentFile` (agenix/sops-nix on NixOS, or plain env files elsewhere). The relay's single-instance SQLite database persists to a host-mounted `/data` volume.

## Container Runtime Contract

The relay container expects the following environment variables and mounts:

### Environment Variables
- **`EZPDS_PUBLIC_URL`** (required) - Public HTTPS URL of the relay (e.g., `https://relay.example.com`)
- **`EZPDS_AVAILABLE_USER_DOMAINS`** (required) - Comma-separated list of allowed handle domains (e.g., `example.com,example.bsky.social`)
- **`EZPDS_SIGNING_KEY_MASTER_KEY`** (required) - Base64-encoded 32-byte key for DID key derivation
- **`EZPDS_ADMIN_TOKEN`** (required) - Bearer token for admin-only endpoints (e.g., rotation key claiming)
- **`PORT`** (optional, default `8080`) - Port to listen on inside the container

### Volumes
- **`/data`** - Host directory bind-mounted for SQLite database persistence. The relay creates `data.db` and `data.db-shm`/`data.db-wal` (WAL files) inside. Must be writable by the container's non-root user (uid 10001). Host permissions should be `0750` or `0755`.

### Health Check
- **`GET /xrpc/_health`** - Simple liveness probe (returns 200 OK). Container runtimes can use this for health checks and automated restarts.

## Railway Deployment

### Setup Steps

1. **Create Railway project** for the relay.
2. **Add a Dockerfile service:**
   - Connect to the GitHub repo (or configure manual Dockerfile path).
   - Railway auto-detects the `Dockerfile` at the repo root.
   - Set the following environment variables in Railway:
     - `EZPDS_PUBLIC_URL` - Use the Railway domain once assigned (see chicken-and-egg note below).
     - `EZPDS_AVAILABLE_USER_DOMAINS` - Your handle domain list.
     - `EZPDS_SIGNING_KEY_MASTER_KEY` - Generated signing key (base64).
     - `EZPDS_ADMIN_TOKEN` - A secure random token.
   - Optionally override `PORT` (Railway default is `8080`; relay listens on whatever you set).

3. **Add a volume:**
   - Create a volume named (e.g., `relay-data`) and mount it to `/data` inside the container.
   - Railway persists the volume across restarts.

4. **Domain + HTTPS:**
   - Railway automatically provisions an HTTPS domain (e.g., `relay-xyz.railway.app`).
   - If you own a custom domain, add a CNAME record to Railway's assigned domain.
   - Update `EZPDS_PUBLIC_URL` to your final domain once the railway domain is known.

### Chicken-and-Egg: EZPDS_PUBLIC_URL

The relay validates its public URL against the domain it's accessed through. On first deploy to Railway:
1. Set `EZPDS_PUBLIC_URL` to the Railway-assigned domain (e.g., `https://relay-xyz.railway.app`).
2. Let the first deployment complete and verify health: `curl https://relay-xyz.railway.app/xrpc/_health`.
3. If migrating a custom domain, update `EZPDS_PUBLIC_URL` and redeploy.

## Colmena / NixOS oci-containers Deployment

For self-hosted NixOS with colmena, use `nixosModules.default` from the flake:

```nix
# colmena target config
services.ezpds.enable = true;
services.ezpds.image = "ghcr.io/your-org/relay@sha256:...";  # Digest-pinned image
services.ezpds.publicUrl = "https://relay.example.com";
services.ezpds.availableUserDomains = ["example.com" "example.bsky.social"];
services.ezpds.environmentFile = "/etc/ezpds-secrets.env";   # agenix/sops-managed secrets
services.ezpds.dataDir = "/var/lib/ezpds";

# Ensure a container backend is enabled:
virtualisation.oci-containers.backend = "podman";
```

The `environmentFile` contains secrets not stored in Nix (via agenix or sops-nix):
```bash
EZPDS_SIGNING_KEY_MASTER_KEY=<base64>
EZPDS_ADMIN_TOKEN=<secure-token>
```

The module creates a systemd unit `podman-ezpds.service` that starts the container, binds the data directory, and injects the secrets.

## Image Distribution

The relay image is built from the repo `Dockerfile` and published to **GHCR** (GitHub Container Registry):

```bash
# Build locally (development):
docker build -t ghcr.io/your-org/relay:latest .

# Push to GHCR:
docker push ghcr.io/your-org/relay:latest

# For reproducibility in production, pin by digest:
docker push ghcr.io/your-org/relay:latest
# Then update references to use the returned digest:
ghcr.io/your-org/relay@sha256:abc123...
```

In CI/CD (e.g., GitHub Actions), automate this: trigger on tag/main push, build, push to GHCR, and redeploy via Railway webhook or colmena.

## Security Posture

The relay image is hardened with:
- **Non-root container** - Runs as uid 10001 (created in the Dockerfile).
- **NoNewPrivileges** - Set on the systemd unit (oci-containers module enforces this); prevents privilege escalation.
- **No secrets in image** - All runtime secrets injected via `environmentFile` or env vars, not baked into the image.
- **Read-only root (where possible)** - SQLite writes to `/data` only; rest of the image can be read-only (optional; set `read_only = true` in container config if desired).

## Reproducibility Tradeoff

The relay switched from Nix-built reproducibility (`flake.nix` → `packages.<system>.relay`) to a **Dockerfile-based container**. This is an **intentional tradeoff** accepted for a solo/experimental relay:

### What We Lose
- **Full Nix/flake reproducibility** - The Docker image is pinned by a Dockerfile digest build (not a Nix hash).
- **Nix-level caching and build inputs** - Docker builds use standard layer caching, not Nix's fine-grained dependency tracking.

### What We Gain
- **Industry-standard deployment** - Dockerfile + container runtime is universal (no Nix knowledge needed to deploy).
- **CI/CD simplicity** - GitHub Actions can build and push without Nix; Railway builds Dockerfiles natively.
- **Faster iteration** - Smaller build context (no full Nix evaluation).

### How We Mitigate Reproducibility
1. **Digest-pinned base images** - `Dockerfile` specifies base images by digest (e.g., `FROM rust:1.84.1@sha256:...`), not floating tags.
2. **Locked Cargo dependencies** - `Cargo.lock` (committed) is used with `cargo build --locked`, ensuring Rust dependency reproducibility.
3. **Asset pinning in CI** - Published images are tagged with commit SHA and digest, enabling rollback and traceability.

### Acceptable Trade-off
For a solo/experimental relay (Wave 1–2), this is the right balance. When Wave 3 (multi-user/production) arrives, consider:
- Running colmena+NixOS everywhere (abandon Dockerfile).
- Using Nix to build the Dockerfile base image, or
- Staying with Dockerfile + Cargo.lock and accepting the modest reproducibility gap (many teams do this).

This decision is orthogonal to the relay's architecture and data model; it can be revisited without breaking changes.
