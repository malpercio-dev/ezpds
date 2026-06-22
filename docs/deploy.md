# Relay Deployment

**Last verified:** 2026-06-21

## Overview

The relay is deployed as an OCI container (Docker/Podman) running on Railway (or any Linux host with a container runtime). Secrets are injected at container start via `environmentFile` (agenix/sops-nix on NixOS, or plain env files elsewhere). The relay's single-instance SQLite database persists to a host-mounted `/data` volume.

## Container Runtime Contract

The relay container expects the following environment variables and mounts:

### Environment Variables
- **`EZPDS_PUBLIC_URL`** (required) - Public HTTPS URL of the relay (e.g., `https://relay.example.com`)
- **`EZPDS_AVAILABLE_USER_DOMAINS`** (required) - Comma-separated list of allowed handle domains (e.g., `example.com,example.bsky.social`)
- **`EZPDS_SIGNING_KEY_MASTER_KEY`** (required) - 64-character hex string (32 bytes) for DID key derivation
- **`EZPDS_ADMIN_TOKEN`** (required) - Bearer token for admin-only endpoints (e.g., rotation key claiming)
- **`EZPDS_DATA_DIR`** (optional, default `/data`) - Directory where `relay.db` is persisted. Set by the Dockerfile ENV; can be overridden if the data volume is mounted elsewhere. Must be writable by the container process.
- **`PORT`** (optional, default `8080`) - Port to listen on inside the container

### Volumes
- **`/data`** - Host directory bind-mounted for SQLite database persistence. The relay creates `relay.db` and `relay.db-shm`/`relay.db-wal` (WAL files) inside. Must be writable by the container's non-root user (uid 10001). Host permissions should be `0750` or `0755`.

### Health Check
- **`GET /xrpc/_health`** - Simple liveness probe (returns 200 OK). Container runtimes can use this for health checks and automated restarts.

## Railway Deployment

### Config as code vs Railway dashboard

`railway.toml` (committed to the repo) captures everything that applies to any deploy of this codebase: Dockerfile builder, health check path, restart policy. Everything else is deliberately Railway-side:

| Config | Where | Why |
|--------|-------|-----|
| Dockerfile builder, health check, restart policy | `railway.toml` (repo) | Applies to all deploys; no secrets |
| `EZPDS_PUBLIC_URL` | Railway dashboard | Environment-specific (staging ≠ production) |
| `EZPDS_AVAILABLE_USER_DOMAINS` | Railway dashboard | Deployment-specific |
| `EZPDS_SIGNING_KEY_MASTER_KEY` | Railway dashboard (sealed) | Secret — never in git |
| `EZPDS_ADMIN_TOKEN` | Railway dashboard (sealed) | Secret — never in git |
| `EZPDS_DATA_DIR` | Not needed in Railway | Already set to `/data` by Dockerfile `ENV` |
| `PORT` | Not needed in Railway | Railway injects it automatically; relay falls through to this |
| Volume mount | Railway dashboard | Railway infra — no `railway.toml` equivalent |
| Domain | Railway dashboard | Environment-specific |

### Setup Steps

1. **Create Railway project** for the relay.
2. **Add a Dockerfile service:**
   - The repo is on tangled, which Railway cannot connect to directly, so deploys are driven by the spindle CI pipeline via the Railway CLI (`railway up`) — see **CI/CD pipeline** below. Railway detects `railway.toml` and uses the Dockerfile builder automatically. (For initial bootstrap you can also run `railway up` from a local checkout.)
   - Set the following environment variables in the Railway dashboard:
     - `EZPDS_PUBLIC_URL` - Use the Railway domain once assigned (see chicken-and-egg note below).
     - `EZPDS_AVAILABLE_USER_DOMAINS` - Your handle domain list (comma-separated).
     - `EZPDS_SIGNING_KEY_MASTER_KEY` - 64-character hex string; generate with: `openssl rand -hex 32`
     - `EZPDS_ADMIN_TOKEN` - A secure random token.
   - Do **not** set `PORT` or `EZPDS_DATA_DIR` — Railway injects `PORT` automatically, and `EZPDS_DATA_DIR=/data` is already set by the Dockerfile `ENV`.

3. **Add a volume:**
   - In the Railway dashboard, create a volume and mount it to `/data` inside the container.
   - Railway persists the volume across restarts and redeploys.
   - **Note:** The Dockerfile does not contain a `VOLUME` instruction — Railway does not support that directive and rejects builds that include it. The volume is configured entirely in the Railway dashboard.

4. **Domain + HTTPS:**
   - Railway automatically provisions an HTTPS domain (e.g., `relay-xyz.up.railway.app`).
   - If you own a custom domain, add a CNAME record to Railway's assigned domain.
   - Update `EZPDS_PUBLIC_URL` to your final domain once the Railway domain is known.

### Chicken-and-Egg: EZPDS_PUBLIC_URL

The relay validates its public URL against the domain it's accessed through. On first deploy to Railway:
1. Set `EZPDS_PUBLIC_URL` to the Railway-assigned domain (e.g., `https://relay-xyz.railway.app`).
2. Let the first deployment complete and verify health: `curl https://relay-xyz.railway.app/xrpc/_health`.
3. If migrating a custom domain, update `EZPDS_PUBLIC_URL` and redeploy.

### CI/CD pipeline (tangled spindle → Railway)

The repo and CI live on tangled; there is no GitHub integration. Three spindle workflows in `.tangled/workflows/` drive everything, each running the `just ci` gate first (fmt, clippy, test, audit):

| Workflow | Trigger | Action |
|----------|---------|--------|
| `pr.yaml` | pull request → `main` | test gate only (no deploy, no Railway token) |
| `staging.yaml` | push → `main` | `just ci`, then `railway up` to the **staging** environment |
| `release.yaml` | push a `v*` tag | `just ci`, then `railway up` to **production** |

Deploys use the Railway CLI (a `nixpkgs` dependency in the workflow) authenticated by an environment-scoped project token stored as a tangled repo secret (`RAILWAY_TOKEN_STAGING` / `RAILWAY_TOKEN_PRODUCTION`). Because `railway up --ci` returns at build completion, `scripts/ci/railway-wait-healthy.sh` then polls deployment status so an unhealthy deploy fails the pipeline. No Railway token is present in PR pipelines.

**Two environments:** `production` (`ezpds-production.up.railway.app`, kept warm) and `staging` (`ezpds-staging.up.railway.app`, serverless sleep), each with its own secrets (distinct master key, admin token, user-domain list) and its own `/data` volume. Production is reached only by pushing a `v*` tag — merging to `main` deploys staging, never production.

### Backup & rollback

When `LITESTREAM_S3_BUCKET` is set on the production environment — together with `LITESTREAM_S3_ENDPOINT` and `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY` — the container runs the relay under Litestream, which streams the SQLite WAL to object storage continuously and restores on boot, so a current restore point always exists before a promote. The replica is defined in `litestream.yml` with `force-path-style: false` (virtual-hosted-style, as Railway/Tigris-style buckets require). Staging/local leave these unset and run the relay directly.

Rollback: because migrations are **forward-only** (no down-path), redeploying a previous `v*` tag is safe only when the schema change was backward-compatible (expand-contract). Otherwise, roll back by restoring the database from the Litestream replica (`litestream restore`) to a pre-promote point.

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
EZPDS_SIGNING_KEY_MASTER_KEY=<64-hex-chars>
EZPDS_ADMIN_TOKEN=<secure-token>
```

The module creates a systemd unit `podman-ezpds.service` that starts the container, binds the data directory, and injects the secrets.

## Image Distribution

For the **Railway** path no registry is required — `railway up` uploads the build context and Railway builds the `Dockerfile`. A published image is only needed for the **secondary** colmena/NixOS path, via **GHCR** (GitHub Container Registry):

```bash
# Build locally (development):
docker build -t ghcr.io/your-org/relay:latest .

# Push to GHCR:
docker push ghcr.io/your-org/relay:latest

# For reproducibility in production, capture the digest from the push output or inspect:
docker buildx imagetools inspect ghcr.io/your-org/relay:latest | grep Digest
# Then update references to use the returned digest:
ghcr.io/your-org/relay@sha256:abc123...
```

The primary CI/CD path (tangled spindle → Railway, above) needs none of this. For the colmena/NixOS path, publish to GHCR (a GitHub account/PAT works even though the repo lives on tangled) and pin the image by digest in the NixOS module.

## Security Posture

The relay image is hardened with:
- **Non-root container** - Runs as uid 10001 (created in the Dockerfile).
- **NoNewPrivileges** - Set by the ezpds NixOS module on the generated `podman-ezpds.service` unit; prevents privilege escalation.
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
