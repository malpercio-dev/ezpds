# PDS Deployment

**Last verified:** 2026-07-16

## Overview

The PDS is deployed as an OCI container (Docker/Podman) running on Railway (or any Linux host with a container runtime). Secrets are injected at container start via `environmentFile` (agenix/sops-nix on NixOS, or plain env files elsewhere). The PDS's single-instance SQLite database persists to a host-mounted `/data` volume.

## Container Runtime Contract

The PDS container expects the following environment variables and mounts:

### Environment Variables
- **`EZPDS_PUBLIC_URL`** (required) - Public HTTPS URL of the PDS (e.g., `https://PDS.example.com`)
- **`EZPDS_AVAILABLE_USER_DOMAINS`** (required) - Comma-separated list of allowed handle domains (e.g., `example.com,example.bsky.social`)
- **`EZPDS_RESERVED_HANDLES`** (optional, default `identitywallet,about`) - Comma-separated handle names (first DNS label) that may never be claimed under a served domain — infrastructure hostnames in the user-handle wildcard space (e.g. `identitywallet.obsign.org`, `about.obsign.org`). Compared case-insensitively. Set to an explicit empty value to reserve nothing.
- **`EZPDS_SIGNING_KEY_MASTER_KEY`** (required) - 64-character hex string (32 bytes) for DID key derivation
- **`EZPDS_ADMIN_TOKEN`** (required) - Bearer token for admin-only endpoints (e.g., rotation key claiming)
- **`EZPDS_DATA_DIR`** (optional, default `/data`) - Directory where `relay.db` is persisted. Set by the Dockerfile ENV; can be overridden if the data volume is mounted elsewhere. Must be writable by the container process.
- **`PORT`** (optional, default `8080`) - Port to listen on inside the container
- **`EZPDS_EMAIL_PROVIDER`** (optional, default `log`) - Outbound email delivery: `log`, `smtp`, or `mailtrap`. The default only *logs* messages — email-confirmation, password-reset, PLC-operation, and account-delete tokens go nowhere — so a real deployment must pick a delivering provider. **On Railway, note that non-Pro plans block outbound SMTP ports entirely**; use `mailtrap` (Mailtrap's transactional HTTPS Send API) there, with `EZPDS_EMAIL_FROM` and `EZPDS_EMAIL_HTTP_TOKEN` (sealed; `EZPDS_EMAIL_HTTP_API_URL` overrides the endpoint). Where SMTP egress works (Railway Pro, self-hosting), `smtp` takes `EZPDS_EMAIL_FROM`, `EZPDS_EMAIL_SMTP_HOST`, and as needed `EZPDS_EMAIL_SMTP_PORT` / `EZPDS_EMAIL_SMTP_USERNAME` / `EZPDS_EMAIL_SMTP_PASSWORD` (sealed) / `EZPDS_EMAIL_SMTP_TLS`.
- **`EZPDS_IROH_ENABLED`** (optional, default `false`) - Set to `true` to bind the Iroh QUIC tunnel alongside the HTTP server, letting devices reach the PDS through NAT by dialing its node id. The node id is advertised via `GET /v1/devices/:id/pds` and is **stable across restarts only when `EZPDS_SIGNING_KEY_MASTER_KEY` is set** (otherwise the identity is ephemeral and rotates each boot). Iroh uses outbound UDP and the n0 discovery/relay servers for NAT traversal.
- **`EZPDS_IROH_IPV6`** (optional, default `true`) - Set to `false` on hosts with no public IPv6 egress (e.g. **Railway** — its containers carry internal v6 addresses but can't route them). With v6 enabled on such a host, iroh's v6 relay probes fail with `NetworkUnreachable` forever — one WARN every ~80s that buries real errors — even though IPv4 paths carry all traffic. `false` skips binding the IPv6 QUIC socket entirely, so those warnings never occur; the tunnel works identically over v4.
- **`EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED`** (optional, default `false`) - Opt-in for the auth.md `service_auth` agent-registration flow (`POST /agent/identity` with a `login_hint` email → claim ceremony the account owner confirms in Obsign). Every agent-registration flow is off by default; the discovery surface (AS metadata, `/auth.md`) is served regardless, and a disabled flow answers its `*_not_enabled` error instead of acting. Sibling knobs (`anonymous_enabled`, trusted issuers, TTLs, granted scopes) are documented on `[agent_auth]` in `crates/common/src/config.rs`. The Custos MCP server's self-onboarding depends on this flag.

### Volumes
- **`/data`** - Host directory bind-mounted for SQLite database persistence. The PDS creates `relay.db` and `relay.db-shm`/`relay.db-wal` (WAL files) inside. Must be writable by the container's non-root user (uid 10001). Host permissions should be `0750` or `0755`.

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
| `EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED` | Railway dashboard | Per-environment opt-in; `true` on production since 2026-07-13 (agent onboarding / Custos MCP) |
| `EZPDS_DATA_DIR` | Not needed in Railway | Already set to `/data` by Dockerfile `ENV` |
| `PORT` | Not needed in Railway | Railway injects it automatically; PDS falls through to this |
| Volume mount | Railway dashboard | Railway infra — no `railway.toml` equivalent |
| Domain | Railway dashboard | Environment-specific |

### Setup Steps

1. **Create Railway project** for the PDS.
2. **Add a Dockerfile service:**
   - Connect the Railway service to the GitHub repo and let Railway build and deploy on its own — see **CI/CD pipeline** below. Railway detects `railway.toml` and uses the Dockerfile builder automatically.
   - Set the following environment variables in the Railway dashboard:
     - `EZPDS_PUBLIC_URL` - Use the Railway domain once assigned (see chicken-and-egg note below).
     - `EZPDS_AVAILABLE_USER_DOMAINS` - Your handle domain list (comma-separated).
     - `EZPDS_SIGNING_KEY_MASTER_KEY` - 64-character hex string; generate with: `openssl rand -hex 32`
     - `EZPDS_ADMIN_TOKEN` - A secure random token.
     - `EZPDS_EMAIL_PROVIDER` + provider settings - **Required for a real deployment.** Leaving the default `log` provider silently disables outbound email — confirmation, password-reset, PLC-operation, and account-delete tokens are only logged, never sent. On Railway non-Pro plans (outbound SMTP blocked) set `mailtrap` with `EZPDS_EMAIL_FROM` + `EZPDS_EMAIL_HTTP_TOKEN` (sealed); see the container contract above for the `smtp` alternative.
   - Do **not** set `PORT` or `EZPDS_DATA_DIR` — Railway injects `PORT` automatically, and `EZPDS_DATA_DIR=/data` is already set by the Dockerfile `ENV`.

3. **Add a volume:**
   - In the Railway dashboard, create a volume and mount it to `/data` inside the container.
   - Railway persists the volume across restarts and redeploys.
   - **Note:** The Dockerfile does not contain a `VOLUME` instruction — Railway does not support that directive and rejects builds that include it. The volume is configured entirely in the Railway dashboard.

4. **Domain + HTTPS:**
   - Railway automatically provisions an HTTPS domain (e.g., `PDS-xyz.up.railway.app`).
   - If you own a custom domain, add a CNAME record to Railway's assigned domain.
   - Update `EZPDS_PUBLIC_URL` to your final domain once the Railway domain is known.

### Chicken-and-Egg: EZPDS_PUBLIC_URL

The PDS validates its public URL against the domain it's accessed through. On first deploy to Railway:
1. Set `EZPDS_PUBLIC_URL` to the Railway-assigned domain (e.g., `https://PDS-xyz.railway.app`).
2. Let the first deployment complete and verify health: `curl https://PDS-xyz.railway.app/xrpc/_health`.
3. If migrating a custom domain, update `EZPDS_PUBLIC_URL` and redeploy.

### CI/CD pipeline (GitHub Actions test gate + native Railway deploys)

CI/CD lives on **GitHub**. Deploys use **Railway's native GitHub integration** — each Railway environment is connected to the repo and watches a branch, so Railway pulls, builds the `Dockerfile`, and deploys on its own. There is **no `railway up` and no Railway token in CI**; GitHub Actions only runs the test gate.

- **Test gate — `.github/workflows/ci.yml`.** Runs `just ci-pds` (fmt-check, lock-check, bruno-check, font-check, cap-check, ios-paths-check, swift-rs-check, ios-template-check, clippy, test, cargo-audit, cargo-deny — excluding the iOS app crates) on pull requests to `main`, on push to `main`, and on push to `production`. Both PDS environments (staging and production) use **"Wait for CI"**, so this workflow's green check is the deploy gate. A second `verify-release` job runs only on the `production` branch and fails unless a `vX.Y.Z` tag points at the tip and matches the workspace version (`env!("CARGO_PKG_VERSION")`).

| Environment | Railway watches | Deploys when |
|-------------|-----------------|--------------|
| **staging** (`ezpds-staging.up.railway.app`, serverless sleep) | `main` branch | a PR merges to `main` (after CI passes) |
| **production** (`obsign.org` custom domain, kept warm) | `production` branch | the `production` branch is advanced to a `v*` tag (after CI passes) |

Each environment has its own secrets (distinct master key, admin token, user-domain list) and its own `/data` volume, set in the Railway dashboard. Merging to `main` deploys **staging only** — production never moves on a `main` merge.

**Releasing to production.** Tags are the release anchors (always equal to the reported PDS version), and promoting one is a deliberate, separate step:

1. `just set-version X.Y.Z` in a reviewed PR; merge it → staging deploys.
2. `just release` from `main` cuts and pushes the annotated `vX.Y.Z` tag (does **not** deploy).
3. `just deploy-production vX.Y.Z` advances the `production` branch to that tag and pushes it. Railway sees the new tip, CI re-runs (gate + `verify-release`), and the production service deploys once it is green. Omit the tag to promote the latest; roll back to an older tag with `FORCE=1 just deploy-production vX.Y.Z`.

### Release-time documentation pass

Every release also refreshes the documentation surfaces, and the order matters —
the changelog rolls up first, *then* the *derived* docs and screenshots regenerate
under the parity gates, *then* the *hand-authored* prose gets a review pass, so
every artifact is generated from the post-roll state. Do all three inside the
**same `set-version` PR** (step 1 of the production flow above), in this order:

1. **Roll the changelog.** `just set-version X.Y.Z` folds the per-PR
   `changelog.d/` fragments into a dated `## [X.Y.Z]` section of `CHANGELOG.md`
   and clears the directory (this is step 1 of the production flow above). Do this
   first, before regenerating docs, so the changelog is in its rolled-up state.
2. **Regenerate derived docs + screenshots (gates green).**
   - `just docs-generate` — regenerate the generated reference pages (HTTP/XRPC
     routes, operator config/env, both apps' IPC surface, version stamp).
   - `just docs-screenshots` — regenerate the harness-driven app imagery
     (per-scenario PNGs, happy paths plus error/rare states).
   - Confirm all three parity gates pass and record them: `just docs-check`
     (reference coverage) and `just changelog-check` (fragment discipline), both
     part of `just ci`/`ci-pds` and enforced on the PR; and
     `just docs-screenshots-check` (image visual-diff), which is **not** in
     `just ci` — cross-runner font rendering differs, so run it where the
     baselines were generated. A red `docs-check` means a shipped
     route/config field/command has no doc entry; fix the source or reference,
     never edit generated pages by hand. A red screenshot diff is an intended UI
     change (commit the regenerated PNGs) or an unexpected one (investigate).
3. **Docs/marketing review pass.** Decide which hand-authored guides
   (`sites/docs/`) and marketing pages (`sites/marketing/`) need edits for what
   shipped in the release range, and draft them. This step is automatable as a
   **Claude Code Routine** that regenerates the derived docs + screenshots, reads
   the release diff and the merged Linear issues, drafts changelog/doc/marketing
   prose, and opens a PR that rides `docs-check` + the changelog gate for a human
   to review rather than author from scratch. See
   [operations/release-docs-routine.md](operations/release-docs-routine.md) for
   the Routine's setup and prompt.

### Backup & rollback

When `LITESTREAM_S3_BUCKET` is set on the production environment — together with `LITESTREAM_S3_ENDPOINT` and `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY` — the container runs the PDS under Litestream, which streams the SQLite WAL to object storage continuously and restores on boot, so a current restore point always exists before a promote. The replica is defined in `litestream.yml` with `force-path-style: false` (virtual-hosted-style, as Railway/Tigris-style buckets require). Staging/local leave these unset and run the PDS directly.

Rollback: because migrations are **forward-only** (no down-path), redeploying a previous `v*` tag is safe only when the schema change was backward-compatible (expand-contract). Otherwise, roll back by restoring the database from the Litestream replica (`litestream restore`) to a pre-promote point. To inspect the replica **non-destructively** — restore a throwaway copy (latest state in the service container, point-in-time in the debug-kit sandbox) and query it with `sqlite3`, no rollback — see the [operator debug kit](operations/debug-kit.md#runbook-1--litestream-restore-and-inspect).

### Observability: metrics and logs

The PDS serves a Prometheus text exposition at `GET /metrics` (on by default; the
federation-health instrument set is documented in `crates/pds/AGENTS.md` → "Metrics"). The
route is deliberately outside the permissive CORS layer and rate-limit accounting — it is a
scrape/diagnostic surface, not a browser API.

**Intended posture on Railway: read it over the project's private network, not the public
domain.** Railway sandboxes join the private network with `railway sandbox create
--private-network`, and `railway ssh` reaches the service container — so an operator (or an
agent harness running in a sandbox) can `curl http://<service>.railway.internal:<port>/metrics`
for a point-in-time federation-health snapshot with zero public exposure. Because the
public Railway domain fronts the same process, `/metrics` **is** also reachable publicly by
default; operators who care should set `EZPDS_METRICS_REQUIRE_ADMIN=true` (admin-token gate,
scrape-compatible via `Authorization: Bearer`) or `EZPDS_METRICS_ENABLED=false`. The
exposition contains no per-user data either way (labels are route templates and small fixed
enums only).

`EZPDS_LOG_FORMAT=json` switches stdout logging to one JSON object per line, so `railway
logs` output can be filtered by field instead of by regex. Default stays human-readable text.

Persistent scraping/dashboards (a collector service inside the project) are deliberately
out of scope for v0.1. For private-network troubleshooting — inspecting a restored DB copy
over `railway ssh`, and a ready diagnostic sandbox that can run the interop suite against the
private-network service — see the [operator debug kit](operations/debug-kit.md).

## Marketing Site (static)

The static marketing site (`sites/marketing/`, the Obsign + Custos pages) deploys as a
**second Railway service in the same project** as the PDS — grouped together, but built and
routed independently. It is a zero-build HTML/CSS/font bundle served by Caddy; there is no
Rust, no database, and no secrets.

### Config as code

Everything build-related is committed under `sites/marketing/`:

| File | Role |
|------|------|
| `Dockerfile` | `FROM caddy:2-alpine`; copies the site into `/srv` and the `Caddyfile` into place. No build stage. |
| `Caddyfile` | Serves `/srv` on `$PORT`, gzip/zstd, clean URLs (`/custos/` → `custos/index.html`), immutable caching for `/assets/fonts/*` and short revalidation for HTML/CSS, plus `nosniff`/`Referrer-Policy`. |
| `railway.toml` | Dockerfile builder + `healthcheckPath = "/"` (Caddy returns 200 at the root). |

### The critical setting: Root Directory

The repo-root `railway.toml` is **PDS-specific** — it builds the `pds` binary and health-checks
`/xrpc/_health`. The marketing service must **not** inherit it. In the service's settings:

- **Root Directory** = `sites/marketing`. This scopes Railway's build context *and* its config
  lookup to that subtree, so it uses `sites/marketing/{Dockerfile,railway.toml}` and never the
  root `railway.toml`. This is the whole isolation mechanism — get it right and the two services
  never collide.
- **Watch Paths** = `sites/marketing/**`, so PDS-only changes don't rebuild the site. Watch Paths
  are matched against **repo-root-relative** paths, so keep the `sites/marketing/` prefix even
  though Root Directory is already set. (Optionally also add an *ignore* path of `sites/marketing/**`
  to the **PDS** service so a copy tweak doesn't redeploy the PDS.)
- **Wait for CI** — optional. `just ci-pds` doesn't test these files, so waiting adds no real
  safety; harmless if you'd rather keep all services uniformly gated.
- **No volume, no environment variables.** Railway injects `PORT`; Caddy binds it.

### Domain: `about.obsign.org`

`obsign.org` + `*.obsign.org` are already Railway custom domains on the **PDS** service (DNS at
Cloudflare). Because of the wildcard, `about.obsign.org` currently resolves to the PDS. To route
it to the marketing service instead:

1. In the **marketing** service → Settings → Networking, add the custom domain
   `about.obsign.org`. An **exact** hostname on one service takes routing priority over a
   **wildcard** (`*.obsign.org`) on another, so this steals just `about` without touching the
   wildcard or the PDS.
2. DNS: the `*.obsign.org` wildcard record already covers `about` at the DNS layer, so no new
   Cloudflare record is strictly required. Adding an explicit `about` CNAME (matching however the
   wildcard is proxied — keep the same orange/grey-cloud mode as the working wildcard) is clearer
   and avoids surprises if the wildcard is ever narrowed.
3. Verify: `curl -I https://about.obsign.org/` returns Caddy's 200 (not the PDS), and
   `https://about.obsign.org/custos/` loads the Custos page. If it still hits the PDS, the exact
   domain didn't register on the marketing service — re-check step 1.

### Local check

```sh
docker build -t obsign-marketing sites/marketing
docker run --rm -p 8080:8080 obsign-marketing   # then open http://localhost:8080
```

## Documentation site (static)

The documentation site (`sites/docs/`, the Obsign user + Custos operator surfaces
built with Astro Starlight) deploys as **another Railway service in the same
project** as the PDS — grouped together, but built and routed independently,
exactly like the marketing site above. There is no Rust, no database, and no
secrets. Unlike the zero-build marketing site, Starlight compiles to static HTML,
so the build has a Node stage; the runtime image is still just Caddy serving the
generated `dist/`.

### Config as code

Everything build-related is committed under `sites/docs/`:

| File | Role |
|------|------|
| `Dockerfile` | Two stages: `node:22-alpine` runs `pnpm install --frozen-lockfile && pnpm build`; `caddy:2-alpine` copies the generated `dist/` into `/srv`. |
| `Caddyfile` | Serves `/srv` on `$PORT`, gzip/zstd, clean URLs, immutable caching for fingerprinted `/_astro/*` and `/pagefind/*` assets and short revalidation for HTML, plus `nosniff`/`Referrer-Policy`. |
| `railway.toml` | Dockerfile builder + `healthcheckPath = "/"` (Caddy returns 200 at the root). |

### The critical setting: Root Directory

The repo-root `railway.toml` is **PDS-specific** — it builds the `pds` binary and
health-checks `/xrpc/_health`. The docs service must **not** inherit it. In the
service's settings:

- **Root Directory** = `sites/docs`. This scopes Railway's build context *and* its
  config lookup to that subtree, so it uses `sites/docs/{Dockerfile,railway.toml}`
  and never the root `railway.toml`. This is the whole isolation mechanism — the
  same one the marketing service relies on.
- **Watch Paths** = `sites/docs/**`, so PDS-only changes don't rebuild the docs.
  Watch Paths are matched against **repo-root-relative** paths, so keep the
  `sites/docs/` prefix even though Root Directory is already set. (Optionally also
  add an *ignore* path of `sites/docs/**` to the **PDS** service so a docs edit
  doesn't redeploy the PDS.)
- **Wait for CI** — optional. `just ci-pds` doesn't compile these files, so waiting
  adds no real safety; harmless if you'd rather keep all services uniformly gated.
- **No volume, no environment variables.** Railway injects `PORT`; Caddy binds it.

### Domain: `docs.obsign.org`

`obsign.org` + `*.obsign.org` are already Railway custom domains on the **PDS**
service (DNS at Cloudflare), and the wildcard means `docs.obsign.org` currently
resolves to the PDS. To route it to the docs service instead:

1. In the **docs** service → Settings → Networking, add the custom domain
   `docs.obsign.org`. An **exact** hostname on one service takes routing priority
   over a **wildcard** (`*.obsign.org`) on another, so this steals just `docs`
   without touching the wildcard, the PDS, or the marketing site's `about`.
2. DNS: the `*.obsign.org` wildcard already covers `docs` at the DNS layer, so no
   new Cloudflare record is strictly required. Adding an explicit `docs` CNAME
   (matching the wildcard's orange/grey-cloud mode) is clearer and avoids surprises
   if the wildcard is ever narrowed.
3. Verify: `curl -I https://docs.obsign.org/` returns Caddy's 200 (not the PDS),
   and `https://docs.obsign.org/operator/` loads the operator surface. If it still
   hits the PDS, the exact domain didn't register on the docs service — re-check
   step 1.

### Local check

```sh
docker build -t obsign-docs sites/docs
docker run --rm -p 8080:8080 obsign-docs   # then open http://localhost:8080
```

## MCP sidecar (`mcp.obsign.org`)

The credential-forwarding MCP sidecar (`tools/mcp-sidecar/`) deploys as **another Railway
service in the same project** as the PDS — the hosted tier of the Custos MCP. It serves the
`tools/mcp` tool surface over Streamable HTTP, authenticates each caller via OAuth against
Custos, and **forwards** the caller's token per request while holding nothing durable
([ADR-0024](architecture/decisions/0024-hosted-agent-credential-forwarding.md)). It reaches the
PDS over **private networking** (`*.railway.internal`), so forwarded traffic never leaves the
project's private network. There is no database, no volume, and **no secret** — the whole point
of the forwarding posture.

### Config as code

| File | Role |
|------|------|
| `tools/mcp-sidecar/Dockerfile` | Two stages on `node:22-alpine`: install prod deps for `tools/mcp` **and** `tools/mcp-sidecar`, then run `src/server.ts` (Node strips TypeScript natively — no compile step). Runs as the non-root `node` user. |
| `tools/mcp-sidecar/railway.toml` | Dockerfile builder + `healthcheckPath = "/"` (the sidecar answers 200 at `/`, touching no credential). |

### The critical difference from the static sites: build context

The marketing and docs services are **self-contained**, so they set **Root Directory** to their
subtree and Railway auto-resolves a sibling `railway.toml` + `Dockerfile`. The sidecar is
**not** self-contained: it single-sources the tool surface from `tools/mcp` (a relative import —
Node will not type-strip a `.ts` resolved under `node_modules`), so its build context must
include **both** packages. It therefore builds from the **repo root**, which needs a different
wiring than the Root-Directory trick:

- **Railway Config File** = `tools/mcp-sidecar/railway.toml` (service → Settings → Config-as-code).
  This is what stops the service from inheriting the repo-root `railway.toml` (which is
  PDS-specific), replacing the Root-Directory isolation the static sites rely on.
- **Root Directory** = repo root (leave it unset). The `dockerfilePath` in the sidecar's
  `railway.toml` is repo-root-relative (`tools/mcp-sidecar/Dockerfile`) and the Dockerfile
  `COPY`s `tools/mcp` alongside `tools/mcp-sidecar`. The repo-root `.dockerignore` already
  excludes `node_modules`/`target`/`.git`, so the context stays small.
- **Watch Paths** = `tools/mcp-sidecar/**` **and** `tools/mcp/**` — the sidecar must rebuild when
  either the sidecar or the shared tool surface changes. (Optionally add an *ignore* path of
  `tools/**` to the **PDS** service so a sidecar edit doesn't redeploy the PDS.)
- **Wait for CI** — optional, same reasoning as the static sites: `just ci-pds` does not run the
  sidecar's Node suite, so waiting adds no real safety; harmless if you'd rather gate uniformly.
- **Environment:** `MCP_SIDECAR_PDS_ORIGIN` = the PDS's private address
  (`http://<pds-service>.railway.internal:<port>`), `MCP_SIDECAR_PUBLIC_ORIGIN` =
  `https://mcp.obsign.org` (the OAuth resource identifier), and
  `MCP_SIDECAR_AUTH_SERVER_ORIGIN` = `https://obsign.org` (the **public** Custos
  authorization server advertised to clients — never the private forwarding
  address, which is unreachable from outside the Railway network).
  `MCP_SIDECAR_PDS_ORIGIN` is **required** — the sidecar parse-fails loudly rather
  than defaulting to a public URL. **No volume, no secret.** Railway injects `PORT`.

### Domain: `mcp.obsign.org`

Same as the other services: `*.obsign.org` is a Railway custom domain on the **PDS**, so
`mcp.obsign.org` currently resolves there via the wildcard. Add the **exact** domain
`mcp.obsign.org` on the **sidecar** service (Settings → Networking); an exact hostname takes
routing priority over the wildcard, stealing just `mcp` without touching the wildcard, the PDS,
or the other services. The wildcard already covers `mcp` at the DNS layer; an explicit `mcp`
CNAME (matching the wildcard's cloud mode) is clearer if the wildcard is ever narrowed.

### Local check

```sh
docker build -t custos-mcp-sidecar -f tools/mcp-sidecar/Dockerfile .   # repo-root context
docker run --rm -p 8080:8080 -e MCP_SIDECAR_PDS_ORIGIN=http://host.docker.internal:8080 \
  custos-mcp-sidecar
curl -s localhost:8080/.well-known/oauth-protected-resource   # names Custos as the AS
```

## Colmena / NixOS oci-containers Deployment

For self-hosted NixOS with colmena, use `nixosModules.default` from the flake:

```nix
# colmena target config
services.ezpds.enable = true;
services.ezpds.image = "ghcr.io/your-org/PDS@sha256:...";  # Digest-pinned image
services.ezpds.publicUrl = "https://PDS.example.com";
services.ezpds.availableUserDomains = ["example.com" "example.bsky.social"];
# services.ezpds.reservedHandles = ["identitywallet" "about"];  # optional; null keeps server defaults
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

For the **Railway** path no registry is required — Railway pulls the connected GitHub repo and builds the `Dockerfile` itself. A published image is only needed for the **secondary** colmena/NixOS path, via **GHCR** (GitHub Container Registry):

```bash
# Build locally (development):
docker build -t ghcr.io/your-org/PDS:latest .

# Push to GHCR:
docker push ghcr.io/your-org/PDS:latest

# For reproducibility in production, capture the digest from the push output or inspect:
docker buildx imagetools inspect ghcr.io/your-org/PDS:latest | grep Digest
# Then update references to use the returned digest:
ghcr.io/your-org/PDS@sha256:abc123...
```

The primary CI/CD path (GitHub Actions gate → native Railway deploys, above) needs none of this. For the colmena/NixOS path, publish to GHCR and pin the image by digest in the NixOS module.

## Security Posture

The PDS image is hardened with:
- **Non-root container** - Runs as uid 10001 (created in the Dockerfile).
- **NoNewPrivileges** - Set by the ezpds NixOS module on the generated `podman-ezpds.service` unit; prevents privilege escalation.
- **No secrets in image** - All runtime secrets injected via `environmentFile` or env vars, not baked into the image.
- **Read-only root (where possible)** - SQLite writes to `/data` only; rest of the image can be read-only (optional; set `read_only = true` in container config if desired).

## Reproducibility Tradeoff

The PDS switched from Nix-built reproducibility (`flake.nix` → `packages.<system>.PDS`) to a **Dockerfile-based container**. This is an **intentional tradeoff** accepted for a solo/experimental PDS:

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
For a solo/experimental PDS (Wave 1–2), this is the right balance. When Wave 3 (multi-user/production) arrives, consider:
- Running colmena+NixOS everywhere (abandon Dockerfile).
- Using Nix to build the Dockerfile base image, or
- Staying with Dockerfile + Cargo.lock and accepting the modest reproducibility gap (many teams do this).

This decision is orthogonal to the PDS's architecture and data model; it can be revisited without breaking changes.
