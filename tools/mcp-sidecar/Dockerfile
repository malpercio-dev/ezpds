# syntax=docker/dockerfile:1

# Credential-forwarding MCP sidecar (mcp.obsign.org), a Node service.
#
# This is its OWN Railway service in the same project as the PDS, reaching the
# PDS over private networking (*.railway.internal). Unlike the marketing/docs
# sites it is NOT self-contained: it single-sources the tool surface from the
# sibling `tools/mcp` package (a relative import — Node will not type-strip a
# `.ts` resolved under node_modules, and neither package has a build step), so
# the build context must include BOTH packages. It therefore builds from the
# REPO ROOT context — not a Root-Directory-scoped subtree like the static sites.
#
# Railway wiring (see docs/deploy.md → "MCP sidecar"): set the service's
# "Railway Config File" to tools/mcp-sidecar/railway.toml so it does NOT inherit
# the repo-root railway.toml (which is PDS-specific), and leave Root Directory at
# the repo root so this Dockerfile can COPY tools/mcp alongside tools/mcp-sidecar.
# The repo-root .dockerignore already excludes node_modules/target/.git, so the
# context stays small and host node_modules never leak in.

# ── Dependency stage: prod deps for both packages ────────────────────────
FROM node:22-alpine AS deps
ENV NODE_ENV=production
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /app

# Manifests + lockfiles only, so the dependency layer caches independently of
# source edits. --prod skips devDependencies (tsc, the file: interop harness dep);
# the sidecar runs TypeScript natively, so nothing is compiled here.
COPY tools/mcp/package.json tools/mcp/pnpm-lock.yaml ./tools/mcp/
COPY tools/mcp-sidecar/package.json tools/mcp-sidecar/pnpm-lock.yaml ./tools/mcp-sidecar/
WORKDIR /app/tools/mcp
RUN pnpm install --prod --frozen-lockfile
WORKDIR /app/tools/mcp-sidecar
RUN pnpm install --prod --frozen-lockfile

# ── Runtime stage ────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Source first, then the installed node_modules over the top (the .dockerignore
# keeps host node_modules out of the context, but this ordering is unambiguous).
COPY tools/mcp ./tools/mcp
COPY tools/mcp-sidecar ./tools/mcp-sidecar
COPY --from=deps /app/tools/mcp/node_modules ./tools/mcp/node_modules
COPY --from=deps /app/tools/mcp-sidecar/node_modules ./tools/mcp-sidecar/node_modules

# Run as the built-in non-root `node` user, matching the repo's container
# security posture (the PDS image runs as a non-root uid; see docs/deploy.md →
# Security Posture). $PORT is Railway-injected (> 1024), so no privileged bind.
USER node
WORKDIR /app/tools/mcp-sidecar

# Documentation only; the actual listen port comes from $PORT at runtime.
EXPOSE 8080

# Liveness probe on the credential-free health route (Railway also health-checks
# via railway.toml; this makes a plain `docker run` self-report too). Node 22 has
# a global fetch, so no extra tooling is needed in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# The sidecar holds no durable secret (ADR-0024): no volume, no state dir.
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.ts"]
