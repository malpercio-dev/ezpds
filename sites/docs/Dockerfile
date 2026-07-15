# syntax=docker/dockerfile:1

# Static documentation site (Obsign user + Custos operator surfaces), built with
# Astro Starlight and served by Caddy.
#
# This is its OWN Railway service, scoped to this directory via the service's
# Root Directory = sites/docs setting — so it uses THIS Dockerfile and the
# sibling railway.toml, never the repo-root railway.toml (which is PDS-specific:
# it builds the pds binary and health-checks /xrpc/_health, neither of which
# applies here). It mirrors the marketing-site service. See docs/deploy.md →
# "Documentation site".
#
# Unlike the zero-build marketing site, Starlight compiles to static HTML, so
# there is a Node build stage; the runtime image is still just Caddy serving the
# generated `dist/`.

# ── Build stage ──────────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app

# corepack pins the exact pnpm version from package.json's packageManager field
# (falls back to the repo's pnpm otherwise); --frozen-lockfile makes the build
# fail on any drift from the committed pnpm-lock.yaml rather than resolving anew.
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Source (config, content, styles, fonts) then the static build.
COPY . .
RUN pnpm build

# ── Runtime stage ────────────────────────────────────────────────────────
FROM caddy:2-alpine
COPY Caddyfile /etc/caddy/Caddyfile
# Only the generated site goes into the web root — not the Dockerfile, the
# Caddyfile, railway.toml, or any source.
COPY --from=build /app/dist /srv

# Run as a non-root user, matching the repo's container security posture (the PDS
# image runs as uid 10001; see docs/deploy.md → Security Posture). Caddy needs
# write access to its XDG state dirs (/config, /data — declared by the base image)
# even when only serving static files, so hand them to the runtime user. $PORT is
# always > 1024 (8080 locally, Railway-injected in prod), so no privileged bind.
RUN addgroup -S web && adduser -S -G web web \
 && mkdir -p /config /data \
 && chown -R web:web /srv /config /data
USER web

# Documentation only; the actual listen port comes from $PORT at runtime.
EXPOSE 8080
