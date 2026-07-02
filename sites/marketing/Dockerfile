# syntax=docker/dockerfile:1

# Static marketing site (Obsign + Custos), served by Caddy.
#
# This is its OWN Railway service, scoped to this directory via the service's
# Root Directory = sites/marketing setting — so it uses THIS Dockerfile and the
# sibling railway.toml, never the repo-root railway.toml (which is PDS-specific:
# it builds the pds binary and health-checks /xrpc/_health, neither of which
# applies here). See docs/deploy.md → "Marketing site".
#
# The site is zero-build HTML/CSS/fonts, so there is no build stage — Caddy just
# serves the files. Caddy binds $PORT (injected by Railway), compresses, and
# sets cache + security headers; see Caddyfile.
FROM caddy:2-alpine

COPY Caddyfile /etc/caddy/Caddyfile
# Only the actual site files go into the web root — not this Dockerfile, the
# Caddyfile, or railway.toml.
COPY index.html /srv/index.html
COPY custos /srv/custos
COPY assets /srv/assets

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
