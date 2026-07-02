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

# Documentation only; the actual listen port comes from $PORT at runtime.
EXPOSE 8080
