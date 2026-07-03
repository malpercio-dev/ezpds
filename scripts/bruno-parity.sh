#!/usr/bin/env bash
# Verify route ⇄ Bruno-collection parity, both directions:
#   1. Every route registered in crates/pds/src/app.rs has at least one request in
#      bruno/*.bru whose URL path matches it (the "Mandatory" rule in AGENTS.md).
#   2. Every bruno/*.bru URL path matches some registered route, so a removed or
#      renamed route can't leave a stale request behind.
#
# Matching is by path only (methods/bodies are not checked): a route path parameter
# (`:id`, `*path`) and a Bruno template segment (`{{did}}`) each match any single
# segment, so `/v1/accounts/:id/usage` is covered by `/v1/accounts/{{did}}/usage`.
#
# Portable bash + coreutils only (no perl/python) — runs identically in the Linux CI
# gate (`just ci-pds`), the macOS `just ci`, and the Nix dev shell.
set -euo pipefail

cd "$(dirname "$0")/.."

APP_RS="crates/pds/src/app.rs"
BRUNO_DIR="bruno"

# Routes that intentionally have no Bruno request. Keep this list short and justified.
#   /static/{*path} — embedded static assets (fonts) for the landing page, not an API
#                     endpoint a client would exercise from the collection.
EXCLUDED_ROUTES=(
  "/static/{*path}"
)

# --- extract route paths from app.rs -------------------------------------------------
# .route( calls span lines, so collapse the file to one line, split on `.route(`, and
# take the first string literal of each call.
routes="$(tr '\n' ' ' < "$APP_RS" \
  | sed 's/\.route(/\n.route(/g' \
  | sed -n 's/^\.route( *"\([^"]*\)".*/\1/p' \
  | sort -u)"

if [ -z "$routes" ]; then
  echo "✗ no routes extracted from $APP_RS — has the router registration moved?" >&2
  exit 1
fi

# --- extract request paths from the Bruno collection ---------------------------------
# url lines look like `url: {{baseUrl}}/xrpc/…?query=…`; strip the host template and
# any query string.
bru_paths="$(grep -h '^[[:space:]]*url:' "$BRUNO_DIR"/*.bru \
  | sed -e 's/^[[:space:]]*url:[[:space:]]*//' -e 's/{{baseUrl}}//' -e 's/[?].*//' \
  | sort -u)"

if [ -z "$bru_paths" ]; then
  echo "✗ no url lines found in $BRUNO_DIR/*.bru" >&2
  exit 1
fi

# --- segment-wise path matching -------------------------------------------------------
# Wildcards: route `{seg}` matches any one Bruno segment; route `{*seg}` (axum splat)
# matches one-or-more trailing segments; Bruno `{{var}}` or `:var` matches any one
# route segment.
matches() {
  local route="$1" bru="$2"
  local -a rs bs
  IFS='/' read -ra rs <<< "$route"
  IFS='/' read -ra bs <<< "$bru"
  local i n=${#rs[@]} m=${#bs[@]}
  for ((i = 0; i < n; i++)); do
    local r="${rs[i]}"
    if [[ "$r" == "{*"* ]]; then
      # splat: consumes the rest, needs at least one segment left
      (( m > i )) && return 0 || return 1
    fi
    (( i < m )) || return 1
    local b="${bs[i]}"
    [[ "$r" == "{"*"}" ]] && continue
    [[ "$b" == \{\{*\}\} || "$b" == :* ]] && continue
    [ "$r" = "$b" ] || return 1
  done
  [ "$n" -eq "$m" ]
}

excluded() {
  local route="$1" ex
  for ex in "${EXCLUDED_ROUTES[@]}"; do
    [ "$route" = "$ex" ] && return 0
  done
  return 1
}

fail=0

# Direction 1: every route is covered by some .bru request.
while IFS= read -r route; do
  excluded "$route" && continue
  covered=0
  while IFS= read -r bru; do
    if matches "$route" "$bru"; then covered=1; break; fi
  done <<< "$bru_paths"
  if [ "$covered" -eq 0 ]; then
    echo "✗ route '$route' ($APP_RS) has no matching request in $BRUNO_DIR/ — add a .bru file (AGENTS.md: Bruno API Collection)" >&2
    fail=1
  fi
done <<< "$routes"

# Direction 2: every .bru request targets a registered route.
while IFS= read -r bru; do
  known=0
  while IFS= read -r route; do
    if matches "$route" "$bru"; then known=1; break; fi
  done <<< "$routes"
  if [ "$known" -eq 0 ]; then
    echo "✗ Bruno request path '$bru' matches no registered route in $APP_RS — remove or update the stale .bru file" >&2
    fail=1
  fi
done <<< "$bru_paths"

if [ "$fail" -ne 0 ]; then
  exit 1
fi

route_count="$(printf '%s\n' "$routes" | wc -l | tr -d ' ')"
echo "✓ bruno parity: all $route_count registered routes covered; no stale .bru requests"
