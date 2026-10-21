#!/usr/bin/env bash
# Verify route ⇄ Bruno-collection parity, both directions:
#   1. Every route registered in a router file (ROUTER_FILES: `pds`'s app.rs plus each feature
#      crate's router.rs) has at least one request in
#      bruno/*.bru whose URL path matches it (the "Mandatory" rule in AGENTS.md).
#   2. Every bruno/*.bru URL path matches some registered route, so a removed or
#      renamed route can't leave a stale request behind.
#
# Matching is by path only (methods/bodies are not checked): a route path parameter
# (`:id`, `*path`) and a Bruno template segment (`{{did}}`) each match any single
# segment, so `/v1/accounts/:id/usage` is covered by `/v1/accounts/{{did}}/usage`.
#
# `--list` prints the extracted route set and exits, for diffing the route table across a
# refactor that moves routes between files.
#
# Portable bash + coreutils only (no perl/python) — runs identically in the Linux CI
# gate (`just ci-pds`), the macOS `just ci`, and the Nix dev shell.
set -euo pipefail

cd "$(dirname "$0")/.."

# Every file that registers routes. A missing file fails the gate rather than silently shrinking
# the route set.
ROUTER_FILES=(
  "crates/pds/src/app.rs"
  "crates/custos-agents/src/router.rs"
  "crates/custos-blobs/src/router.rs"
  "crates/custos-oauth/src/router.rs"
  "crates/custos-spaces/src/router.rs"
)
BRUNO_DIR="bruno"

# Routes that intentionally have no Bruno request. Keep this list short and justified.
#   /static/{*path} — embedded static assets (fonts) for the landing page, not an API
#                     endpoint a client would exercise from the collection.
EXCLUDED_ROUTES=(
  "/static/{*path}"
)

# --- extract route paths from the router files ---------------------------------------
# .route( calls span lines, so collapse each file to one line, split on `.route(`, and
# take the first string literal of each call.
extract_routes() {
  tr '\n' ' ' < "$1" \
    | sed 's/\.route(/\n.route(/g' \
    | sed -n 's/^\.route( *"\([^"]*\)".*/\1/p'
}

routes=""
for file in "${ROUTER_FILES[@]}"; do
  if [ ! -f "$file" ]; then
    echo "✗ router file $file is missing — update ROUTER_FILES in $0" >&2
    exit 1
  fi
  file_routes="$(extract_routes "$file")"
  if [ -z "$file_routes" ]; then
    echo "✗ no routes extracted from $file — has the router registration moved?" >&2
    exit 1
  fi
  routes="$(printf '%s\n%s\n' "$routes" "$file_routes")"
done
routes="$(printf '%s\n' "$routes" | sed '/^$/d' | sort -u)"

if [ "${1:-}" = "--list" ]; then
  printf '%s\n' "$routes"
  exit 0
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
    echo "✗ route '$route' has no matching request in $BRUNO_DIR/ — add a .bru file (AGENTS.md: Bruno API Collection)" >&2
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
    echo "✗ Bruno request path '$bru' matches no registered route in ${ROUTER_FILES[*]} — remove or update the stale .bru file" >&2
    fail=1
  fi
done <<< "$bru_paths"

if [ "$fail" -ne 0 ]; then
  exit 1
fi

route_count="$(printf '%s\n' "$routes" | wc -l | tr -d ' ')"
echo "✓ bruno parity: all $route_count registered routes covered; no stale .bru requests"
