#!/usr/bin/env bash
#
# Harness-driven documentation screenshots (docs.AC4 in
# docs/design-plans/2026-07-14-documentation-sites.md).
#
# Boots each mobile app's browser test harness in fake mode (VITE_HARNESS=fake) and drives it
# with Playwright to capture deterministic per-scenario PNGs — happy paths plus error/rare
# states — into sites/docs/public/screenshots/. Because the harness runs the app frontends
# without the native Tauri shell, this runs on a plain Linux runner (no macOS/Xcode).
#
#   scripts/docs-screenshots.sh            # regenerate every screenshot
#   scripts/docs-screenshots.sh --check    # re-render and diff against the committed PNGs
#   scripts/docs-screenshots.sh --app admin --only status   # forwarded to capture.mjs
#
# Any already-running dev server on the expected port is reused; otherwise one is started here
# and torn down on exit.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

WALLET_DIR="apps/identity-wallet"
ADMIN_DIR="apps/admin-companion"
WALLET_PORT=5173
ADMIN_PORT=5174
TOOL_DIR="tools/screenshots"

log() { printf '  [docs-screenshots] %s\n' "$*"; }

# ── Dependencies ────────────────────────────────────────────────────────────
# Each app needs its frontend deps for `vite dev`; the tool needs Playwright. Install only
# when missing so repeat runs are fast.
ensure_deps() {
  local dir="$1"
  if [[ ! -d "$dir/node_modules" ]]; then
    log "installing deps in $dir"
    (cd "$dir" && pnpm install --frozen-lockfile)
  fi
}
ensure_deps "$WALLET_DIR"
ensure_deps "$ADMIN_DIR"
ensure_deps "$TOOL_DIR"

# A pre-installed Chromium (this managed environment ships one at /opt/pw-browsers) is used as
# is; otherwise fetch Playwright's own. capture.mjs points launch at the pre-installed binary
# when present, so we never download over it.
if [[ ! -e /opt/pw-browsers/chromium ]]; then
  log "installing Playwright Chromium"
  (cd "$TOOL_DIR" && pnpm exec playwright install chromium)
fi

# ── Dev servers ─────────────────────────────────────────────────────────────
# PIDs of servers WE started (never a reused one). Cleanup walks each PID's descendant tree,
# because `pnpm run dev:harness` spawns node/vite children that outlive a bare `kill` of pnpm.
SERVER_PIDS=()
kill_tree() {
  local pid="$1" child
  for child in $(pgrep -P "$pid" 2>/dev/null); do
    kill_tree "$child"
  done
  kill "$pid" 2>/dev/null || true
}
cleanup() {
  for pid in "${SERVER_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill_tree "$pid"
  done
}
trap cleanup EXIT

port_up() { curl -fsS -o /dev/null "http://localhost:$1/" 2>/dev/null; }

start_server() {
  local dir="$1" port="$2" name="$3"
  if port_up "$port"; then
    log "reusing running $name harness on :$port"
    return
  fi
  log "starting $name harness on :$port"
  local logfile="$TOOL_DIR/${name}-dev.log"
  # `exec` so $! is the pnpm PID (not an intermediate shell), making its child node/vite
  # processes reachable via pgrep -P during cleanup.
  bash -c "cd '$dir' && exec pnpm run dev:harness" >"$ROOT/$logfile" 2>&1 &
  SERVER_PIDS+=("$!")
}

wait_for_port() {
  local port="$1" name="$2" tries=0
  until port_up "$port"; do
    tries=$((tries + 1))
    if [[ $tries -gt 60 ]]; then
      log "ERROR: $name harness never came up on :$port"
      cat "$ROOT/$TOOL_DIR/${name}-dev.log" 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
  log "$name harness ready on :$port"
}

start_server "$WALLET_DIR" "$WALLET_PORT" wallet
start_server "$ADMIN_DIR" "$ADMIN_PORT" admin
wait_for_port "$WALLET_PORT" wallet
wait_for_port "$ADMIN_PORT" admin

# ── Capture ─────────────────────────────────────────────────────────────────
log "capturing screenshots"
(cd "$TOOL_DIR" && node capture.mjs "$@")
