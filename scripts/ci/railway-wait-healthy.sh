#!/bin/sh
set -eu
# Wait for the newest Railway deployment (in the RAILWAY_TOKEN-scoped environment)
# to reach SUCCESS. Exit non-zero on FAILED/CRASHED or timeout so CI fails loudly.
#
# `railway up --ci` returns when the build completes, not when the deployment is
# healthy, so this poll provides the real pass/fail signal. Transient query
# failures (backboard.railway.com timeouts) are tolerated — keep polling until
# the deadline rather than aborting.
#
# Requires (nixpkgs workflow deps): railway, jq, coreutils. RAILWAY_TOKEN must be set.
timeout_s="${HEALTH_TIMEOUT_S:-300}"
deadline=$(( $(date +%s) + timeout_s ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  status="$(railway deployment list --json 2>/dev/null | jq -r '.[0].status // empty' 2>/dev/null || true)"
  case "${status:-}" in
    SUCCESS)        echo "deploy healthy"; exit 0 ;;
    FAILED|CRASHED) echo "deploy status: $status"; exit 1 ;;
    "")             echo "deployment status unavailable (transient); retrying..."; sleep 10 ;;
    *)              echo "deploy status: $status; waiting..."; sleep 10 ;;
  esac
done
echo "timed out after ${timeout_s}s waiting for a healthy deploy" >&2
exit 1
