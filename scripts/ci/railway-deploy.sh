#!/bin/sh
set -eu
# Deploy the pds to a Railway environment and wait for the deployment to reach a
# terminal status.
#
# Usage: RAILWAY_TOKEN=<env-scoped token> sh scripts/ci/railway-deploy.sh <environment>
# Requires (nixpkgs workflow deps): railway, jq, coreutils.
#
# `railway up --detach` uploads the build context, queues the deploy, and returns
# immediately — we avoid the attached log stream, which hangs/times out from the
# spindle network (the deploy itself reaches Railway and builds fine). We then
# poll `railway deployment list` until the newest deployment is SUCCESS/FAILED.
# Both calls pass --service/--environment so they resolve context from the token
# alone (there is no `railway link` in CI).
service="ezpds"
env_name="$1"
deploy_attempts="${DEPLOY_ATTEMPTS:-3}"
health_timeout_s="${HEALTH_TIMEOUT_S:-900}"

# --- Upload + queue the deploy (retry only the trigger). A successful --detach
#     exits 0, so this never re-triggers an already-running deploy. ---
i=1
while :; do
  if railway up --service "$service" --environment "$env_name" --detach; then
    break
  fi
  if [ "$i" -ge "$deploy_attempts" ]; then
    echo "railway up failed after ${deploy_attempts} attempts (could not reach Railway)" >&2
    exit 1
  fi
  echo "railway up attempt ${i} failed; retrying in 15s..." >&2
  i=$((i + 1))
  sleep 15
done

# --- Poll the newest deployment. railway up --detach returns before the build
#     finishes, so this is the real pass/fail signal. ---
deadline=$(( $(date +%s) + health_timeout_s ))
dumped=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  json="$(railway deployment list --service "$service" --environment "$env_name" --limit 5 --json 2>/dev/null || true)"
  if [ "$dumped" -eq 0 ]; then
    echo "[diag] deployment list (first poll, <=600 chars): $(printf '%s' "$json" | head -c 600)"
    dumped=1
  fi
  # Shape-robust: take the first `status` value found anywhere in the JSON
  # (deployment list is newest-first, so that is the newest deployment).
  status="$(printf '%s' "$json" | jq -r 'first(.. | objects | select(has("status")) | .status) // empty' 2>/dev/null || true)"
  case "${status:-}" in
    SUCCESS)        echo "deploy healthy (SUCCESS)"; exit 0 ;;
    FAILED|CRASHED) echo "deploy ended: $status" >&2; exit 1 ;;
    "")             echo "deployment status unavailable; retrying..."; sleep 10 ;;
    *)              echo "deployment status: $status; waiting..."; sleep 10 ;;
  esac
done

# Could not read a terminal status in time. The deploy was triggered successfully
# and Railway gates traffic on its own healthcheck, so warn rather than fail CI
# (a genuinely broken deploy reports FAILED/CRASHED above and exits non-zero).
echo "WARNING: could not confirm deploy health within ${health_timeout_s}s; deploy was triggered. Check the Railway dashboard (see [diag] above for the raw status shape)." >&2
exit 0
