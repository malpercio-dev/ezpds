#!/bin/sh
set -eu
# Deploy the relay to a Railway environment with retries, then wait for health.
#
# `railway up --detach` uploads the build context, queues the deploy, and returns
# immediately. We use --detach (not --ci) because following the deployment log
# stream hangs/times out from the spindle network (the deploy itself reaches
# Railway and builds fine); railway-wait-healthy.sh then polls the deployment to
# SUCCESS via short queries. The retry guards a failed upload/trigger.
#
# Usage: RAILWAY_TOKEN=<env-scoped token> sh scripts/ci/railway-deploy.sh <environment>
# Requires (nixpkgs workflow deps): railway, jq, coreutils.
env_name="$1"
attempts="${DEPLOY_ATTEMPTS:-3}"

i=1
while :; do
  if railway up --service ezpds --environment "$env_name" --detach; then
    break
  fi
  if [ "$i" -ge "$attempts" ]; then
    echo "railway up failed after ${attempts} attempts (could not reach Railway)" >&2
    exit 1
  fi
  echo "railway up attempt ${i} failed; retrying in 15s..." >&2
  i=$((i + 1))
  sleep 15
done

exec sh scripts/ci/railway-wait-healthy.sh
