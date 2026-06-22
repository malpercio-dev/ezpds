#!/bin/sh
set -eu
# Deploy the relay to a Railway environment with retries, then wait for health.
#
# `railway up` uploads the build context and talks to backboard.railway.com; that
# call can time out transiently, so retry a few times before failing the pipeline.
# On a successful upload, railway-wait-healthy.sh polls the deployment to SUCCESS.
#
# Usage: RAILWAY_TOKEN=<env-scoped token> sh scripts/ci/railway-deploy.sh <environment>
# Requires (nixpkgs workflow deps): railway, jq, coreutils.
env_name="$1"
attempts="${DEPLOY_ATTEMPTS:-3}"

i=1
while :; do
  if railway up --service ezpds --environment "$env_name" --ci; then
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
