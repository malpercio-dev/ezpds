#!/usr/bin/env bash
# Hermetic local PDS for the browser test harness's proxy mode (browser-harness.AC3.4).
#
# Thin wrapper over scripts/harness-pds.mjs (the spawn logic lives in Node, where the
# mock plc.directory HTTP server and process management are natural). Requires a built
# pds binary (`cargo build -p pds`) or EZPDS_HARNESS_PDS_BIN; node comes from the dev shell.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "harness-pds: node not found — enter the dev shell (nix develop) first." >&2
  exit 1
fi

exec node "${here}/harness-pds.mjs" "$@"
