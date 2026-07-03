#!/usr/bin/env bash
# Thin wrapper — the shared implementation lives in scripts/ios/ios-postinit.sh (single
# source of truth for both app lanes, so the patch logic can never diverge between them
# again). This file only pins admin-companion's app dir, recipe prefix, and Patch E
# framework list:
#   SystemConfiguration — `system-configuration` crate (hickory-resolver, reqwest)
# (No AuthenticationServices: this app has no in-app OAuth session plugin.)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/../../../scripts/ios/ios-postinit.sh" \
  "${SCRIPT_DIR}/.." admin SystemConfiguration
