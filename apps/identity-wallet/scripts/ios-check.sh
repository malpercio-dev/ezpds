#!/usr/bin/env bash
# Thin wrapper — the shared implementation lives in scripts/ios/ios-check.sh (single
# source of truth for both app lanes). Pins the same arguments as ios-postinit.sh:
# app dir, recipe prefix, and identity-wallet's Patch E framework list.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/../../../scripts/ios/ios-check.sh" \
  "${SCRIPT_DIR}/.." ios SystemConfiguration AuthenticationServices
