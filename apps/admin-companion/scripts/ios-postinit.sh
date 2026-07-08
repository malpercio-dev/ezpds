#!/usr/bin/env bash
# Thin wrapper — the shared implementation lives in scripts/ios/ios-postinit.sh (single
# source of truth for both app lanes, so the logic can never diverge between them
# again). This file only pins admin-companion's app dir and recipe prefix. The Apple
# frameworks this app links come from bundle > iOS > frameworks in tauri.conf.json
# (rendered into OTHER_LDFLAGS by the scripts/ios/project.yml template):
#   SystemConfiguration — `system-configuration` crate (hickory-resolver, reqwest)
# (No AuthenticationServices: this app has no in-app OAuth session plugin.)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/../../../scripts/ios/ios-postinit.sh" "${SCRIPT_DIR}/.." admin
