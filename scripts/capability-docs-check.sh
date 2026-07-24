#!/usr/bin/env bash
# Fail if the operator capability documentation has drifted from the capability table in
# crates/pds/src/capabilities.rs (names, and the configuration that controls each one).
# See scripts/capability-docs-check.mjs for what exactly is compared.
set -euo pipefail

cd "$(dirname "$0")/.."
node scripts/capability-docs-check.mjs
