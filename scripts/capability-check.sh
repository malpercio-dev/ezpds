#!/usr/bin/env bash
# Verify the Tauri IPC capability allowlists stay MINIMAL — the automated backstop
# for the least-privilege boundary documented in docs/security/tauri-ipc-boundary.md.
#
# Tauri v2 gates every webview->Rust IPC call for *core* and *plugin* commands through
# the capability files in each app's src-tauri/capabilities/. App-defined
# #[tauri::command]s are allowed by default and need no entry. The blanket
# `core:default` permission set bundles nine core modules (app, event, image, menu,
# path, resources, tray, webview, and window's 40+ commands) — almost all dead
# surface for these two frontends, whose only core use is the wallet's event
# listener. This guard freezes each capability file at its audited-minimal permission
# set so a later edit can't silently re-widen the IPC boundary (e.g. by pasting
# `core:default` back in).
#
# It also asserts:
#   * no capability references the desktop schema (both apps are iOS-only -> mobile),
#   * withGlobalTauri is not enabled (the frontends use @tauri-apps/api imports, so
#     window.__TAURI__ stays out of the webview entirely).
#
# Tauri v2 has no runtime ACL-denial test harness (denial is a console-only string),
# so this static minimality lock — plus the manual denial procedure in the doc — is
# the enforceable half of the boundary.
#
# Portable bash + coreutils only (no jq/perl/python) — runs identically in the Linux
# CI gate (`just ci-pds`), the macOS `just ci`, and the Nix dev shell.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# Extract the contents of the first "permissions": [ ... ] array in a capability file
# as one sorted permission per line. Collapses newlines first so a multi-line array
# parses identically to a single-line one; [^]] stops at the array's closing bracket.
# Assumes a flat array of bare strings — enforced by assert_flat_permissions below.
extract_permissions() {
  tr -d '\n' < "$1" \
    | sed -n 's/.*"permissions"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' \
    | grep -o '"[^"]*"' \
    | tr -d '"' \
    | sort
}

# assert_flat_permissions FILE — the sed/grep parser above only handles a flat array of
# string permissions. Tauri v2 also allows scoped-object permissions
# ({ "identifier": …, "allow": [...] }); those would truncate/mis-parse the extraction
# and could hide a banned grant (a false pass). A capability file's only `{` is the root
# object opener *before* the "permissions" key, so any `{` in the substring that follows
# that key marks a non-flat entry. Fail loudly (fail-closed) rather than parse it wrongly.
assert_flat_permissions() {
  local file="$1" tail
  tail="$(tr -d '\n' < "$file" | sed -n 's/.*"permissions"[[:space:]]*:[[:space:]]*//p')"
  if printf '%s' "$tail" | grep -q '{'; then
    echo "✗ $file uses a non-flat (scoped-object) permission — this guard only parses" >&2
    echo "  flat string permissions. Upgrade extract_permissions in" >&2
    echo "  scripts/capability-check.sh (e.g. a JSON-aware parser) before adding one." >&2
    fail=1
    return 1
  fi
}

# check_caps FILE EXPECTED... — FILE's permissions must equal EXACTLY the expected set.
check_caps() {
  local file="$1"; shift
  if [ ! -f "$file" ]; then
    echo "✗ capability file missing: $file" >&2
    echo "  (moved or renamed? update the file list in scripts/capability-check.sh)" >&2
    fail=1
    return
  fi
  # Refuse to trust the flat-string parser on a shape it can't handle.
  assert_flat_permissions "$file" || return
  local expected actual
  expected="$(printf '%s\n' "$@" | sort)"
  actual="$(extract_permissions "$file")"
  if printf '%s\n' "$actual" | grep -qx 'core:default'; then
    echo "✗ $file grants 'core:default' — the blanket core permission set is banned." >&2
    echo "  Enumerate only the core modules the frontend actually uses" >&2
    echo "  (see docs/security/tauri-ipc-boundary.md)." >&2
    fail=1
  fi
  if [ "$actual" != "$expected" ]; then
    echo "✗ $file permissions drifted from the audited-minimal set:" >&2
    echo "    expected: $(printf '%s' "$expected" | tr '\n' ' ')" >&2
    echo "    actual:   $(printf '%s' "$actual" | tr '\n' ' ')" >&2
    echo "  Widening the IPC surface needs a docs/security/tauri-ipc-boundary.md update" >&2
    echo "  and a matching change to the expected set in scripts/capability-check.sh." >&2
    fail=1
  fi
}

# check_schema FILE — capability files must reference the mobile schema, and must NOT
# reference the desktop one (both apps ship iOS-only; a desktop-schema reference is a
# platform mismatch, and a missing/renamed schema ref is caught by the positive check).
# shellcheck disable=SC2016  # the greps intentionally contain a literal `$schema` (an ERE anchor, not a shell var)
check_schema() {
  local file="$1"
  [ -f "$file" ] || return
  # Anchor both checks to the "$schema" field so a stray mention of a schema name
  # elsewhere (e.g. inside a description) can't satisfy the positive check or trip
  # the negative one. ERE only — `grep -P` (PCRE) is not portable to the BSD grep
  # on the macOS `just ci` lane.
  if grep -Eq '"\$schema"[[:space:]]*:[[:space:]]*"[^"]*desktop-schema\.json"' "$file"; then
    echo "✗ $file's \$schema references the desktop capability schema — both apps are iOS-only." >&2
    echo "  Use ../gen/schemas/mobile-schema.json." >&2
    fail=1
  fi
  if ! grep -Eq '"\$schema"[[:space:]]*:[[:space:]]*"\.\./gen/schemas/mobile-schema\.json"' "$file"; then
    echo "✗ $file's \$schema does not reference the mobile capability schema" >&2
    echo "  (expected exactly ../gen/schemas/mobile-schema.json)." >&2
    fail=1
  fi
}

# check_global_tauri FILE — withGlobalTauri must not be enabled, so the global
# window.__TAURI__ object is never injected into the webview.
check_global_tauri() {
  local file="$1"
  [ -f "$file" ] || return
  if grep -Eq '"withGlobalTauri"[[:space:]]*:[[:space:]]*true' "$file"; then
    echo "✗ $file enables withGlobalTauri — keep window.__TAURI__ out of the webview" >&2
    echo "  (the frontends call commands via @tauri-apps/api imports)." >&2
    fail=1
  fi
}

WALLET_CAPS="apps/identity-wallet/src-tauri/capabilities"
ADMIN_CAPS="apps/admin-companion/src-tauri/capabilities"

# Audited-minimal allowlists (see docs/security/tauri-ipc-boundary.md for the rationale
# tracing each permission to real frontend usage):
#   wallet default  — core:event:default (listen for plc_alert / auth_ready) + the
#                     in-app OAuth plugin. App commands need no entry.
#   wallet mobile   — the three iOS/android plugins (biometric gate, share sheet, and the
#                     barcode scanner for the OAuth consent scan path); platform-gated in-file.
#   admin default   — log:default only. The frontend uses no core API.
#   admin mobile    — the three iOS/android plugins (already platform-gated in-file).
check_caps "$WALLET_CAPS/default.json" core:event:default auth-session:default
check_caps "$WALLET_CAPS/mobile.json" barcode-scanner:default biometric:default sharesheet:default
check_caps "$ADMIN_CAPS/default.json" log:default
check_caps "$ADMIN_CAPS/mobile.json" barcode-scanner:default biometric:default sharesheet:default

for f in "$WALLET_CAPS"/*.json "$ADMIN_CAPS"/*.json; do
  check_schema "$f"
done

check_global_tauri "apps/identity-wallet/src-tauri/tauri.conf.json"
check_global_tauri "apps/admin-companion/src-tauri/tauri.conf.json"

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "✓ capability lockdown: IPC allowlists minimal (no core:default), mobile schema, withGlobalTauri off"
