#!/usr/bin/env bash
# Freeze the access-token binding seam.
#
# Every access-token verification MUST go through `auth::extractors::authenticate_access`, the
# single path that enforces the RFC 9449 §7.1 scheme <-> `cnf.jkt` binding rule (a DPoP-bound
# token presented as plain `Bearer` with no proof is rejected there, and only there). A route or
# guard that calls `auth::jwt::verify_access_token` directly skips that enforcement — exactly the
# MM-386 downgrade on the account-owner surfaces. This guard fails on any NEW direct call outside
# the blessed seam, so the boundary can't silently regrow.
#
# Allowed to call verify_access_token directly:
#   auth/jwt.rs                     — the definition
#   auth/extractors.rs              — authenticate_access, THE binding-enforcing seam
#   routes/oauth_token/jwt_bearer.rs — test-only call (#[cfg(test)])
# Baselined known-live bug (delete this exception when the fix lands):
#   auth/guards.rs                  — MM-386: authenticate_account_owner must route through
#                                     authenticate_access instead of verify_access_token
#
# Portable bash + git grep only.
set -euo pipefail

cd "$(dirname "$0")/.."

# Calls only (trailing `(`); drop the definition and any `use` import lines.
calls="$(git grep -nE 'verify_access_token\(' -- '*.rs' ':(exclude)wt/' | grep -vE 'fn verify_access_token' || true)"

fail=0
baselined=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  case "$file" in
    crates/pds/src/auth/jwt.rs|crates/pds/src/auth/extractors.rs|crates/pds/src/routes/oauth_token/jwt_bearer.rs)
      continue ;;
    crates/pds/src/auth/guards.rs)
      baselined=1
      continue ;;
    *)
      echo "✗ direct verify_access_token call outside the authenticate_access seam: $line" >&2
      fail=1 ;;
  esac
done <<EOF
$calls
EOF

if [ "$fail" -ne 0 ]; then
  echo "  Route it through auth::extractors::authenticate_access so RFC 9449 binding is enforced." >&2
  exit 1
fi

if [ "$baselined" -ne 0 ]; then
  echo "⚠ auth-seam: guards.rs still calls verify_access_token directly (MM-386, known-live; baselined)"
fi
echo "✓ access-token verification confined to the authenticate_access seam"
