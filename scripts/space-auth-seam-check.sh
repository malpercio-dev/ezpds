#!/usr/bin/env bash
# Freeze the space-read auth seam.
#
# Every Atproto Spaces read/sync route authenticates through `auth::space::authenticate_space_read`,
# the single path that accepts a covering OAuth grant *or* a DPoP-bound space credential — never a
# bearer credential — and that runs the full RFC 9449 per-request proof validation (thumbprint vs
# `cnf.jkt`, `ath` = hash of the credential, `htm`/`htu`, `iat` recency, per-host `jti` replay).
# A route that verified a credential itself, or called the proof validator directly, would have to
# re-derive all of that and could silently skip a step. This guard fails on any NEW direct call to
# the two primitives outside the blessed seams, so the boundary can't regrow. Sibling of
# auth-seam-check.sh (the access-token seam).
#
# Allowed to call verify_space_credential / validate_dpop directly:
#   auth/space.rs       — the definitions + authenticate_space_read, THE space seam
#   auth/dpop.rs        — validate_dpop's definition
#   auth/extractors.rs  — authenticate_access, the OAuth access-token seam (validate_dpop only)
#
# Portable bash + git grep only.
set -euo pipefail

cd "$(dirname "$0")/.."

calls="$(git grep -nE '(verify_space_credential|validate_dpop)\(' -- '*.rs' ':(exclude)wt/' \
  | grep -vE 'fn (verify_space_credential|validate_dpop)\(' || true)"

fail=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  case "$file" in
    crates/pds/src/auth/space.rs|crates/pds/src/auth/dpop.rs|crates/pds/src/auth/extractors.rs)
      continue ;;
    *)
      echo "✗ space credential / DPoP proof primitive called outside the auth seams: $line" >&2
      fail=1 ;;
  esac
done <<EOF2
$calls
EOF2

if [ "$fail" -ne 0 ]; then
  echo "  Route it through auth::space::authenticate_space_read so the credential's DPoP binding is enforced." >&2
  exit 1
fi

echo "✓ space credential verification confined to the authenticate_space_read seam"
