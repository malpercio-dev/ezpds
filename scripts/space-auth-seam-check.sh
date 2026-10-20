#!/usr/bin/env bash
# Freeze the space-read auth seam.
#
# Every Atproto Spaces read/sync route authenticates through `auth::space::authenticate_space_read`
# (or its no-repo sibling `authenticate_space_access`), the single path that accepts a covering
# OAuth grant *or* a signature-bound space credential — never a bearer credential — and that checks
# the request's RFC 9421 `atproto-space` signature against the credential's `cnf.kid` and the
# request-derived audience. A route that verified a credential or a signature itself would have to
# re-derive all of that and could silently skip a step. This guard fails on any NEW reference to
# the primitives outside the blessed seams, so the boundary can't regrow. Sibling of
# auth-seam-check.sh (the access-token seam).
#
# Allowed to name verify_space_credential / verify_space_signature / validate_dpop:
#   auth/space.rs                — the credential seam (verify_space_credential, verify_space_signature)
#   auth/http_signature.rs       — verify_space_signature's definition and tests
#   routes/get_space_credential.rs — the mint's delegation-exchange signature (verify_space_signature)
#   auth/dpop.rs, auth/extractors.rs — validate_dpop, now OAuth-only; a space surface must not
#                                  reach for DPoP again
#
# Symbols, not just calls: a `use … as alias` import names the symbol too, so aliasing cannot slip
# past. Doc/line comments are ignored. Scanner failures (anything but "no match") fail the gate.
# Portable bash + git grep only.
set -euo pipefail

cd "$(dirname "$0")/.."

scan() {
  # $1 = symbol; prints `file:line:text` for every non-comment mention outside its definition.
  local sym="$1" out rc
  set +e
  out="$(git grep -nwE "$sym" -- '*.rs' ':(exclude)wt/')"
  rc=$?
  set -e
  if [ "$rc" -gt 1 ]; then
    echo "✗ git grep failed (exit $rc) while scanning for $sym" >&2
    exit 2
  fi
  printf '%s\n' "$out" \
    | grep -vE "^[^:]+:[0-9]+:\s*(//|///|//!)" \
    | grep -vE "fn ${sym}\b" || true
}

fail=0
check() {
  local sym="$1"; shift
  local allowed=("$@") line file ok
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    file="${line%%:*}"
    ok=0
    for a in "${allowed[@]}"; do [ "$file" = "$a" ] && ok=1; done
    if [ "$ok" -ne 1 ]; then
      echo "✗ $sym referenced outside the auth seams: $line" >&2
      fail=1
    fi
  done <<EOF2
$(scan "$sym")
EOF2
}

check verify_space_credential crates/pds/src/auth/space.rs
check verify_space_signature crates/pds/src/auth/space.rs crates/pds/src/auth/http_signature.rs \
  crates/pds/src/routes/get_space_credential.rs
check validate_dpop crates/pds/src/auth/dpop.rs crates/pds/src/auth/extractors.rs

if [ "$fail" -ne 0 ]; then
  echo "  Route it through auth::space::authenticate_space_read so the credential's key binding is enforced." >&2
  exit 1
fi

echo "✓ space credential verification confined to the authenticate_space_read seam"
