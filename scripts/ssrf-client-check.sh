#!/usr/bin/env bash
# Guard the caller-influenced identity fetch against SSRF.
#
# resolveHandle's third fallback fetches `https://<caller-supplied-handle>/.well-known/atproto-did`,
# so the handle is attacker-controlled. That fetch MUST use the SSRF-hardened HTTP client
# (`AppState::hardened_http_client`), whose `SsrfResolver` blocks private/loopback/metadata
# resolutions and disables redirects. Wiring the plain `http_client` there is the MM-387 reflected
# SSRF. This guard freezes the resolver's client so a mis-wiring can't land unnoticed.
#
# MM-387 is currently live: the resolver is still on the plain `http_client` (baselined below). The
# guard stays green while that exact known state holds, FAILS on any other/novel client wiring, and
# turns fully clean the moment the fix rewires it to `hardened_http_client` (delete the baseline
# branch then).
#
# Portable bash + awk only.
set -euo pipefail

cd "$(dirname "$0")/.."

main="crates/pds/src/main.rs"
# The argument passed to HttpWellKnownResolver::new(...) — on the line after the constructor.
arg="$(awk '
  /HttpWellKnownResolver::new\(/ { grab = 1; next }
  grab { gsub(/[[:space:]]/, ""); print; exit }
' "$main")"

case "$arg" in
  hardened_http_client.clone*|hardened_http_client\)*|hardened_http_client)
    echo "✓ well-known handle resolver uses the SSRF-hardened HTTP client"
    exit 0 ;;
  http_client.clone*|http_client\)*|http_client)
    echo "⚠ ssrf-client: well-known resolver still on the plain http_client (MM-387, known-live; baselined)"
    exit 0 ;;
  "")
    echo "✗ could not find HttpWellKnownResolver::new(...) in $main — did the wiring move?" >&2
    exit 1 ;;
  *)
    echo "✗ HttpWellKnownResolver wired to an unrecognized client: '$arg' (expected hardened_http_client)" >&2
    exit 1 ;;
esac
