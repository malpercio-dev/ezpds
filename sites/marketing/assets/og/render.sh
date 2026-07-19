#!/usr/bin/env bash
# Regenerate the social-card PNGs (obsign.png, custos.png) from the *.src.html
# sources in this directory. Zero-build, self-contained: headless Chrome + a
# tiny pure-Node PNG cropper (pngcrop.mjs).
#
# Why the 717 -> 630 crop: headless Chrome (--headless=new) reserves ~87px of
# invisible window chrome, so --window-size=1200,630 yields only a 1200x543
# content viewport and clips the card's lower third. Rendering at 1200x717
# gives a true 1200x630 viewport (the card fills the top 630px, 87px of ground
# below), then pngcrop trims to the top 630 rows. Blocks in the sources are
# placed with absolute `top` so the layout is deterministic under headless.
#
# Chrome's --screenshot writes the PNG but then lingers instead of exiting, so
# we poll for the file and kill it rather than `wait`-ing forever.
#
# Usage:  ./render.sh          (needs Google Chrome + node on PATH)
set -euo pipefail
cd "$(dirname "$0")"

CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
W=1200; RENDER_H=717; CROP_H=630

for name in obsign custos; do
  prof="$(mktemp -d)"
  raw="_${name}.raw.png"
  rm -f "$raw"
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --no-first-run \
    --user-data-dir="$prof" --force-device-scale-factor=1 \
    --window-size=${W},${RENDER_H} --virtual-time-budget=2500 \
    --screenshot="$raw" "file://$PWD/${name}.src.html" >/dev/null 2>&1 &
  cpid=$!
  for _ in $(seq 1 60); do [ -s "$raw" ] && break; sleep 0.3; done
  sleep 0.6
  kill -9 "$cpid" 2>/dev/null || true
  wait "$cpid" 2>/dev/null || true
  node pngcrop.mjs "$raw" "${name}.png" "${CROP_H}"
  rm -rf "$raw" "$prof"
done
echo "Wrote obsign.png and custos.png (${W}x${CROP_H})."
