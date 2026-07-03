#!/usr/bin/env bash
# Verify parity across the bundled font copies.
#
# The brand fonts are deliberately vendored FOUR times — each surface must be
# self-contained (the Tauri apps load from disk with no web server; the PDS embeds
# its assets; the marketing site is zero-build static):
#   apps/identity-wallet/static/fonts   (Obsign wallet)
#   apps/admin-companion/static/fonts   (Brass Console — JetBrains Mono subset only)
#   crates/pds/assets/fonts             (PDS landing page, embedded)
#   sites/marketing/assets/fonts        (static marketing site)
#
# Each copy may bundle a SUBSET of the families (admin-companion ships only the
# mono), but any font file that appears in more than one copy under the same name
# must be byte-identical — otherwise a re-fetch or optimization applied to one copy
# silently forks the brand type. This script fails when same-named font files
# diverge, so a font update must touch every copy that bundles that file.
#
# Per-directory README.md files are intentionally different and are not compared.
#
# Portable bash + coreutils only (no perl/python) — runs identically in the Linux CI
# gate (`just ci-pds`), the macOS `just ci`, and the Nix dev shell.
set -euo pipefail

cd "$(dirname "$0")/.."

FONT_DIRS=(
  "apps/identity-wallet/static/fonts"
  "apps/admin-companion/static/fonts"
  "crates/pds/assets/fonts"
  "sites/marketing/assets/fonts"
)

# Every directory must exist — a moved/renamed copy must update this list, not
# silently drop out of the check.
missing=0
for dir in "${FONT_DIRS[@]}"; do
  if [ ! -d "$dir" ]; then
    echo "✗ font-parity: expected font directory is missing: $dir" >&2
    echo "  (moved or renamed? update FONT_DIRS in scripts/font-parity.sh)" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 1

# Collect "<basename> <sha256> <path>" for every font file across the copies.
records="$(
  for dir in "${FONT_DIRS[@]}"; do
    find "$dir" -maxdepth 1 -type f \
      \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) \
      -exec sha256sum {} +
  done | while read -r hash path; do
    printf '%s %s %s\n' "$(basename "$path")" "$hash" "$path"
  done | sort
)"

if [ -z "$records" ]; then
  echo "✗ font-parity: no font files found in any copy — has the layout changed?" >&2
  exit 1
fi

# For each basename shared by 2+ copies, all hashes must agree.
status=0
for name in $(printf '%s\n' "$records" | cut -d' ' -f1 | sort -u); do
  matches="$(printf '%s\n' "$records" | awk -v n="$name" '$1 == n')"
  count="$(printf '%s\n' "$matches" | wc -l)"
  hashes="$(printf '%s\n' "$matches" | cut -d' ' -f2 | sort -u | wc -l)"
  if [ "$count" -gt 1 ] && [ "$hashes" -gt 1 ]; then
    echo "✗ font-parity: $name differs between copies:" >&2
    printf '%s\n' "$matches" | awk '{printf "    %s  %s\n", $2, $3}' >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "  A font update must be applied to every copy that bundles the file" >&2
  echo "  (see the README.md next to each copy for upstream sources)." >&2
  exit 1
fi

copies="$(printf '%s\n' "$records" | wc -l)"
shared="$(printf '%s\n' "$records" | cut -d' ' -f1 | sort | uniq -d | sort -u | wc -l)"
echo "✓ font parity: $shared shared font file name(s) identical across copies ($copies files checked in ${#FONT_DIRS[@]} directories)"
