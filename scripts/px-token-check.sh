#!/usr/bin/env bash
# Verify the two mobile apps' "never hardcode px" design-token rule stays true.
#
# AGENTS.md's Design Context bullet ("never hardcode hex or px") was previously
# aspirational prose with nothing enforcing it — a 2026-09 sweep found ~307 raw px
# values across 61 files despite the rule. This guard is the forcing function so
# that class of regression can't recur silently: every gap/padding/margin, radius,
# font-size/line-height/letter-spacing, and fixed dimension in app CSS must come
# from a --space-*/--radius-*/--text-*/--leading-*/--size-* token in that app's
# tokens.css, not a bare `Npx` literal.
#
# Narrow allowlist (matches the actual needs of hand-rolled CSS, nothing more):
#   - 0px, 0.5px, and 1px — hairline borders/outlines/shadow offsets and the zero
#     value are common enough, and fine-grained enough, that a token would add
#     indirection without adding meaning.
#   - @media/@container breakpoint px (e.g. `(min-width: 768px)`) — viewport
#     breakpoints are not part of the spacing/size scale.
#   - a per-line escape hatch: `/* px-ok: <reason> */` on the SAME line as the
#     value. Use it only for a genuinely one-off value a token would misrepresent
#     (precisely-coupled component geometry, a decorative shadow/blur radius, a
#     one-time hero glyph) — every reason must be true, and it is reviewed like
#     any other comment. It is not a way to silence the gate on an ordinary
#     spacing/sizing value that should just use a token.
#
# Only apps/*/src is in scope — tokens.css, fonts.css, and base.css are the
# token/reset layer itself and are exempt by name, not by directory, so a
# differently-named token file would still be caught.
#
# For a .svelte file, only its <style> block is scanned. Markup and <script> often
# mention "Npx" in prose (a code comment explaining touch-target math, a doc string)
# with no CSS declaration in sight; scanning the whole file would flag prose, not
# hardcoded style. CSS block comments (/* ... */) inside <style> are still stripped
# before scanning, so a comment like "/* 46 track - 20 knob ... */" restating an
# already-tokenized value doesn't trip the gate either.
#
# Portable bash + awk only (no perl/python) — runs identically in the Linux ci-pds
# gate, the macOS just ci, and the Nix dev shell.
set -euo pipefail

cd "$(dirname "$0")/.."

offenders=0

check_file() {
  local f="$1"
  local is_svelte=0
  case "$f" in
    *.svelte) is_svelte=1 ;;
  esac

  awk -v fname="$f" -v is_svelte="$is_svelte" '
    # ---- state ----
    BEGIN { in_comment = 0; in_style = (is_svelte == 0) }

    # Track <style> block boundaries for .svelte files. A file is expected to
    # carry at most one <style> block; nested/multiple blocks all get scanned.
    is_svelte == 1 && /<style/ { in_style = 1 }

    {
      original = $0
      line = $0

      # Strip /* ... */ block comments, preserving column count (blanked, not
      # deleted) so byte offsets stay stable across the loop below. Handles a
      # comment that opens or closes mid-line, and one that spans lines.
      out = ""
      while (length(line) > 0) {
        if (in_comment) {
          e = index(line, "*/")
          if (e == 0) { line = ""; break }
          seg = substr(line, 1, e + 1); gsub(/./, " ", seg)
          out = out seg
          line = substr(line, e + 2)
          in_comment = 0
        } else {
          s = index(line, "/*")
          if (s == 0) { out = out line; line = ""; break }
          out = out substr(line, 1, s - 1)
          rest = substr(line, s)
          e = index(rest, "*/")
          if (e == 0) {
            seg = rest; gsub(/./, " ", seg)
            out = out seg
            line = ""
            in_comment = 1
          } else {
            seg = substr(rest, 1, e + 1); gsub(/./, " ", seg)
            out = out seg
            line = substr(rest, e + 2)
          }
        }
      }
      stripped = out

      if (is_svelte == 1 && /<\/style>/) { in_style = 0 }

      if (in_style == 0) { next }
      if (index(original, "px-ok:") > 0) { next }
      if (index(stripped, "@media") > 0 || index(stripped, "@container") > 0) { next }

      # Find every "<number>px" in the comment-stripped line; flag the line once
      # if any value is outside the {0, 0.5, 1} allowlist.
      rest2 = stripped
      bad = 0
      while (match(rest2, /[0-9]+(\.[0-9]+)?px/)) {
        tok = substr(rest2, RSTART, RLENGTH)
        val = tok + 0
        if (val != 0 && val != 0.5 && val != 1) { bad = 1 }
        rest2 = substr(rest2, RSTART + RLENGTH)
      }
      if (bad == 1) {
        print fname ":" FNR ":" original
      }
    }
  ' "$f"
}

files="$(find apps/*/src -type f \( -name '*.svelte' -o -name '*.css' -o -name '*.ts' \) \
  ! -name 'tokens.css' ! -name 'fonts.css' ! -name 'base.css' | sort)"

hits="$(
  for f in $files; do
    check_file "$f"
  done
)"

if [ -n "$hits" ]; then
  echo "✗ px-token-check: hardcoded px values found outside the token layer (see scripts/px-token-check.sh for the allowlist):" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi

echo "✓ no hardcoded px values outside apps/*/tokens.css"
