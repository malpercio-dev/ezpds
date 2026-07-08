#!/usr/bin/env bash
# Verify the iOS workflows' `paths:` trigger filters stay in lockstep with the
# apps' real dependency graph, in both directions:
#   1. Coverage: every in-repo crate an app links (transitively, per
#      `cargo metadata`) is watched by that app's workflows — so giving an app a
#      new workspace-crate dependency without widening the filters fails this
#      gate instead of silently letting stale iOS builds ship.
#   2. Tightness: no filter entry is broader than that graph — so pure-PDS
#      changes (crates/pds, crates/repo-engine, crates/common, PDS-only
#      scripts) can never re-acquire the macOS lanes through a re-widened
#      `crates/**` or `scripts/**`.
#
# Enforcement is exact set equality: for each workflow we compute the expected
# entry list (INFRA below + `apps/<app>/**` per app + `<dir>/**` per in-repo
# dependency not already under one of those app dirs) and diff it against the
# workflow's actual `paths:`. A legitimate new trigger path that isn't a crate
# (say, a new root-level config the iOS build reads) belongs in INFRA here, in
# the same change that adds it to the workflows.
#
# Needs jq (in the dev shell and on ubuntu runners) + cargo; the metadata call
# is `--locked`, same as `just lock-check`.
set -euo pipefail

cd "$(dirname "$0")/.."

command -v jq >/dev/null || { echo "✗ jq is required (provided by the dev shell)" >&2; exit 1; }

META="$(cargo metadata --locked --format-version 1)"

# Repo-relative dirs of every in-repo package in the app's transitive dependency
# closure (the app itself included). Walks the resolved graph, so it sees deps
# reached through registry crates too — e.g. the [patch.crates-io] swift-rs fork,
# pulled in via the Tauri plugins' build-dependencies.
path_deps() {
  jq -r --arg app "$1" '
    . as $m
    | ($m.resolve.nodes | map({key: .id, value: [.deps[].pkg]}) | from_entries) as $adj
    | ($m.packages | map({key: .id, value: .}) | from_entries) as $pkgs
    | ($m.workspace_root + "/") as $root
    | [$m.packages[] | select(.name == $app) | .id] as $starts
    | if ($starts | length) != 1
      then error("expected exactly one package named " + $app + ", found " + ($starts | length | tostring))
      else . end
    | $starts
    | until(
        (. + [.[] as $id | ($adj[$id] // [])[]] | unique) == .;
        (. + [.[] as $id | ($adj[$id] // [])[]] | unique)
      )
    | map($pkgs[.])
    | map(select(.source == null and (.manifest_path | startswith($root))))
    | map(.manifest_path[($root | length):] | sub("/Cargo.toml$"; ""))
    | sort | unique | .[]
  ' <<<"$META"
}

# Non-crate entries every iOS lane must carry regardless of the crate graph.
# (Each workflow additionally watches its own file, added in expected_for.)
#   Cargo.toml / Cargo.lock  — a shared-dependency bump can change what the apps build
#   justfile                 — the lanes' build steps are just recipes
#   scripts/ios/**           — the shared iOS toolchain/patch scripts
#   rust-toolchain.toml      — pins the toolchain + iOS targets
INFRA=(
  "Cargo.toml"
  "Cargo.lock"
  "justfile"
  "scripts/ios/**"
  "rust-toolchain.toml"
)

iw_deps="$(path_deps identity-wallet)"
ac_deps="$(path_deps admin-companion)"

deps_for() {
  case "$1" in
    identity-wallet) printf '%s\n' "$iw_deps" ;;
    admin-companion) printf '%s\n' "$ac_deps" ;;
    *) echo "✗ unknown app '$1'" >&2; return 1 ;;
  esac
}

expected_for() { # <workflow file> <app>...
  local wf="$1"; shift
  local app dir covered
  printf '%s\n' "${INFRA[@]}" ".github/workflows/$wf"
  for app in "$@"; do
    printf 'apps/%s/**\n' "$app"
  done
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    # Dirs under one of this workflow's app roots are already covered by apps/<app>/**.
    covered=0
    for app in "$@"; do
      case "$dir" in "apps/$app" | "apps/$app"/*) covered=1 ;; esac
    done
    [ "$covered" -eq 1 ] || printf '%s/**\n' "$dir"
  done <<<"$(for app in "$@"; do deps_for "$app"; done | sort -u)"
}

actual_for() { # <workflow file>
  awk '
    /^[[:space:]]*paths:[[:space:]]*$/ { inp = 1; next }
    inp && /^[[:space:]]*#/ { next }
    inp && /^[[:space:]]*-[[:space:]]*"/ {
      s = $0
      sub(/^[[:space:]]*-[[:space:]]*"/, "", s)
      sub(/".*$/, "", s)
      print s
      next
    }
    inp { inp = 0 }
  ' ".github/workflows/$1"
}

fail=0

check() { # <workflow file> <app>...
  local wf="$1"
  if [ ! -f ".github/workflows/$wf" ]; then
    echo "✗ .github/workflows/$wf not found — update scripts/ios-paths-check.sh if the lane was renamed" >&2
    fail=1
    return
  fi
  local exp act
  exp="$(expected_for "$@" | sort -u)"
  act="$(actual_for "$wf" | sort -u)"
  if [ -z "$act" ]; then
    echo "✗ $wf: no paths: entries extracted — has the trigger block changed shape?" >&2
    fail=1
    return
  fi
  if [ "$exp" != "$act" ]; then
    echo "✗ $wf: paths filter has drifted from the apps' dependency graph:" >&2
    comm -23 <(printf '%s\n' "$exp") <(printf '%s\n' "$act") | sed 's/^/    missing:    /' >&2
    comm -13 <(printf '%s\n' "$exp") <(printf '%s\n' "$act") | sed 's/^/    unexpected: /' >&2
    echo "    (crate deps must be watched; anything broader re-triggers iOS lanes on pure-PDS changes." >&2
    echo "     A legitimate new non-crate path belongs in INFRA in scripts/ios-paths-check.sh.)" >&2
    fail=1
  fi
}

check ios-pr-check.yml identity-wallet admin-companion
check ios-testflight.yml identity-wallet
check admin-testflight.yml admin-companion

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "✓ iOS workflow paths parity: filters match the apps' dependency graph exactly"
