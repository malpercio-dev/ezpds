#!/usr/bin/env bash
# Reclaim local disk by pruning merged git worktrees (and their multi-GB Rust
# target/ build caches) plus merged / [gone] local branches. This automates the
# recurring "disk maxed by stale worktrees" cleanup: every agent-tool worktree
# (.claude/worktrees/*, ~/.t3/worktrees/*) carries its own target/, and nothing
# removes them when the branch's PR merges, so they only ever accumulate.
#
# SAFETY — only work that is provably already in `main` is ever removed:
#   * A worktree is removed only if it is CLEAN (no uncommitted tracked changes)
#     AND merged: its branch/HEAD is an ancestor of main (plain merge) OR every
#     commit's patch is already in main (squash-merge, detected via `git cherry`)
#     OR GitHub's merge record attests the tip belongs to a PR merged into main
#     (squash merges whose landed diff drifted from the local commits; best-effort,
#     needs gh + network — offline it degrades to KEEP, never to PRUNE).
#   * A branch is deleted only if it is merged by the same test and is not the
#     current branch. In-review branches (unmerged, still alive on origin) and
#     anything with commits not represented in main are KEPT and reported.
# Nothing that fails the merged test is touched, so no unmerged work is lost.
# Even a mistaken worktree removal only drops a regenerable target/ — the branch
# ref and its commits survive (recoverable via `git worktree add`).
#
# Usage:
#   scripts/gc.sh          # dry run (default): report what WOULD be removed
#   scripts/gc.sh --apply  # actually remove the reported worktrees/branches
#
# A best-effort `git fetch --prune` runs first so [gone] status and merge checks
# are fresh; a network failure is tolerated (falls back to cached refs).
set -euo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

cd "$(git rev-parse --show-toplevel)"
# The real main working tree — NOT the invoking worktree. `git rev-parse --show-toplevel`
# returns whichever worktree ran this script, so deriving MAIN_WT from cwd would "protect"
# the caller and leave git's actual main checkout eligible for pruning (its branch is `main`,
# so is_merged is trivially true). The first `worktree` entry of the porcelain listing is
# always the main working tree; parse it exactly as flush_wt parses each entry, so the
# equality check below compares like against like.
MAIN_WT="$(git worktree list --porcelain | awk '/^worktree / && !found {print substr($0, 10); found=1}')"

if [ "$APPLY" -eq 1 ]; then
  echo "== gc: APPLY mode — removing merged worktrees and branches =="
else
  echo "== gc: DRY RUN — nothing will be deleted (pass --apply to act) =="
fi

# Fresh remote state so [gone]/merge checks are accurate; tolerate offline.
if ! git fetch --prune origin >/dev/null 2>&1; then
  echo "warn: 'git fetch --prune' failed — using cached remote-tracking refs" >&2
fi

# ---- GitHub squash-merge tier --------------------------------------------------
# git cherry's patch-id test misses a squash merge whenever the landed diff differs
# from the local commits' diffs — concurrent PRs touching the same files, review
# fixups, or a conflict resolution against a newer base all change the patch-id.
# GitHub records which PRs contain a commit, so as a last resort ask it whether the
# tip is part of a PR that merged into main. That is still "provably in main", just
# attested by the merge record instead of a patch-id. Best-effort like the fetch
# above: no gh, no network, or a non-GitHub origin degrades to the local verdict.
# Accept github.com and *.github.com — this repo's origin fetches through the
# `mal.github.com` SSH host alias (dual-push GitHub/tangled setup), not the bare host.
origin_url="$(git remote get-url origin 2>/dev/null || true)"
case "$origin_url" in
  git@github.com:*|git@*.github.com:*|ssh://git@github.com/*|ssh://git@*.github.com/*|https://github.com/*)
    GH_REPO="${origin_url##*github.com[:/]}"; GH_REPO="${GH_REPO%.git}" ;;
  *)
    GH_REPO="" ;;
esac
gh_ok=""  # memoized preflight: "" = unchecked, 1 = usable, 0 = unusable (warned)
gh_usable() {
  if [ -z "$gh_ok" ]; then
    if [ -n "$GH_REPO" ] && gh api "repos/$GH_REPO" --jq .id >/dev/null 2>&1; then
      gh_ok=1
    else
      gh_ok=0
      echo "warn: gh/GitHub unreachable — squash merges may be reported as NOT merged" >&2
    fi
  fi
  [ "$gh_ok" = 1 ]
}
merged_pr=""
merged_on_github() {
  local tip="$1"
  gh_usable || return 1
  # A per-SHA failure (e.g. 404 for a never-pushed tip) is just "not merged".
  merged_pr="$(gh api "repos/$GH_REPO/commits/$tip/pulls" \
    --jq '[.[] | select(.merged_at != null and .base.ref == "main")][0].number // empty' \
    2>/dev/null)" || return 1
  [ -n "$merged_pr" ]
}

# Every commit on <ref> already in main? True for a plain-merge ancestor, for a
# squash-merge (git cherry prints '+' only for commits whose patch is absent), and
# for a squash-merge only GitHub's merge record can prove (see the tier above).
# Sets merged_label so the report shows which test proved it.
is_merged() {
  local ref="$1" tip
  merged_label="merged"
  tip="$(git rev-parse --verify "$ref" 2>/dev/null)" || return 1
  git merge-base --is-ancestor "$tip" main 2>/dev/null && return 0
  git cherry main "$tip" 2>/dev/null | grep -q '^+' || return 0
  merged_on_github "$tip" || return 1
  merged_label="merged (GitHub: PR #$merged_pr)"
}

# ---- Phase 1: worktrees --------------------------------------------------------
# Parse `git worktree list --porcelain` into "path|branch-or-HEAD-sha" records.
removed_wt=0
wt_path=""; wt_head=""; wt_branch=""
flush_wt() {
  [ -z "$wt_path" ] && return
  # Never touch the main checkout.
  if [ "$wt_path" = "$MAIN_WT" ]; then wt_path=""; return; fi
  local ref label
  if [ -n "$wt_branch" ]; then ref="$wt_branch"; label="[$wt_branch]"; else ref="$wt_head"; label="(detached $wt_head)"; fi
  local dirty size
  dirty="$(git -C "$wt_path" status --porcelain 2>/dev/null)"
  size="$(du -sh "$wt_path" 2>/dev/null | cut -f1)"
  if [ -n "$dirty" ]; then
    echo "  KEEP  $size  $wt_path $label — uncommitted changes"
  elif is_merged "$ref"; then
    echo "  PRUNE $size  $wt_path $label — $merged_label"
    if [ "$APPLY" -eq 1 ]; then
      git worktree remove --force "$wt_path" && removed_wt=$((removed_wt+1))
    fi
  else
    echo "  KEEP  $size  $wt_path $label — NOT merged into main"
  fi
  wt_path=""
}
echo "-- worktrees --"
while IFS= read -r line; do
  case "$line" in
    "worktree "*) flush_wt; wt_path="${line#worktree }"; wt_head=""; wt_branch="" ;;
    "HEAD "*)     wt_head="${line#HEAD }" ;;
    "branch "*)   wt_branch="${line#branch refs/heads/}" ;;
    "detached")   wt_branch="" ;;
  esac
done < <(git worktree list --porcelain)
flush_wt
[ "$APPLY" -eq 1 ] && git worktree prune

# ---- Phase 2: branches (after worktrees gone, so freed branches are deletable) --
echo "-- branches --"
current="$(git branch --show-current)"
# Branches still checked out in a surviving worktree can't be deleted; collect them.
checked_out="$(git worktree list --porcelain | sed -n 's/^branch refs\/heads\///p')"
removed_br=0
while IFS= read -r b; do
  [ -z "$b" ] && continue
  [ "$b" = "$current" ] && continue
  # Never delete the baseline every merged-test compares against: main is trivially
  # an ancestor of itself, so once the checkout sits on another branch (and main is
  # therefore neither current nor checked out anywhere) it would read as DELETE.
  [ "$b" = "main" ] && continue
  if printf '%s\n' "$checked_out" | grep -qxF "$b"; then
    echo "  KEEP  $b — checked out in a worktree"
    continue
  fi
  if is_merged "refs/heads/$b"; then
    echo "  DELETE $b — $merged_label"
    if [ "$APPLY" -eq 1 ]; then
      git branch -D "$b" >/dev/null && removed_br=$((removed_br+1))
    fi
  else
    echo "  KEEP   $b — not merged (in review / unpushed)"
  fi
done < <(git for-each-ref --format='%(refname:short)' refs/heads/)

echo "== done: removed $removed_wt worktree(s), $removed_br branch(es) =="
[ "$APPLY" -eq 0 ] && echo "   (dry run — re-run with 'just gc-apply' to remove the PRUNE/DELETE items)"
