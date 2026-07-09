# Post-commit block GC: stop recomputing full-repo reachability (MM-271)

## Summary

Every repo write ran a post-commit block GC (`record_write::gc_repo_blocks`) that recomputed the
*entire* reachable block set from the new root — `repo_engine::collect_reachable_cids`, one
`SELECT` per block through `SqliteBlockStore` — and then scanned the account's whole `block_owners`
table to delete the complement. On the single-connection pool that makes each post/like/delete
O(repo-size) in point reads, blocking every other request while it runs, and it grows with every
record the account has ever written.

This change removes that per-write reachability re-walk by **reusing the reachable set the commit
already computed for the firehose diff**. The GC keeps its exhaustive semantics; it just no longer
walks the repo a second time.

Depends on MM-260 (per-DID write serialization, PR #155): the GC deletes against a keep-set and
must run under the account's `RepoWriteLocks` guard with the new root already committed as the head,
so no concurrent same-repo write's fresh blocks can be misclassified as garbage.

## Where the cost actually was

`commit_repo_write` already walks `reachable(new)` and `reachable(prev)` on every commit to build
the firehose `#commit` diff CAR (`collect_commit_diff_cids` = `reachable(new) − reachable(prev)`).
The separate `gc_repo_blocks` call then walked `reachable(new)` a **third** time purely for GC. The
reachable walk — not the single `block_owners` scan — is the dominant cost (N point reads vs. one
indexed query), and it was pure duplication of work the firehose path had just done.

## Approach

1. **`repo-engine::collect_commit_diff`** (`car_export.rs`) returns a `CommitDiff { added,
   new_reachable }` from a single walk of the new root (plus one of the previous root): `added =
   reachable(new) − reachable(prev)` (the firehose diff), and `new_reachable = reachable(new)` (the
   GC keep-set). `collect_commit_diff_cids` is retained as a thin `added`-only wrapper for
   `export_commit_blocks_car`.

2. **`commit_repo_write`** computes `CommitDiff` once. `added` drives the firehose CAR + the
   `getRepo?since` rev tag exactly as before; `new_reachable` is handed to the post-commit GC as its
   keep-set. The GC now runs *inside* `commit_repo_write` (the single write choke point), after the
   root-advancing CAS commits, best-effort and last.

3. **`gc_repo_blocks`** takes the precomputed `reachable: &HashSet<String>` instead of walking the
   repo itself. It keeps the MM-260 stale-root guard (skip if the head has moved off the GC root)
   and the exhaustive `delete_unreachable_blocks` (delete every owned CID not in the keep-set).

4. The three post-commit `gc_repo_blocks(new_root)` calls in `write_record` / `delete_record` /
   `apply_writes` are removed — the GC is now part of `commit_repo_write`.

Net per write: 3 reachability walks + 1 owner-scan → **2 walks** (the firehose's, unavoidable) +
1 owner-scan. The GC's own O(repo) walk is gone.

## Why not the superseded-set + background-sweep design the issue sketched

The issue proposed computing only the *superseded* set (`reachable(prev) − reachable(new)`),
deleting exactly that, and moving orphan cleanup to a periodic background sweep like `blob_gc`.
That was reconsidered and rejected for this change:

- **It leaks on `applyWrites`.** A multi-op batch applies each op via `put_record_json` in turn, so
  it writes *intermediate* commit/MST blocks that are reachable from neither `prev` nor `new`. Those
  are not in `reachable(prev) − reachable(new)`, so a superseded-only delete never reclaims them —
  they would accumulate until a background sweep ran.
- **It regresses self-healing.** Today a skipped/failed GC is transparently retried by the next
  write's exhaustive pass. A superseded-only delete has no such property; a dropped delete leaks
  permanently until the sweep.
- **The marginal win is small.** Both designs still pay the firehose's two full walks per commit
  (the real remaining O(repo) tax). The superseded-only design only additionally avoids the single
  `block_owners` scan query — at the cost of a whole new background-sweep subsystem plus the leaks
  above.

Reusing the firehose's `reachable(new)` set keeps the GC exhaustive (no leaks, self-healing), needs
no new subsystem, and eliminates the same expensive thing the issue targeted: the per-write
reachability re-walk.

## Follow-up (not in this change)

The firehose diff itself still walks `reachable(prev)` and `reachable(new)` on every commit, so a
write remains O(repo-size) overall. A genuinely incremental MST diff (walking only the changed
subtree, pruning shared-CID subtrees) would make both the firehose diff *and* this GC O(changed) —
the "O(changed subtree)" ideal the issue gestures at. That is a larger, correctness-critical change
(a diff bug corrupts repos, the MM-260 failure class) and is worth its own issue.

## Tests

- `repo-engine`: `collect_commit_diff` reports the correct `added` set and a `new_reachable` that
  equals `reachable(new)` exactly (so the GC keep-set excludes superseded blocks); genesis case
  where `added == new_reachable`.
- `pds` `record_write`:
  - `repeated_updates_reclaim_superseded_blocks` — rewriting one record ten times leaves the same
    number of owned blocks as after the first write (without GC it would grow ~linearly), and the
    repo still opens at head and reads the latest value.
  - `stale_root_gc_preserves_committed_repo` (updated) — the stale-root guard skips a GC keyed on a
    superseded root; passing an empty keep-set makes the test fail loudly if the guard ever regresses.
  - `concurrent_same_repo_writes_never_corrupt_repo` (existing, MM-260) — still green with the GC
    moved into `commit_repo_write`.
