# 2026-08-27 MST data-loss incident

64 records vanished from `did:plc:xhwhcrlq75w45zmm6ea7jgjn` (jzweifel.dev) on
production. No client deleted them: a routine single-record write corrupted the
repository's Merkle Search Tree. This page records what happened, how it was traced,
and how the records were recovered, so the next silent-loss report starts from a
procedure instead of a blank page. The fix is [ADR-0034](architecture/decisions/0034-vendored-atrium-repo-mst-patch.md).

## What happened

At 12:33:38 UTC, firehose seq 792 — `create fm.teal.feed.play/3mu2u7t4nbs2l`, an
ordinary scrobble — dropped every MST key sorting after the inserted key: all of
`fyi.atstore.*`, `id.sifa.*` (49 records), `page.mooring.*`, `sh.tangled.*`, and
`site.standard.*`. The inserted key hashes to MST layer 3 (leading zero bit-pairs of
its SHA-256; roughly 1 in 64 keys), which forces subtree splits on insert, and
atrium-repo 0.1.8's `split_subtree` discards the parent levels' entries on a side of
the split that ends up empty at the bottom ([atrium-rs/atrium#343](https://github.com/atrium-rs/atrium/issues/343)).

The same bug had already hit the same repo on 2026-08-20 (seq 327 took
`page.mooring.site/self`; the app recreated it a day later, masking the loss). No
other repo on the instance was affected — verified by diffing every repo's current
collections against its retained firehose history.

## Why nothing noticed

- The corrupting commit reports only its own op; no delete events are emitted.
- The event chain stays contiguous (`since` = previous `rev` throughout), so relay
  consumers and any chain audit see a healthy repo.
- The PDS has no separate record index: `listRecords`, `describeRepo`, and the sync
  routes all walk the MST, so every surface agreed the records never existed.
- `sync.getRecord` for a lost key returns a well-formed *exclusion* proof.

## How it was traced

All steps used public surfaces — no admin access:

1. `describeRepo` against the live PDS: collections missing entirely.
2. Replay `com.atproto.sync.subscribeRepos?cursor=0` (the durable log retains a
   window of event CARs): creates present, zero deletes, no `#sync`/`#account`
   events, `since`↔`rev` chain contiguous — ruling out clients, imports, restores.
3. Each `#commit` event embeds the blocks it wrote, including the new MST root.
   Accumulating every block across the replay and walking each commit's root toward
   a lost key bisects the loss to the exact commit (present at seq 791, absent at
   792).
4. The trigger key's layer (3) plus the vendored crate's `split_subtree` source
   pinned the mechanism; two minimal repro shapes were confirmed against unpatched
   0.1.8 and became `crates/repo-engine/tests/mst_split_gate.rs`.

## Recovery

The same accumulated event blocks contain the lost records' values. Walking the last
intact root (seq 791) and collecting every key greater than the trigger key recovered
63 of 64 record values; they were re-published with the account's own credentials via
`applyWrites` in ascending key order (each insert is then the tree's new maximum,
which was first simulated against a copy of the live repo CAR on unpatched code and
shown loss-free). The one unrecoverable record, `fyi.atstore.profile/self`, was
created before the log's retention window began and its block had been reclaimed;
only its owner or app can republish it.

Limits worth knowing: recovery depends entirely on the durable firehose log's
retention window. Blocks orphaned by the corruption are reclaimed from the block
store by the account's next write-path GC, so `sync.getBlocks` against old commit
CIDs stops working almost immediately — the event CARs in the log are the only copy.
