# ADR-0034: Vendored atrium-repo patch for the MST split data-loss bug

- **Status:** Accepted
- **Date:** 2026-08-27
- **Deciders:** malpercio
- **Related:** [atrium-rs/atrium#343](https://github.com/atrium-rs/atrium/issues/343),
  `vendor/atrium-repo-patch/`, `crates/repo-engine/tests/mst_split_gate.rs`,
  [2026-08-27 MST data-loss incident](../../2026-08-27-mst-data-loss-incident.md)

## Context

atrium-repo 0.1.8 — the crate `repo-engine` builds every repository's Merkle Search
Tree with — has a data-destroying bug in `split_subtree`. When an insert's key hashes
to a higher tree layer than its neighbors, the tree must split a subtree around the
new key. The split's walk-back-up loop only re-attached each parent level's remaining
entries to a side of the split that the level below had already produced; when the
deepest split left one side empty, every parent level's entries on that side —
including whole subtrees — were silently dropped.

The failure is invisible by construction. The commit that loses the records reports
only its own op, the `since`/`rev` chain stays contiguous, and no delete events are
emitted, so nothing downstream can tell the repo shrank. Because the PDS has no
separate record index — `listRecords`, `describeRepo`, and the sync surface all walk
the MST — the records are gone from every surface at once. On 2026-08-27 a routine
single-record scrobble write whose key hashed to layer 3 destroyed 64 records (every
key sorting after the insertion point) from a production repo; the same repo had been
hit once before on 2026-08-20. The upstream issue reports ~24% of random 20-insert
sequences lose data and is open with no fix as of 0.1.8.

## Decision

We will vendor atrium-repo 0.1.8 at `vendor/atrium-repo-patch/` — upstream's
published source plus one fix to the `split_subtree` walk-up loop, wired through
`[patch.crates-io]` and workspace-`exclude`d, the same byte-minimal-fork discipline
as `swift-rs-patch`. The fix carries each level's orphaned sibling entries into a new
node on that side whether or not the level below contributed one.

The patch is guarded by `crates/repo-engine/tests/mst_split_gate.rs`: two minimal
orphan-shape regressions plus a randomized add/delete model check, all of which fail
against unpatched 0.1.8. A dependency bump that silently dropped the patch without an
upstream fix would go red.

## Consequences

- Repo writes stop destroying data; the write path needs no changes.
- We own a fork until upstream ships a fix; bumps to atrium-repo now mean re-applying
  or retiring the patch (the gate test decides which).
- The vendored crate is not linted or tested by `just ci` (workspace-excluded, same
  as swift-rs-patch); its correctness is asserted from the outside by the gate test.
- Repos already damaged are not healed by the fix; recovery is a separate concern
  (see the incident doc — the durable firehose log retains the lost record blocks
  within its retention window).

## Alternatives considered

- **Wait for or contribute an upstream fix.** The issue is open with no maintainer
  response; production was losing data now. (A fix upstream later retires the patch.)
- **Migrate to atproto-repo.** kan-tools/kan validated it against this exact bug
  class (25k+ inserts, zero loss) and switched. It is the stronger long-term answer
  but a much larger change — different blockstore/CAR APIs across `repo-engine` and
  the PDS's sync surface, and its CAR writer has no incremental-append mode. Worth
  evaluating separately; too much risk coupled to an urgent correctness fix.
- **Git-fork dependency instead of vendoring.** Adds a remote fetch to every build
  and a second repo to maintain; the vendored path patch keeps the fix reviewable in
  this repo and matches the existing swift-rs precedent.
