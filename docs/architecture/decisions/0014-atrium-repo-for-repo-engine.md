# ADR-0014: Adopt `atrium-repo` for the repo engine's MST and block store

- **Status:** Accepted
- **Date:** 2026-07-05 (backfilled; decided 2026-06-22)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0004](0004-pds-signed-repo-commits.md) · [ADR-0005](0005-functional-core-imperative-shell.md) · [design plan](../../archive/design-plans/2026-06-22-repo-engine-atrium-adoption.md) · `crates/repo-engine/`

## Context

`repo-engine` started with a hand-rolled Merkle Search Tree and block store
(PR #18, MM-98). The custom MST turned out to be **spec-non-compliant**: it
omitted the empty intermediate nodes the ATProto MST requires, so its root CIDs
diverged from the rest of the network — and the bug was invisible to its own
tests because the crate had no interop vectors. A repo whose root CID doesn't
match the reference implementation cannot federate.

The `atrium-repo` crate (0.1.8, MIT) was verified to materialize those nodes
and produce reference-matching root CIDs.

## Decision

We will depend on **`atrium-repo`** for MST construction, block storage traits,
and commit building, and delete the hand-rolled MST and block store.
`repo-engine` stays a thin, ezpds-shaped domain API over it. We keep ours:

- the `crypto` crate signs commits via the `CommitBuilder::bytes()` → P-256
  sign → `finalize(sig)` seam (ADR-0004) — key material never enters the repo
  layer;
- the SQLite `blocks` table and its `AsyncBlockStore` adapter live in the
  imperative shell (ADR-0005);
- a permanent interop gate in CI asserts root CIDs and CAR bytes match the
  canonical ATProto reference vectors, so this class of drift can't silently
  return.

## Consequences

- An entire class of interop risk is removed; correctness is anchored to
  reference vectors rather than self-consistent unit tests.
- We take a dependency on a young crate (0.1.x); version bumps need care, but
  the interop gate catches behavioral regressions.
- The repo layer's public surface is ours, so a future swap (or vendoring)
  stays contained in `repo-engine`.

## Alternatives considered

- **Fix the hand-rolled MST** — possible, but keeps us the sole maintainers of
  the trickiest interop-critical data structure in the protocol, with the bug
  class that already bit us once.
- **Adopt atrium wholesale (API/agent layers too)** — unnecessary; only the
  repo layer had the correctness problem, and the rest of the PDS is
  deliberately our own shape.
