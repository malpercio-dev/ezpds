# Vendored ATProto interop fixtures (PDS)

These implementation-neutral vectors are vendored verbatim from
[`bluesky-social/atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests)
at commit `056e5741bb330757205d6b16db5266fffcae937b` under CC0-1.0.

| Files | Consumed by |
|---|---|
| `handle_syntax_{valid,invalid}.txt` | `src/identity/handle.rs` |
| `did_syntax_{valid,invalid}.txt` | `src/identity/did.rs` |
| `commit-proof-fixtures.json` | `src/routes/sync_subscribe_repos.rs` (`mod tests::firehose_interop_gate`) |

Refresh each valid/invalid pair together from the upstream `syntax/` directory. The loaders preserve
case whitespace because leading and trailing spaces are part of the invalid vectors.

## `commit-proof-fixtures.json` (firehose interop gate — MM-384)

Vendored from the upstream repo's `firehose/commit-proof-fixtures.json`. Its content is
byte-identical to [`bluesky-social/atproto`](https://github.com/bluesky-social/atproto)'s
MIT-licensed `packages/repo/tests/commit-proof-fixtures.json` — already vendored separately
under `crates/repo-engine/tests/fixtures/interop/` for the MST root-CID gate — but is fetched and
re-vendored here from the CC0 `firehose/` path per MM-384, since it is this crate's copy that the
firehose interop gate (below) reads. Both copies must be refreshed together if upstream ever
changes it.

Each entry gives a starting key set (`keys` → `rootBeforeCommit`), an operation (`adds`/`dels` →
`rootAfterCommit`), and `blocksInProof` — the MST node CIDs the reference implementation's own
test (`packages/repo/tests/commit-proofs.test.ts`) declares as the *covering proof* for every
touched key (`MST.getCoveringProof`: the target key's node path plus its immediate left/right
sibling paths) — the block set a party must be able to supply to prove the operation happened.
That test's own load-bearing check is that this set, and nothing else, is sufficient to **invert**
the operation (delete every add, re-add every del) and recover exactly `rootBeforeCommit`, across
every ordering of the inverse steps.

MM-384's gate (`sync_subscribe_repos.rs::tests::firehose_interop_gate`) rebuilds each fixture's
before/after MST via `atrium_repo::mst::Tree`, copies out *only* the reference `blocksInProof`
blocks into a fresh blockstore, and reproduces that same inversion check (every permutation of
undo-add/undo-del) against our own `Tree::add`/`Tree::delete` — pinning our MST mutation algorithm
to the reference's declared-minimal proof set using real upstream data. It then round-trips a CAR
of that block set through the real firehose pipeline (`Firehose::emit_commit` → durable persist →
`decode_stored_event` → `encode_commit_frame`) and re-runs the identical inversion check sourced
from nothing but the wire-decoded `#commit.blocks` bytes, confirming the pipeline doesn't drop or
corrupt anything the proof needs end to end.

**Documented divergence (MM-384 AC3):** this is the *only* file under upstream's `firehose/`
directory as of the pinned commit — there is no reference *wire frame byte* vector (header +
body DAG-CBOR bytes) for `#commit`, and none for `#account`/`#identity`/`#sync`. Those
frame shapes (the `{op, t}` header discriminator, `#repoOp.path`/`cid`/`prev` layout, and each
body's field set) are pinned only by this repo's own structural unit tests in
`sync_subscribe_repos.rs`, not by an external interop vector. `atrium-repo` (the MST crate this
codebase builds on) exposes no direct equivalent of the reference's sibling-inclusive
`getCoveringProof`, so the gate does not attempt to reproduce that algorithm's exact block
selection — only the inversion property it exists to guarantee. Production's `#commit.blocks`
payload is actually built by `repo_engine::collect_commit_diff` (a reachable-set diff over a real
signed commit, not a covering proof) — this fixture's raw MST roots carry no wrapping
signed-commit object for `collect_commit_diff`/`Repository::open` to walk, so the gate packages
the reference's own declared block set into the CAR instead, purely as real, upstream-anchored
data to push through the wire encoder.
