# Vendored ATProto interop fixtures (repo-engine)

Implementation-neutral test vectors, vendored verbatim so the interop gate
loads the real upstream files instead of hand-transcribed inline copies.
Refresh by re-downloading from the sources below (the loaders parse whatever
these files contain, so added upstream cases are picked up automatically).

| File | Source | License |
|---|---|---|
| `key_heights.json` | [bluesky-social/atproto-interop-tests](https://github.com/bluesky-social/atproto-interop-tests) `mst/key_heights.json` | CC0-1.0 |
| `common_prefix.json` | bluesky-social/atproto-interop-tests `mst/common_prefix.json` | CC0-1.0 |
| `tid_syntax_valid.txt` | bluesky-social/atproto-interop-tests `syntax/tid_syntax_valid.txt` | CC0-1.0 |
| `tid_syntax_invalid.txt` | bluesky-social/atproto-interop-tests `syntax/tid_syntax_invalid.txt` | CC0-1.0 |
| `data-model-fixtures.json` | bluesky-social/atproto-interop-tests `data-model/data-model-fixtures.json` | CC0-1.0 |
| `commit-proof-fixtures.json` | [bluesky-social/atproto](https://github.com/bluesky-social/atproto) `packages/repo/tests/commit-proof-fixtures.json` | MIT |

`commit-proof-fixtures.json` is the one exception to CC0: it lives in the main
atproto monorepo (MIT-licensed), not the CC0 interop-tests repo. It is vendored
here under the MIT license (attribution: Bluesky PBC), the canonical source of
the MST commit-proof root-CID vectors.

## Consumed by

- `src/mst.rs` — `key_heights.json`, `common_prefix.json`
- `tests/interop_gate.rs` — `commit-proof-fixtures.json`, `tid_syntax_*.txt`,
  `data-model-fixtures.json`

The `.txt` syntax files use one case per line; blank lines and `#`-prefixed
comment lines are ignored by the loader.
