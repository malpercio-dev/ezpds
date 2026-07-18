# Vendored ATProto interop fixtures (repo-engine)

Implementation-neutral test vectors, vendored verbatim so the interop gates load the real
upstream files instead of hand-transcribed inline copies. The CC0 fixtures are pinned to
[`bluesky-social/atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests)
commit `056e5741bb330757205d6b16db5266fffcae937b`.

| File | Source | License |
|---|---|---|
| `key_heights.json` | atproto-interop-tests `mst/key_heights.json` | CC0-1.0 |
| `common_prefix.json` | atproto-interop-tests `mst/common_prefix.json` | CC0-1.0 |
| `tid_syntax_{valid,invalid}.txt` | atproto-interop-tests `syntax/tid_syntax_{valid,invalid}.txt` | CC0-1.0 |
| `nsid_syntax_{valid,invalid}.txt` | atproto-interop-tests `syntax/nsid_syntax_{valid,invalid}.txt` | CC0-1.0 |
| `recordkey_syntax_{valid,invalid}.txt` | atproto-interop-tests `syntax/recordkey_syntax_{valid,invalid}.txt` | CC0-1.0 |
| `aturi_syntax_{valid,invalid}.txt` | atproto-interop-tests `syntax/aturi_syntax_{valid,invalid}.txt` | CC0-1.0 |
| `datetime_syntax_{valid,invalid}.txt`, `datetime_parse_invalid.txt` | atproto-interop-tests `syntax/datetime_{syntax_valid,syntax_invalid,parse_invalid}.txt` | CC0-1.0 |
| `data-model-fixtures.json` | atproto-interop-tests `data-model/data-model-fixtures.json` | CC0-1.0 |
| `data-model-{valid,invalid}.json` | atproto-interop-tests `data-model/data-model-{valid,invalid}.json` | CC0-1.0 |
| `lexicon-{valid,invalid}.json` | atproto-interop-tests `lexicon/lexicon-{valid,invalid}.json` | CC0-1.0 |
| `commit-proof-fixtures.json` | [bluesky-social/atproto](https://github.com/bluesky-social/atproto) `packages/repo/tests/commit-proof-fixtures.json` | MIT |

`commit-proof-fixtures.json` is the one exception to CC0: it lives in the main atproto
monorepo (MIT-licensed), not the CC0 interop-tests repo. It is vendored here under the MIT
license (attribution: Bluesky PBC), the canonical source of the MST commit-proof root-CID
vectors.

## Consumed by

- `src/mst.rs` — `key_heights.json`, `common_prefix.json`
- `src/at_uri.rs` — `aturi_syntax_*.txt`
- `src/records.rs` — `nsid_syntax_*.txt`, `recordkey_syntax_*.txt`
- `src/datetime.rs` — `datetime_syntax_*.txt`, `datetime_parse_invalid.txt`
- `src/data_model.rs` — `data-model-{valid,invalid}.json`
- `src/lexicon.rs` — `lexicon-{valid,invalid}.json`
- `tests/interop_gate.rs` — `commit-proof-fixtures.json`, `tid_syntax_*.txt`,
  `data-model-fixtures.json`

The upstream `lexicon/` directory also carries `record-data-{valid,invalid}.json` (record
values validated *against* a resolved lexicon def). Those are not vendored yet: the
record-against-lexicon validator is the deferred second layer of this feature.

Refresh each fixture or valid/invalid pair from its upstream path. The records loader
preserves case whitespace and treats only `# ` as a comment marker so significant whitespace
and the invalid `#extra` record-key vector remain test cases.
