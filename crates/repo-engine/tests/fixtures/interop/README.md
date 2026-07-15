# Vendored ATProto interop fixtures (repo-engine)

These implementation-neutral syntax vectors are vendored verbatim from
[`bluesky-social/atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests)
at commit `056e5741bb330757205d6b16db5266fffcae937b` under CC0-1.0.

| Files | Consumed by |
|---|---|
| `nsid_syntax_{valid,invalid}.txt` | `src/records.rs` |
| `recordkey_syntax_{valid,invalid}.txt` | `src/records.rs` |

Refresh each valid/invalid pair together from the upstream `syntax/` directory. The loader
preserves case whitespace and treats only `# ` as a comment marker so the invalid `#extra`
record-key vector remains a test case.
