# Vendored ATProto interop fixtures (PDS)

These implementation-neutral syntax vectors are vendored verbatim from
[`bluesky-social/atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests)
at commit `056e5741bb330757205d6b16db5266fffcae937b` under CC0-1.0.

| Files | Consumed by |
|---|---|
| `handle_syntax_{valid,invalid}.txt` | `src/identity/handle.rs` |
| `did_syntax_{valid,invalid}.txt` | `src/identity/did.rs` |

Refresh each valid/invalid pair together from the upstream `syntax/` directory. The loaders preserve
case whitespace because leading and trailing spaces are part of the invalid vectors.
