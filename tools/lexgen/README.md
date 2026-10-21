# lexgen

TypeScript declarations generated from the vendored lexicons in
[`crates/custos-core/lexicons/`](../../crates/custos-core/lexicons/), so the Node tools type their XRPC calls
against the same schemas the PDS validates with instead of re-describing them by hand.

- `types/<namespace>.d.ts`: one file per lexicon namespace (`com.atproto.repo`, `app.bsky.feed`, …).
- `types/index.d.ts`: `XrpcMethods` (NSID → `{ params, input, output }`) and `Records`
  (collection → record type).

`tools/mcp`'s `xrpc()` is generic over the NSID: a vendored NSID gets its lexicon's types, and
one Custos only proxies (`app.bsky.feed.getTimeline`, `com.atproto.repo.uploadBlob`, …) stays
loosely typed. Imports are type-only, so nothing here exists at runtime and no deploy image
needs this directory.

```bash
just lexgen        # regenerate after a lexicon bump
just lexgen-check  # fail on drift (part of `just checks`)
```

Do not edit `types/` by hand. The generator is plain `.mjs` with no dependencies, so the
drift check runs anywhere `node` does.
