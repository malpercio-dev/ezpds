# Vendored lexicon documents

Byte-identical copies of `com.atproto.*` lexicon JSON documents from the reference
implementation, vendored so Custos can validate XRPC request bodies against the same schemas
the reference PDS enforces (`crates/pds/src/lexicon/` — see MM-364).

- **Source:** <https://github.com/bluesky-social/atproto>, `lexicons/` tree
- **Pinned at:** tag `@atproto/pds@0.5.18` (retrieved 2026-07-16)
- **Scope:** only the documents needed by the natively-handled JSON-input procedures (plus the
  documents their refs reach: `com.atproto.admin.defs`, `com.atproto.repo.strongRef`).
  Proxied namespaces (`app.bsky.*`, `chat.bsky.*`, `com.atproto.moderation.*`) are validated
  upstream and are deliberately not vendored.

## Adding or updating a document

1. Fetch the file at a pinned tag, mirroring the upstream path layout:

   ```sh
   curl -o com/atproto/server/example.json \
     "https://raw.githubusercontent.com/bluesky-social/atproto/refs/tags/%40atproto/pds%400.5.18/lexicons/com/atproto/server/example.json"
   ```

2. Add it to `LEXICON_SOURCES` in `crates/pds/src/lexicon/mod.rs` (also vendor anything its
   input schema `ref`s/`union`s reach).
3. `cargo test -p pds --bins lexicon` — the registry parser rejects any construct the validator
   doesn't implement (unknown keys, def types, string formats) and any dangling ref, so an
   unsupported document fails loudly here instead of validating laxer than the reference.
4. When updating the pin, update the tag in this README and in the `curl` example.

Do not hand-edit the JSON files: they must stay byte-identical to upstream so validation parity
is auditable by diff.
