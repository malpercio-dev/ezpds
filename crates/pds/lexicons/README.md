# Vendored lexicon documents

Byte-identical copies of `com.atproto.*` and `app.bsky.*` lexicon JSON documents from the
reference implementation, vendored so Custos can validate XRPC request bodies, query parameters,
response outputs, and repo-write records against the same schemas the reference PDS enforces
(`crates/pds/src/lexicon/` — see MM-364 for the input-body layer, MM-397 for the query-params
layer, MM-398 for the response-output layer, MM-399 for the `validate`-flag record layer).

- **Source:** <https://github.com/bluesky-social/atproto>, `lexicons/` tree
- **Pinned at:** tag `@atproto/pds@0.5.18` (retrieved 2026-07-16; the `app.bsky.*` record set
  2026-07-17; the query-params (`type: "query"`) set 2026-07-17). The
  `com.atproto.{space,simplespace}.*` set is pinned separately, to a `permissioned-data` commit
  SHA — see the Atproto Spaces scope entry below.
- **Scope:**
  - **Input procedures:** the `com.atproto.*` documents needed by the natively-handled JSON-input
    procedures (plus the documents their input refs reach: `com.atproto.admin.defs`,
    `com.atproto.repo.strongRef`).
  - **Query parameters (MM-397):** the `com.atproto.*` `type: "query"` documents behind every
    natively-handled GET route that hand-parsed its query string with axum's bare `Query<T>` (or,
    for `sync.getBlocks`, `RawQuery`) — `com.atproto.identity.resolve*`,
    `com.atproto.repo.{describeRepo,getRecord,listMissingBlobs,listRecords}`,
    `com.atproto.server.getServiceAuth`, and `com.atproto.sync.*` (excluding `subscribeRepos`, a
    `type: "subscription"` def outside this layer's scope). Params properties are restricted to
    primitives (string/integer/boolean) and arrays of primitives, so there is nothing further to
    vendor transitively (no ref/union ever appears in a `parameters` object).
  - **Response outputs (MM-398):** every natively-handled query/procedure that returns a JSON body
    now has its `output` schema parsed and registered by NSID (`assertValidXrpcOutput` parity, a
    self-drift guard on what Custos serves). This makes outputs validation roots, so their ref
    closure must resolve — pulling in the output-only `defs` documents no input/record closure
    already reached: `com.atproto.identity.defs` (`#identityInfo`, for `resolve*`/`refreshIdentity`)
    and `com.atproto.repo.defs` (`#commitMeta`, for the repo-write `commit` field). The other
    output refs are local defs already registered from their own documents (`applyWrites`' result
    unions, `listRecords#record`, `listRepos#repo`, `createAppPassword#appPassword`, …) or the
    already-vendored `com.atproto.admin.defs`/`strongRef`. Non-JSON outputs (the `sync.*` CAR
    streams, `getBlob`'s `*/*`) carry no schema and so are not validation roots.
  - **Record validation (MM-399):** the `app.bsky.*` **record** lexicons worth validating on repo
    writes (`feed.post`/`like`/`repost`, `graph.follow`/`block`/`list`/`listitem`/`listblock`,
    `actor.profile`) plus only the `object`/`string`/`token` defs their record schemas transitively
    reach (`embed.*`, `richtext.facet`, `com.atproto.label.defs`). The AppView **view/output** defs
    those same documents also declare are *not* validation roots, so an unresolvable ref buried in
    one of them is never reached and is deliberately left un-vendored — the record-reachable closure
    is much smaller than the full `app.bsky` graph.
  - **Atproto Spaces (`com.atproto.space.*`):** the record CRUD, read, and sync documents behind
    the permissioned-data surface (the sync group: `listRepoOps`, `getRepo`, `getBlob`,
    `listBlobs`), the space-host notification group (`listRepos`, `registerNotify`,
    `unregisterNotify`, `notifyWrite` — but **not** `notifySpaceDeleted`, which this server only
    ever *sends*, so like `checkUserAccess` it is not a validation root here), plus the `defs`
    document the `getLatestCommit`/`listRepoOps` outputs reach,
    and the two token-flow documents behind `auth/space.rs` (`getDelegationToken`,
    `getSpaceCredential`; both use the `space-ref` string format `space_uri.rs` validates), and
    the PDS-required management surface `com.atproto.simplespace.*` (`createSpace`,
    `updateSpace`, `deleteSpace`, `getSpace`, `addMember`, `removeMember`, `listMembers` + the
    `defs` document their policy/appAccess unions reach; `checkUserAccess` is served by a
    managing app, not the PDS, so it is not vendored).
    These are pinned to commit **`5fbc9a0076a40799c22a13e0bac7e6fba6ec785f`** of the
    `permissioned-data` branch (2026-08-24), not the `@atproto/pds` tag the rest of this list
    follows — the alpha ships no tag carrying them. A branch name is not a pin: it moves, and
    the byte-identity claim below is only auditable against a fixed revision, so re-fetch these
    at the SHA (substitute it for the tag in the `curl` below) and expect upstream to move —
    breaking changes are still promised. The Friday
    [spaces-alpha-watch routine](../../../docs/operations/spaces-alpha-watch-routine.md) diffs
    the branch weekly; when it reports a lexicon delta, re-vendor and advance this SHA.
  - Proxied namespaces (the rest of `app.bsky.*`, `chat.bsky.*`, `com.atproto.moderation.*`) are
    validated upstream and are deliberately not vendored.

## Adding or updating a document

1. Fetch the file at a pinned tag, mirroring the upstream path layout:

   ```sh
   curl -o com/atproto/server/example.json \
     "https://raw.githubusercontent.com/bluesky-social/atproto/refs/tags/%40atproto/pds%400.5.18/lexicons/com/atproto/server/example.json"
   ```

   For the branch-pinned `com.atproto.{space,simplespace}.*` set, substitute the commit SHA for
   the `refs/tags/...` path segment:

   ```sh
   curl -o com/atproto/space/example.json \
     "https://raw.githubusercontent.com/bluesky-social/atproto/5fbc9a0076a40799c22a13e0bac7e6fba6ec785f/lexicons/com/atproto/space/example.json"
   ```

2. Add it to `LEXICON_SOURCES` in `crates/pds/src/lexicon/mod.rs` (also vendor anything its
   input schema, its JSON `output` schema, or — for a record — its `record` body `ref`s/`union`s
   reach).
3. `cargo test -p pds --bins lexicon` — the registry parser rejects any construct the validator
   doesn't implement (unknown keys, def types, string formats) and any dangling ref, so an
   unsupported document fails loudly here instead of validating laxer than the reference.
4. When updating the pin, update the tag — or, for `com.atproto.{space,simplespace}.*`, the
   `permissioned-data` commit SHA — in this README and in the `curl` example.

Do not hand-edit the JSON files: they must stay byte-identical to upstream so validation parity
is auditable by diff.
