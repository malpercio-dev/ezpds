# Repo Engine: atrium-repo Adoption Design

**Wave:** 4 (Repo + Blobs) · **Supersedes:** the from-scratch MST in PR #18 (MM-98)

## Summary

Replace the hand-rolled Merkle Search Tree / block store in `repo-engine` with the
`atrium-repo` crate (0.1.8, MIT), and build the surrounding repository storage layer on
top of it: a content-addressed `blocks` table, an `AsyncBlockStore` adapter in the relay
shell, a P-256 commit-signing seam reusing the `crypto` crate, a signed genesis repo at
account creation, and the `getRepo` read path. The custom MST was found to be
spec-non-compliant (it omits the empty intermediate nodes the ATProto MST requires, so its
root CID diverges from the network) and that bug was invisible to its tests because the
crate has no interop vectors. `atrium-repo` was verified to materialize those nodes and to
produce reference-matching root CIDs, so adoption removes an entire class of interop risk
while keeping `crypto`, the per-user-SQLite plan, and the imperative shell fully ours.

The decision rationale (build-vs-buy, weighted factors, sources) lives in the session that
produced this plan; this document is the implementation roadmap.

## Definition of Done

- `repo-engine` no longer contains a hand-rolled MST or block store; it depends on
  `atrium-repo` and exposes a thin, ezpds-shaped domain API over it.
- A permanent interop gate in CI asserts that repo construction produces root CIDs and CAR
  bytes byte-identical to the canonical ATProto reference vectors.
- Creating an account produces a persisted, signed, network-verifiable genesis repo whose
  commit is signed by the account's atproto signing key via the `crypto` crate.
- `com.atproto.sync.getRepo` returns a valid CAR export of an account's repo.
- Record writes (`applyWrites` / `putRecord` / `deleteRecord` / `getRecord`) mutate the repo
  and produce new signed commits.
- `cargo build`, `cargo test`, `cargo clippy --workspace -- -D warnings`, and
  `cargo fmt --all --check` pass (i.e. `just ci-relay`).

Out of scope (deferred to Wave 5 Federation): `subscribeRepos` firehose framing/sequencing,
`getCheckpoint`, `listRepos`, and `prevData`/covering-proof emission.

## Acceptance Criteria

### repo-atrium.AC1: Custom MST retired, atrium-repo adopted
- **AC1.1 Success:** `repo-engine` depends on `atrium-repo`; `src/mst.rs` and
  `src/blockstore.rs` are deleted; the workspace builds.
- **AC1.2 Success:** `repo-engine`'s public API exposes only ezpds-shaped domain types/helpers;
  no caller references the deleted modules.

### repo-atrium.AC2: Interop gate proves canonical output
- **AC2.1 Success:** Given the CC-0 `mst/key_heights.json` fixtures, the layer/height computed
  for each key matches the fixture.
- **AC2.2 Success:** Given a known-answer key→value set ported from the ATProto reference, the
  repo root CID equals the reference value.
- **AC2.3 Success:** A full-repo CAR round-trip (build → export → re-import) reproduces the same
  root CID.
- **AC2.4 Failure:** A deliberately corrupted fixture causes the gate to fail (the gate is not a
  no-op).

### repo-atrium.AC3: Block storage
- **AC3.1 Success:** A block written by CID can be read back byte-identically.
- **AC3.2 Success:** Writing the same CID twice is idempotent (no error, one row).
- **AC3.3 Success:** Reading an absent CID returns a typed not-found, not a panic.
- **AC3.4 Success:** Blocks are scoped by `account_did` (FK to `accounts`).

### repo-atrium.AC4: AsyncBlockStore adapter
- **AC4.1 Success:** The adapter satisfies `atrium_repo::blockstore::{AsyncBlockStoreRead,
  AsyncBlockStoreWrite}` over the `blocks` table.
- **AC4.2 Success:** A tree built through the adapter has the same root CID as the same tree
  built through atrium's `MemoryBlockStore`.

### repo-atrium.AC5: Commit signing seam
- **AC5.1 Success:** `crypto` exposes a function that signs arbitrary bytes with a P-256 key,
  returning a raw 64-byte low-S r‖s signature.
- **AC5.2 Success:** A commit signed via `CommitBuilder::bytes()` → sign → `finalize(sig)`
  verifies against the signing key's public key.

### repo-atrium.AC6: Genesis repo at account creation
- **AC6.1 Success:** Creating an account persists an empty, signed genesis repo and records its
  root commit CID for the account.
- **AC6.2 Success:** The genesis commit is signed by the account's atproto signing key.
- **AC6.3 Failure:** If repo creation fails, account creation fails atomically (no partial state).

### repo-atrium.AC7: Read & write paths
- **AC7.1 Success:** `com.atproto.sync.getRepo` returns a CAR whose root is the account's current
  commit and which re-imports cleanly.
- **AC7.2 Success:** `putRecord`/`applyWrites` add/update a record and advance the repo to a new
  signed commit referencing the prior commit via `prev`.
- **AC7.3 Success:** `getRecord` returns a previously written record by collection + rkey.
- **AC7.4 Failure:** A malformed record key (not `collection/rkey`) is rejected before mutation.

## Glossary

- **MST** — Merkle Search Tree: the deterministic, content-addressed key→record-CID index whose
  root CID is committed and signed.
- **Block** — a single DAG-CBOR object (an MST node or a record), addressed by its CIDv1
  (dag-cbor codec `0x71`, sha2-256 `0x12`).
- **Commit** — the signed root object `{did, version, data: <mst root CID>, rev, prev, sig}`.
- **CAR** — Content-Addressed aRchive: the wire format for shipping a repo's blocks with a
  declared root (used by `getRepo`).
- **Adapter** — the relay-side struct implementing atrium's two block-store traits over SQLite.
- **Signer seam** — `CommitBuilder::bytes()` → P-256 sign → `finalize(sig)`; the only place
  private key material meets the repo layer.

## Architecture

```
                 ┌──────────────────────────── relay (Imperative Shell) ────────────────────────────┐
  HTTP ──▶ routes/{create_account, sync_get_repo, apply_writes, ...}                                  │
                 │        │                    │                                                      │
                 │        ▼                    ▼                                                      │
                 │   db/blocks.rs        SqliteBlockStore (adapter)  ──impl──▶ atrium_repo::blockstore│
                 │   (SQL over `blocks`)  holds &pool + account_did          AsyncBlockStore{Read,Write}
                 │                                   │                                                 │
                 └───────────────────────────────────┼─────────────────────────────────────────────────┘
                                                      ▼
            repo-engine (thin domain core) ──▶ atrium_repo::{repo::Repository, mst::Tree, CommitBuilder}
                                                      │ bytes()
                                                      ▼
                                       crypto::sign_p256_bytes(priv, &[u8]) -> [u8;64]   (Functional Core)
                                                      │ finalize(sig)
                                                      ▼
                                            signed Commit, root CID
```

**FCIS placement (unchanged contract):** all SQLite/IO stays in the relay. `atrium-repo`'s
storage is fully behind two `&mut self` async traits, so the *only* IO touchpoint is the
adapter, which lives in `relay/src/db` (or `relay/src/repo`) and is `// pattern: Imperative
Shell`. `repo-engine` stays a thin core that orchestrates atrium types and never opens a
connection. `crypto` remains a pure functional core; it gains one byte-signing function.

**Per-user-DB sequencing:** `open_pool(&str)` already takes a URL, so the adapter is generic
over *which* pool it's handed. Wave 4 lands the `blocks` table in the server DB; migrating it to
per-user DBs (Wave 3/4) is a pool-injection change with no adapter rewrite. The `account_did`
column makes the eventual per-user split a straight partition.

**Signing key:** the genesis op already designates the relay-held atproto signing key as
`verificationMethods.atproto`. That same key signs repo commits, so the signer seam loads the
account's signing key (already stored, AES-256-GCM encrypted) and feeds bytes through
`crypto::sign_p256_bytes`.

## Existing Patterns

- **DB module:** `db/blobs.rs` (content-addressed by CID, `account_did` FK to `accounts`,
  `ON CONFLICT(cid)` idempotency) is the template for `db/blocks.rs`. Migrations are
  forward-only `V0NN__name.sql`; latest applied is `V016__blobs.sql`, so the new one is
  `V017__repo_blocks.sql`. db functions accept `&SqlitePool`, return data, open no transactions.
- **External-signer seam:** `crypto::build_did_plc_genesis_op_with_external_signer` already
  takes `sign: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>` returning a raw 64-byte r‖s P-256
  signature. The commit signer is the same primitive; factor the inner ECDSA-SHA256 low-S step
  into a reusable `sign_p256_bytes`.
- **CID/codec constants:** mirror atrium's `blockstore::{DAG_CBOR=0x71, SHA2_256=0x12}`; do not
  reintroduce local copies in `repo-engine`.
- **Route shape:** handlers are thin Imperative Shells (gather → process → respond); register in
  `app.rs`; add a `.bru` file under `bruno/` for every new/changed route.

## Implementation Phases

Each phase is one shippable PR that builds and tests green on its own.

### Phase 1: Adopt atrium-repo, retire custom MST, land the interop gate
- Promote `atrium-repo` from a workspace declaration to a real `repo-engine` dependency; delete
  `src/mst.rs` and `src/blockstore.rs`; reduce `repo-engine` to a thin domain wrapper/re-export
  over `atrium_repo` types.
- Vendor the CC-0 `bluesky-social/atproto-interop-tests` fixtures
  (`mst/key_heights.json`, `mst/common_prefix.json`, `firehose/commit-proof-fixtures.json`) plus
  a small set of known-answer root CIDs ported from the ATProto reference `@atproto/repo` tests
  as pure-data test fixtures in the functional core.
- Add tests asserting atrium-repo-backed construction matches those vectors; wire the gate into
  `just ci-relay`.
- **Verifies:** AC1.1, AC1.2, AC2.1, AC2.2, AC2.3, AC2.4.
- **Done when:** custom modules gone, workspace builds, interop gate is green in CI, and a
  deliberately corrupted fixture turns it red.

### Phase 2: `blocks` storage table + `db/blocks.rs`
- Add `V017__repo_blocks.sql`: `blocks(cid TEXT PRIMARY KEY, account_did TEXT NOT NULL
  REFERENCES accounts(did), bytes BLOB NOT NULL, created_at TEXT)`, index on `account_did`.
- Add `db/blocks.rs` (`// pattern: Imperative Shell`): `put_block`, `get_block`, `has_block`,
  `delete_blocks_for_account`, all `&SqlitePool`-based with `ON CONFLICT(cid)` idempotency.
- **Verifies:** AC3.1, AC3.2, AC3.3, AC3.4.
- **Done when:** in-memory-DB unit tests cover round-trip, idempotency, not-found, and FK scoping.

### Phase 3: `SqliteBlockStore` adapter
- Implement `atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite}` for a
  `SqliteBlockStore { pool, account_did }` struct in the relay; `write_block(codec, hash,
  contents)` computes the CID and persists via `db/blocks.rs`; `read_block` fetches and maps
  absent → atrium's `CidNotFound`.
- **Verifies:** AC4.1, AC4.2.
- **Done when:** a parity test builds the same key set through the adapter and through atrium's
  `MemoryBlockStore` and asserts identical root CIDs.

### Phase 4: P-256 commit-signing seam
- Add `crypto::sign_p256_bytes(private_key: &[u8; 32], msg: &[u8]) -> Result<[u8; 64],
  CryptoError>` (ECDSA-SHA256, low-S, raw r‖s); refactor the did:plc signer to reuse it.
- Add a relay/repo helper that drives `CommitBuilder::bytes()` → `sign_p256_bytes` → `finalize`.
- **Verifies:** AC5.1, AC5.2.
- **Done when:** a unit test signs a commit and verifies the signature against the public key;
  signing is deterministic for fixed inputs.

### Phase 5: Signed genesis repo at account creation
- Add repo-root tracking for accounts (a `repo_root` column or a `repos` row, decided during
  Phase 5 investigation).
- In `create_account.rs` and `create_mobile_account.rs`, after the did:plc genesis, build an
  empty `Repository` over a `SqliteBlockStore`, sign the root commit via the seam, persist its
  blocks, and record the root — all inside the existing account-creation transaction boundary so
  failure rolls back atomically.
- **Verifies:** AC6.1, AC6.2, AC6.3.
- **Done when:** creating an account yields a stored, signature-verifiable genesis commit, and an
  injected failure leaves no partial account/repo.

### Phase 6: `getRepo` CAR export (read path)
- Add `routes/sync_get_repo.rs` for `GET /xrpc/com.atproto.sync.getRepo`: load the account's
  root, export blocks via the adapter into CAR bytes, stream the response; add the `.bru` file.
- **Verifies:** AC7.1.
- **Done when:** the returned CAR re-imports to the recorded root CID in a test.

### Phase 7: Record write/read surface
- Add `applyWrites` / `putRecord` / `deleteRecord` / `getRecord` handlers that mutate the repo
  through atrium, sign the new commit (with `prev` set to the previous commit), persist blocks,
  and advance the account root; validate record keys (`collection/rkey`) before mutation; add
  `.bru` files.
- **Verifies:** AC7.2, AC7.3, AC7.4.
- **Done when:** write→read round-trips through the XRPC surface and each write advances `prev`.

## Additional Considerations

- **Dependency footprint:** `atrium-repo` transitively pulls `atrium-api 0.25.8`,
  `atrium-xrpc`, and `atrium-common`. This is a dependency *cluster*, not a leaf crate; confirm
  the added compile time and surface are acceptable, and pin versions in the workspace.
- **Signature curve:** ezpds is P-256 (ES256) end-to-end; ATProto also permits K-256 (ES256K).
  The interop fixtures and atrium both support P-256 — keep all repo signing keys P-256.
- **Atomicity:** genesis-repo persistence and record writes must share the route handler's
  transaction (per the relay's "transactions live in the handler, not in `db/`" rule) so a repo
  failure cannot leave a half-created account or a dangling root.
- **Interop gate maintenance:** treat the vendored vectors as append-only fixtures; refresh them
  when the ATProto repo spec revs (sync v1.1, `prevData`, covering proofs) and add a `prevData`
  case before Wave 5 federation.
- **PR #18 disposition:** this design replaces #18's custom MST wholesale; repurpose #18 as
  "Phase 1: adopt atrium-repo + interop gate" or close it in favor of a fresh branch.
- **Per-user DBs:** when Wave 3/4 introduces per-user SQLite, the `blocks` table moves to the
  per-user DB and the adapter is constructed with the per-user pool; no adapter logic changes.
- **8-phase limit:** this is 7 phases, within the implementation-plan skill's cap, so each phase
  can be expanded into a `docs/implementation-plans/2026-06-22-repo-engine-atrium-adoption/phase_0N.md`
  when it's picked up for execution.
```
