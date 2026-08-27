# Atproto Spaces (proposal 0016, née Permissioned Data) — Custos Gap Analysis

**Date:** 2026-07-17 · **Revised:** 2026-08-20 (official alpha release)
**Status:** Research / gap analysis — updated for the alpha; implementation green-lit for Phase 0
**Sources:**
- [0016 proposal](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) (canonical; kept in sync with the reference implementation as of the alpha)
- [The Atproto Spaces Alpha is Live](https://atproto.com/blog/atproto-spaces-alpha) (2026-08-20 announcement)
- Reference implementation: `permissioned-data` branch of bluesky-social/atproto — lexicons under `lexicons/com/atproto/{space,simplespace}/`, protocol library in `packages/space/` (LtHash, deniable commits, DPoP, sync — **with golden test vectors**)
- [Permissioned Data Diary 7: Off the Record](https://dholms.leaflet.pub/3mqtqvjidqs2p) (2026-07-17 — repo structure, signing, sync rationale); earlier diaries: [Diary 2: Buckets](https://dholms.leaflet.pub/3mfrsbcn2gk2a), [Diary 4: The Big Picture](https://dholms.leaflet.pub/3mhj6bcqats2o)
- [Community forum discussion](https://discourse.atprotocol.community/t/permissioned-data-proposal-discussion/946)

> **Alpha status (2026-08-20).** The protocol is now named **Atproto Spaces**
> and the alpha is officially open: a hosted sandbox PDS, a tagged Docker image
> (`ghcr.io/bluesky-social/atproto:pds-spaces-alpha`), alpha-tagged TypeScript
> `@atproto` SDK packages, and a sample app ([bulletin.my](https://bulletin.my),
> source at bluesky-social/bulletin). Updates ship **Thursdays** (announcements
> thread on atmosphere.community); target launch is "later this year".
> Breaking changes are still promised — the alpha explicitly disclaims
> production use — but the proposal is now the collaboration point and is kept
> current with the reference implementation. Ecosystem implementations exist
> (ZDS/Zig, atproto-crates/Rust, rsky/Blacksky, HappyView), so interop targets
> are real.

## 0. Spec deltas since the 2026-07-17 analysis

The July analysis was written against the 2026-07-02 proposal text. The
August revisions (proposals repo, commits `393bb7d`…`54c9cf5`) change it in
these ways, each folded into the sections below:

1. **Space credentials are DPoP-bound, not bearer** (the big one). A
   credential carries `cnf.jkt`; `getSpaceCredential` requires a DPoP proof
   (no `ath` on that proof — the delegation token is a grant, not an access
   token) and every credential-authed request to a repo host presents
   `Authorization: DPoP <credential>` plus a per-request proof that hosts MUST
   validate per RFC 9449 (signature vs. header `jwk`, thumbprint vs.
   `cnf.jkt`, `ath` = hash of the credential, `htm`/`htu`, `iat` recency,
   `jti` unseen). Rationale: a bearer credential would let any repo host
   replay it against every other host in the space. Syncers should mint a
   fresh keypair per credential and discard it on expiry.
2. **MAC construction pinned**: `mac = HMAC-SHA256(HKDF-Expand(ikm, ctx, 32),
   hash)` — the *expand step only* of RFC 5869 (§2.3), with `ikm` used
   directly as the PRK and `ctx` as `info`. No extract step.
3. **CAR index ordering pinned**: canonical DAG-CBOR map order (shortest key
   first, then bytewise) — not plain lexicographic; record blocks follow in
   index order.
4. **Endpoint changes**: `com.atproto.space.listBlobs` added (repo read/sync
   group, covered by `read`/`read_self`, used by migration);
   `com.atproto.space.unregisterNotify` added; `getSpace` **moved** from
   `com.atproto.space` into `com.atproto.simplespace` as a read query (OAuth
   `read_self` or space credential; `listMembers` likewise now takes
   `read_self`). `notifyWrite` now carries the repo's current `rev` + `hash`.
5. **Space deletion semantics reworked**: members' repo hosts are **not**
   notified and member data is **not** flagged/erased — a member's records are
   their own and simply become unreadable to everyone else.
   `notifySpaceDeleted` goes to registered syncers only, and the durable
   deletion signal is an explicit `SpaceDeleted` error from
   `getSpaceCredential` on renewal (any other renewal failure means nothing).
6. **Scope semantics**: `read_self` now **ignores `collection`** (it was
   collection-constrained in July); permission-set space entries now carry
   `manage` as well.
7. **`simplespace` config hardening**: `policy` and `appAccess` are open
   unions at the schema layer; a host MUST reject values it does not implement
   at `createSpace`/`updateSpace` time.
8. **Golden test vectors now exist** in `packages/space/tests/` — e.g. the
   empty-state digest is `sha256(2048 zero bytes)` =
   `e5a00aa9…36b183ad`, and `add("one"); add("two")` digests to
   `ae05cb6d…701c63e7` — plus full test suites for commits, credentials,
   DPoP, and sync. The July "no vectors" risk is resolved.

## 1. What the proposal specifies

A second data protocol beside public broadcast, for data with an access
perimeter (personal data, gated content, private posts, groups). **Access
control, not confidentiality** — explicitly *not* E2EE; hosts and authorized
apps read plaintext. Same abstract shape as public atproto (DID authority,
per-user repos, lexicon records, apps crawl PDSes), but a different repo
format, sync mechanism, addressing, and resolution path.

### Core concepts

- **Space** = authorization + sync boundary, identified by
  `(authority DID, spaceType NSID, skey)`. URI form:
  `at://{spaceDid}/space/{spaceType}/{skey}[/{authorDid}/{collection}/{rkey}]`
  (the literal `space` segment — no dots — disambiguates from a collection
  NSID, which always has ≥2 dots).
- **Permissioned repo** = one user's records within one space, hosted on that
  user's PDS. One repo per (user, space); users hold many.
- **Roles:** *repo host* (serves a user's permissioned repos) and *space host*
  (answers for the space: issues credentials, tracks writers, routes
  notifications). A PDS is both for accounts/spaces anchored on it.
- **Space authority DID** resolves via two optional DID-doc entries:
  verification method `#atproto_space` (falls back to `#atproto`) and service
  `#atproto_space_host` (falls back to `#atproto_pds`).
- **Space type declarations**: a new Lexicon shape, `"type": "space"`, with
  `key`, `name` (+ localized), `collections` (default collection set for
  scopes/consent).

### Repo format (no MST)

- Commit digest = **LtHash** homomorphic multiset hash: 2048-byte state read
  as 1024 little-endian u16 lanes; each element is the UTF-8 of
  `{collection}/{rkey}/{record_cid}` expanded to 2048 bytes via **BLAKE3 XOF**;
  add/remove = lane-wise add/subtract mod 2^16. Commit carries
  `hash = sha256(state)` (32 bytes), hosts keep the full state.
- **Deniable commit signature** — the asymmetric signature must not prove
  content. Context string
  `ctx = "atproto-space-v1" || u16be-len-prefixed(space URI, author DID, rev(TID), ikm)`
  (TLS 1.3 vector encoding). Per serving: fresh 32-byte `ikm`,
  `sig = sign(ctx)` with the user's signing key (ES256 or ES256K),
  `mac = HMAC-SHA256(HKDF-Expand(ikm, ctx, 32), hash)` (RFC 5869 §2.3 expand
  only — `ikm` is the PRK, `ctx` the `info`). A fresh `ikm`/`sig`/`mac`
  is produced **per reader served**. `signedCommit = {ver: 1, hash, ikm, sig,
  mac, rev}`. A leaked commit proves only that the user signed a
  `(space, author, rev, ikm)` context — anyone can forge a matching `mac` for
  any `hash`.
- **CAR serialization** with **two roots**: (1) the signed commit, (2) a DRISL
  (DAG-CBOR) index map `"{collection}/{rkey}" → CID` in canonical DAG-CBOR map
  order (shortest key first, then bytewise); record blocks follow in index
  order. Streams verifiably: check
  sig+mac → fold index into a running LtHash and compare to `hash` → verify
  each record block CID.

### Auth model (three token types + a new scope family)

- **Delegation token** — minted by the user's PDS
  (`com.atproto.space.getDelegationToken`, requires a `read` grant), JWT
  `typ: atproto-space-delegation+jwt`, `kid` MUST be `#atproto`, signed by the
  account signing key. `sub` = space URI, `aud` = `{spaceDid}#atproto_space_host`,
  single-use, ~60 s. No `lxm` (deliberately not interchangeable with service
  auth).
- **Client attestation** — only when a space gates on app identity. JWT
  `typ: atproto-client-attestation+jwt`, `iss`=`sub`=`client_id`, verified by
  resolving the client metadata JWKS. Structurally a `private_key_jwt`
  assertion aimed at the space host.
- **Space credential** — minted by the space authority
  (`com.atproto.space.getSpaceCredential`) in exchange for a delegation token
  + a DPoP proof (+ attestation if required). `typ:
  atproto-space-credential+jwt`, `kid` `#atproto_space` or `#atproto`,
  `iss` = authority DID, `sub` = space URI, **no `aud`**, ~2 h, multi-use
  across every repo host in the space. Verifiable offline against the
  authority's published key. **DPoP-bound**: carries `cnf.jkt` (thumbprint of
  the key from the mint-time proof) and is presented under the `DPoP` scheme
  with a fresh per-request proof (`ath` = hash of the credential) that every
  repo host MUST validate per RFC 9449 — never bearer. Syncers mint an
  ephemeral keypair per credential.
- **`space:` OAuth scope**:
  `space:<spaceType>[?authority=<did|self|*>][&skey=…][&collection=…][&action=…][&manage=…]`.
  Defaults: `authority=self`, `skey=*`, `action=read,create,update,delete`,
  `collection` = the space type declaration's `collections` (resolved
  dynamically, like permission sets). `read` is all-or-nothing per space
  (grants the read/sync methods **and** `getDelegationToken`); `read_self`
  covers only the holder's own repo, no delegation token; both `read` and
  `read_self` ignore `collection` (read is all-or-nothing at the space/repo
  boundary). `manage` verbs gate the management surface. Read/sync methods
  accept **either** a covering OAuth grant or a DPoP-bound space credential;
  writes accept OAuth only. Permission sets gain a `"resource": "space"` entry
  type carrying the same params incl. `manage` (no wildcard `spaceType` inside
  sets).
  Consent screens must render the declaration's `name` and the authority's
  bidirectionally-verified handle; wildcard authority+type demands a prominent
  warning.

### Sync (no relay, pull-based)

- **`listRepoOps`** — primary mechanism: per-repo **oplog** entries
  `{rev, collection, rkey, cid, prev}` since a `since` rev (cid null = delete,
  prev null = create, shared rev = atomic batch), record values inlined by
  default (`excludeValues` opt-out). A response reaching the head must include
  the current signed commit; the syncer compares against its own running
  LtHash. Oplog is a transport optimization — droppable/compactable, reset on
  migration.
- **Full-state recovery** — `getRepo` (two-root CAR) with streaming
  verification; or "healing" via `getLatestCommit` + `listRecords
  excludeValues` diff + selective `getRecord`.
- **Write notifications** — best-effort, no record data (just the repo's new
  `rev` + `hash`). `registerNotify` / `unregisterNotify`
  (space-credential-authed; on space host = whole space, on repo host = one
  repo; registrations expire); `notifyWrite` (service auth) from repo host →
  space host → fan-out to registered syncers. On first write into a *shared*
  space, the repo host **auto-registers** the authority's
  `#atproto_space_host` as a subscriber. Self-healing via the set hash;
  periodic sweep via `listRepos` (writer set with per-repo `rev` + `hash` —
  accounts that have written, never a member/reader list).
- **Space deletion** — authority stops answering, deletes its own repo,
  best-effort `notifySpaceDeleted` to registered syncers (who must delete
  their copies). Members' repo hosts are **not** notified and keep the
  member's own records — they simply become unreadable to everyone else. The
  durable signal for a syncer that missed the notification is an explicit
  `SpaceDeleted` error on credential renewal; any other renewal failure says
  nothing about the space.

### Required PDS management: `com.atproto.simplespace`

Every PDS MUST implement it (spaces anchored on the user's own DID):
`createSpace` / `updateSpace` / `deleteSpace` / `getSpace` / `addMember` /
`removeMember` / `listMembers`, config `{policy: public | member-list |
managing-app, appAccess: #open | #allowList, managingApp}`. `policy` and
`appAccess` are open unions — a host MUST reject values it does not implement
at `createSpace`/`updateSpace` time. The management procedures need the
relevant `manage` grant; the read queries need only read access (`getSpace`:
OAuth `read_self` or a space credential; `listMembers`: `read_self`).
`managing-app` policy defers the per-user authorization decision at
credential-mint time to the app via `com.atproto.simplespace.checkUserAccess`
(served by the managing app, service-auth from the authority). Other
space-management implementations are first-class but live on bespoke space
services, not the PDS.

### XRPC surface (all `com.atproto.space.*` unless noted)

| Group | Methods |
|---|---|
| Host | `getSpaceCredential` (delegation token + DPoP), `listRepos` |
| Repo (read/sync) | `getRecord`, `listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`, `listRepoOps` |
| PDS | `getDelegationToken`, `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `listSpaces` |
| Notifications | `registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted` |
| `com.atproto.simplespace.*` | `createSpace`, `updateSpace`, `deleteSpace`, `getSpace`, `addMember`, `removeMember`, `listMembers`, `checkUserAccess` (served by managing app) |

The alpha lexicons pin this at **20 `com.atproto.space.*` + 9
`com.atproto.simplespace.*` schema files** (incl. `defs`); Custos serves
~26 of them as routes (`checkUserAccess` is outbound-only for us, `defs` are
not endpoints) — each needing a `.bru` file under the bruno-parity gate.

### Lifecycle interactions

Migration must enumerate **all** of an account's permissioned repos (via
`listSpaces`) + blobs (via `listBlobs`). Deactivation/deletion/takedown
propagate exactly as for public data. Syncers of permissioned-only data still
need firehose `#account`/`#identity` events.

## 2. What Custos already has (reuse inventory)

Survey result: **no existing private-data, ACL, group, or E2EE machinery
anywhere** — this is a greenfield feature. But the proposal was clearly shaped
to reuse standard PDS plumbing, and Custos has strong versions of most of it:

| Proposal need | Existing Custos primitive |
|---|---|
| Delegation-token minting (account-key JWT, `kid #atproto`) | PDS-held per-account P-256 repo keys (ADR-0004; `db/repo_keys.rs`, `repo-engine::CommitSigner`) + `jwt.rs::mint_service_auth_jwt` as the template |
| Space-credential / attestation verification | `jwt.rs::verify_service_auth_jwt` (ES256+ES256K verify, curve-bound, low-S), `crypto::verify_did_key_signature` |
| Service auth for `notifyWrite`/`checkUserAccess` | `auth/service_auth.rs` (`require_service_auth(lxm)`) — already inbound+outbound |
| `space:` scope grammar | `auth/oauth_scopes.rs` — proposal-0011 engine (positional + query params, wildcard matching, `normalize`/`intersect`/`require_*` gates) is exactly the right chassis to extend |
| Space-type declaration resolution (consent names, default collections) | `auth/permission_sets.rs` — NSID→lexicon-record resolution with TTL cache and the SSRF-hardened client (`ssrf-client-check` gate applies) |
| Record plumbing (TIDs, rkey/NSID validation, JSON↔DAG-CBOR, blob-ref walking, monotonic revs) | `repo-engine::records` (`generate_tid`, `next_commit_rev`, `validate_record_path`, `json_to_record_value`, `record_blob_cids`) |
| CAR framing | `repo-engine::car_export` (`car_v1_header`, `car_v1_block_frame`, streaming) |
| DPoP binding of space credentials (`cnf.jkt`, per-request proofs, `ath`/`htm`/`htu`/`jti` checks) | Full RFC 9449 stack already live for OAuth: `auth/dpop.rs` (proof validation + nonce store) and the scheme↔`cnf.jkt` binding enforced in `auth/extractors.rs::authenticate_access` |
| Single-use `jti` replay protection | DPoP nonce-store pattern (`auth/dpop.rs`) |
| Background fan-out workers | `crawler.rs` / `firehose_gc.rs` / sweep patterns |
| Ownership/lifecycle modeling | `accounts` lifecycle states, `blob_owners`/`block_owners` per-account ownership rows |
| DID-doc handling for new `#atproto_space*` entries | `identity/` + did:web hosting + `getRecommendedDidCredentials` |
| Migration/import flows | `car_import.rs`, transfer surface (`/v1/transfer/*`) |

Notably, the deniable-signature design fits Custos *better* than
wallet-signing PDSes: commits are (re-)signed per reader on the serving path,
which requires the signing key server-side — exactly Custos's ADR-0004 model.
Custos is P-256-only for signing, which the spec permits (ES256); k256 stays
verify-only for foreign authorities' ES256K credentials.

What does **not** change: the public repo engine (MST), firehose, relay
crawling, and existing sync endpoints are untouched. Permissioned data never
rides `subscribeRepos`.

## 3. Gap analysis — the work, by layer

### W1. Crypto primitives (new, small — vectors published, start here)
- LtHash: 2048-byte state, BLAKE3-XOF expansion (dkLen = 2048), u16-LE lane
  add/sub mod 2^16 (~80 lines). New dep: `blake3`; `hmac`/`hkdf`/`sha2` as
  needed. Element format `{collection}/{rkey}/{cid}`.
- `ctx` TLS-vector encoding; commit sign (`sign(ctx)`) + MAC
  (`HMAC-SHA256(HKDF-Expand(ikm, ctx, 32), hash)` — expand only, `ikm` as
  PRK) + verify path.
- Home: `crates/crypto` (pure, no deps on repo-engine) or a sibling module in
  `repo-engine`; Functional Core either way. Pin the reference golden vectors
  from `packages/space/tests/` (empty digest `e5a00aa9…`, `one`+`two` digest
  `ae05cb6d…`, plus commit/DPoP/credential suites) alongside round-trip +
  property tests (order-independence, add/remove inverse, empty-state zero).

### W2. Permissioned repo store (new storage engine — the big one)
- No MST, so this is a DB-backed record store + incremental LtHash state +
  oplog, not an atrium extension. New tables (V048+): `spaces` (authority,
  type, skey, config, policy, lifecycle), `space_repos` (account × space, rev,
  2048-byte LtHash state, commit fields), `space_records` (path → CID + DAG-CBOR
  value), `space_repo_ops` (oplog: rev, collection, rkey, cid, prev; compaction
  window like `firehose_gc`), `space_members` (simplespace member list),
  `space_notify_registrations`, plus a `jti` replay table.
- Two-root CAR serializer/parser (signed commit + DRISL index in canonical
  DAG-CBOR map order + blocks in index order) for `getRepo` and migration
  import.
- A `space_record_write.rs` analog of `record_write.rs`: single write choke
  point doing validate → CAS rev → update LtHash → append oplog → blob ref
  accounting → notification dispatch.
- Blob linkage: blobs upload via existing `uploadBlob` to the author's PDS and
  get associated on reference (per dholms), so `blob_owners` needs a space
  dimension (or a `space_blob_refs` table) and GC must union public + space
  references before deleting a physical blob.

### W3. Auth extensions
- `space:` resource type in `oauth_scopes.rs`: parse/normalize/match/intersect
  (agent scope clamping must handle it), `require_space(read|read_self|create|…)`
  gates, `manage` verbs. Mirror the existing grammar's test discipline.
- Dynamic `collection` default = space-type declaration's `collections` —
  reuse the permission-set resolution path (same dynamic-update semantics).
- Permission sets: accept `"resource": "space"` entries; enforce no-wildcard
  `spaceType` inside sets + namespace-authority rules.
- Token issuance/verification: delegation tokens (mint, single-use, 60 s),
  space credentials (mint as authority — copying the mint-time DPoP proof's
  key thumbprint into `cnf.jkt`; verify as repo host against
  `#atproto_space`→`#atproto` fallback **plus** full RFC 9449 proof validation
  incl. `ath` and per-host `jti` replay tracking), client attestations
  (resolve client metadata JWKS — SSRF-hardened client mandatory). As a
  *syncer/client* (e.g. tooling), mint an ephemeral P-256 keypair per
  credential.
- **New auth seam.** Read/sync methods accept OAuth *or* a DPoP-bound space
  credential — both proof-of-possession, never bearer. That dual acceptance
  must be one function (e.g. `auth::space::authenticate_space_read`) with a
  `just`-gate in the spirit of `auth-seam-check`, so no route grows its own
  credential parsing. It composes directly with the existing DPoP validator
  in `auth/dpop.rs` and mirrors the scheme↔`cnf.jkt` binding
  `authenticate_access` already enforces for OAuth.
- Consent screen: render space-type `name`, authority handle
  (bidirectionally verified), wildcard warnings, in the `/oauth/authorize`
  templates.

### W4. XRPC surface (~26 routes)
One file per route per the route-isolation rule; queries in `db/`, auth in
`auth/`; register in `app.rs`; one `.bru` each (bruno-parity). Groups: PDS
CRUD + `listSpaces` + `getDelegationToken`; repo read/sync (`getRecord`,
`listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`,
`listRepoOps`); host (`getSpaceCredential`, `listRepos`); notifications
(`registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted`);
simplespace management incl. `getSpace`. `checkUserAccess` is *outbound* from
Custos-as-authority (inbound only if we ever ship a managing app). The alpha
lexicons (`lexicons/com/atproto/{space,simplespace}/` on the
`permissioned-data` branch) are the schema source of truth to codegen or
hand-mirror.

### W5. Space-host role
Credential issuance policy engine (`public` / `member-list` / `managing-app` ×
`appAccess` `#open`/`#allowList`, rejecting unimplemented open-union values at
create/update), DPoP-binding at mint time, writer-set tracking (fed by
notifications + own writes), notification fan-out worker with retries and
registration expiry (`registerNotify`/`unregisterNotify`), auto-registration
of the authority on first write into a shared space, space deletion flow
(stop issuing, delete own repo, notify registered syncers, answer renewals
with `SpaceDeleted`; members' data stays put and simply becomes unreadable to
others).

### W6. Identity
Emit/accept `#atproto_space` + `#atproto_space_host` in DID docs (PLC ops via
the wallet-signed rotation surface; did:web hosting), resolution with
fallbacks, and surface them in `getRecommendedDidCredentials`.

### W7. Lifecycle & migration
Deactivation/suspension/takedown checks on every space read/write path;
account deletion cascades; migration enumeration of all (space, repo, blobs)
— extends the `/v1/transfer/*` flows and `importRepo`; oplog reset semantics
on migration.

Two corrections from building it. **`/v1/transfer/*` is not the migration
surface** — those routes are the planned *device* swap and move no repo data;
the flows migration actually extends are `checkAccountStatus`, `importRepo`,
and the account activate/deactivate pair. And **the alpha lexicons define no
space import endpoint** (the 20 `com.atproto.space.*` schema files are
export-only on the repo-read side), so a destination host has to offer its own;
Custos serves `POST /v1/space/import-repo` on its `/v1/*` surface rather than
squatting a namespace the spec may yet fill differently. Oplog reset needed no
code: the new host's oplog simply starts empty, and a syncer reconnecting with
a `since` from the old host folds to a set hash the new head does not match —
already the signal to heal with a full `getRepo`.

### W8. Ops, tooling, product surface (follow-on)
Rate limiting keyed by space credential; metrics; admin-companion moderation
surface for hosted spaces (takedown/refuse-to-serve); Bruno collection;
interop CLI scenarios against the reference alpha; MCP tools
(`tools/mcp`) for agent access to spaces; identity-wallet consent UX for
`space:` scopes; NixOS/Railway config for any new env vars.

## 4. Suggested phasing

1. **Phase 0 — primitives (started with the alpha, vector-pinned):** W1
   crypto + `space:` scope grammar (parse/normalize/display only). Pure,
   testable against the published golden vectors, and the part of the spec
   least likely to move.
2. **Phase 1 — personal spaces (authority = self):** W2 store + PDS CRUD/read
   routes + delegation token + DPoP-bound credential mint where PDS is both
   roles + simplespace with `member-list`/`public` + consent UI. Delivers the
   bookmarks/drafts/private-posts modality end-to-end on a single PDS. Gate
   behind a config flag (e.g. `EZPDS_SPACES_ENABLED`) until the protocol
   launches (target "later this year").
3. **Phase 2 — shared spaces & sync:** oplog + `listRepoOps`, two-root CAR
   `getRepo`, notifications + auto-registration + expiry, writer set, space
   deletion. Validate against the alpha: the hosted sandbox PDS, the
   alpha-tagged TS SDK as a client against Custos, and the bulletin sample
   app. Track the Thursday release notes on atmosphere.community and re-diff
   the proposal each time before building the next slice.
4. **Phase 3 — ecosystem hardening:** client attestation + `#allowList`,
   `managing-app` policy, migration enumeration, moderation/admin surface,
   tooling (interop, MCP, wallet UX).

## 5. Risks & open questions

- **Spec churn** is still real but has changed character: the proposal is now
  tracked against a running reference implementation with weekly (Thursday)
  alpha releases and an explicit breaking-changes warning until launch
  ("later this year"). The August deltas (§0) show the kind of movement to
  expect — auth hardening and endpoint reshuffles, not architectural rewrites.
  Mitigation: re-diff the proposals repo before each implementation slice, and
  interop-test against the hosted alpha PDS + TS SDK continuously.
- ~~No published test vectors~~ **Resolved**: golden vectors and full test
  suites ship in `packages/space/tests/` on the `permissioned-data` branch.
- **Per-reader commit signing** puts a KEK-decrypt + ECDSA sign on the serving
  path of every sync response; needs a benchmark and possibly an in-memory
  decrypted-key cache with zeroization.
- **Single-connection SQLite pool**: oplog append + LtHash update + record
  write per space write is fine transactionally, but heavy shared-space sync
  traffic may motivate the deferred per-user-DB split the DB layer was
  designed to allow.
- **Replay stores** (delegation `jti`, attestation `jti`, and now per-host
  DPoP-proof `jti` on every credential-authed sync request) need TTL sweeps;
  the sync-path store sees the highest volume and should be sized/swept
  accordingly.
- **Agent interaction**: `intersect_scope_tokens` clamping for `space:` scopes
  must be exactly right — an agent must never widen into a space its parent
  grant doesn't cover; sovereign-child accounts (ADR-0023) participate in
  spaces as ordinary DIDs, which composes cleanly but needs tests.
- **Scale posture**: dholms expects permissioned data to exceed public data by
  ≥10×. Custos is a small-fleet PDS, so this is not an immediate constraint,
  but oplog retention and notification fan-out should be bounded from day one.
- **What Custos deliberately need not build:** relays (none exist for
  permissioned data), a managing app, or bespoke space services — only the
  PDS-required surface (`simplespace`) plus repo-host/space-host roles.

## 6. Rough size

Comparable to Wave 2 (Auth) + Wave 4 (Repo/Blobs) combined: a new storage
engine, ~26 routes, a scope-grammar extension, three token types (all
DPoP-bound or single-use), and a notification subsystem — plus ~26 `.bru`
files, ~6–8 migrations, and CI-gate updates (`auth-seam-check` extension,
bruno parity). Phase 0 alone is small (days); Phases 1–2 are a multi-wave
milestone on the order of the original v0.1 auth+repo build-out.

## 7. Issue breakdown (Wave 10)

Implementation tracking: Linear team `MM`, project `ezpds`, label **`Wave 10:
Spaces`** (Wave 9 is taken by Obsign Anywhere; spaces is a new post-v0.1
workstream, distinct from the milestone map's v0.2 desktop enrollment). Filed
2026-08-20. Phases are strict dependency order; issues within a phase can
proceed in parallel (blocking relations are wired in Linear).

| Issue | Phase | Scope |
|---|---|---|
| MM-506 | 0 | Spaces crypto primitives: LtHash (BLAKE3-XOF, 1024×u16 lanes) + deniable commit `ctx`/sign/MAC/verify in `crates/crypto`, pinned to the reference golden vectors |
| MM-507 | 0 | `space:` OAuth scope grammar in `auth/oauth_scopes.rs`: parse/normalize/match/`intersect_scope_tokens` + `require_space` gates (no routes yet); permission-set `resource: "space"` entries |
| MM-508 | 1 | Permissioned repo store: migrations (`spaces`, `space_repos` incl. LtHash state, `space_records`, `space_repo_ops`, `space_members`, notify registrations, `jti` replay) + `space_record_write` choke point |
| MM-509 | 1 | PDS record routes: `com.atproto.space.{createRecord,putRecord,deleteRecord,applyWrites,listSpaces,getRecord,listRecords,getLatestCommit}` + `.bru` files (blocked by MM-506/507/508) |
| MM-510 | 1 | Space auth: delegation-token mint, DPoP-bound space-credential mint/verify (`cnf.jkt`, per-request RFC 9449 proofs), `auth::space::authenticate_space_read` seam + `just` seam gate (blocked by MM-507) |
| MM-511 | 1 | `com.atproto.simplespace` management surface: `createSpace`/`updateSpace`/`deleteSpace`/`getSpace`/`addMember`/`removeMember`/`listMembers`; `member-list` + `public` policies; open-union rejection (blocked by MM-508) |
| MM-512 | 1 | Consent UI for `space:` scopes in `/oauth/authorize`: space-type declaration resolution (name, default collections), authority handle display, wildcard warnings (blocked by MM-507) |
| MM-513 | 2 | Sync surface: `listRepoOps` oplog (+compaction), two-root CAR `getRepo` (canonical DAG-CBOR index order), `listBlobs`, space blob refs + GC union (blocked by MM-509/510) |
| MM-514 | 2 | Space-host role: writer set, `registerNotify`/`unregisterNotify` (+expiry), `notifyWrite` fan-out worker, authority auto-registration, space deletion + `SpaceDeleted` renewal error (blocked by MM-510/511) |
| MM-515 | 2 | Identity: `#atproto_space` / `#atproto_space_host` DID-doc entries (PLC + did:web) with fallbacks; `getRecommendedDidCredentials` |
| MM-516 | 3 | Client attestation verification + `appAccess` `#allowList`; `managing-app` policy with outbound `checkUserAccess` (blocked by MM-510/511) |
| MM-517 | 3 | Lifecycle & migration: `/v1/transfer/*` enumeration via `listSpaces`/`listBlobs`, deactivation/takedown propagation on space paths, spaces `importRepo` (blocked by MM-513) |
| MM-518 | 3 | Tooling & interop: Bruno collection, interop CLI scenarios vs the alpha (hosted sandbox PDS + TS SDK as client), MCP tool surface, browser-harness coverage (blocked by MM-509) |

A weekly routine watches the alpha's Thursday releases and PRs spec-delta
updates to this doc — see
[`docs/operations/spaces-alpha-watch-routine.md`](../operations/spaces-alpha-watch-routine.md).
