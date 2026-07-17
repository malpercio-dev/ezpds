# Permissioned Data (atproto proposal 0016) — Custos Gap Analysis

**Date:** 2026-07-17
**Status:** Research / gap analysis — no implementation decision yet
**Sources:**
- [0016 Permissioned Data proposal](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) (canonical, published 2026-07-02)
- [Permissioned Data Diary 7: Off the Record](https://dholms.leaflet.pub/3mqtqvjidqs2p) (2026-07-17 — repo structure, signing, sync rationale)
- Earlier diaries: [Diary 2: Buckets](https://dholms.leaflet.pub/3mfrsbcn2gk2a), [Diary 4: The Big Picture](https://dholms.leaflet.pub/3mhj6bcqats2o)
- [Community forum discussion](https://discourse.atprotocol.community/t/permissioned-data-proposal-discussion/946)
- Reference implementation in progress: bluesky-social/atproto PR #5187 (lexicons + WIP impl)

> **Spec stability warning.** The proposal says details/terminology/behaviors are
> likely to change. Since the first draft the member list was removed from the
> protocol, and the URI scheme (`at://` with a `space` segment vs. a dedicated
> scheme) is "still undecided" per Diary 7. dholms plans an alpha
> protocol + PDS "in the next couple weeks" (as of 2026-07-17) and an IETF
> working-group meeting on July 23. Anything we build now must expect churn.

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
  `mac = HMAC-SHA256(HKDF-SHA256(ikm, ctx), hash)`. A fresh `ikm`/`sig`/`mac`
  is produced **per reader served**. `signedCommit = {ver: 1, hash, ikm, sig,
  mac, rev}`. A leaked commit proves only that the user signed a
  `(space, author, rev, ikm)` context — anyone can forge a matching `mac` for
  any `hash`.
- **CAR serialization** with **two roots**: (1) the signed commit, (2) a DRISL
  (DAG-CBOR) index map `"{collection}/{rkey}" → CID` in lexicographic order;
  record blocks follow in the same order. Streams verifiably: check
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
  (+ attestation if required). `typ: atproto-space-credential+jwt`,
  `kid` `#atproto_space` or `#atproto`, `iss` = authority DID, `sub` = space
  URI, **no `aud`**, ~2 h, multi-use across every repo host in the space.
  Verifiable offline against the authority's published key.
- **`space:` OAuth scope**:
  `space:<spaceType>[?authority=<did|self|*>][&skey=…][&collection=…][&action=…][&manage=…]`.
  Defaults: `authority=self`, `skey=*`, `action=read,create,update,delete`,
  `collection` = the space type declaration's `collections` (resolved
  dynamically, like permission sets). `read` is all-or-nothing per space
  (grants the read/sync methods **and** `getDelegationToken`); `read_self`
  covers only the holder's own repo, no delegation token. `manage` verbs gate
  the management surface. Read/sync methods accept **either** a covering OAuth
  grant or a space credential; writes accept OAuth only. Permission sets gain
  a `"resource": "space"` entry type (no wildcard `spaceType` inside sets).
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
- **Write notifications** — best-effort, no record data.
  `registerNotify` (space-credential-authed; on space host = whole space, on
  repo host = one repo); `notifyWrite` (service auth) from repo host → space
  host → fan-out to registered syncers. On first write into a *shared* space,
  the repo host **auto-registers** the authority's `#atproto_space_host` as a
  subscriber. Self-healing via the set hash; periodic sweep via `listRepos`
  (writer set with per-repo `rev` + `hash` — accounts that have written, never
  a member/reader list).
- **Space deletion** — authority stops answering, deletes its own repo,
  best-effort `notifySpaceDeleted`; syncers must delete copies, repo hosts
  flag-don't-delete members' own data.

### Required PDS management: `com.atproto.simplespace`

Every PDS MUST implement it (spaces anchored on the user's own DID):
`createSpace` / `updateSpace` / `deleteSpace` / `addMember` / `removeMember` /
`listMembers`, config `{policy: public | member-list | managing-app, appAccess:
#open | #allowList, managingApp}`. `managing-app` policy defers the per-user
authorization decision at credential-mint time to the app via
`com.atproto.simplespace.checkUserAccess` (served by the managing app,
service-auth from the authority). Other space-management implementations are
first-class but live on bespoke space services, not the PDS.

### XRPC surface (all `com.atproto.space.*` unless noted)

| Group | Methods |
|---|---|
| Host | `getSpace`, `getSpaceCredential`, `listRepos` |
| Repo (read/sync) | `getRecord`, `listRecords`, `getBlob`, `getLatestCommit`, `getRepo`, `listRepoOps` |
| PDS | `getDelegationToken`, `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `listSpaces` |
| Notifications | `registerNotify`, `notifyWrite`, `notifySpaceDeleted` |
| `com.atproto.simplespace.*` | `createSpace`, `updateSpace`, `deleteSpace`, `addMember`, `removeMember`, `listMembers`, `checkUserAccess` (served by managing app) |

≈ 18 space methods on the PDS + 6 simplespace methods ⇒ **~24 new routes**
(each needing a `.bru` file under the bruno-parity gate).

### Lifecycle interactions

Migration must enumerate **all** of an account's permissioned repos + blobs.
Deactivation/deletion/takedown propagate exactly as for public data. Syncers
of permissioned-only data still need firehose `#account`/`#identity` events.

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

### W1. Crypto primitives (new, small, spec-frozen enough to start)
- LtHash: 2048-byte state, BLAKE3-XOF expansion, u16-LE lane add/sub mod 2^16
  (~80 lines per Diary 7). New dep: `blake3`; `hmac`/`hkdf`/`sha2` as needed.
- `ctx` TLS-vector encoding; commit sign (`sign(ctx)`) + MAC
  (`HMAC(HKDF(ikm, ctx), hash)`) + verify path.
- Home: `crates/crypto` (pure, no deps on repo-engine) or a sibling module in
  `repo-engine`; Functional Core either way. Test against reference vectors as
  soon as the alpha/PR #5187 publishes them — until then, round-trip +
  property tests (order-independence, add/remove inverse, empty-state zero).

### W2. Permissioned repo store (new storage engine — the big one)
- No MST, so this is a DB-backed record store + incremental LtHash state +
  oplog, not an atrium extension. New tables (V048+): `spaces` (authority,
  type, skey, config, policy, lifecycle), `space_repos` (account × space, rev,
  2048-byte LtHash state, commit fields), `space_records` (path → CID + DAG-CBOR
  value), `space_repo_ops` (oplog: rev, collection, rkey, cid, prev; compaction
  window like `firehose_gc`), `space_members` (simplespace member list),
  `space_notify_registrations`, plus a `jti` replay table.
- Two-root CAR serializer/parser (signed commit + DRISL index + ordered
  blocks) for `getRepo` and migration import.
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
  space credentials (mint as authority; verify as repo host against
  `#atproto_space`→`#atproto` fallback), client attestations (resolve client
  metadata JWKS — SSRF-hardened client mandatory).
- **New auth seam.** Read/sync methods accept OAuth *or* space credential.
  That dual acceptance must be one function (e.g.
  `auth::space::authenticate_space_read`) with a `just`-gate in the spirit of
  `auth-seam-check`, so no route grows its own credential parsing.
- Consent screen: render space-type `name`, authority handle
  (bidirectionally verified), wildcard warnings, in the `/oauth/authorize`
  templates.

### W4. XRPC surface (~24 routes)
One file per route per the route-isolation rule; queries in `db/`, auth in
`auth/`; register in `app.rs`; one `.bru` each (bruno-parity). Groups: PDS
CRUD + `listSpaces` + `getDelegationToken`; repo read/sync (`getRecord`,
`listRecords`, `getBlob`, `getLatestCommit`, `getRepo`, `listRepoOps`); host
(`getSpace`, `getSpaceCredential`, `listRepos`); notifications
(`registerNotify`, `notifyWrite`, `notifySpaceDeleted`); simplespace
management. `checkUserAccess` is *outbound* from Custos-as-authority
(inbound only if we ever ship a managing app).

### W5. Space-host role
Credential issuance policy engine (`public` / `member-list` / `managing-app` ×
`appAccess` `#open`/`#allowList`), writer-set tracking (fed by notifications +
own writes), notification fan-out worker with retries, auto-registration of
the authority on first write into a shared space, space deletion flow
(stop issuing, delete own repo, notify, flag members' repos).

### W6. Identity
Emit/accept `#atproto_space` + `#atproto_space_host` in DID docs (PLC ops via
the wallet-signed rotation surface; did:web hosting), resolution with
fallbacks, and surface them in `getRecommendedDidCredentials`.

### W7. Lifecycle & migration
Deactivation/suspension/takedown checks on every space read/write path;
account deletion cascades; migration enumeration of all (space, repo, blobs)
— extends the `/v1/transfer/*` flows and `importRepo`; oplog reset semantics
on migration.

### W8. Ops, tooling, product surface (follow-on)
Rate limiting keyed by space credential; metrics; admin-companion moderation
surface for hosted spaces (takedown/refuse-to-serve); Bruno collection;
interop CLI scenarios against the reference alpha; MCP tools
(`tools/mcp`) for agent access to spaces; identity-wallet consent UX for
`space:` scopes; NixOS/Railway config for any new env vars.

## 4. Suggested phasing

1. **Phase 0 — primitives (can start now, churn-safe):** W1 crypto + `space:`
   scope grammar (parse/normalize/display only). Pure, testable, and the part
   of the spec least likely to move (LtHash/deniable-commit rationale is
   settled per Diary 7).
2. **Phase 1 — personal spaces (authority = self):** W2 store + PDS CRUD/read
   routes + delegation token + credential mint where PDS is both roles +
   simplespace with `member-list`/`public` + consent UI. Delivers the
   bookmarks/drafts/private-posts modality end-to-end on a single PDS. Gate
   behind a config flag (e.g. `EZPDS_SPACES_ENABLED`) until the spec is
   official.
3. **Phase 2 — shared spaces & sync:** oplog + `listRepoOps`, two-root CAR
   `getRepo`, notifications + auto-registration, writer set, space deletion.
   Validate against dholms' alpha PDS + at least one ecosystem syncer.
4. **Phase 3 — ecosystem hardening:** client attestation + `#allowList`,
   `managing-app` policy, migration enumeration, moderation/admin surface,
   tooling (interop, MCP, wallet UX).

## 5. Risks & open questions

- **Spec churn** is the dominant risk: member list already removed, URI scheme
  "still undecided", further updates promised before an official spec, IETF
  WG just starting. Phase 0 is safe; Phases 1+ should track PR #5187 and the
  alpha implementation, and interop-test early.
- **No published test vectors yet** for LtHash folding, `ctx` encoding, or the
  MAC chain — interop drift risk until the alpha lands.
- **Per-reader commit signing** puts a KEK-decrypt + ECDSA sign on the serving
  path of every sync response; needs a benchmark and possibly an in-memory
  decrypted-key cache with zeroization.
- **Single-connection SQLite pool**: oplog append + LtHash update + record
  write per space write is fine transactionally, but heavy shared-space sync
  traffic may motivate the deferred per-user-DB split the DB layer was
  designed to allow.
- **Replay stores** (delegation `jti`, attestation `jti`, DPoP-style) need TTL
  sweeps.
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
engine, ~24 routes, a scope-grammar extension, three token types, and a
notification subsystem — plus ~24 `.bru` files, ~6–8 migrations, and CI-gate
updates (`auth-seam-check` extension, bruno parity). Phase 0 alone is small
(days); Phases 1–2 are a multi-wave milestone on the order of the original
v0.1 auth+repo build-out.
