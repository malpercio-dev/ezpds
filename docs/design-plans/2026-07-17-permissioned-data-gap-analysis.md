# Atproto Spaces (proposal 0016, née Permissioned Data) — Custos Gap Analysis

**Date:** 2026-07-17 · **Revised:** 2026-08-20 (official alpha release) · 2026-09-04, 2026-10-09 (weekly watch)
**Status:** Research / gap analysis — updated for the alpha; implementation green-lit for Phase 0
**Sources:**
- [0016 proposal](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) (canonical; kept in sync with the reference implementation as of the alpha; last diffed against commit `0c9c2e8`)
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

1. **Space credentials are key-bound, not bearer** (the big one; *the DPoP mechanism described here was replaced by HTTP Message Signatures on 2026-10-01 — see the 2026-10-09 entry*). A
   credential carries `cnf.jkt`; `getSpaceCredential` requires a DPoP proof
   (no `ath` on that proof — the delegation token is a grant, not an access
   token; the delegation token itself rides `Authorization: Bearer`,
   alongside the `DPoP:` proof header, on that request) and every
   credential-authed request to a repo host presents
   `Authorization: DPoP <credential>` plus a per-request proof that hosts MUST
   validate per RFC 9449 (`typ`/`alg` header fields, signature vs. header
   `jwk`, thumbprint vs. `cnf.jkt`, `ath` = hash of the credential, `htm`/`htu`
   — `htu` is the plain request URL, no `lxm` claim — `iat` recency, `jti`
   unseen; no DPoP server-provided nonces anywhere in the flow). Rationale: a
   bearer credential would let any repo host replay it against every other
   host in the space. Syncers should mint a fresh keypair per credential and
   discard it on expiry.
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

### 2026-09-04 weekly watch (proposals repo, commits `54c9cf5`…`35a2d37`)

Prose-clarification pass, no lexicon/endpoint/vector movement (re-verified
against `permissioned-data` @ `7cefacc`: same 20 `com.atproto.space.*` + 9
`com.atproto.simplespace.*` schema files, same golden LtHash digests). Four
deltas worth folding in:

1. **DID-doc entries error on malformed data instead of falling back.** If
   `#atproto_space` is present but malformed/invalid, a host MUST return an
   error rather than silently falling back to `#atproto`; same for
   `#atproto_space_host` vs. `#atproto_pds`. Fallback is only for an *absent*
   entry, not a broken one. The `#atproto_space_host` service entry also now
   has a pinned type, `AtprotoSpaceHost`.
2. **`collections` in a space type declaration may not be a wildcard `*`**
   (the `name` field's old 1–64 length cap was also dropped — cosmetic).
   Doesn't change Custos's plan: the doc already modeled `collection`
   resolution as dynamic, like permission sets.
3. **Client attestation is now explicitly optional in the base protocol**
   text, not just inferable from "some spaces don't require one" — no change
   to Custos's plan, which already treated it as conditional.
4. **`getSpaceCredential` wire format spelled out for the first time**: the
   delegation token travels as `Authorization: Bearer <delegation token>`
   alongside a `DPoP: <proof>` header (the proof still carries no `ath` — the
   delegation token is a grant, not an access token); the proof's `htu` is
   the plain request URL (scheme + host + path, no query/fragment) rather
   than an `lxm` claim; DPoP server-provided nonces are **not** used anywhere
   in the flow; and host-side proof validation must additionally check the
   proof's `typ` (`dpop+jwt`) and `alg` header fields alongside the checklist
   already in item 1 above. This affects the wire contract MM-510 mints
   against and the space-credential row in the auth-model table below.

### 2026-10-09 weekly watch (proposals repo, commits `35a2d37`…`0c9c2e8`)

Material changes (six proposal commits, 2026-09-10…2026-10-01). The reference
implementation agrees: `permissioned-data` @ `5b95b2f` (2026-10-01) now has
21 `com.atproto.space.*` + 9 `com.atproto.simplespace.*` schema files, and
`packages/space/` swaps DPoP for a new `http-signature.ts`. Item 1
**supersedes** the DPoP wording in the August deltas above (item 1 and the
2026-09-04 item 4) and the ~2 h lifetime; item 4 supersedes the per-repo
`registerNotify`/auto-registration wording in the August entries. Where they
disagree this entry wins.

1. **DPoP replaced by HTTP Message Signatures (RFC 9421) + `cnf.kid`**
   (the big one; #113). The credential is no longer bound by a DPoP thumbprint
   (`cnf.jkt`) but by `cnf.kid` (RFC 7800 §3.4) — a P-256 `did:key`. To mint,
   the app signs the `Authorization` header (the delegation token) with a
   fresh keypair: `Signature-Input: atproto-space=("authorization");keyid="did:key:zDna…"`
   and `Signature: atproto-space=:…:`. The covered components MUST be exactly
   `("authorization")`; the space host validates it, requires `keyid` to be a
   P-256 `did:key`, and copies it into `cnf.kid`; `alg`, if present, MUST be
   `ecdsa-p256-sha256`. To use a credential, the app sends
   `Authorization: Atproto-Space <credential>` (new scheme — not `DPoP`) plus
   `Atproto-Space-Audience: <DID>` (the repo owner when syncing a repo; the
   authority DID when calling the space host) and a signature over exactly
   `("authorization" "atproto-space-audience")`, in that order, verified
   against `cnf.kid`. Signature value is raw 64-octet `r||s` (as for atproto
   commits) but **low-S is not required** — verifiers MUST accept both. The
   signature binds neither method nor URI and may be replayed against the same
   audience until the credential expires: **no `htm`/`htu`/`iat`/`jti`/`ath`
   proof checks and no per-request replay store**. The cross-host replay
   defence is unchanged in spirit (the audience header is signed). Syncers
   still mint a fresh keypair per credential.
2. **Credential lifetime cut**: default **10 minutes, max 60** (was ~2 h).
   `jti` is now explicitly the revocation handle.
3. **Revocation added** (#109): new `com.atproto.space.notifyCredentialRevoked`
   (repo host, procedure, service auth from the space authority) carrying one
   or more `jti`s. Authority MAY fan it out to repo hosts; a repo host MUST
   reject revoked `jti`s for that space and retain the revocation ≥ 60 min,
   idempotently. Short expiry stays the primary mechanism; fan-out is the
   authority's call (costlier for large spaces).
4. **Sync/notification topology reworked** (#116). Repo hosts notify the
   **space host** automatically via service-authed `notifyWrite` (unless the
   authority is the repo account itself); there is **no per-repo
   `registerNotify` and no auto-registration step**. `registerNotify` /
   `unregisterNotify` are space-host-only (space-credential-authed;
   registrations carry an expiry in the response body). The space host keeps a
   per-repo state table, sequences updates with its own **space-level
   revision (TID)**, and forwards notifications carrying the current and
   previous space rev, so syncers detect gaps and catch up via `listRepos`
   `since` a space rev. The host should reject notifications from repos not
   authorized to write, and the authority may exclude or rate-limit writers.
   Repo hosts retry network failures and transient statuses, stop on permanent
   errors; the host need not verify the repo `hash`.
5. **`simplespace` write access** (#105): `addMember` → **`putMember`**
   (add or update; each member entry carries required `read` and `write`
   booleans, replaced together); `policy` split into **`readPolicy`** and
   **`writePolicy`** (same variants, default `member-list`; open unions still);
   `managingApp` is used when *either* is `managing-app`; `checkUserAccess`
   gains an `access` field (`read`|`write`) and gets no client on write checks;
   `appAccess` applies to reads only. `manage=update` covers `putMember`.
   Write access decides whether the authority tracks a writer in `listRepos`
   and forwards their notifications — it does not stop an account writing to
   its own repo.
6. **Naming/minor**: proposal retitled "Atproto Spaces" (#115); new
   `space-ref` Lexicon string format for a reference to just a space
   (up to `skey`) (#117).

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
  `#atproto_space_host` (typed `AtprotoSpaceHost`; falls back to
  `#atproto_pds`). Fallback applies only when an entry is *absent* — a
  present-but-malformed/invalid entry MUST error, never silently fall back.
- **Space type declarations**: a new Lexicon shape, `"type": "space"`, with
  `key`, `name` (+ localized), `collections` (default collection set for
  scopes/consent; MUST NOT contain a wildcard `*`).

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
  presented as `Authorization: Bearer <delegation token>` + an RFC 9421
  `atproto-space` HTTP Message Signature over `("authorization")` (+
  attestation if required). `typ:
  atproto-space-credential+jwt`, `kid` `#atproto_space` or `#atproto`,
  `iss` = authority DID, `sub` = space URI, **no `aud`**, default 10 min / max 60 min, multi-use
  across every repo host in the space. Verifiable offline against the
  authority's published key. **Key-bound**: carries `cnf.kid` (the P-256
  `did:key` that signed the mint request) and is presented as
  `Authorization: Atproto-Space <credential>` + `Atproto-Space-Audience` +
  an `atproto-space` signature over both headers that every host MUST verify
  against `cnf.kid` — never bearer. No method/URI binding, so a signature is
  replayable against the same audience until expiry. Revocable by `jti` via
  `notifyCredentialRevoked`. Syncers mint an ephemeral keypair per credential.
- **`space:` OAuth scope**:
  `space:<spaceType>[?authority=<did|self|*>][&skey=…][&collection=…][&action=…][&manage=…]`.
  Defaults: `authority=self`, `skey=*`, `action=read,create,update,delete`,
  `collection` = the space type declaration's `collections` (resolved
  dynamically, like permission sets). `read` is all-or-nothing per space
  (grants the read/sync methods **and** `getDelegationToken`); `read_self`
  covers only the holder's own repo, no delegation token; both `read` and
  `read_self` ignore `collection` (read is all-or-nothing at the space/repo
  boundary). `manage` verbs gate the management surface. Read/sync methods
  accept **either** a covering OAuth grant or a key-bound space credential;
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
- **Write notifications** — reasonable-effort, no record data (just the repo's
  new `rev` + `hash`). `notifyWrite` (service auth) goes automatically from
  repo host → space host (no registration; skipped when the authority is the
  repo account); the space host tracks per-repo state, assigns a space-level
  rev (TID), and forwards (current + previous space rev) to syncers that
  called `registerNotify` (space host only, space-credential-authed,
  expiring; `unregisterNotify` withdraws). Gaps in space revs are detected by
  syncers and healed via `listRepos` `since` a space rev (writer set with
  per-repo `rev` + `hash` — accounts that have written, never a
  member/reader list). Syncers then sync from the repo host directly.
- **Credential revocation** — short expiry first; optionally the authority
  fans `notifyCredentialRevoked` (by `jti`, service auth) to repo hosts,
  which keep the revocation ≥ 60 min.
- **Space deletion** — authority stops answering, deletes its own repo,
  best-effort `notifySpaceDeleted` to registered syncers (who must delete
  their copies). Members' repo hosts are **not** notified and keep the
  member's own records — they simply become unreadable to everyone else. The
  durable signal for a syncer that missed the notification is an explicit
  `SpaceDeleted` error on credential renewal; any other renewal failure says
  nothing about the space.

### Required PDS management: `com.atproto.simplespace`

Every PDS MUST implement it (spaces anchored on the user's own DID):
`createSpace` / `updateSpace` / `deleteSpace` / `getSpace` / `putMember` /
`removeMember` / `listMembers` (members carry `read` + `write` booleans),
config `{readPolicy, writePolicy: public | member-list | managing-app
(default member-list), appAccess: #open | #allowList, managingApp}`. The
policies and `appAccess` are open unions — a host MUST reject values it does not implement
at `createSpace`/`updateSpace` time. The management procedures need the
relevant `manage` grant; the read queries need only read access (`getSpace`:
OAuth `read_self` or a space credential; `listMembers`: `read_self`).
`managing-app` policy defers the per-user authorization decision (at
credential-mint time for reads; at writer-tracking time for writes, via an
`access` field) to the app via `com.atproto.simplespace.checkUserAccess`
(served by the managing app, service-auth from the authority). Other
space-management implementations are first-class but live on bespoke space
services, not the PDS.

### XRPC surface (all `com.atproto.space.*` unless noted)

| Group | Methods |
|---|---|
| Host | `getSpaceCredential` (delegation token + HTTP Message Signature), `listRepos` |
| Repo (read/sync) | `getRecord`, `listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`, `listRepoOps` |
| PDS | `getDelegationToken`, `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `listSpaces` |
| Notifications | `registerNotify`, `unregisterNotify` (space host only), `notifyWrite`, `notifySpaceDeleted`, `notifyCredentialRevoked` |
| `com.atproto.simplespace.*` | `createSpace`, `updateSpace`, `deleteSpace`, `getSpace`, `putMember`, `removeMember`, `listMembers`, `checkUserAccess` (served by managing app) |

The alpha lexicons pin this at **21 `com.atproto.space.*` + 9
`com.atproto.simplespace.*` schema files** (incl. `defs`; `notifyCredentialRevoked`
is the 2026-10-09 addition); Custos serves
~27 of them as routes (`checkUserAccess` is outbound-only for us, `defs` are
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
| Key binding of space credentials (RFC 9421 `atproto-space` signature vs `cnf.kid`) | **No longer reusable from DPoP**: the space credential path leaves RFC 9449 for HTTP Message Signatures (2026-10-09 §0). Reusable pieces: P-256/`did:key` handling in `crates/crypto`, and `authenticate_access` stays OAuth-only. New: RFC 9421 signature-base construction + verify (covered components pinned, raw `r‖s`, low-S not required) |
| Single-use `jti` replay protection (delegation/attestation tokens) and revoked-credential `jti` store | DPoP nonce-store pattern (`auth/dpop.rs`); credential-authed requests themselves no longer need a replay store |
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
  `ae05cb6d…`, plus commit/HTTP-signature/credential suites) alongside round-trip +
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
  The declaration's `collections` field itself is validated non-wildcard at
  the space-type-registry layer (reject a `*` entry the same way
  `createSpace`/`updateSpace` reject an unimplemented open-union value).
- Permission sets: accept `"resource": "space"` entries; enforce no-wildcard
  `spaceType` inside sets + namespace-authority rules.
- Token issuance/verification: delegation tokens (mint, single-use, 60 s,
  presented to `getSpaceCredential` as `Authorization: Bearer` alongside an
  RFC 9421 `atproto-space` signature over `("authorization")`), space
  credentials (mint as authority — validating that signature, requiring a
  P-256 `did:key` `keyid`, and copying it into `cnf.kid`; 10 min default /
  60 min max; verify as repo host against `#atproto_space`→`#atproto`
  fallback for an *absent* entry only — a present-but-malformed key or
  `#atproto_space_host` service entry errors rather than falling back —
  **plus** the `Atproto-Space` scheme + `Atproto-Space-Audience` signature
  check against `cnf.kid`, and a revoked-`jti` store fed by
  `notifyCredentialRevoked`, retained ≥ 60 min),
  client attestations (resolve client metadata JWKS — SSRF-hardened client
  mandatory; optional per space, so the mint path must tolerate its absence
  cleanly). As a *syncer/client* (e.g. tooling), mint an ephemeral P-256
  keypair per credential.
- **New auth seam.** Read/sync methods accept OAuth *or* a key-bound space
  credential — both proof-of-possession, never bearer. That dual acceptance
  must be one function (e.g. `auth::space::authenticate_space_read`) with a
  `just`-gate in the spirit of `auth-seam-check`, so no route grows its own
  credential parsing. The OAuth arm keeps the existing DPoP validator
  (`auth/dpop.rs`); the credential arm needs a new RFC 9421 verifier and no
  longer composes with it. **Existing seam code that validates DPoP proofs for
  space credentials must be reworked** (see §7 MM-510).
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
create/update), `cnf.kid` binding at mint time, writer-set tracking (fed by
notifications + own writes, gated by `writePolicy`), a per-space revision (TID)
sequence, notification fan-out worker with retries and registration expiry
(`registerNotify`/`unregisterNotify`, space host only), optional
`notifyCredentialRevoked` fan-out, space deletion flow
(stop issuing, delete own repo, notify registered syncers, answer renewals
with `SpaceDeleted`; members' data stays put and simply becomes unreadable to
others).

### W6. Identity
Emit/accept `#atproto_space` + `#atproto_space_host` in DID docs (PLC ops via
the wallet-signed rotation surface; did:web hosting), resolution with
fallbacks — an absent entry falls back (`#atproto`/`#atproto_pds`), but a
present, malformed/invalid one MUST error rather than fall back — and surface
them in `getRecommendedDidCredentials`.

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

Also deferred (MM-527): benchmark per-serving commit signing, then decide
whether anything needs caching. `space_views::sign_current_commit` mints a
fresh deniable commit per serving, so every sync call
(`getLatestCommit`/`getRepo`/`listRepoOps`) reads the repo head, SELECTs the
wrapped signing key, unwraps it, and signs. The unwrap is not the expensive
step — it is 32 bytes. The DB round trip is the candidate bottleneck, and it
costs more than its latency suggests, because the single-connection pool makes
each sync call serialize against every other DB user. The cost is per-reader,
scaling with syncers × poll frequency rather than with writes, so a quiet repo
with many pollers is the worst case. Measure before caching, and note what a
cache would actually change: `load_repo_signing_key` already returns
`Zeroizing<[u8; 32]>`, so the question is not whether the key is zeroized but
how long it stays resident — microseconds today, a TTL under a cache. If the
DB read dominates, caching the head read may beat caching key material at
all.

## 4. Suggested phasing

1. **Phase 0 — primitives (started with the alpha, vector-pinned):** W1
   crypto + `space:` scope grammar (parse/normalize/display only). Pure,
   testable against the published golden vectors, and the part of the spec
   least likely to move.
2. **Phase 1 — personal spaces (authority = self):** W2 store + PDS CRUD/read
   routes + delegation token + key-bound (`cnf.kid`) credential mint where PDS is both
   roles + simplespace with `member-list`/`public` + consent UI. Delivers the
   bookmarks/drafts/private-posts modality end-to-end on a single PDS. Gate
   behind a config flag (e.g. `EZPDS_SPACES_ENABLED`) until the protocol
   launches (target "later this year").
   > **Decision (2026-08-27, MM-524):** the gate shipped as `[spaces] enabled`
   > / `EZPDS_SPACES_ENABLED`, default **off** until the protocol launches, as
   > planned (it had shipped always-on in the interim). Disabled, the routes
   > are simply not registered — an XRPC space method answers the catch-all's
   > `MethodNotImplemented`, stored space data is untouched, and the space
   > sweeps are not spawned. Discoverability is the `spaces` entry in
   > `describeServer`'s `custos` capability set, keyed to `spaces.enabled`
   > **and** `signing_key_master_key` (the precondition for the sync surface:
   > per-serving commit signing needs the KEK-wrapped repo signing key, so
   > `getLatestCommit`/`listRepoOps`/`getRepo` answer 503 without one).
3. **Phase 2 — shared spaces & sync:** oplog + `listRepoOps`, two-root CAR
   `getRepo`, notifications (repo→space host→syncers, space revs) + expiry, writer set, credential revocation, space
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
- **Replay/revocation stores** (delegation `jti`, attestation `jti`, and
  revoked credential `jti`s kept ≥ 60 min) need TTL sweeps. The per-request
  DPoP-proof `jti` store from the August design is **no longer needed** —
  credential-authed requests are replayable by spec until expiry, which makes
  the 10-minute lifetime and `notifyCredentialRevoked` the real containment.
- **Replayable signatures**: the `atproto-space` signature binds neither
  method nor URI, so a captured request can be replayed (same audience) for
  the credential's remaining life. Keep TLS-only transport and short TTL;
  don't log credential or signature headers.
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
key-bound or single-use), and a notification subsystem — plus ~26 `.bru`
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
| MM-510 | 1 | Space auth: delegation-token mint, key-bound space-credential mint/verify (RFC 9421 `atproto-space` signatures, `cnf.kid`, `Atproto-Space` scheme + `Atproto-Space-Audience`, 10 min TTL, revoked-`jti` store; replaces the DPoP design — rework any DPoP-based credential code), `auth::space::authenticate_space_read` seam + `just` seam gate (blocked by MM-507) |
| MM-511 | 1 | `com.atproto.simplespace` management surface: `createSpace`/`updateSpace`/`deleteSpace`/`getSpace`/`putMember`/`removeMember`/`listMembers` (members carry `read`+`write`); `readPolicy`/`writePolicy` with `member-list` + `public`; open-union rejection (blocked by MM-508) |
| MM-512 | 1 | Consent UI for `space:` scopes in `/oauth/authorize`: space-type declaration resolution (name, default collections), authority handle display, wildcard warnings (blocked by MM-507) |
| MM-513 | 2 | Sync surface: `listRepoOps` oplog (+compaction), two-root CAR `getRepo` (canonical DAG-CBOR index order), `listBlobs`, space blob refs + GC union (blocked by MM-509/510) |
| MM-514 | 2 | Space-host role: writer set, `registerNotify`/`unregisterNotify` (+expiry), `notifyWrite` ingest + space-rev sequencing + fan-out worker (no auto-registration), `notifyCredentialRevoked` (send + receive), space deletion + `SpaceDeleted` renewal error (blocked by MM-510/511) |
| MM-515 | 2 | Identity: `#atproto_space` / `#atproto_space_host` DID-doc entries (PLC + did:web) with fallbacks; `getRecommendedDidCredentials` |
| MM-516 | 3 | Client attestation verification + `appAccess` `#allowList`; `managing-app` read/write policies with outbound `checkUserAccess` (`access` field) (blocked by MM-510/511) |
| MM-517 | 3 | Lifecycle & migration: `/v1/transfer/*` enumeration via `listSpaces`/`listBlobs`, deactivation/takedown propagation on space paths, spaces `importRepo` (blocked by MM-513) |
| MM-518 | 3 | Tooling & interop: Bruno collection, interop CLI scenarios vs the alpha (hosted sandbox PDS + TS SDK as client), MCP tool surface, browser-harness coverage (blocked by MM-509) |

A weekly routine watches the alpha's Thursday releases and PRs spec-delta
updates to this doc — see
[`docs/operations/spaces-alpha-watch-routine.md`](../operations/spaces-alpha-watch-routine.md).
