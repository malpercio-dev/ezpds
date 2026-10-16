# Atproto Spaces (proposal 0016, née Permissioned Data) — Custos Gap Analysis

**Date:** 2026-07-17 · **Revised:** 2026-08-20 (official alpha release) · 2026-09-04, 2026-10-16 (weekly watch)
**Status:** Research / gap analysis — updated for the alpha; implementation green-lit for Phase 0
**Sources:**
- [0016 proposal](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) (canonical; kept in sync with the reference implementation as of the alpha; last diffed against commit `c76714a`)
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

1. **Space credentials are DPoP-bound, not bearer** (the big one).
   *(Superseded 2026-10-16: DPoP was replaced by RFC 9421 HTTP Message
   Signatures and `cnf.kid` — see that entry; the not-bearer rationale stands.)* A
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
4. **`getSpaceCredential` wire format spelled out for the first time**
   *(DPoP specifics superseded 2026-10-16 — see below)*: the
   delegation token travels as `Authorization: Bearer <delegation token>`
   alongside a `DPoP: <proof>` header (the proof still carries no `ath` — the
   delegation token is a grant, not an access token); the proof's `htu` is
   the plain request URL (scheme + host + path, no query/fragment) rather
   than an `lxm` claim; DPoP server-provided nonces are **not** used anywhere
   in the flow; and host-side proof validation must additionally check the
   proof's `typ` (`dpop+jwt`) and `alg` header fields alongside the checklist
   already in item 1 above. This affects the wire contract MM-510 mints
   against and the space-credential row in the auth-model table below.

### 2026-10-16 weekly watch (proposals repo, commits `35a2d37`…`c76714a`)

The biggest movement since the alpha: seven spec PRs (#105, #109, #113, #115,
#116, #117, #121) plus a rename. Re-verified against `permissioned-data` @
`619c6e8`: **21 `com.atproto.space.*` + 9 `com.atproto.simplespace.*`** schema
files (`notifyCredentialRevoked` added; `simplespace.addMember` became
`putMember`), same golden LtHash digests (`e5a00aa9…`, `ae05cb6d…`;
`packages/space/src/http-signature.ts` is new). Folded into the sections below:

1. **DPoP is gone: space credentials are bound with HTTP Message Signatures
   (RFC 9421), PR #113 — supersedes items 1 and 4 of the 2026-08 and
   2026-09-04 entries above.** The credential carries `cnf.kid` (a P-256
   `did:key`), not `cnf.jkt`. At `getSpaceCredential` the syncer sends
   `Authorization: Bearer <delegation token>` plus
   `Signature-Input: atproto-space=("authorization");keyid="did:key:zDna…"` and
   `Signature: atproto-space=:…:`; the host validates the delegation token,
   requires the covered components to be exactly `("authorization")`, an
   `alg` (if present) of `ecdsa-p256-sha256`, and a P-256 `did:key` `keyid`,
   and copies the `keyid` into `cnf.kid`. Credential-authed requests carry
   `Authorization: Atproto-Space <credential>` (new scheme, not `DPoP`), an
   `Atproto-Space-Audience` header (the repo owner's DID when syncing; the
   space authority DID against the space host), and a signature over exactly
   `("authorization" "atproto-space-audience")`, in that order. Hosts verify:
   one `Authorization` + one audience field, credential type/issuer/signature/
   subject/expiry, covered-component list, `cnf.kid` is a P-256 `did:key`,
   signature verifies against it, audience equals the audience derived from
   the request. **No `ath`, `htm`, `htu`, `iat`, or `jti` proof checks and no
   per-request replay store**: the signature binds neither method nor URI and
   MAY be replayed against the same audience until the credential expires.
   Signature value is raw 64-byte `r || s`; low-S is *not* required and
   verifiers MUST accept both forms (unlike atproto commit signatures).
2. **Credential lifetime cut to 10 minutes by default, 60 minutes max** (was
   2 hours) — short expiry is now the primary revocation mechanism, so
   renewals are ~12× more frequent and every renewal needs a live
   delegation (a user session); `jti` is now "random unique identifier, used
   for revocation" rather than a nonce.
3. **New `com.atproto.space.notifyCredentialRevoked`** (service auth from the
   space authority; `{space, credentials: [jti…]}`): an authority MAY push
   revoked credential `jti`s to repo hosts, which MUST reject them and retain
   the revocation ≥ 60 minutes. Idempotent; fan-out is the authority's
   choice (costly for large spaces, cheap for small ones).
4. **Notification/sync topology reworked (PR #116).** Repo hosts push
   `notifyWrite` to the **space host** automatically (service auth, no
   registration; retry network failures/transient statuses, stop on permanent
   errors); the space host rejects writers not authorized to write, ignores
   non-increasing `repoRev`, rejects future revs (`FutureRev` error beyond a
   clock-skew window), keeps a per-repo state table, assigns its own **space
   revision** (TID) and forwards to registered syncers with `spaceRev` +
   `prevSpaceRev`. A gap means missed notifications; recover with
   `listRepos` using `cursor` = a processed `spaceRev` (repos updated after
   it, ascending `spaceRev`; each entry now has `did`, `repoRev`, `hash`,
   `spaceRev`). **`registerNotify`/`unregisterNotify` are space-host-only**
   (no per-repo registration on repo hosts) and registrations have a fixed
   duration (`expiresAt`). **The repo host's auto-registration of the
   authority is removed** — notification to the authority is simply
   automatic. The wire field is now `repoRev` (was `rev`).
5. **`simplespace` read/write split (PR #105; `addMember` → `putMember`).**
   `policy` is replaced by independent **`readPolicy`** and **`writePolicy`**
   (`public` | `member-list` | `managing-app`, both default `member-list`).
   Read policy gates minting a credential (with `appAccess`, which does *not*
   apply to writes); write policy gates whether the authority **tracks** the
   writer in `listRepos` and forwards their `notifyWrite` — it never blocks
   an account writing into its own repo. Member-list entries carry required
   `read` and `write` booleans; `putMember {space, did, read, write}`
   replaces both (the `manage=update` verb now covers `putMember`, not
   `addMember`). `checkUserAccess` gains a required `access: read | write`;
   no `clientId` is sent on write checks.
6. **Repo lifecycle defined (PR #121).** A space repo is created implicitly
   by its first record write (no create op; a non-self authority's existence
   isn't checked by the writer's PDS, but a self-authority's space must
   already exist). An empty repo ≡ a nonexistent repo; deleting a repo =
   deleting all its records (no repo-delete op); a later write recreates it.
   Deleting a repo does not delete the space. On space deletion the authority
   deletes *all records* in its own repo.
7. **Terminology rename (PR #115):** "permissioned data/repo" → **"atproto
   spaces"/"space repo"** throughout the proposal. New **`space-ref`** Lexicon
   string format for references to a space (URI through `skey`, no more);
   lexicons now use it for `space` parameters. Cosmetic for Custos except
   that route/validation code accepting a space parameter should validate it
   as a `space-ref`.

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
- **Space repo** (née permissioned repo) = one user's records within one space,
  hosted on that user's PDS. One repo per (user, space); users hold many.
  Created implicitly by the first write; empty ≡ nonexistent; deleting all
  records deletes the repo (the space itself survives).
- **Roles:** *repo host* (serves a user's space repos) and *space host*
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
  `atproto-space` HTTP Message Signature over `("authorization")` by the key
  to bind (+ attestation if required). `typ:
  atproto-space-credential+jwt`, `kid` `#atproto_space` or `#atproto`,
  `iss` = authority DID, `sub` = space URI, **no `aud`**, 10 min default /
  60 min max, multi-use
  across every repo host in the space. Verifiable offline against the
  authority's published key. **Key-bound, not bearer**: carries `cnf.kid` (the
  P-256 `did:key` from the mint-time signature) and is presented as
  `Authorization: Atproto-Space <credential>` + `Atproto-Space-Audience:
  <repo owner DID>` + an `atproto-space` signature over `("authorization"
  "atproto-space-audience")` that every host MUST verify against `cnf.kid`
  (no method/URI binding; replay against the same audience is allowed until
  expiry). Syncers mint an ephemeral keypair per credential. Short expiry is
  the primary revocation mechanism; `notifyCredentialRevoked` (by `jti`) is
  the optional fast path.
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
- **Write notifications** — best-effort, no record data (just the repo's new
  `repoRev` + `hash`). Repo host → space host `notifyWrite` is automatic
  (service auth, no registration; host retries transient failures); the space
  host validates the writer, sequences a per-space `spaceRev`, and forwards
  to syncers registered via `registerNotify` (space host only, space-credential
  auth, fixed-duration registrations withdrawn with `unregisterNotify`),
  carrying `spaceRev` + `prevSpaceRev`. A gap is the missed-notification
  signal; `listRepos` (writer set: `did`, `repoRev`, `hash`, `spaceRev` —
  accounts that have written, never a member/reader list) with `cursor` =
  last processed `spaceRev` catches up, including after any downtime. Syncers
  then pull directly from repo hosts, never through the space host. The
  authority may exclude or rate-limit writers.
- **Credential revocation** — `notifyCredentialRevoked` (authority → repo
  hosts, service auth, by `jti`; hosts retain ≥ 60 min).
- **Space deletion** — authority stops answering, deletes all records in its own repo,
  best-effort `notifySpaceDeleted` to registered syncers (who must delete
  their copies). Members' repo hosts are **not** notified and keep the
  member's own records — they simply become unreadable to everyone else. The
  durable signal for a syncer that missed the notification is an explicit
  `SpaceDeleted` error on credential renewal; any other renewal failure says
  nothing about the space.

### Required PDS management: `com.atproto.simplespace`

Every PDS MUST implement it (spaces anchored on the user's own DID):
`createSpace` / `updateSpace` / `deleteSpace` / `getSpace` / `putMember` /
`removeMember` / `listMembers`, config `{readPolicy, writePolicy: public |
member-list | managing-app (default member-list), appAccess: #open |
#allowList, managingApp}` (member-list entries carry `read` + `write`
booleans). The policies and `appAccess` are open unions — a host MUST reject values it does not implement
at `createSpace`/`updateSpace` time. The management procedures need the
relevant `manage` grant; the read queries need only read access (`getSpace`:
OAuth `read_self` or a space credential; `listMembers`: `read_self`).
`managing-app` policy defers the per-user decision — at credential-mint time
for reads, at write-tracking time for writes — to the app via
`com.atproto.simplespace.checkUserAccess` (served by the managing app,
service-auth from the authority; `access: read | write`). Other
space-management implementations are first-class but live on bespoke space
services, not the PDS.

### XRPC surface (all `com.atproto.space.*` unless noted)

| Group | Methods |
|---|---|
| Host | `getSpaceCredential` (delegation token + HTTP Message Signature), `listRepos` |
| Repo (read/sync) | `getRecord`, `listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`, `listRepoOps` |
| PDS | `getDelegationToken`, `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `listSpaces` |
| Notifications | `registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted`, `notifyCredentialRevoked` |
| `com.atproto.simplespace.*` | `createSpace`, `updateSpace`, `deleteSpace`, `getSpace`, `putMember`, `removeMember`, `listMembers`, `checkUserAccess` (served by managing app) |

The alpha lexicons pin this at **21 `com.atproto.space.*` + 9
`com.atproto.simplespace.*` schema files** (incl. `defs`); Custos serves
~27 of them as routes (`checkUserAccess` is outbound-only for us, `defs` are
not endpoints) — each needing a `.bru` file under the bruno-parity gate.

### Lifecycle interactions

Migration must enumerate **all** of an account's space repos (via
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
| Key binding of space credentials (`cnf.kid`, RFC 9421 `atproto-space` signatures) | **Not covered by the OAuth DPoP stack any more** — `auth/dpop.rs` stays OAuth-only. Reusable pieces: P-256 `did:key` parse/verify (`crypto::verify_did_key_signature`; raw `r‖s`, accept high-S) and the `Authorization`-scheme dispatch in `auth/extractors.rs`. The RFC 9421 `Signature-Input`/`Signature` parsing (exactly-one-label, exact covered-component list) is new code |
| Single-use `jti` replay protection (delegation tokens, attestations) | DPoP nonce-store pattern (`auth/dpop.rs`); no longer needed on the sync path, which has no per-request replay check |
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
  `ae05cb6d…`, plus commit/credential suites and the new
  `http-signature.test.ts`) alongside round-trip +
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
  presented to `getSpaceCredential` as `Authorization: Bearer` alongside the
  `atproto-space` signature over `("authorization")`), space credentials (mint
  as authority — validating that signature and copying its P-256 `did:key`
  `keyid` into `cnf.kid`, 10 min default / 60 min cap; verify as repo host
  against `#atproto_space`→`#atproto` fallback for an *absent* entry only — a
  present-but-malformed key or `#atproto_space_host` service entry errors
  rather than falling back — **plus** the `Atproto-Space` scheme check: one
  `Authorization` + one `Atproto-Space-Audience`, exact covered-component
  list `("authorization" "atproto-space-audience")`, signature verified against
  `cnf.kid` with `ecdsa-p256-sha256`, audience equal to the request-derived
  repo DID — and rejection of `jti`s revoked via `notifyCredentialRevoked`),
  client attestations (resolve client metadata JWKS — SSRF-hardened client
  mandatory; optional per space, so the mint path must tolerate its absence
  cleanly). As a *syncer/client* (e.g. tooling), mint an ephemeral P-256
  keypair per credential and re-mint roughly every 10 minutes.
- **New auth seam.** Read/sync methods accept OAuth *or* a key-bound space
  credential — both proof-of-possession, never bearer. That dual acceptance
  must be one function (e.g. `auth::space::authenticate_space_read`) with a
  `just`-gate in the spirit of `auth-seam-check`, so no route grows its own
  credential parsing. The OAuth arm still composes with `auth/dpop.rs`; the
  credential arm is now a distinct RFC 9421 verifier and no longer shares
  the DPoP validator or replay store.
- Consent screen: render space-type `name`, authority handle
  (bidirectionally verified), wildcard warnings, in the `/oauth/authorize`
  templates.

### W4. XRPC surface (~27 routes)
One file per route per the route-isolation rule; queries in `db/`, auth in
`auth/`; register in `app.rs`; one `.bru` each (bruno-parity). Groups: PDS
CRUD + `listSpaces` + `getDelegationToken`; repo read/sync (`getRecord`,
`listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`,
`listRepoOps`); host (`getSpaceCredential`, `listRepos`); notifications
(`registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted`,
`notifyCredentialRevoked`); simplespace management incl. `getSpace` and
`putMember`. `checkUserAccess` is *outbound* from
Custos-as-authority (inbound only if we ever ship a managing app). The alpha
lexicons (`lexicons/com/atproto/{space,simplespace}/` on the
`permissioned-data` branch) are the schema source of truth to codegen or
hand-mirror.

### W5. Space-host role
Credential issuance policy engine (`readPolicy` / `writePolicy` — `public` /
`member-list` / `managing-app` — × `appAccess` `#open`/`#allowList`, applied to
reads only; rejecting unimplemented open-union values at create/update),
key-binding at mint time (`cnf.kid`), writer-set tracking gated on
`writePolicy` and fed by notifications + own writes, per-space `spaceRev`
sequencing with `prevSpaceRev` on forwarded notifications, `listRepos`
`cursor` = `spaceRev` catch-up, notification fan-out worker with retries and
registration expiry (`registerNotify`/`unregisterNotify`), rejection of
non-increasing or future `repoRev`, optional `notifyCredentialRevoked` fan-out
(authority's discretion), space deletion flow (stop issuing, delete all
records in own repo, notify registered syncers, answer renewals with
`SpaceDeleted`; members' data stays put and simply becomes unreadable to
others). The repo-host side needs no authority auto-registration: it just
pushes `notifyWrite` to the space host, retrying transient failures.

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
space import endpoint** (the 21 `com.atproto.space.*` schema files are
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
   `getRepo`, notifications + `spaceRev` sequencing + expiry, writer set, credential
   revocation, space deletion. Validate against the alpha: the hosted sandbox PDS, the
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
  ("later this year"). The August deltas (§0) were auth hardening and endpoint reshuffles;
  the October ones are bigger — the credential binding was swapped from DPoP to
  HTTP Message Signatures, the notification topology and `simplespace`
  policy model were reworked — so a module built against a prior week's wire
  contract can need real rework, not a tweak.
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
- **Replay stores** (delegation `jti`, attestation `jti`) need TTL sweeps. The
  per-host DPoP-proof `jti` store on the sync path is no longer required
  (RFC 9421 signatures are replayable by design until credential expiry), but
  a retained-revocation table (`notifyCredentialRevoked`, ≥ 60 min) takes its
  place and also needs a sweep.
- **Credential renewal load.** With a 10-minute default lifetime a syncer needs
  a live user session and a `getDelegationToken` → `getSpaceCredential` round
  trip every ~10 minutes; size the mint path (and the single-use delegation
  `jti` store) for that, and expect `SpaceDeleted`/denial to surface at renewal.
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
engine, ~27 routes, a scope-grammar extension, three token types (all
key-bound or single-use), and a notification subsystem — plus ~27 `.bru`
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
| MM-510 | 1 | Space auth: delegation-token mint, key-bound space-credential mint/verify (`cnf.kid`, RFC 9421 `atproto-space` signatures, 10 min default / 60 min max, `jti` revocation list), `auth::space::authenticate_space_read` seam + `just` seam gate (blocked by MM-507) |
| MM-511 | 1 | `com.atproto.simplespace` management surface: `createSpace`/`updateSpace`/`deleteSpace`/`getSpace`/`putMember`/`removeMember`/`listMembers`; `readPolicy`/`writePolicy` with `member-list` + `public`; open-union rejection (blocked by MM-508) |
| MM-512 | 1 | Consent UI for `space:` scopes in `/oauth/authorize`: space-type declaration resolution (name, default collections), authority handle display, wildcard warnings (blocked by MM-507) |
| MM-513 | 2 | Sync surface: `listRepoOps` oplog (+compaction), two-root CAR `getRepo` (canonical DAG-CBOR index order), `listBlobs`, space blob refs + GC union (blocked by MM-509/510) |
| MM-514 | 2 | Space-host role: writer set, `registerNotify`/`unregisterNotify` (+expiry, space-host-only), `notifyWrite` ingest + `spaceRev`/`prevSpaceRev` fan-out, `listRepos` cursor catch-up, `notifyCredentialRevoked`, space deletion + `SpaceDeleted` renewal error (blocked by MM-510/511) |
| MM-515 | 2 | Identity: `#atproto_space` / `#atproto_space_host` DID-doc entries (PLC + did:web) with fallbacks; `getRecommendedDidCredentials` |
| MM-516 | 3 | Client attestation verification + `appAccess` `#allowList`; `managing-app` read/write policies with outbound `checkUserAccess` (`access` param) (blocked by MM-510/511) |
| MM-517 | 3 | Lifecycle & migration: `/v1/transfer/*` enumeration via `listSpaces`/`listBlobs`, deactivation/takedown propagation on space paths, spaces `importRepo` (blocked by MM-513) |
| MM-518 | 3 | Tooling & interop: Bruno collection, interop CLI scenarios vs the alpha (hosted sandbox PDS + TS SDK as client), MCP tool surface, browser-harness coverage (blocked by MM-509) |

A weekly routine watches the alpha's Thursday releases and PRs spec-delta
updates to this doc — see
[`docs/operations/spaces-alpha-watch-routine.md`](../operations/spaces-alpha-watch-routine.md).
