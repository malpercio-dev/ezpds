# Atproto Spaces (proposal 0016, née Permissioned Data) — Custos Gap Analysis

**Date:** 2026-07-17 · **Revised:** 2026-08-20 (official alpha release) · 2026-09-04, 2026-09-11, 2026-10-16, 2026-10-30 (weekly watch)
**Status:** Research / gap analysis — updated for the alpha; implementation green-lit for Phase 0
**Sources:**
- [0016 proposal](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) (canonical; kept in sync with the reference implementation as of the alpha; last diffed against commit `701ef9c`)
- [The Atproto Spaces Alpha is Live](https://atproto.com/blog/atproto-spaces-alpha) (2026-08-20 announcement)
- Reference implementation: `permissioned-data` branch of bluesky-social/atproto — lexicons under `lexicons/com/atproto/{space,memberspace,managedspace,personalspace}/`, protocol library in `packages/space/` (LtHash, deniable commits, DPoP, sync — **with golden test vectors**)
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

### 2026-10-30 weekly watch (proposals repo, commits `c76714a`…`701ef9c`)

The largest single-week rewrite since the alpha: eleven 0016 commits (#114,
#119, #120, #122, #123, #124, #127, #128, #129 and two follow-ups) land the
10-22 and 10-29 releases. Re-verified against `permissioned-data` @
`d009736`: the lexicon set is now **31 `com.atproto.space.*` + 5
`memberspace` + 2 `managedspace` + 1 `personalspace` = 39 schema files**
(`com.atproto.simplespace.*` is **gone**; added `clearRecords`, `removeWriter`,
`importRepo`, `exportSpaceMeta`, `importSpaceMeta`, `policy`, with
`createSpace`/`updateSpace`/`deleteSpace`/`getSpace` moved into
`com.atproto.space`). The LtHash golden digests are unchanged (`e5a00aa9…`,
`ae05cb6d…`); `packages/space` gains `kem.ts`, `mac.ts`, `star.ts`,
`space-meta-archive.ts` and tests (`kem.test.ts` carries an RFC 9180-derived
P-256 vector). Folded into the sections below:

1. **The deniable signature is gone: commits are authenticated by a MAC under
   an ephemeral KEM shared secret (PRs #122, #123).** `signedCommit` becomes a
   plain `commit` `{ver: 1, repo, space, rev, data}` (`hash` → `data`;
   `ikm`/`sig`/`mac` dropped from the object). The author's repo host holds a
   new P-256 **KEM key**, published as DID-doc `verificationMethod`
   `{did}#atproto_kem` (type `Multikey`, dedicated keypair). Per request the
   syncer generates a fresh ephemeral P-256 keypair, does ECDH against the
   author's `#atproto_kem` key, derives `shared_secret` with HKDF-SHA256 using
   the RFC 9180 DHKEM(P-256) labels, and sends its public key as
   `Atproto-Space-Want-Mac: type="atproto-space-repo", ver=1, key_share="did:key:…"`.
   The host replies `Atproto-Space-Mac: type=…, ver=1, mac=:…:` and
   `Vary: Atproto-Space-Want-Mac`. Commit MAC =
   `HMAC-SHA256(shared_secret, ctx || data)` with
   `ctx = "atproto-space-repo-v1" || u16be-prefixed(space, repo, rev)`; record
   MAC (`getRecord`) = `HMAC-SHA256(shared_secret, "atproto-space-record-v1" ||
   u16be-prefixed(uri) || record_cid_bytes)`. Applies to `getLatestCommit`,
   `getRepo`, `listRepoOps` (final page only) and `getRecord`. A new keypair
   per request, including retries and each page. **No signature remains in the
   repo format at all**, so the author's `#atproto` key is no longer used on
   the sync path; the old HKDF-Expand construction and per-reader `ikm` are
   obsolete. Failed MAC → refresh the DID doc, retry with a new keypair.
2. **DID-doc resolution simplified (#123).** `#atproto_space` and
   `#atproto_space_host` are **removed**. The space host is the authority's
   `#atproto_pds` endpoint and the credential is signed by its `#atproto`
   key — no fallbacks, no malformed-entry error rule. Credential `kid` MUST be
   `#atproto`; token `aud` becomes `{spaceDid}#atproto_pds`. (Supersedes the
   2026-09-04 item 1 error-on-malformed rule and the `#atproto_space*` rows
   in §1/W6.)
3. **`getSpaceCredential` request reshaped (#120).** Auth is now *none* at the
   HTTP layer: the body carries `{space, credentialKid (required P-256
   did:key), delegationToken?, clientAttestation?}` and the host copies
   `credentialKid` into `cnf.kid`. The RFC 9421 signature over
   `("authorization")` at mint time is **removed**. Presentation changed:
   `Authorization: Atproto-Space-Credential <cred>` (scheme renamed from
   `Atproto-Space`; matched case-insensitively, signature base uses the header
   exactly as received), signature label `atproto-space-credential`, and the
   signature MUST carry `tag="atproto-space-credential"` alongside the
   unchanged covered list `("authorization" "atproto-space-audience")`.
4. **Public spaces; delegation token and attestation both optional (#120).**
   An authority may require either assertion, both, or neither, and MUST NOT
   reject a request merely for carrying an assertion it does not require. A
   `memberspace` with `publicRead` mints credentials to anyone (syncers still
   need one). A syncer on a delegation-free space no longer needs a user
   session to renew.
5. **`simplespace` replaced by pluggable space policies (#119).**
   `createSpace`/`updateSpace`/`deleteSpace`/`getSpace` move to
   `com.atproto.space` and are policy-agnostic; `createSpace`/`updateSpace`
   take a full `policy` object (identified by `$type`; `updateSpace` replaces
   it wholesale; unimplemented policy → `UnsupportedPolicy`). A PDS MUST
   support three baseline policies: **`personalspace`** (authority only, no
   config), **`memberspace`** (member list via `putMember`/`removeMember`/
   `listMembers`; config `publicRead`, `publicWrite`, `allowedApps`,
   `publishPolicy`, `publishMembers`) and **`managedspace`** (`managingApp`
   decides per user via `checkUserAccess`; `publishPolicy`). The old
   `readPolicy`/`writePolicy`/`appAccess` matrix is gone: `allowedApps`
   (optional array of client IDs, evaluated against the *attested* `client_id`,
   reads only) replaces `appAccess`. The authority's own account is always
   authorized under every policy. `publishPolicy`/`publishMembers` mirror the
   policy and member list as records in the authority's own repo
   (`com.atproto.space.policy/self`, `com.atproto.memberspace.member/{did}`);
   the PDS must reject direct writes to those collections and `clearRecords`
   leaves them. `manage` verbs now map onto `createSpace`/`updateSpace`/
   `deleteSpace` plus the policy's methods; `manage=update` also authorizes
   `removeWriter` under every policy.
6. **Repo serialization is STAR, not CAR (#114).** `getRepo` and migration use
   a STAR-lite v1 file: magic `2A 6C 01 00`, a DRISL metadata map (`$type:
   "atproto-space-repo"` + all commit fields; MAC rides the response header),
   then varint-framed `{collection}/{rkey}` → DRISL record pairs in strict
   key-byte order, ≤ 1 MiB per record. Verification streams: validate
   metadata and commit MAC → fold each record's `path/cid` into the running
   LtHash → compare `sha256(state)` to `data` at EOF; reject the whole archive
   on any parse/order/duplicate/limit/MAC/digest failure. Two roots, the
   index map, and block order all disappear. `record_cid` is pinned as a DASL
   CID over DRISL bytes.
7. **New repo/space lifecycle methods.** `clearRecords` (#127): delete every
   record in the caller's repo for a space and advance to a new `rev` whose
   `data` is the all-zero LtHash digest `e5a00aa9…183ad`; the repo stays in
   the writer set. A host MAY GC an empty repo after a grace period.
   `removeWriter` (#128, host, OAuth `manage=update`): drop an account from
   the writer set (re-added on its next authorized write). Space deletion
   (#124): the authority now owns *reliable* `notifySpaceDeleted` delivery
   (retry transient, stop on permanent) and SHOULD retain a deletion record
   until every then-registered syncer is notified or expired; deleting the
   authority's account deletes its spaces; a space may be **recreated** with
   the same type + skey, re-exposing members' surviving records.
8. **Account migration specified (#129).** New `importRepo` (OAuth;
   `create` on every collection in the archive; whole-archive reject if scope
   doesn't cover; new host may assign a new `rev`, `data` unchanged),
   `exportSpaceMeta` (host, `read_self`) and `importSpaceMeta` (`manage=create`
   + `manage=update`). A **space meta archive** is a STAR file
   (`$type: "atproto-space-meta"`) with sections in order: `policy`, policy
   state (`{NSID}/{rkey}` keys, e.g. member entries), `writer/{did}` rows
   (`rev`, `data`, `spaceRev`). Order for authority spaces: `listSpaces` →
   `exportSpaceMeta`/`importSpaceMeta` (before the authority's own repo
   import) → per space `getRepo`/`importRepo` + `listBlobs`. The new host
   generates and publishes its own `#atproto_kem` key. Notification
   registrations, credential revocations and deletion tombstones are not
   carried over. `listSpaces` now also returns spaces the caller is the
   authority of. KEM rotation = replace `#atproto_kem` in the DID doc; no
   repo hash/rev change.

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
  Created implicitly by the first write; empty ≡ nonexistent. There is no
  repo-delete op: `clearRecords` empties it to the all-zero digest and a host
  MAY GC it later; the space itself survives.
- **Roles:** *repo host* (serves a user's space repos) and *space host*
  (answers for the space: issues credentials, tracks writers, routes
  notifications). A PDS is both for accounts/spaces anchored on it.
- **Space authority DID** resolves like any account: the space host is its
  `#atproto_pds` endpoint and its `#atproto` key signs credentials (the
  dedicated `#atproto_space*` entries were removed 2026-10-30). Separately,
  every *repo author* publishes a `#atproto_kem` P-256 key (`Multikey`) whose
  private half the repo host holds, used for commit/record MACs.
- **Space type declarations**: a new Lexicon shape, `"type": "space"`, with
  `key`, `name` (+ localized), `collections` (default collection set for
  scopes/consent; MUST NOT contain a wildcard `*`).

### Repo format (no MST)

- Commit digest = **LtHash** homomorphic multiset hash: 2048-byte state read
  as 1024 little-endian u16 lanes; each element is the UTF-8 of
  `{collection}/{rkey}/{record_cid}` expanded to 2048 bytes via **BLAKE3 XOF**;
  add/remove = lane-wise add/subtract mod 2^16. Commit carries
  `hash = sha256(state)` (32 bytes), hosts keep the full state.
- **MAC-authenticated commit** — a plain `commit {ver: 1, repo, space, rev,
  data}` (`data = sha256(LtHash state)`), carrying no signature. Authenticity
  comes from a per-request MAC under an ephemeral ECDH shared secret between
  the syncer and the author's `#atproto_kem` key (HKDF-SHA256, RFC 9180
  DHKEM(P-256) labels), requested via `Atproto-Space-Want-Mac` and returned in
  `Atproto-Space-Mac` (see §0, 2026-10-30 item 1 for the exact contexts).
  Deniability falls out of the shared secret: the syncer could have forged
  any MAC. Records are MACed the same way on `getRecord`.
- **STAR serialization** (`getRepo`, migration): magic + DRISL metadata
  (`$type: atproto-space-repo`, commit fields) + varint-framed
  `{collection}/{rkey}` → DRISL record pairs in strict key-byte order.
  Streams verifiably: validate metadata + commit MAC → fold each record into
  a running LtHash → compare to `data` at EOF.

### Auth model (three token types + a new scope family)

- **Delegation token** — minted by the user's PDS
  (`com.atproto.space.getDelegationToken`, requires a `read` grant), JWT
  `typ: atproto-space-delegation+jwt`, `kid` MUST be `#atproto`, signed by the
  account signing key. `sub` = space URI, `aud` = `{spaceDid}#atproto_pds`,
  single-use, ~60 s (`aud` = `{spaceDid}#atproto_pds`). No `lxm` (deliberately not interchangeable with service
  auth).
- **Client attestation** — only when a space requires it (`allowedApps`). JWT
  `typ: atproto-client-attestation+jwt`, `iss`=`sub`=`client_id`, verified by
  resolving the client metadata JWKS. Structurally a `private_key_jwt`
  assertion aimed at the space host.
- **Space credential** — minted by the space authority
  (`com.atproto.space.getSpaceCredential`) on request; the body carries
  `credentialKid` (the P-256 `did:key` to bind) plus whichever of
  `delegationToken`/`clientAttestation` the space's policy requires — either,
  both, or neither (public spaces); no HTTP-layer auth. `typ:
  atproto-space-credential+jwt`, `kid` `#atproto`,
  `iss` = authority DID, `sub` = space URI, **no `aud`**, 10 min default /
  60 min max, multi-use
  across every repo host in the space. Verifiable offline against the
  authority's published key. **Key-bound, not bearer**: carries `cnf.kid` (the
  P-256 `did:key` from the mint-time signature) and is presented as
  `Authorization: Atproto-Space-Credential <credential>` +
  `Atproto-Space-Audience: <repo owner DID>` + an
  `atproto-space-credential` signature (`tag="atproto-space-credential"`) over
  `("authorization" "atproto-space-audience")` that every host MUST verify against `cnf.kid`
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
  the current commit (with its MAC header); the syncer compares `data`
  against its own running LtHash. Oplog is a transport optimization — droppable/compactable, reset on
  migration.
- **Full-state recovery** — `getRepo` (STAR archive) with streaming
  verification; or "healing" via `getLatestCommit` + `listRecords
  excludeValues` diff + selective `getRecord`.
- **Write notifications** — best-effort, no record data (just the repo's new
  `repoRev` + `data`). Repo host → space host `notifyWrite` is automatic
  (service auth, no registration; host retries transient failures); the space
  host validates the writer, sequences a per-space `spaceRev`, and forwards
  to syncers registered via `registerNotify` (space host only, space-credential
  auth, fixed-duration registrations withdrawn with `unregisterNotify`),
  carrying `spaceRev` + `prevSpaceRev`. A gap is the missed-notification
  signal; `listRepos` (writer set: `did`, `repoRev`, `data`, `spaceRev` —
  accounts that have written, never a member/reader list) with `cursor` =
  last processed `spaceRev` catches up, including after any downtime. Syncers
  then pull directly from repo hosts, never through the space host. The
  authority may exclude or rate-limit writers, and can drop one
  explicitly with `removeWriter`.
- **Credential revocation** — `notifyCredentialRevoked` (authority → repo
  hosts, service auth, by `jti`; hosts retain ≥ 60 min).
- **Space deletion** — authority stops issuing credentials, deletes all
  records in its own repo, and reliably delivers `notifySpaceDeleted` to
  registered syncers (retry transient failures, stop on permanent ones; it
  SHOULD retain a deletion record until each is notified or expired; syncers
  must delete their copies). The same type + skey may later be recreated. Members' repo hosts are **not** notified and keep the
  member's own records — they simply become unreadable to everyone else. The
  durable signal for a syncer that missed the notification is an explicit
  `SpaceDeleted` error on credential renewal; any other renewal failure says
  nothing about the space.

### Space policies (replacing `com.atproto.simplespace`, 2026-10-30)

A space's configuration is a `policy` object identified by `$type`; the
policy-agnostic lifecycle lives in `com.atproto.space`
(`createSpace`/`updateSpace`/`deleteSpace`/`getSpace`, `manage` grants for the
first three, `read_self` or a credential for `getSpace`). Every PDS MUST
support three baseline policies, all anchored on the creating user's DID:
`personalspace` (authority only), `memberspace` (member list with `read` +
`write` booleans; `publicRead`/`publicWrite`/`allowedApps`/`publishPolicy`/
`publishMembers`; `putMember`/`removeMember`/`listMembers` in
`com.atproto.memberspace`) and `managedspace` (`managingApp` + `publishPolicy`;
per-user decisions via `com.atproto.managedspace.checkUserAccess`, served by the
managing app with service auth from the authority, `access: read | write`, no
client on writes). The host MUST reject an unimplemented policy
(`UnsupportedPolicy`). Reads and writes stay independent: read access gates
minting a credential; write access gates whether the authority *tracks* the
writer and forwards `notifyWrite`. Changing `$type` discards the old policy's
state. Other policies are first-class but may live on bespoke space services.

### XRPC surface (all `com.atproto.space.*` unless noted)

| Group | Methods |
|---|---|
| Host | `getSpaceCredential` (request body: `credentialKid` + optional delegation token/attestation), `listRepos`, `removeWriter`, `getSpace`, `exportSpaceMeta` |
| Repo (read/sync) | `getRecord`, `listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`, `listRepoOps` |
| PDS | `getDelegationToken`, `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `clearRecords`, `listSpaces`, `createSpace`, `updateSpace`, `deleteSpace`, `importRepo`, `importSpaceMeta` |
| Notifications | `registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted`, `notifyCredentialRevoked` |
| `com.atproto.memberspace.*` | `putMember`, `removeMember`, `listMembers` |
| `com.atproto.managedspace.*` | `checkUserAccess` (served by managing app) |

The alpha lexicons pin this at **31 `com.atproto.space.*` + 5
`memberspace` + 2 `managedspace` + 1 `personalspace` schema files** (incl.
`defs` and the `policy` records); Custos serves ~35 of them as routes
(`checkUserAccess` is outbound-only for us, `defs`/`policy`/`member` are
records not endpoints) — each needing a `.bru` file under the bruno-parity gate.

### Lifecycle interactions

Migration is now specified (§0, 2026-10-30 item 8): `listSpaces` →
`exportSpaceMeta`/`importSpaceMeta` for authority spaces → `getRepo`/`importRepo`
+ `listBlobs` per space repo, with a fresh `#atproto_kem` key on the new host. Deactivation/deletion/takedown
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
| DID-doc handling for new `#atproto_kem` entry | `identity/` + did:web hosting + `getRecommendedDidCredentials` |
| Migration/import flows | `car_import.rs`, transfer surface (`/v1/transfer/*`) |

Since 2026-10-30 the repo format carries no signature: the serving path does
an ECDH + HKDF + HMAC with a PDS-held `#atproto_kem` private key (a new
dedicated key, not the ADR-0004 repo signing key). The only signature left in
the sync path is the credential, which the authority signs with its `#atproto`
key (ES256 for Custos; k256 stays verify-only for foreign authorities' ES256K
credentials). `crates/crypto` already has P-256 ECDH/HKDF/HMAC building
blocks to extend; no new asymmetric primitive is required.

What does **not** change: the public repo engine (MST), firehose, relay
crawling, and existing sync endpoints are untouched. Permissioned data never
rides `subscribeRepos`.

## 3. Gap analysis — the work, by layer

### W1. Crypto primitives (new, small — vectors published, start here)
- LtHash: 2048-byte state, BLAKE3-XOF expansion (dkLen = 2048), u16-LE lane
  add/sub mod 2^16 (~80 lines). New dep: `blake3`; `hmac`/`hkdf`/`sha2` as
  needed. Element format `{collection}/{rkey}/{cid}`.
- KEM + MAC (replaces the old deniable sign/MAC): ephemeral P-256 ECDH
  against an author's `#atproto_kem` key, RFC 9180 DHKEM(P-256) HKDF-SHA256
  shared-secret derivation (uncompressed `0x04||x||y` points, empty salt),
  commit MAC (`atproto-space-repo-v1` ctx with u16be-prefixed
  space/repo/rev, then `data`) and record MAC (`atproto-space-record-v1` ctx
  with u16be-prefixed URI, then CID bytes), constant-time verify, and the
  `Atproto-Space-Want-Mac`/`Atproto-Space-Mac` Structured Field Dictionary
  headers. Pin `kem.test.ts` / `mac.test.ts`.
- Home: `crates/crypto` (pure, no deps on repo-engine) or a sibling module in
  `repo-engine`; Functional Core either way. Pin the reference golden vectors
  from `packages/space/tests/` (empty digest `e5a00aa9…`, `one`+`two` digest
  `ae05cb6d…`, plus the credential, `http-signature`, `kem`, `mac`, STAR and
  space-meta-archive suites) alongside round-trip +
  property tests (order-independence, add/remove inverse, empty-state zero).

### W2. Permissioned repo store (new storage engine — the big one)
- No MST, so this is a DB-backed record store + incremental LtHash state +
  oplog, not an atrium extension. New tables (V048+): `spaces` (authority,
  type, skey, policy object + policy state, lifecycle), `space_repos` (account
  × space, rev, 2048-byte LtHash state, commit fields), `space_records` (path → CID + DAG-CBOR
  value), `space_repo_ops` (oplog: rev, collection, rkey, cid, prev; compaction
  window like `firehose_gc`), `space_members` (memberspace member list),
  `space_notify_registrations`, plus a `jti` replay table.
- STAR-lite v1 writer/streaming parser for `getRepo`, `importRepo` and the
  space meta archive (`exportSpaceMeta`/`importSpaceMeta`): metadata map,
  strict key-order and 1 MiB record limit, whole-archive reject. The existing
  CAR framing helpers no longer apply here.
- A per-account `#atproto_kem` keypair (storage + rotation) and `clearRecords`
  (empty-digest commit, writer-set membership kept, optional GC of empty
  repos after a grace period).
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
- Token issuance/verification: delegation tokens (mint, single-use, 60 s, `aud` `…#atproto_pds`, sent in
  the `getSpaceCredential` body), space credentials (mint as authority —
  copying the request's `credentialKid` P-256 `did:key` into `cnf.kid`, signed
  with `#atproto`, 10 min default / 60 min cap, optionally with no delegation
  token or attestation when the policy requires neither; verify as repo host
  against the authority's `#atproto` key — **plus** the
  `Atproto-Space-Credential` scheme check (case-insensitive scheme, signature
  base over the header as received): `Authorization` + `Atproto-Space-Audience`,
  exact covered-component list `("authorization" "atproto-space-audience")`,
  `tag="atproto-space-credential"`, signature verified against
  `cnf.kid` with `ecdsa-p256-sha256`, audience equal to the request-derived
  repo DID — and rejection of `jti`s revoked via `notifyCredentialRevoked`),
  client attestations (resolve client metadata JWKS — SSRF-hardened client
  mandatory; optional per space, so the mint path must tolerate its absence
  cleanly, and must not reject a valid assertion the space does not require). As a *syncer/client* (e.g. tooling), mint an ephemeral P-256
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

### W4. XRPC surface (~35 routes)
One file per route per the route-isolation rule; queries in `db/`, auth in
`auth/`; register in `app.rs`; one `.bru` each (bruno-parity). Groups: PDS
CRUD + `listSpaces` + `getDelegationToken`; repo read/sync (`getRecord`,
`listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`,
`listRepoOps`); host (`getSpaceCredential`, `listRepos`); notifications
(`registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted`,
`notifyCredentialRevoked`); space lifecycle (`createSpace`/`updateSpace`/`deleteSpace`/`getSpace`),
`memberspace` (`putMember`/`removeMember`/`listMembers`), `clearRecords`,
`removeWriter`, and migration (`importRepo`, `exportSpaceMeta`,
`importSpaceMeta`). `checkUserAccess` (now `com.atproto.managedspace`) is *outbound* from
Custos-as-authority (inbound only if we ever ship a managing app). The alpha
lexicons (`lexicons/com/atproto/{space,memberspace,managedspace,personalspace}/` on the
`permissioned-data` branch) are the schema source of truth to codegen or
hand-mirror.

### W5. Space-host role
Credential issuance policy engine (the three baseline policies —
`personalspace`, `memberspace` with `publicRead`/`publicWrite`/`allowedApps`,
`managedspace` — authority always authorized, `allowedApps` on reads only;
`UnsupportedPolicy` on create/update; policy-state discard on `$type` change;
`publishPolicy`/`publishMembers` mirror records in the authority's repo with
direct writes rejected), key-binding at mint time (`credentialKid` →
`cnf.kid`), writer-set tracking gated on write authorization, `removeWriter` and fed by notifications + own writes, per-space `spaceRev`
sequencing with `prevSpaceRev` on forwarded notifications, `listRepos`
`cursor` = `spaceRev` catch-up, notification fan-out worker with retries and
registration expiry (`registerNotify`/`unregisterNotify`), rejection of
non-increasing or future `repoRev`, optional `notifyCredentialRevoked` fan-out
(authority's discretion), space deletion flow (stop issuing, delete all
records in own repo, *reliably* notify registered syncers with retry and a
retained deletion record until each is notified or expired, answer renewals
with `SpaceDeleted`; members' data stays put and simply becomes unreadable to
others; same type + skey may be recreated; account deletion cascades to its
spaces). The repo-host side needs no authority auto-registration: it just
pushes `notifyWrite` to the space host, retrying transient failures.

### W6. Identity
Publish a per-account `#atproto_kem` P-256 `Multikey` verification method
(PLC ops via the wallet-signed rotation surface; did:web hosting), surface it
in `getRecommendedDidCredentials`, and resolve other authors' `#atproto_kem`
keys when acting as a syncer. The `#atproto_space` / `#atproto_space_host`
entries (and their fallback rules) no longer exist: the space host is just
`#atproto_pds`. KEM rotation is a DID-doc replacement and must not disturb
repo hashes or revs; a migration to a new host publishes that host's key.

### W7. Lifecycle & migration
Deactivation/suspension/takedown checks on every space read/write path;
account deletion cascades; migration per the now-specified flow (§0, 2026-10-30 item 8):
`listSpaces`, `exportSpaceMeta`/`importSpaceMeta` before the authority's own
repo, then `getRepo`/`importRepo` (STAR) + `listBlobs`; a fresh `#atproto_kem`
key; whole-archive scope rejection; registrations, revocations and deletion
tombstones not carried over; oplog reset semantics on migration.

Two corrections from building it. **`/v1/transfer/*` is not the migration
surface** — those routes are the planned *device* swap and move no repo data;
the flows migration actually extends are `checkAccountStatus`, `importRepo`,
and the account activate/deactivate pair. And **until 2026-10-30 the alpha
lexicons defined no space import endpoint**, so Custos built
`POST /v1/space/import-repo` on its `/v1/*` surface rather than squat a
namespace the spec might fill differently. The spec has now filled it:
`com.atproto.space.importRepo` (STAR body, per-collection `create` scope) plus
`exportSpaceMeta`/`importSpaceMeta`. The bespoke route (CAR-based, MM-517)
needs to be re-pointed or aliased, not extended. Oplog reset needed no
code: the new host's oplog simply starts empty, and a syncer reconnecting with
a `since` from the old host folds to a set hash the new head does not match —
already the signal to heal with a full `getRepo`.

### W8. Ops, tooling, product surface (follow-on)
Rate limiting keyed by space credential; metrics; admin-companion moderation
surface for hosted spaces (takedown/refuse-to-serve); Bruno collection;
interop CLI scenarios against the reference alpha; MCP tools
(`tools/mcp`) for agent access to spaces; identity-wallet consent UX for
`space:` scopes; NixOS/Railway config for any new env vars.

Also deferred (MM-527), **reframed 2026-10-30**: the per-serving *signature*
is gone — serving now costs an ECDH + HKDF + HMAC against the author's
`#atproto_kem` private key, which is still loaded from the DB per request, so
the analysis below holds for the KEM key with a cheaper operation in place of
ECDSA. Original framing: benchmark per-serving commit signing, then decide
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
   crypto (LtHash, then KEM/MAC — the deniable sign/MAC of earlier weeks is gone) + `space:` scope grammar (parse/normalize/display only). Pure,
   testable against the published golden vectors, and the part of the spec
   least likely to move.
2. **Phase 1 — personal spaces (authority = self):** W2 store + PDS CRUD/read
   routes + delegation token + key-bound (`cnf.kid`) credential mint where PDS is both
   roles + `personalspace`/`memberspace` policies + consent UI. Delivers the
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
3. **Phase 2 — shared spaces & sync:** oplog + `listRepoOps`, STAR
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
  HTTP Message Signatures, the notification topology was reworked, and on
  10-30 the commit signature was replaced by a KEM/MAC, the repo
  serialization by STAR, and `simplespace` by pluggable policies. Code written
  to the 10-16 contract (e.g. `signedCommit`, two-root CAR, `#atproto_space*`
  entries, the mint-time signature) needs real rework — so a module built against a prior week's wire
  contract can need real rework, not a tweak.
  Mitigation: re-diff the proposals repo before each implementation slice, and
  interop-test against the hosted alpha PDS + TS SDK continuously.
- ~~No published test vectors~~ **Resolved**: golden vectors and full test
  suites ship in `packages/space/tests/` on the `permissioned-data` branch.
- **Per-request MAC derivation** puts a `#atproto_kem` key load + ECDH +
  HKDF + HMAC on the serving path of every sync response and a fresh syncer
  keypair per request/page (so no MAC reuse across pages); needs a benchmark
  and possibly an in-memory decrypted-key cache with zeroization (MM-527).
- **KEM key custody and rollout.** A new per-account key must be generated,
  stored KEK-wrapped like the repo keys, published in the DID doc, and
  rotated/re-published on migration; until a syncer sees the new DID doc its
  MAC checks fail (spec: refresh and retry).
- **Migration scope breadth.** `importRepo`/`importSpaceMeta` reject whole
  archives the granted `space:` scope doesn't cover, so migrating every space
  takes very broad scopes; the wallet/consent UX for that is unsolved.
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
  PDS-required surface (the baseline `personalspace`/`memberspace`/`managedspace` policies) plus repo-host/space-host roles.

## 6. Rough size

Comparable to Wave 2 (Auth) + Wave 4 (Repo/Blobs) combined: a new storage
engine, ~35 routes, a scope-grammar extension, three token types (all
key-bound or single-use), and a notification subsystem — plus ~35 `.bru`
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
| MM-506 | 0 | Spaces crypto primitives: LtHash (BLAKE3-XOF, 1024×u16 lanes) + KEM shared-secret + commit/record MAC (and `Atproto-Space-*Mac` header codec) in `crates/crypto`, pinned to the reference golden vectors; *re-scoped 2026-10-30 from the removed deniable sign/MAC* |
| MM-507 | 0 | `space:` OAuth scope grammar in `auth/oauth_scopes.rs`: parse/normalize/match/`intersect_scope_tokens` + `require_space` gates (no routes yet); permission-set `resource: "space"` entries |
| MM-508 | 1 | Permissioned repo store: migrations (`spaces` incl. policy + policy state, `space_repos` incl. LtHash state, `space_records`, `space_repo_ops`, `space_members`, notify registrations, `jti` replay, per-account `#atproto_kem` key) + `space_record_write` choke point + `clearRecords` |
| MM-509 | 1 | PDS record routes: `com.atproto.space.{createRecord,putRecord,deleteRecord,applyWrites,clearRecords,listSpaces,getRecord,listRecords,getLatestCommit}` + `.bru` files; `getRecord`/`getLatestCommit` answer with `Atproto-Space-Mac` per `Want-Mac` (blocked by MM-506/507/508) |
| MM-510 | 1 | Space auth: delegation-token mint (`aud` `…#atproto_pds`), key-bound space-credential mint/verify (`credentialKid` in the `getSpaceCredential` body → `cnf.kid`, `kid` `#atproto`, `Atproto-Space-Credential` scheme + RFC 9421 `atproto-space-credential` signature with `tag`, 10 min default / 60 min max, `jti` revocation list, delegation token/attestation optional), `auth::space::authenticate_space_read` seam + `just` seam gate (blocked by MM-507) |
| MM-511 | 1 | Space management surface (**re-scoped 2026-10-30**; `simplespace` removed): `com.atproto.space.{createSpace,updateSpace,deleteSpace,getSpace}` with `personalspace` + `memberspace` policies (`putMember`/`removeMember`/`listMembers`, `publicRead`/`publicWrite`, `publishPolicy`/`publishMembers`), `UnsupportedPolicy` rejection (blocked by MM-508) |
| MM-512 | 1 | Consent UI for `space:` scopes in `/oauth/authorize`: space-type declaration resolution (name, default collections), authority handle display, wildcard warnings (blocked by MM-507) |
| MM-513 | 2 | Sync surface: `listRepoOps` oplog (+compaction), STAR `getRepo` (strict key order, per-request MAC header), `listBlobs`, space blob refs + GC union (blocked by MM-509/510) |
| MM-514 | 2 | Space-host role: writer set + `removeWriter`, `registerNotify`/`unregisterNotify` (+expiry, space-host-only), `notifyWrite` ingest + `spaceRev`/`prevSpaceRev` fan-out, `listRepos` cursor catch-up, `notifyCredentialRevoked`, space deletion (reliable `notifySpaceDeleted`, retained tombstone, recreate) + `SpaceDeleted` renewal error (blocked by MM-510/511) |
| MM-515 | 2 | Identity: `#atproto_kem` DID-doc verification method (PLC + did:web), `getRecommendedDidCredentials`, KEM key resolve/rotate; *re-scoped 2026-10-30 — `#atproto_space*` entries removed* |
| MM-516 | 3 | Client attestation verification + `memberspace.allowedApps`; `managedspace` policy with outbound `checkUserAccess` (`access` param) (blocked by MM-510/511) |
| MM-517 | 3 | Lifecycle & migration: spec'd flow (`listSpaces`, `exportSpaceMeta`/`importSpaceMeta`, `getRepo`/`importRepo` STAR, `listBlobs`; re-point the bespoke `/v1/space/import-repo`), deactivation/takedown propagation on space paths (blocked by MM-513) |
| MM-518 | 3 | Tooling & interop: Bruno collection, interop CLI scenarios vs the alpha (hosted sandbox PDS + TS SDK as client), MCP tool surface, browser-harness coverage (blocked by MM-509) |

A weekly routine watches the alpha's Thursday releases and PRs spec-delta
updates to this doc — see
[`docs/operations/spaces-alpha-watch-routine.md`](../operations/spaces-alpha-watch-routine.md).
