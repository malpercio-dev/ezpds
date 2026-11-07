# Atproto Spaces (proposal 0016, née Permissioned Data) — Custos Gap Analysis

**Date:** 2026-07-17 · **Revised:** 2026-08-20 (official alpha release) · 2026-09-04, 2026-09-11, 2026-10-16, 2026-11-06 (weekly watch)
**Status:** Research / gap analysis — updated for the alpha; implementation green-lit for Phase 0
**Sources:**
- [0016 proposal](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) (canonical; kept in sync with the reference implementation as of the alpha; last diffed against commit `9e86df3`)
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

### 2026-10-23 and 2026-10-30 weekly watches (folded into the 2026-11-06 entry)

Two earlier watch runs diffed the same moving target in smaller steps; their
findings are subsumed by the 2026-11-06 entry below, which is the one to read.
Only what that entry does not restate is kept here.

- **2026-10-23** (proposals `c76714a`…`b89d0b0`, atproto `3a0b8c6`; schema set
  still 21 `space` + 9 `simplespace`): the release-10-22 batch (#114, #120,
  #122, #123, #124) introduced the KEM-keyed MAC, STAR, the simplified DID
  resolution, the reshaped `getSpaceCredential` and the reliable
  `notifySpaceDeleted`; `packages/space/` gained `kem.ts`, `mac.ts` and
  `star.ts`. The `getSpaceCredential` error set at that point was
  `SpaceNotFound`, `SpaceDeleted`, `UserNotAuthorized`, `AppNotAuthorized`,
  `NotAuthorized`, `InvalidDelegationToken` and `InvalidClientAttestation`.
  The proposal's comparison table changed from "Signature / Deniable on
  rebroadcast" to "Commit authenticity: Signature vs HMAC".
- **2026-10-30** (proposals `c76714a`…`701ef9c`, atproto `d009736`; 31 `space`
  + 5 `memberspace` + 2 `managedspace` + 1 `personalspace` = 39 files,
  `simplespace` gone): the release-10-29 batch added the policy model (#119),
  `clearRecords` (#127), `removeWriter` (#128) and migration (#129).
  `kem.test.ts` carries an RFC 9180-derived P-256 vector, which is the one to
  pin for the KEM primitive.

### 2026-11-06 weekly watch (proposals repo, commits `c76714a`…`9e86df3`)

The largest single-week rewrite since the alpha: fifteen commits (PRs #114,
#119, #120, #122, #123, #124, #127, #128, #129, #131, #134, plus follow-up
tweaks; the #133 lexicon refactor was landed and then reverted in #135).
Re-verified against `permissioned-data` @ `a620ad3`: **31
`com.atproto.space.*`** schema files (incl. `defs` and the new `policy`
record), **5 `memberspace`, 2 `managedspace`, 1 `personalspace`**, and the
`com.atproto.simplespace` namespace is **gone**. The golden LtHash digests
are unchanged (`e5a00aa9…`, `ae05cb6d…`); `packages/space/src/` gained
`kem.ts` and `space-meta-archive.ts` and the old signed-commit/`ikm` tests
were replaced by `kem.test.ts`/`mac.test.ts`/`repo-commit.test.ts`. Several
items below **supersede** items in the 2026-10-16 entry and §1 text that has
been rewritten to match.

1. **Commit authenticity: signature + `ikm` is gone, replaced by a KEM-derived
   shared secret and a plain MAC (PRs #122, #123).** Commits no longer carry
   `sig`/`ikm`/`mac` and `signedCommit` is renamed **`commit`**
   (`{ver: 1, repo, space, rev, data}`; `hash` became **`data`**,
   `sha256` of the LtHash state; the wire field in `notifyWrite`,
   `listRepos`, and the `getRepo` metadata follows). Authenticity moves to an
   HTTP header pair: the syncer sends `Atproto-Space-Want-Mac: type=…, ver=1,
   key_share="did:key:…"` (a fresh ephemeral P-256 key per request, including
   retries and each page); the repo host does ECDH against its **`#atproto_kem`**
   key and returns `Atproto-Space-Mac` (base64 32-byte MAC) with
   `Vary: Atproto-Space-Want-Mac`. `shared_secret` = HKDF-SHA256 over the ECDH
   x-coordinate using the RFC 9180 §4.1 DHKEM(P-256) labels (`HPKE-v1` `KEM`
   `0x0010`, `eae_prk`, `shared_secret`, uncompressed `0x04||x||y` of syncer
   then author keys). Commit MAC =
   `HMAC-SHA256(shared_secret, "atproto-space-repo-v1" || u16be-prefixed(space,
   repo, rev) || data)`; record MAC (`getRecord`, `type="atproto-space-record"`)
   = `HMAC-SHA256(shared_secret, "atproto-space-record-v1" ||
   u16be-prefixed(uri) || record_cid_bytes)`. **The per-reader signature is
   gone entirely**: the commit is never signed and the user's `#atproto` key
   no longer participates; `listRepoOps` pages without the head commit carry
   no MAC header. A new **`#atproto_kem`** `Multikey` (P-256) verification
   method in the author's DID doc is required; the repo host holds the private
   key (should be dedicated, not the signing key); rotation = replace the DID
   entry, and a MAC failure means refresh the DID doc and retry with a fresh
   keypair. This removes the "per-reader commit signing" cost entirely
   (the MM-527 benchmark question is moot — a per-request ECDH + HMAC
   replaces KEK-decrypt + ECDSA) but adds a DID-doc key Custos must generate,
   store, publish and recommend.
2. **Space-authority resolution simplified (PR #123) — supersedes the
   2026-09-04 DID-doc items.** `#atproto_space` and `#atproto_space_host` are
   removed. The authority resolves like any account: `#atproto_pds` is the
   space host and `#atproto` signs credentials (credential `kid` MUST be
   `#atproto`; delegation-token and attestation `aud` become
   `{spaceDid}#atproto_pds`). No fallback logic, no
   malformed-entry-must-error rule for those entries.
3. **Credential request/presentation reworked (PR #120).**
   `getSpaceCredential` is now **unauthenticated at the transport level**:
   `{space, credentialKid, delegationToken?, clientAttestation?}` in the JSON
   body, with `credentialKid` the P-256 `did:key` to bind as `cnf.kid`. The
   `Authorization: Bearer` + `atproto-space` signature mint-time proof is
   gone (the key is simply asserted; possession is proven on first use). The
   delegation token and client attestation are each **optional, required only
   when the space's policy asks**. Presentation moves to
   `Authorization: Atproto-Space-Credential <credential>` (scheme matched
   case-insensitively; the signature base uses the field value exactly as
   received) with signature label **`atproto-space-credential`** over
   `("authorization" "atproto-space-audience")` and a required
   `tag="atproto-space-credential"` parameter that hosts MUST check.
4. **Public spaces (PR #120).** A `memberspace` with `publicRead: true`
   requires no delegation token: the authority mints a credential for any
   requester (syncers read without acting for a user), still honouring
   `allowedApps` (then a client attestation is required). `publicWrite: true`
   tracks any account's writes in `listRepos`. Credentials are still required
   to read.
5. **`simplespace` is dissolved into pluggable policies (PR #119).** The
   per-PDS management surface is now policy-agnostic:
   `com.atproto.space.{createSpace,updateSpace,deleteSpace,getSpace,
   exportSpaceMeta,importSpaceMeta}` take a full **`policy`** object
   (`$type`-discriminated; `updateSpace` replaces it wholesale; unsupported
   `$type` → `UnsupportedPolicy`). Every PDS MUST support three baseline
   policies: `com.atproto.personalspace.policy` (authority only, no config),
   `com.atproto.memberspace.policy` (`publicRead`, `publicWrite`,
   `allowedApps` — replaces `appAccess`/`#allowList` — `publishPolicy`,
   `publishMembers`; methods `putMember`, `removeMember`, `listMembers`), and
   `com.atproto.managedspace.policy` (`managingApp`, `publishPolicy`;
   `checkUserAccess` served by the managing app). `readPolicy`/`writePolicy`
   and `appAccess` no longer exist; `public` = the `publicRead`/`publicWrite`
   flags, `managing-app` = its own policy type. The authority's own account is
   always authorized for read and write. `manage=update` covers
   `updateSpace`, memberspace `putMember`/`removeMember`, and
   `removeWriter` under every policy. **Publishing to readers:** with
   `publishPolicy`/`publishMembers` set, the PDS mirrors the policy
   (`com.atproto.space.policy`/`self`) and member list
   (`com.atproto.memberspace.member`/`<did>`) as records in the authority's
   own space repo; the config stays authoritative, repo CRUD must reject
   direct writes to those collections, and `clearRecords` leaves them.
6. **Repo format: CAR → STAR (PR #114, #131).** `getRepo` now returns a
   **STAR archive** (`dasl.ing/star`): magic `2A 6C 01 00`, a DRISL metadata
   map (`$type: "atproto-space-repo"` + all commit fields; the MAC rides the
   response header, not the body), then `0x01 len path len record` pairs in
   **strict bytewise key order**, `0x00` terminator. There is no longer a
   separate index root: the syncer folds `{path}/{record_cid}` into the
   LtHash as it streams and checks `sha256(state)` against `data`, rejecting
   the whole archive on parse error, non-canonical metadata, duplicate or
   out-of-order key, MAC mismatch, or digest mismatch. Archive limits:
   64 KiB metadata, 4 KiB key, 1 MiB value. The canonical-DAG-CBOR-index
   ordering rule from the August entry is obsolete. `record_cid` is now
   specified as a DASL CID over DRISL-encoded bytes.
7. **New `clearRecords` (PR #127) and repo lifecycle changes.**
   `com.atproto.space.clearRecords` deletes every record in the caller's repo
   in a space, advances `rev`, and yields the empty digest
   `e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad`; it
   clears the oplog and notifies the space host. A host MAY garbage-collect
   an empty repo after a grace period (it must stay long enough to propagate
   the clear); it then behaves as nonexistent.
8. **New `removeWriter` (PR #128).** `com.atproto.space.removeWriter`
   (OAuth `manage=update`) drops an account from the writer set; the account
   is re-added if it later makes an authorized write (immediately, under
   `publicWrite`). `memberspace` `removeMember` / write-revoking `putMember`
   SHOULD also remove the writer.
9. **Account migration specified (PR #129).** New
   `com.atproto.space.importRepo` (OAuth, `create` on every collection in the
   archive; whole-archive reject if the scope doesn't cover it) imports a
   STAR repo; new `exportSpaceMeta`/`importSpaceMeta` move an authority's
   host-side state as an `atproto-space-meta` STAR archive (metadata
   `{$type, ver, space}`; body: `policy`, then policy-state keys such as
   `com.atproto.memberspace.member/<did>`, then `writer/<did>` entries
   carrying `rev`, `data`, `spaceRev`; strict ordering within sections;
   reject unknown policy-state keys). Flow: `listSpaces` → for each
   authority space `exportSpaceMeta`→`importSpaceMeta` **before** its repo
   → per repo `getRepo`→`importRepo` + blobs via `listBlobs`. The new host
   mints its own `#atproto_kem` key and may re-`rev` an imported repo
   (`data` unchanged). Registrations, credential revocations and deletion
   tombstones are not migrated. A taken-down account can still export via
   `listSpaces`, `exportSpaceMeta`, `getRepo`, `listBlobs`, `getBlob`.
   **This fills the gap the 2026-08 notes recorded** ("the alpha lexicons
   define no space import endpoint"): Custos's `POST /v1/space/import-repo`
   should converge on `com.atproto.space.importRepo`.
10. **Space deletion hardening (PR #124).** The authority must reliably
    deliver `notifySpaceDeleted` (retry transient failures, stop on permanent
    ones) and SHOULD retain a deletion record until each registered syncer is
    notified or its registration expires. Deleting the authority account
    deletes its spaces. An authority MAY recreate a deleted space with the
    same type/`skey`; members' surviving records become readable again under
    the new policy. A taken-down/deactivated authority *suspends* (not
    deletes) its spaces: `getSpaceCredential`/`listWriters` answer
    `RepoTakendown`/`RepoDeactivated`, issued credentials stay valid to
    expiry. Repo methods answer taken-down/deactivated repos with
    `RepoTakendown`/`RepoDeactivated`, as `com.atproto.sync.*` does.
11. **`listSpaces` now includes spaces the caller is the authority of**, not
    only those they hold a repo in. `listWriters` appears in the proposal's
    suspension text; check it against the lexicon set (the lexicons list
    `listRepos` and no `listWriters` file at `a620ad3`).

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
  Created implicitly by the first write; empty ≡ nonexistent; `clearRecords`
  empties it (the space itself survives, and a host MAY GC an empty repo
  after a grace period).
- **Roles:** *repo host* (serves a user's space repos) and *space host*
  (answers for the space: issues credentials, tracks writers, routes
  notifications). A PDS is both for accounts/spaces anchored on it.
- **Space authority DID** resolves like any account (2026-11-06): its
  `#atproto_pds` service is the space host and its `#atproto` key signs
  credentials. The dedicated `#atproto_space`/`#atproto_space_host` entries
  are gone. Separately, each repo author's DID doc carries a P-256
  `#atproto_kem` `Multikey` the repo host uses for commit/record MACs.
- **Space type declarations**: a new Lexicon shape, `"type": "space"`, with
  `key`, `name` (+ localized), `collections` (default collection set for
  scopes/consent; MUST NOT contain a wildcard `*`).

### Repo format (no MST)

- Commit digest = **LtHash** homomorphic multiset hash: 2048-byte state read
  as 1024 little-endian u16 lanes; each element is the UTF-8 of
  `{collection}/{rkey}/{record_cid}` expanded to 2048 bytes via **BLAKE3 XOF**;
  add/remove = lane-wise add/subtract mod 2^16. Commit carries
  `hash = sha256(state)` (32 bytes), hosts keep the full state.
- **Commit authenticity = MAC, no signature** (2026-11-06; supersedes the
  deniable signed commit). Commit `{ver: 1, repo, space, rev, data}` with
  `data = sha256(state)`. The syncer sends `Atproto-Space-Want-Mac` carrying a
  fresh ephemeral P-256 `did:key` (`key_share`); the repo host ECDHs it with
  the author's `#atproto_kem` private key, derives `shared_secret` with
  HKDF-SHA256 per RFC 9180 §4.1 (DHKEM P-256 labels), and returns
  `Atproto-Space-Mac`. Commit MAC =
  `HMAC-SHA256(shared_secret, "atproto-space-repo-v1" || u16be-len-prefixed(space,
  repo, rev) || data)`; record MAC (`getRecord`) covers the URI and CID bytes.
  Since the syncer could compute the MAC itself, a leaked commit proves
  nothing to a third party. See §0 (2026-11-06) item 1 for the full
  construction.
- **STAR serialization** (replaces the two-root CAR): DRISL metadata map
  (`$type: atproto-space-repo` + commit fields) then `path → record` pairs in
  strict bytewise key order, limits 64 KiB / 4 KiB / 1 MiB. Streams
  verifiably: check the header MAC → fold each `{path}/{cid}` into a running
  LtHash → compare `sha256(state)` to `data`.

### Auth model (three token types + a new scope family)

- **Delegation token** — minted by the user's PDS
  (`com.atproto.space.getDelegationToken`, requires a `read` grant), JWT
  `typ: atproto-space-delegation+jwt`, `kid` MUST be `#atproto`, signed by the
  account signing key. `sub` = space URI, `aud` = `{spaceDid}#atproto_pds`,
  single-use, ~60 s. No `lxm` (deliberately not interchangeable with service
  auth).
- **Client attestation** — only when a space's policy requires app identity
  (`memberspace.allowedApps`). JWT
  `typ: atproto-client-attestation+jwt`, `iss`=`sub`=`client_id`, verified by
  resolving the client metadata JWKS. Structurally a `private_key_jwt`
  assertion aimed at the space host.
- **Space credential** — minted by the space authority
  (`com.atproto.space.getSpaceCredential`, no transport auth) from a JSON body
  `{space, credentialKid, delegationToken?, clientAttestation?}`; the
  delegation token is required unless the policy allows public read, the
  attestation only when the policy gates on apps. `credentialKid` is the
  P-256 `did:key` bound as `cnf.kid`. `typ: atproto-space-credential+jwt`,
  `kid` MUST be `#atproto`, `iss` = authority DID, `sub` = space URI,
  **no `aud`**, 10 min default / 60 min max, multi-use across every repo host
  in the space. Verifiable offline against the authority's `#atproto` key.
  **Key-bound, not bearer**: presented as `Authorization:
  Atproto-Space-Credential <credential>` + `Atproto-Space-Audience: <repo
  owner DID>` + an RFC 9421 `atproto-space-credential` signature over
  `("authorization" "atproto-space-audience")` with
  `tag="atproto-space-credential"`, which every host MUST verify against
  `cnf.kid` (no method/URI binding; replay against the same audience is
  allowed until expiry). Syncers mint an ephemeral keypair per credential.
  Short expiry is the primary revocation mechanism;
  `notifyCredentialRevoked` (by `jti`) is the optional fast path.
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
  the current commit (with its `Atproto-Space-Mac` header); the syncer
  verifies the MAC and compares `data` against its own running LtHash. Oplog is a transport optimization — droppable/compactable, reset on
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
  authority may exclude or rate-limit writers, or drop one explicitly with
  `removeWriter`.
- **Credential revocation** — `notifyCredentialRevoked` (authority → repo
  hosts, service auth, by `jti`; hosts retain ≥ 60 min).
- **Space deletion** — authority stops issuing credentials, deletes all
  records in its own repo, and reliably delivers `notifySpaceDeleted` to
  registered syncers (retry transient failures; keep a deletion record until
  each is notified or its registration expires; syncers must delete their
  copies). Members' repo hosts are **not** notified and keep the
  member's own records — they simply become unreadable to everyone else. The
  durable signal for a syncer that missed the notification is an explicit
  `SpaceDeleted` error on credential renewal; any other renewal failure says
  nothing about the space.

### Space policies and required PDS management (2026-11-06)

`com.atproto.simplespace` no longer exists. Space management is
policy-agnostic: `createSpace` / `updateSpace` / `deleteSpace` / `getSpace` /
`exportSpaceMeta` / `importSpaceMeta` live under `com.atproto.space` and take
a `$type`-discriminated **`policy`** object (unsupported `$type` →
`UnsupportedPolicy`; `updateSpace` replaces it wholesale and a `$type` change
discards the old policy's state). Every PDS MUST support three baseline
policies, each anchored on the creating user's DID; the authority's own
account is always authorized for read and write:

| Policy | Access decided by | Config / methods |
|---|---|---|
| `com.atproto.personalspace.policy` | authority only | none |
| `com.atproto.memberspace.policy` | PDS-held member list (`read` + `write` booleans per DID) | `publicRead`, `publicWrite`, `allowedApps` (attested `client_id` allow-list, reads only), `publishPolicy`, `publishMembers`; `putMember`, `removeMember`, `listMembers` (`read_self`) |
| `com.atproto.managedspace.policy` | external managing app per user (`checkUserAccess`, `access: read \| write`, service-auth from the authority; no client on write checks) | `managingApp`, `publishPolicy` |

Read access gates credential minting; write access gates whether the
authority tracks the writer in `listRepos` and forwards their `notifyWrite`
— it never blocks an account writing to its own repo. `publishPolicy` /
`publishMembers` mirror state as records in the authority's own repo (config
remains the source of truth; reject direct CRUD on those collections).
Management procedures need the relevant `manage` grant (`manage=update` also
covers `removeWriter` under every policy). Other policies are first-class but
may live on bespoke space services, not the PDS.

### XRPC surface (all `com.atproto.space.*` unless noted)

| Group | Methods |
|---|---|
| Host | `getSpaceCredential` (JSON body, no transport auth), `listRepos`, `removeWriter` |
| Repo (read/sync) | `getRecord`, `listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo` (STAR), `listRepoOps` |
| PDS | `getDelegationToken`, `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `clearRecords`, `importRepo`, `listSpaces`, `createSpace`, `updateSpace`, `deleteSpace`, `getSpace`, `exportSpaceMeta`, `importSpaceMeta` |
| Notifications | `registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted`, `notifyCredentialRevoked` |
| `com.atproto.memberspace.*` | `putMember`, `removeMember`, `listMembers` |
| `com.atproto.managedspace.*` | `checkUserAccess` (served by the managing app) |

The alpha lexicons pin this at **31 `com.atproto.space.*` + 5
`memberspace` + 2 `managedspace` + 1 `personalspace` schema files** (incl.
`defs` and the `policy` records); Custos serves ~30 of them as routes
(`checkUserAccess` is outbound-only for us, `defs`/`policy` are not
endpoints) — each needing a `.bru` file under the bruno-parity gate.

### Lifecycle interactions

Migration must enumerate **all** of an account's space repos (via
`listSpaces`) + blobs (via `listBlobs`), move each authority space's meta
archive (`exportSpaceMeta`/`importSpaceMeta`, before the repo) and each repo
(`getRepo`/`importRepo`), and publish a fresh `#atproto_kem` key on the new
host. Takedown/deactivation of a member answers `RepoTakendown`/
`RepoDeactivated` but must still allow export; of an authority, suspends its
spaces. Deactivation/deletion/takedown
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
| Archive framing | CAR helpers in `repo-engine::car_export` no longer fit — `getRepo` is now a STAR archive (varint-framed `path → record` pairs); the framing is new, small code |
| Key binding of space credentials (`cnf.kid`, RFC 9421 `atproto-space` signatures) | **Not covered by the OAuth DPoP stack any more** — `auth/dpop.rs` stays OAuth-only. Reusable pieces: P-256 `did:key` parse/verify (`crypto::verify_did_key_signature`; raw `r‖s`, accept high-S) and the `Authorization`-scheme dispatch in `auth/extractors.rs`. The RFC 9421 `Signature-Input`/`Signature` parsing (exactly-one-label, exact covered-component list) is new code |
| Single-use `jti` replay protection (delegation tokens, attestations) | DPoP nonce-store pattern (`auth/dpop.rs`); no longer needed on the sync path, which has no per-request replay check |
| Background fan-out workers | `crawler.rs` / `firehose_gc.rs` / sweep patterns |
| Ownership/lifecycle modeling | `accounts` lifecycle states, `blob_owners`/`block_owners` per-account ownership rows |
| DID-doc handling for the new `#atproto_kem` entry | `identity/` + did:web hosting + `getRecommendedDidCredentials` |
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
- KEM/MAC: ephemeral-key ECDH on P-256 → RFC 9180 §4.1 DHKEM
  `shared_secret` (HKDF-SHA256, uncompressed-point `keys`), commit MAC and
  record MAC (`HMAC-SHA256(shared_secret, context || data|cid)`, u16be
  length-prefixed context), `Atproto-Space-Want-Mac` / `Atproto-Space-Mac`
  header codecs (Structured Field Dictionary), verify path. Replaces the
  signed-commit `ctx`/`ikm`/`sig` code (no per-commit signature remains).
- Home: `crates/crypto` (pure, no deps on repo-engine) or a sibling module in
  `repo-engine`; Functional Core either way. Pin the reference golden vectors
  from `packages/space/tests/` (empty digest `e5a00aa9…`, `one`+`two` digest
  `ae05cb6d…`, plus the `kem`/`mac`/`repo-commit`/`credential` suites,
  `http-signature.test.ts` and `space-meta-archive.test.ts`) alongside round-trip +
  property tests (order-independence, add/remove inverse, empty-state zero).

### W2. Permissioned repo store (new storage engine — the big one)
- No MST, so this is a DB-backed record store + incremental LtHash state +
  oplog, not an atrium extension. New tables (V048+): `spaces` (authority,
  type, skey, config, policy, lifecycle), `space_repos` (account × space, rev,
  2048-byte LtHash state, commit `data`), `space_records` (path → CID + DAG-CBOR
  value), `space_repo_ops` (oplog: rev, collection, rkey, cid, prev; compaction
  window like `firehose_gc`), `space_members` (memberspace member list + `policy` object per space),
  `space_notify_registrations`, plus a `jti` replay table.
- STAR serializer/parser (DRISL metadata + strictly ordered `path → record`
  pairs, size limits) for `getRepo` and `importRepo`; the same framing carries
  the `atproto-space-meta` archive for `exportSpaceMeta`/`importSpaceMeta`.
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
  presented in the `getSpaceCredential` JSON body), space credentials (mint
  as authority from `credentialKid`, which becomes `cnf.kid`, 10 min default /
  60 min cap, `kid` `#atproto`, delegation token required unless the policy
  allows public read; verify as repo host against the authority's `#atproto`
  key **plus** the `Atproto-Space-Credential` scheme check (case-insensitive
  scheme, signature base over the field as received): `Authorization` +
  `Atproto-Space-Audience`, exact covered-component list
  `("authorization" "atproto-space-audience")`, `tag="atproto-space-credential"`,
  signature verified against `cnf.kid` with `ecdsa-p256-sha256`, audience
  equal to the request-derived repo DID — and rejection of `jti`s revoked via
  `notifyCredentialRevoked`),
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

### W4. XRPC surface (~30 routes)
One file per route per the route-isolation rule; queries in `db/`, auth in
`auth/`; register in `app.rs`; one `.bru` each (bruno-parity). Groups: PDS
CRUD + `listSpaces` + `getDelegationToken`; repo read/sync (`getRecord`,
`listRecords`, `getBlob`, `listBlobs`, `getLatestCommit`, `getRepo`,
`listRepoOps`); host (`getSpaceCredential`, `listRepos`, `removeWriter`);
PDS additions `clearRecords`, `importRepo`, `exportSpaceMeta`,
`importSpaceMeta`; notifications
(`registerNotify`, `unregisterNotify`, `notifyWrite`, `notifySpaceDeleted`,
`notifyCredentialRevoked`); policy-agnostic `createSpace`/`updateSpace`/
`deleteSpace`/`getSpace` plus memberspace `putMember`/`removeMember`/
`listMembers`. Every route that returns a commit or record also implements
the `Atproto-Space-Want-Mac` → `Atproto-Space-Mac` exchange. `checkUserAccess` is *outbound* from
Custos-as-authority (inbound only if we ever ship a managing app). The alpha
lexicons (`lexicons/com/atproto/{space,memberspace,managedspace,personalspace}/` on the
`permissioned-data` branch) are the schema source of truth to codegen or
hand-mirror.

### W5. Space-host role
Credential issuance policy engine (`personalspace` / `memberspace`
(`publicRead`, `publicWrite`, `allowedApps` applied to reads only,
`publishPolicy`/`publishMembers` mirroring) / `managedspace`; rejecting
unimplemented policy `$type`s with `UnsupportedPolicy` at create/update),
key-binding at mint time (`cnf.kid`), writer-set tracking gated on
`writePolicy` and fed by notifications + own writes, per-space `spaceRev`
sequencing with `prevSpaceRev` on forwarded notifications, `listRepos`
`cursor` = `spaceRev` catch-up, notification fan-out worker with retries and
registration expiry (`registerNotify`/`unregisterNotify`), `removeWriter`, rejection of
non-increasing or future `repoRev`, optional `notifyCredentialRevoked` fan-out
(authority's discretion), space deletion flow (stop issuing, delete all
records in own repo, reliably notify registered syncers and retain a
deletion record until they are notified or expire, answer renewals with
`SpaceDeleted`; members' data stays put and simply becomes unreadable to
others). The repo-host side needs no authority auto-registration: it just
pushes `notifyWrite` to the space host, retrying transient failures.

### W6. Identity
Generate, store and publish a dedicated P-256 **`#atproto_kem`** `Multikey`
per account in its DID doc (PLC ops via the wallet-signed rotation surface;
did:web hosting) and surface it in `getRecommendedDidCredentials`; resolve
other authors' `#atproto_kem` keys when acting as a syncer, refreshing the DID
doc on MAC failure. The `#atproto_space`/`#atproto_space_host` entries and
their fallback rules no longer exist — the authority resolves via
`#atproto_pds` and `#atproto`. KEM-key rotation does not change repo hashes
or revisions.

### W7. Lifecycle & migration
Deactivation/suspension/takedown checks on every space read/write path;
account deletion cascades; migration enumeration of all (space, repo, blobs)
— extends the `/v1/transfer/*` flows and `importRepo`; oplog reset semantics
on migration.

Two corrections from building it. **`/v1/transfer/*` is not the migration
surface** — those routes are the planned *device* swap and move no repo data;
the flows migration actually extends are `checkAccountStatus`, `importRepo`,
and the account activate/deactivate pair. And **the alpha lexicons defined no
space import endpoint** (as of 2026-10-16 they were export-only on the
repo-read side), so Custos served `POST /v1/space/import-repo` on its `/v1/*`
surface rather than squatting a namespace the spec might fill differently.
As of 2026-11-06 the spec fills it (`com.atproto.space.importRepo`,
`exportSpaceMeta`/`importSpaceMeta`, STAR archives — §0), so that route should
be reworked to the spec'd shape and the authority-meta half added. Oplog reset needed no
code: the new host's oplog simply starts empty, and a syncer reconnecting with
a `since` from the old host folds to a set hash the new head does not match —
already the signal to heal with a full `getRepo`.

### W8. Ops, tooling, product surface (follow-on)
Rate limiting keyed by space credential; metrics; admin-companion moderation
surface for hosted spaces (takedown/refuse-to-serve); Bruno collection;
interop CLI scenarios against the reference alpha; MCP tools
(`tools/mcp`) for agent access to spaces; identity-wallet consent UX for
`space:` scopes; NixOS/Railway config for any new env vars.

The deferred MM-527 benchmark (per-serving commit signing) is **moot as of
2026-11-06**: commits are no longer signed. The per-reader cost becomes one
ECDH + HKDF + HMAC with the repo host's `#atproto_kem` private key per
request — still a key load per sync call, so the single-connection-pool
serialization concern stands if the key is read from the DB each time, but
there is no ECDSA and the question reduces to how long the KEM key stays
resident.

## 4. Suggested phasing

1. **Phase 0 — primitives (started with the alpha, vector-pinned):** W1
   crypto + `space:` scope grammar (parse/normalize/display only). Pure,
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
   > *(2026-11-06: commits are now MAC'd with the `#atproto_kem` key rather
   > than signed; the precondition moves to that key.)*
3. **Phase 2 — shared spaces & sync:** oplog + `listRepoOps`, STAR
   `getRepo`, notifications + `spaceRev` sequencing + expiry, writer set, credential
   revocation, space deletion. Validate against the alpha: the hosted sandbox PDS, the
   alpha-tagged TS SDK as a client against Custos, and the bulletin sample
   app. Track the Thursday release notes on atmosphere.community and re-diff
   the proposal each time before building the next slice.
4. **Phase 3 — ecosystem hardening:** client attestation + `allowedApps`,
   `managedspace` policy, migration enumeration, moderation/admin surface,
   tooling (interop, MCP, wallet UX).

## 5. Risks & open questions

- **Spec churn** is still real but has changed character: the proposal is now
  tracked against a running reference implementation with weekly (Thursday)
  alpha releases and an explicit breaking-changes warning until launch
  ("later this year"). The August deltas (§0) were auth hardening and endpoint reshuffles;
  the October ones are bigger — the credential binding was swapped from DPoP to
  HTTP Message Signatures, the notification topology and `simplespace`
  policy model were reworked — so a module built against a prior week's wire
  contract can need real rework, not a tweak. The 2026-11-06 delta is larger
  still: the signed commit gave way to a KEM-derived MAC, CAR gave way to
  STAR, `simplespace` was dissolved into pluggable policies, and
  `#atproto_space*` DID entries were dropped. Anything built on the
  signed-commit, two-root-CAR, `simplespace`, `readPolicy`/`writePolicy` or
  `Atproto-Space` scheme shapes needs rework (see §7).
  Mitigation: re-diff the proposals repo before each implementation slice, and
  interop-test against the hosted alpha PDS + TS SDK continuously.
- ~~No published test vectors~~ **Resolved**: golden vectors and full test
  suites ship in `packages/space/tests/` on the `permissioned-data` branch.
- **Per-request KEM MAC** (replaces per-reader commit signing) puts a
  `#atproto_kem` private-key load + ECDH + HMAC on the serving path of every
  commit/record response; cheaper than ECDSA but still needs a key-residency
  decision (DB read per call vs. zeroized in-memory cache).
- **New DID-doc key to manage.** Every account needs a dedicated
  `#atproto_kem` key published in its DID doc (and re-published on
  migration), and a missing/stale key makes every syncer's MAC check fail.
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
  PDS-required baseline policies (`personalspace`, `memberspace`,
  `managedspace`) plus repo-host/space-host roles.

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
| MM-506 | 0 | Spaces crypto primitives: LtHash (BLAKE3-XOF, 1024×u16 lanes) + KEM shared secret (P-256 ECDH → RFC 9180 DHKEM HKDF) and commit/record MAC + `Atproto-Space-Want-Mac`/`Atproto-Space-Mac` codecs in `crates/crypto`, pinned to the reference golden vectors. **2026-11-06: rework — the `ctx`/`ikm`/`sig` signed-commit code is obsolete (commit is `{ver, repo, space, rev, data}`, no signature)** |
| MM-507 | 0 | `space:` OAuth scope grammar in `auth/oauth_scopes.rs`: parse/normalize/match/`intersect_scope_tokens` + `require_space` gates (no routes yet); permission-set `resource: "space"` entries |
| MM-508 | 1 | Permissioned repo store: migrations (`spaces` incl. policy object, `space_repos` incl. LtHash state, `space_records`, `space_repo_ops`, `space_members`, notify registrations, `jti` replay) + `space_record_write` choke point. **2026-11-06: `hash`→`data`; add `clearRecords` and empty-repo GC** |
| MM-509 | 1 | PDS record routes: `com.atproto.space.{createRecord,putRecord,deleteRecord,applyWrites,clearRecords,listSpaces,getRecord,listRecords,getLatestCommit}` + `.bru` files (blocked by MM-506/507/508). **2026-11-06: `getRecord`/`getLatestCommit` return the `Atproto-Space-Mac` header; `listSpaces` includes authority spaces** |
| MM-510 | 1 | Space auth: delegation-token mint (`aud` `#atproto_pds`), key-bound space-credential mint/verify (`credentialKid`→`cnf.kid` from a body with no transport auth; `Atproto-Space-Credential` scheme + `atproto-space-credential` signature with `tag`; `kid` `#atproto`; 10 min default / 60 min max; `jti` revocation list), public-read mint without a delegation token, `auth::space::authenticate_space_read` seam + `just` seam gate (blocked by MM-507). **2026-11-06: rework of the mint-time proof and the presentation scheme** |
| MM-511 | 1 | Space management: policy-agnostic `createSpace`/`updateSpace`/`deleteSpace`/`getSpace` under `com.atproto.space` (full `policy` object, `UnsupportedPolicy`) with baseline `personalspace` + `memberspace` (`publicRead`/`publicWrite`/`allowedApps`/`putMember`/`removeMember`/`listMembers`, `publishPolicy`/`publishMembers`) (blocked by MM-508). **2026-11-06: replaces the `com.atproto.simplespace` surface and `readPolicy`/`writePolicy`/`appAccess`** |
| MM-512 | 1 | Consent UI for `space:` scopes in `/oauth/authorize`: space-type declaration resolution (name, default collections), authority handle display, wildcard warnings (blocked by MM-507) |
| MM-513 | 2 | Sync surface: `listRepoOps` oplog (+compaction), STAR `getRepo` (strict key order, archive limits, MAC header), `listBlobs`, space blob refs + GC union (blocked by MM-509/510). **2026-11-06: replaces the two-root CAR** |
| MM-514 | 2 | Space-host role: writer set + `removeWriter`, `registerNotify`/`unregisterNotify` (+expiry, space-host-only), `notifyWrite` ingest (`repoRev`/`data`) + `spaceRev`/`prevSpaceRev` fan-out, `listRepos` cursor catch-up, `notifyCredentialRevoked`, space deletion with reliable `notifySpaceDeleted` + retained deletion record + `SpaceDeleted` renewal error, authority-takedown suspension (blocked by MM-510/511) |
| MM-515 | 2 | Identity: dedicated `#atproto_kem` DID-doc key (generate/store/publish via PLC + did:web, `getRecommendedDidCredentials`) and syncer-side resolution/refresh. **2026-11-06: replaces the `#atproto_space`/`#atproto_space_host` entries** |
| MM-516 | 3 | Client attestation verification + `memberspace.allowedApps`; `managedspace` policy with outbound `checkUserAccess` (`access` param) (blocked by MM-510/511) |
| MM-517 | 3 | Lifecycle & migration: `listSpaces`/`listBlobs` enumeration, spec'd `importRepo`/`exportSpaceMeta`/`importSpaceMeta` (STAR; meta before repo; `atproto-space-meta` archive), deactivation/takedown propagation (`RepoTakendown`/`RepoDeactivated`, export still allowed), authority suspension (blocked by MM-513). **2026-11-06: converge `POST /v1/space/import-repo` on the spec'd methods** |
| MM-518 | 3 | Tooling & interop: Bruno collection, interop CLI scenarios vs the alpha (hosted sandbox PDS + TS SDK as client), MCP tool surface, browser-harness coverage (blocked by MM-509) |

A weekly routine watches the alpha's Thursday releases and PRs spec-delta
updates to this doc — see
[`docs/operations/spaces-alpha-watch-routine.md`](../operations/spaces-alpha-watch-routine.md).
