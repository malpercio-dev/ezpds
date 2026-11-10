# Reference handler semantics for policies, writers and empty repos

Researched 2026-11-09 for MM-663. Where the Atproto Spaces proposal text is loose, this records what the reference PDS does.

Sources, both read from a `--filter=blob:none` clone; nothing was executed:

- **Reference**: `bluesky-social/atproto`, branch `permissioned-data`, commit `a620ad3d68d94ad2db653c1cd9ecff7b12c9b88e` (2026-11-06). Paths below are relative to `packages/pds/src/` unless they start with `packages/`, `lexicons/` or `tests/` (`tests/` = `packages/pds/tests/`).
- **Proposal**: `bluesky-social/proposals`, `0016-permissioned-data/README.md`, commit `9e86df35b17f828294333a4c5b95dce22bcbf323` (2026-11-05). Cited as `README L<n>`.

A claim marked **inferred** follows from the code read but is not asserted by a reference test. A claim marked **not implemented** has no code in the reference at this commit.

Error mapping used throughout: `InvalidRequestError` is HTTP 400, `AuthRequiredError` 401, `ForbiddenError` 403.

There are no handler directories for `managedspace` or `personalspace`. `api/com/atproto/` holds only `space/` and `memberspace/` (`putMember`, `removeMember`, `listMembers`). `personalspace` defines no methods, and `managedspace.checkUserAccess` is an outbound call only (section 7). All policy logic lives in `space-policy/{policy,manager,publish,archive}.ts`.

## 1. The three baseline policies

**Storage.** One row per space in `space_policy (uri PRIMARY KEY, policyJson TEXT NOT NULL)`, in the authority's own actor store (`actor-store/db/migrations/006-space-policy.ts:17-21`). The whole normalized policy object, `$type` included, is `JSON.stringify`-ed into `policyJson` (`actor-store/space/transactor.ts:58-74`) and read back with `JSON.parse` and no re-validation (`actor-store/space/reader.ts:27-34`). The member list is a separate table, `memberspace_member (space, did, read, write)`, not part of the policy object (`transactor.ts:99-128`).

**Validation.** Two layers:

1. The lexicon types `policy` as an open union of the three policy refs (`lexicons/com/atproto/space/updateSpace.json`, `createSpace.json`). A known `$type` with malformed fields fails schema validation before the handler runs. An unknown `$type` passes the schema.
2. `normalizePolicy` (`space-policy/policy.ts:33-62`) then rebuilds the object from known fields only:
   - `personalspace`: stored as `{$type}` alone; every other field is dropped (`policy.ts:34-36`).
   - `memberspace`: `publicRead`, `publicWrite`, `publishPolicy`, `publishMembers` default to `false`; `allowedApps` is kept as given, so absent stays absent (`policy.ts:37-45`). An empty array is stored as an empty array, which admits no app (`policy.ts:112-116`).
   - `managedspace`: `managingApp` must start with `did:`, else a 400 with **no error name** and message `managingApp must be a DID with an optional service fragment` (`policy.ts:46-57`; `tests/space/policy.test.ts:358-366`). `publishPolicy` defaults to `false`.
   - Unknown fields are dropped silently ("as Lexicon evolution allows", `policy.ts:26-32`). What is stored is exactly what is enforced.

**`UnsupportedPolicy`** (400) is thrown in one place: the fall-through of `normalizePolicy` when `$type` is none of the three (`policy.ts:58-61`). It is reached from `createSpace` (`manager.ts:46`), `updateSpace` (`manager.ts:72`) and `importSpaceMeta` via `parsePolicy` (`manager.ts:186`, `policy.ts:68-74`). Confirmed for `updateSpace` with `{$type: 'com.example.whatever'}` at `tests/space/policy.test.ts:351-356`. In `importSpaceMeta` a policy that fails the union schema is a plain 400 `Invalid policy: …` with no error name (`policy.ts:69-72`); only an unrecognized `$type` gets `UnsupportedPolicy`.

Order of checks: `updateSpace` runs `assertSpaceOwner` (scope `manage=update`, then `NotSpaceOwner`) before the policy is normalized (`api/com/atproto/space/updateSpace.ts:19-21`). `createSpace` normalizes before the `SpaceAlreadyExists` check (`manager.ts:46-54`).

**`updateSpace` and policy state** (`manager.ts:70-98`), all in one transaction on the authority's store:

1. Load the current policy; a missing or tombstoned space is `SpaceNotFound` (`reader.ts:36-43`).
2. Prepare the policy-record write for the new policy (publish, update or withdraw; section 2).
3. If "members are published" differs between old and new policy, prepare a write per member to publish or withdraw the whole list (`manager.ts:83-90`). This runs before the member list is deleted, so a migration away from `memberspace` withdraws every published member record.
4. Replace `policyJson` wholesale (`manager.ts:92`).
5. **If `$type` changed, delete every `memberspace_member` row for the space** (`manager.ts:93-95`). Migrating back does not restore it (`tests/space/policy.test.ts:413-426`). A same-`$type` update keeps the list (`policy.test.ts:327-335`).
6. Apply the prepared writes as one commit and return it; the handler sends `notifyWrite` (`updateSpace.ts:21-22`).

`updateSpace` **never touches the writer set** (`space_writer`), on a config change or on a `$type` change. Writers admitted under the old policy stay in `listRepos` until `removeWriter` is called or a later `notifyWrite` from them is refused (a refusal does not remove the row either; `api/com/atproto/space/util.ts:345-357`). This matches README L789 ("applications remain responsible for removing any writers").

`PolicyMismatch` (400) is what `putMember`, `removeMember` and `listMembers` answer on a space not under `memberspace` (`policy.ts:77-84`, `manager.ts:107-108`, `memberspace/listMembers.ts:24-25`).

## 2. `publishPolicy` / `publishMembers`

**Record shapes** (`space-policy/publish.ts:31-39`, lexicons `com/atproto/space/policy.json`, `com/atproto/memberspace/member.json`):

| Flag | Collection | rkey | Value |
|---|---|---|---|
| `publishPolicy` (memberspace, managedspace) | `com.atproto.space.policy` | `self` | `{policy: <normalized policy>}` |
| `publishMembers` (memberspace only) | `com.atproto.memberspace.member` | the member DID | `{read, write}` |

The member rkey is the DID verbatim, except that `%3A` is replaced by `:` so a `did:web:localhost%3A2583` fits the record-key grammar (`util/did-rkey.ts:10-16`, marked `@TODO` stopgap).

**When they are written.** Always into the authority's own repo in the space (`publish.ts:105-117`, `did = spaceDid`), inside the same transaction as the config change:

| Trigger | Writes | Source |
|---|---|---|
| `createSpace` | policy record if `publishPolicy` | `manager.ts:55-61` |
| `updateSpace` | policy record created, updated, or deleted to match the new flag; whole member list published or withdrawn when `publishMembers` effectively flips | `manager.ts:76-96` |
| `putMember` | that member's record created or updated if `publishMembers`, else deleted if present | `manager.ts:109-120`, `publish.ts:69-82` |
| `removeMember` | that member's record deleted if present | `manager.ts:129-137` |
| `importSpaceMeta` | nothing; the records arrive with the authority's repo via `importRepo` | `manager.ts:177-196` |

Each helper checks `hasRecord` first and emits create vs update vs delete accordingly; a withdraw of a record that is not there emits nothing (`publish.ts:105-130`). On a same-type update with `publishMembers` unchanged, no member records are rewritten.

**`rev` and `notifyWrite`.** These writes go through the same `SpaceTransactor.applyWrites` as user writes (`manager.ts:61,96,120,137`): one new TID `rev` for the batch, set hash updated, one oplog row per record (`actor-store/space/transactor.ts:198-287`). The manager returns the commit and every handler passes it to `fireNotifyWrite` (`createSpace.ts:28-29`, `updateSpace.ts:21-22`, `memberspace/putMember.ts:21-25`, `removeMember.ts:21-22`). So **yes**: a published write advances the authority repo's `rev` and puts the authority in the writer set. Confirmed at `tests/space/policy.test.ts:588-599`. When nothing is published, `applyWrites` gets an empty batch, returns `null`, and no `rev` advance or notification happens (`transactor.ts:203`, `util.ts:402-403`).

**Direct writes are rejected** by `assertNotPolicyRecord(collection)` (`publish.ts:41-48`): a 400 with **no error name**, message `<collection> records are published by the PDS from a space's configuration and cannot be written directly`. Called from `createRecord.ts:40`, `putRecord.ts:42`, `deleteRecord.ts:35` and per-write in `applyWrites.ts:104-105`. The check is on the collection alone, so it applies **in any repo in any space**, including a member's own repo (the proposal, README L822, notes members are "technically capable" of writing them; the reference refuses). It runs before the scope check. `importRepo` is the one path that accepts them, taking the archive's records as they are (`transactor.ts:289-295`).

**`clearRecords`** (`api/com/atproto/space/clearRecords.ts:35-51`): when the caller is the space authority, `keep = [com.atproto.space.policy, com.atproto.memberspace.member]`; otherwise `keep = []`. Kept collections need no `delete` grant; every other collection present needs one. The transactor deletes records outside `keep`, clears the **whole** oplog, and rebuilds the set hash from the kept records, so the authority's digest after a clear is that of the published records, not the empty digest (`transactor.ts:364-404`; `tests/space/policy.test.ts:560-586`). In a member's repo, records in those two collections (possible only via `importRepo`) are deleted like any other.

## 3. `removeWriter` and the writer set

**`removeWriter`** (`api/com/atproto/space/removeWriter.ts:15-25`): OAuth, `assertSpaceOwner(..., {manage: 'update'})` (so 400 `NotSpaceOwner` for anyone else, `tests/space/sync.test.ts:738-746`), then in one transaction `getActiveSpacePolicy` (400 `SpaceNotFound` for a missing or deleted space) and a plain `DELETE FROM space_writer WHERE space = ? AND did = ?` (`transactor.ts:186-192`). Idempotent. It emits nothing: no notification to syncers, no `spaceRev` advance, no tombstone of the removal. Nothing stops the authority removing itself.

**Re-add rule.** There is no separate rule; re-adding is just the normal `notifyWrite` path (`util.ts:323-358`, `transactor.ts:131-167`). On each `notifyWrite` the authority re-runs `authorizeUser(access: 'write')`; if refused it answers 403 `notifyWrite writer is not authorized` and records nothing. If authorized, `recordWriter` upserts the row whenever the stored `repoRev` is absent or older. Because `removeWriter` deletes the row, the stale-rev guard has nothing to compare against, so:

- any authorized `notifyWrite` after removal re-adds the writer, with a fresh `spaceRev` (`tests/space/sync.test.ts:715-736`, under `publicWrite`);
- **inferred:** that includes a redelivery of a `repoRev` the authority had already seen (the sender's retry queue, `space-notifications.ts:54-102`), so a removed writer who is still authorized can reappear without a new write.

**`removeMember`** deletes the member row and then calls `removeWriter` in the same transaction (`manager.ts:124-139`). **`putMember`** calls `removeWriter` whenever `access.write` is false (`manager.ts:100-122`). Both are unconditional: they do not check `publicWrite`, and they run even if the DID was never a writer. Tests at `tests/space/policy.test.ts:253-272`. The proposal's SHOULD (README L860) is implemented as always.

Under `publicWrite: true` the removed account is still authorized (`manager.ts:252-255`), so its next notification puts it back. The authority itself is always authorized (`manager.ts:245-247`).

A cleared repo stays in the writer set at the empty digest (`tests/space/sync.test.ts:748-761`).

## 4. `clearRecords` and empty-repo garbage collection

**`clearRecords`** (`clearRecords.ts`, `transactor.ts:364-404`): `repo` must equal the caller (403 otherwise). Then:

- No `space_repo` row: returns `null`. No write, no notification, no error. It does not call `ensureRepo`, so it neither creates a repo nor checks the space exists.
- Row exists but zero records deleted (already empty, or only kept records remain): returns `null`. **`rev` does not advance** and no `notifyWrite` is sent (`transactor.ts:378`; `tests/space/records.test.ts:467-478`).
- Otherwise: blobs of the cleared records dropped, records deleted, oplog deleted for the whole space repo, set hash rebuilt, `rev = TID.nextStr(prev)`, and the commit is passed to `fireNotifyWrite`.

The response is `{}` in every case. This is narrower than README L360, which reads as "always advance to a new `rev`"; the lexicon description says only "Succeeds whether or not the repo held any records to delete".

**Garbage collection of empty repos is not implemented.** There is no grace period, no sweep, and no code that deletes a `space_repo` row other than `deleteSpace` on the authority's own space (`transactor.ts:79-97`). A search of `packages/pds/src` for `grace`, `garbage`, and deletes of `space_repo` finds nothing else. A cleared repo, and a repo emptied by deleting its last record, both persist indefinitely with their `rev` and a zeroed set hash. Account migration does not drop them either: `importRepo` of an empty archive creates the row at a new `rev` (`transactor.ts:296-357`) (**inferred**; no test covers an empty import).

The reference therefore has three distinguishable states, and only the first "behaves as nonexistent":

| Endpoint | Never written (no row, or a row with `rev = NULL`) | Cleared / emptied (row with a `rev`) | Source |
|---|---|---|---|
| `getLatestCommit` | 400 `RepoNotFound` (`Could not find repo for space`) | 200, commit with the empty digest `e5a00aa9…` | `getLatestCommit.ts:35-48`, `util.ts:191-204`; `tests/space/sync.test.ts:490-499`, `records.test.ts:420-447` |
| `getRepo` | 400 `RepoNotFound` | 200, STAR archive with the commit and no records | `getRepo.ts:47-54` |
| `listRepoOps` | 200 `{ops: []}`, no `commit`, no `cursor`, no MAC header | 200 `{ops: [], commit}` with MAC header | `listRepoOps.ts:38-78`; `records.test.ts:449-465` |
| `listRecords` | 200 `{records: []}` | 200 `{records: []}` | `listRecords.ts:22-44` |
| `getRecord` | 400 `RecordNotFound` | 400 `RecordNotFound` | `getRecord.ts:36-45` |
| `listBlobs` | 200 `{cids: []}` | 200 `{cids: []}` | `listBlobs.ts:23-33` |
| `getBlob` | 400 `BlobNotFound` | 400 `BlobNotFound` | `getBlob.ts:25-42` |
| `listSpaces` (owner) | listed if a `space` row exists | listed | `reader.ts:45-68` |
| `listRepos` on the authority | absent | present, at the empty digest | `sync.test.ts:748-761` |

Before any of the read handlers reach the store: an account credential naming another account's repo gets 400 `RepoNotFound` (`Could not find repo for DID`), the same error as an absent repo (`util.ts:140-161`); an account this host does not have gets the same from `assertRepoAvailability` (`api/com/atproto/sync/util.ts:6-37`); a taken-down or deactivated repo answers `RepoTakendown` / `RepoDeactivated` to anyone but the owner or admin.

The "row with `rev = NULL`" case is real: `createSpace` inserts a `space_repo` row with null `setHash` and `rev` for the authority (`transactor.ts:38-56`), and `buildCommit` treats it as unwritten (`util.ts:197`).

Writing again after a clear continues from the cleared `rev`; the oplog starts over with the new write (`records.test.ts:480-499`).

## 5. `getSpaceCredential`

Handler: `api/com/atproto/space/getSpaceCredential.ts`. It has **no transport auth**; everything is in the JSON body.

**Order of checks:**

1. `credentialKid` must be a P-256 `did:key`, else 400 with no error name (`:14-16`).
2. If `delegationToken` is present it is verified and its `jti` consumed (`auth-verifier.ts:417-462`): type `atproto-space-delegation+jwt`, `kid #atproto`, not expired, `aud == <spaceDid>#atproto_pds` derived from the token's own `sub`, `iss` a DID, signature against the issuer's key (one forced refresh on mismatch), single use. Any failure is 400 `InvalidDelegationToken`. Then `sub` must equal the requested `space`, else 400 `InvalidDelegationToken` (`:21-31`).
3. The authority account must be on this host and active: 400 `SpaceNotFound`, `RepoTakendown` or `RepoDeactivated` (`:33`, `util.ts:83-113`).
4. If `clientAttestation` is present it is verified, whether or not the policy needs it (`:35-40`, `client-attestation-verifier.ts:74-107`): `iss == sub == client_id`, client metadata and JWKS fetched through the SSRF-guarded fetch (cached 1 hour), `aud == <spaceDid>#atproto_pds`, `jti` and `exp` required, single use. Any failure is 400 `InvalidClientAttestation`.
5. A tombstoned space answers 400 `SpaceDeleted`, with or without a delegation token, before any authorization (`:42-52`; `tests/space/policy.test.ts:1171-1195`). A space with no row or no policy is 400 `SpaceNotFound`.
6. User perimeter, then app perimeter (`manager.ts:206-233`).

**What each policy requires** (`manager.ts:214-274`, `policy.ts:90-116`):

| Policy state | Delegation token | Client attestation |
|---|---|---|
| `memberspace`, neither flag | required; user must be the authority or a member with `read: true` | not required |
| `memberspace`, `publicRead` | not required. If one is sent it is still verified and consumed, and any valid user passes | not required |
| `memberspace`, `allowedApps` set | required unless `publicRead` | required, and its `client_id` must be in the list |
| `memberspace`, `publicRead` + `allowedApps` | not required | required and listed (`policy.test.ts:895-904`) |
| `personalspace` | required, and the user must be the authority | not required; `allowedApps` does not exist |
| `managedspace` | required; the managing app decides (section 7), authority short-circuits | not required by the PDS; if sent, its verified `client_id` is forwarded to the managing app |

**Error set actually emitted** (all 400):

| Error | When |
|---|---|
| (unnamed) | `credentialKid` not a P-256 `did:key` |
| `InvalidDelegationToken` | token invalid, replayed, wrong audience, or `sub` differs from `space` |
| `InvalidClientAttestation` | attestation invalid, unresolvable, replayed, wrong audience |
| `SpaceNotFound` | authority not on this host; no such space; **or the user perimeter refused** (no token on a non-public space, non-member, member without `read`, managing app said no or failed) |
| `SpaceDeleted` | tombstoned space |
| `RepoTakendown` / `RepoDeactivated` | authority suspended |
| `AppNotAuthorized` | user perimeter passed, `allowedApps` set, attestation absent or not listed |

The lexicon also declares `UserNotAuthorized` and `NotAuthorized` (`lexicons/com/atproto/space/getSpaceCredential.json`); **the reference never returns either**. A user refusal is always disguised as `SpaceNotFound`, and the user check runs first, so a non-member learns nothing about `allowedApps` (`manager.ts:198-225`; `policy.test.ts:729-783`). `AppNotAuthorized` is reachable without a delegation token only on a `publicRead` space.

**Lifetime.** `createSpaceToken('credential', …)` is called with no `expiresInSec`, so every credential is exactly 600 s (`getSpaceCredential.ts:64-68`, `packages/space/src/credential.ts:24-31,94-116`). There is no request parameter or config to change it. The verifier accepts up to 3600 s (`credential.ts:67,174-181`), with 5 s clock skew (`credential.ts:66,213-219`). The credential carries `iss` = authority, `sub` = space, `cnf.kid` = `credentialKid`, `iat`, `exp`, a random 16-byte hex `jti`, header `kid #atproto`, and no `aud`. It is signed with the authority account's repo signing key (`:63`). Possession of `credentialKid` is not proven at mint. Delegation tokens and attestations are 60 s and single-use (`credential.ts:16-39`).

## 6. `listSpaces`

Handler: `api/com/atproto/space/listSpaces.ts`; query: `actor-store/space/reader.ts:45-68`.

**Output shape:** `{cursor?, spaces: [{uri}]}`. `spaceView` has one field, `uri` (`lexicons/com/atproto/space/listSpaces.json`). There is no role, policy, repo state or "authority" marker.

**How authority-only spaces appear.** There is one `space` table per actor store. A row is inserted by `ensureSpace`, which is called both from `createSpace` (authority) and from the first write into anyone's space (`transactor.ts:38-66,409-417`). `listSpaces` selects every row with `deletedAt IS NULL`, so a space the caller created and never wrote to is listed exactly like a space they hold a repo in, as `{uri}`. A client can tell it is the authority only by comparing the URI's DID with its own. The query does not join `space_repo`, so listing does not depend on a repo existing.

Other behaviour: ordered by `uri` ascending; `cursor` is the last `uri`, omitted when the page is short; `spaceType` and `did` (authority) filters are exact matches; tombstoned spaces are excluded. A foreign space the caller cleared stays listed (the `space` row is never removed for a non-authority). OAuth callers need a `read_self` grant matching the filters, with `*` for an absent filter (`listSpaces.ts:18-28`). The route also accepts a taken-down account's session (`additional: [AuthScope.Takendown]`, `:10`), which is what lets a taken-down account enumerate for migration.

## 7. `managedspace` `checkUserAccess`

All in `SpacePolicyManager.checkManagingApp` (`space-policy/manager.ts:299-346`), reached from `authorizeUser` (`manager.ts:263-272`). The PDS serves no `checkUserAccess` route.

- **When called:** on every `getSpaceCredential` that carries a delegation token for a managedspace (`access: 'read'`), and on every `notifyWrite` for one (`access: 'write'`, `util.ts:345-350`), including writes by accounts on the same PDS, which are delivered in-process through the same function (`space-notifications.ts:371-374`). Not called when the user is the authority (`manager.ts:245-247`).
- **Endpoint:** `managingApp` is split on `#`. With a fragment, the DID document's service entry with that id; without one, the DID's `#atproto_pds` endpoint (`util.ts:286-299`).
- **Request:** XRPC query `com.atproto.managedspace.checkUserAccess` with params `space`, `user`, `access` (`read` or `write`), and `clientId` (`manager.ts:323-335`). `clientId` is the verified attestation's `client_id` on reads and is absent when no attestation was sent; `notifyWrite` passes none, so it is always absent on write checks.
- **Auth:** service-auth JWT with `iss` = the space authority DID, `aud` = the `managingApp` string exactly as stored (fragment included), `lxm` = `com.atproto.managedspace.checkUserAccess`, signed with the authority account's repo signing key (`util.ts:305-320`).
- **Result:** authorized only if the response body has `authorized === true` (`manager.ts:336`).
- **Caching:** none. No positive or negative cache; every credential mint and every write notification makes a fresh call. Only DID resolution goes through the shared id resolver.
- **Failure handling:** fail closed. An unresolvable managing app, a network error, a non-2xx response or a malformed body all log a warning and return `false` (`manager.ts:316-322,337-345`; `tests/space/policy.test.ts:969-991`). The caller then sees `SpaceNotFound` (credential) or 403 (`notifyWrite`); a 403 is not retried by the sending PDS (`space-notifications.ts:436-443`), so a write made while the managing app is down is not tracked until the writer's next write.
- **No timeout or abort signal** is passed to this `xrpc` call, unlike the notification fan-out's 10 s (`util.ts:381`). **Inferred:** a hung managing app holds the `getSpaceCredential` or `notifyWrite` request open for the HTTP client's default.

## 8. What survives from the `simplespace` note

The earlier note (old `simplespace` reference handlers) recorded three behaviours.

| Old behaviour | Status at `a620ad3` | Source |
|---|---|---|
| `400 NotSpaceOwner` | **Survives.** `assertSpaceOwner` throws `InvalidRequestError('Not the space owner', 'NotSpaceOwner')` after the scope check. Used by `updateSpace`, `deleteSpace`, `getSpace`, `removeWriter`, `exportSpaceMeta`, `putMember`, `removeMember`, `listMembers`. | `api/com/atproto/space/util.ts:117-127` |
| Owner-only reads | **Survives for configuration, replaced for records.** `getSpace` and `listMembers` are OAuth-only and owner-only (`read_self` + `NotSpaceOwner`); a space credential does not reach them, and a policy publishes itself to readers instead (section 2). Record and sync reads are now: an account credential reads only its **own** repo in a space (others answer `RepoNotFound`), and anything cross-repo needs a space credential issued by the authority. | `getSpace.ts:8-18`, `memberspace/listMembers.ts:10-21`, `util.ts:129-161`; `tests/space/policy.test.ts:201-221,368-391` |
| A deleted space URI is re-creatable | **Survives.** `deleteSpace` keeps the `space` row as a tombstone and deletes the `space_policy` row; `createSpace` checks only `space_policy` for `SpaceAlreadyExists`, and `ensureSpace` upserts `deletedAt = NULL`. The new space gets the policy it was created with, an empty member list, writer set and repo. A queued `notifySpaceDeleted` retry is dropped once the space is live again. | `transactor.ts:38-97`, `manager.ts:44-63`, `space-notifications.ts:239-246`; `tests/space/policy.test.ts:1237-1262` |

Related `deleteSpace` facts: it is idempotent on a tombstone and `SpaceNotFound` only when no row ever existed (`deleteSpace.ts:21-27`); a write by the authority into its own deleted or never-created space is `SpaceNotFound`, while a write into another authority's space never checks existence (`transactor.ts:406-417`).

## Against the gap analysis, §0 "2026-11-06 weekly watch"

`docs/design-plans/2026-07-17-permissioned-data-gap-analysis.md` §0 summarizes the proposal text, and the reference agrees with it on every point checked except the following. None is a flat contradiction of the proposal; each is a place where the summary is stronger or looser than the code.

1. **Item 7, `clearRecords` "advances `rev`".** Only when at least one record was deleted. On an empty, unwritten, or already-cleared repo it is a silent no-op: no new `rev`, no notification (section 4).
2. **Item 7, empty digest.** In the authority's own repo the published policy and member records are kept, so the post-clear digest is theirs, not `e5a00aa9…`. Item 5 says the records are kept; item 7 reads as if the digest is always the empty one.
3. **Item 7, garbage collection after a grace period.** The reference implements none. A cleared repo keeps answering with a valid empty commit and stays in the writer set. Only a repo that was never written reads as nonexistent, and even then `listRecords`, `listBlobs` and `listRepoOps` answer 200 with empty lists rather than `RepoNotFound` (section 4 table).
4. **Item 3, "optional, required only when the policy asks".** True for presence, but a token or attestation that is sent is always verified and its `jti` consumed, so a bad optional one fails the request.
5. **Item 5 / §"Space policies", `$type` change "discards the old policy's state".** The member list only. The writer set is untouched.
6. **Items 3-5, error vocabulary.** `UserNotAuthorized` and `NotAuthorized` are declared in the lexicon and never emitted; user refusals are `SpaceNotFound`.

Against Custos today (`crates/custos-spaces/AGENTS.md`, still on the `simplespace`-era surface): `space_record_write.rs` deletes a repo when a commit empties it ("empty ≡ nonexistent"). The reference does the opposite: an emptied repo keeps its `rev` and serves the empty digest, which the proposal relies on so that syncers see the clear (README L358). That is the one place where converging on the reference changes existing Custos behaviour rather than adding to it.

## Not verified

- Nothing was run; every claim is from reading source and tests at the two commits.
- `permissions.assertSpaceRef` / `assertSpace` (in `@atproto/oauth-scopes`) were not read, so the exact scope-matching rules behind `manage=update`, `read_self` and the `delete` grants in `clearRecords` are taken from call sites only.
- The `@atproto/lex` runtime was not read. That an unknown `$type` passes the open union and reaches `normalizePolicy` is confirmed by the test at `tests/space/policy.test.ts:351-356`, not by reading the validator.
- The timeout behaviour of the `checkUserAccess` call and the redelivery re-add in section 3 are inferences from code, with no reference test.
- `registerNotify`, `notifyCredentialRevoked`, `exportSpaceMeta`/`importSpaceMeta` and the STAR format were read only as far as these eight questions needed.
