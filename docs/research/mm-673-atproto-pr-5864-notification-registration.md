# Research note: atproto pull request 5864, notification registration through getSpaceCredential

**Summary**

1. Pull request 5864 deletes `registerNotify`/`unregisterNotify` and the service-identifier registration. A syncer now registers by passing `notify: {endpoint, token}` to `getSpaceCredential`. The registration is keyed `(space, endpoint, token)`, expires with the credential (600 s), and keeps a 24 h grace for one more notification. Outbound calls carry `Authorization: Bearer <token>` over `safeFetch`.
2. The PR is open, not a draft, mergeable, and CI is green. It has zero reviews, zero review comments and no requested reviewers. The author, dholms, merged every one of his roughly 20 earlier permissioned-data PRs himself, most within 1 to 2 days and several with no review at all. I estimate an 85 to 90% chance it merges, mostly as it stands, within about a week.
3. The main rework risks are four:
   - bnewbold's unanswered request on proposal 138 for an explicit expiry field;
   - a rebase collision with pull request 5877, which edits the same fan-out, the same `notifyRepoUpdate` body and the same actor-store migration number;
   - revocation-drops-registration, which the proposal requires and the code does not implement;
   - bnewbold's non-blocking objection to bearer tokens in place of service auth.
4. In Custos, both notify routes, `space_notify_registrations`, the DID resolution and service-auth minting in `space_notify.rs`, and `ServiceNotResolvable` go away. The hardened client, the per-space fan-out caps, the retry classification and the deletion flow (capture the recipients, then drop them in the tombstone transaction) stay. Nothing in Custos already has the endpoint+token shape.
5. One part of MM-667 is moot: "a permanent error unregisters the syncer" on a status notification, because the reference has already dropped the registrations in the delete transaction. It also differs from MM-667 on two points, neither a protocol conflict: its retry row is written only after the first attempt fails, not in the tombstone transaction, and its retryable set is a fixed list rather than all 5xx. Four decisions are not in MM-677's list:
   - the lexicon-pin jump, which is a prerequisite;
   - durable retry for the repo host to space host leg;
   - a cap on registrations and an abuse policy;
   - an IP-literal SSRF gap that exists in `space_notify.rs` today.

**Date:** 2026-11-11 (GitHub timestamps below are UTC).

**SHAs read**

- bluesky-social/atproto `permissioned-data` head `6b67aa8af9d64eb4cddb0a49de43b2cd40d4b6fc`. It moved from `aaf3311` during this research when pull request 5851 merged. The merge base of pull request 5864 is `aaf3311cd57f4a00fe8c5f463b2f32c6861f5700`.
- Pull request 5864 head `d27e78f53d7079122ef9624b72a970ac623d57ff`. Its commits are `51bc559` "continuous notifs & webhooks" (2026-11-11T02:26Z), `376409b` "allow grace period for missed notifs" (02:37Z), and `d27e78f`, a merge of permissioned-data (19:51Z).
- Pull request 5877 head `d83340177c1cbbc85f8e4248927ac9459f2f38b9`. Pull request 5862 head `15cc4db6e819dca9dcc5c3b306e4723fe4ad4b1a`.
- bluesky-social/proposals pull request 138 head `8f1cabee5ca901641d6a8cc5eb6226f68fec5a80`. This already contains pull request 140, which was merged into 138's branch.
- Custos (this repo) `7bbb96c7c059fb573df7d418ba8c9b50abb31e58` ("release: 0.17.0"). Its vendored space lexicons are pinned to permissioned-data `619c6e8` (2026-10-15; `crates/custos-core/lexicons/README.md:56`), 79 commits behind the current head.

All `file:line` citations for atproto are at `d27e78f` unless marked otherwise. Custos citations are at `7bbb96c7`.

---

## 1. What pull request 5864 changes

### Lexicons

- **`getSpaceCredential`** gains an optional `notify` (ref `#notify`), at `lexicons/com/atproto/space/getSpaceCredential.json:29-33`. `#notify` (`:83-98`) requires `endpoint` (format `uri`, described as "Base HTTPS URL") and `token` (string, `maxLength: 512`, "Opaque secret, presented as a bearer token"). The **output is unchanged**: still only `{credential}` (`:37-43`), with no expiry field.
- **`registerNotify.json` and `unregisterNotify.json` are deleted.** The old `registerNotify` took `{space, service}` (a `did#serviceId`) under space-credential auth and returned `{expiresAt}`. The old `unregisterNotify` had just moved to service auth (the `.changeset/signed-syncers-withdraw.md` that pull request 5864 deletes).
- **`notifyRepoUpdate`**: the description now says the repo host calls the space host with service auth, and the space host calls syncers "presenting each one's registered token as a bearer token". **`notifySpaceStatus`**: syncers receive the bearer token, with no service auth (the diff of `notifyRepoUpdate.json:7` and `notifySpaceStatus.json:7`). The input schemas do not change in this PR.
- The changeset is `.changeset/webhook-syncers-register.md`, a minor bump for `@atproto/pds` and `@atproto/api`.

### Storage

- **Actor-store migration `008-space-notify-registration.ts`** drops `space_credential_recipient` without carrying anything over ("Syncers re-register on their next credential request", `:4-6`). It creates `space_notify_registration(space, endpoint, token, expiresAt)` with PK `(space, endpoint, token)` (`:10-22`). The token is stored **in plaintext**. It cannot be hashed, because the host has to present it.
- **Account-manager migration `011-space-notify-registration.ts`** drops and recreates the service-wide `space_status_notification_retry` table: `(space, endpoint, token, attempts, retryAt, expiresAt)`, PK `(space, endpoint, token)`, indexed on `retryAt` (`:6-24`). Pending service-keyed retries are discarded. The table predates pull request 5864: it came from pull request 5697 "retry space deletion" and was renamed by migration 010. It lives in the account-manager DB, not in the space authority's actor store.

### Registration, renewal, expiry

- **Register or renew** (`api/com/atproto/space/getSpaceCredential.ts:95-107`). This runs only after the credential is minted. `expiresAt` is set to **the credential's own `exp`**. The credential lifetime is 600 s (`packages/space/src/credential.ts:34-37`; max 3600 s at `:79`). The upsert on `(space, endpoint, token)` only extends `expiresAt` (`actor-store/space/transactor.ts:431-445`). The same call prunes this space's rows that are past the grace window (`:447-453`). A different token for the same endpoint creates a second registration.
- **Active plus grace.** `NOTIFY_GRACE_PERIOD_MS = DAY` (`actor-store/space/reader.ts:25-27`). `getNotifyRegistrations` returns rows with `expiresAt > now − 24h` (`:333-346`), so the result includes lapsed registrations "still owed one more notification".
- **The "grace period for missed notifs" commit, `376409b`**, sits in `forwardNotifyRepoUpdate` (`api/com/atproto/space/util.ts:375-424`). A lapsed registration is removed only after a notification to it is **delivered** (`:398` collects it; `:410-422` calls `removeLapsedNotifyRegistration` with `expiresAt <= now`, so a registration renewed in the meantime survives, `transactor.ts:468-480`), or after it is **permanently rejected**. A retryable failure leaves it in place for the next write, up to the 24 h cap.
- **Unregister by permanent HTTP error** (`util.ts:400-407`). If `err instanceof XrpcError && !err.shouldRetry()`, the row is deleted. In lex-client terms that covers any status outside `RETRYABLE_HTTP_STATUS_CODES` = {408, 425, 429, 500, 502, 503, 504, 522, 524} (`packages/lex/lex-client/src/errors.ts:62-64`, `:208-210`), any 401/`XrpcAuthenticationError` (`:283-285`), and the internal and validation error classes (`:403-405`). `XrpcFetchError` (network or timeout) counts as retryable (`:437-440`). A 501 or 505 therefore unregisters.
- **A refused credential withdraws the registration** (`getSpaceCredential.ts:69-85`). If `authorizeCredential` throws and `notify` is present, `removeNotifyRegistration(space, notify)` runs and the error is rethrown. A `SpaceDeleted` refusal happens earlier (`:55-67`), so it does not reach this path. The space's registrations are already gone by then (below).
- **Deletion.** `SpaceTransactor.deleteSpace` deletes `space_notify_registration` together with the space's other rows, in the tombstone transaction (`transactor.ts:79-97`). `SpacePolicyManager.deleteSpace` reads the registrations, lapsed-in-grace ones included, inside the same transaction and returns them (`space-policy/manager.ts:301-312`). The route then queues `notifySpaceStatus` on the in-memory background queue (`api/com/atproto/space/deleteSpace.ts:30-33`).

### Outbound delivery

- **Bearer token, not service auth.** Both outbound calls send `authorization: Bearer ${token}`: repo update at `util.ts:388-396`, space status at `space-notifications.ts:405-418` (the `deliverSpaceStatus` hunk). No DID resolution and no JWT minting are left on the syncer leg.
- **SSRF-protected fetch.** Syncer calls use `{ service: endpoint, fetch: ctx.safeFetch }` (`util.ts:390`, `space-notifications.ts` `deliverSpaceStatus`). `safeFetch` is `safeFetchWrap({ allowIpHost: false, allowImplicitRedirect: false, responseMaxSize, ssrfProtection })` (`context.ts:340-344`), which **refuses IP-literal hosts outright** and does not follow redirects. The PR also moves two other outbound calls onto `safeFetch`: the repo host to space host retry (`space-notifications.ts` `deliver`) and the managing-app `checkAccess` (`space-policy/manager.ts:341`). Neither the handler nor the lexicon enforces `https`: the format is plain `uri`, and the scheme is left to `safeFetch`'s policy.
- **Repo-update fan-out to syncers is best-effort.** It is one attempt per registration on the background queue, with a 10 s timeout and no durable retry (`util.ts:365-366`, `:385-409`).
- **Status notification retry** (`space-notifications.ts:105-144`, `:210-266`, `:268-300`):
  - The first attempt is immediate. Only a **retryable** failure writes a row, and that write happens after the deletion transaction, in a different DB.
  - `expiresAt = Date.now() + DAY` (`:125`). Before pull request 5864 it expired with the registration.
  - Backoff doubles from 1 min up to 1 h, with 50 to 100% jitter (`:453-457`), capped at `expiresAt` (`:277`).
  - A permanent failure clears the row and **does not touch any registration** (`:115-121`, `:252-258`); none is left by then.
  - The retry is dropped if the authority account is gone (`:229-234`) and deferred while the authority is deactivated or taken down (`:235-238`). It is also dropped if the space has been **recreated** since (`:239-246`): "telling the syncer now would purge its new copy".
  - `isRetryableError` treats any non-XRPC error as retryable (`:444-451`).
  - One worker drains the retries, holding a lease (`:158-208`).

### Where the code departs from proposals 138 and 140 (138 head `8f1cabe`, README `0016-permissioned-data/README.md`)

- **Revocation.** The proposal says the space host "should also drop a registration early if it revokes the credential that last renewed it". The code does not do this. The registration row stores no credential `jti`/`kid`, and nothing in the revocation path touches it (`git grep removeNotifyRegistration` hits only `getSpaceCredential.ts:81` and `util.ts:404`).
- **Method names.** The proposal still says `notifyWrite`/`notifySpaceDeleted`. The reference uses `notifyRepoUpdate`/`notifySpaceStatus`, the rename from pull request 5800 "lexicon review", merged 2026-11-11T00:04Z.
- **HTTPS.** The proposal says the endpoint is "a base HTTPS url". The code enforces only through `safeFetch`, as noted above.
- **What does match:** endpoint and token as the identity, renewal by the same pair, active while the credential is valid, the 24 h grace with "temporary failures don't count", unregister by permanent error, refusal withdraws, lapsed registrations receiving the deletion notice, and "not carried over on migration".

## 2. Review state and merge likelihood

- **State.** Open, `isDraft: false`, `mergeable: MERGEABLE`. `reviewDecision` is empty, `reviews: []`, `reviewRequests: []`, no labels, no issue comments, and `gh api …/pulls/5864/comments` returns nothing, so there are **no unresolved threads**. All CI checks pass: Build, Test 1/8 to 8/8, Verify, Changeset and claude-review (`gh pr view 5864 --json statusCheckRollup`). The body reads, in full: "Impl for proposals/pull/138 and proposals/pull/140".
- **Author.** dholms (Daniel Holmgren). He merges his own PRs into permissioned-data (`mergedBy=dholms` on 5812, 5800, 5810, 5766, 5697, 5706, 5574 and 5567) and authored the umbrella pull request 5423 "Atproto spaces alpha" (open since 2026-08-18). He also merged pull request 140 on proposals himself.
- **Merge history on permissioned-data** (`gh pr list --base permissioned-data --state all`):
  - All 21 dholms PRs before this batch merged. None was closed unmerged; the only closed PR (5434) was from an outside contributor.
  - Time open: usually under 2 days (5810 19 h, 5766 18 h, 5697 23 h, 5705 3 h, 5706 16 h). The longest were 5800 (8 days, with bnewbold review rounds ending in APPROVED) and 5812 (7 days, one matthieusieben COMMENTED).
  - Several merged with no review at all (5810, 5766, 5697, 5567), so the branch has no approval gate in practice.
- **Proposal state.**
  - Pull request 138 is **open and APPROVED by bnewbold** (2026-11-11T00:46Z, "I like the direction"). That approval came before the webhook switch landed.
  - Pull request 140 was **merged into 138's branch** (`0016/continuous-notify-register`, not main) by dholms at 2026-11-12T02:34Z. bnewbold's only review was COMMENTED: "I don't really love this change, though I would not block it", arguing that service auth "plopped right in with no new code".
  - **The explicit-expiry comment.** On 138, bnewbold wrote (2026-11-11T00:40Z, review comment 4532401914, on the old line 586) that "credential lifespan + 1 notification" is "less reliable than the previous system with an expiration time". He proposed "an expiration time as a field in the space credential response". No one replied. dholms then pushed "registrations on token + endpoint" (02:18Z) and "allow for grace period of missed notifs" (02:31Z). The grace commit answers the "missed the last notification" failure but adds **no expiry field**. One thing the thread does not mention: the registration expiry *is* the credential JWT's `exp` (`getSpaceCredential.ts:98-104`), so a syncer can already read it out of the token.
  - A second bnewbold comment (4532447841, line 768) floats folding unregister into a "burn space credential" endpoint. He calls it "a bit convoluted". No reply.
- **Neighbouring PRs.**
  - **Pull request 5877** "writer set lifecycle" (dholms, opened 2026-11-11T23:15Z, implements proposals pull request 144). It edits `notifyRepoUpdate.json`: `repoRev`+`data` become `latest`, a union of `defs#repoWrite`/`defs#repoRemoved`. It adds a `repoRemoved` fan-out to registered syncers from `removeWriter`/`removeMembers`/`putMembers`. It touches `util.ts`, `space-notifications.ts` and `space-policy/manager.ts`. It also adds **actor-store migration `008-space-writer-removed.ts`**, the same number as 5864's `008-space-notify-registration.ts`. Whichever merges second has to renumber and rebase its fan-out.
  - **Pull request 5862** (MACs to HTTP Signatures) touches `util.ts` and sync, but nothing on the notification path.
- **Likelihood: about 85 to 90% that it merges onto permissioned-data substantially as it stands, within days.** The track record is uniform, there are no review threads or CI failures, the proposal is approved, and the author is also the branch's merger. Rework risks, roughly in order of likelihood:
  1. **Renumbering and rebase against 5877.** This is near-certain but mechanical. It changes the `notifyRepoUpdate` body that the syncer fan-out sends.
  2. **An explicit expiry field** in the `getSpaceCredential` output, e.g. a `notify.expiresAt`, if bnewbold presses. This would be additive and cheap.
  3. **Revocation dropping the registration**, which the proposal requires and the code lacks. It would need a credential `jti` on the registration row.
  4. **Reverting to service auth.** Unlikely: bnewbold said he would not block, and 140 is already merged into 138's branch.
  5. **A "burn credential" unregister path.** Speculative.

  Separately, none of this is on atproto `main`: pull request 5423 into main is still open. Permissioned-data is a moving alpha branch, so "merged" means merged into the alpha, not stable.

## 3. Impact on Custos

| Custos item | Fate under pull request 5864 |
|---|---|
| `routes/space_register_notify.rs:31-67` (`registerNotify`, space-access auth, `ServiceNotResolvable`, 7-day TTL) | **Removed.** Registration moves into `get_space_credential`. |
| `routes/space_unregister_notify.rs:29-50` (authenticated with a *space credential*; the reference had already moved to service auth before 5864) | **Removed.** Withdrawal becomes a permanent HTTP error from the syncer. |
| `router.rs:84-89`, `routes/mod.rs:30-31,72-73`, vendored `lexicons/com/atproto/space/{registerNotify,unregisterNotify}.json`, `custos-core/src/lexicon/mod.rs:160-161`, `common/src/error.rs:154` (`ServiceNotResolvable`), the two `bruno/` requests | **Removed** (the bruno parity gate follows). |
| `custos-db` V065 `space_notify_registrations(space_uri, subscriber_did, repo_did, created_at, expires_at)`, PK on all three, plus V074's per-repo row cleanup (`V065__spaces.sql:115-122`, `V074__space_notify_topology.sql:7`) | **Replaced** by a new migration: `(space_uri, endpoint, token, expires_at)` with PK `(space_uri, endpoint, token)`. The `repo_did` sentinel column has no counterpart. As in the reference, nothing carries over. |
| `db/space_notify.rs:28-51` `upsert_registration` (TTL from now) | **Replaced** by an upsert whose `expires_at` comes from the minted credential's `exp`, plus pruning past the grace window (the reference prunes on write; Custos's "expiry by read predicate" comment, `:15-17`, needs revising, because endpoint+token keys can accumulate dead rows). |
| `db/space_notify.rs:54-71` `delete_registration` (by service id) | **Replaced** by delete-by-`(space, endpoint, token)` and a lapsed-only delete (`expires_at <= now`). |
| `db/space_notify.rs:77-92` `subscribers_for_space` (`expires_at > now`, returns service ids) | **Changed** to `expires_at > now − 24h`, returning `(endpoint, token, expires_at)`. |
| `routes/get_space_credential.rs:30-37` input (`space`, `clientAttestation`) | **Gains `notify`.** After a successful mint, upsert the row. When `authorize`/issuance refuses, delete `(space, endpoint, token)` before returning the error. Precondition: Custos is pinned to `619c6e8`, so its `getSpaceCredential` takes the delegation token in `Authorization` plus an RFC 9421 signature (`:44-48`, `:86-92`), while 5864 builds on the post-5800 body shape (`credentialKey`, `delegationToken` in the body). |
| `space_notify.rs:261-308` `deliver` (mints `mint_account_service_auth` per call, `:269-285`) and `:312-363` `attempt_delivery` (DID doc to endpoint, `:321-332`) | **Replaced on the syncer leg** by a POST to `{endpoint}/xrpc/{lxm}` with `bearer_auth(token)`. `split_service`, `endpoint_in`, `service_is_resolvable` and `resolve_service_endpoint` (`:249-255`, `:366-393`) go away for syncers. **Kept** for `report_write` (repo host to space host stays on service auth). |
| `space_notify.rs` forward fan-out (`spawn_write`, `:123-200`) | **Changed**: after a delivery to a lapsed registration, drop it with a lapsed-only delete; on a permanent error, drop it. The module doc's stance "a permanent failure deliberately does **not** unregister the subscriber" (`:21-23`) is **inverted** by 5864. |
| `space_notify.rs:206-226` `fan_out_space_deleted`, `routes/simplespace_delete_space.rs:66-96` (capture the subscribers, then delete the registrations in the tombstone transaction via `db/spaces.rs:294`) | **Kept in shape.** It already matches the reference's ordering, and Custos can capture inside the transaction because it has one DB. It changes to carry `(endpoint, token)`, to include in-grace lapsed rows, and to send the bearer token. |
| `space_notify.rs:51` `REGISTRATION_TTL_SECS = 7 days` | **Removed.** Expiry becomes the credential's 10 min plus a 24 h grace. |
| `space_notify.rs:55,60` `MAX_SUBSCRIBERS = 100`, `MAX_CONCURRENT_FANOUTS = 8`; `simplespace_delete_space.rs:19` `NOTIFY_DELETED_FANOUT_MAX = 100` | **Kept.** The reference has no cap at all. |
| `space_notify.rs:338-362` retry classification (non-2xx 4xx except 408/429 is permanent; 5xx, 408, 429 and network errors are transient; 3 attempts in memory) | **Kept**, and compatible. The reference uses an explicit set (also 425/522/524, and treats 501/505 as permanent). |
| `custos-core/src/identity/proxy.rs` `HardenedClient`/`CallerUrl` (`:41-84`) | **Kept** and used for the stored endpoint. See the SSRF gap in section 4. |
| `custos-spaces/src/lib.rs:76` purge (`DELETE FROM space_notify_registrations WHERE subscriber_did = ?`) and `:155,176` test | **Changed.** A registration no longer names an account, so the account-purge row goes; the schema-walk test entry changes with it. |
| `routes/space_notify_credential_revoked.rs` | **Unaffected** by 5864. If the proposal's "drop the registration on revoke" lands upstream, the registration needs a credential `jti` column. |

**Does anything already resemble the new shape?** Partly:

- `fan_out_space_deleted` takes its recipient list before the delete transaction and drops the registrations inside it. That is what `SpacePolicyManager.deleteSpace` does.
- `get_space_credential` already answers `SpaceDeleted` before issuance (`:63-68`). That is the durable fallback the reference relies on.
- Delivery already goes through the SSRF-hardened client with a bearer `Authorization` header: a service-auth JWT today, an opaque token afterwards.

Nothing stores an endpoint or token, and Custos has no grace or lapsed logic.

## 4. Decisions touched

**MM-671** ("138/140 wait for a reference implementation; design against registerNotify + service auth"). Superseded on both conditions: the reference implementation exists (pull request 5864), and proposal 140 has been merged into 138's branch. MM-667 already records the switch.

**MM-667 checked against the code:**

- *Durable `space_status_notify_retries`, one row per (space, registration), 24 h expiry.* **Consistent.** The PK is `(space, endpoint, token)` (`011-space-notify-registration.ts:6-19`) and expiry is `Date.now() + DAY` (`space-notifications.ts:125`).
- *Written in the tombstone transaction.* **Not what the reference does.** The reference attempts first and writes a row only on a retryable failure, after the delete commits, into a separate DB (`deleteSpace.ts:30-33`, `space-notifications.ts:110-136`). If the process crashes between commit and first attempt, the notice is lost and only the `SpaceDeleted` renewal answer remains. MM-667's choice is strictly stronger and still conforms: the proposal says "SHOULD retain a record … until … notified or had its registration dropped". Keep it, and expect a first delivery to clear a row that was just written.
- *Retryable = network/resolution/408/429/5xx.* **Compatible, but not identical.** The reference also retries 425/522/524, treats 501/505 and others as permanent (`errors.ts:62-64`), and retries any non-XRPC error (`space-notifications.ts:444-451`). "Resolution" is moot on the syncer leg under 5864, because nothing is resolved.
- *Permanent other status drops the row and, under 5864, unregisters the syncer.* **The "drops the row" half matches. The "unregisters" half is vacuous**: the registrations were already deleted in the tombstone transaction (`transactor.ts:87-96`; Custos does the same at `simplespace_delete_space.rs:80-82`), and the reference's status path never calls `removeNotifyRegistration` (`space-notifications.ts:115-121`). "Unregister on permanent error" exists only on the repo-update fan-out (`util.ts:400-407`). This is not a contradiction, but MM-667's wording should not lead to a "delete registration" step on the status path.
- *Per-attempt guards.* **Consistent.** MM-667's resolution, item 3, already lists the three guards the reference runs: drop once the space is recreated (`space-notifications.ts:239-246`), drop once the authority account is gone (`:229-234`), and defer while the authority is deactivated or taken down (`:235-238`).

**MM-677's question list against the code:**

- *Replacement for `space_notify_registrations`.* The answer is in section 3. One correction to any assumption that it maps 1:1: the key becomes `(space, endpoint, token)`, so one syncer can hold several registrations, and rows need pruning on write.
- *Token storage.* The reference stores it in plaintext in both tables, and it has to, because it presents the token outbound. Hashing is off the table. The only open choice is encrypting it at rest under the master key.
- *Whether the `notifyRepoUpdate` fan-out joins the durable queue.* **The reference says no.** The syncer fan-out is one best-effort attempt (`util.ts:385-409`); the grace logic exists so that a missed notification heals on the next write. Joining the durable queue is a Custos choice beyond the reference, not parity.
- *SSRF client coverage.* `HardenedClient` covers domain hosts at connect time, but **IP-literal hosts bypass `SsrfResolver`** (`proxy.rs:107-110`; `validate_proxy_endpoint` exists for exactly this, `:275-306`). `space_notify.rs:326-339` builds a `CallerUrl` from a DID-document endpoint and never calls `validate_proxy_endpoint`. **The gap exists today:** a syncer DID whose service entry is `http://10.0.0.5` gets POSTed to. Under 5864 the endpoint is typed straight into a request body, so the hole is easier to reach. The reference refuses IP hosts outright (`allowIpHost: false`, `context.ts:341`). MM-677 should decide between validating at registration, at delivery, or both, and whether to refuse IP literals as the reference does.

**New decisions not covered by MM-677:**

1. **The lexicon pin jump is a prerequisite.** Pull request 5864 sits on top of pull request 5800 (method renames, `getSpaceCredential` taking `credentialKey`/`delegationToken` in the body) and pull request 5812, which Custos's `619c6e8` pin predates. MM-671 already decided the lexicons re-vendor from the frozen pin, so this is an ordering fact for slicing (MM-675), not a new decision.
2. **Pull request 5877's `repoRemoved` and the `latest` union** ride the same syncer fan-out and change the `notifyRepoUpdate` body. Decide whether Custos's fan-out redesign targets the post-5877 body.
3. **Durable retry on the repo host to space host leg.** The reference keeps a durable, coalesced `space_notification_retry` per `(repo, space)` with a 24 h window (`space-notifications.ts:48-97`), and the proposal says repo hosts are "responsible for reliably updating the space host". Custos's `report_write` has 3 in-memory attempts (`space_notify.rs:77-78`). This is outside 5864's diff but is the same subsystem.
4. **Registration cap and abuse policy.** The reference has no per-space cap, so anyone who can obtain a credential (on a public space, without a delegation token) can point notifications at an arbitrary public endpoint. Custos always requires a delegation token, which narrows this. Decide on a per-space registration cap and on how it interacts with `MAX_SUBSCRIBERS` (does registration refuse, or does fan-out truncate?).
5. **Revocation dropping the registration, and an expiry field.** Both are proposal or review asks the code lacks (section 2, rework risks 2 and 3). Decide whether Custos stores a credential `jti` on the registration now, to stay ahead of either landing.
