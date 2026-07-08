# Daily-driver readiness audit — 2026-07-08

A full-codebase sweep aimed at three questions: (1) is ezpds trustworthy enough to run as
the operator's daily-driver Bluesky PDS, (2) where can the code be made easier to read and
contribute to, and (3) are there hidden bugs — especially in `crates/crypto`.

**Verdict.** The endpoint surface is essentially complete and the functional cores (crypto,
MST, CAR) are sound. What stands between this and moving a real account is a short list of
**correctness bugs** (four fixed this session, below) plus a few **concurrency/architecture
hardening items** (open, ranked below) and **validation gaps** (the live migration + first
real OAuth login have never been run end-to-end). No finding is an unfixable design flaw.

The SQLite pool is single-connection (`max_connections(1)`, WAL), which serializes individual
queries and materially lowers the probability of the concurrency races below — but it does
**not** serialize the multi-query logical sequence of a request, so those races remain real
under concurrent writes to the same repo.

---

## Fixed this session

All four are verified (reproduced with a failing test where practical) and landed with
regression tests. Commits on `claude/pds-audit-refactor-g6o2ak`.

### Crypto (commit `efda9ed`)

1. **High-S signatures accepted on every PLC verification path.** `verify_genesis_op`,
   `verify_plc_operation`, and `verify_p256_signature` accepted mathematically-valid but
   non-canonical high-S ECDSA signatures. `@atproto/crypto` and plc.directory reject high-S;
   worse, because a PLC DID/CID is derived from the *signed* CBOR, the malleable high-S twin
   of a valid signature verified **and** derived a different DID/CID — one signature yielding
   two valid ops. Now rejected centrally in `verify_signature_with_key`.
2. **`build_did_plc_genesis_op` emitted high-S ~50% of the time** despite a documented "low-S
   canonical" contract — those ops would be rejected by plc.directory. Now normalized. (In-tree
   production callers already normalized on their own; this closed a public-API footgun.)
3. **`decrypt_private_key` briefly held the decrypted key in an unzeroized `Vec`**, violating
   the crate's zeroization invariant. Wrapped in `Zeroizing` at the point of decryption.

### repo-engine + pds (commit `bc8b924`)

4. **CRITICAL — updating any record containing a blob ref or bytes returned 500.**
   `put_record` chose create-vs-update by decoding the stored record into `serde_json::Value`,
   which cannot represent DAG-CBOR CID links (`$link`, tag 42) or byte strings (`$bytes`).
   Reproduced: create `app.bsky.actor.profile/self` with an avatar, then `putRecord` again →
   `invalid type: byte array, expected any valid JSON value`. This breaks **updating your
   profile when it has an avatar/banner** and **editing any post with an image embed** — core
   daily-driver actions. Fixed by probing existence with the MST key→CID lookup
   (`get_record_cid`), which never decodes the record.
5. **HIGH — `listRecords` was O(limit × repo-size) per page.** Each returned record was
   resolved via atrium's `get_raw_cid`, which re-enumerates the entire MST to prove CID
   membership (its own docs say "always prefer `get_raw`" when you hold the key — we do, from
   the tree walk). On a mature repo this is millions of block reads per page and a public
   resource-exhaustion vector. Fixed to resolve by key (`get_raw`, one descent each).
6. **HIGH — commit `rev` was not strictly increasing.** atrium's `CommitBuilder` defaults `rev`
   to the raw wall clock with clock-id 0, so two commits in the same microsecond collide and a
   backward clock step (NTP correction, VM migration) yields a *decreasing* rev — relays drop
   such commits as stale, silently desyncing the repo. `put_record`/`delete_record` now force a
   rev strictly greater than the previous commit's (mirrors the reference PDS's monotonic-clock
   guard). Covered by unit + end-to-end monotonicity tests.
7. **MEDIUM — refresh-token rotation race defeated replay detection.** `refreshSession`'s
   rotation UPDATE lacked an `AND next_jti IS NULL` guard and the replay check read `next_jti`
   outside the transaction, so two requests with the same token could both rotate and mint
   working pairs — two live refresh chains from one token. The UPDATE is now conditional; the
   race-loser fails closed and rolls back.

---

## Open findings (ranked; not yet fixed)

These are verified but were left for a dedicated change because each needs a schema migration
or a concurrency-critical redesign that shouldn't ride in on an audit sweep. Linear issues
filed for the HIGH items.

### H1 — Post-commit block GC can corrupt a repo under concurrent same-repo writes
- **Where:** `record_write.rs::gc_repo_blocks` (called from `record_write.rs`,
  `routes/delete_record.rs`, `routes/apply_writes.rs`); deletion in
  `db/blocks.rs::delete_unreachable_blocks`.
- **Mechanism:** GC computes the reachable set from *this* request's post-commit root and
  deletes every other block-owner row (and unowned bytes) for the account, outside any
  transaction and without re-checking the root. If write B commits R1→R2 between write A's
  commit and A's GC delete (possible across await points even on the single-connection pool),
  A's GC deletes B's new blocks. The persisted root is then R2 pointing at deleted blocks →
  `Repository::open` fails → **all** subsequent writes/`getRepo`/blob-GC for that repo fail
  permanently.
- **Fix direction:** a per-DID async write mutex shared by the write path and GC, or make the
  delete conditional on the still-current root computed in one transaction.

### H2 — Blob metadata is single-owner keyed by CID; a shared blob can be destroyed
- **Where:** `db/blobs.rs::insert_blob` (`ON CONFLICT(cid) DO UPDATE` keeps the first
  uploader's `account_did`/`temp_until`), `blob_gc.rs` (reconciles per-owner-DID),
  `account_delete.rs` (deletes the on-disk file by path).
- **Mechanism:** repo blocks got a multi-owner `block_owners` table (V035); blobs did not.
  With multiple accounts (the server supports claim-code signups), if account B uploads bytes
  already owned by A, the row still says A: B's `getBlob` 404s; blob GC can release the blob
  against A's MST and delete the file B references; purging A deletes a file B still links.
- **Fix direction:** a `blob_owners` table mirroring `block_owners`; delete the file only when
  no owner remains. Latent for a strictly single-account instance.

### M1 — A cancelled request between commit and firehose `finish()` can wedge all writes
- **Where:** `firehose.rs` staged path (`stage_commit`/`PendingCommit::finish`), callers in
  `record_write.rs` etc.
- **Mechanism:** the `repo_seq` row becomes durable at the caller's `tx.commit()`, but
  `last_seq` advances only in `finish()` after. If the handler future is dropped in between,
  a durable row exists at seq N while `last_seq` stays N−1; every later emit computes seq = N
  and hits the `repo_seq` PK → every write 500s until process restart (restart re-seeds from
  `MAX(seq)`).
- **Fix direction:** on a unique-violation insert, re-seed `last_seq` from `MAX(seq)` and retry
  once; or advance the frontier from the durable row.

### M2 — One slow cursor-replay subscriber blocks all other cursor subs + firehose GC
- **Where:** `firehose.rs::subscribe_from` (`retention_replay_lock` held for the whole drain),
  `firehose_gc.rs`.
- **Mechanism:** a subscriber draining an old cursor slowly holds an exclusive lock, so any
  other relay reconnecting with a cursor blocks before it can send even an error frame, and
  `firehose_gc` can't prune (`repo_seq` grows unbounded).
- **Fix direction:** per-reader snapshot / prune-floor watermark check per page instead of an
  exclusive mutex across the drain.

### M3 — Hostile CAR bytes panic the import path (defects in the atrium-repo dependency)
- **Where:** `import_repo.rs` → `car_import.rs` → atrium-repo `blockstore/car.rs` (unchecked
  `data_len - (offset - start)`, `vec![0; attacker_len]`).
- **Mechanism:** an authenticated account holder can post a crafted CAR to `importRepo` that
  panics the request task (overflow subtraction) or drives a giant allocation. Also: non-SHA2-256
  block CIDs skip hash verification and are re-hashed on persist, so a crafted CAR can persist a
  repo with a dangling MST reference (violates import's all-or-nothing contract).
- **Fix direction:** a validated-CAR front-end in `import_repo_car` — frame-length sanity,
  reject non-SHA2-256 multihashes, and verify every MST/record CID the walk references exists in
  the captured block set — before handing bytes to `CarStore`.

### Lower-severity (documented, not filed)
- **repo-engine:** out-of-`i64`/`u64`-range integers in imported records read back as JSON
  `null` (`records.rs::record_value_to_json`); NSID validation is more permissive than the spec
  (`validate_collection` allows leading digits/hyphens, >63-char segments); `RawConfig` in
  `common` carries plaintext secrets under `#[derive(Debug)]` (validated `Config` correctly wraps
  them in `Sensitive`; nothing logs the raw form today).
- **pds:** re-uploading previously-expired temp blob content doesn't refresh the grace clock
  (`db/blobs.rs`), so a retry after TTL can be swept immediately; `createRecord` silently ignores
  `swapCommit` (other write routes honor it); `uploadBlob` ignores the request `Content-Type`
  (MIME is sniff-only), so a `blob:image/*`-scoped token is rejected for an SVG avatar.

### Verified sound (for confidence)
Shamir GF(2⁸) arithmetic and AES-256-GCM key wrapping; commit signing (low-S, correct signed
bytes); DAG-CBOR canonicity (golden-tested against `@ipld/dag-cbor`); MST layering/split/merge
(interop-fixture-pinned); CAR export framing; firehose ordering (persist-before-broadcast,
disjoint replay/live boundary, restart-safe seq); account lifecycle transitions and the
write-path active-status re-check at commit; token TTL math and app-password privilege
re-derivation on refresh. Request-path panic sweep came back clean (every `unwrap`/index is
invariant-guarded and unreachable from user input).

---

## Capability coverage vs. a daily-driver Bluesky PDS

Every `com.atproto.*` route a daily driver needs is implemented: server sessions,
createAccount/describeServer, app passwords, email/account management, repo CRUD + applyWrites
+ uploadBlob + importRepo + listMissingBlobs, the full sync surface incl. Sync v1.1 (`#sync`
frames, `prevData`, per-op `prev`) and `subscribeRepos`, identity (resolve/updateHandle/PLC-op
signing), service proxying to the AppView with read-after-write munging, chat proxy, the full
atproto OAuth provider stack (PAR, DPoP, rotating refresh, revoke, client-metadata resolution,
granular scopes), preferences, invite/signup, and moderation/admin.

**The gaps are validation, not features:**
1. The **live migration round trip** (bsky.social → ezpds and the credible-exit leg, MM-241)
   has never been executed — the runbook exists with a blank execution record. This is the exact
   path a real account takes. Do not move a real account before it passes.
2. **First real OAuth login by the official Bluesky app** is implemented but unproven — the
   interop suite and HTTP tests authenticate with `createSession` passwords, never OAuth/DPoP.
3. **`atproto-proxy` header is honored only for `com.atproto.moderation.*`**, not `app.bsky.*`,
   so `app.bsky.video.*` (routed by the official app with that header) will not reach the video
   service — **posting video from the official app likely fails**. The resolution machinery
   already exists in the moderation branch; generalizing it is the fix.
4. **Operational config, not code:** the default email sender only logs — password reset,
   PLC-op, email-confirm and account-delete tokens go nowhere until `[email] provider = "smtp"`
   is set.

Proven against the live network (interop suite, staging): account provisioning, identity
triple-agreement, repo CRUD with CID match, live firehose observation, CAR export consistency,
PDS→AppView proxy auth, real social interactions, full account lifecycle incl. reaper purge.

---

## Refactoring opportunities (for contributor onboarding)

1. **Extract the shared record-write preamble.** `delete_record.rs` and `apply_writes.rs`
   duplicate `record_write.rs`'s entire gather phase (DID resolution, auth/scope, lifecycle 403,
   root load, signer load) verbatim — three copies of the lifecycle-guard reasoning is where the
   next drift bug lands.
2. **Unify blob ownership with the block model** (also fixes H2): a `blob_owners` table would
   make the two content-addressed stores one teachable pattern.
3. **Split the largest modules:** `routes/oauth_token.rs` (~3.1k lines; three grant handlers +
   claim polling), `firehose.rs` (~2.5k; sequencer + staging state machine + stored-event codec —
   the codec is a clean Functional Core extraction), `read_after_write/mod.rs`, `create_did.rs`,
   `db/accounts.rs`.
4. **Move refresh-token rotation SQL into `db/refresh_tokens.rs`** so the table's write-side
   invariants (the guard from fix #7) live next to its reads, per the crate's "queries in db/"
   rule (`db/transfers.rs` already takes `&mut SqliteTransaction`).
5. **One generic sweeper scaffold** for `account_reaper.rs`/`blob_gc.rs`/`firehose_gc.rs` — they
   hand-roll the identical spawn/interval/stats/metrics skeleton (~120 duplicated lines).
6. **Split `repo-engine/records.rs` by concern** (TID codec, JSON↔IPLD, path validation, repo
   ops) and give a shared "sign → finalize" helper a home (the natural anchor for the rev-guard
   from fix #6).
