# custos-spaces

Last verified: 2026-11-24

The Atproto Spaces feature crate: every `com.atproto.space.*` and `com.atproto.memberspace.*`
route, the operator's `/v1/admin/spaces` pair, the space authorization
seam, the space query modules, both space sweeps, and the `spaces` capability entry. It depends on
[`custos-core`](../custos-core/AGENTS.md) and [`custos-db`](../custos-db/AGENTS.md), never on `pds`
or a sibling feature, so `cargo test -p custos-spaces` builds neither the OAuth server nor agents.
The rationale is archived at
[docs/archive/design-plans/2026-10-21-feature-crates.md](../../docs/archive/design-plans/2026-10-21-feature-crates.md);
where its sketch differs from this map (`internal_router` keeps the operator pair when disabled,
`spawn_sweeps` registers on the shared scheduler, the route-import rule is a review rule rather
than a compile error), this map is current.

This file is a map; mechanism and invariants live in each module's `//!` doc.

## What `pds` consumes

`lib.rs` is the contract; `pds` uses nothing else:

| Export | Use in `pds` |
|---|---|
| (state) | handlers extract `State<CoreState>`; the feature owns no state of its own |
| `router` / `internal_router` | merged unconditionally in `app.rs` before the layer stack. `router` is empty unless `[spaces] enabled`; `internal_router` always carries `/v1/admin/spaces{,/takedown}` (the operator's takedown governs data already stored, ADR-0035) and nothing else |
| `spawn_sweeps(&mut Scheduler, &SpacesConfig)` | `main.rs`; registers both sweeps on `pds`'s scheduler only when enabled, so graceful shutdown covers them |
| `CAPABILITY` | listed in `pds`'s `CAPABILITIES` between `appPasswordPersonalDetails` and `waitlist`; `enabled` must mirror the router gate plus the master key |
| `purge_account_rows` / `PURGE_ACCOUNT_SQL` | `account_delete::purge_account` runs it inside its transaction; its schema-walking FK test reads `PURGE_ACCOUNT_SQL`. Which rows go (and that `spaces` survives) is tested here, beside a walk of the `space*` tables' account FKs |
| `space_record_write` | `pds`'s blob-GC test, which seeds a space record |
| `test_support` (`test-support` feature) | `test_app(state)` (plus everything in `custos_core::test_support`), `SpaceSigKey`, request builders |

## Module Map

```
src/
  lib.rs           — the exports above
  router.rs        — the route table and the `[spaces] enabled` gate (`scripts/bruno-parity.sh` reads its `.route(` literals)
  capability.rs    — `CAPABILITY`, the `spaces` entry of the `describeServer` table
  policy.rs        — the space policy (V079): the closed `SpacePolicy { Personal, Member, Managed }` enum, its normalization from the wire (`UnsupportedPolicy`) and from storage, the app perimeter, `require_memberspace` (`PolicyMismatch`), and the published-record builders (`com.atproto.space.policy/self`, `com.atproto.memberspace.member/<did>`) plus `commit_with_published`, which lands them in the configuration change's transaction — see module doc
  space_record_write.rs — the single write choke point for permissioned space repos (V065, DB-backed, no MST): validate → CAS rev → LtHash fold → oplog append → writer-set row, all one transaction; a write into the writer's own space needs that space created first, and a commit that empties a repo leaves it at the empty-set digest (nothing is collected); `clear_space_records` is `clearRecords`' commit; blob refs are GC-derived, and the notification fan-out is spawned from here post-commit so no write path can skip it. `apply_space_writes` refuses direct writes to the published policy/member collections in any repo; `apply_space_writes_in_tx` is the caller-transaction variant only `policy.rs` uses; `import_space_repo` is the migration import, which replaces a repo outright (fresh rev, empty oplog, no notification, no write points) on a deactivated account — see module doc
  kem_gate.rs      — `require_kem_key_published`: every space write route except the migration imports, and `policy::commit_with_published` when it has records to publish (through the caller's transaction, `require_kem_key_published_in`), refuses with `KemKeyNotPublished` until the writer's cached DID document publishes its active KEM key (ADR-0043); reads are not gated, and `published_kem_private_key` is what `space_mac` keys a read's MAC through — see module doc
  space_migration.rs — the two migration STAR archives: `atproto-space-repo` (`getRepo` writes it, `importRepo` reads and verifies it against its own commit) and `atproto-space-meta` (`exportSpaceMeta` / `importSpaceMeta`: policy, member list, writer set). Its module doc lists the deliberate divergences from the reference (deactivated-only imports, no KEM check on import, no takedown exit lane on exports yet, a per-space takedown blocks the authority's export)
  space_mac.rs     — MACs on the four space reads (`getRecord`, `getLatestCommit`, `listRepoOps`, `getRepo`): parse the syncer's `Accept-Signature` (malformed, or none on a space-credential read, is `InvalidSpaceMac`), agree the secret from its key share and the account's KEM key, answer with `Atproto-Space-{Commit,Record}` + `Signature-Input`/`Signature`, and vary every response on `Accept-Signature`; an account whose KEM key is unpublished is served without a MAC — see module doc
  space_notify.rs  — outbound Atproto Spaces notifications: `report_write` (repo host → authority, one service-authed `notifyRepoUpdate`, retrying transient failures), `forward_write` / `forward_removed` / `fan_out_space_deleted` (authority → registered syncers, `notifySpaceUpdate` in the `{space, token, update}` envelope, one attempt each, 4 at once, never unregisters), and `confirm_registration` (the `confirmRegistration` challenge echo); detached and bounded — see module doc
  space_jti_sweep.rs — periodic retention sweep for `space_jti_replay` and `space_revoked_credentials`; each row carries its own horizon
  space_oplog_sweep.rs — hourly `space_repo_ops` compaction sweep (7-day retention): the oplog is droppable by spec, and a syncer whose `since` predates the window heals via `getRepo` — see module doc
  views.rs         — shared handler-free support for the space + memberspace routes: space-ref parsing, the `validate`-flag record check, stored-block decoding, the write-result shape, repo-head load and the unsigned commit (`load_repo`/`current_commit`/`SpaceCommit`), blob-reference derivation (`space_blob_cids`), and `load_active_space` (row + parsed policy, or `SpaceNotFound`)
  test_support.rs  — `test-support` feature (and this crate's own tests): `test_app` merges both routers under the same layers `pds` applies (shared stack, XRPC error dialect, CORS), so a path no Spaces route claims is a plain 404 here — tests that need `pds`'s `/xrpc/{method}` catch-all stay in `pds`
  auth/            — the space authorization seam (table below); the verification core is named at `custos_core::auth::…`
  db/              — the space query modules (table below); the shared tables are named at `custos_db::…`
  routes/          — one file per endpoint; `routes/mod.rs` re-exports handler functions only
```

### `auth/`

| File | Pattern | Contents |
|---|---|---|
| `client_attestation.rs` | Imperative Shell | Atproto Spaces client attestation: verify the JWT an app signs to name itself to a space authority (`typ atproto-client-attestation+jwt`, `iss` = `sub` = `client_id`, `aud` the space host, single-use `jti`). Resolves the caller-named `client_id` to its client-metadata document and JWKS through the SSRF-hardened client — skip that and memberspace's `allowedApps` is an unverified claim, not a perimeter. Key resolution is shared verbatim with the token endpoint (`jwks::client_verification_key`) — see module doc |
| `http_signature.rs` | Functional Core | RFC 9421 HTTP Message Signatures as Atproto Spaces profiles them for a space credential: the signature tagged `atproto-space-credential` (selected by tag, never label; P-256 `did:key`, raw `r‖s`, either S) that binds each credential-authed request to `cnf.kid` and an audience. The structured-field parse and signature base are `crypto::http_signature`'s, shared with the MAC profiles; the reference's test cases are ported — see module doc |
| `space.rs` | Mixed (unavoidable) | the one authorization seam every `com.atproto.space.*` route enters through: authenticate, confirm the caller owns the repo it named, and match the operation against its `space:` grant. A read naming another account's repo answers `RepoNotFound`, not `Forbidden` — deliberate non-disclosure. Mixed because a grant naming no `collection` falls back to the space type declaration's, resolved over the network — see module doc Also the Atproto Spaces token machinery: delegation-token mint/verify (single-use via `space_jti_replay`), space-credential mint/verify (10 min, `cnf.kid`-bound, a `jti` its authority has not revoked; signed by the authority's `#atproto` key), the issuance policy, and the credential arm of `authenticate_space_read` — a covering OAuth grant on the caller's own repo *or* a credential for any repo in the space, presented as `Atproto-Space-Credential` (scheme case-insensitive) and signed per RFC 9421 (`http_signature.rs`) over the request's audience DID, never bearer or DPoP; the credential and credential-signature verifiers are private to `auth`, so no route can re-derive it. Issuance is two perimeters, both decided by the `SpacePolicy`: app first (memberspace's `allowedApps`, decided from the stored policy alone, so a refused app is never disclosed to a third-party managing app) then account (personalspace: the authority alone; memberspace: its public flags and member bits; managedspace: an outbound service-auth `com.atproto.managedspace.checkAccess`, resolved per call through the SSRF-hardened client with its timeout, that denies on any failure to get an answer). The management and space-host seams (`authenticate_space_authority`, `authenticate_space_access`) are siblings built on the same arms. Account lifecycle is enforced at three cuts on purpose: `require_serviceable_caller` (the gate every account-credential arm passes) refuses moderation states (`AccountTakedown`) but admits self-service deactivation — that is the migration window; `require_available_repo` answers a credential read of a non-active writer's repo `RepoTakendown`/`RepoDeactivated`; and `require_active_space_host` gates only `authorizeSpaceSync` and `listWriters` on the authority's own status (same two codes), so an issued credential keeps reading the other writers' repos until it expires. `require_space_servable` is the third, per-*space* cut: the operator's V070 takedown, answering `SpaceNotFound` after authentication at every seam (the write path re-reads the same row inside its commit transaction) — see module doc |

**Seam held by visibility:** `verify_space_credential` is private to `auth::space`, and
`verify_credential_signature` is `pub(super)` to `auth`. Never widen them: every space
read authenticates through `auth::space::authenticate_space_read`.

### `db/`

| File | Contents |
|---|---|
| `spaces.rs` | `spaces` rows (V065/V070/V079): every space this PDS interacts with, keyed by canonical URI, with its normalized `policy` JSON (read through `SpaceRow::space_policy`; NULL for a foreign authority's space), plus the memberspace `space_members` list — the `insert_space` (member write) vs `create_space` (authority create) distinction is in the module doc; the remaining notify queries land with the space-host surface. V070's `takendown_at` is the operator's refusal to serve, independent of the authority's `deleted_at` tombstone — `set_space_takedown` writes it, `list_hosted_spaces` is the operator listing |
| `space_meta.rs` | the writer-set half of a space meta archive: `all_writers` for the export (removed writers left out), `replace_writers` for the import (which moves `last_space_rev` forward, never back) |
| `space_notify.rs` | the space-host notification tables: `space_notify_registrations` (V081, a syncer's `(endpoint, token)` per space, made through `authorizeSpaceSync` and expiring with its credential; `put_registration` enforces the per-space cap and refuses a deleted space in the same statement as the write, and `prune_lapsed_registrations` drops rows lapsed over 72 h without a claimed expiry notice) and `space_writers` (V067/V073/V074/V083, the `listWriters` set; `upsert_writer` returns a `WriterUpdate` that decides which notification follows, `remove_writer` marks a row removed at a new space revision, and a newer write clears the mark). Expiry is enforced by the read query, not a sweep — see module doc |
| `space_repos.rs` | permissioned repo store queries (V065): repo heads (rev + LtHash state), record blocks, oplog; the write transaction lives in `space_record_write.rs` — see module doc |
| `space_jti.rs` | spaces-token jti replay store (V065): scope-discriminated insert-if-absent + the expiry sweep; and the credential revocation store (V075, keyed `(space_uri, jti)`, read by the credential verifier) — see module doc |

### `routes/`

| File | Endpoint |
|---|---|
| `get_delegation_token.rs` | `GET /xrpc/com.atproto.space.getDelegationToken` — mint a single-use 60 s delegation token for a space (account-key JWT, `kid #atproto`); requires an OAuth/full session whose grant covers `read` on the space; the space need not be known here |
| `authorize_space_sync.rs` | `POST /xrpc/com.atproto.space.authorizeSpaceSync` — the space-authority side, with no request authorization: body `credentialKey` (a P-256 `did:key`, becomes `cnf.kid`) plus an optional `delegationToken` and `clientAttestation` → 10 min space credential and the space's `spaceRev`; answers only for spaces anchored on a local, active account (`RepoTakendown`/`RepoDeactivated` otherwise). Without a delegation token only a `publicRead` memberspace mints; `allowedApps` still holds. The attestation is verified whenever present, after the delegation token when there is one. `notify: {endpoint, token}` registers the syncer until the credential's `exp`: the endpoint must be https on a domain host (`validate_notify_endpoint`); a new registration is refused past 100 active per space (`TooManyRegistrations`, Custos's own bound) and must echo a `confirmRegistration` challenge (`RegistrationNotConfirmed`); a definite refusal withdraws it (under a managedspace only `AppNotAuthorized` is definite, since an unreachable managing app also answers `AccountNotAuthorized`) |
| `admin_spaces.rs` | `GET /v1/admin/spaces` + `POST /v1/admin/spaces/takedown` — per-space operator moderation: the inventory of what this host stores (owned *and* foreign-authority spaces, with repo/record counts) and the reversible refusal to serve one URI. The only lever that reaches a space governed elsewhere, where `deleteSpace` is not this host's to call; not gated on `[spaces] enabled` — see module doc and [ADR-0035](../../docs/architecture/decisions/0035-per-space-operator-takedown.md) |
| `space_create_record.rs` | `POST /xrpc/com.atproto.space.createRecord` — create a record in the caller's own permissioned space repo |
| `space_put_record.rs` | `POST /xrpc/com.atproto.space.putRecord` — upsert; reads the record's presence first so an app granted only `update` is not asked for `create` too |
| `space_delete_record.rs` | `POST /xrpc/com.atproto.space.deleteRecord` — idempotent *here*, by skipping the commit for an absent record; the store keeps the strict precondition `applyWrites` needs |
| `space_apply_writes.rs` | `POST /xrpc/com.atproto.space.applyWrites` — batch of ≤200 writes in one commit; every op states a precondition, so the batch lands whole or reports `RecordAlreadyExists`/`RecordNotFound` |
| `space_list_spaces.rs` | `GET /xrpc/com.atproto.space.listSpaces` — spaces the caller has *written to* or is the authority for (never a membership list), each with the caller's `repoRev`/`data` when it holds a repo and `spaceRev` for the authority; the query's filters (`spaceType`, `spaceDid`) are what its `space:` grant is matched against, since it names no one space |
| `space_get_record.rs` | `GET /xrpc/com.atproto.space.getRecord` — a requested MAC covers the record's uri and cid (`space_mac`) |
| `space_list_records.rs` | `GET /xrpc/com.atproto.space.listRecords` — `(collection, rkey)` keyset paging, values inlined unless `excludeValues` |
| `space_get_latest_commit.rs` | `GET /xrpc/com.atproto.space.getLatestCommit` — the repo's unsigned commit `{ver, repo, space, rev, data}` (`views::current_commit`), authenticated by a requested MAC (`space_mac`) |
| `space_list_repo_ops.rs` | `GET /xrpc/com.atproto.space.listRepoOps` — page the oplog since a rev; only a record's *current* value is inlined (stale ops join to nothing); every page carries the current commit (and a requested MAC over it), a full page also a `rev/idx` cursor — see module doc |
| `space_get_repo.rs` | `GET /xrpc/com.atproto.space.getRepo` — a streaming `atproto-space-repo` STAR archive: the commit as metadata, records in strict bytewise path order; the MAC rides the response headers — see module doc |
| `space_import_repo.rs` | `POST /xrpc/com.atproto.space.importRepo` — lands a `getRepo` archive as the caller's repo (`RepoMismatch` for another account's, `InvalidRepoFile` for one that does not verify); a deactivated account and a grant over the whole space |
| `space_export_space_meta.rs` / `space_import_space_meta.rs` | `GET /xrpc/com.atproto.space.exportSpaceMeta` / `POST …importSpaceMeta` — the authority's space meta archive; the import creates the space (or replaces its policy), replaces members and writers, publishes nothing, and refuses policy state the policy does not define (`InvalidSpaceMeta`) |
| `space_get_blob.rs` | `GET /xrpc/com.atproto.space.getBlob` — space-authed blob serving; a stored-but-unreferenced blob answers the same `BlobNotFound` as an unknown CID, and the response is `Cache-Control: private` (unlike the public route's immutable-public) — see module doc |
| `space_list_writers.rs` | `GET /xrpc/com.atproto.space.listWriters` — the space host's writer set (repos that have *written*, never a reader list): each repo's latest update, a `repoWrite` with its last-reported `repoRev`/`data` or a `repoRemoved`, in ascending `spaceRev` order (the cursor is a `spaceRev`, `prevSpaceRev` is never set); taken-down writers are listed; a space whose authority is elsewhere reads as `SpaceNotFound`, and a non-active authority answers `RepoTakendown`/`RepoDeactivated` |
| `space_remove_writer.rs` | `POST /xrpc/com.atproto.space.removeWriter` — take an account out of the writer set at a new `spaceRev` and send the `repoRemoved` to the registered syncers; `manage=update`, authority only, any policy; no-op for an account not in the set; its next authorized write rejoins it |
| `space_clear_records.rs` | `POST /xrpc/com.atproto.space.clearRecords` — delete every record in the caller's own repo in a space as one commit (new rev, oplog cleared, announced like any write); the authority's published policy/member records are kept; a `delete` grant per cleared collection; nothing to delete commits nothing |
| `space_notify_repo_update.rs` | `POST /xrpc/com.atproto.space.notifyRepoUpdate` — inbound report from a foreign repo host. Deliberately *not* `require_service_auth` (that guard demands a local issuer); the key is resolved from the network and the issuer must be the repo — see module doc |
| `space_notify_credentials_revoked.rs` | `POST /xrpc/com.atproto.space.notifyCredentialsRevoked` — the repo-host side of credential revocation: service auth verified like `notifyRepoUpdate`'s, but the issuer must be the space authority and `aud` may be any local account (the lexicon addresses a repo DID) or this server; idempotent, recorded only for a space known here. The authority-side fan-out is not built — see module doc |
| `space_list_blobs.rs` | `GET /xrpc/com.atproto.space.listBlobs` — blob CIDs referenced by a repo's records (derived by decoding stored blocks, like blob GC), `since` filtered on V066's per-record rev |
| `space_create_space.rs` | `POST /xrpc/com.atproto.space.createSpace` — a space anchored on the caller's own DID under a full `policy` (normalized by `policy.rs`; `UnsupportedPolicy` for an unknown `$type`); `manage=create`; a published policy record lands in the same transaction |
| `space_update_space.rs` | `POST /xrpc/com.atproto.space.updateSpace` — replaces the policy wholesale, `manage=update`, authority only; a `$type` change deletes the member list but not the writer set, and the published records follow in the same transaction |
| `space_delete_space.rs` | `POST /xrpc/com.atproto.space.deleteSpace` — tombstone + cleanup (members, registrations, writer set, the authority's own repo) then a best-effort `spaceDeleted` notice to every registration, lapsed included, idempotent; `manage=delete`, authority only — see module doc |
| `space_get_space.rs` | `GET /xrpc/com.atproto.space.getSpace` — `{space, policy}`; OAuth `read_self`, authority only (a space credential does not reach it) |
| `memberspace_put_members.rs` / `memberspace_remove_members.rs` | `POST /xrpc/com.atproto.memberspace.{putMembers,removeMembers}` — batches of ≤ 100 (lexicon-bounded) on a memberspace only (`PolicyMismatch`); `putMembers` upserts each member's `read`/`write` bits (read at credential mint, write on `notifyRepoUpdate`), `removeMembers` ignores non-members; a removed member, or one put with `write: false`, leaves the writer set in the same transaction; published member records follow in the same transaction; `manage=update`, authority only |
| `memberspace_list_members.rs` | `GET /xrpc/com.atproto.memberspace.listMembers` — OAuth `read_self`, authority only, memberspace only, DID-keyset paged |
| `space_registration_test.rs` | notification registration through `authorizeSpaceSync` against a wiremock syncer on `localhost`: confirm once, renew without confirming, expiry at the credential's `exp`, a write arriving as `repoWrite`, the endpoint check, the cap, withdrawal on refusal |
| `space_policy_routes_test.rs` | the management journeys: the three baseline policies through the routes, `$type` changes, publishing, the authority gate, and `listSpaces`' authority entries |
| `space_lifecycle_test.rs` | account-lifecycle + migration coverage for the space surface: which account states may touch a space repo, the repo lifecycle (own space must exist; an emptied repo stays, reading as empty everywhere), and both migration legs: `getRepo` → `importRepo`, and an authority's `exportSpaceMeta` → `importSpaceMeta` → `getRepo` → `importRepo` across two hosts, each asserted on the set hash (the digest syncers fold against) |

## Rules

- **Routes do not import routes.** Shared route support goes in `views.rs`, `auth/`, `db/`, or a
  top-level module. Rust privacy does not enforce this between sibling modules, so it is a review
  rule here as in `pds`.
- **Never depend on `pds` or a sibling feature crate.** Anything two features need moves down to
  `custos-core` (or `custos-db` for a table).
- **The gate lives in `router.rs`.** `pds` merges unconditionally; a new space route is registered
  in `router`/`internal_router` and gets a `.bru` file in `bruno/` (root AGENTS.md).
- **Migrations stay in `custos-db`.** A new space table's migration goes there; its queries come here.
