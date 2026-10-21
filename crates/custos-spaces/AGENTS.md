# custos-spaces

Last verified: 2026-10-21

The Atproto Spaces feature crate: every `com.atproto.space.*` and `com.atproto.simplespace.*`
route, `/v1/space/import-repo`, the operator's `/v1/admin/spaces` pair, the space authorization
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
| `SpacesState` (`core: CoreState` + `space_type_cache`, `Deref<Target = CoreState>`) | `AppState.spaces`, projected by `impl FromRef<AppState> for SpacesState` |
| `router` / `internal_router` | merged unconditionally in `app.rs` before the layer stack. `router` is empty unless `[spaces] enabled`; `internal_router` always carries `/v1/admin/spaces{,/takedown}` (the operator's takedown governs data already stored, ADR-0035) and adds `/v1/space/import-repo` only when enabled |
| `spawn_sweeps(&mut Scheduler, &SpacesConfig)` | `main.rs`; registers both sweeps on `pds`'s scheduler only when enabled, so graceful shutdown covers them |
| `CAPABILITY` | listed in `pds`'s `CAPABILITIES` between `appPasswordPersonalDetails` and `waitlist`; `enabled` must mirror the router gate plus the master key |
| `purge_account_rows` / `PURGE_ACCOUNT_SQL` | `account_delete::purge_account` runs it inside its transaction; the schema-walking FK test reads `PURGE_ACCOUNT_SQL` |
| `db::*` | `blob_gc` unions `db::space_repos::list_record_blocks_for_account` into blob references |
| `space_record_write` | `pds` tests that seed space records |
| `consent` | the OAuth consent page (`routes/oauth_authorize.rs`, `routes/oauth_templates.rs`) renders `space:` grants through it; takes `&CoreState` |
| `test_support` (`test-support` feature) | `test_app(state)`, the `SpacesState` constructors, `SpaceSigKey`, request builders |

## Module Map

```
src/
  lib.rs           — the exports above; aliases `custos_core`'s modules at the crate root so `crate::identity::…` resolves as it did in `pds`
  state.rs         — `SpacesState`; `FromRef<SpacesState> for CoreState`
  router.rs        — the route table and the `[spaces] enabled` gate (`scripts/bruno-parity.sh` reads its `.route(` literals)
  capability.rs    — `CAPABILITY`, the `spaces` entry of the `describeServer` table
  space_record_write.rs — the single write choke point for permissioned space repos (V065, DB-backed, no MST): validate → CAS rev → LtHash fold → oplog append → writer-set row, all one transaction; blob refs are GC-derived, and the notification fan-out is spawned from here post-commit so no write path can skip it. `SpaceWriteAdmission` is the one knob on its account-lifecycle guard: `Import` admits the deactivated state migration runs in (and skips write-point charging), `Active` is everything else — see module doc
  space_notify.rs  — outbound Atproto Spaces write notifications: the repo-host → space-host report (with the authority auto-registration that creates the subscription) and the space-host → registered-syncer fan-out; detached, retrying, bounded — see module doc
  space_jti_sweep.rs — periodic `space_jti_replay` retention sweep; each row carries its own token's acceptance horizon
  space_oplog_sweep.rs — hourly `space_repo_ops` compaction sweep (7-day retention): the oplog is droppable by spec, and a syncer whose `since` predates the window heals via `getRepo` — see module doc
  consent.rs       — the user-legible text `/oauth/authorize` shows for `space:` grants: the space type declaration's `name` (localized), a named authority's bidirectionally-verified handle, the collections a bare grant resolves to, and the both-wildcards warning. Reuses `permission_sets.rs`'s Lexicon resolution path and TTL-cache machinery; degrades to the raw token instead of failing the page — see module doc
  views.rs         — shared handler-free support for the space + simplespace routes: space-ref parsing, the `validate`-flag record check, stored-block decoding, the write-result shape, repo-head load + per-serving commit signing (`load_repo`/`sign_current_commit`/`commit_json`), blob-reference derivation (`space_blob_cids`), and the simplespace config's lexicon-union ↔ column mapping
  test_support.rs  — `test-support` feature (and this crate's own tests): `test_app` merges both routers under the same layers `pds` applies (shared stack, XRPC error dialect, CORS), so a path no Spaces route claims is a plain 404 here — tests that need `pds`'s `/xrpc/{method}` catch-all stay in `pds`
  auth/            — the space authorization seam (table below); `custos_core::auth` is re-exported here
  db/              — the space query modules (table below); `custos_db`'s cross-feature modules are re-exported here crate-privately
  routes/          — one file per endpoint; `routes/mod.rs` re-exports handler functions only
```

### `auth/`

| File | Pattern | Contents |
|---|---|---|
| `client_attestation.rs` | Imperative Shell | Atproto Spaces client attestation: verify the JWT an app signs to name itself to a space authority (`typ atproto-client-attestation+jwt`, `iss` = `sub` = `client_id`, `aud` the space host, single-use `jti`). Resolves the caller-named `client_id` to its client-metadata document and JWKS through the SSRF-hardened client — skip that and `appAccess: #allowList` is an unverified claim, not a perimeter. Key resolution is shared verbatim with the token endpoint (`jwks::client_verification_key`) — see module doc |
| `http_signature.rs` | Functional Core | RFC 9421 HTTP Message Signatures as Atproto Spaces profiles them: the one `atproto-space` signature (P-256 `did:key`, raw `r‖s`, either S) that binds a delegation exchange to its key and each credential-authed request to `cnf.kid` and an audience. Parses `Signature-Input`/`Signature` as full RFC 8941 structured fields because the signature base embeds the re-serialized inner list; the reference's test cases are ported — see module doc |
| `space.rs` | Mixed (unavoidable) | the one authorization seam every `com.atproto.space.*` route enters through: authenticate, confirm the caller owns the repo it named, and match the operation against its `space:` grant. A read naming another account's repo answers `RepoNotFound`, not `Forbidden` — deliberate non-disclosure. Mixed because a grant naming no `collection` falls back to the space type declaration's, resolved over the network — see module doc Also the Atproto Spaces token machinery: delegation-token mint/verify (single-use via `space_jti_replay`), space-credential mint/verify (10 min, `cnf.kid`-bound; `#atproto_space` key, `#atproto` accepted only when no dedicated key is published), the issuance policy, and the credential arm of `authenticate_space_read` — a covering OAuth grant on the caller's own repo *or* a credential for any repo in the space, presented as `Atproto-Space` and signed per RFC 9421 (`http_signature.rs`) over the request's audience DID, never bearer or DPoP; the credential and credential-signature verifiers are private to `auth`, so no route can re-derive it. Issuance is two perimeters, app first (`appAccess` decides from stored config alone, so a refused app is never disclosed to a third-party managing app) then user (`public`/`member-list`/`managing-app`, the last an outbound service-auth `checkUserAccess` that denies on any failure to get an answer). The simplespace management/read seams (`authenticate_space_owner`, `authenticate_space_access`) are siblings built on the same arms. Account lifecycle is enforced at two different cuts on purpose: `require_serviceable_caller` (the gate every account-credential arm passes) refuses moderation states but admits self-service deactivation — that is the migration window — while `require_serviceable_authority` (the space-*host* arm) demands a fully active authority before this server answers a syncer's credential for its space. `require_space_servable` is the third, per-*space* cut: the operator's V070 takedown, answering `SpaceNotFound` after authentication at every seam (the write path re-reads the same row inside its commit transaction) — see module doc |

**Seam held by visibility:** `verify_space_credential` is private to `auth::space`, and
`verify_space_signature` / `SignedFor` are `pub(super)` to `auth`. Never widen them: every space
read authenticates through `auth::space::authenticate_space_read`.

### `db/`

| File | Contents |
|---|---|
| `spaces.rs` | `spaces` rows (V065/V069/V070): every space this PDS interacts with, keyed by canonical URI, plus the `space_members` list and the `allowList` client-ID set (`app_allowed`, read through `SpaceRow::allowed_client_ids` — an absent or unparseable list reads as empty, which admits no app) — the `insert_space` (member write) vs `create_space` (simplespace create) distinction is in the module doc; the remaining notify queries land with the space-host surface. V070's `takendown_at` is the operator's refusal to serve, independent of the owner's `deleted_at` tombstone — `set_space_takedown` writes it, `list_hosted_spaces` is the operator listing |
| `space_notify.rs` | the space-host notification tables: `space_notify_registrations` (V065, one table for both roles — `repo_did = ''` is a whole-space subscription on a space host, a named repo is the auto-registration a repo host writes for itself) and `space_writers` (V067, the `listRepos` set). Expiry is enforced by the read query, not a sweep — see module doc |
| `space_repos.rs` | permissioned repo store queries (V065): repo heads (rev + LtHash state), record blocks, oplog; the write transaction lives in `space_record_write.rs` — see module doc |
| `space_jti.rs` | spaces-token jti replay store (V065): scope-discriminated insert-if-absent + the expiry sweep — see module doc |

### `routes/`

| File | Endpoint |
|---|---|
| `get_delegation_token.rs` | `GET /xrpc/com.atproto.space.getDelegationToken` — mint a single-use 60 s delegation token for a space (account-key JWT, `kid #atproto`); requires an OAuth/full session whose grant covers `read` on the space; the space need not be known here |
| `get_space_credential.rs` | `POST /xrpc/com.atproto.space.getSpaceCredential` — the space-authority side: delegation token (Authorization) + an RFC 9421 `atproto-space` signature over it → 10 min space credential bound to the signature's key (`cnf.kid`); answers only for spaces anchored on a local account. An optional `clientAttestation` is verified whenever present, but only *after* the delegation token, so no unauthenticated caller can drive its outbound client_id resolution; the attested client_id then feeds both issuance perimeters |
| `admin_spaces.rs` | `GET /v1/admin/spaces` + `POST /v1/admin/spaces/takedown` — per-space operator moderation: the inventory of what this host stores (owned *and* foreign-authority spaces, with repo/record counts) and the reversible refusal to serve one URI. The only lever that reaches a space governed elsewhere, where `deleteSpace` is not this host's to call; not gated on `[spaces] enabled` — see module doc and [ADR-0035](../../docs/architecture/decisions/0035-per-space-operator-takedown.md) |
| `space_create_record.rs` | `POST /xrpc/com.atproto.space.createRecord` — create a record in the caller's own permissioned space repo |
| `space_put_record.rs` | `POST /xrpc/com.atproto.space.putRecord` — upsert; reads the record's presence first so an app granted only `update` is not asked for `create` too |
| `space_delete_record.rs` | `POST /xrpc/com.atproto.space.deleteRecord` — idempotent *here*, by skipping the commit for an absent record; the store keeps the strict precondition `applyWrites` needs |
| `space_apply_writes.rs` | `POST /xrpc/com.atproto.space.applyWrites` — batch of ≤200 writes in one commit; every op states a precondition, so the batch lands whole or reports `RecordAlreadyExists`/`RecordNotFound` |
| `space_list_spaces.rs` | `GET /xrpc/com.atproto.space.listSpaces` — spaces the caller has *written to* (never a membership list); the query's filters are what its `space:` grant is matched against, since it names no one space |
| `space_get_record.rs` | `GET /xrpc/com.atproto.space.getRecord` |
| `space_list_records.rs` | `GET /xrpc/com.atproto.space.listRecords` — `(collection, rkey)` keyset paging, values inlined unless `excludeValues` |
| `space_get_latest_commit.rs` | `GET /xrpc/com.atproto.space.getLatestCommit` — mints a fresh deniable commit per serving (new `ikm`/`sig`/`mac` each time); never stored (`views::sign_current_commit`) |
| `space_list_repo_ops.rs` | `GET /xrpc/com.atproto.space.listRepoOps` — page the oplog since a rev; only a record's *current* value is inlined (stale ops join to nothing); a short page reaches the head and carries the signed commit, a full page a `rev/idx` cursor — see module doc |
| `space_get_repo.rs` | `GET /xrpc/com.atproto.space.getRepo` — streaming two-root CAR (signed commit, then DRISL index in canonical DAG-CBOR key order, record blocks in index order); `excludeValues` writes only the roots — see module doc |
| `space_import_repo.rs` | `POST /v1/space/import-repo` — the inbound migration leg for a permissioned repo, consuming `space.getRepo`'s two-root CAR. Custos-native (`/v1/*`), because the alpha lexicons define no space import; deactivated-account precondition like `com.atproto.repo.importRepo`, and the repo becomes *exactly* the CAR (records the index omits are deleted in the same commit) — see module doc |
| `space_get_blob.rs` | `GET /xrpc/com.atproto.space.getBlob` — space-authed blob serving; a stored-but-unreferenced blob answers the same `BlobNotFound` as an unknown CID, and the response is `Cache-Control: private` (unlike the public route's immutable-public) — see module doc |
| `space_list_repos.rs` | `GET /xrpc/com.atproto.space.listRepos` — the space host's writer set (repos that have *written*, never a reader list) with each repo's last-reported `repoRev`/`hash` and the `spaceRev` it last changed at (ascending `spaceRev` order, the cursor is a `spaceRev`); a space whose authority is elsewhere reads as `SpaceNotFound` |
| `space_register_notify.rs` / `space_unregister_notify.rs` | `POST /xrpc/com.atproto.space.{registerNotify,unregisterNotify}` — syncer subscriptions on the space host; the subscriber is a *service identifier* (DID + optional `#fragment`) resolved at registration (`ServiceNotResolvable`), re-registering renews the expiry, unregister is idempotent |
| `space_notify_write.rs` | `POST /xrpc/com.atproto.space.notifyWrite` — inbound report from a foreign repo host. Deliberately *not* `require_service_auth` (that guard demands a local issuer); the key is resolved from the network and the issuer must be the repo or the space authority — see module doc |
| `space_list_blobs.rs` | `GET /xrpc/com.atproto.space.listBlobs` — blob CIDs referenced by a repo's records (derived by decoding stored blocks, like blob GC), `since` filtered on V066's per-record rev |
| `simplespace_create_space.rs` | `POST /xrpc/com.atproto.simplespace.createSpace` — a space anchored on the caller's own DID, with separate `readPolicy`/`writePolicy`; `manage=create`; unimplemented open-union config values refused |
| `simplespace_update_space.rs` | `POST /xrpc/com.atproto.simplespace.updateSpace` — `manage=update`, owner only |
| `simplespace_delete_space.rs` | `POST /xrpc/com.atproto.simplespace.deleteSpace` — tombstone + cleanup (members, registrations, writer set, the authority's own repo) then a best-effort `notifySpaceDeleted` fan-out, idempotent; `manage=delete`, owner only — see module doc |
| `simplespace_get_space.rs` | `GET /xrpc/com.atproto.simplespace.getSpace` — the one simplespace method a space credential reaches; OAuth callers are owner-only |
| `simplespace_put_member.rs` / `simplespace_remove_member.rs` | `POST /xrpc/com.atproto.simplespace.{putMember,removeMember}` — the member list behind the `member-list` policies (`putMember` upserts the member's `read`/`write` bits, read at credential mint, write on `notifyWrite`); `manage=update`, owner only, idempotent |
| `simplespace_list_members.rs` | `GET /xrpc/com.atproto.simplespace.listMembers` — OAuth `read_self`, owner only, DID-keyset paged |
| `space_lifecycle_test.rs` | account-lifecycle + migration coverage for the space surface: which account states may touch a space repo, and the `getRepo` → `/v1/space/import-repo` round trip (asserted on the set hash, the digest syncers fold against) |

## Rules

- **Routes do not import routes.** Shared route support goes in `views.rs`, `auth/`, `db/`, or a
  top-level module. Rust privacy does not enforce this between sibling modules, so it is a review
  rule here as in `pds`.
- **Never depend on `pds` or a sibling feature crate.** Anything two features need moves down to
  `custos-core` (or `custos-db` for a table).
- **The gate lives in `router.rs`.** `pds` merges unconditionally; a new space route is registered
  in `router`/`internal_router` and gets a `.bru` file in `bruno/` (root AGENTS.md).
- **Migrations stay in `custos-db`.** A new space table's migration goes there; its queries come here.
