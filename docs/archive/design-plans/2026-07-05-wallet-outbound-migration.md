# Wallet Outbound Migration Orchestration Design

## Summary

The wallet-authorized outbound migration (ADR-0002 path 1) moves an ezpds identity from one PDS to
another entirely under the wallet's control, without depending on the old PDS's cooperation for the
DID-repointing step. The design adds a new `migration_orchestrator.rs` module in the
identity-wallet's Tauri backend that mirrors the existing `claim.rs` state-machine pattern: a
sequential pipeline of fine-grained, individually-invokable commands, each gated by a prerequisite
phase check and a DID match, with state parked in `AppState` behind a mutex. The pipeline logs into
the source PDS, mints a service-auth token to create a deactivated destination account under the
same DID, transfers the repo CAR, drains blobs, copies preferences, verifies the import via
`checkAccountStatus`, then hands off to the already-built `migrate.rs` module (MM-229) to render and
submit the PLC operation for biometric approval, and finally activates the destination account and
deactivates the source. Because state is in-memory only, resumability is achieved by re-deriving
progress from the destination server's own state (`DidAlreadyExists`, `listMissingBlobs`,
`checkAccountStatus`) rather than by persisting a resume checkpoint.

The main technical wrinkle this introduces is that the destination account, once created in
migration mode, is authenticated with a plain legacy Bearer session rather than an OAuth/DPoP
session — so `OAuthClient` gains a second `AuthMode` alongside the existing DPoP mode, used only for
talking to the freshly-created destination account. The design keeps this work strictly scoped to
the orchestration plumbing: the migration UI, path-detection logic (self-signed vs. interop), and
outbound email are explicitly deferred to other tickets, and the identity-signing leg itself is
reused unchanged from MM-229 rather than rebuilt.

## Definition of Done

MM-228 is complete when:

1. **`OAuthClient` gains a Bearer-session mode** — it can send `Authorization: Bearer {token}`
   with no DPoP proof header, and refresh via `com.atproto.server.refreshSession` (legacy
   session semantics), for authenticating as the migrated (deactivated) account on the
   destination PDS. The existing DPoP/OAuth mode is untouched.

2. **A migration orchestration module** exists in `apps/identity-wallet/src-tauri/`, mirroring
   the `claim.rs` state machine (state parked in `AppState` behind a `tokio::sync::Mutex`, each
   command validating prerequisites, `_impl` test helpers extracting core logic from Tauri's
   `State` wrapper). It exposes **fine-grained per-step Tauri commands** driving the
   wallet-authorized (ADR-0002 path 1) outbound migration:
   - Fresh source-PDS OAuth login (prepare/complete pair, like the claim flow).
   - Mint a service-auth JWT from the source PDS (`com.atproto.server.getServiceAuth`).
   - Create the destination account deactivated with the existing DID
     (`com.atproto.server.createAccount`, migration mode) → obtain a destination **Bearer
     session**.
   - Transfer the repo CAR (`sync.getRepo` old → `repo.importRepo` new).
   - Drain blobs (`sync.listBlobs`/`getBlob` old → `uploadBlob` new, guided by
     `repo.listMissingBlobs`) until none remain.
   - Transfer preferences (`app.bsky.actor.getPreferences` old → `putPreferences` new).
   - Verify import via `com.atproto.server.checkAccountStatus`.
   - **Pause for approval**: build the identity-leg PLC op (via MM-229's `migrate.rs`,
     populating `MigrationState.dest_oauth_client`), surface its diff, and stop. The UI shows
     the diff, gets biometric approval, then the flow submits the op and finalizes.
   - Finalize: `activateAccount` (new) then `deactivateAccount` (old).

   Resume is **server-derived**: tolerate `DidAlreadyExists` on re-run, use `listMissingBlobs`
   and `checkAccountStatus` as resume checklists, rely on idempotent activate/deactivate. State
   is in-memory only (dies on app kill; re-derived by querying the destination). Errors are a
   typed SCREAMING_SNAKE_CASE enum surfaced to the frontend.

3. **TypeScript IPC wrappers + types** in `src/lib/ipc.ts` for every new command, matching the
   serialization contracts (SCREAMING_SNAKE_CASE error codes, camelCase field names).

4. **Tests:** Rust httpmock integration tests covering the pipeline and its failure/resume
   paths, **plus** a `migrate` command added to the interop CLI (`tools/interop/src/migrate.js`
   + a `cli.js` case) that drives the full self-signed migration against a configurable
   destination PDS (`--target-pds`), runnable when a second instance is available (not wired
   into the default single-PDS `suite` run).

**Explicitly out of scope:** the migration UI screens (MM-232), path detection
self-signed-vs-interop (MM-230), the PDS-signed interop fallback path, and outbound email
delivery (MM-211).

## Acceptance Criteria

### wallet-outbound-migration.AC1: A wallet-authorized outbound migration drives to completion
- **wallet-outbound-migration.AC1.1 Success:** Given a wallet-controlled DID and a reachable
  destination PDS, running the commands in phase order (`prepare_migration` → `prepare/complete_source_auth`
  → `create_destination_account` → `transfer_repo` → `transfer_blobs` → `transfer_preferences` →
  `verify_import` → `arm_identity_leg` → identity submit → `finalize_migration`) moves the identity between
  two ezpds instances with the repo serveable on the new PDS and the DID's `atproto_pds` repointed.
- **wallet-outbound-migration.AC1.2 Success:** `finalize_migration` activates the destination account,
  then deactivates the source account, in that order.
- **wallet-outbound-migration.AC1.3 Failure:** Any command invoked out of phase order (e.g. `transfer_repo`
  before `create_destination_account`) returns `MIGRATION_NOT_READY` without performing network side effects.
- **wallet-outbound-migration.AC1.4 Failure:** A command whose `did` argument does not match
  `OutboundMigrationState.did` returns `MIGRATION_NOT_READY` (defense-in-depth against a concurrent flow).
- **wallet-outbound-migration.AC1.5 Failure:** `prepare_migration` against an unreachable destination PDS
  returns `DESTINATION_UNREACHABLE`.

### wallet-outbound-migration.AC2: Repo, blobs, and preferences transfer to the destination
- **wallet-outbound-migration.AC2.1 Success:** `transfer_repo` exports the source CAR and imports it into
  the deactivated destination account.
- **wallet-outbound-migration.AC2.2 Success:** `transfer_blobs` drains `list_missing_blobs` on the
  destination, fetching each missing CID from the source and uploading it, until the missing set is empty.
- **wallet-outbound-migration.AC2.3 Success:** The blob loop walks multiple `list_missing_blobs` pages via
  cursor and terminates when a page returns an empty set.
- **wallet-outbound-migration.AC2.4 Success:** `transfer_preferences` reads source preferences and writes
  them to the destination.
- **wallet-outbound-migration.AC2.5 Edge:** `transfer_blobs` on an account with no missing blobs completes
  immediately (empty first page) without error.
- **wallet-outbound-migration.AC2.6 Failure:** A failed `getBlob`/`uploadBlob`/`list_missing_blobs` leg
  returns `BLOB_TRANSFER_FAILED` and leaves the phase un-advanced so the step can be retried.

### wallet-outbound-migration.AC3: Import completeness is verified before the identity leg
- **wallet-outbound-migration.AC3.1 Success:** `verify_import` returns the destination `checkAccountStatus`
  fields and advances to `Verified` when `imported_blobs == expected_blobs` and record counts reconcile.
- **wallet-outbound-migration.AC3.2 Success:** `verify_import` does **not** require `valid_did` to be true
  (the DID doc still points at the old PDS pre-identity-op).
- **wallet-outbound-migration.AC3.3 Failure:** When blobs/records do not yet reconcile, `verify_import`
  returns `VERIFICATION_INCOMPLETE` carrying the imported/expected counts.

### wallet-outbound-migration.AC4: The identity leg is handed off for user approval
- **wallet-outbound-migration.AC4.1 Success:** `arm_identity_leg` populates
  `migrate::MigrationState.dest_oauth_client` with the destination Bearer client and advances to
  `IdentityArmed`, so the existing `migrate::build_migration_op_cmd` can render the PLC diff and
  `migrate::submit_migration_op_cmd` can submit after biometric approval.
- **wallet-outbound-migration.AC4.2 Success:** The identity op runs after `verify_import` and before
  `finalize_migration`'s `activateAccount`.
- **wallet-outbound-migration.AC4.3 Failure:** `arm_identity_leg` before `verify_import` returns
  `MIGRATION_NOT_READY`.

### wallet-outbound-migration.AC5: Partial failure is resumable and leaves a coherent state
- **wallet-outbound-migration.AC5.1 Success:** Re-running `create_destination_account` after the account
  already exists tolerates `DidAlreadyExists` and re-establishes the destination Bearer session.
- **wallet-outbound-migration.AC5.2 Success:** Re-running `transfer_blobs` after a partial drain resumes and
  uploads only the still-missing blobs (verified via `list_missing_blobs`).
- **wallet-outbound-migration.AC5.3 Success:** `finalize_migration`'s `activateAccount` is retry-tolerant:
  a repeat call on an already-active account succeeds (idempotent), and a call that fails on transient
  DID-propagation can be retried.
- **wallet-outbound-migration.AC5.4 Edge:** On abort before the identity op, the destination account remains
  deactivated (coherent, not half-live).

### wallet-outbound-migration.AC6: OAuthClient supports a Bearer-session mode
- **wallet-outbound-migration.AC6.1 Success:** A Bearer-mode client sends `Authorization: Bearer {token}`
  and no `DPoP` header.
- **wallet-outbound-migration.AC6.2 Success:** A Bearer-mode client refreshes via
  `com.atproto.server.refreshSession`, not `/oauth/token`.
- **wallet-outbound-migration.AC6.3 Success:** `post_bytes` sends the provided body with the given
  `Content-Type` (e.g. `application/vnd.ipld.car`).
- **wallet-outbound-migration.AC6.4 Success:** The existing DPoP mode is unchanged — its tests still pass.

### wallet-outbound-migration.AC7: The migration XRPC client surface exists
- **wallet-outbound-migration.AC7.1 Success:** Each new client function (`get_service_auth`,
  `create_account_migration`, `import_repo`, `upload_blob`, `list_missing_blobs`, `get_preferences`,
  `put_preferences`, `check_account_status`, `activate_account`, `deactivate_account`, `fetch_repo_car`,
  `fetch_blob`) issues the correct method, path, and auth, and parses its response.
- **wallet-outbound-migration.AC7.2 Success:** `get_service_auth` requests a token with `aud = dest_did`
  and `lxm = com.atproto.server.createAccount`.
- **wallet-outbound-migration.AC7.3 Success:** `fetch_repo_car`/`fetch_blob` use the unauthenticated
  `PdsClient` (the endpoints are `auth: none`).

### wallet-outbound-migration.AC8: The commands are callable from the frontend with matching types
- **wallet-outbound-migration.AC8.1 Success:** `src/lib/ipc.ts` exposes a typed wrapper for every new
  orchestrator command.
- **wallet-outbound-migration.AC8.2 Success:** The TS `MigrationError` union matches the Rust enum's
  SCREAMING_SNAKE_CASE codes exactly.
- **wallet-outbound-migration.AC8.3 Success:** `pnpm check` (frontend type-check) passes.

### wallet-outbound-migration.AC9: The interop CLI can drive the migration end-to-end
- **wallet-outbound-migration.AC9.1 Success:** `migrate perform --name <n> --target-pds <url>` drives the
  seven-step flow against a live source→destination pair, self-signing the PLC op with the rotation key in
  `.state/state.json`.
- **wallet-outbound-migration.AC9.2 Success:** `migrate verify --name <n> --target-pds <url>` confirms the
  handle, DID, and repo resolve to the new PDS after migration.
- **wallet-outbound-migration.AC9.3 Edge:** The `migrate` command is not part of the default single-PDS
  `suite` run and requires an explicit `--target-pds`.

### wallet-outbound-migration.AC10: Cross-cutting behaviors
- **wallet-outbound-migration.AC10.1:** `MigrationError` serializes as `{ "code": "SCREAMING_SNAKE_CASE" }`,
  matching the wallet's established error contract.
- **wallet-outbound-migration.AC10.2:** The orchestrator never POSTs to plc.directory itself; the only
  plc.directory write is `migrate::submit_migration_op_cmd`, which prevents double-post.
- **wallet-outbound-migration.AC10.3:** Migration state lives only in `AppState` (in-memory); an app kill
  loses it and the flow restarts from `prepare_migration`.

## Glossary

- **ATProto (AT Protocol)**: The federated social-networking protocol (used by Bluesky) that
  defines DIDs, PDSs, repos, and the XRPC API this document's migration flow implements.
- **PDS (Personal Data Server)**: The server that hosts a user's repo, blobs, and preferences and
  speaks the ATProto XRPC surface; migration moves a user from a "source" PDS to a "destination" PDS.
- **did:plc**: The ATProto DID method backed by a public, append-only operation log (hosted at
  `plc.directory`) that records a DID's current rotation keys and PDS endpoint (`atproto_pds`
  service).
- **plc.directory**: The hosted service that stores and serves did:plc operation logs; POSTing a
  signed operation here is what actually repoints a DID to a new PDS.
- **PLC operation / rotation keys**: A signed, versioned record appended to a DID's did:plc log;
  `rotationKeys` are the keys authorized to sign such operations, and the "identity leg" of migration
  is producing and submitting one that changes the PDS endpoint.
- **DPoP (Demonstrating Proof-of-Possession)**: An OAuth extension that binds access tokens to a
  client-held key via a signed proof header sent on every request; the wallet's existing
  `OAuthClient` mode for authenticated PDS calls.
- **Bearer session / Bearer-session mode**: A simpler legacy auth mode (`Authorization: Bearer
  {token}`, no proof header) used for the migrated account on the destination PDS immediately after
  `createAccount`, refreshed via `com.atproto.server.refreshSession` instead of OAuth's
  `/oauth/token`.
- **Service-auth JWT**: A short-lived, purpose-scoped token (`com.atproto.server.getServiceAuth`)
  minted on the source PDS, bound to a specific audience DID (`aud`) and method (`lxm`), used to
  authorize account creation on the destination.
- **CAR (Content Addressable aRchive)**: The binary format (`application/vnd.ipld.car`) used to
  export/import an entire repo in one transfer (`sync.getRepo` / `repo.importRepo`).
- **MST (Merkle Search Tree)**: The data structure ATProto uses to store repo records inside the CAR
  file, referenced here as part of why blobs must be imported after the repo (so record references
  resolve).
- **Blobs**: Binary attachments (e.g. images) referenced by repo records but stored separately;
  transferred via `listMissingBlobs`/`getBlob`/`uploadBlob` after the repo import.
- **Tauri command**: A Rust function in the Tauri app backend exposed to the SvelteKit frontend via
  IPC (`invoke`); each migration step is implemented as one such command.
- **ADR-0002**: The architecture decision record establishing that ezpds migration is
  wallet-authorized by default (the wallet signs the identity-repointing PLC op directly, bypassing
  the old PDS's email-tokened `signPlcOperation` flow), with a PDS-signed path reserved as a fallback
  for identities the wallet doesn't yet control.
- **The migrate.rs identity leg**: The already-landed (MM-229) module that builds and submits the
  DID-repointing PLC operation for wallet-signed migrations; it exposes `build_migration_op_cmd`
  (renders the diff for user review) and `submit_migration_op_cmd` (POSTs to plc.directory), and
  expects its `MigrationState.dest_oauth_client` to be populated by this design's orchestrator.
- **checkAccountStatus**: The XRPC endpoint on the destination PDS that reports import progress
  (blob/record counts, `valid_did`), used both to verify completeness before the identity op and as a
  resume checklist.
- **Deactivated account**: The state a destination account is created in during migration-mode
  `createAccount` — it exists and can receive data but is not yet "live"; `activateAccount` promotes
  it after the identity op lands, and the source is `deactivateAccount`'d last.

## Architecture

The wallet-authorized outbound migration (ADR-0002 path 1) is a sequential command
pipeline in `apps/identity-wallet/src-tauri/`, modeled on the existing `claim.rs` state
machine. A new module `migration_orchestrator.rs` owns the flow; the identity-signing leg
reuses the already-landed `migrate.rs` (MM-229) unchanged.

**State.** A single `OutboundMigrationState` is parked in a new
`AppState.orchestration_state: tokio::sync::Mutex<Option<OutboundMigrationState>>`, plus a
`pending_source_login: Mutex<Option<PendingSourceLogin>>` (twin of `pending_pds_login`) for the
source-PDS OAuth prepare/complete split. State is in-memory only — an app kill loses it and the
UI restarts from `prepare_migration`; each step is written to re-derive its position from the
destination server (see Resume semantics).

```
struct OutboundMigrationState {
    did: String,
    dest_pds_url: String,
    dest_did: String,                          // getServiceAuth `aud`, from dest describeServer
    handle: String,                            // preserved into createAccount
    source_client: Option<Arc<OAuthClient>>,   // DPoP mode, old PDS
    dest_client:   Option<Arc<OAuthClient>>,   // Bearer mode, new PDS (from createAccount)
    phase: MigrationPhase,
}

enum MigrationPhase {                          // drives prerequisite checks + resume hints
    Resolved, SourceAuthed, DestCreated, RepoTransferred,
    BlobsTransferred, PreferencesTransferred, Verified, IdentityArmed, Finalized,
}
```

**Two clients, split by auth need.** The old PDS is reached with a DPoP `OAuthClient` obtained by
a fresh interactive OAuth login; the new PDS is reached with a **Bearer-session** `OAuthClient`
built from the session `createAccount` returns. Public sync reads (`getRepo`, `getBlob`,
`auth: none`) use the stateless `PdsClient` reqwest client. The destination Bearer client is also
what the identity leg needs, so the orchestrator hands it to `migrate.rs` via
`MigrationState.dest_oauth_client` before the identity-op step.

**Command surface (fine-grained, per-step).** Each Tauri command validates its prerequisite phase
and the DID (defense-in-depth, like `claim.rs`), so the UI (MM-232) drives and can retry any step:

| Command | Does | Advances to |
|---|---|---|
| `prepare_migration(did, dest_pds_url)` | resolve dest `describeServer` → `dest_did` + reachability; store state | `Resolved` |
| `prepare_source_auth()` / `complete_source_auth(callback_url)` | fresh OAuth+DPoP login on old PDS (parks `PendingSourceLogin`) | `SourceAuthed` |
| `create_destination_account()` | `getServiceAuth`(old) → `createAccount`(new, deactivated) → Bearer session | `DestCreated` |
| `transfer_repo()` | `fetch_repo_car`(old) → `import_repo`(new) | `RepoTransferred` |
| `transfer_blobs()` | drain `list_missing_blobs`(new) → `fetch_blob`(old) → `upload_blob`(new) | `BlobsTransferred` |
| `transfer_preferences()` | `getPreferences`(old) → `putPreferences`(new) | `PreferencesTransferred` |
| `verify_import()` | `checkAccountStatus`(new); return status; gate on blobs+records (not `valid_did`) | `Verified` |
| `arm_identity_leg()` | copy `dest_client` → `migrate::MigrationState.dest_oauth_client` | `IdentityArmed` |
| *(UI: existing `migrate::build_migration_op_cmd` → biometric → `migrate::submit_migration_op_cmd`)* | render PLC diff, approve, POST to plc.directory | — |
| `finalize_migration()` | `activateAccount`(new, retry-tolerant) → `deactivateAccount`(old) | `Finalized` |

**Execution sequence and ordering constraints** (confirmed against the canonical goat flow —
`ACCOUNT_MIGRATION.md`, atproto.com/guides/account-migration):
- `getServiceAuth` on the old PDS is minted with `aud = dest_did` and
  `lxm = com.atproto.server.createAccount` (method-bound).
- `import_repo` **must** precede the blob loop — blobs uploaded before the repo is indexed are
  garbage-collected for lack of record references.
- The blob loop is driven by `list_missing_blobs` on the **new** PDS (cursor-paginated,
  `{cid, recordUri}`), draining until the missing set is empty.
- `verify_import` gates on `imported_blobs == expected_blobs` and record counts but **not**
  `valid_did` — the DID doc still points at the old PDS until the identity op lands, so
  `valid_did` is expected to be false here.
- The identity op (self-signed, POSTed directly to plc.directory by `migrate.rs`) runs **after**
  transfer/verify and **before** `activateAccount`.
- `activateAccount`(new) is retry-tolerant: the new PDS may need a moment to observe the repointed
  DID document before it reports `valid_did` and activates. `deactivateAccount`(old) is the
  **last** step.

## Existing Patterns

This design follows patterns already established in `apps/identity-wallet/src-tauri/`:

- **State-machine module mirroring `claim.rs`.** `claim.rs` is a sequential command pipeline with
  state parked in `AppState` behind a `tokio::sync::Mutex<Option<ClaimState>>`, each command
  validating prerequisites and the DID, `Arc<OAuthClient>` cloned out of the lock before network
  calls, and `_impl` helpers extracting core logic from Tauri's `State` wrapper.
  `migration_orchestrator.rs` adopts this structure verbatim.
- **OAuth prepare/complete split around the in-app auth session.** `claim::prepare_pds_auth` /
  `complete_pds_auth` (parking `PendingPdsLogin`, driving `plugin:auth-session|start`, sharing
  `oauth::parse_callback_url` + `OAuthPrepared`) is the exact template for
  `prepare_source_auth` / `complete_source_auth` and the new `PendingSourceLogin`.
- **Identity-leg reuse (`migrate.rs`, MM-229).** `migrate.rs` was deliberately built as a pure,
  independently-testable identity leg whose destination `OAuthClient` is "populated by the
  migration orchestrator" (its own doc comment). Its `build_migration_op_cmd` (returns the PLC
  diff) → `submit_migration_op_cmd` (POSTs to plc.directory, `take()`s the op under lock to
  prevent double-post) already implement the pause-for-approval seam; the orchestrator reuses them
  unchanged.
- **Module-level XRPC helpers taking `&OAuthClient`.** `pds_client.rs` already exposes
  `get_recommended_did_credentials`, `request_plc_operation_signature`, `sign_plc_operation` as
  standalone functions (not `PdsClient` methods) because they need a DPoP-authenticated client.
  The new XRPC helpers follow the same convention.
- **Typed SCREAMING_SNAKE_CASE error enums.** Every wallet module serializes errors as
  `#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]` (`ClaimError`, `MigrateError`,
  `RecoveryError`); `MigrationError` matches.
- **httpmock integration tests.** `migrate.rs`/`recovery.rs` use `#[ignore]` socket-binding tests
  against mock plc.directory + PDS servers; the orchestrator's end-to-end test follows suit.
- **Interop CLI raw-XRPC/Bearer-session pattern.** `tools/interop/` drives a live deployment with
  raw XRPC over Bearer JWT sessions (no DPoP, no `@atproto/api`) and already holds each account's
  did:plc rotation key in `.state/state.json` — so it can self-sign the identity leg. The new
  `migrate` command follows the existing `create-account`/module + `cli.js` case pattern.

**Divergence:** `OAuthClient` currently sends `Authorization: DPoP` + a proof header
unconditionally and refreshes via `/oauth/token`. This design adds a Bearer-session mode (plain
`Authorization: Bearer`, no proof, refresh via `com.atproto.server.refreshSession`) gated by an
internal `AuthMode`, because the migrated account is authenticated on the destination by the
legacy session JWTs that migration-mode `createAccount` returns, not by an OAuth login. The DPoP
path is unchanged.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: OAuthClient Bearer-session mode + binary POST
**Goal:** `OAuthClient` can authenticate as a legacy Bearer session and send binary bodies, so the
destination (migrated, deactivated) account can be driven.

**Components:**
- `src-tauri/src/oauth_client.rs` — internal `AuthMode { Dpop, Bearer }`; `new_bearer(session,
  base_url)` constructor; `send_*` branches header construction on mode (`Authorization: Bearer`,
  no `DPoP` header in Bearer mode); `refresh_token` branches transport (`refreshSession` in Bearer
  mode); new `post_bytes(path, content_type, body)` for `application/vnd.ipld.car` and raw blobs.

**Dependencies:** None.

**Done when:** Unit tests confirm Bearer mode sends `Authorization: Bearer` with no `DPoP` header,
refresh hits `com.atproto.server.refreshSession` (not `/oauth/token`), `post_bytes` sets the given
`Content-Type`, and the existing DPoP tests still pass. Covers `wallet-outbound-migration.AC6.*`.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Migration XRPC client surface
**Goal:** Client functions for every migration XRPC leg exist and are individually tested.

**Components:**
- `src-tauri/src/pds_client.rs` — public unauthenticated fetches on `PdsClient`:
  `fetch_repo_car(pds_url, did)`, `fetch_blob(pds_url, did, cid)`. Module-level XRPC helpers taking
  `&OAuthClient`: `get_service_auth(client, aud, lxm)`, `create_account_migration(client, req)`,
  `import_repo(client, car)`, `upload_blob(client, mime, bytes)`, `list_missing_blobs(client,
  cursor)`, `get_preferences(client)`, `put_preferences(client, value)`,
  `check_account_status(client)`, `activate_account(client)`, `deactivate_account(client,
  delete_after)`. New response types: `ServiceAuthToken`, `CreateAccountResponse`, `MissingBlobs`,
  `AccountStatus`.

**Dependencies:** Phase 1 (`post_bytes` for `import_repo`/`upload_blob`).

**Done when:** Each helper has a mock-server unit test asserting method, path, auth header, and
response parsing. Covers `wallet-outbound-migration.AC7.*`.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Orchestrator module — state, setup, and auth
**Goal:** The state machine exists with the resolve + source-auth + destination-account-creation
front half.

**Components:**
- `src-tauri/src/migration_orchestrator.rs` (new) — `OutboundMigrationState`, `MigrationPhase`,
  `MigrationError`, `PendingSourceLogin`; commands `prepare_migration`, `prepare_source_auth` /
  `complete_source_auth`, `create_destination_account` (mints service-auth JWT, creates the
  deactivated destination account, builds the Bearer `dest_client`, tolerates `DidAlreadyExists`).
- `src-tauri/src/oauth.rs` — add `orchestration_state` + `pending_source_login` fields to
  `AppState`.
- `src-tauri/src/lib.rs` — register the new commands.

**Dependencies:** Phases 1-2.

**Done when:** `_impl` tests confirm phase/DID prerequisite gating and the `DidAlreadyExists`
tolerance; the module compiles and commands are registered. Covers
`wallet-outbound-migration.AC1.*` (auth/setup portion).
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Orchestrator — data transfer + verification
**Goal:** Repo, blobs, and preferences transfer to the destination and import is verified.

**Components:**
- `src-tauri/src/migration_orchestrator.rs` — commands `transfer_repo`, `transfer_blobs` (drains
  `list_missing_blobs`), `transfer_preferences`, `verify_import` (returns `AccountStatus`, gates on
  blobs/records, not `valid_did`).

**Dependencies:** Phase 3.

**Done when:** `_impl` tests cover the blob-drain loop (multi-page cursor walk terminates on
empty; a fully-drained account returns immediately) and `verify_import` completeness logic. Covers
`wallet-outbound-migration.AC2.*`, `wallet-outbound-migration.AC3.*`.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Orchestrator — identity handoff + finalize
**Goal:** The identity leg is armed for the existing `migrate.rs` commands, and the migration
finalizes.

**Components:**
- `src-tauri/src/migration_orchestrator.rs` — `arm_identity_leg` (populates
  `migrate::MigrationState.dest_oauth_client`), `finalize_migration` (`activateAccount` new,
  retry-tolerant for DID propagation → `deactivateAccount` old).
- Full-pipeline `#[ignore]` mock integration test: mock old-PDS, new-PDS, plc.directory; drive
  every command incl. reuse of `migrate::build/submit`; assert ordering (import before blobs,
  identity before activate, deactivate last) and a resume case (pre-created + partially-blobbed
  destination re-runs cleanly).

**Dependencies:** Phase 4, `migrate.rs` (existing).

**Done when:** The pipeline + resume integration tests pass. Covers
`wallet-outbound-migration.AC1.*` (finalize), `wallet-outbound-migration.AC4.*`,
`wallet-outbound-migration.AC5.*`.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: TypeScript IPC wrappers + types
**Goal:** Every orchestrator command is callable from the frontend with matching types.

**Components:**
- `src/lib/ipc.ts` — typed wrappers for all new commands and types (`OutboundMigrationState` view
  fields, `AccountStatus`, `MigrationError` union matching the SCREAMING_SNAKE_CASE codes).
- `apps/identity-wallet/CLAUDE.md` — extend the `ipc.ts` exports list and add the module's
  contract entry.

**Dependencies:** Phases 3-5.

**Done when:** `pnpm check` (frontend type-check) passes; the `MigrationError` TS union matches the
Rust enum exactly. Covers `wallet-outbound-migration.AC8.*`.
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: Interop CLI migrate command
**Goal:** The full self-signed migration is runnable end-to-end against live infrastructure.

**Components:**
- `tools/interop/src/migrate.js` (new) — `performMigration({name, targetPds})` driving the seven
  steps with raw XRPC, self-signing the PLC op with the rotation key in `.state/state.json`;
  `verifyMigration({name, targetPds})` confirming handle/DID/repo resolve to the new PDS (reusing
  `identity.js`/`sync.js`).
- `tools/interop/src/cli.js` — a `migrate` command group (`perform`, `verify`) following the
  existing switch/`flags`/`print` pattern.
- `tools/interop/README.md` — a "migration" subsection documenting `--target-pds` and that it
  needs a second instance (not part of the default `suite`).

**Dependencies:** None on the Rust work (independent implementation exercising the server surface).

**Done when:** `just interop migrate perform --name <n> --target-pds <url>` drives a migration
against a second instance and `migrate verify` confirms resolution to the new PDS. Covers
`wallet-outbound-migration.AC9.*`.
<!-- END_PHASE_7 -->

## Additional Considerations

**DID-document propagation.** After the identity op is POSTed to plc.directory, the destination
PDS may briefly still see the old DID document (cache/propagation). `activateAccount` is therefore
retry-tolerant and idempotent; the UI (MM-232) surfaces a transient "waiting for identity to
propagate" state rather than a hard failure. This is the one place the flow waits on an external
system it does not control.

**Non-idempotent step isolation.** Every orchestrator step is safely re-runnable via server-derived
resume. The single non-idempotent action — the plc.directory POST — lives entirely in
`migrate::submit_migration_op_cmd`, which `take()`s the signed op under lock and clears state, so a
double-invoke cannot double-post. The orchestrator never POSTs to plc.directory itself.

**createAccount body shape.** The exact migration-mode `createAccount` request fields (handle,
optional email, optional invite code) must match the server's `create_account_xrpc.rs` migration
branch; implementation verifies against that handler and the `create_account_xrpc_migration.bru`
fixture rather than assuming.

**Bruno parity.** All destination XRPC endpoints already have `.bru` files
(`create_account_xrpc_migration`, `import_repo`, `list_missing_blobs`, `check_account_status`,
`activate_account`, `deactivate_account`, `get_preferences`, `put_preferences`, `get_service_auth`),
so no `bruno/` changes are required — this ticket adds a client, not a route.

**Out of scope (tracked elsewhere):** migration UI screens (MM-232), self-signed-vs-interop path
detection (MM-230), the PDS-signed interop fallback, and outbound email (MM-211).
