# PDS Crate (Custos)

Last verified: 2026-07-01

## Purpose

The PDS is the axum-based web server. It is the sole Imperative Shell in the workspace —
the only crate that touches SQLite, handles HTTP, or manages process-level state. All other
crates (`crypto`, `repo-engine`, `common`) are pure Functional Cores that the PDS calls.

## Module Map

```
src/
  main.rs          — startup: open pool, run migrations, bind server
  app.rs           — AppState definition and construction
  firehose.rs      — persistent subscribeRepos event pipeline (durable sequencer + broadcast fan-out)
  firehose_gc.rs   — periodic `repo_seq` retention sweep (age/count pruning below the live frontier)
  crawler.rs       — outbound requestCrawl notifier (rate-limited, retrying, fire-and-forget)
  iroh_tunnel.rs   — Iroh QUIC endpoint: NAT-traversing device↔pds tunnel (opt-in)
  record_write.rs  — shared repo write flow + firehose commit emission
  handle.rs        — handle validation (structural + domain policy), shared by provisioning + handle routes
  auth/            — authentication primitives (no HTTP, no DB schema ownership)
  db/              — SQL query functions + migration runner (no business logic)
  routes/          — HTTP handlers, one file per endpoint
```

### `firehose.rs`

The **persistent** event pipeline behind `com.atproto.sync.subscribeRepos`. Holds a durable
monotonic sequencer (backed by the `repo_seq` table, V028) and a Tokio `broadcast` channel;
`AppState.firehose: Arc<Firehose>` is shared by every handler. Each repo commit calls
`record_write::commit_repo_write`, which builds the commit's block diff
(`repo_engine::collect_commit_diff_cids` + `build_car_from_cids`, run *before* post-commit GC) and
publishes a sequenced `CommitEvent` carrying the DID, rev, `since`, `prevData` (the previous
commit's MST root CID — Sync v1.1's inductive-validation anchor, captured before the write mutates
the repo; `None` for genesis), per-record `RepoOp`s (action + collection/rkey + cid + value), and
the CARv1 diff blocks. The `#commit` wire frame emits the deprecated `blobs` list empty. Backpressure is by design: the bounded
channel never blocks producers — a slow subscriber observes `Lagged` and is expected to disconnect.
All three write paths (`create_record`/`put_record` via `record_write`, `delete_record`,
`apply_writes`) emit exactly one event per commit. (Those same write paths reject a deactivated
account with 403 before committing.) `create_did.rs`'s `promote_account` stages the same kind of
`#commit` event for a new account's *genesis* repo, atomically with the `accounts`/`did_documents`/
`sessions` inserts, so a fresh host self-announces to the relay instead of staying invisible until
its first record write; chained after that genesis `#commit` in the same transaction is a Sync v1.1
`#sync` state assertion (via `PendingCommit::stage_sync`, carrying a single-root CAR of just the
signed commit block), so a relay can anchor to this fresh host's head. It then emits a best-effort
`#account` (active) frame and calls `crawlers.notify()` once that transaction has committed.
A `#sync` frame (`SyncEvent`: DID, rev, and a ≤10 KB commit-block CAR) is the Sync v1.1 head
assertion relays use to auto-repair drift; it is emitted on account genesis (above) and on
`activateAccount` (chained after the `#account` via `PendingAccount::stage_sync` when the account
has a repo — the commit-block CAR is built *before* the transaction, since the single-connection
pool can't serve a block read while the tx holds the connection), and belongs on a future
`importRepo` once that lands. Account-status changes emit a separate
`#account` frame instead of a `#commit`: `activate_account.rs`/`deactivate_account.rs` stage one
via `Firehose::stage_account` (active=false/`deactivated` or active=true) **only on a real status
transition** — a redundant no-op activate/deactivate returns 200 and emits nothing.
`update_subject_status.rs` (`com.atproto.admin.updateSubjectStatus`) stages the same kind of frame
for an admin-driven takedown/clear, but derives `active`/`status` from the account's full
`AccountLifecycle` after the write rather than assuming its own dimension won — clearing a
takedown on a still-suspended account must report `suspended`, not `active`. The `#account` frame
shares the same sequencer so account frames are ordered relative to commits.

**Durability and atomicity.** `Firehose::emit_commit`/`emit_account`/`emit_identity`/`emit_sync`
persist each event to
`repo_seq` (via `db::firehose_seq`) **before** broadcasting it, all under one async `emit_lock`
that keeps broadcast order = `seq` order and the log a dense prefix (a failed insert doesn't
consume a `seq`). The sequencer loads `MAX(seq)` on construction, so `seq` is monotonic across
restarts/redeploys. Those methods remain bare best-effort primitives — used directly by tests,
`emit_identity`'s neighbours (`create_handle.rs`/`delete_handle.rs`/`update_handle.rs`), and
`create_did.rs`'s post-commit `emit_account` call, none of which need atomicity with a specific
transaction; the call sites that do instead acquire `emit_lock` via `Firehose::lock_emit`
(returning an `EmitGuard`) *before* opening their transaction, then call
`EmitGuard::stage_commit`/`stage_account` to insert the `repo_seq` row into that *caller's own*
open transaction. A caller that also needs a chained `#sync` in the same transaction (genesis,
activation) calls `PendingCommit::stage_sync`/`PendingAccount::stage_sync`, which inserts the
`#sync` row at the next `seq` and returns a `PendingWithSync` whose `finish` broadcasts the primary
event then the `#sync`, advancing the counter past both. The staging insert lands in the caller's
open transaction — the same one carrying the repo-root CAS (`record_write::commit_repo_write`,
`create_did.rs`'s genesis promotion) or the account-status UPDATE (`activate_account`/
`deactivate_account`) — and get back a `Pending*` handle that carries the guard forward. Acquiring
the lock before the transaction (rather than inside the staging call) matters on this crate's
single-connection pool: `emit_commit`/
`emit_account`/`emit_identity` already acquire the lock before touching the pool, so a staging
path that instead opened its transaction first and acquired the lock after could deadlock against
one of them (each would hold what the other is waiting for). The caller commits that transaction
and only then calls `Pending*::finish` to advance `last_seq` and broadcast; a failed insert rolls
the whole transaction back (via `?`/`Drop`) rather than landing the state change with a
silently-dropped event, and dropping a `Pending*` without finishing never advances the sequence,
so the seq is retried by the next emit. `subscribe_from(cursor)` snapshots the live receiver and
the sequence frontier `upper` together under
`emit_lock`; the `sync_subscribe_repos` handler then pages the durable log for `(cursor, upper]`
(`events_in_range`, decoded via `decode_stored_event`) and streams live events (`seq > upper`)
after — the two ranges are exactly disjoint, so the replay→live boundary has no gap and no
duplication, and replay now survives a restart (it reads the log, not an in-memory buffer). The
subscriber-facing WebSocket frame encoding lives in the `sync_subscribe_repos` handler.

### `crawler.rs`

Outbound `com.atproto.sync.requestCrawl` notifier. `AppState.crawlers: Arc<CrawlerNotifier>`
is shared by every handler; `record_write::commit_repo_write` calls `crawlers.notify()`
once per commit, right after the firehose event is emitted. `notify` is fire-and-forget: it
selects the crawlers outside their rate-limit window (one notification per crawler per 30s),
then spawns a detached task per crawler that POSTs `{ "hostname": <PDS-host> }` to
`<url>/xrpc/com.atproto.sync.requestCrawl`, retrying with exponential backoff up to 3 times.
All outcomes are logged, never propagated — a commit never blocks on or fails because of a
crawler. Configured via `[crawlers] urls = [...]` (default `["https://bsky.network"]`; empty
disables) or `EZPDS_CRAWLERS`.

### `iroh_tunnel.rs`

The Iroh QUIC tunnel — a NAT-traversing endpoint devices dial by node id instead of by a
routable address. Opt-in via `[iroh] enabled` (default off); when enabled, `main.rs` loads the
persistent node identity (`auth::load_or_create_iroh_secret_key`, backed by the `iroh_identity`
table so the node id is stable across restarts), binds the endpoint with the `N0` preset (n0
discovery + relays), and spawns a detached accept loop. `AppState.iroh: Option<Arc<IrohState>>`
holds the bound endpoint and its node-id string; `get_device_pds` advertises that node id.
The accept loop speaks a minimal v0.1 echo protocol on the `ezpds/iroh/0` ALPN — enough to
prove the bidirectional channel and serve as a liveness probe; the real repo-sync / push
protocols register here later. Errors are logged, never propagated (one bad peer never stops
the loop). The endpoint is closed on graceful shutdown, which ends the accept loop.

### `auth/`

Pure authentication logic and middleware. Submodules:

| File | Pattern | Contents |
|---|---|---|
| `dpop.rs` | Mixed (unavoidable) | DPoP proof validation, nonce store |
| `extractors.rs` | Imperative Shell | `AuthenticatedUser` axum extractor |
| `jwt.rs` | Functional Core | JWT parsing, scope validation, access/refresh token verification, HS256 token issuance |
| `password.rs` | Functional Core | `hash_password`, `verify_password` (argon2id) |
| `rate_limit.rs` | Functional Core | Sliding-window login-failure rate limiter |
| `signing_key.rs` | Imperative Shell | ES256 signing key load-or-create |
| `bearer.rs` | Functional Core | Bearer token extraction from headers |

**Rule:** `auth/` has no knowledge of specific routes. Route handlers call into `auth/`; `auth/` never imports from `routes/`.

### `db/`

SQL query functions organised by domain entity. Each submodule exposes plain data structs
and async query functions; no business logic lives here.

| File | Contents |
|---|---|
| `mod.rs` | `open_pool`, `run_migrations`, `DbError`, `is_unique_violation` |
| `accounts.rs` | `AccountRow` + `resolve_identifier` (handle/DID→account); `SessionAccountRow` + `get_session_account` (DID→account+handle+DID doc); `resolve_by_email` (email→account); `account_is_active`, `deactivate_account`/`activate_account` (flip `deactivated_at`, report the transition); `get_repo_write_state` + `advance_repo_root_if_active` (repo-write preconditions and the commit CAS); `get_account_overview` + `account_last_active` (operator usage/storage lookups — unfiltered by deactivation); `AccountLifecycle` + `get_repo_status`/`list_repos` (derive `active`/`status` from the `deactivated_at`/`suspended_at`/`taken_down_at` columns for the public sync endpoints); `set_account_takedown` + `TakedownStateChange` (flip `taken_down_at`, returning the account's full derived lifecycle so the caller's firehose event reflects takendown/suspended/deactivated precedence, not just the takedown dimension). All lifecycle-gated lookups (`get_session_account`, `resolve_identifier`, `resolve_by_email`, `account_is_active`, `get_repo_write_state`, `advance_repo_root_if_active`) now require `deactivated_at`/`suspended_at`/`taken_down_at` all NULL — a suspension or takedown closes logins and repo writes exactly like a self-service deactivation |
| `app_passwords.rs` | app-password store (V031): `insert_app_password` (409 on duplicate name), `list_app_passwords` (metadata, no hash), `list_verify_candidates` (hash + privilege for `createSession`), `app_password_privileged` (privilege re-derivation for `refreshSession`). Revocation's multi-table delete lives in `routes/revoke_app_password.rs` |
| `blocks.rs` | content-addressed repo-block store + `SqliteBlockStore` adapter; `account_block_stats` (block count, total bytes, distinct-rev commit count for the usage endpoint) |
| `blobs.rs` | blob metadata store; `account_storage_bytes`, `account_blob_metrics`, `account_largest_blob` (blob-storage metrics) |
| `oauth.rs` | OAuth client lookup, auth code storage, token management |
| `password_reset.rs` | `insert_reset_token`, `get_reset_token`, `mark_reset_token_used`, `update_password_hash` |
| `preferences.rs` | `get_preferences` (DID→stored `app.bsky` preferences JSON blob); `put_preferences` (upsert the blob, overwriting any previous value) |
| `repo_keys.rs` | Per-account repo signing keys: pending-account key storage for the mobile DID ceremony, reserved signing keys for standard account migration, promotion into DID-keyed `signing_keys`, and commit-signer lookup |
| `transfers.rs` | Planned device-swap sessions (V027/V029/V030): `insert_transfer` opens a `pending` transfer for a DID, sweeping any expired active row first then letting the partial unique indexes reject a still-active duplicate (→ `DuplicateActive`, the 409 path) or an already-taken active code (→ `CodeCollision`, caller regenerates and retries). Transfer-accept query helpers store promoted-device credentials in `transfer_devices`; completion helpers revoke superseded sessions/transfer-device credentials and append `transfer_audit_events`. `transfer_device_token_exists` lets the `routes/auth.rs` device-token auth path accept those credentials later. Wired by `routes/transfer_initiate.rs`, the root `transfer.rs` accept/complete workflows, `routes/transfer_accept.rs`, `routes/transfer_complete.rs`, and `routes/auth.rs` |
| `firehose_seq.rs` | Persistent firehose event log (V028): `max_seq` (seed the sequencer on boot), `insert_event` (append one sequenced `#commit`/`#account`/`#identity`/`#sync` row with an explicit `seq`), `events_in_range(after, upper, limit)` (the cursor-replay page query). Consumed by `firehose.rs` (persist-before-broadcast) and `routes/sync_subscribe_repos.rs` (replay paging) |
| `admin_devices.rs` | Operator companion app admin-device model (V025): pairing-code mint/consume (single-use), device insert/get/list/revoke (derived active status) + `touch_last_seen` (liveness bump on auth), nonce insert-if-absent + stale-nonce sweep (anti-replay). Pairing/register wired by `routes/admin_devices.rs`; the `require_admin` signed-request guard (`routes/auth.rs`) consumes `get_device`/`insert_nonce_if_absent`/`touch_last_seen`; the list/revoke routes (`routes/admin_devices.rs`) consume `list_devices`/`revoke_device`/`get_device` |

See [`src/db/CLAUDE.md`](src/db/CLAUDE.md) for migration history and invariants.

**Rule:** `db/` submodules never import from `routes/` or `auth/`. They accept `&SqlitePool`
and return data; callers decide what to do with it.

### `routes/`

One file per HTTP endpoint. Each handler is a thin Imperative Shell:
**gather** (extract state/body/headers) → **process** (call `auth/` or `db/`) → **respond**.

| File | Endpoint |
|---|---|
| `oauth_authorize.rs` | `GET/POST /oauth/authorize` |
| `oauth_par.rs` | `POST /oauth/par` |
| `oauth_token.rs` | `POST /oauth/token` |
| `atproto_did.rs` | `GET /.well-known/atproto-did` |
| `oauth_protected_resource.rs` | `GET /.well-known/oauth-protected-resource` |
| `oauth_server_metadata.rs` | `GET /.well-known/oauth-authorization-server` |
| `oauth_jwks.rs` | `GET /oauth/jwks` |
| `oauth_templates.rs` | Pure HTML rendering helpers (Functional Core, no handler) |
| `static_assets.rs` | `GET /static/*path` — embedded brand fonts (woff2/ttf via `include_bytes!`) and future web-UI assets |
| `create_session.rs` | `POST /xrpc/com.atproto.server.createSession` — password auth. Verifies the main account password first (→ full `com.atproto.access`); on mismatch (or a mobile account with no main password) falls back to the account's app passwords (→ `com.atproto.appPass`/`com.atproto.appPassPrivileged`, email omitted from the response, refresh token tagged with the app password name) |
| `create_app_password.rs` | `POST /xrpc/com.atproto.server.createAppPassword` — mint a named app password (optionally `privileged`); returns the generated `xxxx-xxxx-xxxx-xxxx` secret once. Requires full access scope (app-pass tokens rejected); duplicate name → 409 |
| `list_app_passwords.rs` | `GET /xrpc/com.atproto.server.listAppPasswords` — list an account's app passwords (name/createdAt/privileged, never the secret). Requires full access scope |
| `revoke_app_password.rs` | `POST /xrpc/com.atproto.server.revokeAppPassword` — delete a named app password and its refresh tokens/sessions atomically (idempotent 200). Requires full access scope |
| `get_session.rs` | `GET /xrpc/com.atproto.server.getSession` |
| `get_service_auth.rs` | `GET /xrpc/com.atproto.server.getServiceAuth` — mint a short-lived ES256 inter-service auth JWT (signed by the account's repo key) for a requested `aud` service; optional `lxm` (method binding) and `exp` (absolute, ≤1h with `lxm`, ≤60s without). Shares the mint helper with `service_proxy.rs` |
| `update_subject_status.rs` | `POST /xrpc/com.atproto.admin.updateSubjectStatus` — apply/clear an account-level takedown (`subject` as `com.atproto.admin.defs#repoRef`, `takedown` as `#statusAttr`; record/blob subjects and the `deactivated` field are unsupported). Admin-authed via `require_admin_json`. Emits an `#account` firehose event on a real transition, reflecting the account's full derived lifecycle |
| `get_subject_status.rs` | `GET /xrpc/com.atproto.admin.getSubjectStatus` — report an account's current takedown status. Admin-authed via `require_admin` |
| `admin_subject_defs.rs` | Shared `com.atproto.admin.defs` response view types (`RepoRefView`, `StatusAttrView`) for `update_subject_status.rs`/`get_subject_status.rs` (Functional Core, no handler) — same non-handler-support-file pattern as `oauth_templates.rs` |
| `refresh_session.rs` | `POST /xrpc/com.atproto.server.refreshSession` |
| `request_password_reset.rs` | `POST /xrpc/com.atproto.server.requestPasswordReset` |
| `reset_password.rs` | `POST /xrpc/com.atproto.server.resetPassword` |
| `reserve_signing_key.rs` | `POST /xrpc/com.atproto.server.reserveSigningKey` — public standard account-migration repo signing-key reservation; returns `{ signingKey }` |
| `create_did.rs` | `POST /v1/dids` |
| `get_did.rs` | `GET /v1/dids/:did` |
| `create_account.rs` | `POST /v1/accounts` |
| `create_handle.rs` | `POST /v1/handles` |
| `delete_handle.rs` | `DELETE /v1/handles/:handle` |
| `create_mobile_account.rs` | `POST /v1/accounts/mobile` |
| `account_usage.rs` | `GET /v1/accounts/:id/usage` — operator usage metrics (records/commits/blobs counts, total storage bytes, last-active); admin token; reports on deactivated accounts too |
| `account_storage.rs` | `GET /v1/accounts/:id/storage` — operator blob-storage metrics (blob count, total bytes, configured quota + used %, largest blob); admin token |
| `admin_devices.rs` | `POST /v1/admin/pairing-codes` (master token; mint single-use pairing code), `POST /v1/admin/devices` (pairing code + self-signature; register a companion-app device public key), `GET /v1/admin/devices` (list devices with derived status), and `POST /v1/admin/devices/:id/revoke` (revoke a device; idempotent, 404 on unknown). List/revoke are admin-authed via `require_admin` (master token OR active device signature). Registration verifies the self-signature before consuming the code; rejection paths return a generic 401 |
| `create_signing_key.rs` | `POST /v1/pds/keys` (deprecated alias: `POST /v1/relay/keys`) |
| `register_device.rs` | `POST /v1/devices` |
| `transfer_initiate.rs` | `POST /v1/transfer/initiate` — open a planned device-swap session (source-device session token → DID); mints a 6-char code + `pending` transfer, one active per account (409 otherwise) |
| `transfer_accept.rs` | `POST /v1/transfer/accept` — accept a planned device-swap code from the new device; no bearer auth (code is the credential); registers promoted-device credentials and advances the transfer to `accepted` atomically |
| `transfer_complete.rs` | `POST /v1/transfer/complete` — finalize an accepted planned device swap; bearer auth accepts either the source account session or the accepted target device token; marks the transfer `complete`, revokes old sessions/prior transfer-device credentials, keeps the accepted target credential, and records a transfer audit event |
| `get_device_pds.rs` | `GET /v1/devices/:id/pds` |
| `describe_server.rs` | `GET /xrpc/com.atproto.server.describeServer` |
| `describe_repo.rs` | `GET /xrpc/com.atproto.repo.describeRepo` |
| `service_proxy.rs` | `GET/POST /xrpc/app.bsky.*`, `GET/POST /xrpc/chat.bsky.*`, and `GET/POST /xrpc/com.atproto.moderation.*` — catch-all proxy forwarding unhandled `app.bsky.*` NSIDs to the configured AppView and `chat.bsky.*` NSIDs (direct messages) to the configured chat service. The `chat.bsky.*` branch (in `app.rs::xrpc_handler`) requires a privileged credential — full access or a *privileged* app password; a plain `com.atproto.appPass` session is refused with 403. `com.atproto.moderation.*` (e.g. `createReport`) has no single configured upstream — the client names the target labeler via the `atproto-proxy` header (`did#serviceId`), which `identity_resolution::resolve_atproto_proxy_target` resolves (DID document → matching `service` entry's `serviceEndpoint`) before proxying; a missing header is 400, an unresolvable target is 503 |
| `get_preferences.rs` | `GET /xrpc/app.bsky.actor.getPreferences` — local preference read (stored on the PDS, not proxied; registered ahead of the catch-all) |
| `put_preferences.rs` | `POST /xrpc/app.bsky.actor.putPreferences` — local preference write (overwrites the stored blob entirely; registered ahead of the catch-all) |
| `resolve_handle.rs` | `GET /xrpc/com.atproto.identity.resolveHandle` |
| `sync_subscribe_repos.rs` | `GET /xrpc/com.atproto.sync.subscribeRepos` (WebSocket firehose) |
| `claim_codes.rs` | Claim code management |
| `get_pds_signing_key.rs` | `GET /v1/pds/keys` (deprecated alias: `GET /v1/relay/keys`) |
| `health.rs` | `GET /xrpc/_health` |
| `delete_session.rs` | `POST /xrpc/com.atproto.server.deleteSession` (session revocation) |
| `deactivate_account.rs` | `POST /xrpc/com.atproto.server.deactivateAccount` (flip account to deactivated, store optional `deleteAfter`, emit `#account` firehose event on transition) |
| `activate_account.rs` | `POST /xrpc/com.atproto.server.activateAccount` (clear deactivation, emit `#account` firehose event on transition) |
| `oauth_client_metadata.rs` | `GET /oauth/client-metadata.json` (OAuth client metadata per ATProto spec) |
| `provisioning_session.rs` | Provisioning session creation (email + password → session token) |
| `code_gen.rs` | Claim code generation (random alphanumeric codes) |
| `uniqueness.rs` | Pre-flight uniqueness checks for email and handle (Functional Core) |
| `auth.rs` | Route-level auth middleware (`require_admin` [master token OR device signature], `require_admin_token`, `require_pending_session`, `require_session`, `require_device_token`) |
| `token.rs` | Bearer token generation helpers |
| `test_utils.rs` | Test helpers (excluded from production builds) |

## Hard Rules

**Routes must not import from other routes.**
If two routes share logic, that logic belongs in `auth/` (pure) or `db/` (queries). A route
importing from another route creates hidden coupling and makes it impossible to reason about
a handler in isolation.

**Every `.rs` file with runtime behavior must have a pattern comment.**
Add `// pattern: Functional Core`, `// pattern: Imperative Shell`, or
`// pattern: Mixed (unavoidable)` at the top of any file containing functions or
orchestration logic. Files with only types, constants, or re-exports are exempt.

**`db/` submodules own queries, not transactions.**
Business-logic transactions (multi-table atomic operations) live in the route handler or
a dedicated helper called by the handler — not inside `db/` functions. `db/` functions
accept `&SqlitePool` or `&mut SqliteTransaction`; they never open transactions themselves
unless the operation is inherently single-table.

## Adding a New Route

1. Create `src/routes/<name>.rs` with `// pattern: Imperative Shell` at the top.
2. If the handler needs shared auth logic → add to `auth/` (pure) or use an existing extractor.
3. If the handler needs a new DB query → add to the appropriate `db/` submodule.
4. Register in `src/app.rs` router.
5. Add a `.bru` file in `bruno/` (see root CLAUDE.md).

## Adding a New DB Query

1. Identify the owning entity (`accounts`, `oauth`, etc.).
2. Add the function to the matching `db/<entity>.rs` file.
3. If no matching file exists, create one with `// pattern: Imperative Shell`.
4. Export the function and any new data struct via `db/mod.rs` (`pub mod <entity>;`).
