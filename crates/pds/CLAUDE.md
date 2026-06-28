# PDS Crate (Custos)

Last verified: 2026-06-26

## Purpose

The PDS is the axum-based web server. It is the sole Imperative Shell in the workspace —
the only crate that touches SQLite, handles HTTP, or manages process-level state. All other
crates (`crypto`, `repo-engine`, `common`) are pure Functional Cores that the PDS calls.

## Module Map

```
src/
  main.rs          — startup: open pool, run migrations, bind server
  app.rs           — AppState definition and construction
  firehose.rs      — in-memory subscribeRepos event pipeline (sequencer + broadcast fan-out)
  crawler.rs       — outbound requestCrawl notifier (rate-limited, retrying, fire-and-forget)
  iroh_tunnel.rs   — Iroh QUIC endpoint: NAT-traversing device↔pds tunnel (opt-in)
  record_write.rs  — shared repo write flow + firehose commit emission
  auth/            — authentication primitives (no HTTP, no DB schema ownership)
  db/              — SQL query functions + migration runner (no business logic)
  routes/          — HTTP handlers, one file per endpoint
```

### `firehose.rs`

The in-memory event pipeline behind `com.atproto.sync.subscribeRepos`. Holds a monotonic
sequencer and a Tokio `broadcast` channel; `AppState.firehose: Arc<Firehose>` is shared by
every handler. Each repo commit calls `record_write::emit_firehose_commit`, which builds the
commit's block diff (`repo_engine::export_commit_blocks_car`, run *before* post-commit GC) and
publishes a sequenced `CommitEvent` carrying the DID, rev, `since`, per-record `RepoOp`s
(action + collection/rkey + cid + value), and the CARv1 diff blocks. Backpressure is by design:
the bounded channel never blocks producers — a slow subscriber observes `Lagged` and is expected
to disconnect. All three write paths (`create_record`/`put_record` via `record_write`,
`delete_record`, `apply_writes`) emit exactly one event per commit. (Those same write paths
reject a deactivated account with 403 before committing.) Account-status changes emit a
separate `#account` frame instead of a `#commit`: `deactivate_account`/`activate_account` call
`Firehose::emit_account` (active=false/`deactivated` or active=true) **only on a real status
transition** — a redundant no-op activate/deactivate returns 200 and emits nothing. The
`#account` frame shares the same sequencer and replay backlog so account frames are ordered relative to commits. Alongside the broadcast
channel the firehose keeps a bounded replay backlog so a late subscriber that passes a `cursor`
can be backfilled; `subscribe_from(cursor)` snapshots that backlog and attaches the live
receiver under one lock, so the replay→live boundary is exact (no gap, no duplication). The
subscriber-facing WebSocket frame encoding lives in the `sync_subscribe_repos` handler.

### `crawler.rs`

Outbound `com.atproto.sync.requestCrawl` notifier. `AppState.crawlers: Arc<CrawlerNotifier>`
is shared by every handler; `record_write::emit_firehose_commit` calls `crawlers.notify()`
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
| `accounts.rs` | `AccountRow` + `resolve_identifier` (handle/DID→account); `SessionAccountRow` + `get_session_account` (DID→account+handle+DID doc); `resolve_by_email` (email→account); `account_is_active`, `deactivate_account`/`activate_account` (flip `deactivated_at`, report the transition); `get_repo_write_state` + `advance_repo_root_if_active` (repo-write preconditions and the commit CAS); `get_account_overview` + `account_last_active` (operator usage/storage lookups — unfiltered by deactivation) |
| `blocks.rs` | content-addressed repo-block store + `SqliteBlockStore` adapter; `account_block_stats` (block count, total bytes, distinct-rev commit count for the usage endpoint) |
| `blobs.rs` | blob metadata store; `account_storage_bytes`, `account_blob_metrics`, `account_largest_blob` (blob-storage metrics) |
| `oauth.rs` | OAuth client lookup, auth code storage, token management |
| `password_reset.rs` | `insert_reset_token`, `get_reset_token`, `mark_reset_token_used`, `update_password_hash` |
| `preferences.rs` | `get_preferences` (DID→stored `app.bsky` preferences JSON blob); `put_preferences` (upsert the blob, overwriting any previous value) |
| `admin_devices.rs` | Operator companion app admin-device model (V025): pairing-code mint/consume (single-use), device insert/get/list/revoke (derived active status) + `touch_last_seen` (liveness bump on auth), nonce insert-if-absent + stale-nonce sweep (anti-replay). Pairing/register wired by `routes/admin_devices.rs` (Phase 3); the `require_admin` signed-request guard (`routes/auth.rs`, Phase 4) consumes `get_device`/`insert_nonce_if_absent`/`touch_last_seen`; the Phase 5 list/revoke routes (`routes/admin_devices.rs`) consume `list_devices`/`revoke_device`/`get_device` |

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
| `oauth_server_metadata.rs` | `GET /.well-known/oauth-authorization-server` |
| `oauth_jwks.rs` | `GET /oauth/jwks` |
| `oauth_templates.rs` | Pure HTML rendering helpers (Functional Core, no handler) |
| `static_assets.rs` | `GET /static/*path` — embedded brand fonts (woff2/ttf via `include_bytes!`) and future web-UI assets |
| `create_session.rs` | `POST /xrpc/com.atproto.server.createSession` |
| `get_session.rs` | `GET /xrpc/com.atproto.server.getSession` |
| `refresh_session.rs` | `POST /xrpc/com.atproto.server.refreshSession` |
| `request_password_reset.rs` | `POST /xrpc/com.atproto.server.requestPasswordReset` |
| `reset_password.rs` | `POST /xrpc/com.atproto.server.resetPassword` |
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
| `get_device_pds.rs` | `GET /v1/devices/:id/pds` |
| `describe_server.rs` | `GET /xrpc/com.atproto.server.describeServer` |
| `describe_repo.rs` | `GET /xrpc/com.atproto.repo.describeRepo` |
| `service_proxy.rs` | `GET/POST /xrpc/app.bsky.*` and `GET/POST /xrpc/chat.bsky.*` — catch-all proxy forwarding unhandled `app.bsky.*` NSIDs to the configured AppView and `chat.bsky.*` NSIDs (direct messages) to the configured chat service |
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
