# Relay Crate

Last verified: 2026-06-21

## Purpose

The relay is the axum-based web server. It is the sole Imperative Shell in the workspace —
the only crate that touches SQLite, handles HTTP, or manages process-level state. All other
crates (`crypto`, `repo-engine`, `common`) are pure Functional Cores that the relay calls.

## Module Map

```
src/
  main.rs          — startup: open pool, run migrations, bind server
  app.rs           — AppState definition and construction
  firehose.rs      — in-memory subscribeRepos event pipeline (sequencer + broadcast fan-out)
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
`delete_record`, `apply_writes`) emit exactly one event per commit. The subscriber-facing
WebSocket frame encoding lives in the (separate) `subscribeRepos` handler.

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
| `accounts.rs` | `AccountRow` + `resolve_identifier` (handle/DID→account); `SessionAccountRow` + `get_session_account` (DID→account+handle+DID doc); `resolve_by_email` (email→account) |
| `oauth.rs` | OAuth client lookup, auth code storage, token management |
| `password_reset.rs` | `insert_reset_token`, `get_reset_token`, `mark_reset_token_used`, `update_password_hash` |

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
| `create_signing_key.rs` | `POST /v1/signing-keys` |
| `register_device.rs` | `POST /v1/devices` |
| `get_device_relay.rs` | `GET /v1/devices/:id/relay` |
| `describe_server.rs` | `GET /xrpc/com.atproto.server.describeServer` |
| `describe_repo.rs` | `GET /xrpc/com.atproto.repo.describeRepo` |
| `resolve_handle.rs` | `GET /xrpc/com.atproto.identity.resolveHandle` |
| `claim_codes.rs` | Claim code management |
| `get_relay_signing_key.rs` | `GET /v1/signing-keys` |
| `health.rs` | `GET /xrpc/_health` |
| `delete_session.rs` | `POST /xrpc/com.atproto.server.deleteSession` (session revocation) |
| `oauth_client_metadata.rs` | `GET /oauth/client-metadata.json` (OAuth client metadata per ATProto spec) |
| `provisioning_session.rs` | Provisioning session creation (email + password → session token) |
| `code_gen.rs` | Claim code generation (random alphanumeric codes) |
| `uniqueness.rs` | Pre-flight uniqueness checks for email and handle (Functional Core) |
| `auth.rs` | Route-level auth middleware (`require_admin_token`, `require_pending_session`, `require_session`, `require_device_token`) |
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
