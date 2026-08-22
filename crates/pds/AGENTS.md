# PDS Crate (Custos)

Last verified: 2026-08-02

## Purpose

The PDS is the axum-based web server. It is the sole Imperative Shell in the workspace —
the only crate that touches SQLite, handles HTTP, or manages process-level state. All other
crates (`crypto`, `repo-engine`, `common`) are pure Functional Cores that the PDS calls.

This file is a map. Each entry is what the module is plus the fact or two an agent needs
before opening it; mechanism and invariants live in the module's own `//!` doc.

## Module Map

```
src/
  main.rs          — startup: open pool, run migrations, bind server
  telemetry.rs     — OTel tracing-subscriber init (`init_subscriber`) + shutdown-flushing `OtelGuard`; `[telemetry]` config incl. `log_format = "json"` — see module doc
  metrics.rs       — OTel meter + Prometheus registry behind `GET /metrics`; `metrics::names` is the instrument source of truth (each constant documents what it measures and who records it) — see module doc
  app.rs           — router construction (route table + shared middleware layers); re-exports `AppState`/`FailedLoginStore` (and the `#[cfg(test)]` constructors) from `state.rs` so existing `crate::app::AppState` imports stay unchanged
  state.rs         — `AppState` definition + `FailedLoginStore`, plus the `#[cfg(test)]` `test_state`/`test_state_with_plc_url` constructors
  xrpc_dispatch.rs — catch-all XRPC proxy dispatcher (`xrpc_handler` at `/xrpc/{method}`): upstream resolution for the three proxied namespaces + the read-after-write branch — see module doc
  firehose/        — persistent subscribeRepos event pipeline (see section below)
  firehose_gc.rs   — periodic `repo_seq` retention sweep (age/count pruning below the live frontier)
  blob_store.rs    — blob storage backend: durable filesystem I/O, CID computation, MIME detection; blobs at `{data_dir}/blobs/{cid[0:2]}/{cid}` — see module doc
  blob_gc.rs       — periodic blob GC over per-account ownership rows (`blob_owners`, V039); references union the public MST and stored space records (V065); fails closed on a failed reconcile (that account leaks disk until fixed) — see module doc
  blob_mirror/     — off-volume blob replication to an S3-compatible bucket (`[blob_mirror]` / `EZPDS_BLOB_MIRROR_*`); boot restore runs before the listener binds; `s3.rs` is a hand-rolled SigV4 client — see module doc
  blob_scrub.rs    — periodic blob-integrity scrub: re-hash every stored blob + walk both orphan directions; auto-heals from the mirror when configured — see module doc
  crawler.rs       — outbound requestCrawl notifier (rate-limited, retrying, fire-and-forget) — see section below
  relay_status.rs  — inbound `com.atproto.sync.getHostStatus` client (total, never fatal) backing `GET /v1/admin/relay-status` — see section below
  email.rs         — pluggable outbound email (`Arc<dyn EmailSender>`: log default, SMTP, Mailtrap HTTPS) behind the token-delivery flows; `[email]` / `EZPDS_EMAIL_*` — see module doc
  rate_limit.rs    — request rate-limiting middleware + shared limiter state — see section below
  iroh_tunnel.rs   — opt-in (`[iroh] enabled`) NAT-traversing QUIC endpoint devices dial by node id; v0.1 echo ALPN, IPv6 gate for v4-only hosts — see module doc
  notify_relay_client.rs — outbound iroh leg to the notification relay (`ezpds/notify/0`) + the fire-and-forget send worker; lazy cached connection, self-healing enrollment — see module doc
  notifications.rs — sending side: pad + HPKE-seal one payload per registered device and enqueue; inert when `[notifications] relay` is unset — see module doc
  record_write.rs  — shared repo write flow + firehose commit emission + post-commit block GC (one reachability walk per commit) — see module doc
  space_record_write.rs — the single write choke point for permissioned space repos (V065, DB-backed, no MST): validate → CAS rev → LtHash fold → oplog append, all one transaction; blob refs are GC-derived and notification fan-out attaches to the returned rev+hash — see module doc
  space_uri.rs     — space-ref syntax (`at://{authority}/space/{type}/{skey}`) and the wider space AT-URI family; deliberately separate from `repo_engine::AtUri`, whose callers resolve MST paths a space URI must never reach
  space_jti_sweep.rs — periodic `space_jti_replay` retention sweep; each row carries its own token's acceptance horizon (template: sovereign_session_nonce_sweep.rs)
  repo_rev.rs      — shared `read_repo_rev`, homed beside `record_write.rs` so the public sync endpoints share it without a route-to-route import
  time.rs          — shared epoch/RFC-3339 time helpers; the variants differ on return type + pre-epoch handling — pick by call-site contract (module doc)
  account_delete.rs— shared permanent account-deletion transaction (FK-ordered child tables, blob-file reclamation, `#account` deleted frame), used by deleteAccount and the reaper — see module doc
  account_reaper.rs— periodic sweep permanently deleting deactivated accounts past `deleteAfter` (template: firehose_gc.rs)
  agent_claim_sweep.rs— periodic sweep flipping lapsed agent claim attempts to `expired` (template: account_reaper.rs) — see module doc
  labeler_watch.rs — periodic labeler watcher reconciling `account_labels` (V051) to the labels currently in force; first pass runs at boot — see module doc
  label_state.rs   — Functional Core for the watcher: reduce raw label events to the in-force set and diff against persisted rows
  admin_nonce_sweep.rs— periodic stale `admin_nonces` sweep (pure storage reclamation; retention stays above the replay-acceptance window) — see module doc
  sovereign_session_nonce_sweep.rs— hourly `sovereign_session_nonces` sweep; a compile-time assertion keeps retention above the replay window
  sweep_status.rs  — readable last-run state per periodic sweep (`AppState.sweeps`) for `GET /v1/admin/health`; a failed pass records nothing — staleness is the alarm — see module doc
  transfer.rs      — planned device-transfer accept/complete/cancel workflows; `db/transfers.rs` owns the SQL, this module owns the cross-table ordering — see module doc
  identity/        — everything "who is this handle/DID" (see section below)
  session_issuer.rs— shared legacy access+refresh JWT issuance transaction; explicit full-access vs app-password authority — see module doc
  capabilities.rs  — the `CAPABILITIES` table behind `describeServer`'s `custos` extension; an entry's `enabled` predicate must be the same condition its routes enforce, and `just capability-docs-check` gates the operator docs. Also owns `IDENTIFYING_VERSION` — see module doc
  code_gen.rs      — random claim-code generation (pure), shared by claim-code + account-creation routes
  uniqueness.rs    — email/handle pre-flight uniqueness DB checks, shared by the account-creation routes
  platform.rs      — device `Platform` enum, shared by the device-registration routes
  request_host.rs  — `request_host` (Functional Core): resolve the client-addressed host and normalize default ports for the Host-keyed well-known routes — see module doc
  lexicon/         — vendored lexicon documents (`crates/pds/lexicons/`, pinned upstream — see its README) compiled into a registry, plus the reference-parity XRPC validation layers: input bodies (`LexiconInput<T>`), query params (`LexiconParams<T>`), repo-write records (`validate_record`), and served outputs (test-build drift detection). Strict schema parsing and byte-identical reference error messages, so Custos can't drift laxer than the reference. Start at `mod.rs`'s module doc — it maps the entry points and files
  rewrap.rs        — offline `pds rewrap-master-key` KEK rotation (inventory in `db/kek.rs`; keys env-only, server stopped) — see module doc
  recovery_share.rs— the KEK boundary for PDS-held Shamir Share 2: base32↔bytes, authenticated wrap/unwrap, idempotent startup data migration — see module doc
  no_input.rs      — `NoInputBody` extractor: 400s any body on a no-input XRPC procedure with the reference PDS's exact message; extract it last — see module doc
  read_after_write/— buffered AppView response munge path for read-after-write (see section below)
  auth/            — authentication primitives + route guards (HTTP-aware, no DB schema ownership)
  db/              — SQL query functions + migration runner (no business logic)
  routes/          — HTTP handlers, one file per endpoint
```

### `firehose/`

The persistent event pipeline behind `com.atproto.sync.subscribeRepos`: a durable monotonic
sequencer (`repo_seq`, V028) plus a Tokio broadcast fan-out, shared as `AppState.firehose`.
Three files — `mod.rs` (sequencer, bare `emit_*` primitives, and the staged-transaction path
`lock_emit`/`EmitGuard`/`Pending*`), `events.rs` (wire-facing event model + DAG-CBOR stored
encoding), `replay.rs` (cursor replay over the durable log) — with every public type
re-exported at `crate::firehose::*`. The invariants that make it subtle (persist-before-
broadcast under one `emit_lock`, the lock-before-transaction deadlock rule on this crate's
single-connection pool, staging into a caller's transaction, cancellation recovery via
`insert_at_frontier`, and the emission map of which routes emit which frames) are documented
in `firehose/mod.rs`'s module and item docs — read those before touching any emit path.

### `crawler.rs`

Outbound `com.atproto.sync.requestCrawl` notifier (`AppState.crawlers`). Fires on startup and on
**every** firehose broadcast frame — lifecycle frames included, so a relay that silently dropped
its subscription is re-invited even when the only news is a post-migration `#account`/`#sync`.
Fire-and-forget, rate-limited to one notification per crawler per 30s, retried with backoff;
configured via `[crawlers] urls` / `EZPDS_CRAWLERS` (default `["https://bsky.network"]`, empty
disables). Mechanism and invariants: the module doc in `src/crawler.rs`.

### `relay_status.rs`

The inbound half of federation health: a `com.atproto.sync.getHostStatus` client asking the
upstream relay what it knows about this PDS, backing `GET /v1/admin/relay-status` (which compares
the relay's cursor against our exact sequencer head — see that route's row below, and
`admin_request_crawl.rs` for the companion action). Total, never fatal: every failure becomes a
`RelayReport` variant, so the readout always renders the outcome — what the relay said, or that
it could not be asked. Details: the module doc in `src/relay_status.rs`.

### `rate_limit.rs`

Reference-parity request rate limiting. The pure sliding-window algorithm lives in
`auth/rate_limit.rs` (Functional Core); this module is the Imperative Shell owning the
process-level limiters and the Axum middleware. Three families — global per-IP, per-endpoint
per-IP (guess-target endpoint pairs share one limiter instance so alternating endpoints can't
double a guess budget), and per-account write points charged in `record_write::commit_repo_write`
on the **authenticated** DID — all off when `[rate_limit] enabled = false`, all tunable via
`[rate_limit]` / `EZPDS_RATE_LIMIT_*` (a knob of `0` disables that limiter). The family
rosters, exemptions, and `RateLimit-*` header behavior: the module doc.

### `identity/`

Everything answering "who is this handle/DID": the resolution chain, handle/DID syntax
validation, the live signing-authority lookup behind the passwordless surfaces, and did:plc
genesis/rotation-op machinery. Each is consumed from the outside by `routes/`, `auth/`,
`app.rs`/`xrpc_dispatch.rs`, and `main.rs`; a few also share helpers within the module (for
example `authority.rs` reads through `plc.rs` and `resolution.rs`, and `well_known.rs` borrows
`did.rs`'s validator), so check a file's imports before assuming it stands alone.

| File | Contents |
|---|---|
| `mod.rs` | `pub mod` declarations only — no shared code |
| `resolution.rs` | shared handle/DID resolution chain, the cache-first DID-document reads (the `did_documents` cache has no TTL; `resolve_did_document_force_refresh` is the only un-staling path), and the pure DID-document accessors including the Atproto Spaces fallbacks (`space_verification_key`, `space_host_endpoint`) — see module doc |
| `proxy.rs` | the `atproto-proxy` header target guard and the shared SSRF-hardened client (`AppState::hardened_http_client`). Security-critical — the module doc carries the full design (`SsrfResolver` connect-time DNS allowlist, TOCTOU closure, all four consumers); `just ssrf-client-check` guards the well-known-resolver wiring |
| `did.rs` | general `did:` syntax validation (Functional Core): the canonical `is_valid_did`, re-exported by `auth/validation.rs` and called by `lexicon/formats.rs` for the `did` string format — see module doc |
| `handle.rs` | handle validation: structural + domain policy + reserved infrastructure names — see module doc |
| `dns.rs` | `DnsProvider` (handle DNS records; v0.1 ships no provider) + `TxtResolver` (DNS TXT fallback for resolveHandle) — see module doc |
| `well_known.rs` | `WellKnownResolver`: HTTP `.well-known/atproto-did`, resolveHandle's third fallback — see module doc |
| `plc.rs` | shared did:plc rotation/update-op machinery for the `identity.*PlcOperation` interop routes — see module doc |
| `genesis.rs` | shared did:plc genesis-op machinery, used by both `create_did.rs` and `create_account_xrpc.rs` — see module doc |
| `authority.rs` | the shared live signing-authority lookup (`authorized_signing_keys`) behind the three passwordless surfaces (`sovereign_session`, `oauth_consent` approve, and `deleteAccount`'s proof branch); resolves the authorized keys live — a did:plc account's current rotation set, or a did:web account's served document — never the `did_documents` cache — see module doc |

### `read_after_write/`

Buffered munge path for the six munged AppView NSIDs — merges the requester's not-yet-indexed
records into the AppView's response. `mod.rs`'s module doc is the authority: the NSID list,
rev-comparison selection, the five-rung fallback ladder, the 10 MiB buffering cap,
`Atproto-Upstream-Lag` semantics, the `service_proxy::proxy_request` shared extraction, and the
`[appview]` config keys (`EZPDS_APPVIEW_URL`/`_DID`/`_CDN_URL`). Submodules: `munge.rs`
(per-NSID munges), `viewer.rs` (`LocalViewer` hydration), `types.rs` (`LocalRecords`).

### `auth/`

Pure authentication logic and middleware. Submodules:

| File | Pattern | Contents |
|---|---|---|
| `agent_assertion.rs` | Mixed (unavoidable) | shared auth.md agent machinery both `routes/agent_identity.rs` and `routes/agent_claim.rs` need (routes can't import each other): assertion minting, claim-block helpers, `AgentAuthError`, agent audit — see module doc |
| `dpop.rs` | Mixed (unavoidable) | DPoP proof validation, nonce store |
| `extractors.rs` | Imperative Shell | `AuthenticatedUser` extractor + `authenticate_access`, the single authoritative access-auth path (RFC 9449 scheme ↔ `cnf.jkt` binding); `just auth-seam-check` freezes the seam — see module doc |
| `guards.rs` | Imperative Shell | route-level auth guards (admin, session, pending-session, device) + `authenticate_account_owner`'s dual credential; queries `sessions`/`devices`/`admin_devices`, owns no schema — see module doc |
| `issuer_trust.rs` | Mixed (unavoidable) | shared trusted-issuer verification for the two provider-signed auth.md tokens (ID-JAG + SET); also owns `REVOKED_EVENT_TYPE` — see module doc |
| `jwks.rs` | Imperative Shell | `JwksFetcher` + TTL `JwksCache` — the dynamic-trust half of `issuer_trust.rs`'s key resolution, with a per-URL refetch cooldown against bogus-`kid` amplification — see module doc |
| `jwt.rs` | Functional Core | JWT parsing, scope validation, access/refresh token verification, HS256 token issuance |
| `oauth_client_resolution.rs` | Mixed (unavoidable) | the ATProto OAuth client resolver: client_id URL policy before any I/O, metadata fetch, bounded negative cache; also `validate_private_use_redirect` — see module doc |
| `oauth_response_mode.rs` | Functional Core | `ResponseMode` (`query` \| `fragment`): parse the OAuth `response_mode` and pick the redirect separator; shared by four route surfaces — see module doc |
| `oauth_scopes.rs` | Functional Core | the granular ATProto OAuth scope grammar (proposal 0011, plus `space:` from the Spaces proposal 0016): parse, normalize, and canonicalize `resource[:positional][?param=value]` across the six resource types, and enforce it via the `require_*`/`allows_*` checks scoped routes call; `supported_scopes()` backs the discovery metadata. Ported for round-trip parity with `@atproto/oauth-scopes` — see module doc |
| `permission_sets.rs` | Mixed (unavoidable) | resolves `include:<nsid>` scope references to Lexicon-published permission-set records and expands them into the grammar `oauth_scopes.rs` validates; owns the TTL'd `PermissionSetCache` and the shared `resolve_cached` helper `space_consent.rs` reuses. Does live DNS/HTTP, so not a pure core despite living in `auth/` — see module doc |
| `space.rs` | Mixed (unavoidable) | the one authorization seam every `com.atproto.space.*` route enters through: authenticate, confirm the caller owns the repo it named, and match the operation against its `space:` grant. A read naming another account's repo answers `RepoNotFound`, not `Forbidden` — deliberate non-disclosure. Mixed because a grant naming no `collection` falls back to the space type declaration's, resolved over the network — see module doc |
| `space_consent.rs` | Mixed (unavoidable) | the user-legible text `/oauth/authorize` shows for `space:` grants: the space type declaration's `name` (localized), a named authority's bidirectionally-verified handle, the collections a bare grant resolves to, and the both-wildcards warning. Reuses `permission_sets.rs`'s Lexicon resolution path and TTL-cache machinery; degrades to the raw token instead of failing the page — see module doc |
| `password.rs` | Functional Core | `hash_password`, `verify_password` (argon2id) |
| `rate_limit.rs` | Functional Core | sliding-window login-failure limiter + the generic `MultiWindowLimiter` used by the top-level `rate_limit.rs` middleware |
| `service_auth.rs` | Imperative Shell | `require_service_auth(lxm)` — the inbound atproto service-auth guard, one lexicon method per call — plus the shared resolve-and-verify key machinery migration-`createAccount` reuses — see module doc |
| `signed_proof.rs` | Functional Core | shared decoding for the device-key-signed proof envelopes three routes verify (`sovereign_session`, `oauth_consent`, `delete_account`): fixed lengths + canonical base64url — see module doc |
| `signing_key.rs` | Imperative Shell | ES256 signing key load-or-create |
| `bearer.rs` | Functional Core | Authorization-header extraction: `extract_access_token` (Bearer + DPoP, RFC 9449) and Bearer-only `extract_bearer_token` — see module doc |
| `token.rs` | Functional Core | single source of truth for the bearer/device token format (32 random bytes → base64url wire, SHA-256 hex DB): `generate_token`, `sha256_hex`, `hash_bearer_token` — see module doc |
| `validation.rs` | Functional Core | pure format/shape helpers shared across routes (`is_valid_did` re-export, device-public-key bounds, failed-login lock plumbing); each returns a bool or a message the caller maps to its own `ApiError` — see module doc |

**Rule:** `auth/` has no knowledge of specific routes. Route handlers call into `auth/`; `auth/` never imports from `routes/`.

### `db/`

SQL query functions organised by domain entity. Each submodule exposes plain data structs
and async query functions; no business logic lives here.

| File | Contents |
|---|---|
| `mod.rs` | `open_pool`, `run_migrations`, `DbError`, `is_unique_violation` |
| `migrations.rs` | the forward-only schema manifest; a schema change touches only this file plus its `migrations/VNNN__*.sql` — see module doc |
| `accounts.rs` | account lookups, lifecycle transitions, repo-root CAS, and the operator listing; the module doc carries the full inventory (which lookups are lifecycle-gated and the all-NULL rule, `AccountLifecycle` derivation) |
| `app_passwords.rs` | app-password store (V031) — see module doc; revocation's multi-table delete lives in `routes/revoke_app_password.rs` |
| `claim_codes.rs` | invite/claim-code store (V004/V041): preflight, mint, keyset inventory page, revoke — see module doc |
| `handles.rs` | `handles` table (V002) single-table queries; multi-table swaps stay in route handlers — see module doc |
| `dids.rs` | `did_documents` cache queries (V002) plus the Custos did:web hosting queries (V044) — see module doc |
| `blocks.rs` | content-addressed repo-block store + `block_owners` (V035), `SqliteBlockStore` adapter, `account_block_stats` — see module doc |
| `blobs.rs` | blob metadata store: physical `blobs` + per-owner `blob_owners` lifecycle (V039); `account_uploaded_blob_metrics` is the one query bypassing `blob_owners` — see module doc |
| `oauth.rs` | OAuth server-side state: clients, auth codes, signing key, refresh tokens, PAR + expiry sweeps — see module doc |
| `password_reset.rs` | password-reset token store (the hashed 1-hour single-use envelope) — see module doc |
| `plc_operation_tokens.rs` | PLC-operation email-token store (V033), gating `signPlcOperation` — see module doc |
| `account_deletion_tokens.rs` | account-deletion email-token store (V034, same hashed envelope) — see module doc |
| `email_tokens.rs` | email verification token store (V036, purpose-discriminated single-use envelope) — see module doc |
| `preferences.rs` | preferences blob get/put, executor-generic for the one-transaction read-merge-write — see module doc |
| `refresh_tokens.rs` | `refresh_tokens` reads (V002/V006); rotation/revocation transactions stay in route handlers — see module doc |
| `relay_signing_keys.rs` | operator-level PDS signing keys (V003) backing `/v1/pds/keys` — see module doc |
| `kek.rs` | the exhaustive `SecretFamily` inventory of KEK-wrapped columns + generic fetch/update; a new KEK-wrapped column must be added as a variant here — see module doc |
| `recovery_escrow.rs` | PDS-held Shamir Share 2 escrow (V050) plus the release state machine — see module doc |
| `recovery_otps.rs` | recovery-release email OTP store (V053) — see module doc |
| `recovery_audit.rs` | append-only recovery-escrow audit log (V050, the V040 doctrine) — see module doc |
| `jwt_secret.rs` | persistent encrypted HS256 JWT signing secret (V015) — see module doc |
| `iroh_identity.rs` | persistent encrypted Iroh node Ed25519 key (V022) — see module doc |
| `sessions.rs` | `sessions` writes (V009): the standalone provisioning-session insert only; every other session insert stays in its route's transaction — see module doc |
| `repo_keys.rs` | per-account repo signing keys: ceremony storage, migration reservations, commit-signer lookup (V048), rotation staging — see module doc |
| `transfers.rs` | planned device-swap sessions (V027/V029/V030): initiate/accept/complete plus the operator view and cancel — see module doc |
| `firehose_seq.rs` | persistent firehose event log (V028): boot seed, append, cursor-replay page — see module doc |
| `server_stats.rs` | whole-server aggregates for `GET /v1/admin/health`; the unowned-blob readout's meaning lives on the `ServerStats` field docs |
| `admin_audit.rs` | server-wide append-only admin-action audit log (V052); doctrine and function inventory in the module doc |
| `admin_devices.rs` | admin-device model (V025): pairing codes, devices, anti-replay nonces — see module doc |
| `sovereign_session_nonces.rs` | sovereign-session anti-replay store (V043); the sweep-retention rule is in the module doc |
| `spaces.rs` | `spaces` rows (V065): every space this PDS interacts with, keyed by canonical URI; member/notify queries land with their consuming surfaces — see module doc |
| `space_repos.rs` | permissioned repo store queries (V065): repo heads (rev + LtHash state), record blocks, oplog; the write transaction lives in `space_record_write.rs` — see module doc |
| `space_jti.rs` | spaces-token jti replay store (V065): scope-discriminated insert-if-absent + the expiry sweep — see module doc |
| `waitlist.rs` | public waitlist signup store (V057, no FKs — off the purge path) — see module doc |
| `account_labels.rs` | watched-labeler flag store (V051) — see module doc; the filtered listing predicates live beside `list_accounts_admin` in `accounts.rs` |

See [`src/db/AGENTS.md`](src/db/AGENTS.md) for migration history and invariants.

**Rule:** `db/` submodules never import from `routes/` or `auth/`. They accept `&SqlitePool`
and return data; callers decide what to do with it.

### `routes/`

One file per HTTP endpoint. Each handler is a thin Imperative Shell:
**gather** (extract state/body/headers) → **process** (call `auth/` or `db/`) → **respond**.
Rows below name the endpoint and the fact to know before opening the file; the module doc has
the rest. The client-facing wire contract of the OAuth endpoints (`PAR → consent → token →
authenticated call`) is pinned from the client's side by an out-of-crate suite,
`tools/oauth-conformance/`; the interop failures it guards slipped past this crate's own Rust
tests, so check it when changing an OAuth response shape — see its README.

| File | Endpoint |
|---|---|
| `oauth_authorize.rs` | `GET/POST /oauth/authorize` — consent page + code issuance; PAR-only (a GET without a PAR `request_uri`, or carrying a JAR `request` object, is refused), and the GET's wallet path owns the Phase C login-approval push dispatch |
| `oauth_consent.rs` | `GET /oauth/authorize/{consent-request,status}`, `POST /oauth/authorize/{approve,complete}` — the wallet-confirmed (passwordless) consent half; approval is a device-key envelope verified against `identity::authority`, never the cached DID doc |
| `oauth_par.rs` | `POST /oauth/par` — RFC 9126; enforces the atproto reverse-FQDN private-use-redirect rule (`auth/oauth_client_resolution.rs`) and stores `response_mode` |
| `oauth_token/` | `POST /oauth/token` — one route module, per-grant submodules (`authorization_code`, `refresh`, `jwt_bearer`, `claim_polling`); grants incl. the RFC 7523 jwt-bearer exchange and the `urn:workos:agent-auth:grant-type:claim` poll — each submodule's doc carries its grant's rules |
| `oauth_revoke.rs` | `POST /oauth/revoke` — RFC 7009; refresh tokens only, DPoP proof-of-possession, uniform 200-empty non-disclosure |
| `atproto_did.rs` | `GET /.well-known/atproto-did` |
| `did_json.rs` | `GET /.well-known/did.json` — the serving half of Custos-managed did:web hosting; module doc covers the opt-in gate and the config-synthesized server-DID exception |
| `did_web_hosting.rs` | `POST /v1/did-web/hosting` + `POST /v1/did-web/document` — owner-authed did:web hosting opt-in and non-PLC document edit — see module doc |
| `oauth_protected_resource.rs` | `GET /.well-known/oauth-protected-resource` |
| `oauth_server_metadata.rs` | `GET /.well-known/oauth-authorization-server` |
| `oauth_jwks.rs` | `GET /oauth/jwks` |
| `agent_identity.rs` | `POST /agent/identity` — auth.md registration (Step 3), dispatching on `type` (`identity_assertion`/`service_auth`/`anonymous`); every flow operator-opt-in, scopes clamped to current config — see module doc |
| `agent_claim.rs` | `POST /agent/identity/claim` + `/claim/confirm` — the auth.md claim ceremony (Step 4): public agent initiate, owner-authed confirm flips `active → claimed`; polling collection lives at the token endpoint — see module doc |
| `agent_event.rs` | `POST /agent/event/notify` — auth.md `events_endpoint`: a trusted-issuer SET (RFC 8417/8935) revokes the matching registration; idempotent 202 — see module doc |
| `agents.rs` | `GET /v1/agents`, `POST /v1/agents/claim-preview`, `POST /v1/agents/{registration_id}/revoke`, `GET /v1/agents/{registration_id}/audit` — owner-guarded "My agents" management; agent-derived callers refused, a parent operates its sovereign children — see module doc |
| `notifications.rs` | `POST/DELETE /v1/notifications/register[/{deviceUuid}]`, `GET /v1/notifications/sender-keys` — the account push surface, keyed on `(did, device_uuid)`; the relay round trip stays out of the request path — see module doc |
| `admin_notifications.rs` | `POST /v1/admin/notifications/register`, `GET /v1/admin/notifications/sender-keys` — the operator analog; registration is device-signed only (master token → 400) — see module doc |
| `notification_views.rs` | shared handler-free support for both notification surfaces (routes may not import one another): enabled-check, registration validators, `sender-keys` shape |
| `oauth_templates.rs` | pure HTML rendering helpers (Functional Core, no handler) |
| `oauth_errors.rs` | shared `OAuthTokenError` — the RFC 6749 §5.2 responder used by `oauth_token/` and `oauth_revoke.rs` (Functional Core, no handler) |
| `static_assets.rs` | `GET /static/*path` — embedded brand fonts and future web-UI assets |
| `landing.rs` | `GET /` — the instance landing page (embedded `assets/landing.html`): config facts, a `_health` status chip, joiner/developer pointers |
| `create_session.rs` | `POST /xrpc/com.atproto.server.createSession` — password auth with app-password fallback — see module doc |
| `sovereign_session.rs` | `POST /v1/sessions/sovereign` — passwordless full session from a rotation-key-signed proof; envelope and verification rules in the module doc |
| `create_app_password.rs` | `POST /xrpc/com.atproto.server.createAppPassword` — mint a named app password; secret returned once, full access required, duplicate name → 409; off-lexicon `personalDetails` grant (ADR-0033) |
| `list_app_passwords.rs` | `GET /xrpc/com.atproto.server.listAppPasswords` — metadata only, never the secret; full access required |
| `revoke_app_password.rs` | `POST /xrpc/com.atproto.server.revokeAppPassword` — delete an app password and its sessions atomically (idempotent 200); full access required |
| `get_session.rs` | `GET /xrpc/com.atproto.server.getSession` |
| `get_service_auth.rs` | `GET /xrpc/com.atproto.server.getServiceAuth` — mint a short-lived inter-service JWT for a requested `aud`, optional `lxm`/`exp` bounds; shares the mint helper with `service_proxy.rs` |
| `update_subject_status.rs` | `POST /xrpc/com.atproto.admin.updateSubjectStatus` — apply/clear an account takedown; admin-authed; subject-kind limits and firehose semantics in the module doc |
| `get_subject_status.rs` | `GET /xrpc/com.atproto.admin.getSubjectStatus` — report an account's takedown status; admin-authed — see module doc |
| `admin_subject_defs.rs` | shared `com.atproto.admin.defs` response view types for the two subject-status routes (Functional Core, no handler) |
| `refresh_session.rs` | `POST /xrpc/com.atproto.server.refreshSession` |
| `request_password_reset.rs` | `POST /xrpc/com.atproto.server.requestPasswordReset` — mint + email a reset token; always 200 to prevent enumeration |
| `reset_password.rs` | `POST /xrpc/com.atproto.server.resetPassword` |
| `request_email_confirmation.rs` | `POST /xrpc/com.atproto.server.requestEmailConfirmation` — mint + email a single-use 1-hour confirm token; full access required |
| `confirm_email.rs` | `POST /xrpc/com.atproto.server.confirmEmail` — consume the confirm token, set `email_confirmed_at`; full access required |
| `request_email_update.rs` | `POST /xrpc/com.atproto.server.requestEmailUpdate` — returns `{tokenRequired}`; mints the update token when the current email is confirmed |
| `update_email.rs` | `POST /xrpc/com.atproto.server.updateEmail` — change the address (token required iff confirmed), reset `email_confirmed_at`; duplicate → 400 |
| `reserve_signing_key.rs` | `POST /xrpc/com.atproto.server.reserveSigningKey` — public standard-migration signing-key reservation |
| `get_repo_signing_key.rs` | `GET /v1/repo-signing-key` — idempotently issue the pending account's repo signing key for the mobile DID ceremony — see module doc |
| `create_did.rs` | `POST /v1/dids` — device-signed DID ceremony + promotion, dual-mode on share custody (client-share did:plc / no-escrow did:web) — see module doc |
| `get_did.rs` | `GET /v1/dids/:did` |
| `create_account.rs` | `POST /v1/accounts` |
| `create_account_xrpc.rs` | `POST /xrpc/com.atproto.server.createAccount` — standard onboarding + resumable migration, dual-mode on `did` presence — see module doc |
| `create_handle.rs` | `POST /v1/handles` |
| `delete_handle.rs` | `DELETE /v1/handles/:handle` |
| `create_mobile_account.rs` | `POST /v1/accounts/mobile` |
| `account_usage.rs` | `GET /v1/accounts/:id/usage` — operator usage metrics (counts, bytes, last-active); admin-authed, reports deactivated accounts too — see module doc |
| `account_storage.rs` | `GET /v1/accounts/:id/storage` — operator blob-storage metrics incl. the `uploadedBlob*` second witness for lost ownership rows; admin-authed — see module doc |
| `admin_list_accounts.rs` | `GET /v1/admin/accounts` — operator listing/search, flagged accounts first behind a two-part cursor; filters, per-row storage + `didWebHosting` + flags — see module doc |
| `admin_recovery_releases.rs` | `GET /v1/admin/recovery-releases` — operator view of in-flight escrow releases; the share ciphertext is never returned — see module doc |
| `admin_health.rs` | `GET /v1/admin/health` — literal server-health readout (the JSON counterpart of `/metrics`), no ok/warn verdicts; admin-authed — see module doc |
| `admin_relay_status.rs` | `GET /v1/admin/relay-status` — is the relay actually crawling us? Exact-head vs relay-cursor comparison, raw truth only; admin-authed — see module doc |
| `admin_request_crawl.rs` | `POST /v1/admin/request-crawl` — un-throttled "Request crawl" action paired with relay-status; per-relay outcomes reported; admin-authed — see module doc |
| `admin_revoke_credentials.rs` | `POST /v1/admin/accounts/{id}/revoke-credentials` — operator kill-switch: one-transaction credential sweep with per-family counts; admin-authed — see module doc |
| `admin_account_repair.rs` | `POST /v1/admin/accounts/{id}/email` + `.../reset-token` — operator account-repair pair; reset tokens refused for passwordless accounts — see module doc |
| `admin_audit.rs` | `GET /v1/admin/audit` — the server-wide admin audit log, newest first, attributed per credential; admin-authed; filters, writer inventory, and logging rules in the module doc |
| `admin_transfers.rs` | `GET /v1/admin/transfers` + `POST /v1/admin/transfers/{id}/cancel` — in-flight device-transfer visibility and interruption; the 6-char code is never returned (it is a live account-takeover credential) — see module doc |
| `waitlist_signup.rs` | `POST /waitlist` — public CORS'd interest signup, 404 unless `[waitlist] enabled`; handle validated but never resolved — see module doc |
| `admin_waitlist.rs` | `GET /v1/admin/waitlist` — operator waitlist readout, available even when signup is off; admin-authed — see module doc |
| `admin_devices.rs` | `POST /v1/admin/pairing-codes`, `POST/GET /v1/admin/devices`, `POST /v1/admin/devices/:id/revoke` — companion-app device pairing/management; auth model in the module doc |
| `create_signing_key.rs` | `POST /v1/pds/keys` (deprecated alias: `POST /v1/relay/keys`) |
| `recovery_escrow.rs` | `PUT/DELETE /v1/recovery/escrow-share` — owner deposit/replace/opt-out of the escrowed Share 2 — see module doc |
| `recovery_release.rs` | `POST /v1/recovery/{initiate,release,release/cancel}` — the escrow release gate (OTP → cancellable delay → one-time share), uniform-401 no-oracle posture — see module doc |
| `repo_key_rotation.rs` | `POST /v1/repo-keys/rotation` + `/complete` — stage-then-cutover repo signing-key rotation under the repo write lock (ADR-0025) — see module doc |
| `register_device.rs` | `POST /v1/devices` |
| `transfer_initiate.rs` | `POST /v1/transfer/initiate` — open a planned device-swap session (6-char code, one active per account, 409 otherwise) |
| `transfer_accept.rs` | `POST /v1/transfer/accept` — accept a device-swap code from the new device (the code is the credential); advances the transfer to `accepted` atomically |
| `transfer_complete.rs` | `POST /v1/transfer/complete` — finalize an accepted swap (source session or accepted target token); revokes superseded credentials, records the audit event |
| `get_device_pds.rs` | `GET /v1/devices/:id/pds` |
| `describe_server.rs` | `GET /xrpc/com.atproto.server.describeServer` — lexicon fields plus the off-lexicon `custos` capability extension — see module doc |
| `upload_blob.rs` | `POST /xrpc/com.atproto.repo.uploadBlob` — blob store + metadata insert, dual auth (access token or method-scoped service-auth JWT, the video-service path) — see module doc |
| `get_blob.rs` | `GET /xrpc/com.atproto.sync.getBlob` — ownership-scoped, re-hash-verified blob serving with immutable caching — see module doc |
| `sync_get_blocks.rs` | `GET /xrpc/com.atproto.sync.getBlocks` — requested repo blocks as a rootless CAR; a foreign account's CID reads as `BlockNotFound` |
| `sync_get_latest_commit.rs` | `GET /xrpc/com.atproto.sync.getLatestCommit` — current commit CID and rev |
| `sync_get_record.rs` | `GET /xrpc/com.atproto.sync.getRecord` — a record with its MST proof as a CAR (200 inclusion or exclusion proof; only an unknown DID 404s) |
| `get_repo.rs` | `GET /xrpc/com.atproto.sync.getRepo` — repository CAR export; optional `since` makes it incremental |
| `sync_get_repo_status.rs` | `GET /xrpc/com.atproto.sync.getRepoStatus` — hosting status of a single repo |
| `list_blobs.rs` | `GET /xrpc/com.atproto.sync.listBlobs` — paginated blob CIDs for a DID |
| `list_repos.rs` | `GET /xrpc/com.atproto.sync.listRepos` — all hosted repositories, paginated |
| `apply_writes.rs` | `POST /xrpc/com.atproto.repo.applyWrites` — a batch of record writes in one atomic commit |
| `import_repo.rs` | `POST /xrpc/com.atproto.repo.importRepo` — migration CAR ingest, idempotent + CAS-guarded for return migration — see module doc |
| `list_missing_blobs.rs` | `GET /xrpc/com.atproto.repo.listMissingBlobs` — MST-referenced blobs diffed against uploads, paginated |
| `create_record.rs` | `POST /xrpc/com.atproto.repo.createRecord` |
| `get_record.rs` | `GET /xrpc/com.atproto.repo.getRecord` |
| `list_records.rs` | `GET /xrpc/com.atproto.repo.listRecords` |
| `put_record.rs` | `POST /xrpc/com.atproto.repo.putRecord` |
| `delete_record.rs` | `POST /xrpc/com.atproto.repo.deleteRecord` |
| `describe_repo.rs` | `GET /xrpc/com.atproto.repo.describeRepo` |
| `space_create_record.rs` | `POST /xrpc/com.atproto.space.createRecord` — create a record in the caller's own permissioned space repo |
| `space_put_record.rs` | `POST /xrpc/com.atproto.space.putRecord` — upsert; reads the record's presence first so an app granted only `update` is not asked for `create` too |
| `space_delete_record.rs` | `POST /xrpc/com.atproto.space.deleteRecord` — idempotent *here*, by skipping the commit for an absent record; the store keeps the strict precondition `applyWrites` needs |
| `space_apply_writes.rs` | `POST /xrpc/com.atproto.space.applyWrites` — batch of ≤200 writes in one commit; every op states a precondition, so the batch lands whole or reports `RecordAlreadyExists`/`RecordNotFound` |
| `space_list_spaces.rs` | `GET /xrpc/com.atproto.space.listSpaces` — spaces the caller has *written to* (never a membership list); the query's filters are what its `space:` grant is matched against, since it names no one space |
| `space_get_record.rs` | `GET /xrpc/com.atproto.space.getRecord` |
| `space_list_records.rs` | `GET /xrpc/com.atproto.space.listRecords` — `(collection, rkey)` keyset paging, values inlined unless `excludeValues` |
| `space_get_latest_commit.rs` | `GET /xrpc/com.atproto.space.getLatestCommit` — mints a fresh deniable commit per serving (new `ikm`/`sig`/`mac` each time); never stored — see module doc |
| `space_views.rs` | shared handler-free support for the space routes (routes may not import one another): space-ref parsing, the `validate`-flag record check, stored-block decoding, the write-result shape |
| `service_proxy.rs` | `GET/POST /xrpc/{app.bsky,chat.bsky,com.atproto.moderation}.*` — dual-path proxy (namespace defaults / SSRF-guarded header targets); dispatch, munge routing, and the header-forwarding seam are in the module doc |
| `get_preferences.rs` | `GET /xrpc/app.bsky.actor.getPreferences` — local read, registered ahead of the catch-all; app-password callers never see full-access-only types unless minted with the personal-details grant (ADR-0033) |
| `put_preferences.rs` | `POST /xrpc/app.bsky.actor.putPreferences` — local scope-limited write; an ungranted app-password write preserves full-access-only entries |
| `preference_scope.rs` | shared (non-handler): which preference `$type`s are full-access-only, matching the reference PDS; the personal-details grant is the one divergence (ADR-0033) |
| `resolve_handle.rs` | `GET /xrpc/com.atproto.identity.resolveHandle` |
| `resolve_identity.rs` | `GET resolveDid` / `GET resolveIdentity` / `POST refreshIdentity` — shared local→network resolution; the refresh `#identity` change-gate is in the module doc |
| `get_recommended_did_credentials.rs` | `GET /xrpc/com.atproto.identity.getRecommendedDidCredentials` — the PLC-op fields this PDS recommends (ADR-0002) — see module doc |
| `request_plc_operation_signature.rs` | `POST …identity.requestPlcOperationSignature` — mint the `signPlcOperation` email token (interop path); the shared `ensure_did_plc` guard is documented here |
| `sign_plc_operation.rs` | `POST …identity.signPlcOperation` — two-factor PDS-signed repoint op, returned unsubmitted (interop, ADR-0002) — see module doc |
| `submit_plc_operation.rs` | `POST …identity.submitPlcOperation` — verify (current rotation key + `prev` chain) then submit to plc.directory and refresh the cached doc — see module doc |
| `sync_subscribe_repos.rs` | `GET /xrpc/com.atproto.sync.subscribeRepos` — WebSocket firehose (framing, replay, and the interop commit-proof gate in the module doc) |
| `claim_codes.rs` | `POST/GET /v1/accounts/claim-codes` + `POST …/revoke` — claim-code mint, inventory, and revoke; admin-authed; status derivation in the module doc |
| `standard_signup.rs` | the standard-signup interop NSIDs (`createInviteCode(s)`, `getAccountInviteCodes`, `temp.checkHandleAvailability`, `temp.checkSignupQueue`) mapped onto claim-code primitives; each NSID's quirks in the module doc |
| `get_pds_signing_key.rs` | `GET /v1/pds/keys` (deprecated alias: `GET /v1/relay/keys`) |
| `health.rs` | `GET /xrpc/_health` — `version` is the self-identifying `custos vX.Y.Z` diagnostic tooling fingerprints on — see module doc |
| `get_metrics.rs` | `GET /metrics` — Prometheus exposition, outside the CORS/tracing/rate-limit stack; gated by `metrics_enabled`/`metrics_require_admin` — see module doc |
| `delete_session.rs` | `POST /xrpc/com.atproto.server.deleteSession` (session revocation) |
| `deactivate_account.rs` | `POST /xrpc/com.atproto.server.deactivateAccount` — flip to deactivated, store optional `deleteAfter`, `#account` frame on transition |
| `activate_account.rs` | `POST /xrpc/com.atproto.server.activateAccount` — clear deactivation, `#account` (+ chained `#sync`) on transition |
| `request_account_delete.rs` | `POST /xrpc/com.atproto.server.requestAccountDelete` — mint + email the single-use 1-hour deletion token; full access required |
| `delete_account.rs` | `POST /xrpc/com.atproto.server.deleteAccount` — body-credential deletion (password OR the `custos.proof` envelope) + email token; factor rules and no-oracle posture in the module doc |
| `check_account_status.rs` | `GET /xrpc/com.atproto.server.checkAccountStatus` — activation/repo/blob completeness report for migration tooling |
| `oauth_client_metadata.rs` | `GET /oauth/client-metadata.json` — the wallet's OAuth client metadata; fixed canonical client_id except under a loopback `public_url` — see module doc |
| `provisioning_session.rs` | provisioning session creation (email + password → session token) |
| `test_utils.rs` | test helpers (excluded from production builds) |

## Metrics

`GET /metrics` serves the federation-health instrument set. `metrics::names` in
`src/metrics.rs` is the single source of truth: each constant documents what it measures and
who records it, a unit test pins the rendered Prometheus names (counters gain their `_total`
suffix at export), and label values never come from request data. `GET /v1/admin/health`
mirrors the sweeps' last-run state as JSON via `sweep_status.rs`, so operators keep the
signal with `[telemetry] metrics_enabled` off.

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

**Authentication must never be cookie-based; permissive CORS on the public surface depends on it.**
`app.rs` applies `CorsLayer::permissive()` to the public surface (landing, `.well-known`, OAuth,
agent registration, all XRPC, static assets) but deliberately **not** to the admin/provisioning
`/v1/*` surface (same-origin only). Permissive CORS is safe only because every auth path is
Bearer/DPoP/signed-request — never an ambient cookie — so a hostile origin cannot ride a logged-in
user's credentials. If any future auth mechanism becomes cookie-based, the permissive CORS layer
must be tightened (explicit origin allowlist + credentials handling) in the same change.

## Adding a New Route

1. Create `src/routes/<name>.rs` with `// pattern: Imperative Shell` at the top.
2. If the handler needs shared auth logic → add to `auth/` (pure) or use an existing extractor.
3. If the handler needs a new DB query → add to the appropriate `db/` submodule.
4. If it's an XRPC procedure: a JSON input body is parsed with `LexiconInput<T>` (never bare
   `axum::Json<T>`) after vendoring its lexicon document (`crates/pds/lexicons/README.md`); a
   no-input procedure takes `NoInputBody` instead. Both must be the handler's final extractor.
5. Register in `src/app.rs` router.
6. Add a `.bru` file in `bruno/` (see root AGENTS.md).

## Adding a New DB Query

1. Identify the owning entity (`accounts`, `oauth`, etc.).
2. Add the function to the matching `db/<entity>.rs` file.
3. If no matching file exists, create one with `// pattern: Imperative Shell`.
4. Export the function and any new data struct via `db/mod.rs` (`pub mod <entity>;`).
