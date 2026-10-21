# custos-core

Last verified: 2026-10-21

The runtime every Custos feature crate shares: `CoreState`, the access-token and DPoP
verification seam, identity resolution, the lexicon registry, rate limiting, metrics, the sweep
scheduler, and the shared middleware stack. `pds` and the feature crates depend on it; it depends
on `custos-db`, `common`, `crypto`, and `repo-engine`, never on a feature crate or `pds`.

## Crate graph

```
common · crypto · repo-engine
            ▼
        custos-db        pool, migration log + runner, cross-feature queries
            ▼
        custos-core      this crate
            ▼
  feature crates         custos-oauth, custos-spaces (more to come)
            ▼
          pds            the binary: composes every feature, owns what is not yet extracted
```

A feature crate depends on `custos-core` and `custos-db`, never on `pds` or a sibling feature;
this crate never depends on a feature. Code two features need moves down here (or to
`custos-db` for a table). The feature-crate contract `pds` consumes is in
[`custos-spaces`' map](../custos-spaces/AGENTS.md#what-pds-consumes). The rationale behind the
split is archived:
[docs/archive/design-plans/2026-10-21-feature-crates.md](../../docs/archive/design-plans/2026-10-21-feature-crates.md).

## Module Map

```
src/
  lib.rs           — module list; re-exports `CoreState`, `FailedLoginStore`, `apply_shared_layers`
  state.rs         — `CoreState`: every field a core module reads or more than one feature reads. A feature's own fields live in its state, which embeds this one (`pds`'s `AppState`) and implements `FromRef<_> for CoreState`
  layers.rs        — `apply_shared_layers(router, &CoreState)`: Trace → HTTP metrics → rate limiting, generic over the router's state; each route group applies it before its own CORS layer
  auth/            — the verification core plus the auth.md agent machinery the token endpoint and the agents surface share (table below); the OAuth server's response mode is `custos-oauth`'s; the Spaces seam is `custos-spaces`'
  test_support.rs  — `test-support` feature only: the test state constructor and shared fixtures (see "Tests from other crates")
  crawler.rs       — outbound `requestCrawl` notifier (`CoreState.crawlers`) — see section below
  capability.rs    — the `Capability` type (`Clone, Copy`): wire name, operator controls, summary, `enabled` predicate. `pds` owns the `CAPABILITIES` table and its order; a feature crate exports its entry as `CAPABILITY`
  blob_store.rs    — blob storage backend: durable filesystem I/O, CID computation, MIME detection; blobs at `{data_dir}/blobs/{cid[0:2]}/{cid}` — see module doc
  firehose/        — the sequencer every writer emits through (`CoreState.firehose`); the `subscribeRepos` serving side stays with its route — see section below
  identity/        — everything "who is this handle/DID" (see section below)
  lexicon/         — vendored lexicon documents (`crates/custos-core/lexicons/`, pinned upstream — see its README) compiled into a registry, plus the reference-parity XRPC validation layers: input bodies (`LexiconInput<T>`), query params (`LexiconParams<T>`), repo-write records (`validate_record`), and served outputs (test-build drift detection). Strict schema parsing and byte-identical reference error messages, so Custos can't drift laxer than the reference. Start at `mod.rs`'s module doc — it maps the entry points and files
  metrics.rs       — OTel meter + Prometheus registry behind `GET /metrics`; `metrics::names` is the instrument source of truth (each constant documents what it measures and who records it) — see module doc
  notify.rs        — the account-push seam: `NotificationPayload`, the `AccountNotifier` trait `pds`'s `RelayNotifier` implements, and `CoreState::notify_account` (`0` when `[notifications] relay` is unset). Features push through it without seeing the relay client
  no_input.rs      — `NoInputBody` extractor: 400s any body on a no-input XRPC procedure with the reference PDS's exact message; extract it last — see module doc
  rate_limit.rs    — request rate-limiting middleware + shared limiter state — see section below
  scope_display.rs — the user-legible text `/oauth/authorize` shows for `space:` grants: the space type declaration's `name` (localized), a named authority's bidirectionally-verified handle, the collections a bare grant resolves to, and the both-wildcards warning. Owns `SpaceTypeCache` (`CoreState.space_type_cache`), which the Spaces auth seam also reads for a bare grant's collection fallback. Degrades to the raw token instead of failing the page — see module doc
  request_host.rs  — `request_host` (Functional Core): resolve the client-addressed host and normalize default ports for the Host-keyed well-known routes — see module doc
  space_uri.rs     — space-ref syntax (`at://{authority}/space/{type}/{skey}`) and the wider space AT-URI family; deliberately separate from `repo_engine::AtUri`, whose callers resolve MST paths a space URI must never reach
  sweep.rs         — the `Sweep` trait (name, cadence, one `run` pass → `Pass`) and the one `Scheduler` (`spawn`/`shutdown`/`run_once`) that owns the interval loop, the skipped boot tick, per-pass jitter, graceful shutdown, and publishing each completed pass to `CoreState.sweeps`; a pass returning `Err` records nothing. Each periodic sweep is a `Sweep<St>` impl in the crate that owns it, generic over the state it reads
  sweep_status.rs  — readable last-run state per periodic sweep (`CoreState.sweeps`) for `GET /v1/admin/health`; a failed pass records nothing — staleness is the alarm — see module doc
  time.rs          — shared epoch/RFC-3339 time helpers; the variants differ on return type + pre-epoch handling — pick by call-site contract (module doc)
```

## Contracts

- **State.** Core helpers take `&CoreState`. The `AuthenticatedUser` extractor works for any
  state `S` with `CoreState: FromRef<S>`, so a feature's handler can extract its own state and
  still authenticate; `Sweep<St>` / `Scheduler<St>` publish to `CoreState.sweeps` the same way.
  The middleware runs on a `CoreState` clone, so `apply_shared_layers` takes a router over any
  state.
- **The access-token seam is held by visibility.** `auth::jwt::verify_access_token` and
  `auth::dpop::validate_dpop` are `pub(super)`: nothing outside `auth` can verify an access
  token except through `auth::extractors::authenticate_access`. Never widen them.
- **The SSRF seam is held by type.** A caller-influenced URL is an `identity::proxy::CallerUrl`
  (private field), and `HardenedClient`'s request methods take only that;
  `HardenedClient::into_inner` is the one escape hatch.
- **`SweepSnapshot` keeps every sweep's typed field**, including the two space sweeps: the
  `GET /v1/admin/health` JSON shape is what the Brass Console reads.

### `firehose/`

The persistent event pipeline behind `com.atproto.sync.subscribeRepos`: a durable monotonic
sequencer (`repo_seq`, V028) plus a Tokio broadcast fan-out, shared as `CoreState.firehose`.
Three files — `mod.rs` (sequencer, bare `emit_*` primitives, and the staged-transaction path
`lock_emit`/`EmitGuard`/`Pending*`), `events.rs` (wire-facing event model + DAG-CBOR stored
encoding), `replay.rs` (cursor replay over the durable log) — with every public type
re-exported at `custos_core::firehose::*`. The invariants that make it subtle (persist-before-
broadcast under one `emit_lock`, the lock-before-transaction deadlock rule on the
single-connection pool, staging into a caller's transaction, cancellation recovery via
`insert_at_frontier`, and the emission map of which routes emit which frames) are documented
in `firehose/mod.rs`'s module and item docs — read those before touching any emit path.

### `crawler.rs`

Outbound `com.atproto.sync.requestCrawl` notifier (`CoreState.crawlers`). Fires on startup and on
**every** firehose broadcast frame — lifecycle frames included, so a relay that silently dropped
its subscription is re-invited even when the only news is a post-migration `#account`/`#sync`.
Fire-and-forget, rate-limited to one notification per crawler per 30s, retried with backoff;
configured via `[crawlers] urls` / `EZPDS_CRAWLERS` (default `["https://bsky.network"]`, empty
disables). Mechanism and invariants: the module doc in `crawler.rs`.

### `identity/`

Everything answering "who is this handle/DID": the resolution chain, handle/DID syntax
validation, the live signing-authority lookup behind the passwordless surfaces, and did:plc
genesis/rotation-op machinery. Each is consumed from the outside by `auth/` here and by `pds`'s `routes/`,
`app.rs`/`xrpc_dispatch.rs`, and `main.rs`; a few also share helpers within the module (for
example `authority.rs` reads through `plc.rs` and `resolution.rs`, and `well_known.rs` borrows
`did.rs`'s validator), so check a file's imports before assuming it stands alone.

| File | Contents |
|---|---|
| `resolution.rs` | shared handle/DID resolution chain, the cache-first DID-document reads (two tiers: the `did_documents` table holds this server's own/migrated accounts with no TTL, force-refreshed by `resolve_did_document_force_refresh`; `CoreState::did_document_cache` holds every remote document on 1h-stale / 24h-hard TTLs with stale-while-revalidate), the cool-down-bounded `refresh_did_document_after_signature_mismatch` seam every token-signature-mismatch retry takes (`custos-spaces`' `auth/space.rs` and this crate's `auth/service_auth.rs` both), and the pure DID-document accessors including the Atproto Spaces fallbacks (`space_verification_key`, `space_host_endpoint`) — see module doc |
| `proxy.rs` | the `atproto-proxy` header target guard and the shared SSRF-hardened client (`CoreState::hardened_http_client`). Security-critical — the module doc carries the full design (`SsrfResolver` connect-time DNS allowlist, TOCTOU closure, all four consumers); a caller-influenced URL is a `CallerUrl`, which only `HardenedClient` accepts |
| `did.rs` | re-exports `common::is_valid_did` (the validator behind `common::Did`) and holds its interop-fixture test; re-exported again by `auth/validation.rs` and called by `lexicon/formats.rs` for the `did` string format |
| `handle.rs` | handle domain policy + reserved infrastructure names over `common::Handle` (the structural validator lives in `common`) — see module doc |
| `dns.rs` | `DnsProvider` (handle DNS records; v0.1 ships no provider) + `TxtResolver` (DNS TXT fallback for resolveHandle) — see module doc |
| `well_known.rs` | `WellKnownResolver`: HTTP `.well-known/atproto-did`, resolveHandle's third fallback — see module doc |
| `plc.rs` | shared did:plc rotation/update-op machinery for the `identity.*PlcOperation` interop routes — see module doc |
| `genesis.rs` | shared did:plc genesis-op machinery, used by both `create_did.rs` and `create_account_xrpc.rs` — see module doc |
| `authority.rs` | the shared live signing-authority lookup (`authorized_signing_keys`) behind the three passwordless surfaces (`sovereign_session`, `oauth_consent` approve, and `deleteAccount`'s proof branch); resolves the authorized keys live — a did:plc account's current rotation set, or a did:web account's served document — never the `did_documents` cache — see module doc |

### `rate_limit.rs`

Reference-parity request rate limiting. The pure sliding-window algorithm lives in
`auth/rate_limit.rs` (Functional Core); this module is the Imperative Shell owning the
process-level limiters and the Axum middleware. Six families — global per-IP, per-endpoint
per-IP (guess-target endpoint pairs share one limiter instance so alternating endpoints can't
double a guess budget), per-account write points charged in `pds`'s `record_write::commit_repo_write`
on the **authenticated** DID, per-space-credential requests charged at the credential seam
in `custos-spaces`' `auth/space.rs` on the **verified** `cnf.kid`, a per-DID cool-down on the
signature-mismatch DID-document force-refresh (the one limiter guarding an *outbound* resource,
charged in `identity::resolution::refresh_did_document_after_signature_mismatch`), and a
per-`(IP, DID)` cooldown on repeat full `getRepo` exports of an unchanged root, checked in
`pds`'s `routes/get_repo.rs` (`since=` deltas never limited) — all off when
`[rate_limit] enabled = false`; the first four are tunable via `[rate_limit]` /
`EZPDS_RATE_LIMIT_*` (a knob of `0` disables that limiter), as is the `getRepo` cooldown
(`get_repo_full_cooldown_secs`); the DID-refresh cool-down is a fixed constant.
The family rosters, exemptions, and `RateLimit-*` header behavior: the module doc.

### `auth/`

| File | Pattern | Contents |
|---|---|---|
| `dpop.rs` | Mixed (unavoidable) | DPoP proof validation, nonce store — OAuth only |
| `extractors.rs` | Imperative Shell | `AuthenticatedUser` extractor + `authenticate_access`, the single authoritative access-auth path (RFC 9449 scheme ↔ `cnf.jkt` binding); `jwt::verify_access_token` is `pub(super)`, so nothing outside `auth` can bypass it — see module doc |
| `guards.rs` | Imperative Shell | route-level auth guards (admin, session, pending-session, device) + `authenticate_account_owner`'s dual credential; queries `sessions`/`devices`/`admin_devices`, owns no schema — see module doc |
| `issuer_trust.rs` | Mixed (unavoidable) | shared trusted-issuer verification for the two provider-signed auth.md tokens (ID-JAG + SET); also owns `REVOKED_EVENT_TYPE` — see module doc |
| `jwks.rs` | Imperative Shell | `JwksFetcher` + TTL `JwksCache` — the dynamic-trust half of `issuer_trust.rs`'s key resolution, with a per-URL refetch cooldown against bogus-`kid` amplification. Also `client_verification_key`, the one place an OAuth client's self-signed JWT is matched to the keys its metadata publishes (token-endpoint client assertions and space client attestations both) — see module doc |
| `jwt.rs` | Functional Core | JWT parsing, scope validation, access/refresh token verification, HS256 token issuance |
| `oauth_client_resolution.rs` | Mixed (unavoidable) | the ATProto OAuth client resolver: client_id URL policy before any I/O, metadata fetch, bounded negative cache; also `validate_private_use_redirect` — see module doc |
| `oauth_scopes.rs` | Functional Core | the granular ATProto OAuth scope grammar (proposal 0011, plus `space:` from the Spaces proposal 0016): parse, normalize, and canonicalize `resource[:positional][?param=value]` across the six resource types, and enforce it via the `require_*`/`allows_*` checks scoped routes call; `supported_scopes()` backs the discovery metadata. Ported for round-trip parity with `@atproto/oauth-scopes` — see module doc |
| `permission_sets.rs` | Mixed (unavoidable) | resolves `include:<nsid>` scope references to Lexicon-published permission-set records and expands them into the grammar `oauth_scopes.rs` validates; owns the TTL'd `PermissionSetCache` and the shared `resolve_cached` helper `scope_display.rs` reuses. Does live DNS/HTTP, so not a pure core despite living in `auth/` — see module doc |
| `password.rs` | Functional Core | `hash_password`, `verify_password` (argon2id) |
| `rate_limit.rs` | Functional Core | sliding-window login-failure limiter + the generic `MultiWindowLimiter` used by the top-level `rate_limit.rs` middleware |
| `service_auth.rs` | Imperative Shell | `require_service_auth(lxm)` — the inbound atproto service-auth guard, one lexicon method per call — plus the shared resolve-and-verify key machinery migration-`createAccount` reuses — see module doc |
| `signed_proof.rs` | Functional Core | shared decoding for the device-key-signed proof envelopes three routes verify (`sovereign_session`, `oauth_consent`, `delete_account`): fixed lengths + canonical base64url — see module doc |
| `signing_key.rs` | Imperative Shell | ES256 signing key load-or-create |
| `agent_assertion.rs` | Mixed (unavoidable) | shared auth.md agent machinery the agents routes and the token endpoint's agent grants both need: assertion minting, claim-block helpers, `start_claim_attempt`, `AgentAuthError`, agent audit, and `ClaimPollTracker` (`CoreState.poll_tracker`) — see module doc |
| `bearer.rs` | Functional Core | Authorization-header extraction: `extract_access_token` (Bearer + DPoP, RFC 9449) and Bearer-only `extract_bearer_token` — see module doc |
| `validation.rs` | Functional Core | pure format/shape helpers shared across routes (`is_valid_did` re-export, device-public-key bounds, failed-login lock plumbing); each returns a bool or a message the caller maps to its own `ApiError` — see module doc |
| `token` | Functional Core | re-export of `common::token`, the bearer/device token format (`generate_token`, `sha256_hex`, `hash_bearer_token`) shared with `custos-db` |

**Rule:** `auth/` has no knowledge of specific routes and never imports a feature crate.

## Metrics

`pds`'s `GET /metrics` serves the instrument set defined here. `metrics::names` in
`src/metrics.rs` is the single source of truth: each constant documents what it measures and
who records it, a unit test pins the rendered Prometheus names (counters gain their `_total`
suffix at export), and label values never come from request data. `pds`'s `GET /v1/admin/health`
mirrors the sweeps' last-run state as JSON via `sweep_status.rs`, so operators keep the
signal with `[telemetry] metrics_enabled` off.

## Tests from other crates

`#[cfg(test)]` does not cross crates. `test_support` (and the few test-only hooks it needs:
`lexicon::validate_xrpc_output`, `auth::extractors::authenticate_bearer`,
`auth::permission_sets::tests_support`) compile under `cfg(any(test, feature = "test-support"))`.
Enable the feature only from `[dev-dependencies]`:

```toml
[dev-dependencies]
custos-core = { workspace = true, features = ["test-support"] }
```

`test_support::test_state()` returns a `CoreState` (migrated in-memory pool, fixed `jwt_secret`,
Spaces on, rate limiting off, loopback proxy targets allowed). A crate with a wider state wraps
it: `pds`'s `routes::test_utils` re-exports this module and shadows each state constructor with
one returning `AppState` (`AppState::for_test(core)`).

`cargo test -p custos-core` builds neither `pds` nor any feature crate.
