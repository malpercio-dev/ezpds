# Feature Crates Design: `custos-db`, `custos-core`, and the Spaces extraction

Wave 11 track S3, step 1 of 3 ([v2 in place](2026-09-06-v2-in-place.md) §S3).
Linear: MM-566 (this plan, `custos-db`, `custos-spaces`); MM-567 inherits the
remaining features.

## Summary

`crates/pds` is one 148k-line binary crate. Every `cargo test` and `clippy` pass
compiles OAuth, Spaces, agents, blobs, notifications, and admin together, and the
only thing keeping a route from importing a sibling route is a sentence in
`AGENTS.md`. This plan splits the crate along seams that already exist in the
code: the `capabilities.rs` table models features as gated entries, and the
Spaces surface registers only when `[spaces] enabled`.

Three crates come out of `pds`, in this order:

1. **`custos-db`** owns the pool, the one linear V-migration log, the migration
   runner, and the query modules more than one feature reads. Migrations never
   leave it, so V-numbering stays linear by construction.
2. **`custos-core`** owns the shared runtime every feature crate needs and the
   issue did not name: the state struct handlers extract, the access-token and
   DPoP verification seam, identity resolution, the lexicon registry, rate
   limiting, metrics, and the sweep runner. It exists because every Spaces file
   imports `crate::app::AppState`, and a feature crate cannot depend on the binary
   that composes it. Without this layer, step 3 is a cycle.
3. **`custos-spaces`** is the first feature crate: the `com.atproto.space.*` and
   `com.atproto.simplespace.*` routes, `/v1/space/import-repo`, the space auth
   module, the space query modules, both space sweeps, and the `spaces`
   capability entry. Spaces goes first because its gate already exists and its
   route table is the easiest to prove unchanged.

The `pds` binary becomes the composition root: it opens the pool through
`custos-db`, builds a `CoreState`, builds each feature's state from it, merges each
feature's `Router` slice, spawns each feature's sweeps, and lists each feature's
capability entry in `CAPABILITIES`. The wire contract (every route path, the
capability order, the health readout) stays byte-identical; `bruno-check` and
`http_suite.rs` are the oracle.

The one mechanism that keeps the diff mechanical rather than a rewrite:
feature-crate routers are generic over the state type through axum's `FromRef`,
and the composite `AppState` in `pds` derefs to `CoreState`. Shared helpers change
their parameter type from `&AppState` to `&CoreState` once; call sites in `pds`
keep passing `&state` and auto-deref.

## Definition of Done

1. `custos-db` exists; `pds` opens its pool and runs migrations through it. No
   behaviour change.
2. `custos-core` exists; `pds` handlers extract a composite `AppState` whose core
   half is `custos_core::CoreState`. No behaviour change.
3. `custos-spaces` exists; `pds` composes it. `cargo test -p custos-spaces` does
   not compile `crates/pds`, so neither the OAuth server routes nor the agents
   surface build for a Spaces test run.
4. `bruno-check` and `capability-docs-check` run against the new layout and
   pass, and the three seams the retired grep gates once held still hold by
   visibility and type across the crate boundaries: `verify_access_token`
   `pub(super)` (PR #672), `verify_space_credential` private and
   `verify_space_signature` `pub(super)` (PR #673), and `CallerUrl` +
   `HardenedClient` (PR #674).
5. Each new crate has an `AGENTS.md` map; `crates/pds/AGENTS.md`'s module map and
   shared-helpers index point at the new homes.
6. MM-567 can follow the feature-crate contract in §Architecture for OAuth,
   agents, blobs, firehose, and admin without a second design pass.

## Acceptance Criteria

### feature-crates.AC1: `custos-db`
- **feature-crates.AC1.1 Success:** `custos_db::{open_pool, run_migrations, DbError}` are the only pool/migration entry points in the workspace; `pds` calls them and defines none of its own.
- **feature-crates.AC1.2 Success:** every `VNNN__*.sql` file lives under `crates/custos-db/src/migrations/`; the migration runner tests (first run, idempotency, populated-upgrade tests V038/V047/V055) move with it and pass.
- **feature-crates.AC1.3 Success:** `cargo tree -p custos-db -e normal` lists neither `axum` nor `reqwest`.
- **feature-crates.AC1.4 Success:** `http_suite.rs` boots the binary against the full migration log unchanged.

### feature-crates.AC2: `custos-core` and the state split
- **feature-crates.AC2.1 Success:** `custos_core::CoreState` holds every field a core module or more than one feature reads; `pds::AppState` embeds it and implements `FromRef<AppState> for CoreState` and `Deref<Target = CoreState>`.
- **feature-crates.AC2.2 Success:** `auth::extractors::authenticate_access` and `auth::dpop` live in `custos-core`; `verify_access_token` stays `pub(super)` (frozen contract: Wire / OAuth and DPoP).
- **feature-crates.AC2.3 Success:** the `test-support` cargo feature on `custos-core` exposes the test state constructor and the account/token/DPoP fixtures `routes/test_utils.rs` holds today; `pds` and every feature crate enable it only as a dev-dependency.
- **feature-crates.AC2.4 Success:** `cargo test -p custos-core` passes without compiling `crates/pds`.

### feature-crates.AC3: `custos-spaces`
- **feature-crates.AC3.1 Success:** the route set `bruno-check` extracts is identical before and after the extraction: the gate passes against the same `bruno/` collection on both sides of the PR, and `scripts/bruno-parity.sh --list` output diffs empty.
- **feature-crates.AC3.2 Success:** `custos_spaces::router(&config.spaces)` returns an empty router when disabled; `pds` merges it unconditionally; `disabled_spaces_answers_like_a_pds_without_spaces` stays in `pds` and still asserts the catch-all's `MethodNotImplemented`.
- **feature-crates.AC3.3 Success:** `describeServer`'s advertised capability list, with a master key and spaces enabled, equals the pre-extraction list in the same order (new golden test in `pds`).
- **feature-crates.AC3.4 Success:** `cargo test -p custos-spaces` output contains no `Compiling pds` line and every moved `*_test.rs` passes.
- **feature-crates.AC3.5 Success:** `purge_account` still deletes every space-owned row (the schema-walking FK test in `account_delete.rs` passes) and `blob_gc` still unions space-record blob references in.
- **feature-crates.AC3.6 Failure:** a route in `custos-spaces` importing another route does not compile (the module is private to the crate and `routes/mod.rs` exports only handler functions).
- **feature-crates.AC3.7 Success:** `auth/space.rs` and `auth/http_signature.rs` both land in `custos-spaces`, so `verify_space_credential` stays private to `auth::space` and `verify_space_signature` / `SignedFor` stay `pub(super)` to `auth` (the visibility rule that replaced `space-auth-seam-check`, PR #673); neither is `pub` from any crate.

### feature-crates.AC4: Documentation and gates
- **feature-crates.AC4.1 Success:** `crates/custos-db/AGENTS.md`, `crates/custos-core/AGENTS.md`, `crates/custos-spaces/AGENTS.md` exist and follow the map-not-territory rule; `crates/pds/AGENTS.md`'s module map lists only what remains.
- **feature-crates.AC4.2 Success:** `just ci-pds` is green at the end of every phase; the frozen-contracts rows this touches (Wire / XRPC paths, Wire / `describeServer` `custos` extension, Data / SQLite file and migration log) cite the same oracles.

## Glossary

- **Feature crate:** a library crate that owns one gated surface end to end (routes, auth module, query modules, sweeps, capability entry) and depends on `custos-core` and `custos-db`, never on `pds` or on a sibling feature.
- **Core:** code that two or more features need and that has no feature-specific knowledge: token verification, identity resolution, lexicon validation, rate limiting, metrics, the sweep runner.
- **`CoreState`:** the struct every core helper takes and every feature-crate handler can extract. **`SpacesState`:** the Spaces feature's state, which embeds a `CoreState` and adds the feature's own fields. **`AppState`:** the composite in `pds`, the only type that names every feature.
- **Router slice:** a `Router<S>` a feature crate exports, generic over `S` through `FromRef`, so `pds` can merge it into its own `Router<AppState>` before applying the shared middleware stack.

## Architecture

### Crate graph

```
common ──────┐
crypto ──────┤
repo-engine ─┤
             ▼
         custos-db        pool · migrations · runner · cross-feature query modules
             │
             ▼
         custos-core      CoreState · auth core · identity · lexicon · rate_limit
             │            metrics · time · sweep · sweep_status · blob_store
             │            [test-support]: test state + fixtures
             ▼
         custos-spaces    SpacesState · routes · auth/space · db/space_* · sweeps · CAPABILITY
             │
             ▼
           pds (bin)      AppState · app.rs composition · main.rs · everything not yet extracted
                          (oauth server, agents, blobs, firehose, admin, repo, notifications)
```

Edges point from dependency to dependent. Two rules hold the shape: a feature
crate never depends on `pds` or on another feature crate, and `custos-core` never
depends on a feature crate. The second rule is what makes `cargo test -p
custos-spaces` skip OAuth and agents: those stay in `pds` until MM-567 moves
them into siblings.

The `pds` package keeps its name. `Dockerfile`, the `just` recipes, `ci.yml`'s
`CUSTOS_MCP_TEST_PDS_BIN`, and `http_suite.rs`'s `CARGO_BIN_EXE_pds` all name it
(frozen contract: Operations / Deploy artifact and Railway wiring). The new crates
take the `custos-` prefix, which is the one-crate-at-a-time rename the umbrella
allows.

### What each crate owns

| Module today (`crates/pds/src/`) | Goes to | Note |
|---|---|---|
| `db/mod.rs` pool, runner, `DbError`, unique-violation helpers, `insert_with_retry_*`, `test_pool` | `custos-db` | `test_pool` behind a `test-support` feature |
| `db/migrations.rs` + `db/migrations/*.sql` | `custos-db` | the only home migrations ever have |
| `db/accounts.rs`, `dids.rs`, `handles.rs`, `blobs.rs`, `blocks.rs`, `kek.rs`, `admin_audit.rs`, `sessions.rs`, `refresh_tokens.rs`, `server_stats.rs`, `oauth.rs` | `custos-db` | cross-feature tables (`oauth.rs` because client attestation reads `ClientMetadata`); the rest of `db/` stays in `pds` until a feature crate needs it |
| `uniqueness.rs`, `code_gen.rs`, `auth/token.rs` | `common` | the three upward imports `db/` makes (`normalize_email`, `generate_code`, and `generate_token` in tests); pure, alongside `Did`/`Handle` |
| `time.rs` | `custos-core` | every moved module's clock |
| `space_uri.rs` | `common` | `lexicon/formats.rs` and `auth/validation.rs` (both core) call it; a pure string validator like `Did` |
| `state.rs` (as `CoreState`), `auth/{extractors,bearer,jwt,dpop,signing_key,guards,oauth_scopes,permission_sets,service_auth,issuer_trust,jwks,oauth_client_resolution,signed_proof,validation,password,rate_limit}` | `custos-core` | the verification seam and everything it needs; `jwt` and `dpop` move with `extractors` so `verify_access_token` / `validate_dpop` keep their `pub(super)` (PR #672); `oauth_client_resolution` because client attestation resolves client metadata through it. The OAuth *server* (`routes/oauth_*`, `auth/oauth_response_mode`) stays in `pds` for MM-567 |
| `identity/`, `lexicon/` + `lexicons/`, `rate_limit.rs`, `metrics.rs`, `sweep.rs`, `sweep_status.rs`, `blob_store.rs`, `request_host.rs`, `no_input.rs`, `xrpc_error_shape.rs`, `apply_shared_layers` | `custos-core` | `lexicons/` moves with the registry (`include_str!` is path-relative); `tools/lexgen` and the lexicons README repoint |
| `record_write::record_validation_error` | `custos-core::lexicon` | `space_views.rs` imports it; the repo write path itself stays in `pds` |
| `routes/test_utils.rs` | `custos-core::test_support` | behind the `test-support` feature |
| `space_record_write.rs`, `space_notify.rs`, `space_jti_sweep.rs`, `space_oplog_sweep.rs`, `auth/space.rs`, `auth/http_signature.rs`, `auth/space_consent.rs`, `auth/client_attestation.rs`, `db/{spaces,space_repos,space_notify,space_jti}.rs`, `routes/*space*.rs`, `routes/simplespace_*.rs`, `routes/get_delegation_token.rs`, `routes/admin_spaces.rs`, `routes/space_views.rs`, `routes/space_test_support.rs` | `custos-spaces` | `http_signature` has no caller outside Spaces (`auth::space`, `routes/get_space_credential.rs`, and the space-request signer in `routes/test_utils.rs`, which goes to `custos_spaces::test_support`), and `auth::space` calls its `pub(super)` `verify_space_signature`, so the two must share a crate; `client_attestation` is reached only from `auth::space` and spends `space_jti` rows; `get_delegation_token` and `admin_spaces` are registered inside the gate today |
| `capabilities.rs` `spaces` entry | `custos_spaces::CAPABILITY` | the `Capability` type moves to `custos-core` |
| everything else | `pds` | until MM-567 |

The `common` rows are the cost the issue predicted: `db/` reaches three small
helpers above it, and two core modules reach `space_uri`. Each is pure and moves
down rather than being copied.

### The state split

`AppState` today has 28 fields. Eight are owned by one feature: `firehose`,
`crawlers`, `iroh`, `notify_sender`, `poll_tracker` (agents), `email`,
`repo_write_locks`, `space_type_cache`. `permission_set_cache` looks
feature-specific but core scope resolution reads it. A field goes in `CoreState`
when a core module reads it or two features do; otherwise it lives in the owning
feature's state. First cut:

```rust
// custos-core
#[derive(Clone)]
pub struct CoreState {
    pub config: Arc<Config>,
    pub db: SqlitePool,
    pub http_client: reqwest::Client,
    pub hardened_http_client: identity::proxy::HardenedClient,
    pub dns_provider: Option<Arc<dyn DnsProvider>>,
    pub txt_resolver: Option<Arc<dyn TxtResolver>>,
    pub well_known_resolver: Option<Arc<dyn WellKnownResolver>>,
    pub jwks_cache: Arc<JwksCache>,
    pub oauth_client_jwks_cache: Arc<JwksCache>,
    pub jwt_secret: [u8; 32],
    pub oauth_signing_keypair: OAuthSigningKey,
    pub dpop_nonces: DpopNonces,
    pub permission_set_cache: PermissionSetCache,
    pub did_document_cache: DidDocumentCache,
    pub failed_login_attempts: FailedLoginStore,
    pub rate_limiter: Arc<RateLimiterState>,
    pub allow_loopback_proxy_targets: bool,
    pub metrics: Arc<Metrics>,
    pub sweeps: Arc<SweepStatus>,
    pub started_at: Instant,
}

// custos-spaces
#[derive(Clone)]
pub struct SpacesState {
    pub core: CoreState,
    pub space_type_cache: SpaceTypeCache,
}
impl Deref for SpacesState { type Target = CoreState; /* &self.core */ }

// pds
#[derive(Clone)]
pub struct AppState {
    pub core: CoreState,
    pub spaces: SpacesState,
    pub firehose: Arc<Firehose>,
    pub crawlers: Arc<CrawlerNotifier>,
    pub iroh: Option<Arc<IrohState>>,
    pub notify_sender: Option<NotifySender>,
    pub poll_tracker: ClaimPollTracker,
    pub email: Arc<dyn EmailSender>,
    pub repo_write_locks: Arc<RepoWriteLocks>,
}
impl Deref for AppState { type Target = CoreState; /* &self.core */ }
impl FromRef<AppState> for CoreState { /* state.core.clone() */ }
impl FromRef<AppState> for SpacesState { /* state.spaces.clone() */ }
```

`FromRef` is what lets a `Router<AppState>` host handlers that extract
`State<SpacesState>`: axum projects the substate per request. The clone is a
handful of `Arc` increments, nothing an SQLite round trip would notice.

`Deref` is a diff-size decision, not an architecture one. Without it, every
`state.db` / `state.config` read in `pds` and every `helper(&state, ..)` call
becomes `state.core.db` / `helper(&state.core, ..)`: thousands of edits across
the files that stay put. With it, a `pds` handler that extracts `State<AppState>`
compiles unchanged. The same holds for `SpacesState`. `Deref` on a plain struct
is unidiomatic enough to deserve its one-line comment; it is not a smart pointer
and nothing should ever rely on it for anything but field access.

`SweepSnapshot` keeps its typed fields, including `space_jti_sweep` and
`space_oplog_sweep`, and moves to `custos-core` as is. The `GET /v1/admin/health`
JSON keys are what the Brass Console reads, so the shape must not move in a
"no behaviour change" PR. A feature naming its sweep in a core struct is a known
smell; S2's single sweep scheduler is the place to key sweeps by name.

### The feature-crate contract

A feature crate exports exactly these, and `pds` consumes nothing else from it:

```rust
pub struct SpacesState { pub core: CoreState, /* feature fields */ }
impl SpacesState { pub fn new(core: CoreState) -> Self }

/// Empty when `config.enabled` is false: the gate lives with the feature.
pub fn router<S>(config: &SpacesConfig) -> Router<S>
where S: Clone + Send + Sync + 'static, SpacesState: FromRef<S>;
/// The same, for routes that belong in the no-CORS `/v1/*` group.
pub fn internal_router<S>(config: &SpacesConfig) -> Router<S> where /* as above */;

/// `None` when disabled, so the health readout reads "not configured" as today.
pub fn spawn_sweeps(state: SpacesState) -> Option<Vec<JoinHandle<()>>>;

pub const CAPABILITY: Capability;

/// Hooks the composition root calls from its own transactions.
pub mod db;            // the feature's query modules, `pub`
pub fn purge_account_rows(tx: &mut SqliteTransaction<'_>, did: &str) -> Result<(), sqlx::Error>;

#[cfg(feature = "test-support")]
pub mod test_support;  // `test_app(state)`, request builders, record bodies
```

`routes/` inside the crate is a private module that re-exports handler
functions only. A route importing another route fails to compile because the
sibling module is not in scope, which is the isolation rule held by a type.

The gate moves inside the crate. Today `app.rs` wraps `space_routes()` in
`if state.config.spaces.enabled`; after, `router(&config.spaces)` returns
`Router::new()` when disabled and `pds` merges it unconditionally. `CAPABILITY.
enabled` reads the same flag plus the master key, as today. One switch, one home.

`Capability` moves to `custos-core` and gains `Clone, Copy` (it is two `&'static
str` and a `fn` pointer). The `pds` table stays a `&[Capability]` literal with
`custos_spaces::CAPABILITY` in the slot `spaces` occupies today, between
`appPasswordPersonalDetails` and `waitlist`, so `advertised()` and the
advertisement order are untouched.

### Composition in `pds`

```rust
// main.rs
let pool = custos_db::open_pool(&db_url).await?;
custos_db::run_migrations(&pool).await?;
let core = CoreState { /* as today, minus feature fields */ };
let spaces = SpacesState::new(core.clone());
let state = AppState { core, spaces, firehose, /* .. */ };
// ...
let _space_sweeps = custos_spaces::spawn_sweeps(state.spaces.clone());

// app.rs
let public = Router::new()
    .route(/* every route that still lives here */)
    .merge(custos_spaces::router(&state.config.spaces));
let internal = Router::new()
    .route(/* .. */)
    .merge(custos_spaces::internal_router(&state.config.spaces));
let public = apply_shared_layers(public, &state.core) /* flatten + CORS as today */;
```

`apply_shared_layers` moves to `custos-core` and takes `&CoreState`;
`rate_limit_middleware` and `http_metrics_middleware` already read only core
fields. Feature routers are merged *before* the layer stack, as `space_routes()`
is today, so they inherit tracing, metrics, rate limiting, and the XRPC error
dialect without re-declaring them.

`purge_account` (still in `pds`) calls `custos_spaces::purge_account_rows` inside
its transaction in the same FK order it uses today; `blob_gc` (still in `pds`)
calls `custos_spaces::db::list_record_blocks_for_account`. Both edges point the
allowed way, composition root to feature.

### Cross-cutting consumers that stay in `pds`

Three places outside the Spaces files reach into it today and keep doing so
through the crate's public surface:

- `routes/oauth_authorize.rs` and `routes/oauth_templates.rs` render `space:`
  scopes on the consent page through `auth::space_consent`. That module moves to
  `custos_spaces::consent`; the consent page imports it from there. When MM-567
  extracts the OAuth server, `custos-oauth` would depend on `custos-spaces` for
  this one display resolver. That is a feature-to-feature edge the rules forbid,
  so MM-567 either keeps the consent *rendering* in `pds` (it is one page, and
  `pds` may depend on every feature) or puts the scope-display resolver behind a
  trait in `custos-core`. This plan does not decide it; it records the edge.
- `account_delete.rs` and `blob_gc.rs`, covered above. Their tests that write
  space records keep doing so through `custos_spaces::space_record_write`.
- `routes/admin_health.rs` reads the typed `SweepSnapshot`, unchanged.

### Tests across the crate boundary

`#[cfg(test)]` does not cross crates, so shared fixtures need a cargo feature.
`custos-core` gets `test-support`, gating `pub mod test_support` with the test
state constructor (today's `test_state_with_plc_url`, returning a `CoreState`) and
the account, token, DPoP-proof, request-builder, and body-decoding helpers from
`routes/test_utils.rs`. Feature crates and `pds` enable it only under
`[dev-dependencies]`; resolver v2 keeps a dev-dependency feature out of the
normal build.

The Spaces route tests drive requests through the whole router, by way of
`space_test_support::send` and some fifty direct `crate::app::app(state)` calls.
After the move they call `custos_spaces::test_support::test_app(state)`, which merges `router()` and
`internal_router()` and applies `custos_core::apply_shared_layers`, so the
rate-limit assertions in `space_lifecycle_test.rs` keep their middleware. The two
assertions that need the *rest* of the app, the disabled-gate test and anything
that hits the `/xrpc/{method}` catch-all, stay in `pds`.

`http_suite.rs` is untouched: it spawns the binary and never imports a crate.

### Gate scripts that name `crates/pds`

| Script | Today | After |
|---|---|---|
| `scripts/bruno-parity.sh` | extracts `.route("…")` literals from `crates/pds/src/app.rs` | takes a `ROUTER_FILES` list (`app.rs` plus every `crates/custos-*/src/router.rs`), fails if any is missing, gains `--list` for the before/after diff |
| `scripts/capability-docs-check.mjs`, `scripts/generate-docs-reference.mjs` | parse the `CAPABILITIES` literal in `crates/pds/src/capabilities.rs` | also parse every `crates/custos-*/src/capability.rs`; order comes from the `pds` table, entries from wherever the literal lives |
| `scripts/changelog-test.sh` | symlinks `crates/pds/src/capabilities.rs` into its fixture repo | symlinks the feature crates' `capability.rs` files too, so the fixture sees the whole table |
| `tools/lexgen/generate.mjs`, `justfile` `lexgen` | `crates/pds/lexicons` | `crates/custos-core/lexicons` |

`ticket-ref-check`, `adr-ref-check`, and `workspace-dep-check` already glob
`crates/*` and need nothing.

The three seam grep gates (`auth-seam-check`, `space-auth-seam-check`,
`ssrf-client-check`) are gone; PRs #672–#674 replaced each with a rule the
compiler holds, and a crate boundary only tightens a visibility rule. What each
phase must keep true instead:

| Seam | Held by | Holds across the split when |
|---|---|---|
| access-token verification only through `authenticate_access` | `verify_access_token` `pub(super)` in `auth::jwt`; `validate_dpop` `pub(super)` in `auth::dpop` (PR #672) | `jwt`, `dpop`, and `extractors` move to `custos-core` together and neither function is widened to `pub` |
| space-credential verification only inside `auth::space` | `verify_space_credential` private; `verify_space_signature` / `SignedFor` `pub(super)` in `auth::http_signature`; the mint route's only check is `verify_delegation_signature` (PR #673) | `auth/space.rs` and `auth/http_signature.rs` move to `custos-spaces` together |
| caller-influenced URLs only on the SSRF-hardened client | `CallerUrl` (private field) and `HardenedClient`, whose request methods take only a `CallerUrl` (PR #674) | the types move to `custos-core` with `identity/` unchanged; `HardenedClient::into_inner` stays the one escape hatch |

## Existing Patterns

- **`custos-client` (MM-556, PR #645)** is the precedent for pulling a library out
  of a binary: workspace member, `{ workspace = true }` dependencies, its own
  `AGENTS.md` map with a scope note, apps inject what they own as trait objects.
  The same shape applies here with `FromRef` in place of trait objects, because
  axum already has the projection.
- **`capabilities.rs`** is the feature registry the plan builds on: one entry per
  gated surface, `enabled` mirrors the route gate, order is the wire contract.
- **`sweep::spawn_sweep`** is already the one periodic-task shape; the space
  sweeps use it and keep using it from `custos-core`.
- **`routes/space_test_support.rs`** already isolates the Spaces tests' request
  plumbing from `test_utils.rs`; it becomes the crate's `test_support` module
  nearly as is.
- **`auth::extractors::authenticate_access` / `auth::space::authenticate_space_read`**
  are the two authentication seams, held by visibility since PRs #672 and #673.
  Crate boundaries keep that rule: a feature crate can only reach verification
  through the `pub` seam.

## Implementation Phases

Each phase is one PR, green on `just ci-pds` and `just ci` at its end, with no
behaviour change. Phases 2 and 3 are large but mechanical; the plan calls out
where the mechanical part ends.

### Phase 1: `custos-db`

Move `db/mod.rs`'s pool, runner, `DbError`, unique-violation helpers,
`insert_with_retry_*`, and `test_pool` (behind `test-support`), plus
`db/migrations.rs` and every SQL file, into `crates/custos-db`. Move the
cross-feature query modules listed above with them, and the three pure helpers
they import (`uniqueness`, `code_gen`, `auth/token`) to `common`. The
migration runner tests move with the runner. `pds`'s `db/mod.rs` keeps the
remaining query modules and re-exports the moved API (`pub use custos_db::{…}`)
so no call site in `pds` changes. Add the crate to the workspace members and the
`ci-pds` gate picks it up (it excludes only the iOS apps).

Gate: AC1. Plus `cargo tree -p custos-db` as a one-line check in the crate's
`AGENTS.md`.

### Phase 2: `custos-core` and the state split

Create `crates/custos-core`; move the modules in the ownership table; rename the
moved `AppState` to `CoreState` and drop the feature-owned fields; define the
composite `AppState` in `pds` with `Deref` + `FromRef`; move `apply_shared_layers`;
add the `test-support` feature with the test state constructor and fixtures;
move `lexicons/` and repoint `tools/lexgen`. Every helper signature `&AppState` →
`&CoreState` is the mechanical half. The non-mechanical half is the field triage:
any field a core module turns out to read that the first cut left in `pds` moves
to `CoreState` then, not by widening `CoreState` up front.

Keep the access-token and SSRF seams in the gate-scripts section's seam table
holding: `jwt`, `dpop`, and `extractors` land together, and no `pub(super)` is
widened to make the move compile.

Gate: AC2. The `pds` route tests all still build the full `app(state)`; nothing
about them changes in this phase.

### Phase 3: `custos-spaces`

Create `crates/custos-spaces`; move the Spaces files; define `SpacesState`,
`router`, `internal_router`, `spawn_sweeps`, `CAPABILITY`, `purge_account_rows`,
`test_support::test_app`; move `space_uri` to `common`; move the gate inside
`router`; swap the `pds` consumers (`purge_account`, `blob_gc`, the consent page,
the capability table) to the crate's public surface; replace the `app(state)`
calls in the moved tests with `test_app`; add the capability-order golden test. Repoint
`bruno-parity.sh` (with `--list`) and the three capability parsers, and move
`auth/http_signature.rs` with `auth/space.rs` so the space-credential seam keeps
its visibility (AC3.7).

Route-to-route imports surface here as compile errors. Known today:
`space_notify.rs` (a top-level module) imports `routes::space_views::lex_bytes`,
and `space_views.rs` imports `record_write::record_validation_error`. The first
moves `lex_bytes` into the crate's non-route module; the second moves the error
mapper to `custos-core::lexicon`. Budget for a few more.

Gate: AC3, AC4. Before opening the PR, capture `scripts/bruno-parity.sh --list`
on `main` and on the branch and attach the empty diff to the PR description.

### Phase 4: Maps and hand-off

Write the three `AGENTS.md` maps; trim `crates/pds/AGENTS.md` to what remains and
repoint its shared-helpers index (`routes::test_utils` → `custos_core::test_support`,
`routes::space_test_support` → `custos_spaces::test_support`, `sweep::spawn_sweep`
→ `custos_core::sweep::spawn_sweep`, and so on); add the new crates to the root
`AGENTS.md` project structure. Record in MM-567 the consent-page edge from
§Cross-cutting consumers and the `SweepSnapshot` smell, so the OAuth extraction
starts with both decided.

This phase can ride on Phase 3's PR if the maps are small enough to review
together.

## Additional Considerations

**Why not an extension map for feature state.** An `Extensions`-style
type-erased map in `CoreState` would let feature crates stash their state without
`pds` naming them. It trades a compile error for a runtime `None`, which is the
opposite of what Wave 11 is for (rules held by a type cannot drift). `FromRef`
costs one impl per feature in `pds` and nothing at runtime beyond `Arc` clones.

**Why `custos-core` and not a fatter `custos-db`.** The issue names two crates.
The verification seam, identity resolution, and the lexicon registry are not
database concerns, and a crate named `custos-db` that exports
`authenticate_access` would mislead every reader after. The third crate is the
cost of the AppState wall; it is not optional.

**Compile-time payoff.** `custos-spaces` builds `common`, `crypto`,
`repo-engine`, `custos-db`, `custos-core`, and itself: roughly 14k lines of Spaces
code plus the core it needs, instead of 148k. The `pds` binary's own build does
not get faster until MM-567 moves the rest out; what gets faster now is the
feature-local edit-test loop, and `cargo clippy -p custos-spaces` as a
pre-commit check.

**Dependency hygiene.** Each new manifest uses `{ workspace = true }` for every
dependency (`workspace-dep-check`). No new third-party crates: `FromRef` is in
axum, and the `Deref` impls are hand-written rather than pulling `axum-macros`
for `#[derive(FromRef)]`.

**Frozen contracts touched.** Wire / XRPC paths and lexicons (route table
identical, `bruno-check`); Wire / `describeServer` `custos` extension (order
pinned by the new golden test, `capability-docs-check`); Data / SQLite file and
migration log (runner tests move, `http_suite.rs` boots against the full log).
No row changes meaning; this plan needs no ADR.

**What this plan does not do.** It does not touch the OAuth server, agents,
blobs, firehose, or admin surfaces beyond the three consumer edges above (that is
MM-567). It does not change the health readout's shape (S2). It does not rename
`pds`, `ezpds`, or the `EZPDS_*` configuration. It does not introduce
lexicon-generated handlers (ADR-0038 stands).
