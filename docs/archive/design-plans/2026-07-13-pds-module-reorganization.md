# PDS Crate Module Reorganization

Status: **landed** — the AppState/state.rs, identity/, firehose/, auth/, and oauth_token splits shipped across #241/#259/#246/#253/#256 (2026-07-13..14).
Tracked in Linear: [MM-325](https://linear.app/malpercio/issue/MM-325) (sweeps/),
[MM-326](https://linear.app/malpercio/issue/MM-326) (identity/),
[MM-327](https://linear.app/malpercio/issue/MM-327) (proxy guard split),
[MM-328](https://linear.app/malpercio/issue/MM-328) (AppState extraction),
[MM-329](https://linear.app/malpercio/issue/MM-329) (firehose split),
[MM-330](https://linear.app/malpercio/issue/MM-330) (oauth_token split),
[MM-331](https://linear.app/malpercio/issue/MM-331) (jwks/oauth_client_resolution → auth/),
[MM-332](https://linear.app/malpercio/issue/MM-332) (db/migrations.rs),
[MM-333](https://linear.app/malpercio/issue/MM-333) (cross-route helper dedup).

## Problem

`crates/pds/src/` has 31 top-level `.rs` files (~13.9k lines) beside four
subdirectories (`auth/` 15 files, `db/` 26, `routes/` 103, `read_after_write/` 4).
The top level mixes at least four distinct kinds of code — background sweepers,
identity resolution, firehose machinery, auth primitives — so finding the right
file means already knowing its name, and the auth/security boundary is fuzzy
(token hashing lives outside `auth/` while token extraction lives inside).

Two facts make the reorganization cheap:

- **This is a binary crate** (no `lib.rs`): all `pub` is effectively
  crate-visible, so moves are `mod` declarations in `main.rs` plus
  `use crate::x` → `use crate::group::x` re-paths. No external API to preserve.
- **`mod.rs` re-exports** can keep consumer files untouched where churn would
  otherwise be wide (firehose has 19 consumers; AppState has all of them).

None of the moves touch the crate's hard rules (route isolation, pattern
comments, DB ownership) — pattern comments travel with their files, and the
`crates/pds/AGENTS.md` module map must be updated in the same PR as each move.

## Current top-level inventory

| File | LOC (≈prod) | Purpose |
|---|---|---|
| firehose.rs | 2769 (1500) | Firehose: event types, sequencer, emit/staging, replay |
| app.rs | 1245 (830) | AppState + router construction + `xrpc_handler` dispatch |
| record_write.rs | 984 (700) | Shared repo write flow, write locks, commit CAS, block GC |
| identity_resolution.rs | 888 (650) | Handle/DID resolution **and** proxy-target SSRF guard |
| blob_gc.rs | 703 (335) | Periodic blob GC sweep |
| firehose_gc.rs | 649 (305) | Periodic `repo_seq` retention sweep |
| rate_limit.rs | 560 (300) | Rate-limit middleware shell (core in `auth/rate_limit.rs`) |
| email.rs | 508 | Pluggable outbound email sender |
| main.rs | 502 | Startup + all `mod` declarations |
| jwks.rs | 492 | JWKS fetcher + TTL cache (pairs with `auth/issuer_trust.rs`) |
| account_delete.rs | 489 (200) | Shared permanent account-deletion transaction |
| crawler.rs | 424 | Outbound requestCrawl notifier |
| blob_store.rs | 412 | Filesystem blob backend, CID computation |
| metrics.rs | 362 | OTel meter + Prometheus + HTTP metrics middleware |
| plc_ops.rs | 330 | did:plc rotation/update op machinery |
| handle.rs | 328 | Handle validation (pure) |
| transfer.rs | 268 | Device-transfer workflows |
| agent_claim_sweep.rs | 238 (120) | Periodic agent-claim expiry sweep |
| genesis.rs | 212 | Shared did:plc genesis-op machinery |
| oauth_client_resolution.rs | 205 | OAuth client_id URL policy + metadata fetch |
| account_reaper.rs | 205 (100) | Periodic deactivated-account deletion sweep |
| iroh_tunnel.rs | 190 | Iroh QUIC endpoint (opt-in) |
| admin_nonce_sweep.rs | 152 (75) | Periodic stale admin-nonce sweep |
| sweep_status.rs | 139 | Readable last-run state per sweep |
| code_gen.rs | 129 | Random claim-code generation (pure) |
| dns.rs | 122 | DnsProvider + TxtResolver traits |
| token.rs | 114 | Token generation + hashing (pure security primitive) |
| telemetry.rs | 100 | OTel tracing init |
| well_known.rs | 69 | `.well-known/atproto-did` resolver trait |
| platform.rs | 52 | Device Platform enum |
| uniqueness.rs | 33 | Email/handle preflight uniqueness checks |

## Target tree

```
src/
  main.rs
  app.rs                    # router construction + shared layers only
  state.rs                  # AppState + FailedLoginStore (from app.rs)

  firehose/                 # split of firehose.rs
    mod.rs                  #   Firehose, emit_*/lock_emit, EmitGuard, Pending* staging
    events.rs               #   RepoOp, CommitEvent, AccountEvent, IdentityEvent,
                            #   SyncEvent, FirehoseEvent, decode_stored_event
    replay.rs               #   Subscription, SubscribeOutcome, ReplayReader

  sweeps/                   # the five template-shaped background tasks
    mod.rs                  #   re-exports; optional shared spawn-loop helper
    account_reaper.rs
    admin_nonce_sweep.rs
    agent_claim_sweep.rs
    blob_gc.rs
    firehose_gc.rs
    status.rs               #   (sweep_status.rs)

  identity/                 # everything "who is this handle/DID"
    mod.rs
    resolution.rs           #   identity_resolution.rs minus the proxy half
    proxy.rs                #   resolve_atproto_proxy_target, validate_proxy_endpoint,
                            #   PinnedResolution/build_pinned_client (SSRF guard, ~450 LOC)
    handle.rs
    dns.rs
    well_known.rs
    plc.rs                  #   plc_ops.rs
    genesis.rs

  auth/
    jwks.rs                 #   from src/jwks.rs — pairs with issuer_trust.rs
    oauth_client_resolution.rs
    token.rs                #   optional: from src/token.rs (see MM-331 discussion)
    ...existing files

  # unchanged at top level (small, distinct, multi-domain consumers):
  telemetry.rs  metrics.rs  email.rs  crawler.rs  iroh_tunnel.rs  rate_limit.rs
  blob_store.rs  record_write.rs  account_delete.rs  transfer.rs
  code_gen.rs  platform.rs  uniqueness.rs
```

Result: 31 top-level files → ~17 entries.

## Rationale per group

- **sweeps/** — the five sweepers explicitly cite each other as templates
  ("template: account_reaper.rs") and share the exact
  `spawn_* / run_* / *Stats` + gauge + `sweep_status` shape. Import churn ≈
  zero: referenced only from `main.rs` spawn calls plus 7 `sweep_status`
  imports. Optional follow-on: extract the shared interval-loop scaffolding
  into `sweeps/mod.rs`.
- **identity/** — six files, one conceptual domain (resolution chain +
  did:plc ops); ~26 import sites total. The proxy split (MM-327, done)
  additionally isolates the SSRF guard + DNS-pinning client into its own
  reviewable `identity/proxy.rs`; consumers are `xrpc_dispatch.rs`,
  `routes/service_proxy.rs`, and `auth::permission_sets`.
- **firehose/** — three cohesive layers (event model, durable emit/staging,
  replay); `mod.rs` re-exports keep the 19 consumer files untouched. The
  1270-line test module splits along the same seams.
- **auth/ absorption** — `jwks.rs` and `oauth_client_resolution.rs` are auth
  machinery consumed only by auth-flow code. The independent security review
  reached the same conclusion and extends it to `token.rs`: token *extraction*
  (`auth/bearer.rs`) lives inside `auth/` while the hashing/generation
  primitive lives outside, which blurs the "where do I audit token handling"
  boundary. `oauth_client_resolution.rs` is also missing from the AGENTS.md
  module map today.
- **state.rs** — every file in the crate depends on `AppState`, so `app.rs`
  churns constantly and must be read for unrelated reasons. A `pub use` shim
  in `app.rs` makes the extraction zero-churn. Moving `xrpc_handler` to its
  own file is optional but principled: it is the proxy front door, not router
  plumbing.

## Related splits and dedup (same review)

- **routes/oauth_token.rs** (3307 lines, MM-330): one handler, four grant
  types → `routes/oauth_token/{mod,authorization_code,refresh,jwt_bearer,claim_polling}.rs`.
  Still a single route module; route isolation untouched.
- **db/mod.rs** (MM-332): extract `db/migrations.rs` holding
  `Migration` + the 42-entry `MIGRATIONS` table.
- **Cross-route helper dedup** (MM-333): `read_repo_rev` ×3, `unix_now` ×2,
  epoch/rfc3339 variants ×3 — copies forced by the (good) no-routes-importing-routes
  rule; home them next to `record_write.rs` / in `crates/common`.
- **DPoP validator prologue** ([MM-335](https://linear.app/malpercio/issue/MM-335)):
  not a file move, but the same drift-prevention motive — the two validators in
  `auth/dpop.rs` re-implement the same proof-validation sequence.

## Non-goals

- No `pub` → `pub(crate)` sweep: cosmetic in a binary crate.
- `routes/` and `db/` stay as they are — consistently organized. Only
  opportunistic harmonization of the `pub mod` vs `pub(super)` mix in the four
  non-handler route support files.
- No behavior changes anywhere; every PR in this plan should be reviewable as
  pure moves + import re-paths.

## Sequencing

1. **MM-325 (sweeps/), MM-331 (auth/ absorption), MM-332 (db/migrations.rs)** —
   cheap wins, near-zero churn.
2. **MM-326 + MM-327 together** — identity/ move + proxy split in one PR.
3. **MM-328** — state.rs extraction.
4. **MM-329** — firehose split.
5. **MM-330** — oauth_token split.
6. **MM-333, MM-335** — dedup passes, any time.

Each PR: move files with their pattern comments, update `main.rs` mods and
import paths, update the module map in `crates/pds/AGENTS.md`, run `just ci-pds`.
