# Rev-aware cooldown on full `getRepo` exports

**Date:** 2026-10-20 · **Status:** Implementation in review · **Linear:** MM-597 (Wave 7: Hardening)
**Sources:**
- Railway usage CLI (`railway usage`, `railway usage projects --project ezpds`), per-service `NETWORK_TX_GB` series and HTTP/flow logs for `custos-obsign`, billing period 2026-09-29 → 2026-10-29
- Production PDS `/metrics` (counters since the 2026-09-04 deploy)
- [hydrant](https://tangled.org/did:plc:dfl62fgb7wtjj3fcbb72naae/hydrant) source: `src/types.rs::ResyncState::next_backoff`, `src/backfill/{client,error,manager,filtered_car}.rs`, `src/resolver.rs`
- [Railway CDN reference](https://docs.railway.com/networking/cdn), [cache headers guide](https://docs.railway.com/guides/cache-headers-cdn.md)

## 1. The bill

Railway usage for the current period was $21.23 at day 21 of 30 (estimated $30.42 at
month end), against $19.46 the period before. Almost all of it is one service and,
inside that service, one line item.

| Scope | 2026-09-29 → 10-20 | 2026-08-29 → 09-29 |
|---|---|---|
| Workspace usage | $21.23 | $19.46 |
| `ezpds` project | $20.74 (98%) | $17.41 |
| PDS service `custos-obsign` | $19.50 | $15.63 |
| — egress | **$15.00** | $10.86 |
| — memory (~470 MB RSS average) | $3.82 | $4.20 |
| — CPU (~0.05 vCPU average) | $0.65 | $0.53 |
| Everything else (notify relay, umami + Postgres + Valkey, marketing, docs, MCP sidecar, `atbb`) | ~$1.75 | ~$2.2 |

Staging and the static/sidecar services sleep. Litestream and blob-mirror traffic to
object storage is negligible in the flow logs. There is nothing material to trim
outside the PDS's egress.

## 2. What the egress is

The PDS transmitted 12–17 GB/day over the period (~298 GB so far, rising). One hour of
Railway HTTP logs (2026-10-20 00:00–01:00 UTC) accounts for it:

| Path | Requests / h | Bytes / h |
|---|---|---|
| `com.atproto.sync.getRepo` | 185 | ~604 MB |
| everything else combined | thousands | ~1 MB |

That is ~14.5 GB/day, ~93% of the service's measured egress, and it is one caller
fleet fetching one repo:

- Seven IPs: four with User-Agent `hydrant/0.1.0` (GCP europe-north1/west1, AWS
  us-west-2, one Hetzner-range, one residential) and three with no User-Agent on the
  identical cadence and byte count.
- Each fetches the **full CAR of `did:web:malpercio.dev`** (3,505,558 bytes; 6,697
  records, 1,721 MST nodes) every 2–3 minutes, around the clock. Never the `did:plc`
  repo on the same host, never a `since=` delta.
- 15-minute samples on 2026-10-16, 10-19 and 10-20 are identical. Railway log retention
  ends at ~7 days, but the daily egress series is flat-to-rising back to 09-29 and the
  previous period's egress was 72% of this one's, so it has run for at least two cycles.

hydrant is ptr.pet's AT Protocol indexer. Its resync backoff is "first retry 2 min,
doubling, capped at 1 h" (`ResyncState::next_backoff`). The observed cadence is pinned
at the *first* retry, so every successful download is being requeued as a fresh
failure. Three ways this could be our fault were checked and ruled out:

- The latest commit signature verifies against the `#atproto` key (and fails against
  the `#device` key as a control).
- The self-hosted `did.json` on the atbb host and the PDS's own view of the DID document
  are identical (`describeRepo`).
- The CAR is structurally sound: all 8,411 blocks reachable from the root, no dangling
  references, keys strictly ordered, canonical layers. The `did:plc` repo nobody
  re-fetches has the same shape.

So the loop is a hydrant-side behaviour that triggers on this repo (did:web handling is
the likely culprit; its resolver has recent did:web-specific changes). The exact
internal trigger is unconfirmed: Tangled's knot was unavailable when `src/backfill/task.rs`
was requested.

Two side observations: the atbb host curls all twelve repos hourly (~$0.15/mo, fine),
and neither Railway's edge nor the PDS compresses the CAR (`Accept-Encoding: gzip` is
ignored).

## 3. Why the limiter lets this through

`crates/pds/src/rate_limit.rs` exempts `getRepo` (and `subscribeRepos`, `_health`)
from the global per-IP cap, mirroring the reference PDS, so relay backfill is never
throttled. The exemption has no notion of "you already hold this rev". A client that
re-downloads an unchanged repo every two minutes is indistinguishable from a relay
backfilling twelve repos once.

## 4. Options considered

| Option | Effect on the bill | Why not (alone) |
|---|---|---|
| **Rev-aware cooldown on full exports** (chosen) | hydrant → ~$0.7/mo at a 1 h window | needs two small wallet changes (§6) |
| Railway CDN + `Cache-Control: s-maxage` on full exports | hits are free; origin sees 1 fetch per TTL | a CAR stale by up to the TTL after a commit can be imported by a migration silently; CDN toggle is service-wide |
| `ETag` = rev + `If-None-Match`, gzip/zstd | helps cooperative clients | hydrant sends neither; low yield |
| Block/limit the `hydrant/` User-Agent | immediate | three of the seven IPs send no UA; the next bad client has a different name |
| Upstream bug report to hydrant | removes the cause for every did:web PDS | not on our timeline; doesn't reach the UA-less operators. Deferred by decision |
| Cloudflare proxy for free egress | removes the line item | wildcard proxying, OAuth, firehose WebSockets, TLS mode: largest blast radius |
| Trim PDS memory (~$4/mo) | small | later |

Window length matters more than it first looks: hydrant honours `Retry-After` (it
records a per-host throttle), so a `429` *paces* it to one fetch per window per IP
rather than stopping it. At 10 min that is still ~3.5 GB/day (~$5/mo); at 1 h, ~$0.7/mo.
Keying on the rev makes a long window safe: no legitimate consumer needs the same
unchanged rev twice.

## 5. Design: the PDS cooldown

**Rule.** A full `getRepo` export (no `since`) for `(client IP, DID)` whose current root
CID equals the root served to that IP within the last `window` seconds answers `429`
with `Retry-After` (seconds remaining), `RateLimit-Limit: 1`, `RateLimit-Remaining: 0`,
`RateLimit-Reset`, and the standard error envelope (`ErrorCode::RateLimited`). Anything
else is served and recorded. The root CID stands in for the rev: it already identifies
the commit and the handler has it in hand before streaming.

**Never limited.** `since=` requests (deltas are what a well-behaved consumer sends and
are tiny); any request when `[rate_limit] enabled = false`; any request when the window
is `0`.

**Where.** In the `get_repo` handler, after the root-CID lookup and before
`stream_car_response`, because the middleware knows neither the DID's root nor whether
`since` is present. Client IP via the existing public `client_ip_from_headers` (leftmost
valid `X-Forwarded-For`, which Railway's edge sets; `"unknown"` bucket otherwise, same
assumption as the global limiter).

**State.** One more field on `RateLimiterState`:
`get_repo_full: Mutex<HashMap<(String /*ip*/, String /*did*/), (String /*root*/, Instant)>>`.
On every insert, when the map exceeds a fixed cap (10k entries), retain only entries
younger than the window. `ponytail:` plain map + occasional sweep; a sliding-window
limiter is more than this needs.

**Recording.** The entry is written before the body streams, so an aborted download
still counts. Acceptable: the client holds the rev it asked for in all but the
abort case, and the abort case is bounded by the window.

**Config.** `RateLimitConfig::get_repo_full_cooldown_secs: u64`, default `3600`, `0`
disables, env `EZPDS_RATE_LIMIT_GET_REPO_FULL_COOLDOWN_SECS`, following the existing
`[rate_limit]` knob pattern in `crates/common/src/config.rs`.

**Observability.** `count_rejection(&state, "get_repo_cooldown")` so refusals appear in
`rate_limit_rejections_total{limiter="get_repo_cooldown"}`; one `tracing::info!` per
refusal with `did` and `ip`.

**Tests** (in `routes/get_repo.rs`, driving the router with `X-Forwarded-For`):
same IP + same DID twice → second is `429` with `Retry-After` ≤ window; different IP →
`200`; `since=` repeatedly → `200`; a write between the two fetches (new root) → `200`;
window `0` → `200`. One `rate_limit.rs` test asserting the `getRepo` global exemption
still holds (it does today; keep it).

**Docs.** The new knob in `docs/deploy.md` (environment variables), the operator config
reference under `sites/docs/src/content/docs/operator/reference/config.md`, and the
rate-limit paragraph in `crates/pds/AGENTS.md`. One row in
`docs/security/threat-model.md` next to the existing global-limiter row. Changelog
fragment `changelog.d/mm-597.changed.md`. No route changes, so no Bruno update.

## 6. Design: the wallet

Both of the wallet's own full-export fetches would trip the cooldown, and one of them
is a correctness hazard today regardless of this change.

1. **Migration transfer** (`apps/identity-wallet/src-tauri/src/migration_orchestrator.rs`,
   `transfer_repo`). Today *any* source `getRepo` failure falls back to the iCloud repo
   snapshot. On `PdsClientError::RateLimited { retry_after, .. }` it must instead return
   `MigrationError::RateLimited { retry_after }` (the existing code, which the progress
   screen renders as "try again in about N minutes"), with no fallback: a
   `429` means the source can serve the repo and already did; the snapshot may be older
   than the live repo. Test: mock source answers `429` with `Retry-After` and a valid
   snapshot is present → the transfer fails with that message and the snapshot is not
   imported.
2. **Repo backup** (`repo_backup.rs::run_backup_core`). Today it downloads the full CAR
   and only then compares `rev` to the manifest. Call `com.atproto.sync.getLatestCommit`
   first (add `fetch_latest_commit(pds_url, did)` to `custos-client` if absent) and, when
   the rev matches the manifest and the CAR file is present, advance the timestamp
   without downloading. Cuts the wallet's own egress and makes a second backup run within
   the window a no-op rather than a `429`.

No IPC surface changes, so no `just docs-generate`. Wallet changes need their own
changelog fragment and the host-target test run (`cargo test -p identity-wallet` with
`EZPDS_IOS_BUILD=1` + `ios-env.sh` + `SDKROOT`).

## 7. Operator actions (outside the repo)

- **Done 2026-10-20:** Railway workspace soft usage limit set to $25 (email only, no
  hard limit) via `railway usage limit set --target workspace --soft 25`. Current-period
  usage is already $21, so expect the first email within days; that is the intended
  baseline check, not a regression.
- **atbb host cron** (hourly `curl` of `getRepo` for all twelve repos): gate each fetch
  on `getLatestCommit` so unchanged repos are skipped. Until then, unchanged repos answer
  `429` once the cooldown ships; the previous run's file stays in place.

## 8. Phases

1. **Wallet guards** (§6; one PR, `apps/identity-wallet` + `crates/custos-client`). Land
   first so a TestFlight build with the guards exists before production serves `429`s.
2. **PDS cooldown** (§5; one PR, `crates/pds` + `crates/common` + docs + fragment). Deploys
   to staging on merge; promote to production with the next tagged release after the
   phase 1 build is on TestFlight.
3. **Verify in production** (§9) within a day of the promote.

## 9. Verification

- `just ci-pds` green on the PDS PR; wallet host tests green on the wallet PR.
- Within 24 h of the production promote, from the repo root with the Railway CLI
  (`~/.railway/bin/railway`, sandbox off):
  - `railway metrics --service custos-obsign --environment production --network --since 1d --json`
    egress average drops from ~650 MB/h to well under 50 MB/h.
  - `railway logs --service custos-obsign --environment production --http --lines 500 --filter '@path:/xrpc/com.atproto.sync.getRepo' --json`
    shows the hydrant IPs receiving `429`s and at most one `200` per IP per hour.
  - `curl -s https://pds.obsign.org/metrics | grep 'rate_limit_rejections_total{limiter="get_repo_cooldown"'`
    is climbing.
  - **Spoof check (the cooldown's key is only as good as this):** from one machine, fetch the
    same unchanged repo twice in full, each time with a different made-up
    `X-Forwarded-For: 198.51.100.N`. The second must answer `429`. A `200` means Railway's edge
    passes the caller's `X-Forwarded-For` through, so the key is caller-chosen: an attacker could
    claim a relay's IP and hold its full export off. In that case, switch the cooldown (and the
    other per-IP limiters) to Railway's `X-Real-IP`, or set the window to `0` until fixed.
- Next billing period's `railway usage` egress line item is a few dollars, not fifteen.

## 10. Risks and open points

- **Shared NAT.** Two independent consumers behind one IP fetching the same repo within
  an hour: the second gets a `429` with a `Retry-After` it can honour. Accepted.
- **XFF spoofing.** Same limitation as the existing per-IP limiters, but sharper: a spoofed
  key here buys a 1 h refusal for the victim IP, not a share of a 3000-per-5-min budget. Safe
  only if Railway's edge replaces the caller's `X-Forwarded-For` (most reports say it does, none
  official); the §9 spoof check confirms it after deploy. The cooldown is a cost control, not
  a security boundary.
- **hydrant's per-host throttle.** A `429` makes each hydrant instance pause *all*
  fetches from this host for `Retry-After`. Fine for a twelve-repo PDS.
- **Upstream.** The evidence in §2 is enough for a hydrant bug report; deferred by
  decision until the bill drops. If the loop turns out to be a did:web-wide hydrant
  bug, every did:web PDS benefits from the report.
- **Later:** Railway CDN with `s-maxage` on full exports as belt-and-braces once the
  wallet's migration fetch can tolerate a stale CAR (it can't today); PDS memory.
