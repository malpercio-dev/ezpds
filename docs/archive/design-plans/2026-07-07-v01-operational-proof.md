# v0.1 Operational Proof Design

## Summary

The v0.1 feature surface is complete, but the deployment is operationally blind and the canonical
acceptance run has never happened. `crates/pds/src/telemetry.rs` exports OTel **traces** only —
there is no `/metrics` endpoint and no counters or gauges anywhere, so federation health (firehose
subscribers, relay crawl outcomes, appview proxy lag, blob GC sweeps, rate-limit rejections,
migration outcomes) is invisible in production. Separately, the only end-to-end HTTP validation is
the `tools/interop` Node CLI, which requires a live deployment and a real network; there is no
`crates/pds/tests/` harness CI can run. Finally, MM-241 — the live bsky.social migration round
trip, the single unvalidated leg of the MM-207 migration epic — is still open.

This plan adds three things: (1) an OTel-metrics layer plus a Prometheus-compatible `/metrics`
endpoint with a small, deliberate set of federation-health instruments; (2) a black-box HTTP
integration harness in `crates/pds/tests/` that boots the real router against a temp SQLite DB and
exercises the golden paths the interop suite covers, minus the live network; (3) the MM-241
validation run, executed with the existing `tools/interop` migration commands and written up as a
checklist document. Together these are the release gate for calling v0.1 done.

## Definition of Done

1. **Metrics layer.** A `metrics.rs` module in `crates/pds` initializes an OTel meter (or the
   `metrics` + `metrics-exporter-prometheus` crates — implementer's choice; prefer whichever
   integrates with the existing `telemetry.rs` OTLP setup with the least new dependency surface)
   and exposes a typed handle in `AppState`. A `GET /metrics` route serves the Prometheus text
   exposition format. The route must be **excluded** from the permissive CORS layer and from
   rate-limit accounting, and must be optionally bindable to a separate port or gated by config
   (`[telemetry] metrics_enabled`, default on; `metrics_require_admin`, default off for scrape
   compatibility) so operators can keep it off the public interface.

2. **Initial instrument set** (deliberately small; each instrument documented in
   `crates/pds/AGENTS.md`):
   - `firehose_subscribers` (gauge), `firehose_events_total` (counter, by frame type),
     `firehose_backfill_window_seconds` (gauge from oldest retained seq).
   - `relay_crawl_requests_total` (counter, by outcome) around the requestCrawl trigger.
   - `proxy_requests_total` (counter, by upstream + status class) and
     `proxy_upstream_lag_seconds` (histogram) in `service_proxy.rs` / read-after-write.
   - `blob_gc_swept_total`, `blob_gc_last_run_timestamp` in `blob_gc.rs`; same pattern for
     `account_reaper` and `firehose_gc`.
   - `rate_limit_rejections_total` (counter, by limiter).
   - `http_requests_total` (counter, by route template + status class) via middleware — use the
     matched route path, never the raw URI (cardinality).
   - `migration_imports_total` (counter, by outcome) in `import_repo`.

3. **Local integration harness.** `crates/pds/tests/http_suite.rs` (plus helpers in
   `crates/pds/tests/common/`) boots the full `app()` router with a temp-file SQLite DB (not the
   in-memory `test_state()` — the point is to exercise the real migration/startup path) and runs,
   over real HTTP via `tokio::net` + `reqwest` or `oneshot`: health → describeServer → create
   account → createSession → repo CRUD round trip → uploadBlob/getBlob → firehose WebSocket
   `#commit` observation → sync.getRepo CAR export → deactivate/reap. External calls (PLC
   directory, appview) are mocked with `httpmock` or stubbed via config. This mirrors
   `tools/interop/src/suite.js` step order so the two suites stay conceptually paired.

4. **MM-241 validation run.** Execute the live bsky.social round trip using
   `tools/interop`'s migrate command group against staging, both directions where applicable.
   Deliverable is `docs/validation/2026-XX-XX-mm-241-live-migration.md` recording each step,
   pass/fail, artifacts (DIDs used, report JSON paths), and any bugs filed. The runbook's
   **required pass conditions are MM-241's acceptance criteria**, checked after every leg —
   not just "the commands ran": (a) the plc.directory audit log for the DID shows the correct
   new entry for that hop, and (b) handle, DID document, and repo all resolve correctly against
   the new host. A leg without both checks recorded is not passed. If a leg fails, file the bug
   and stop — do not paper over it. (This item needs a human in the loop for live-network
   credentials; an agent prepares the checklist and runbook, the maintainer executes or supervises.)

**Explicitly out of scope:** dashboards/alerting config (Grafana etc.), SLO definitions, OTel
metrics for the iOS apps, converting `tools/interop` itself.

## Acceptance Criteria

### op-proof.AC1: Metrics endpoint
- **AC1.1:** `GET /metrics` returns Prometheus text format including at minimum
  `http_requests_total` and `firehose_subscribers` after boot.
- **AC1.2:** With `metrics_enabled = false`, the route returns 404 and no meter is registered.
- **AC1.3:** Route-template labels are bounded: hitting `/xrpc/com.atproto.repo.getRecord?rkey=X`
  1000 times with distinct rkeys produces one series, not 1000.

### op-proof.AC2: Instruments fire
- **AC2.1:** A repo write through `record_write` increments `firehose_events_total{frame="commit"}`
  and a connected subscriber raises `firehose_subscribers` by 1 (drops on disconnect).
- **AC2.2:** A blob-GC sweep updates `blob_gc_swept_total` and `blob_gc_last_run_timestamp`.
- **AC2.3:** A rate-limited request increments `rate_limit_rejections_total` with the correct
  limiter label.

### op-proof.AC3: Integration harness
- **AC3.1:** `cargo test -p pds --test http_suite` passes on a clean checkout with no network
  access and no running deployment.
- **AC3.2:** The suite covers the golden path listed in DoD item 3; each step is a separate,
  named assertion so failures localize.
- **AC3.3:** The harness runs in the existing `just ci-pds` gate without extending wall-clock by
  more than ~2 minutes.

### op-proof.AC4: MM-241 runbook
- **AC4.1:** The runbook document exists with concrete commands (copy-pasteable `just interop …`
  invocations), preconditions, rollback notes for the live account used, and — as required
  pass conditions per leg — the plc.directory audit-log check and the handle/DID/repo
  resolution checks from MM-241's acceptance criteria.
- **AC4.2:** After execution, the document records the outcome and links the JSON reports; MM-241
  is closed or a blocking bug is filed.

## Implementation notes

- Wire metrics into `AppState` the same way `telemetry.rs` tracing is wired — init in `main.rs`
  before `app()`, pass handles through state; avoid global statics except the exporter registry if
  the chosen crate requires it.
- `GET /metrics` is a route: it needs a `bruno/` entry per repo policy (`just bruno-check`).
- Keep instrument names/labels in one constants module so the AGENTS.md table can't drift silently.
- The harness should reuse fixture helpers from existing `#[cfg(test)]` code where exportable;
  if that requires making a `pds` test-support feature, prefer a `tests/common/mod.rs` copy over
  adding a public feature to the crate.
