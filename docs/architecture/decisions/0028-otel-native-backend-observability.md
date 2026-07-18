# ADR-0028: OpenTelemetry-native observability for the backend; user-initiated log export for mobile

- **Status:** Accepted
- **Date:** 2026-07-18
- **Deciders:** malpercio
- **Related:** `crates/pds/src/telemetry.rs`, `crates/pds/src/metrics.rs`, `docs/deploy.md` (Observability), `docs/operations/debug-kit.md`, MM-436 / MM-437 (mobile diagnostics export), `apps/identity-wallet/src-tauri/src/diagnostics.rs`

## Context

The PDS already carries most of an observability stack, but idle. `telemetry.rs`
composes a `tracing` subscriber that can export **OTLP traces** over gRPC
(`opentelemetry-otlp` + `tracing-opentelemetry`, W3C trace-context propagation) —
gated off by default (`telemetry.enabled = false`, endpoint `localhost:4317`).
`metrics.rs` serves a Prometheus exposition at `GET /metrics` (federation-health
instrument set, cardinality-disciplined — labels are route templates and small
enums only, never request data). Logs are stdout `tracing` events, optionally
one-JSON-object-per-line (`EZPDS_LOG_FORMAT=json`). Errors surface only as those
log lines plus metric counters — there is no aggregation, and no collector is
deployed; `deploy.md` and `debug-kit.md` both name a persistent collector /
OTLP-trace sink as deliberately out of scope for v0.1.

The mobile apps had **no off-device capture** at all. A redacted, in-memory,
user-initiated diagnostics export just landed in the wallet (a network-error
breadcrumb log shared via the native share sheet — operation, host, HTTP status,
short error code only; never tokens, bodies, handles, or DIDs), with MM-436 /
MM-437 tracking coverage completion and the admin-companion port.

The question this ADR resolves: how do we get real error/troubleshooting
visibility — adopt an error-tracker (a Sentry SDK + a self-hosted Bugsink
instance on Railway), or lean into the OpenTelemetry we already emit? Two forces
make the answer non-obvious. First, on the **server** a Sentry/Bugsink pipe would
sit *alongside* the traces and metrics OTel already produces — error tracking is
largely a subset of what an OTLP backend surfaces from error logs and span
events, so a dedicated tracker is a redundant fourth signal path. Second, on the
**client**, the calculus inverts: any *passive* field telemetry — OTel or Sentry
alike — adds a public ingest endpoint plus an opt-in / privacy surface that the
user-initiated export sidesteps entirely, and OTel specifically brings no mobile
crash-handling, an area where Sentry's mobile SDK is materially stronger.

## Decision

**We will make OpenTelemetry the single observability substrate for the backend,
and keep mobile on user-initiated log export — no passive client telemetry — for
now.**

Backend:

1. **Enable the existing OTLP export** (`telemetry.enabled = true`) once a
   backend exists, pointing `EZPDS_TELEMETRY_OTLP_ENDPOINT` at it.
2. **Add an OTel logs layer.** Bridge `tracing` events to OTLP **log records**
   (`opentelemetry-appender-tracing`) as a third layer beside the existing
   `fmt` and `otel-traces` layers in `init_subscriber`, so `warn!/error!` ship
   structured *and* trace-correlated (shared trace/span IDs). The metrics
   cardinality discipline extends verbatim to log attributes: no DIDs, handles,
   emails, tokens, or raw URIs in fields.
3. **Deploy one OTLP-native backend as a Railway service reached over the
   project's private network** (a single self-hosted box that ingests traces +
   metrics + logs — SigNoz / Uptrace class), not a dedicated error-tracker.
   `/metrics` stays as the Prometheus scrape surface; the same OTLP endpoint
   carries traces and logs.

We will **not** adopt Sentry or a self-hosted Bugsink on the backend.

Mobile: we will **stay with the redacted, user-initiated diagnostics export**
(the landed wallet feature + MM-436 / MM-437) and add **no passive or always-on
client telemetry** — neither OTel export from the device nor a crash SDK — until
a concrete need (e.g. crashes we cannot reproduce from field reports) forces the
question. That future decision is scoped out here, not foreclosed.

## Consequences

- **Unlocks:** correlated traces, metrics, and logs for the server in one
  backend — pivot from a slow or failed request's span straight to its logs;
  retained history instead of ad-hoc `railway logs`. Reuses the dormant OTLP
  investment rather than paying for a parallel pipe.
- **Keeps the sovereign posture:** observability lives on the private network
  (matching `deploy.md`'s intended stance for `/metrics`), and no third party
  holds user-adjacent data. OTLP is vendor-neutral, so this stays reversible — a
  hosted backend later is a config change, not a re-instrumentation.
- **Costs / risks accepted:** a new Railway service to run, with its own storage
  and a retention policy to set. The log-attribute redaction rule is now
  load-bearing (a leaked handle/DID/token in a log field is a privacy defect) —
  it inherits the existing metrics cardinality discipline. An OTLP backend's
  **error-triage UX** (fingerprint grouping, regression detection, release
  health) is weaker than Sentry's; accepted, to be revisited only if server-side
  error *triage* — distinct from observability — becomes a real need, at which
  point a Sentry SDK can point at the same events without displacing this stack.
- **Follow-on:** a Wave 7 issue to stand up the collector/backend, add the logs
  layer, and wire the telemetry defaults; update `deploy.md` (Observability) and
  `debug-kit.md` (drop the "deferred / out of scope" framing, point here).
- **Mobile stays simple:** zero client infra, zero passive collection, no opt-in
  toggle to manage. If passive field capture is later wanted, Sentry's mobile SDK
  (crash handling, release health) is the stronger client choice than OTel — this
  ADR records that as the expected direction *if* the need arises.

## Alternatives considered

- **Sentry SDK + self-hosted Bugsink on the backend.** Rejected: it duplicates
  signals OTel already emits — a redundant fourth pipe next to traces, metrics,
  and logs — and error tracking is largely a subset of what an OTLP backend
  surfaces from error logs and span events. Its genuine edge (the issue-triage
  workflow) is not the current need, and adopting it would mean instrumenting a
  second SDK and running a box that sees only errors.
- **OpenTelemetry everywhere, including passive export from mobile devices.**
  Rejected for the client: it carries the same public-ingest, opt-in, and
  privacy surface as any passive telemetry — the user-initiated export avoids all
  of it — while offering weaker mobile tooling and, critically, no crash
  handling. OTel's strength is the server, not a field WKWebView app.
- **Hosted SaaS observability (Grafana Cloud, Datadog, hosted Sentry).**
  Rejected: cuts against the self-host / sovereign ethos and the private-network
  posture, and puts user-adjacent telemetry on a third party. OTLP's
  vendor-neutrality keeps this option open later without re-instrumenting.
- **Status quo — `railway logs` + `/metrics` only.** Rejected: no
  trace-correlated logs, no retained history, and error visibility stays ad hoc —
  while the OTLP trace pipeline already built into `telemetry.rs` goes unused.
