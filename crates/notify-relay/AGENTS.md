# notify-relay Crate

Last verified: 2026-07-27

## Purpose

The notification relay: a **blind courier** between a self-hosted Custos instance and APNs.
APNs auth keys are bundle-ID-bound, so a self-hoster cannot push to the official iOS apps
directly — a relay is structurally required. It is trusted for *availability only*: payloads
reach it already HPKE-sealed to a per-device key, so neither the relay nor Apple ever sees
plaintext, and the relay holds no key material belonging to an instance or a device.

Architecture: [`docs/design-plans/2026-07-10-notification-relay.md`](../../docs/design-plans/2026-07-10-notification-relay.md).
Implementation detail: [`docs/design-plans/2026-07-17-notification-relay-implementation.md`](../../docs/design-plans/2026-07-17-notification-relay-implementation.md).

Its own binary and its own SQLite database — nothing is shared with the pds crate at
runtime. The conventions *are* shared: pattern comments, `db/` submodules owning queries
while cross-table sequences live above them, and `VNNN__*.sql` migrations behind a manifest
plus runner (copied, not shared — the runner is ~50 lines and the two crates' migration
histories are independent).

## Module Map

```text
src/
  main.rs        — CLI (serve, `mint-code --ttl`), config load, store open, endpoint bind, accept loop, shutdown
  config.rs      — TOML + `EZPDS_NOTIFY_*` env overlay, validated once into an immutable `Config`
  identity.rs    — the persistent iroh node secret key file (64 hex chars, created 0600, refused if wider)
  protocol.rs    — the `ezpds/notify/0` wire types: `Request`/`Response`/`PushOutcome`, the ALPN, the 64 KiB cap
  transport.rs   — iroh endpoint bind + accept loop; one JSON RPC per bidi stream, FIN-delimited, 30 s deadline
  service.rs     — RPC dispatch: the authorization order and the cross-table enrollment transaction
  rate_limit.rs  — in-memory token buckets (registration + per-node push + per-handle push budgets)
  apns.rs        — the APNs leg: ES256 provider token, envelope assembly, 4 KiB cap, status → outcome
  db/            — `enrollment_codes`, `enrollments`, `handles`, plus the pool/migration runner
```

## Security Invariants

**The caller's identity is the connection, never the message.** `service.rs` is only ever
called with `connection.remote_id()`. No request field names a node, so there is nothing to
forge — iroh has verified the peer's key before the first application byte arrives. Do not
add a "node id" field to any request.

**Every RPC except `enroll` requires enrollment, checked before the rate-limit charge.** An
unenrolled node is rejected on a cheap read, so it can neither spend an enrolled node's
budget nor build one against an identity it has not earned.

**Handle queries are always scoped by node id.** `db/handles.rs` binds the caller's node id
into every WHERE clause; that is the whole cross-tenant boundary. A handle owned by another
node reads exactly like one that never existed (`unknownHandle` on push, a silent no-op on
drop) — the response must never become an ownership oracle.

**Refusals are shape-uniform.** An enrollment code that is unknown, spent, or expired — and
an enroll with no code at all — all answer `denied`, so probing teaches nothing about which
codes the operator has minted. Storage failures answer with a fixed reason and are logged,
never reflected; an unparseable request is never echoed back.

**The sealed payload is copied, never inspected.** `apns.rs` moves the RPC's `kid`/`enc`/`ct`
into the envelope verbatim. The only secret in this crate is the operator's own APNs
token-auth key; no instance key and no device key is ever handled here.

**A push charges two budgets, and only after the handle resolves.** The per-node bucket
bounds what one instance costs the relay; the per-handle bucket (60/h) bounds what one
device is subjected to. Charging the per-handle bucket *before* the ownership-scoped
resolve would let a stranger spend a device's budget by guessing handles.

## Configuration

TOML file (default `./notify-relay.toml`, or `--config`/`EZPDS_NOTIFY_CONFIG`) overlaid by
`EZPDS_NOTIFY_*` environment variables, which always win — the container deployment sets
everything that way and ships no file.

| Setting | Env | Default |
|---|---|---|
| `database_url` | `EZPDS_NOTIFY_DATABASE_URL` | `notify-relay.db` |
| `secret_key_path` | `EZPDS_NOTIFY_SECRET_KEY_PATH` | `notify-relay-node.key` |
| `ipv6` | `EZPDS_NOTIFY_IPV6` | `true` (set false on a v4-only host) |
| `open_enrollment` | `EZPDS_NOTIFY_OPEN_ENROLLMENT` | `false` |
| `apns.key_path` / `key_id` / `team_id` | `EZPDS_NOTIFY_APNS_KEY_PATH` / `_KEY_ID` / `_TEAM_ID` | unset (all-or-nothing) |
| `apns.topics` | `EZPDS_NOTIFY_APNS_TOPICS` (comma-separated) | empty = any topic |
| `apns.sandbox` | `EZPDS_NOTIFY_APNS_SANDBOX` | `false` |
| `apns.endpoint` | `EZPDS_NOTIFY_APNS_URL` | unset (the wiremock seam) |
| `rate_limits.*` | `EZPDS_NOTIFY_RATE_{REGISTRATIONS,PUSHES,HANDLE_PUSHES}_{PER_HOUR,BURST}` | 100/10 registrations, 1000/50 pushes, 60/10 per-handle pushes per hour |

APNs credentials are all-or-nothing and validated at startup: a relay whose `.p8` is
missing or malformed refuses to start rather than coming up healthy and failing every
push. With no credentials at all it serves every RPC but `push`, which answers `apnsError`
— the posture for bringing a relay up before its key exists.

## Operating

```sh
notify-relay                      # serve; prints the node id instances dial
notify-relay mint-code --ttl 24h  # mint one single-use enrollment grant
```

Enrollment codes are minted at the relay's own shell — there is deliberately no remote
admin surface. Relay state is re-derivable by re-enrollment, so backups are optional; the
node secret key file is not, since losing it re-addresses the relay.

## Adding an RPC

1. Add the variant to `Request`/`Response` in `protocol.rs` (camelCase tags) with a test
   pinning its wire shape.
2. Add the handler arm in `service.rs`, going through `require_enrolled` unless the RPC is
   deliberately pre-enrollment.
3. If it needs a new query, add it to the owning `db/` submodule — scoped by node id.
4. Cover it in `transport.rs`'s loopback tests, including the cross-tenant probe.
