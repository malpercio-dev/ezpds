# custos-firehose

Last verified: 2026-10-21

The firehose serving side: `com.atproto.sync.subscribeRepos` (live fan-out plus cursor replay
over the durable log), the `repo_seq` retention sweep, and the operator's federation-health pair
(`/v1/admin/relay-status`, `/v1/admin/request-crawl`). It depends on
[`custos-core`](../custos-core/AGENTS.md) and [`custos-db`](../custos-db/AGENTS.md), never on `pds`
or a sibling feature. The sequencer every writer emits through (`custos_core::firehose`), the
crawler notifier (`custos_core::crawler`), and the event-log queries (`custos_db::firehose_seq`)
sit below the features, because every repo writer in `pds` and the agents' child minting emit
events. The feature-crate contract is
[`custos-spaces`' map](../custos-spaces/AGENTS.md#what-pds-consumes); this crate owns no state.

`http_suite.rs` in `pds` reads the firehose over a real WebSocket against the spawned binary; the
commit-proof interop gate (`tests/fixtures/interop/`) runs here.

This file is a map; mechanism and invariants live in each module's `//!` doc.

## What `pds` consumes

| Export | Use in `pds` |
|---|---|
| `router()` / `internal_router()` | `subscribeRepos` in `app.rs`'s public (CORS'd) group; the relay-status / request-crawl pair in the `/v1/*` group. Always on |
| `spawn_sweeps(&mut Scheduler, &FirehoseConfig)` | `main.rs`; registers the `repo_seq` retention sweep |
| `test_support` (`test-support` feature) | `test_app(state)` plus `custos_core::test_support` re-exported |

## Module Map

```
src/
  lib.rs            — the exports above; aliases `custos_core`'s `auth`, `crawler`, `firehose`, `metrics`, `sweep`, `sweep_status`, `time` at the crate root so the moved files' `crate::…` paths resolve
  router.rs         — both route tables (`scripts/bruno-parity.sh` and `scripts/generate-docs-reference.mjs` read its `.route(` literals)
  firehose_gc.rs    — periodic `repo_seq` retention sweep (age/count pruning below the live frontier)
  relay_status.rs   — inbound `com.atproto.sync.getHostStatus` client (total, never fatal) backing `GET /v1/admin/relay-status` — see section below
  db.rs             — `custos_db`, re-exported crate-privately
  routes/           — one file per endpoint (table below); private, only handler functions leave it
  test_support.rs   — `test-support` feature (and this crate's own tests): `test_app` wraps both routers in the layers `pds` applies
```

### `relay_status.rs`

The inbound half of federation health: a `com.atproto.sync.getHostStatus` client asking the
upstream relay what it knows about this PDS, backing `GET /v1/admin/relay-status` (which compares
the relay's cursor against our exact sequencer head — see that route's row below, and
`admin_request_crawl.rs` for the companion action). Total, never fatal: every failure becomes a
`RelayReport` variant, so the readout always renders the outcome — what the relay said, or that
it could not be asked. Details: the module doc in `relay_status.rs`.

### `routes/`

| File | Endpoint |
|---|---|
| `sync_subscribe_repos.rs` | `GET /xrpc/com.atproto.sync.subscribeRepos` — WebSocket firehose (framing, replay, and the interop commit-proof gate in the module doc) |
| `admin_relay_status.rs` | `GET /v1/admin/relay-status` — is the relay actually crawling us? Exact-head vs relay-cursor comparison, raw truth only; admin-authed — see module doc |
| `admin_request_crawl.rs` | `POST /v1/admin/request-crawl` — un-throttled "Request crawl" action paired with relay-status; per-relay outcomes reported; admin-authed — see module doc |

## Rules

- **Routes do not import routes.**
- **Never depend on `pds` or a sibling feature crate.** Anything another feature also needs moves
  down to `custos-core` (or `custos-db` for a table); the emit side already lives there.
- **A new firehose route** is registered in `router.rs` and gets a `.bru` file in `bruno/` (root
  AGENTS.md).
- **Migrations stay in `custos-db`.**
