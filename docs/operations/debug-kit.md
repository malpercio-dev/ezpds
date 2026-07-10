# Operator debug kit

**Last verified:** 2026-07-10

A small, deliberate toolkit for troubleshooting the production/staging PDS on
Railway **over the private network / SSH boundary** — no new public surface, no
new auth machinery. Two entry points:

- **`railway ssh`** — a shell inside the running PDS service container. Reach it
  for anything that needs the live filesystem or the Litestream replica the
  container is already configured for (the restore-and-inspect runbook below).
- **`railway sandbox`** — a throwaway diagnostic box. With `--private-network`
  it joins the environment's private network and can reach the PDS at
  `<service>.railway.internal:<port>` with zero public routing, while keeping
  outbound internet for the ATProto interop suite. Pre-bake the toolset once as
  a template/checkpoint (recipe below) so a fresh box is ready in seconds.

> **Prerequisite:** Railway Sandboxes require **Priority Boarding** enablement
> on the workspace. `railway ssh` needs no special enablement.

The related read-only diagnostic surfaces — `GET /metrics` (Prometheus
exposition) and `EZPDS_LOG_FORMAT=json` (greppable `railway logs`) — are
documented under [deploy.md → Observability](../deploy.md#observability-metrics-and-logs).
This page covers the rest of the kit.

---

## What's in the runtime image

The PDS container (`Dockerfile`, `debian:bookworm-slim` runtime stage) ships:

| Tool | Why it's there |
|------|----------------|
| `pds` | the server binary |
| `litestream` | continuous WAL replication + restore-on-boot (active only when `LITESTREAM_S3_BUCKET` is set — production) |
| `sqlite3` | **inspect a restored DB copy** over `railway ssh` (this kit) |
| `curl` | health/metrics probes from inside the container |

Richer tools (`jq`, `websocat`, `node`/`pnpm`, an `ezpds` checkout for the
interop suite) are deliberately **not** in the runtime image — they live in the
debug-kit sandbox instead, so the deployed image stays minimal.

---

## Runbook 1 — Litestream restore-and-inspect

**Goal:** query the production database without touching the live one. The live
`/data/relay.db` is a single-writer WAL SQLite owned by the `pds` process; the
safe pattern is to restore a **point-in-time copy from the S3 replica** into
`/tmp` and open *that* with `sqlite3`. The replica read never touches the live
DB, so there is zero risk to the running server.

This runs against **production**, where Litestream is active and the replica
credentials (`LITESTREAM_S3_BUCKET`, `LITESTREAM_S3_ENDPOINT`,
`LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY`) are already in the
service environment. The config lives at `/etc/litestream.yml` and defines the
`/data/relay.db` → S3 replica.

```sh
railway ssh                    # shell into the running production PDS container

# Restore the latest replica state into a throwaway copy (NOT over /data/relay.db).
litestream restore -config /etc/litestream.yml -o /tmp/copy.db /data/relay.db

# Inspect the copy freely — it's disconnected from the live DB.
sqlite3 /tmp/copy.db '.tables'
sqlite3 /tmp/copy.db 'SELECT count(*) FROM accounts;'

rm -f /tmp/copy.db             # clean up when done
```

`-o /tmp/copy.db` **must** differ from `/data/relay.db`; never restore over the
path the server is writing.

### Point-in-time restore

To inspect state as of a specific instant (e.g. just before a bad deploy),
list what the replica holds, then restore to a timestamp:

```sh
litestream generations -config /etc/litestream.yml /data/relay.db
litestream snapshots   -config /etc/litestream.yml /data/relay.db

litestream restore -config /etc/litestream.yml \
  -timestamp 2026-07-09T18:00:00Z \
  -o /tmp/point-in-time.db /data/relay.db

sqlite3 /tmp/point-in-time.db '.schema accounts'
```

This is the same primitive used for **disaster recovery** — see
[deploy.md → Backup & rollback](../deploy.md#backup--rollback). There, the
restore lands at `/data/relay.db` on a fresh boot; here it lands in `/tmp` for
inspection only.

### Quick read-only peek at the live DB (escape hatch)

If you must see *current* state without a restore (e.g. the replica lags and you
need the last committed rows), open the live DB **strictly read-only** so you
can never take a write lock or corrupt the WAL:

```sh
sqlite3 -readonly /data/relay.db 'SELECT count(*) FROM accounts;'
```

Prefer the restore-copy path for anything nontrivial — a read-only connection
still shares the file with the single writer, and a WAL reader only sees frames
committed up to the last checkpoint it observes. The restore copy has neither
caveat.

### From a sandbox instead of the container

The same restore works from a `--private-network` sandbox given the replica
credentials — export the four `LITESTREAM_*` values and either copy
`litestream.yml` in or pass the replica URL directly. Inside the container is
simpler (config + creds already present), so reach for the sandbox only when you
also want the richer tooling below.

---

## Runbook 2 — Debug-kit sandbox (private-network diagnostics)

**Goal:** a ready diagnostic box on the environment's private network that can
probe the PDS and run the ATProto interop suite against it with **no public
routing**. Bake the toolset once, then boot fresh boxes from it.

The kit bakes: `sqlite3`, `jq`, `websocat` (live firehose frame tap), `curl`,
`git`, and `node`/`pnpm` with a `tools/interop` checkout ready to run.

### Option A — build a reusable template (preferred)

A template is a content-addressed filesystem snapshot built from an ordered list
of shell steps (`-c` once per step; each must exit 0 within 10 min). Identical
instructions are a cache hit for ~7 days, so rebuilds are instant.

```sh
railway sandbox template build \
  --name ezpds-debug-kit \
  -c "apt-get update && apt-get install -y --no-install-recommends sqlite3 jq websocat curl git ca-certificates" \
  -c "curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs" \
  -c "corepack enable && corepack prepare pnpm@latest --activate" \
  -c "git clone --depth 1 https://github.com/malpercio-dev/ezpds /opt/ezpds" \
  -c "cd /opt/ezpds/tools/interop && pnpm install --frozen-lockfile" \
  --wait
```

Boot a box from it on the private network and open a shell:

```sh
railway sandbox create --template ezpds-debug-kit --private-network
railway sandbox ssh
```

### Option B — checkpoint a configured box

If you'd rather configure interactively, start a plain box, set it up, then
snapshot it. A checkpoint is a named disk snapshot captured from a running
sandbox; capture is synchronous, so it's bootable as soon as the command
returns (reusing a name replaces it).

```sh
railway sandbox create --private-network
railway sandbox ssh
#   ...inside: apt-get install sqlite3 jq websocat curl git, install node+pnpm,
#      git clone the repo, cd tools/interop && pnpm install...
railway sandbox checkpoint create --name ezpds-debug-kit    # acts on the active sandbox

# Later, boot a fresh box from the checkpoint:
railway sandbox create --checkpoint ezpds-debug-kit --private-network
```

### Using the box

Inside the sandbox, the PDS is reachable at its private hostname
`<service>.railway.internal:<port>` (`<port>` is the service's `PORT`). None of
this is exposed publicly.

```sh
# Point-in-time federation-health + liveness snapshot (no public exposure):
curl -s http://<service>.railway.internal:<port>/metrics | jq -R .
curl -s http://<service>.railway.internal:<port>/xrpc/_health

# Tap live firehose frames (com.atproto.sync.subscribeRepos is a WebSocket):
websocat "ws://<service>.railway.internal:<port>/xrpc/com.atproto.sync.subscribeRepos"

# Run the interop suite against the private-network service:
cd /opt/ezpds/tools/interop
EZPDS_BASE_URL=http://<service>.railway.internal:<port> \
EZPDS_ADMIN_TOKEN=<admin-token> \
  ./bin/interop describe
```

> **The interop suite touches the live ATProto network** (real plc.directory,
> relay, AppView) and every created account registers a **permanent** `did:plc`.
> Read `tools/interop/README.md` → "Ground rules" before running anything beyond
> `describe`; use `--name primary` for routine runs and `--ephemeral` only for
> lifecycle tests.

When finished, tear the box down (it also expires on its own):

```sh
railway sandbox destroy          # acts on the active sandbox
```

---

## Out of scope

- **Persistent scraping / dashboards** (a collector service inside the project
  to retain `/metrics` history and receive the OTLP traces `telemetry.rs`
  already exports) is a separate cost/benefit decision, not part of this kit.
- **JSON log output** (`EZPDS_LOG_FORMAT=json`) shipped separately — see
  [deploy.md → Observability](../deploy.md#observability-metrics-and-logs).

## References

- Railway Sandboxes: <https://docs.railway.com/sandboxes>
- `railway sandbox` CLI reference: <https://docs.railway.com/cli/sandbox>
- Agents in sandboxes: <https://docs.railway.com/guides/agents-in-sandboxes>
- Private networking: <https://docs.railway.com/networking/private-networking>
- Litestream: <https://litestream.io/reference/restore/>

The exact `railway sandbox` flags evolve with the CLI; confirm against
`railway sandbox --help` and the reference above if a command has changed.
