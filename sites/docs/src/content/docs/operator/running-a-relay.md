---
title: Running a relay
description: Stand up the PDS, check its health, and understand what you are responsible for.
---

The PDS is a single Rust binary with a SQLite database. It is designed to be
easy to host — the whole point of the project.

## Health

Every deployment exposes a health endpoint the platform can watch:

```sh
curl -sS https://your-pds.example.com/xrpc/_health
```

A healthy server reports its version, derived from the workspace version — the
same source these docs stamp — so the server and its documentation cannot claim
different versions.

:::note[Status is stated, not colored]
The operator console reports health as an explicit label — `healthy`,
`degraded`, `down` — always paired with the metric behind it, never a bare
colored dot. A degraded server tells you _what_ degraded.
:::

<figure>
  <img src="/screenshots/admin/status.png" alt="Custos operator console server-status screen listing version, uptime, account counts, storage, firehose state, and background-sweep last-runs" width="280" />
  <figcaption>The console's server-status readout — version, uptime, account counts, storage, firehose, and background-sweep last-runs. Facts only.</figcaption>
</figure>

On a degraded relay, the same readout flags stale background sweeps with a
trailing glyph, so _what_ degraded is legible without relying on color.

<figure>
  <img src="/screenshots/admin/status-degraded.png" alt="Custos operator console server-status screen for a degraded relay, with stale background sweeps flagged by a trailing glyph" width="280" />
  <figcaption>A degraded relay: stale sweeps carry a trailing <code>!</code> glyph, never color alone.</figcaption>
</figure>

## Is the upstream relay seeing you?

A healthy server that no relay is crawling is invisible to the network — and an
upstream relay can silently drop your subscription. The console's Home screen
carries a **Relay federation** block that compares your server's exact sequencer
head against what the upstream relay reports for your host: the relay's
lifecycle status, its cursor, how many events it is behind, and when it last
consumed one. **Request crawl** re-invites the relay on demand — the recovery
move when the readout says the relay has stopped listening.

<figure>
  <img src="/screenshots/admin/home.png" alt="Custos operator console home screen with a Relay federation block reporting crawling status, events behind, and a Request crawl action" width="280" />
  <figcaption>The Relay federation block on Home: crawling status, exact gap, last seen — and <strong>Request crawl</strong> when it stops listening.</figcaption>
</figure>

The same facts are served at `GET /v1/admin/relay-status` and the re-invite at
`POST /v1/admin/request-crawl` — see the [API reference](/operator/reference/api/).

## What you are responsible for

- **Durability** — the SQLite database is the identity store. Back it up.
  Production streams continuous backups to object storage with Litestream — see
  [Backups & restore](/operator/backups/).
- **Availability** — users' clients reach your server to read and write. Health
  checks and restart policy are your safety net.
- **You can't lock anyone in** — you hold the lowest-precedence rotation key;
  the user's device key (`rotationKeys[0]`) and their recovery key outrank it,
  so they can move their identity to another server whenever they choose. Design
  your operations for that.

:::caution[Do not treat the DB as disposable]
Losing the database is not like losing a cache. It holds the repositories your
users depend on. Verify your restore path before you need it.
:::

## Deploy

The server deploys as an OCI image (Railway builds the `Dockerfile` directly).
The full runbook — staging vs production branches, Litestream backups, and the
security posture — lives in the repository's `docs/deploy.md`.
