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

## What you are responsible for

- **Durability** — the SQLite database is the identity store. Back it up.
  Production streams continuous backups to object storage with Litestream — see
  [Backups & restore](/operator/backups/).
- **Availability** — users' clients reach your server to read and write. Health
  checks and restart policy are your safety net.
- **You can't lock anyone in** — you hold the lower-precedence rotation key
  (`rotationKeys[1]`); the user's key (`rotationKeys[0]`) outranks it, so they can
  move their identity to another server whenever they choose. Design your
  operations for that.

:::caution[Do not treat the DB as disposable]
Losing the database is not like losing a cache. It holds the repositories your
users depend on. Verify your restore path before you need it.
:::

## Deploy

The server deploys as an OCI image (Railway builds the `Dockerfile` directly).
The full runbook — staging vs production branches, Litestream backups, and the
security posture — lives in the repository's `docs/deploy.md`.
