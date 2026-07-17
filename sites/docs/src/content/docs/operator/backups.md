---
title: Backups & restore
description: Continuous SQLite backups with Litestream, and how to restore.
---

The PDS keeps everything in one SQLite database, so backing it up **is** your
disaster-recovery plan. Custos uses [Litestream](https://litestream.io/) to stream
that database to object storage continuously and restore it on boot.

## How it works

When the Litestream environment variables are set, the container runs the PDS
under Litestream: it streams the SQLite write-ahead log to your bucket as writes
happen (not a nightly snapshot — a continuous replica), and on boot it restores
from that replica if the local database is missing. So a current restore point
always exists.

The replica is defined in `litestream.yml` (committed in the repo) with
`force-path-style: false` — virtual-hosted-style addressing, which
Railway/Tigris-style buckets require.

## Turning it on

Set these on the environment you want backed up (production; staging and local
leave them unset and run the PDS directly):

| Variable | Role |
| --- | --- |
| `LITESTREAM_S3_BUCKET` | The bucket the replica is written to. Setting this is what switches Litestream on. |
| `LITESTREAM_S3_ENDPOINT` | Object-storage endpoint (e.g. your Tigris/S3-compatible host). |
| `LITESTREAM_ACCESS_KEY_ID` | Access key for the bucket. |
| `LITESTREAM_SECRET_ACCESS_KEY` | Secret key for the bucket. |

:::caution[The bucket credentials are secrets]
Store them in your platform's secret manager, never in the repository or the
image — the same discipline as the [master key](/operator/configuration/). Anyone
with the replica has a full copy of your accounts' data.
:::

:::caution[The replica is only half the picture]
This backup protects the *ciphertext*. It does **not** protect the
[master key](/operator/configuration/) that decrypts it — back that up
separately, in a different store than this replica. If the key is ever lost
or compromised, follow the [master-key disaster runbook](/operator/master-key-runbook/)
instead of restoring from here alone.
:::

## Restoring

To restore the database from the replica:

```sh
litestream restore <path-to-db>
```

Litestream pulls the latest state (or a point in time) from the bucket. On a
fresh container the PDS does this automatically on boot when the local database is
absent.

### Rollback after a bad release

Schema migrations are **forward-only** — there is no down-path. Redeploying an
earlier `vX.Y.Z` tag is safe **only** when the schema change was
backward-compatible. If it wasn't, roll back by restoring the database from the
Litestream replica to a point *before* the promote, rather than by redeploying
old code against a newer schema.

:::note[Inspect without rolling back]
To look inside the replica without touching production, restore a throwaway copy
and query it with `sqlite3` — no rollback required. The repository's operator
debug kit documents this runbook.
:::

:::caution[Verify your restore path before you need it]
A backup you've never restored is a hope, not a plan. Do a restore into a
throwaway copy at least once so you know the bucket, credentials, and endpoint are
right before an incident forces the question.
:::
