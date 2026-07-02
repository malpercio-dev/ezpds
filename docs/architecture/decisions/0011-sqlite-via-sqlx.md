# ADR-0011: SQLite (via sqlx) as the datastore

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0007](0007-mobile-only-pds-is-full-pds.md) · [`AGENTS.md`](../../../AGENTS.md) · [`crates/pds/src/db`](../../../crates/pds/src/db)

## Context

The PDS needs a datastore for accounts, sessions, repo blocks, blobs, the
firehose sequencer, and OAuth state. ezpds is a **sovereign, single-instance**
PDS (one operator, per-instance data), not a multi-tenant cloud service — which
shapes what "the right database" means here.

## Decision

Use **SQLite via `sqlx`** (`runtime-tokio` + `sqlite`), linked against the
system SQLite (`LIBSQLITE3_SYS_USE_PKG_CONFIG=1`, not the bundled copy).
Production durability is provided by **Litestream** streaming replication of the
single DB file.

## Consequences

- **Simple operations and backup.** A single-file DB is trivial to snapshot, and
  Litestream gives continuous point-in-time backup without a database server.
- **`sqlx` compile-time-checked queries** keep the `db/` layer honest;
  `just lock-check` + migrations keep schema drift reviewable.
- **Single-writer constraints are real** and visible in the code — e.g. the
  firehose builds commit-block CARs *before* opening a transaction because the
  single-connection pool can't serve a block read while a tx holds the
  connection. New DB work must respect this.
- **Not horizontally scalable**, which is acceptable and even aligned for a
  sovereign per-instance PDS (ADR-0007); scale is "more instances", not "bigger
  database".

## Alternatives considered

- **PostgreSQL.** Better concurrency and horizontal scale, but it's a separate
  service to run, secure, and back up — overkill for a single-tenant sovereign
  PDS, and it forfeits the single-file simplicity Litestream leans on. Rejected
  for this phase.
